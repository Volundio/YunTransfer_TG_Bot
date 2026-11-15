"""Baidu Netdisk async CloudProvider implementation (§5.4, §5.5).

Strict Dependency Boundary:
- Never imports `storage`, `runtime_config`, `pydantic`, `requests`, `httpx`, or `reference`.
- Reuses the injected application-level `aiohttp.ClientSession`, `CredentialStore`, and
  `ProviderConfigReader` protocols from `providers.base`.
- Reads every JSON response via `models.read_bounded_json` (`MAX_API_JSON_BYTES = 4 MiB`).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit

import aiohttp

import yunbot.models as models
from yunbot.models import (
    API_REQUEST_TIMEOUT_SECONDS,
    BAIDU_FILEMETAS_BATCH_SIZE,
    BAIDU_LIST_MAX_PAGES,
    BAIDU_LIST_PAGE_SIZE,
    BAIDU_SHARE_PAGE_SIZE,
    BAIDU_TRANSFER_BATCH_SIZE,
    MAX_API_JSON_BYTES,
    MAX_SHARE_ENUM_ITEMS,
    ApiResponseTooLargeError,
    AuthMode,
    BindingMismatchError,
    DeleteItemsOutcome,
    ErrorCode,
    InteractiveAuthPollResult,
    InteractiveAuthStart,
    PasswordPolicy,
    ProviderAccountStatus,
    ProviderAuthInvalidError,
    ProviderCredentialRecord,
    ProviderInvalidPasswordError,
    ProviderQuotaExceededError,
    ProviderRateLimitedError,
    ProviderShareExpiredError,
    RecognizedShareUrl,
    ShareLinkInfo,
    TransferItemRecord,
    TransferOutcome,
    TransferredEntry,
    YunBotError,
    format_error_message,
    normalize_posix_path,
    read_bounded_json,
    redact_sensitive_text,
    validate_direct_item_path,
    validate_save_path,
)
from yunbot.providers.base import (
    CredentialStore,
    ItemsBatchCallback,
    ProgressCallback,
    ProviderConfigReader,
    ProviderSpec,
    RemoteTaskCallback,
    ShareRecognizer,
)

logger = logging.getLogger(__name__)

_OAUTH_AUTHORIZE_URL = "https://openapi.baidu.com/oauth/2.0/authorize"
_OAUTH_TOKEN_URL = "https://openapi.baidu.com/oauth/2.0/token"
_NAS_URL = "https://pan.baidu.com/rest/2.0/xpan/nas"
_SHARE_URL = "https://pan.baidu.com/rest/2.0/xpan/share"
_FILE_URL = "https://pan.baidu.com/rest/2.0/xpan/file"
_MULTIMEDIA_URL = "https://pan.baidu.com/rest/2.0/xpan/multimedia"

_DESKTOP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_XPAN_HEADERS: dict[str, str] = {
    "User-Agent": _DESKTOP_USER_AGENT,
    "Referer": "https://pan.baidu.com/disk/home",
}
_OAUTH_HEADERS: dict[str, str] = {
    "User-Agent": _DESKTOP_USER_AGENT,
}

_AUTH_EXPIRED_ERRNOS: frozenset[int] = frozenset({-6, 110, 111})
_SHARE_EXPIRED_ERRNOS: frozenset[int] = frozenset({-7, -9, -3, -21, 105, 115, 117, 145})
_VERIFY_SHARE_EXPIRED_ERRNOS: frozenset[int] = frozenset({-7, -3, -21, 105, 115, 117, 145})
_VERIFY_INVALID_PWD_ERRNOS: frozenset[int] = frozenset({-12, -9})
_QUOTA_ERRNOS: frozenset[int] = frozenset({12, -30, -32, -33, 120, 130})
_RATE_LIMIT_ERRNOS: frozenset[int] = frozenset(
    {31034, 31045, 42000, 42001, 9100, 9200, 9300, 9400, 9500}
)
_DELETE_IDEMPOTENT_ERRNOS: frozenset[int] = frozenset({0, -9, 31066})
_DELETE_SYNC_LIMIT_ERRNOS: frozenset[int] = frozenset({11, 12, 130, 31024})

_FALLBACK_SHARE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,128}$")
_FALLBACK_PWD_RE = re.compile(r"^[A-Za-z0-9]{4}$")

BAIDU_SPEC = ProviderSpec(
    provider_id="baidu",
    display_name="百度网盘",
    command="baidu",
    password_policy=PasswordPolicy.REQUIRED,
    auth_mode=AuthMode.OAUTH_CODE,
    save_path_key="BAIDU_SAVE_PATH",
    openlist_path_key="OPENLIST_BAIDU_PATH",
    default_save_path="/转存文件",
    default_openlist_path="/baidu/转存文件",
)


@dataclass(frozen=True, slots=True)
class _ShareSourceItem:
    """Single top-level entry discovered from xpan/share?method=list."""

    fs_id: str
    name: str
    is_dir: bool


class _FallbackBaiduShareRecognizer:
    """Pure zero-I/O fallback recognizer used when parsing.py is not loaded."""

    @property
    def provider_id(self) -> str:
        return BAIDU_SPEC.provider_id

    def recognize(self, url: str) -> RecognizedShareUrl | None:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            return None

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https") or parsed.hostname != "pan.baidu.com":
            return None
        allowed_ports = (None, 80) if scheme == "http" else (None, 443)
        if parsed.username or parsed.password or port not in allowed_ports:
            return None

        query = parse_qs(parsed.query, keep_blank_values=True)
        external_id: str | None = None
        if parsed.path.startswith("/s/1") and parsed.path.count("/") == 2:
            external_id = parsed.path.removeprefix("/s/1")
        elif parsed.path == "/share/init":
            values = query.get("surl", [])
            if len(values) == 1:
                external_id = values[0]
        if not external_id or not _FALLBACK_SHARE_ID_RE.fullmatch(external_id):
            return None

        embedded_code: str | None = None
        pwd_values = query.get("pwd", [])
        if pwd_values:
            unique_pwds = set(pwd_values)
            if len(unique_pwds) != 1 or not _FALLBACK_PWD_RE.fullmatch(pwd_values[0]):
                return None
            embedded_code = pwd_values[0]

        canonical_url = f"https://pan.baidu.com/share/init?{urlencode({'surl': external_id})}"
        return RecognizedShareUrl(
            provider_id=self.provider_id,
            normalized_url=canonical_url,
            external_id=external_id,
            embedded_code=embedded_code,
        )


def _resolve_default_recognizer() -> ShareRecognizer:
    try:
        from yunbot.domain.parsing import BaiduShareRecognizer  # type: ignore[import-not-found]

        candidate = BaiduShareRecognizer()
        if isinstance(candidate, ShareRecognizer):
            return candidate
    except Exception:
        pass
    return _FallbackBaiduShareRecognizer()


def _parse_errno(payload: Mapping[str, Any]) -> int:
    raw = payload.get("errno")
    if isinstance(raw, bool) or raw is None:
        raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘返回缺少有效的 errno 字段")
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘返回的 errno 格式无效") from exc


def _string_id(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    return None


def _as_bool_isdir(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip() not in ("", "0", "false", "False")
    return False


def _batched[T](items: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


def _normalize_surl(raw_surl: str, share_url: str = "") -> str:
    stripped = raw_surl.strip()
    if not (stripped.startswith("1") and len(stripped) > 1):
        return stripped

    if share_url:
        try:
            parsed = urlsplit(share_url)
            path = parsed.path.rstrip("/")
        except ValueError:
            path = ""
        if path == "/share/init":
            return stripped
        if path.startswith("/s/1") and path.removeprefix("/s/1") == stripped:
            return stripped

    return stripped[1:]


_MODEL_BASELINES: dict[str, int] = {
    "BAIDU_SHARE_PAGE_SIZE": 100,
    "BAIDU_TRANSFER_BATCH_SIZE": 100,
    "BAIDU_FILEMETAS_BATCH_SIZE": 100,
    "BAIDU_LIST_PAGE_SIZE": 1000,
    "BAIDU_LIST_MAX_PAGES": 5,
    "MAX_SHARE_ENUM_ITEMS": 5000,
    "MAX_API_JSON_BYTES": 4_194_304,
}


def _effective_int(local_val: int, name: str) -> int:
    baseline = _MODEL_BASELINES[name]
    if local_val != baseline:
        return local_val
    return int(getattr(models, name, local_val))


class BaiduProvider:
    """Async Baidu Netdisk provider implementing CloudProvider (§5.5)."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        credential_store: CredentialStore,
        config_reader: ProviderConfigReader,
        recognizer: ShareRecognizer | None = None,
    ) -> None:
        self._session = session
        self._credential_store = credential_store
        self._config_reader = config_reader
        self._recognizer: ShareRecognizer = recognizer or _resolve_default_recognizer()
        self._refresh_lock = asyncio.Lock()

    @property
    def spec(self) -> ProviderSpec:
        return BAIDU_SPEC

    @property
    def recognizer(self) -> ShareRecognizer:
        return self._recognizer

    def validate_transfer_mode(self, *, no_subdir: bool) -> None:
        return None

    def _read_client_credentials(self) -> tuple[str, str]:
        settings = self._config_reader.get_provider_settings(BAIDU_SPEC.provider_id)
        client_id = (
            settings.get("client_id")
            or settings.get("baidu_client_id")
            or settings.get("BAIDU_CLIENT_ID")
            or ""
        ).strip()
        client_secret = (
            settings.get("client_secret")
            or settings.get("baidu_client_secret")
            or settings.get("BAIDU_CLIENT_SECRET")
            or ""
        ).strip()
        return client_id, client_secret

    def get_oauth_authorize_url(self) -> str | None:
        client_id, _ = self._read_client_credentials()
        if not client_id:
            return None
        encoded_id = quote(client_id, safe="")
        return (
            f"{_OAUTH_AUTHORIZE_URL}?response_type=code"
            f"&client_id={encoded_id}&redirect_uri=oob&scope=basic,netdisk"
        )

    async def get_account_status(self) -> ProviderAccountStatus:
        cred = await self._credential_store.get_credential(BAIDU_SPEC.provider_id)
        if cred is None or not cred.access_token.strip() or not cred.account_binding_id.strip():
            client_id, client_secret = self._read_client_credentials()
            msg = (
                "尚未完成百度网盘 OAuth 授权"
                if (client_id and client_secret)
                else "尚未配置百度网盘应用凭证（Client ID / Secret）"
            )
            return ProviderAccountStatus(
                provider_id=BAIDU_SPEC.provider_id,
                authorized=False,
                account_binding_id=None,
                account_label="",
                auth_mode_used=AuthMode.OAUTH_CODE.value,
                updated_at=cred.updated_at if cred is not None else None,
                message=msg,
            )

        extra = self._parse_extra_json(cred.extra_json)
        label = (
            str(extra.get("netdisk_name") or "").strip()
            or str(extra.get("baidu_name") or "").strip()
            or cred.account_binding_id
        )
        return ProviderAccountStatus(
            provider_id=BAIDU_SPEC.provider_id,
            authorized=True,
            account_binding_id=cred.account_binding_id,
            account_label=label,
            auth_mode_used=AuthMode.OAUTH_CODE.value,
            updated_at=cred.updated_at,
            message="已授权",
        )

    async def get_current_binding_id(self) -> str:
        cred = await self._credential_store.get_credential(BAIDU_SPEC.provider_id)
        if cred is None or not cred.access_token.strip():
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)

        binding = cred.account_binding_id.strip()
        if binding.startswith("baidu:") and len(binding) > len("baidu:"):
            return binding

        # Verify via uinfo if an imported credential lacks account_binding_id
        uinfo = await self._xpan_request("GET", _NAS_URL, params={"method": "uinfo"})
        binding_id, extra_dict = self._extract_uinfo_binding(uinfo)
        latest = await self._credential_store.get_credential(BAIDU_SPEC.provider_id) or cred
        updated = ProviderCredentialRecord(
            provider=BAIDU_SPEC.provider_id,
            access_token=latest.access_token,
            refresh_token=latest.refresh_token,
            account_binding_id=binding_id,
            extra_json=json.dumps(extra_dict, ensure_ascii=False),
            updated_at=time.time(),
        )
        await self._credential_store.upsert_credential(updated)
        return binding_id

    async def save_secret_credentials(self, fields: Mapping[str, str]) -> ProviderAccountStatus:
        raise YunBotError(
            ErrorCode.INTERNAL_ERROR,
            "百度网盘采用 OAuth 授权码模式，不支持直接保存静态密钥",
        )

    async def exchange_oauth_code(self, code: str) -> ProviderAccountStatus:
        clean_code = (code or "").strip()
        if not clean_code:
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)

        client_id, client_secret = self._read_client_credentials()
        if not client_id or not client_secret:
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)

        token_payload = await self._oauth_token_request(
            {
                "grant_type": "authorization_code",
                "code": clean_code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": "oob",
            }
        )
        access_token = str(token_payload.get("access_token") or "").strip()
        refresh_token = str(token_payload.get("refresh_token") or "").strip()
        if not access_token or not refresh_token:
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)

        uinfo = await self._raw_xpan_call(
            "GET",
            _NAS_URL,
            params={"method": "uinfo", "access_token": access_token},
        )
        errno = _parse_errno(uinfo)
        if errno != 0:
            if errno in _AUTH_EXPIRED_ERRNOS:
                raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
            raise self._map_xpan_error(errno, operation="uinfo")

        binding_id, extra_dict = self._extract_uinfo_binding(uinfo)
        now = time.time()
        record = ProviderCredentialRecord(
            provider=BAIDU_SPEC.provider_id,
            access_token=access_token,
            refresh_token=refresh_token,
            account_binding_id=binding_id,
            extra_json=json.dumps(extra_dict, ensure_ascii=False),
            updated_at=now,
        )
        await self._credential_store.upsert_credential(record)

        label = (
            str(extra_dict.get("netdisk_name") or "").strip()
            or str(extra_dict.get("baidu_name") or "").strip()
            or binding_id
        )
        return ProviderAccountStatus(
            provider_id=BAIDU_SPEC.provider_id,
            authorized=True,
            account_binding_id=binding_id,
            account_label=label,
            auth_mode_used=AuthMode.OAUTH_CODE.value,
            updated_at=now,
            message="百度网盘授权成功",
        )

    async def start_interactive_auth(self) -> InteractiveAuthStart:
        raise YunBotError(
            ErrorCode.INTERNAL_ERROR,
            "百度网盘采用 OAuth 授权码模式，不支持设备码交互登录",
        )

    async def poll_interactive_auth(self) -> InteractiveAuthPollResult:
        raise YunBotError(
            ErrorCode.INTERNAL_ERROR,
            "百度网盘采用 OAuth 授权码模式，不支持设备码轮询",
        )

    async def cancel_interactive_auth(self) -> None:
        return None

    async def keepalive(self) -> None:
        return None

    async def close(self) -> None:
        # Shared application ClientSession is owned and closed by app.py.
        return None

    async def prepare_task_dir(self, task_dir_path: str) -> str:
        norm_path = validate_save_path(task_dir_path)
        payload = await self._xpan_request(
            "POST",
            _FILE_URL,
            params={"method": "create"},
            data={"path": norm_path, "isdir": "1", "rtype": "0"},
        )
        errno = _parse_errno(payload)
        if errno in (0, -8):
            return norm_path
        raise self._map_xpan_error(errno, operation="create")

    async def transfer(
        self,
        share: ShareLinkInfo,
        target_dir: str,
        *,
        task_id: str = "",
        collect_items: bool = False,
        on_items_batch: ItemsBatchCallback | None = None,
        on_remote_task: RemoteTaskCallback | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> TransferOutcome:
        if share.provider_id != BAIDU_SPEC.provider_id:
            raise YunBotError(ErrorCode.INVALID_LINK)

        norm_target_dir = validate_save_path(target_dir)
        raw_surl = (share.external_id or "").strip()
        if not raw_surl and share.url:
            recognized = self._recognizer.recognize(share.url)
            if recognized is not None:
                raw_surl = recognized.external_id
        if not raw_surl:
            raise YunBotError(ErrorCode.INVALID_LINK)
        surl = _normalize_surl(raw_surl, share.url)

        sekey = await self._verify_share(surl, share.code or "")

        target_dir_prepared = False
        succeeded_count = 0
        failed_count = 0
        total_discovered = 0
        truncated_by_limit = False
        uncertain = False
        outcome_error_code: ErrorCode | None = None
        outcome_error_message: str | None = None
        share_title = f"百度分享_{surl}"

        try:
            await self.prepare_task_dir(norm_target_dir)
            target_dir_prepared = True

            page = 1
            share_id: str | None = None
            uk: str | None = None
            previous_page_ids: tuple[str, ...] | None = None
            processed_candidates = 0

            while True:
                share_page_size = _effective_int(BAIDU_SHARE_PAGE_SIZE, "BAIDU_SHARE_PAGE_SIZE")
                max_enum_items = _effective_int(MAX_SHARE_ENUM_ITEMS, "MAX_SHARE_ENUM_ITEMS")
                transfer_batch_size = _effective_int(
                    BAIDU_TRANSFER_BATCH_SIZE, "BAIDU_TRANSFER_BATCH_SIZE"
                )

                list_payload = await self._xpan_request(
                    "GET",
                    _SHARE_URL,
                    params={
                        "method": "list",
                        "shorturl": surl,
                        "root": 1,
                        "page": page,
                        "num": share_page_size,
                        "sekey": sekey,
                    },
                )
                list_errno = _parse_errno(list_payload)
                if list_errno != 0:
                    raise self._map_xpan_error(list_errno, operation="list")

                if share_id is None or uk is None:
                    raw_sid = list_payload.get("shareid")
                    if raw_sid is None:
                        raw_sid = list_payload.get("share_id")
                    share_id = _string_id(raw_sid)
                    uk = _string_id(list_payload.get("uk"))

                raw_title = list_payload.get("title")
                if isinstance(raw_title, str) and raw_title.strip():
                    share_title = raw_title.strip()

                raw_items = list_payload.get("list")
                if not isinstance(raw_items, list):
                    raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘分享列表结构异常")

                if not raw_items:
                    break

                if share_id is None or uk is None:
                    raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘分享响应缺少 shareid/uk")

                page_items = [self._parse_share_item(item) for item in raw_items]
                page_ids = tuple(item.fs_id for item in page_items)
                if page_ids and page_ids == previous_page_ids:
                    break
                previous_page_ids = page_ids

                if page == 1 and share_title == f"百度分享_{surl}" and page_items:
                    share_title = page_items[0].name

                total_discovered += len(page_items)
                budget = max_enum_items - processed_candidates
                if len(page_items) > budget:
                    truncated_by_limit = True
                    page_items = page_items[: max(0, budget)]

                has_more_flag = list_payload.get("has_more")
                has_more = (
                    bool(has_more_flag) and has_more_flag not in (0, "0", False)
                    if "has_more" in list_payload
                    else len(raw_items) >= share_page_size
                )

                stop_batches = False
                page_consumed = 0
                for batch in _batched(page_items, transfer_batch_size):
                    processed_candidates += len(batch)
                    page_consumed += len(batch)
                    try:
                        (
                            batch_ok,
                            batch_fail,
                            batch_uncertain,
                            batch_err,
                        ) = await self._execute_transfer_batch(
                            batch=batch,
                            target_dir=norm_target_dir,
                            share_id=share_id,
                            uk=uk,
                            sekey=sekey,
                            collect_items=collect_items,
                            on_items_batch=on_items_batch,
                        )
                    except (TimeoutError, aiohttp.ClientError) as exc:
                        logger.warning(
                            "Baidu transfer batch uncertain due to network/timeout (task=%s): %s",
                            task_id,
                            redact_sensitive_text(str(exc)),
                        )
                        uncertain = True
                        failed_count += len(batch) + (len(page_items) - page_consumed)
                        outcome_error_code = outcome_error_code or ErrorCode.INTERNAL_ERROR
                        outcome_error_message = outcome_error_message or format_error_message(
                            ErrorCode.INTERNAL_ERROR, task_id=task_id
                        )
                        stop_batches = True
                        break
                    except YunBotError as exc:
                        if succeeded_count == 0 and not uncertain:
                            raise
                        failed_count += len(batch) + (len(page_items) - page_consumed)
                        outcome_error_code = outcome_error_code or exc.code
                        outcome_error_message = outcome_error_message or exc.user_message
                        stop_batches = True
                        break

                    succeeded_count += batch_ok
                    failed_count += batch_fail
                    if batch_uncertain:
                        uncertain = True
                        failed_count += len(page_items) - page_consumed
                        stop_batches = True
                    if batch_err is not None and outcome_error_code is None:
                        outcome_error_code = batch_err

                    if on_progress is not None:
                        await on_progress(
                            share_title or "正在转存",
                            succeeded_count + failed_count,
                            total_discovered,
                        )

                    if stop_batches:
                        break

                if stop_batches:
                    break

                if truncated_by_limit:
                    break

                if processed_candidates >= max_enum_items:
                    if has_more:
                        truncated_by_limit = True
                    break

                if not has_more:
                    break
                page += 1

        except YunBotError:
            if target_dir_prepared and not collect_items and succeeded_count == 0 and not uncertain:
                await self._best_effort_delete_dir(norm_target_dir)
            raise
        except (TimeoutError, aiohttp.ClientError) as exc:
            # Pre-batch HTTP timeout/network failure (during prepare_task_dir or share?method=list)
            if succeeded_count == 0 and not uncertain:
                if target_dir_prepared and not collect_items:
                    await self._best_effort_delete_dir(norm_target_dir)
                raise YunBotError(
                    ErrorCode.INTERNAL_ERROR,
                    format_error_message(ErrorCode.INTERNAL_ERROR, task_id=task_id),
                    task_id=task_id,
                ) from exc
            failed_count = max(failed_count, total_discovered - succeeded_count)
            outcome_error_code = outcome_error_code or ErrorCode.INTERNAL_ERROR
            outcome_error_message = outcome_error_message or format_error_message(
                ErrorCode.INTERNAL_ERROR, task_id=task_id
            )

        if target_dir_prepared and not collect_items and succeeded_count == 0 and not uncertain:
            await self._best_effort_delete_dir(norm_target_dir)

        if truncated_by_limit and outcome_error_code is None:
            outcome_error_code = ErrorCode.ENUM_LIMIT_EXCEEDED
            outcome_error_message = format_error_message(ErrorCode.ENUM_LIMIT_EXCEEDED)

        if (failed_count > 0 or uncertain) and outcome_error_code is None:
            if succeeded_count > 0:
                outcome_error_code = ErrorCode.TRANSFER_PARTIAL
                outcome_error_message = format_error_message(
                    ErrorCode.TRANSFER_PARTIAL,
                    ok_count=succeeded_count,
                    fail_count=failed_count,
                )
            else:
                outcome_error_code = ErrorCode.INTERNAL_ERROR
                outcome_error_message = format_error_message(
                    ErrorCode.INTERNAL_ERROR, task_id=task_id
                )

        if outcome_error_code is not None and outcome_error_message is None:
            outcome_error_message = format_error_message(
                outcome_error_code,
                provider_name=BAIDU_SPEC.display_name,
                ok_count=succeeded_count,
                fail_count=failed_count,
                task_id=task_id,
            )

        return TransferOutcome(
            share_title=share_title,
            succeeded_count=succeeded_count,
            failed_count=failed_count,
            total_discovered=total_discovered,
            truncated_by_limit=truncated_by_limit,
            uncertain=uncertain,
            error_code=outcome_error_code,
            error_message=outcome_error_message,
        )

    async def delete_directory(
        self,
        task_dir_path: str,
        *,
        expected_binding_id: str | None = None,
    ) -> None:
        norm_dir = validate_save_path(task_dir_path)
        active_binding = expected_binding_id or (await self.get_current_binding_id())
        filelist_json = json.dumps([norm_dir], ensure_ascii=False)

        payload = await self._xpan_request(
            "POST",
            _FILE_URL,
            params={"method": "filemanager", "opera": "delete"},
            data={"async": "0", "filelist": filelist_json},
            expected_binding_id=active_binding,
        )
        if self._is_filemanager_delete_ok(payload):
            return

        if self._is_filemanager_sync_limit(payload):
            retry_payload = await self._xpan_request(
                "POST",
                _FILE_URL,
                params={"method": "filemanager", "opera": "delete"},
                data={"async": "1", "filelist": filelist_json},
                expected_binding_id=active_binding,
            )
            if self._is_filemanager_delete_ok(retry_payload):
                return
            errno = _parse_errno(retry_payload)
            raise self._map_delete_error(errno)

        errno = _parse_errno(payload)
        raise self._map_delete_error(errno)

    async def delete_items(
        self,
        base_save_path: str,
        items: Sequence[TransferItemRecord],
        *,
        expected_binding_id: str | None = None,
        deleted_ids_sink: list[str] | None = None,
    ) -> DeleteItemsOutcome:
        norm_base = validate_save_path(base_save_path)
        if not items:
            return DeleteItemsOutcome()

        normalized_items: list[tuple[TransferItemRecord, str, int]] = []
        for item in items:
            norm_item_path = validate_direct_item_path(item.path, norm_base)
            raw_id = item.item_id.strip()
            if not raw_id.isdigit():
                raise ValueError(f"Invalid Baidu fs_id for item: {item.item_id!r}")
            normalized_items.append((item, norm_item_path, int(raw_id)))

        active_binding = expected_binding_id or (await self.get_current_binding_id())

        deleted_ids: list[str] = []
        skipped_items: list[TransferItemRecord] = []
        failed_items: list[TransferItemRecord] = []
        verified_to_delete: list[tuple[TransferItemRecord, str]] = []

        p_base = PurePosixPath(norm_base)

        filemetas_batch_size = _effective_int(
            BAIDU_FILEMETAS_BATCH_SIZE, "BAIDU_FILEMETAS_BATCH_SIZE"
        )
        for meta_batch in _batched(normalized_items, filemetas_batch_size):
            fsids_json = json.dumps([fsid for _, _, fsid in meta_batch])
            try:
                meta_payload = await self._xpan_request(
                    "GET",
                    _MULTIMEDIA_URL,
                    params={"method": "filemetas", "fsids": fsids_json, "dlink": 0},
                    expected_binding_id=active_binding,
                )
            except (ProviderAuthInvalidError, BindingMismatchError, ApiResponseTooLargeError):
                raise
            except (TimeoutError, aiohttp.ClientError, YunBotError) as exc:
                logger.warning(
                    "Baidu filemetas batch failed during delete_items: %s",
                    redact_sensitive_text(str(exc)),
                )
                failed_items.extend(rec for rec, _, _ in meta_batch)
                continue

            errno = _parse_errno(meta_payload)
            if errno in (-9, 31066):
                raw_meta_list: list[Any] = []
            elif errno == 0:
                maybe_list = meta_payload.get("list")
                if not isinstance(maybe_list, list):
                    failed_items.extend(rec for rec, _, _ in meta_batch)
                    continue
                raw_meta_list = maybe_list
            else:
                failed_items.extend(rec for rec, _, _ in meta_batch)
                continue

            metas_by_fsid: dict[str, Mapping[str, Any]] = {}
            for meta in raw_meta_list:
                if isinstance(meta, Mapping):
                    fid = _string_id(meta.get("fs_id"))
                    if fid is not None:
                        metas_by_fsid[fid] = meta

            for rec, expected_norm_path, fsid_int in meta_batch:
                meta = metas_by_fsid.get(str(fsid_int))
                if meta is None:
                    deleted_ids.append(rec.item_id)
                    if deleted_ids_sink is not None:
                        deleted_ids_sink.append(rec.item_id)
                    continue

                cloud_raw_path = meta.get("path")
                if not isinstance(cloud_raw_path, str) or not cloud_raw_path.strip():
                    skipped_items.append(rec)
                    continue
                try:
                    cloud_norm_path = normalize_posix_path(cloud_raw_path, allow_root=False)
                except ValueError:
                    skipped_items.append(rec)
                    continue

                p_cloud = PurePosixPath(cloud_norm_path)
                if (
                    cloud_norm_path == norm_base
                    or not p_cloud.is_relative_to(p_base)
                    or cloud_norm_path != expected_norm_path
                ):
                    skipped_items.append(rec)
                    continue

                verified_to_delete.append((rec, expected_norm_path))

        for del_batch in _batched(verified_to_delete, filemetas_batch_size):
            await self._delete_verified_batch(
                del_batch,
                deleted_ids=deleted_ids,
                failed_items=failed_items,
                expected_binding_id=active_binding,
                deleted_ids_sink=deleted_ids_sink,
            )

        return DeleteItemsOutcome(
            deleted_ids=tuple(deleted_ids),
            skipped_items=tuple(skipped_items),
            failed_items=tuple(failed_items),
        )

    # ==========================================================================
    # Internal Helpers
    # ==========================================================================

    async def _verify_share(self, surl: str, pwd: str) -> str:
        payload = await self._xpan_request(
            "POST",
            _SHARE_URL,
            params={"method": "verify", "surl": surl},
            data={"pwd": pwd.strip()},
        )
        errno = _parse_errno(payload)
        if errno != 0:
            raise self._map_xpan_error(errno, operation="verify")
        randsk = payload.get("randsk")
        if not isinstance(randsk, str) or not randsk.strip():
            raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘校验响应缺少有效的 randsk")
        return unquote(randsk)

    async def _execute_transfer_batch(
        self,
        *,
        batch: Sequence[_ShareSourceItem],
        target_dir: str,
        share_id: str,
        uk: str,
        sekey: str,
        collect_items: bool,
        on_items_batch: ItemsBatchCallback | None,
    ) -> tuple[int, int, bool, ErrorCode | None]:
        """Execute one transfer batch (FORBIDDEN to pass `ondup`) and resolve -n items."""
        fsidlist_json = json.dumps([int(item.fs_id) for item in batch])
        payload = await self._xpan_request(
            "POST",
            _SHARE_URL,
            params={
                "method": "transfer",
                "shareid": share_id,
                "from": uk,
                "sekey": sekey,
            },
            data={
                "fsidlist": fsidlist_json,
                "path": target_dir,
            },
        )
        errno = _parse_errno(payload)
        if errno != 0:
            raise self._map_xpan_error(errno, operation="transfer")

        expected_to_paths, per_item_failed, per_item_err = self._extract_batch_to_paths(
            payload=payload,
            batch=batch,
            target_dir=target_dir,
        )

        if not collect_items:
            return len(expected_to_paths), per_item_failed, False, per_item_err

        if not expected_to_paths:
            return 0, per_item_failed, False, per_item_err

        # -n mode: immediately query target_dir ordered by time DESC (up to BAIDU_LIST_MAX_PAGES)
        try:
            matched_entries, all_matched = await self._resolve_transferred_entries(
                target_dir=target_dir,
                expected_to_paths=expected_to_paths,
            )
        except ApiResponseTooLargeError:
            raise
        except Exception as exc:
            logger.warning(
                "Baidu -n file?method=list failed after transfer succeeded: %s",
                redact_sensitive_text(str(exc)),
            )
            return (
                0,
                len(expected_to_paths) + per_item_failed,
                True,
                ErrorCode.INTERNAL_ERROR,
            )

        if matched_entries and on_items_batch is not None:
            # Propagate callback exceptions immediately so remaining batches abort!
            await on_items_batch(matched_entries)

        if not all_matched:
            unmatched = len(expected_to_paths) - len(matched_entries)
            return (
                len(matched_entries),
                per_item_failed + max(0, unmatched),
                True,
                per_item_err or ErrorCode.TRANSFER_PARTIAL,
            )

        return len(matched_entries), per_item_failed, False, per_item_err

    def _extract_batch_to_paths(
        self,
        *,
        payload: Mapping[str, Any],
        batch: Sequence[_ShareSourceItem],
        target_dir: str,
    ) -> tuple[list[str], int, ErrorCode | None]:
        extra = payload.get("extra")
        raw_list = extra.get("list") if isinstance(extra, Mapping) else None

        if not isinstance(raw_list, list) or len(raw_list) == 0:
            derived = [
                validate_direct_item_path(f"{target_dir}/{item.name}", target_dir) for item in batch
            ]
            return derived, 0, None

        valid_paths: list[str] = []
        first_item_err: ErrorCode | None = None
        for entry in raw_list:
            if isinstance(entry, Mapping):
                to_val = entry.get("to")
                if isinstance(to_val, str) and to_val.strip():
                    norm_to = validate_direct_item_path(to_val, target_dir)
                    valid_paths.append(norm_to)
                    continue
                raw_item_errno = entry.get("errno")
                if isinstance(raw_item_errno, int) and not isinstance(raw_item_errno, bool):
                    if raw_item_errno in _QUOTA_ERRNOS and first_item_err is None:
                        first_item_err = ErrorCode.QUOTA_EXCEEDED

        failed = max(0, len(batch) - len(valid_paths))
        if failed > 0 and first_item_err is None:
            first_item_err = ErrorCode.TRANSFER_PARTIAL if valid_paths else ErrorCode.INTERNAL_ERROR
        return valid_paths, failed, first_item_err

    async def _resolve_transferred_entries(
        self,
        *,
        target_dir: str,
        expected_to_paths: Sequence[str],
    ) -> tuple[list[TransferredEntry], bool]:
        remaining: set[str] = set(expected_to_paths)
        matched_by_path: dict[str, TransferredEntry] = {}

        max_pages = _effective_int(BAIDU_LIST_MAX_PAGES, "BAIDU_LIST_MAX_PAGES")
        list_page_size = _effective_int(BAIDU_LIST_PAGE_SIZE, "BAIDU_LIST_PAGE_SIZE")

        for page in range(1, max_pages + 1):
            if not remaining:
                break

            start = (page - 1) * list_page_size
            list_payload = await self._xpan_request(
                "GET",
                _FILE_URL,
                params={
                    "method": "list",
                    "dir": target_dir,
                    "order": "time",
                    "desc": 1,
                    "start": start,
                    "limit": list_page_size,
                },
            )
            errno = _parse_errno(list_payload)
            if errno != 0:
                raise self._map_xpan_error(errno, operation="file_list")

            raw_entries = list_payload.get("list")
            if not isinstance(raw_entries, list) or not raw_entries:
                break

            for raw_entry in raw_entries:
                if not isinstance(raw_entry, Mapping):
                    continue
                fs_id = _string_id(raw_entry.get("fs_id"))
                if fs_id is None or not fs_id.isdigit():
                    continue

                raw_path = raw_entry.get("path")
                raw_name = raw_entry.get("server_filename")
                candidate_path_str: str | None = None
                if isinstance(raw_path, str) and raw_path.strip():
                    candidate_path_str = raw_path
                elif isinstance(raw_name, str) and raw_name.strip():
                    candidate_path_str = f"{target_dir}/{raw_name.strip()}"
                if candidate_path_str is None:
                    continue

                try:
                    norm_path = validate_direct_item_path(candidate_path_str, target_dir)
                except ValueError:
                    continue

                if norm_path in remaining:
                    name = (
                        raw_name.strip()
                        if isinstance(raw_name, str) and raw_name.strip()
                        else PurePosixPath(norm_path).name
                    )
                    matched_by_path[norm_path] = TransferredEntry(
                        item_id=fs_id,
                        path=norm_path,
                        name=name,
                        is_dir=_as_bool_isdir(raw_entry.get("isdir", 0)),
                    )
                    remaining.discard(norm_path)
                    if not remaining:
                        break

        ordered_entries: list[TransferredEntry] = []
        seen_paths: set[str] = set()
        for path in expected_to_paths:
            if path in matched_by_path and path not in seen_paths:
                ordered_entries.append(matched_by_path[path])
                seen_paths.add(path)

        return ordered_entries, len(remaining) == 0

    async def _delete_verified_batch(
        self,
        del_batch: Sequence[tuple[TransferItemRecord, str]],
        *,
        deleted_ids: list[str],
        failed_items: list[TransferItemRecord],
        expected_binding_id: str | None = None,
        deleted_ids_sink: list[str] | None = None,
    ) -> None:
        def _mark_deleted(item_id: str) -> None:
            deleted_ids.append(item_id)
            if deleted_ids_sink is not None:
                deleted_ids_sink.append(item_id)

        filelist_json = json.dumps([path for _, path in del_batch], ensure_ascii=False)
        try:
            payload = await self._xpan_request(
                "POST",
                _FILE_URL,
                params={"method": "filemanager", "opera": "delete"},
                data={"async": "0", "filelist": filelist_json},
                expected_binding_id=expected_binding_id,
            )
        except (ProviderAuthInvalidError, BindingMismatchError, ApiResponseTooLargeError):
            raise
        except (TimeoutError, aiohttp.ClientError, YunBotError) as exc:
            logger.warning(
                "Baidu filemanager delete batch failed: %s",
                redact_sensitive_text(str(exc)),
            )
            failed_items.extend(rec for rec, _ in del_batch)
            return

        top_errno = _parse_errno(payload)
        raw_info = payload.get("info")
        info_by_path: dict[str, int] = {}
        if isinstance(raw_info, list):
            for entry in raw_info:
                if isinstance(entry, Mapping):
                    raw_p = entry.get("path")
                    raw_e = entry.get("errno")
                    if isinstance(raw_p, str) and raw_p.strip() and raw_e is not None:
                        try:
                            norm_p = normalize_posix_path(raw_p, allow_root=False)
                            info_by_path[norm_p] = int(raw_e)
                        except (TypeError, ValueError):
                            continue

        if not info_by_path and top_errno in _DELETE_SYNC_LIMIT_ERRNOS:
            try:
                payload = await self._xpan_request(
                    "POST",
                    _FILE_URL,
                    params={"method": "filemanager", "opera": "delete"},
                    data={"async": "1", "filelist": filelist_json},
                    expected_binding_id=expected_binding_id,
                )
                top_errno = _parse_errno(payload)
            except (ProviderAuthInvalidError, BindingMismatchError, ApiResponseTooLargeError):
                raise
            except (TimeoutError, aiohttp.ClientError, YunBotError) as exc:
                logger.warning(
                    "Baidu filemanager async=1 delete fallback failed: %s",
                    redact_sensitive_text(str(exc)),
                )
                failed_items.extend(rec for rec, _ in del_batch)
                return

        if info_by_path:
            sync_retry_subset: list[tuple[TransferItemRecord, str]] = []
            for rec, norm_path in del_batch:
                item_errno = info_by_path.get(norm_path)
                if item_errno is None:
                    if top_errno in _DELETE_IDEMPOTENT_ERRNOS:
                        _mark_deleted(rec.item_id)
                    else:
                        failed_items.append(rec)
                elif item_errno in _DELETE_IDEMPOTENT_ERRNOS:
                    _mark_deleted(rec.item_id)
                elif item_errno in _DELETE_SYNC_LIMIT_ERRNOS:
                    sync_retry_subset.append((rec, norm_path))
                else:
                    failed_items.append(rec)

            if sync_retry_subset:
                retry_json = json.dumps([path for _, path in sync_retry_subset], ensure_ascii=False)
                try:
                    retry_payload = await self._xpan_request(
                        "POST",
                        _FILE_URL,
                        params={"method": "filemanager", "opera": "delete"},
                        data={"async": "1", "filelist": retry_json},
                        expected_binding_id=expected_binding_id,
                    )
                    if self._is_filemanager_delete_ok(retry_payload):
                        for rec, _ in sync_retry_subset:
                            _mark_deleted(rec.item_id)
                    else:
                        failed_items.extend(rec for rec, _ in sync_retry_subset)
                except (ProviderAuthInvalidError, BindingMismatchError, ApiResponseTooLargeError):
                    raise
                except (TimeoutError, aiohttp.ClientError, YunBotError):
                    failed_items.extend(rec for rec, _ in sync_retry_subset)
            return

        if top_errno in _DELETE_IDEMPOTENT_ERRNOS:
            for rec, _ in del_batch:
                _mark_deleted(rec.item_id)
        else:
            failed_items.extend(rec for rec, _ in del_batch)

    async def _best_effort_delete_dir(
        self,
        norm_dir: str,
        *,
        expected_binding_id: str | None = None,
    ) -> None:
        try:
            await self.delete_directory(norm_dir, expected_binding_id=expected_binding_id)
        except Exception as exc:
            logger.warning(
                "Best-effort cleanup of empty Baidu task directory %s failed: %s",
                norm_dir,
                redact_sensitive_text(str(exc)),
            )

    async def _xpan_request(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any],
        data: Mapping[str, Any] | None = None,
        expected_binding_id: str | None = None,
    ) -> Mapping[str, Any]:
        cred = await self._credential_store.get_credential(BAIDU_SPEC.provider_id)
        if cred is None or not cred.access_token.strip():
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
        if (
            expected_binding_id is not None
            and cred.account_binding_id.strip() != expected_binding_id
        ):
            raise BindingMismatchError()

        used_token = cred.access_token.strip()
        req_params = dict(params)
        req_params["access_token"] = used_token

        payload = await self._raw_xpan_call(method, url, params=req_params, data=data)
        errno = _parse_errno(payload)
        if errno not in _AUTH_EXPIRED_ERRNOS:
            return payload

        refreshed = await self._refresh_access_token(
            failed_access_token=used_token,
            expected_binding_id=expected_binding_id,
        )
        if (
            expected_binding_id is not None
            and refreshed.account_binding_id.strip() != expected_binding_id
        ):
            raise BindingMismatchError()
        retry_params = dict(params)
        retry_params["access_token"] = refreshed.access_token
        retry_payload = await self._raw_xpan_call(method, url, params=retry_params, data=data)
        retry_errno = _parse_errno(retry_payload)
        if retry_errno in _AUTH_EXPIRED_ERRNOS:
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
        return retry_payload

    async def _refresh_access_token(
        self,
        *,
        failed_access_token: str,
        expected_binding_id: str | None = None,
    ) -> ProviderCredentialRecord:
        async with self._refresh_lock:
            current = await self._credential_store.get_credential(BAIDU_SPEC.provider_id)
            if current is None:
                raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
            if (
                expected_binding_id is not None
                and current.account_binding_id.strip() != expected_binding_id
            ):
                raise BindingMismatchError()

            # Deduplicate concurrent refreshes only when still bound to the same account
            if current.access_token.strip() and current.access_token.strip() != failed_access_token:
                return current

            refresh_tok = current.refresh_token.strip()
            if not refresh_tok:
                raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)

            client_id, client_secret = self._read_client_credentials()
            if not client_id or not client_secret:
                raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)

            token_payload = await self._oauth_token_request(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_tok,
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            )
            new_access = str(token_payload.get("access_token") or "").strip()
            if not new_access:
                raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
            new_refresh = str(token_payload.get("refresh_token") or "").strip() or refresh_tok

            binding_id = current.account_binding_id.strip()
            extra_json = current.extra_json or "{}"
            if not (binding_id.startswith("baidu:") and len(binding_id) > len("baidu:")):
                uinfo = await self._raw_xpan_call(
                    "GET",
                    _NAS_URL,
                    params={"method": "uinfo", "access_token": new_access},
                )
                if _parse_errno(uinfo) != 0:
                    raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
                binding_id, extra_dict = self._extract_uinfo_binding(uinfo)
                extra_json = json.dumps(extra_dict, ensure_ascii=False)

            if expected_binding_id is not None and binding_id != expected_binding_id:
                raise BindingMismatchError()

            latest = await self._credential_store.get_credential(BAIDU_SPEC.provider_id)
            if expected_binding_id is not None and (
                latest is None or latest.account_binding_id.strip() != expected_binding_id
            ):
                raise BindingMismatchError()
            if (
                latest is not None
                and latest.account_binding_id.strip()
                and latest.account_binding_id.strip() != binding_id
            ):
                raise BindingMismatchError()

            updated = ProviderCredentialRecord(
                provider=BAIDU_SPEC.provider_id,
                access_token=new_access,
                refresh_token=new_refresh,
                account_binding_id=binding_id,
                extra_json=extra_json,
                updated_at=time.time(),
            )
            await self._credential_store.upsert_credential(updated)
            return updated

    async def _oauth_token_request(self, params: Mapping[str, str]) -> Mapping[str, Any]:
        timeout = aiohttp.ClientTimeout(total=API_REQUEST_TIMEOUT_SECONDS)
        try:
            async with self._session.get(
                _OAUTH_TOKEN_URL,
                params=params,
                headers=_OAUTH_HEADERS,
                timeout=timeout,
            ) as resp:
                if resp.status == 429:
                    raise ProviderRateLimitedError(BAIDU_SPEC.display_name)
                max_json = _effective_int(MAX_API_JSON_BYTES, "MAX_API_JSON_BYTES")
                try:
                    payload = await read_bounded_json(resp, max_bytes=max_json)
                except json.JSONDecodeError as exc:
                    if resp.status >= 400:
                        raise ProviderAuthInvalidError(BAIDU_SPEC.display_name) from exc
                    raise YunBotError(
                        ErrorCode.INTERNAL_ERROR, "百度网盘 OAuth 响应 JSON 解析失败"
                    ) from exc

                if not isinstance(payload, Mapping):
                    raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
                if "error" in payload or resp.status >= 400:
                    raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
                return payload
        except (TimeoutError, aiohttp.ClientError) as exc:
            raise YunBotError(
                ErrorCode.INTERNAL_ERROR,
                "连接百度网盘开放平台 OAuth 服务失败，请稍后重试",
            ) from exc

    async def _raw_xpan_call(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, Any],
        data: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        timeout = aiohttp.ClientTimeout(total=API_REQUEST_TIMEOUT_SECONDS)
        req_fn = self._session.get if method == "GET" else self._session.post
        kwargs: dict[str, Any] = {
            "params": params,
            "headers": _XPAN_HEADERS,
            "timeout": timeout,
        }
        if method != "GET" and data is not None:
            kwargs["data"] = data

        async with req_fn(url, **kwargs) as resp:
            if resp.status == 429:
                raise ProviderRateLimitedError(BAIDU_SPEC.display_name)
            max_json = _effective_int(MAX_API_JSON_BYTES, "MAX_API_JSON_BYTES")
            try:
                payload = await read_bounded_json(resp, max_bytes=max_json)
            except json.JSONDecodeError as exc:
                raise YunBotError(
                    ErrorCode.INTERNAL_ERROR,
                    f"百度网盘接口响应无法解析 (HTTP {resp.status})",
                ) from exc

            if resp.status >= 500:
                raise aiohttp.ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=resp.status,
                    message="Baidu xpan 5xx error",
                )
            if not isinstance(payload, Mapping):
                raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘返回了非对象 JSON 结构")
            if resp.status >= 400 and "errno" not in payload:
                raise YunBotError(
                    ErrorCode.INTERNAL_ERROR,
                    f"百度网盘请求返回异常状态码 (HTTP {resp.status})",
                )
            return payload

    @staticmethod
    def _extract_uinfo_binding(payload: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        raw_uk = payload.get("uk")
        if isinstance(raw_uk, bool) or raw_uk is None:
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)
        try:
            uk_int = int(raw_uk)
        except (TypeError, ValueError) as exc:
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name) from exc
        if uk_int <= 0:
            raise ProviderAuthInvalidError(BAIDU_SPEC.display_name)

        netdisk_name = str(payload.get("netdisk_name") or "").strip()
        baidu_name = str(payload.get("baidu_name") or "").strip()
        extra_dict: dict[str, Any] = {
            "uk": uk_int,
            "netdisk_name": netdisk_name,
            "baidu_name": baidu_name,
        }
        vip_type = payload.get("vip_type")
        if isinstance(vip_type, int) and not isinstance(vip_type, bool):
            extra_dict["vip_type"] = vip_type

        return f"baidu:{uk_int}", extra_dict

    @staticmethod
    def _parse_extra_json(raw: str) -> dict[str, Any]:
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}

    @staticmethod
    def _parse_share_item(raw_item: Any) -> _ShareSourceItem:
        if not isinstance(raw_item, Mapping):
            raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘分享条目结构异常")
        fs_id = _string_id(raw_item.get("fs_id"))
        if fs_id is None or not fs_id.isascii() or not fs_id.isdigit():
            raise YunBotError(ErrorCode.INTERNAL_ERROR, "百度网盘分享条目缺少合法的 fs_id")
        raw_name = raw_item.get("server_filename")
        if isinstance(raw_name, str) and raw_name.strip():
            name = raw_name.strip()
        else:
            raw_path = raw_item.get("path")
            name = (
                PurePosixPath(raw_path).name
                if isinstance(raw_path, str) and raw_path.strip()
                else fs_id
            )
        return _ShareSourceItem(
            fs_id=fs_id,
            name=name,
            is_dir=_as_bool_isdir(raw_item.get("isdir", 0)),
        )

    @staticmethod
    def _is_filemanager_delete_ok(payload: Mapping[str, Any]) -> bool:
        errno = _parse_errno(payload)
        raw_info = payload.get("info")
        if isinstance(raw_info, list) and raw_info:
            item_errnos: list[int] = []
            for entry in raw_info:
                if not isinstance(entry, Mapping):
                    return False
                try:
                    item_errnos.append(int(entry.get("errno")))  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return False
            if all(code in _DELETE_IDEMPOTENT_ERRNOS for code in item_errnos):
                return errno in _DELETE_IDEMPOTENT_ERRNOS or errno in (2, 12)
            return False
        return errno in _DELETE_IDEMPOTENT_ERRNOS

    @staticmethod
    def _is_filemanager_sync_limit(payload: Mapping[str, Any]) -> bool:
        errno = _parse_errno(payload)
        if errno in _DELETE_SYNC_LIMIT_ERRNOS:
            return True
        raw_info = payload.get("info")
        if isinstance(raw_info, list):
            for entry in raw_info:
                if isinstance(entry, Mapping):
                    try:
                        if int(entry.get("errno")) in _DELETE_SYNC_LIMIT_ERRNOS:  # type: ignore[arg-type]
                            return True
                    except (TypeError, ValueError):
                        continue
        return False

    @staticmethod
    def _map_xpan_error(errno: int, *, operation: str) -> YunBotError:
        if errno in _AUTH_EXPIRED_ERRNOS:
            return ProviderAuthInvalidError(BAIDU_SPEC.display_name)
        if errno in _RATE_LIMIT_ERRNOS:
            return ProviderRateLimitedError(BAIDU_SPEC.display_name)
        if operation == "verify":
            if errno in _VERIFY_INVALID_PWD_ERRNOS:
                return ProviderInvalidPasswordError()
            if errno in _VERIFY_SHARE_EXPIRED_ERRNOS:
                return ProviderShareExpiredError()
        if operation in ("list", "transfer") and errno in _SHARE_EXPIRED_ERRNOS:
            return ProviderShareExpiredError()
        if errno in _QUOTA_ERRNOS:
            return ProviderQuotaExceededError(BAIDU_SPEC.display_name)
        return YunBotError(
            ErrorCode.INTERNAL_ERROR,
            f"百度网盘操作失败 ({operation}, errno={errno})",
        )

    @staticmethod
    def _map_delete_error(errno: int) -> YunBotError:
        if errno in _AUTH_EXPIRED_ERRNOS:
            return ProviderAuthInvalidError(BAIDU_SPEC.display_name)
        if errno in _RATE_LIMIT_ERRNOS:
            return ProviderRateLimitedError(BAIDU_SPEC.display_name)
        return YunBotError(
            ErrorCode.DELETE_PARTIAL,
            format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=1),
            remain_count=1,
        )
