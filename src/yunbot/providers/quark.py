"""Quark Netdisk (夸克网盘) provider adapter (§5.4, §5.7).

Protocol baseline verified against:
- `x1ao4/quark-auto-save-x@1c35e969` (`quark_auto_save.py`)
- `OpenListTeam/OpenList@0497ee85` (`drivers/quark_uc/`)

Strict Dependency Boundary:
Does NOT import `storage`, `runtime_config`, `pydantic`, `requests`, or `httpx`.
Uses the injected singleton `aiohttp.ClientSession` (passing `Cookie` per request)
and `CredentialStore` / `ProviderConfigReader` Protocols from `providers/base.py`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.cookies import CookieError, SimpleCookie
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlparse

import aiohttp

from yunbot.models import (
    API_REQUEST_TIMEOUT_SECONDS,
    MAX_SHARE_ENUM_ITEMS,
    MAX_SNAPSHOT_ITEMS_PER_PHASE,
    QUARK_COOKIE_ALLOWED_SUFFIXES,
    QUARK_DETAIL_PAGE_SIZE,
    QUARK_PATH_LIST_BATCH_SIZE,
    QUARK_SAVE_BATCH_SIZE,
    QUARK_TASK_POLL_DELAYS_SECONDS,
    QUARK_TASK_POLL_TIMEOUT_SECONDS,
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
    ProviderNeedPasswordError,
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
    ProviderFieldSpec,
    ProviderSpec,
    RemoteTaskCallback,
    ShareRecognizer,
)

logger = logging.getLogger(__name__)

QUARK_DRIVE_BASE_URL: str = "https://drive-pc.quark.cn"
QUARK_ACCOUNT_INFO_URL: str = "https://pan.quark.cn/account/info"
QUARK_MEMBER_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/member"
QUARK_PATH_LIST_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/file/info/path_list"
QUARK_CREATE_FILE_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/file"
QUARK_SHARE_TOKEN_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/share/sharepage/token"
QUARK_SHARE_DETAIL_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/share/sharepage/detail"
QUARK_SHARE_SAVE_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/share/sharepage/save"
QUARK_TASK_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/task"
QUARK_FILE_SORT_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/file/sort"
QUARK_FILE_DELETE_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/file/delete"
QUARK_FILE_INFO_URL: str = f"{QUARK_DRIVE_BASE_URL}/1/clouddrive/file/info"

_QUARK_REFERER: str = "https://pan.quark.cn/"
_QUARK_ORIGIN: str = "https://pan.quark.cn"
_QUARK_ACCEPT: str = "application/json, text/plain, */*"
_QUARK_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "quark-cloud-drive/2.5.20 Chrome/100.0.4896.160 "
    "Electron/18.3.5.4-b478491100 Safari/537.36 Channel/pckk_other_ch"
)

_FILE_SORT_PAGE_SIZE: int = 100
_FILE_SORT_MAX_PAGES: int = max(1, MAX_SNAPSHOT_ITEMS_PER_PHASE // _FILE_SORT_PAGE_SIZE)

_COOKIE_ATTR_NAMES: frozenset[str] = frozenset(
    {
        "expires",
        "path",
        "comment",
        "domain",
        "max-age",
        "secure",
        "httponly",
        "version",
        "samesite",
        "partitioned",
        "priority",
    }
)

_AUTH_INVALID_CODES: frozenset[int] = frozenset({14001, 31001, 31002})
_PASSWORD_ERROR_CODES: frozenset[int] = frozenset({41008, 41009, 41012})
_SHARE_EXPIRED_CODES: frozenset[int] = frozenset(
    {
        41001,
        41002,
        41003,
        41004,
        41005,
        41006,
        41007,
        41010,
        41011,
        41013,
        41014,
        41015,
    }
)
_QUOTA_ERROR_CODES: frozenset[int] = frozenset({10006, 23009, 23010, 41020, 41025})
_NOT_FOUND_CODES: frozenset[int] = frozenset({404, 23003, 23013})

_ALLOWED_SHARE_HOSTS: frozenset[str] = frozenset({"pan.quark.cn", "quark.cn"})
_SHARE_PATH_RE: re.Pattern[str] = re.compile(r"^/s/([A-Za-z0-9]{6,64})/?$")
_SUB_DIR_FID_RE: re.Pattern[str] = re.compile(r"/([0-9a-fA-F]{32})(?:-|$|/)")
_PASSCODE_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9]{4}$")

QUARK_SPEC = ProviderSpec(
    provider_id="quark",
    display_name="夸克网盘",
    command="quark",
    password_policy=PasswordPolicy.OPTIONAL_TRY_FIRST,
    auth_mode=AuthMode.SECRET_FIELDS,
    secret_fields=(
        ProviderFieldSpec(
            key="cookie",
            label="夸克网页版 Cookie",
            secret=True,
            required=True,
            placeholder="粘贴包含 __pus 与 __puus 的完整 Cookie",
        ),
    ),
    save_path_key="QUARK_SAVE_PATH",
    openlist_path_key="OPENLIST_QUARK_PATH",
    default_save_path="/转存文件",
    default_openlist_path="/quark/转存文件",
    stream_cookie_allowed_suffixes=QUARK_COOKIE_ALLOWED_SUFFIXES,
)


@dataclass(frozen=True, slots=True)
class _ShareItem:
    """Single top-level entry enumerated from Quark sharepage/detail."""

    fid: str
    fid_token: str
    name: str
    is_dir: bool


@dataclass(frozen=True, slots=True)
class _FallbackQuarkShareRecognizer:
    """Built-in pure recognizer fallback when `parsing.QuarkShareRecognizer` is unavailable."""

    @property
    def provider_id(self) -> str:
        return "quark"

    def recognize(self, url: str) -> RecognizedShareUrl | None:
        raw = (url or "").strip()
        if not raw:
            return None
        try:
            parsed = urlparse(raw)
        except ValueError:
            return None

        if parsed.scheme.lower() not in ("http", "https"):
            return None
        host = (parsed.hostname or "").lower()
        if host not in _ALLOWED_SHARE_HOSTS:
            return None

        match = _SHARE_PATH_RE.fullmatch(parsed.path or "")
        if not match:
            return None
        pwd_id = match.group(1)

        embedded_code: str | None = None
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=False)
            for key in ("pwd", "passcode", "code"):
                vals = qs.get(key)
                if vals:
                    candidate = vals[0].strip()
                    if _PASSCODE_RE.fullmatch(candidate):
                        embedded_code = candidate
                        break

        sub_dir_fid = "0"
        if parsed.fragment:
            fids = _SUB_DIR_FID_RE.findall(parsed.fragment)
            if fids:
                sub_dir_fid = fids[-1].lower()

        normalized = f"https://pan.quark.cn/s/{pwd_id}"
        return RecognizedShareUrl(
            provider_id="quark",
            normalized_url=normalized,
            external_id=pwd_id,
            embedded_code=embedded_code,
            sub_dir_fid=sub_dir_fid,
        )


def _parse_cookie_header(raw_cookie: str) -> dict[str, str]:
    """Parse a raw Cookie header string into an ordered name->value dict safely."""
    text = (raw_cookie or "").strip()
    if text.lower().startswith("cookie:"):
        text = text[7:].strip()
    if any(ch in text for ch in ("\r", "\n", "\x00")):
        raise ProviderAuthInvalidError("夸克网盘", "Cookie 包含非法控制字符")

    jar: dict[str, str] = {}
    for segment in text.split(";"):
        part = segment.strip()
        if not part or "=" not in part:
            continue
        raw_k, raw_v = part.split("=", 1)
        key = raw_k.strip()
        val = raw_v.strip()
        if key and key.lower() not in _COOKIE_ATTR_NAMES and val:
            jar[key] = val
    return jar


def _serialize_cookie_jar(jar: Mapping[str, str]) -> str:
    """Serialize an ordered cookie dict back into a standard Cookie header string."""
    return "; ".join(f"{k}={v}" for k, v in jar.items() if k and v)


def _get_set_cookie_headers(headers: Any) -> list[str]:
    """Extract all Set-Cookie header lines across CIMultiDictProxy or plain mappings."""
    if headers is None:
        return []
    getall = getattr(headers, "getall", None)
    if callable(getall):
        return [str(v) for v in getall("Set-Cookie", []) if v]
    raw = headers.get("Set-Cookie") or headers.get("set-cookie")
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(v) for v in raw if v]
    return [str(raw)] if raw else []


def _extract_set_cookie_updates(set_cookie_headers: Sequence[str]) -> dict[str, str]:
    """Extract updated non-empty cookie pairs (e.g. __puus / __pus) from Set-Cookie headers."""
    updates: dict[str, str] = {}
    for raw_header in set_cookie_headers:
        if not raw_header or any(ch in raw_header for ch in ("\r", "\n", "\x00")):
            continue
        parsed_any = False
        try:
            sc = SimpleCookie()
            sc.load(raw_header)
            for key, morsel in sc.items():
                parsed_any = True
                max_age = str(morsel["max-age"] or "").strip()
                if max_age == "0" or not morsel.value:
                    continue
                updates[key] = morsel.value
        except CookieError:
            parsed_any = False

        if not parsed_any:
            first_seg = raw_header.split(";", 1)[0].strip()
            if "=" in first_seg:
                raw_k, raw_v = first_seg.split("=", 1)
                key = raw_k.strip()
                val = raw_v.strip()
                if key and key.lower() not in _COOKIE_ATTR_NAMES and val:
                    updates[key] = val
    return updates


def _generate_quark_binding_id() -> str:
    """Generate an opaque internal account_binding_id `quark:bind_<hex16>` (§5.4.1)."""
    return f"quark:bind_{secrets.token_hex(8)}"


def _is_entry_dir(item: Mapping[str, Any]) -> bool:
    """Determine directory flag across Quark share/detail and file/sort payloads."""
    dir_flag = item.get("dir")
    file_type = item.get("file_type")
    return bool(dir_flag or file_type == 0)


class QuarkProvider:
    """Quark Netdisk CloudProvider implementation."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        credential_store: CredentialStore,
        config_reader: ProviderConfigReader | None = None,
        recognizer: ShareRecognizer | None = None,
        *,
        poll_delays: Sequence[float] = QUARK_TASK_POLL_DELAYS_SECONDS,
        poll_timeout: float = QUARK_TASK_POLL_TIMEOUT_SECONDS,
        request_timeout: float = API_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._session = session
        self._credential_store = credential_store
        self._config_reader = config_reader
        self._recognizer = recognizer
        self._cookie_lock = asyncio.Lock()
        self._poll_delays: tuple[float, ...] = tuple(poll_delays) or (0.5,)
        self._poll_timeout = float(poll_timeout)
        self._request_timeout = float(request_timeout)

    @property
    def spec(self) -> ProviderSpec:
        return QUARK_SPEC

    @property
    def recognizer(self) -> ShareRecognizer:
        if self._recognizer is None:
            try:
                from yunbot.domain.parsing import QuarkShareRecognizer  # type: ignore[import-not-found]

                self._recognizer = QuarkShareRecognizer()
            except ImportError:
                self._recognizer = _FallbackQuarkShareRecognizer()
        return self._recognizer

    def validate_transfer_mode(self, *, no_subdir: bool) -> None:
        del no_subdir

    def get_oauth_authorize_url(self) -> str | None:
        return None

    async def get_account_status(self) -> ProviderAccountStatus:
        record = await self._credential_store.get_credential("quark")
        if (
            record is None
            or not record.access_token.strip()
            or not record.account_binding_id.strip()
        ):
            return ProviderAccountStatus(
                provider_id="quark",
                authorized=False,
                account_binding_id=None,
                account_label="",
                auth_mode_used=AuthMode.SECRET_FIELDS.value,
                updated_at=None,
                message="未配置夸克网盘 Cookie",
            )

        nickname = ""
        try:
            extra = json.loads(record.extra_json or "{}")
            if isinstance(extra, dict):
                nickname = str(extra.get("nickname") or "")
        except json.JSONDecodeError:
            nickname = ""

        return ProviderAccountStatus(
            provider_id="quark",
            authorized=True,
            account_binding_id=record.account_binding_id,
            account_label=nickname,
            auth_mode_used=AuthMode.SECRET_FIELDS.value,
            updated_at=record.updated_at,
            message="已授权",
        )

    async def get_current_binding_id(self) -> str:
        record = await self._credential_store.get_credential("quark")
        if (
            record is None
            or not record.access_token.strip()
            or not record.account_binding_id.strip()
        ):
            raise ProviderAuthInvalidError("夸克网盘")
        return record.account_binding_id

    async def save_secret_credentials(self, fields: Mapping[str, str]) -> ProviderAccountStatus:
        raw_cookie = (fields.get("cookie") or fields.get("QUARK_COOKIE") or "").strip()
        if not raw_cookie:
            raise ProviderAuthInvalidError("夸克网盘", "夸克网盘 Cookie 不能为空")

        candidate_jar = _parse_cookie_header(raw_cookie)
        if not candidate_jar:
            raise ProviderAuthInvalidError("夸克网盘", "夸克网盘 Cookie 格式无效")

        nickname = await self._verify_candidate_cookie_jar(candidate_jar)
        new_binding_id = _generate_quark_binding_id()
        now = time.time()
        extra_json = json.dumps({"nickname": nickname}, ensure_ascii=False)

        record = ProviderCredentialRecord(
            provider="quark",
            access_token=_serialize_cookie_jar(candidate_jar),
            refresh_token="",
            account_binding_id=new_binding_id,
            extra_json=extra_json,
            updated_at=now,
        )
        async with self._cookie_lock:
            await self._credential_store.upsert_credential(record)

        return ProviderAccountStatus(
            provider_id="quark",
            authorized=True,
            account_binding_id=new_binding_id,
            account_label=nickname,
            auth_mode_used=AuthMode.SECRET_FIELDS.value,
            updated_at=now,
            message="已授权",
        )

    async def seed_initial_cookie_if_empty(
        self, cookie: str | None = None
    ) -> ProviderAccountStatus | None:
        """Optionally seed initial QUARK_COOKIE only when no stored credential exists."""
        existing = await self._credential_store.get_credential("quark")
        if (
            existing is not None
            and existing.access_token.strip()
            and existing.account_binding_id.strip()
        ):
            return await self.get_account_status()

        raw_cookie = cookie
        if raw_cookie is None and self._config_reader is not None:
            settings = self._config_reader.get_provider_settings("quark")
            raw_cookie = settings.get("cookie") or settings.get("QUARK_COOKIE") or ""

        if not raw_cookie or not raw_cookie.strip():
            return None
        return await self.save_secret_credentials({"cookie": raw_cookie})

    async def exchange_oauth_code(self, code: str) -> ProviderAccountStatus:
        del code
        raise YunBotError(ErrorCode.INTERNAL_ERROR, "夸克网盘不支持 OAuth 授权码模式")

    async def start_interactive_auth(self) -> InteractiveAuthStart:
        raise YunBotError(ErrorCode.INTERNAL_ERROR, "夸克网盘不支持设备码交互授权")

    async def poll_interactive_auth(self) -> InteractiveAuthPollResult:
        raise YunBotError(ErrorCode.INTERNAL_ERROR, "夸克网盘不支持设备码交互授权")

    async def cancel_interactive_auth(self) -> None:
        return None

    async def keepalive(self) -> None:
        """Perform lightweight member check to trigger rolling `__puus` refresh (§5.7.1)."""
        record = await self._credential_store.get_credential("quark")
        if (
            record is None
            or not record.access_token.strip()
            or not record.account_binding_id.strip()
        ):
            logger.debug("Quark keepalive skipped: credentials not configured")
            return

        try:
            http_status, payload = await self._request_json(
                "GET",
                QUARK_MEMBER_URL,
                params={
                    "pr": "ucpro",
                    "fr": "pc",
                    "fetch_subscribe": "true",
                    "_ch": "home",
                },
                expected_binding_id=record.account_binding_id,
            )
            self._check_response_errors(http_status, payload)
        except Exception as exc:
            logger.warning(
                "Quark keepalive warning: %s",
                redact_sensitive_text(str(exc)),
            )

    async def prepare_task_dir(self, task_dir_path: str) -> str:
        norm_dir = normalize_posix_path(task_dir_path, allow_root=False)
        fid = await self._resolve_or_create_dir(norm_dir, create=True)
        if not fid:
            raise YunBotError(ErrorCode.INTERNAL_ERROR, "无法创建夸克任务目录")
        return norm_dir

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
        norm_target = normalize_posix_path(target_dir, allow_root=False)
        binding_id = await self.get_current_binding_id()

        passcode = (share.code or "").strip()
        has_passcode = bool(passcode)

        # 1. Exchange pwd_id + passcode for stoken
        stoken_status, stoken_payload = await self._request_json(
            "POST",
            QUARK_SHARE_TOKEN_URL,
            params={"pr": "ucpro", "fr": "pc"},
            json_body={"pwd_id": share.external_id, "passcode": passcode},
            expected_binding_id=binding_id,
        )
        self._check_response_errors(
            stoken_status,
            stoken_payload,
            share_context=True,
            has_passcode=has_passcode,
        )
        stoken_data = (stoken_payload or {}).get("data")
        if not isinstance(stoken_data, dict):
            raise ProviderShareExpiredError()
        stoken = str(stoken_data.get("stoken") or "").strip()
        if not stoken:
            raise ProviderShareExpiredError()
        share_title = str(stoken_data.get("title") or "").strip()

        # 2. Enumerate top-level items (S4 Red Line: NEVER auto-unwrap single-folder share)
        pdir_fid = (share.sub_dir_fid or "0").strip() or "0"
        (
            enumerated,
            total_discovered,
            truncated_by_limit,
            detail_title,
        ) = await self._enumerate_share_items(
            pwd_id=share.external_id,
            stoken=stoken,
            pdir_fid=pdir_fid,
            has_passcode=has_passcode,
            binding_id=binding_id,
        )
        if detail_title and not share_title:
            share_title = detail_title
        if not share_title:
            share_title = enumerated[0].name if enumerated else share.external_id

        if not enumerated:
            if not collect_items:
                await self._best_effort_cleanup_dir(norm_target, binding_id=binding_id)
            return TransferOutcome(
                share_title=share_title,
                succeeded_count=0,
                failed_count=0,
                total_discovered=0,
                truncated_by_limit=False,
                uncertain=False,
                error_code=ErrorCode.SHARE_EXPIRED,
                error_message=format_error_message(ErrorCode.SHARE_EXPIRED),
            )

        # 3. Ensure target directory exists
        to_pdir_fid = await self._resolve_or_create_dir(
            norm_target,
            create=True,
            binding_id=binding_id,
        )
        if not to_pdir_fid:
            raise YunBotError(ErrorCode.INTERNAL_ERROR, "无法解析或创建夸克目标目录")

        # 4. Save in batches of QUARK_SAVE_BATCH_SIZE (50) & poll async task
        succeeded_count = 0
        failed_count = 0
        uncertain = False
        last_error_code: ErrorCode | None = None
        last_error_message: str | None = None
        total_to_process = len(enumerated)

        for offset in range(0, total_to_process, QUARK_SAVE_BATCH_SIZE):
            batch = enumerated[offset : offset + QUARK_SAVE_BATCH_SIZE]
            save_body = {
                "fid_list": [it.fid for it in batch],
                "fid_token_list": [it.fid_token for it in batch],
                "to_pdir_fid": to_pdir_fid,
                "pwd_id": share.external_id,
                "stoken": stoken,
                "pdir_fid": pdir_fid,
                "scene": "link",
            }

            try:
                save_status, save_payload = await self._request_json(
                    "POST",
                    QUARK_SHARE_SAVE_URL,
                    params={"pr": "ucpro", "fr": "pc"},
                    json_body=save_body,
                    expected_binding_id=binding_id,
                )
            except (TimeoutError, aiohttp.ClientError) as exc:
                logger.warning(
                    "Quark sharepage/save uncertain failure on batch offset=%d: %s",
                    offset,
                    redact_sensitive_text(str(exc)),
                )
                uncertain = True
                failed_count += total_to_process - offset
                last_error_code = (
                    ErrorCode.TRANSFER_PARTIAL if succeeded_count > 0 else ErrorCode.INTERNAL_ERROR
                )
                last_error_message = format_error_message(
                    last_error_code,
                    ok_count=succeeded_count,
                    fail_count=failed_count,
                    task_id=task_id,
                )
                break

            try:
                self._check_response_errors(
                    save_status,
                    save_payload,
                    share_context=True,
                    has_passcode=has_passcode,
                )
            except (
                ProviderQuotaExceededError,
                ProviderAuthInvalidError,
                ProviderRateLimitedError,
                ProviderShareExpiredError,
                BindingMismatchError,
            ) as exc:
                if succeeded_count == 0 and not uncertain:
                    if not collect_items:
                        await self._best_effort_cleanup_dir(norm_target, binding_id=binding_id)
                    raise
                failed_count += total_to_process - offset
                last_error_code = exc.code
                last_error_message = exc.user_message
                break
            except YunBotError as exc:
                failed_count += len(batch)
                last_error_code = exc.code
                last_error_message = exc.user_message
                continue

            save_data = (save_payload or {}).get("data")
            if not isinstance(save_data, dict):
                failed_count += len(batch)
                last_error_code = ErrorCode.INTERNAL_ERROR
                continue

            quark_task_id = str(save_data.get("task_id") or "").strip()
            if quark_task_id:
                if on_remote_task is not None:
                    await on_remote_task(quark_task_id)

                poll_outcome, task_data, poll_err = await self._poll_task(
                    quark_task_id,
                    binding_id=binding_id,
                )
                if poll_outcome == "timeout":
                    uncertain = True
                    failed_count += total_to_process - offset
                    last_error_code = (
                        ErrorCode.TRANSFER_PARTIAL
                        if succeeded_count > 0
                        else ErrorCode.INTERNAL_ERROR
                    )
                    last_error_message = format_error_message(
                        last_error_code,
                        ok_count=succeeded_count,
                        fail_count=failed_count,
                        task_id=task_id,
                    )
                    break
                if poll_outcome == "failed":
                    if isinstance(
                        poll_err,
                        (
                            ProviderQuotaExceededError,
                            ProviderAuthInvalidError,
                            ProviderRateLimitedError,
                            BindingMismatchError,
                        ),
                    ):
                        if succeeded_count == 0 and not uncertain:
                            if not collect_items:
                                await self._best_effort_cleanup_dir(
                                    norm_target,
                                    binding_id=binding_id,
                                )
                            raise poll_err
                        failed_count += total_to_process - offset
                        last_error_code = poll_err.code
                        last_error_message = poll_err.user_message
                        break

                    failed_count += len(batch)
                    if poll_err is not None:
                        last_error_code = poll_err.code
                        last_error_message = poll_err.user_message
                    else:
                        last_error_code = ErrorCode.TRANSFER_PARTIAL
                    continue
            elif save_data.get("finish") is True:
                task_data = save_data
            else:
                uncertain = True
                failed_count += total_to_process - offset
                last_error_code = (
                    ErrorCode.TRANSFER_PARTIAL if succeeded_count > 0 else ErrorCode.INTERNAL_ERROR
                )
                break

            if collect_items:
                save_as = (task_data or {}).get("save_as")
                raw_top_fids = (
                    save_as.get("save_as_top_fids") if isinstance(save_as, dict) else None
                ) or []
                top_fids = list(
                    dict.fromkeys(str(fid).strip() for fid in raw_top_fids if str(fid).strip())
                )
                if not top_fids:
                    uncertain = True
                    failed_count += total_to_process - offset
                    last_error_code = (
                        ErrorCode.TRANSFER_PARTIAL
                        if succeeded_count > 0
                        else ErrorCode.INTERNAL_ERROR
                    )
                    break

                try:
                    entries, unresolved = await self._resolve_saved_top_entries(
                        to_pdir_fid=to_pdir_fid,
                        norm_target=norm_target,
                        top_fids=top_fids,
                        binding_id=binding_id,
                    )
                except (TimeoutError, aiohttp.ClientError, YunBotError) as exc:
                    logger.warning(
                        "Quark failed resolving save_as_top_fids for -n batch: %s",
                        redact_sensitive_text(str(exc)),
                    )
                    uncertain = True
                    failed_count += total_to_process - offset
                    last_error_code = (
                        exc.code
                        if isinstance(exc, YunBotError)
                        else (
                            ErrorCode.TRANSFER_PARTIAL
                            if succeeded_count > 0
                            else ErrorCode.INTERNAL_ERROR
                        )
                    )
                    break

                if entries and on_items_batch is not None:
                    await on_items_batch(entries)

                succeeded_count += len(entries)
                if unresolved:
                    uncertain = True
                    failed_count += len(unresolved) + max(
                        0, total_to_process - (offset + len(batch))
                    )
                    last_error_code = (
                        ErrorCode.TRANSFER_PARTIAL
                        if succeeded_count > 0
                        else ErrorCode.ENUM_LIMIT_EXCEEDED
                    )
                    break
            else:
                succeeded_count += len(batch)

            if on_progress is not None:
                await on_progress(share_title, succeeded_count, total_to_process)

        # 5. Best-effort delete empty target_dir when default mode transferred 0 items cleanly
        if not collect_items and succeeded_count == 0 and not uncertain:
            await self._best_effort_cleanup_dir(norm_target, binding_id=binding_id)

        error_code: ErrorCode | None = None
        error_message: str | None = None
        if uncertain:
            error_code = last_error_code or (
                ErrorCode.TRANSFER_PARTIAL if succeeded_count > 0 else ErrorCode.INTERNAL_ERROR
            )
            error_message = last_error_message or format_error_message(
                error_code,
                provider_name="夸克网盘",
                ok_count=succeeded_count,
                fail_count=failed_count,
                task_id=task_id,
            )
        elif failed_count > 0:
            if succeeded_count > 0:
                error_code = ErrorCode.TRANSFER_PARTIAL
                error_message = format_error_message(
                    ErrorCode.TRANSFER_PARTIAL,
                    ok_count=succeeded_count,
                    fail_count=failed_count,
                )
            else:
                error_code = last_error_code or ErrorCode.INTERNAL_ERROR
                error_message = last_error_message or format_error_message(
                    error_code,
                    provider_name="夸克网盘",
                    task_id=task_id,
                )
        elif truncated_by_limit:
            error_code = ErrorCode.ENUM_LIMIT_EXCEEDED
            error_message = format_error_message(ErrorCode.ENUM_LIMIT_EXCEEDED)

        return TransferOutcome(
            share_title=share_title,
            succeeded_count=succeeded_count,
            failed_count=failed_count,
            total_discovered=total_discovered,
            truncated_by_limit=truncated_by_limit,
            uncertain=uncertain,
            error_code=error_code,
            error_message=error_message,
        )

    async def delete_directory(
        self,
        task_dir_path: str,
        *,
        expected_binding_id: str | None = None,
    ) -> None:
        norm_dir = normalize_posix_path(task_dir_path, allow_root=False)
        current_binding = await self.get_current_binding_id()
        if expected_binding_id is not None and current_binding != expected_binding_id:
            raise BindingMismatchError()
        binding_id = expected_binding_id or current_binding

        fid = await self._resolve_or_create_dir(norm_dir, create=False, binding_id=binding_id)
        if not fid:
            return

        await self._delete_fids_strict([fid], binding_id=binding_id)

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

        base_posix = PurePosixPath(norm_base)
        for item in items:
            norm_item = validate_direct_item_path(item.path, norm_base)
            if PurePosixPath(norm_item).parent != base_posix:
                raise ValueError(
                    f"Direct item path must be a direct child of base_save_path: {item.path}"
                )
            if not (item.item_id or "").strip():
                raise ValueError("TransferItemRecord.item_id must not be empty")

        current_binding = await self.get_current_binding_id()
        if expected_binding_id is not None and current_binding != expected_binding_id:
            raise BindingMismatchError()
        binding_id = expected_binding_id or current_binding

        base_fid = await self._resolve_or_create_dir(
            norm_base,
            create=False,
            binding_id=binding_id,
        )

        target_fids = {it.item_id for it in items}
        live_in_base: dict[str, tuple[str, bool]] = {}
        if base_fid is not None:
            live_in_base = await self._list_dir_entries_map(
                pdir_fid=base_fid,
                stop_when_found=target_fids,
                binding_id=binding_id,
            )

        deleted_ids: list[str] = []
        skipped_items: list[TransferItemRecord] = []
        failed_items: list[TransferItemRecord] = []
        to_delete: list[TransferItemRecord] = []

        for item in items:
            in_base = live_in_base.get(item.item_id)
            if in_base is not None:
                cur_name, cur_is_dir = in_base
                if cur_name == item.name and cur_is_dir == item.is_dir:
                    to_delete.append(item)
                else:
                    skipped_items.append(item)
                continue

            state = await self._probe_missing_item_state(
                item.item_id,
                binding_id=binding_id,
            )
            if state == "deleted":
                deleted_ids.append(item.item_id)
                if deleted_ids_sink is not None:
                    deleted_ids_sink.append(item.item_id)
            elif state == "alive":
                skipped_items.append(item)
            else:
                failed_items.append(item)

        for offset in range(0, len(to_delete), QUARK_SAVE_BATCH_SIZE):
            batch = to_delete[offset : offset + QUARK_SAVE_BATCH_SIZE]
            batch_fids = [it.item_id for it in batch]
            try:
                await self._delete_fids_strict(batch_fids, binding_id=binding_id)
            except BindingMismatchError:
                raise
            except ProviderAuthInvalidError:
                if not deleted_ids and not skipped_items and not failed_items:
                    raise
                failed_items.extend(to_delete[offset:])
                break
            except Exception as exc:
                logger.warning(
                    "Quark delete_items batch failed (count=%d): %s",
                    len(batch),
                    redact_sensitive_text(str(exc)),
                )
                failed_items.extend(batch)
            else:
                deleted_ids.extend(batch_fids)
                if deleted_ids_sink is not None:
                    deleted_ids_sink.extend(batch_fids)

        return DeleteItemsOutcome(
            deleted_ids=tuple(deleted_ids),
            skipped_items=tuple(skipped_items),
            failed_items=tuple(failed_items),
        )

    async def close(self) -> None:
        return None

    # ==========================================================================
    # Internal Helpers
    # ==========================================================================

    async def _verify_candidate_cookie_jar(self, candidate_jar: dict[str, str]) -> str:
        """Verify candidate Cookie against account/info AND clouddrive/member."""
        info_status, info_payload = await self._request_json(
            "GET",
            QUARK_ACCOUNT_INFO_URL,
            params={"fr": "pc", "platform": "pc"},
            transient_cookie_jar=candidate_jar,
        )
        if info_status in (401, 403):
            raise ProviderAuthInvalidError("夸克网盘")
        if info_status == 429:
            raise ProviderRateLimitedError("夸克网盘")
        if (
            info_status != 200
            or not isinstance(info_payload, dict)
            or info_payload.get("code") not in (0, "0", "OK")
            or (info_payload.get("status") not in (None, 200))
        ):
            raise ProviderAuthInvalidError("夸克网盘")

        info_data = info_payload.get("data")
        if not isinstance(info_data, dict) or not info_data:
            raise ProviderAuthInvalidError("夸克网盘")
        nickname = str(info_data.get("nickname") or "").strip()
        if not nickname:
            raise ProviderAuthInvalidError("夸克网盘")

        member_status, member_payload = await self._request_json(
            "GET",
            QUARK_MEMBER_URL,
            params={
                "pr": "ucpro",
                "fr": "pc",
                "fetch_subscribe": "true",
                "_ch": "home",
            },
            transient_cookie_jar=candidate_jar,
        )
        if member_status in (401, 403):
            raise ProviderAuthInvalidError("夸克网盘")
        if member_status == 429:
            raise ProviderRateLimitedError("夸克网盘")
        if (
            member_status != 200
            or not isinstance(member_payload, dict)
            or member_payload.get("code") not in (0, "0", "OK")
            or (member_payload.get("status") not in (None, 200))
        ):
            raise ProviderAuthInvalidError("夸克网盘")

        member_data = member_payload.get("data")
        if not isinstance(member_data, dict) or not member_data:
            raise ProviderAuthInvalidError("夸克网盘")

        return nickname

    async def _resolve_or_create_dir(
        self,
        path: str,
        *,
        create: bool = True,
        binding_id: str | None = None,
    ) -> str | None:
        """Resolve cloud directory path to `fid`, creating it if missing and `create=True`."""
        norm_path = normalize_posix_path(path, allow_root=False)
        active_binding = binding_id or await self.get_current_binding_id()

        resolved_map = await self._query_path_fids([norm_path], binding_id=active_binding)
        existing_fid = resolved_map.get(norm_path)
        if existing_fid:
            return existing_fid

        if not create:
            return None

        create_status, create_payload = await self._request_json(
            "POST",
            QUARK_CREATE_FILE_URL,
            params={"pr": "ucpro", "fr": "pc"},
            json_body={
                "pdir_fid": "0",
                "file_name": "",
                "dir_path": norm_path,
                "dir_init_lock": False,
            },
            expected_binding_id=active_binding,
        )
        try:
            self._check_response_errors(create_status, create_payload)
        except YunBotError:
            recheck = await self._query_path_fids([norm_path], binding_id=active_binding)
            if norm_path in recheck:
                return recheck[norm_path]
            raise

        data = (create_payload or {}).get("data")
        if isinstance(data, dict):
            fid = str(data.get("fid") or "").strip()
            if fid:
                return fid

        recheck = await self._query_path_fids([norm_path], binding_id=active_binding)
        return recheck.get(norm_path)

    async def _query_path_fids(
        self,
        paths: Sequence[str],
        *,
        binding_id: str,
    ) -> dict[str, str]:
        """Query `file/info/path_list` in batches of `QUARK_PATH_LIST_BATCH_SIZE`."""
        norm_paths = [normalize_posix_path(p, allow_root=False) for p in paths]
        result: dict[str, str] = {}

        for offset in range(0, len(norm_paths), QUARK_PATH_LIST_BATCH_SIZE):
            batch = norm_paths[offset : offset + QUARK_PATH_LIST_BATCH_SIZE]
            http_status, payload = await self._request_json(
                "POST",
                QUARK_PATH_LIST_URL,
                params={"pr": "ucpro", "fr": "pc"},
                json_body={"file_path": batch},
                expected_binding_id=binding_id,
            )
            self._check_response_errors(http_status, payload)

            data = (payload or {}).get("data")
            folder_entries: list[Any] = []
            if isinstance(data, dict):
                raw_folder = data.get("folder")
                if isinstance(raw_folder, list):
                    folder_entries = raw_folder
                elif isinstance(data.get("list"), list):
                    folder_entries = data["list"]
            elif isinstance(data, list):
                folder_entries = data

            for idx, entry in enumerate(folder_entries):
                if not isinstance(entry, dict):
                    continue
                fid = str(entry.get("fid") or "").strip()
                if not fid:
                    continue
                raw_fp = str(entry.get("file_path") or entry.get("dir_path") or "").strip()
                if raw_fp:
                    try:
                        matched_path = normalize_posix_path(raw_fp, allow_root=False)
                    except ValueError:
                        continue
                    result[matched_path] = fid
                elif len(batch) == 1 and idx == 0:
                    result[batch[0]] = fid

        return result

    async def _enumerate_share_items(
        self,
        *,
        pwd_id: str,
        stoken: str,
        pdir_fid: str,
        has_passcode: bool,
        binding_id: str,
    ) -> tuple[list[_ShareItem], int, bool, str]:
        """Paginate `sharepage/detail` without auto-unwrapping top-level folders."""
        items: list[_ShareItem] = []
        seen_fids: set[str] = set()
        total_discovered = 0
        has_reported_total = False
        truncated_by_limit = False
        share_title = ""
        page = 1

        while True:
            http_status, payload = await self._request_json(
                "GET",
                QUARK_SHARE_DETAIL_URL,
                params={
                    "pr": "ucpro",
                    "fr": "pc",
                    "pwd_id": pwd_id,
                    "stoken": stoken,
                    "pdir_fid": pdir_fid,
                    "force": "0",
                    "_page": str(page),
                    "_size": str(QUARK_DETAIL_PAGE_SIZE),
                    "_fetch_banner": "1",
                    "_fetch_share": "1",
                    "_fetch_total": "1",
                    "_sort": "file_type:asc,updated_at:desc",
                },
                expected_binding_id=binding_id,
            )
            self._check_response_errors(
                http_status,
                payload,
                share_context=True,
                has_passcode=has_passcode,
            )

            body = payload or {}
            metadata = body.get("metadata")
            if isinstance(metadata, dict) and metadata.get("_total") is not None:
                try:
                    total_discovered = int(metadata["_total"])
                    has_reported_total = True
                except (TypeError, ValueError):
                    pass

            data = body.get("data")
            if not isinstance(data, dict):
                break

            share_meta = data.get("share")
            if isinstance(share_meta, dict) and not share_title:
                share_title = str(share_meta.get("title") or "").strip()

            raw_list = data.get("list")
            if not isinstance(raw_list, list) or not raw_list:
                break

            for raw_item in raw_list:
                if not isinstance(raw_item, dict):
                    continue
                fid = str(raw_item.get("fid") or "").strip()
                fid_token = str(
                    raw_item.get("share_fid_token") or raw_item.get("fid_token") or ""
                ).strip()
                name = str(raw_item.get("file_name") or "").strip()
                if not fid or fid in seen_fids:
                    continue
                if len(items) >= MAX_SHARE_ENUM_ITEMS:
                    truncated_by_limit = True
                    break
                seen_fids.add(fid)
                items.append(
                    _ShareItem(
                        fid=fid,
                        fid_token=fid_token,
                        name=name or fid,
                        is_dir=_is_entry_dir(raw_item),
                    )
                )

            if has_reported_total and total_discovered > MAX_SHARE_ENUM_ITEMS:
                truncated_by_limit = True

            if len(items) >= MAX_SHARE_ENUM_ITEMS:
                if not has_reported_total and not truncated_by_limit:
                    if len(raw_list) == QUARK_DETAIL_PAGE_SIZE:
                        probe_has_more = await self._probe_share_has_next_page(
                            pwd_id=pwd_id,
                            stoken=stoken,
                            pdir_fid=pdir_fid,
                            next_page=page + 1,
                            has_passcode=has_passcode,
                            binding_id=binding_id,
                        )
                        if probe_has_more:
                            truncated_by_limit = True
                break

            if len(raw_list) < QUARK_DETAIL_PAGE_SIZE:
                break
            if has_reported_total and len(items) >= total_discovered:
                break

            page += 1

        if not has_reported_total or total_discovered < len(items):
            total_discovered = len(items) + (1 if truncated_by_limit else 0)

        return items, total_discovered, truncated_by_limit, share_title

    async def _probe_share_has_next_page(
        self,
        *,
        pwd_id: str,
        stoken: str,
        pdir_fid: str,
        next_page: int,
        has_passcode: bool,
        binding_id: str,
    ) -> bool:
        http_status, payload = await self._request_json(
            "GET",
            QUARK_SHARE_DETAIL_URL,
            params={
                "pr": "ucpro",
                "fr": "pc",
                "pwd_id": pwd_id,
                "stoken": stoken,
                "pdir_fid": pdir_fid,
                "force": "0",
                "_page": str(next_page),
                "_size": str(QUARK_DETAIL_PAGE_SIZE),
                "_fetch_banner": "1",
                "_fetch_share": "1",
                "_fetch_total": "1",
                "_sort": "file_type:asc,updated_at:desc",
            },
            expected_binding_id=binding_id,
        )
        self._check_response_errors(
            http_status,
            payload,
            share_context=True,
            has_passcode=has_passcode,
        )
        data = (payload or {}).get("data")
        if not isinstance(data, dict):
            return False
        raw_list = data.get("list")
        return isinstance(raw_list, list) and len(raw_list) > 0

    async def _poll_task(
        self,
        quark_task_id: str,
        *,
        binding_id: str,
    ) -> tuple[str, dict[str, Any] | None, YunBotError | None]:
        """Poll `/1/clouddrive/task` until `data.status == 2`, failure, or timeout.

        Returns `("ok" | "failed" | "timeout", task_data, domain_error)`.
        """
        deadline = time.monotonic() + self._poll_timeout
        retry_index = 0

        while True:
            try:
                http_status, payload = await self._request_json(
                    "GET",
                    QUARK_TASK_URL,
                    params={
                        "pr": "ucpro",
                        "fr": "pc",
                        "task_id": quark_task_id,
                        "retry_index": str(retry_index),
                    },
                    expected_binding_id=binding_id,
                )
            except (TimeoutError, aiohttp.ClientError) as exc:
                logger.warning(
                    "Quark task poll uncertain timeout/network failure (retry=%d): %s",
                    retry_index,
                    redact_sensitive_text(str(exc)),
                )
                return "timeout", None, None

            try:
                self._check_response_errors(http_status, payload)
            except YunBotError as exc:
                return "failed", None, exc

            data = (payload or {}).get("data")
            if not isinstance(data, dict):
                return "failed", None, YunBotError(ErrorCode.INTERNAL_ERROR, "夸克任务响应为空")

            status_val = data.get("status")
            task_err_code = data.get("error_code")
            task_msg = str(data.get("message") or data.get("task_title") or "")

            if status_val == 2 and (task_err_code in (None, 0, "0")):
                return "ok", data, None

            if status_val == 3 or (task_err_code not in (None, 0, "0")):
                domain_err = self._classify_task_failure(task_err_code, task_msg)
                return "failed", data, domain_err

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "timeout", data, None

            delay = self._poll_delays[min(retry_index, len(self._poll_delays) - 1)]
            await asyncio.sleep(min(delay, remaining))
            if time.monotonic() >= deadline:
                return "timeout", data, None
            retry_index += 1

    def _classify_task_failure(self, raw_code: Any, message: str) -> YunBotError:
        code_int: int | None = None
        try:
            if raw_code is not None:
                code_int = int(raw_code)
        except (TypeError, ValueError):
            code_int = None

        msg_lower = (message or "").lower()
        if (
            code_int in _QUOTA_ERROR_CODES
            or any(
                kw in message
                for kw in ("容量", "空间不足", "空间已满", "超出上限", "文件数超限", "转存上限")
            )
            or "quota" in msg_lower
            or "capacity" in msg_lower
        ):
            return ProviderQuotaExceededError("夸克网盘")
        if code_int in _AUTH_INVALID_CODES or "未登录" in message:
            return ProviderAuthInvalidError("夸克网盘")
        return YunBotError(ErrorCode.TRANSFER_PARTIAL)

    async def _resolve_saved_top_entries(
        self,
        *,
        to_pdir_fid: str,
        norm_target: str,
        top_fids: Sequence[str],
        binding_id: str,
    ) -> tuple[list[TransferredEntry], list[str]]:
        """Resolve `save_as_top_fids` to actual cloud names via bounded `file/sort` pages."""
        needed = set(top_fids)
        live_map = await self._list_dir_entries_map(
            pdir_fid=to_pdir_fid,
            stop_when_found=needed,
            binding_id=binding_id,
        )

        entries: list[TransferredEntry] = []
        unresolved: list[str] = []
        target_posix = PurePosixPath(norm_target)

        for fid in top_fids:
            resolved = live_map.get(fid)
            if resolved is None:
                unresolved.append(fid)
                continue
            file_name, is_dir = resolved
            if not file_name or "/" in file_name or "\\" in file_name or "\x00" in file_name:
                unresolved.append(fid)
                continue
            try:
                full_path = validate_direct_item_path(f"{norm_target}/{file_name}", norm_target)
            except ValueError:
                unresolved.append(fid)
                continue
            if PurePosixPath(full_path).parent != target_posix:
                unresolved.append(fid)
                continue
            entries.append(
                TransferredEntry(
                    item_id=fid,
                    path=full_path,
                    name=file_name,
                    is_dir=is_dir,
                )
            )

        return entries, unresolved

    async def _list_dir_entries_map(
        self,
        *,
        pdir_fid: str,
        stop_when_found: set[str] | None,
        binding_id: str,
    ) -> dict[str, tuple[str, bool]]:
        """List `pdir_fid` via `file/sort` up to `_FILE_SORT_MAX_PAGES` bounded pages."""
        found: dict[str, tuple[str, bool]] = {}

        for page in range(1, _FILE_SORT_MAX_PAGES + 1):
            http_status, payload = await self._request_json(
                "GET",
                QUARK_FILE_SORT_URL,
                params={
                    "pr": "ucpro",
                    "fr": "pc",
                    "pdir_fid": pdir_fid,
                    "_page": str(page),
                    "_size": str(_FILE_SORT_PAGE_SIZE),
                    "_fetch_total": "1",
                    "fetch_all_file": "1",
                    "fetch_risk_file_name": "1",
                    "_sort": "file_type:asc,updated_at:desc",
                },
                expected_binding_id=binding_id,
            )
            self._check_response_errors(http_status, payload)

            body = payload or {}
            data = body.get("data")
            if not isinstance(data, dict):
                break
            raw_list = data.get("list")
            if not isinstance(raw_list, list) or not raw_list:
                break

            for item in raw_list:
                if not isinstance(item, dict):
                    continue
                fid = str(item.get("fid") or "").strip()
                file_name = str(item.get("file_name") or "").strip()
                if not fid or not file_name:
                    continue
                found[fid] = (file_name, _is_entry_dir(item))

            if stop_when_found and stop_when_found.issubset(found.keys()):
                break

            if len(raw_list) < _FILE_SORT_PAGE_SIZE:
                break

            metadata = body.get("metadata")
            if isinstance(metadata, dict) and metadata.get("_total") is not None:
                try:
                    total = int(metadata["_total"])
                    if page * _FILE_SORT_PAGE_SIZE >= total:
                        break
                except (TypeError, ValueError):
                    pass

        return found

    async def _probe_missing_item_state(
        self,
        item_id: str,
        *,
        binding_id: str,
    ) -> str:
        """Check `file/info` for an item absent from `base_fid`.

        Returns `"deleted"`, `"alive"`, or `"error"`.
        """
        try:
            http_status, payload = await self._request_json(
                "GET",
                QUARK_FILE_INFO_URL,
                params={"pr": "ucpro", "fr": "pc", "fid": item_id},
                expected_binding_id=binding_id,
            )
        except BindingMismatchError:
            raise
        except (TimeoutError, aiohttp.ClientError) as exc:
            logger.warning(
                "Quark file/info probe failed for item_id=%s: %s",
                item_id,
                redact_sensitive_text(str(exc)),
            )
            return "error"

        if http_status == 404:
            return "deleted"
        if http_status == 429:
            return "error"
        if http_status in (401, 403):
            raise ProviderAuthInvalidError("夸克网盘")
        if http_status >= 500 or not isinstance(payload, dict):
            return "error"

        body_status = payload.get("status")
        raw_code = payload.get("code")
        code_int: int | None = None
        try:
            if raw_code is not None:
                code_int = int(raw_code)
        except (TypeError, ValueError):
            code_int = None

        if body_status in (401, 403) or code_int in _AUTH_INVALID_CODES:
            raise ProviderAuthInvalidError("夸克网盘")
        if body_status == 429:
            return "error"
        if body_status == 404 or (code_int is not None and code_int != 0):
            return "deleted"

        data = payload.get("data")
        if not data:
            return "deleted"

        info: dict[str, Any] | None = None
        if isinstance(data, dict):
            if "fid" in data or "ban" in data or "trashed" in data:
                info = data
            elif isinstance(data.get("file"), dict):
                info = data["file"]
            elif isinstance(data.get("list"), list) and data["list"]:
                first = data["list"][0]
                if isinstance(first, dict):
                    info = first
        elif isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                info = first

        if not info:
            return "deleted"

        fid = str(info.get("fid") or "").strip()
        if not fid:
            return "deleted"
        if (
            bool(info.get("ban"))
            or bool(info.get("trashed"))
            or bool(info.get("in_trash"))
            or bool(info.get("deleted"))
            or bool(info.get("is_delete"))
        ):
            return "deleted"

        return "alive"

    async def _delete_fids_strict(
        self,
        fids: Sequence[str],
        *,
        binding_id: str,
    ) -> None:
        """Delete `fids` via `/1/clouddrive/file/delete` and poll async task to completion."""
        if not fids:
            return

        http_status, payload = await self._request_json(
            "POST",
            QUARK_FILE_DELETE_URL,
            params={"pr": "ucpro", "fr": "pc"},
            json_body={
                "action_type": 2,
                "filelist": list(fids),
                "exclude_fids": [],
            },
            expected_binding_id=binding_id,
        )

        if http_status == 404:
            return
        if isinstance(payload, dict):
            raw_code = payload.get("code")
            msg = str(payload.get("message") or "")
            if raw_code in _NOT_FOUND_CODES or "不存在" in msg:
                return

        self._check_response_errors(http_status, payload)

        data = (payload or {}).get("data")
        if isinstance(data, dict):
            task_id = str(data.get("task_id") or "").strip()
            if task_id:
                poll_outcome, _, poll_err = await self._poll_task(
                    task_id,
                    binding_id=binding_id,
                )
                if poll_outcome != "ok":
                    if isinstance(poll_err, (ProviderAuthInvalidError, BindingMismatchError)):
                        raise poll_err
                    raise YunBotError(
                        ErrorCode.DELETE_PARTIAL,
                        "夸克异步删除任务未完成",
                    )

    async def _best_effort_cleanup_dir(self, norm_dir: str, *, binding_id: str) -> None:
        try:
            fid = await self._resolve_or_create_dir(
                norm_dir,
                create=False,
                binding_id=binding_id,
            )
            if fid:
                await self._delete_fids_strict([fid], binding_id=binding_id)
        except Exception as exc:
            logger.debug(
                "Best-effort cleanup of empty Quark dir %s skipped: %s",
                norm_dir,
                redact_sensitive_text(str(exc)),
            )

    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
        expected_binding_id: str | None = None,
        transient_cookie_jar: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any] | None]:
        """Execute a bounded JSON HTTP request with per-request Cookie & rolling refresh."""
        if transient_cookie_jar is not None:
            cookie_str = _serialize_cookie_jar(transient_cookie_jar)
        else:
            record = await self._credential_store.get_credential("quark")
            if (
                record is None
                or not record.access_token.strip()
                or not record.account_binding_id.strip()
            ):
                raise ProviderAuthInvalidError("夸克网盘")
            if expected_binding_id and record.account_binding_id != expected_binding_id:
                raise BindingMismatchError()
            expected_binding_id = record.account_binding_id
            cookie_str = record.access_token

        headers = {
            "Cookie": cookie_str,
            "Referer": _QUARK_REFERER,
            "Origin": _QUARK_ORIGIN,
            "Accept": _QUARK_ACCEPT,
            "User-Agent": _QUARK_USER_AGENT,
        }
        timeout = aiohttp.ClientTimeout(total=self._request_timeout)

        async with self._session.request(
            method,
            url,
            params=params,
            json=json_body,
            headers=headers,
            timeout=timeout,
        ) as resp:
            set_cookie_lines = _get_set_cookie_headers(resp.headers)
            if set_cookie_lines and resp.status not in (401, 403):
                await self._apply_set_cookie_updates(
                    set_cookie_lines,
                    expected_binding_id=expected_binding_id,
                    transient_cookie_jar=transient_cookie_jar,
                )

            try:
                parsed = await read_bounded_json(resp)
            except json.JSONDecodeError:
                parsed = None

            if parsed is not None and not isinstance(parsed, dict):
                parsed = {"status": resp.status, "code": 0, "data": parsed}

            return resp.status, parsed

    async def _apply_set_cookie_updates(
        self,
        set_cookie_lines: Sequence[str],
        *,
        expected_binding_id: str | None,
        transient_cookie_jar: dict[str, str] | None,
    ) -> None:
        """Merge Set-Cookie updates (such as `__puus` / `__pus`) preserving `account_binding_id`."""
        updates = _extract_set_cookie_updates(set_cookie_lines)
        if not updates:
            return

        if transient_cookie_jar is not None:
            transient_cookie_jar.update(updates)
            return

        if not expected_binding_id:
            return

        async with self._cookie_lock:
            current = await self._credential_store.get_credential("quark")
            if current is None or current.account_binding_id != expected_binding_id:
                return
            jar = _parse_cookie_header(current.access_token)
            changed = False
            for k, v in updates.items():
                if jar.get(k) != v:
                    jar[k] = v
                    changed = True
            if not changed:
                return
            updated_record = ProviderCredentialRecord(
                provider="quark",
                access_token=_serialize_cookie_jar(jar),
                refresh_token=current.refresh_token,
                account_binding_id=current.account_binding_id,
                extra_json=current.extra_json,
                updated_at=time.time(),
            )
            await self._credential_store.upsert_credential(updated_record)

    def _check_response_errors(
        self,
        http_status: int,
        payload: dict[str, Any] | None,
        *,
        share_context: bool = False,
        has_passcode: bool = False,
    ) -> None:
        """Translate HTTP status and Quark business codes into structured YunBotErrors."""
        if http_status == 429:
            raise ProviderRateLimitedError("夸克网盘")

        body = payload or {}
        body_status = body.get("status")
        raw_code = body.get("code")
        code_int: int | None = None
        try:
            if raw_code is not None:
                code_int = int(raw_code)
        except (TypeError, ValueError):
            code_int = None

        msg = str(body.get("message") or "").strip()
        msg_lower = msg.lower()

        if body_status == 429 or "频繁" in msg or "rate limit" in msg_lower:
            raise ProviderRateLimitedError("夸克网盘")

        if (
            http_status in (401, 403)
            or body_status in (401, 403)
            or code_int in _AUTH_INVALID_CODES
            or "未登录" in msg
            or "登录已过期" in msg
        ):
            raise ProviderAuthInvalidError("夸克网盘")

        is_ok = (
            200 <= http_status < 300
            and (body_status is None or body_status == 200)
            and code_int == 0
        )
        if is_ok:
            return

        if share_context:
            if (
                code_int in _PASSWORD_ERROR_CODES
                or "提取码" in msg
                or "密码" in msg
                or "passcode" in msg_lower
            ):
                if has_passcode:
                    raise ProviderInvalidPasswordError()
                raise ProviderNeedPasswordError()

            if (
                http_status == 404
                or body_status == 404
                or code_int in _SHARE_EXPIRED_CODES
                or any(
                    kw in msg
                    for kw in (
                        "失效",
                        "取消",
                        "不存在",
                        "已删除",
                        "删除",
                        "违规",
                        "过期",
                        "封禁",
                        "无法访问",
                    )
                )
            ):
                raise ProviderShareExpiredError()

        if (
            code_int in _QUOTA_ERROR_CODES
            or any(
                kw in msg
                for kw in ("容量", "空间不足", "空间已满", "超出上限", "文件数超限", "转存上限")
            )
            or "quota" in msg_lower
            or "capacity" in msg_lower
        ):
            raise ProviderQuotaExceededError("夸克网盘")

        safe_msg = redact_sensitive_text(msg)
        detail = f"http={http_status}, status={body_status}, code={code_int}"
        raise YunBotError(
            ErrorCode.INTERNAL_ERROR,
            f"Quark API error ({detail}): {safe_msg}",
        )
