"""OpenList async client: raw auth, binding verification, share lifecycle, and hop-by-hop streaming.

Depends strictly on Python 3.12 stdlib, aiohttp, and models (no reverse imports).
Anchored to OpenListTeam/OpenList@0497ee85 (v4.2.9, server/handles/{auth,fsread,sharing,storage}).
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import json
import logging
import shutil
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import aiohttp

from yunbot.models import (
    ALLOWED_MEDIA_EXTS,
    API_REQUEST_TIMEOUT_SECONDS,
    MAX_API_JSON_BYTES,
    MAX_OPENLIST_DIR_REQUESTS,
    MAX_OPENLIST_RECURSION_DEPTH,
    OPENLIST_REFRESH_RETRY_DELAYS_SECONDS,
    OPENLIST_SHARE_REUSE_MARGIN_SECONDS,
    OPENLIST_SHARE_URL_TEMPLATE,
    OPENLIST_STREAM_HEADER_ALLOWLIST,
    QUARK_COOKIE_ALLOWED_SUFFIXES,
    SHAREABLE_TASK_STATUSES,
    STREAM_CHUNK_SIZE_BYTES,
    STREAM_CONNECT_TIMEOUT_SECONDS,
    STREAM_MAX_REDIRECTS,
    STREAM_MIN_FREE_DISK_BYTES,
    TG_UPLOAD_SAFE_LIMIT_BYTES,
    ApiResponseTooLargeError,
    BindingMismatchError,
    ErrorCode,
    FileTooLargeForTelegramError,
    OpenListConnectionStatus,
    OpenListUnavailableError,
    ProbeMediaFile,
    ProbeResult,
    RuntimeSettingsSnapshot,
    ShareLinkResult,
    TaskRecord,
    TempDiskFullError,
    YunBotError,
    normalize_posix_path,
    read_bounded_json,
    redact_sensitive_text,
    validate_task_dir_path,
)

logger = logging.getLogger(__name__)

_PROBE_LIST_PAGE_SIZE: int = 200
_REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
_TWO_PART_TLDS: frozenset[str] = frozenset(
    {
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "co.uk",
        "org.uk",
        "co.jp",
        "ne.jp",
        "com.hk",
        "com.tw",
        "com.au",
        "com.sg",
    }
)


@dataclass(frozen=True, slots=True)
class _ApiEnvelope:
    """Normalized OpenList JSON API response envelope."""

    http_status: int
    code: int
    message: str
    data: Any


@dataclass(slots=True)
class _ProbeTracker:
    """Mutable bounded counters for a single media integrity probe run."""

    max_files: int
    fs_list_calls: int = 0
    truncated_reason: str | None = None


def _url_origin(raw_url: str) -> tuple[str, str, int] | None:
    """Extract normalized (scheme, hostname, effective_port) origin tuple from a URL."""
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in ("http", "https") or not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, host, port)


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registrable_domain(hostname: str) -> str:
    """Best-effort registrable domain extraction for same-site CDN Referer checks."""
    host = hostname.lower().rstrip(".")
    if not host or _is_ip_literal(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    tail_two = ".".join(labels[-2:])
    if tail_two in _TWO_PART_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail_two


def _same_registrable_domain(host_a: str, host_b: str) -> bool:
    a = host_a.lower().rstrip(".")
    b = host_b.lower().rstrip(".")
    if not a or not b:
        return False
    if a == b:
        return True
    if _is_ip_literal(a) or _is_ip_literal(b):
        return False
    dom_a = _registrable_domain(a)
    dom_b = _registrable_domain(b)
    return "." in dom_a and dom_a == dom_b


def _is_allowed_quark_host(hostname: str | None) -> bool:
    """Verify whether target hostname matches QUARK_COOKIE_ALLOWED_SUFFIXES."""
    if not hostname:
        return False
    host = hostname.lower().rstrip(".")
    if not host or _is_ip_literal(host):
        return False
    for suffix in QUARK_COOKIE_ALLOWED_SUFFIXES:
        norm_suffix = suffix.lower()
        bare = norm_suffix.lstrip(".")
        if host == bare or host.endswith(norm_suffix):
            return True
    return False


def _flatten_stream_headers(raw_headers: Any) -> dict[str, str]:
    """Flatten OpenList /api/fs/link header map into allowlisted single-line strings."""
    if not isinstance(raw_headers, Mapping):
        return {}
    flattened: dict[str, str] = {}
    for raw_key, raw_val in raw_headers.items():
        if not isinstance(raw_key, str):
            continue
        key_lower = raw_key.strip().lower()
        if key_lower not in OPENLIST_STREAM_HEADER_ALLOWLIST:
            continue

        value_str = ""
        if isinstance(raw_val, str):
            value_str = raw_val.strip()
        elif isinstance(raw_val, Sequence) and not isinstance(raw_val, bytes | bytearray):
            parts = [
                str(item).strip() for item in raw_val if item is not None and str(item).strip()
            ]
            sep = "; " if key_lower == "cookie" else ", "
            value_str = sep.join(parts)

        if not value_str or "\r" in value_str or "\n" in value_str or "\x00" in value_str:
            continue
        flattened[key_lower] = value_str
    return flattened


def _build_hop_headers(
    current_url: str,
    base_url: str,
    provider_id: str,
    candidate_headers: Mapping[str, str],
    *,
    initial_external_host: str | None = None,
) -> dict[str, str]:
    """Compute per-hop request headers enforcing strict Cookie & Auth isolation (§5.8.4)."""
    cur_origin = _url_origin(current_url)
    base_origin = _url_origin(base_url)
    if cur_origin is None:
        return {}

    # Same-origin OpenList proxy (/p/ or /d/?sign=): rely strictly on URL sign, zero headers.
    if base_origin is not None and cur_origin == base_origin:
        return {}

    scheme, host, _port = cur_origin
    hop_headers: dict[str, str] = {}

    ua = candidate_headers.get("user-agent")
    if ua:
        hop_headers["User-Agent"] = ua

    if provider_id == "quark":
        # Quark Cookie/Referer/Origin ONLY allowed over HTTPS to *.quark.cn / quark.cn.
        if scheme == "https" and _is_allowed_quark_host(host):
            if "cookie" in candidate_headers:
                hop_headers["Cookie"] = candidate_headers["cookie"]
            if "referer" in candidate_headers:
                hop_headers["Referer"] = candidate_headers["referer"]
            if "origin" in candidate_headers:
                hop_headers["Origin"] = candidate_headers["origin"]
    else:
        # Non-quark providers never attach Cookie; Referer/Origin require same registrable domain.
        if initial_external_host and _same_registrable_domain(host, initial_external_host):
            if "referer" in candidate_headers:
                hop_headers["Referer"] = candidate_headers["referer"]
            if "origin" in candidate_headers:
                hop_headers["Origin"] = candidate_headers["origin"]

    return hop_headers


def _match_longest_storage_mount(
    target_path: str,
    storages: Sequence[Mapping[str, Any]],
) -> tuple[Mapping[str, Any], str] | None:
    """Match an OpenList path against enabled admin storages by longest POSIX mount_path prefix."""
    norm_target = normalize_posix_path(target_path, allow_root=True)
    target_posix = PurePosixPath(norm_target)

    best_match: Mapping[str, Any] | None = None
    best_mount: str = ""
    best_len = -1

    for st in storages:
        if not isinstance(st, Mapping):
            continue
        if bool(st.get("disabled", False)):
            continue
        raw_mount = str(st.get("mount_path") or "").strip()
        if not raw_mount:
            continue
        try:
            norm_mount = normalize_posix_path(raw_mount, allow_root=True)
        except ValueError:
            continue
        mount_posix = PurePosixPath(norm_mount)
        if target_posix.is_relative_to(mount_posix) and len(norm_mount) > best_len:
            best_match = st
            best_mount = norm_mount
            best_len = len(norm_mount)

    if best_match is None:
        return None
    return (best_match, best_mount)


def _is_valid_single_segment_name(name: str) -> bool:
    stripped = (name or "").strip()
    if not stripped or stripped in (".", ".."):
        return False
    return not ("\x00" in stripped or "/" in stripped or "\\" in stripped)


class OpenListClient:
    """Async OpenList v4.2.9+ client for bindings, single-share lifecycle, and streaming."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        settings_getter: Callable[[], RuntimeSettingsSnapshot],
        storage: Any,
        task_lock_factory: Callable[[str], AbstractAsyncContextManager[Any]],
        binding_builder: Callable[[str, str], str | None] | None = None,
    ) -> None:
        self._session = session
        self._settings_getter = settings_getter
        self._storage = storage
        self._task_lock_factory = task_lock_factory
        self._binding_builder = binding_builder

        self._auth_lock = asyncio.Lock()
        self._jwt_token: str = ""
        self._jwt_config_sig: tuple[str, str, str] | None = None

        self._refresh_supported: bool | None = None
        self._refresh_config_sig: tuple[str, str, str, str] | None = None

        self._storage_list_forbidden_sig: tuple[str, str, str, str] | None = None

    @property
    def is_enabled(self) -> bool:
        return bool(self._settings_getter().openlist_base_url.strip())

    def invalidate_caches(self) -> None:
        """Clear cached JWT, refresh capability flag, and non-admin storage probe state."""
        self._jwt_token = ""
        self._jwt_config_sig = None
        self._refresh_supported = None
        self._refresh_config_sig = None
        self._storage_list_forbidden_sig = None

    def _require_base_url(self, snap: RuntimeSettingsSnapshot) -> str:
        base_url = snap.openlist_base_url.strip().rstrip("/")
        if not base_url:
            raise OpenListUnavailableError("OPENLIST_BASE_URL is not configured")
        if _url_origin(base_url) is None:
            raise OpenListUnavailableError("OPENLIST_BASE_URL has invalid scheme or host")
        return base_url

    def _public_base_url(self, snap: RuntimeSettingsSnapshot) -> str:
        base_url = self._require_base_url(snap)
        pub = snap.openlist_public_url.strip().rstrip("/")
        return pub or base_url

    def _current_auth_sig(
        self, snap: RuntimeSettingsSnapshot, base_url: str
    ) -> tuple[str, str, str, str]:
        return (
            base_url,
            snap.openlist_token.strip(),
            snap.openlist_username.strip(),
            snap.openlist_instance_epoch,
        )

    async def _get_auth_token(
        self,
        snap: RuntimeSettingsSnapshot,
        base_url: str,
        *,
        force_relogin: bool = False,
        failed_token: str | None = None,
    ) -> tuple[str, bool]:
        """Return (raw_token_or_jwt, uses_dynamic_jwt). Static openlist_token takes priority."""
        static_token = snap.openlist_token.strip()
        if static_token:
            return (static_token, False)

        username = snap.openlist_username.strip()
        password = snap.openlist_password
        if not username or not password:
            raise OpenListUnavailableError("OpenList credentials are not configured")

        jwt_sig = (base_url, username, password)
        async with self._auth_lock:
            if not force_relogin and self._jwt_token and self._jwt_config_sig == jwt_sig:
                return (self._jwt_token, True)

            if (
                force_relogin
                and failed_token
                and self._jwt_token
                and self._jwt_config_sig == jwt_sig
                and self._jwt_token != failed_token
            ):
                # Another coroutine already refreshed the JWT while we were in flight.
                return (self._jwt_token, True)

            login_url = f"{base_url}/api/auth/login"
            timeout = aiohttp.ClientTimeout(total=API_REQUEST_TIMEOUT_SECONDS)
            try:
                async with self._session.post(
                    login_url,
                    json={"username": username, "password": password},
                    timeout=timeout,
                ) as resp:
                    payload = await read_bounded_json(resp, max_bytes=MAX_API_JSON_BYTES)
                    http_status = resp.status
            except ApiResponseTooLargeError:
                raise
            except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
                self._jwt_token = ""
                logger.warning(
                    "OpenList login request failed: %s",
                    redact_sensitive_text(str(exc)),
                )
                raise OpenListUnavailableError("OpenList login request failed") from exc

            if not isinstance(payload, Mapping):
                self._jwt_token = ""
                raise OpenListUnavailableError("OpenList login returned non-object JSON")

            code = int(payload.get("code") or http_status)
            data = payload.get("data")
            token = str(data.get("token") or "").strip() if isinstance(data, Mapping) else ""
            if http_status != 200 or code != 200 or not token:
                self._jwt_token = ""
                raise OpenListUnavailableError("OpenList login rejected credentials")

            self._jwt_token = token
            self._jwt_config_sig = jwt_sig
            return (token, True)

    async def _request_json(
        self,
        method: str,
        path_and_query: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        snap: RuntimeSettingsSnapshot | None = None,
    ) -> _ApiEnvelope:
        """Execute an authenticated OpenList JSON request with raw Authorization & 401 retry."""
        cfg = snap or self._settings_getter()
        base_url = self._require_base_url(cfg)
        url = f"{base_url}{path_and_query}"
        timeout = aiohttp.ClientTimeout(total=API_REQUEST_TIMEOUT_SECONDS)

        token, uses_jwt = await self._get_auth_token(cfg, base_url, force_relogin=False)

        for attempt in range(2):
            # CRITICAL (§5.8.1): Raw Authorization header — NEVER prefix with 'Bearer '!
            headers = {"Authorization": token}
            try:
                async with self._session.request(
                    method,
                    url,
                    headers=headers,
                    json=json_body,
                    timeout=timeout,
                ) as resp:
                    http_status = resp.status
                    try:
                        payload = await read_bounded_json(resp, max_bytes=MAX_API_JSON_BYTES)
                    except json.JSONDecodeError as exc:
                        if http_status in (401, 403, 404):
                            payload = {"code": http_status, "message": "", "data": None}
                        else:
                            raise OpenListUnavailableError(
                                f"OpenList returned non-JSON response (HTTP {http_status})"
                            ) from exc
            except ApiResponseTooLargeError:
                raise
            except OpenListUnavailableError:
                raise
            except (aiohttp.ClientError, TimeoutError) as exc:
                logger.warning(
                    "OpenList API %s %s failed: %s",
                    method,
                    redact_sensitive_text(path_and_query),
                    redact_sensitive_text(str(exc)),
                )
                raise OpenListUnavailableError("OpenList service unreachable") from exc

            if not isinstance(payload, Mapping):
                raise OpenListUnavailableError("OpenList API response is not a JSON object")

            raw_code = payload.get("code")
            try:
                code = int(raw_code) if raw_code is not None else http_status
            except (TypeError, ValueError):
                code = http_status
            message = str(payload.get("message") or "")
            data = payload.get("data")

            if http_status == 401 or code == 401:
                if uses_jwt and attempt == 0:
                    token, uses_jwt = await self._get_auth_token(
                        cfg,
                        base_url,
                        force_relogin=True,
                        failed_token=token,
                    )
                    continue
                raise OpenListUnavailableError("OpenList unauthorized (401)")

            return _ApiEnvelope(
                http_status=http_status,
                code=code,
                message=message,
                data=data,
            )

        raise OpenListUnavailableError("OpenList authentication retry exhausted")

    async def _fetch_admin_storages(
        self,
        snap: RuntimeSettingsSnapshot,
        *,
        strict_admin: bool = False,
    ) -> list[Mapping[str, Any]] | None:
        """Fetch enabled/all storage entries from GET /api/admin/storage/list if permitted."""
        base_url = self._require_base_url(snap)
        auth_sig = self._current_auth_sig(snap, base_url)
        if not strict_admin and self._storage_list_forbidden_sig == auth_sig:
            return None

        env = await self._request_json("GET", "/api/admin/storage/list", snap=snap)
        if env.http_status == 403 or env.code == 403:
            self._storage_list_forbidden_sig = auth_sig
            return None
        if not strict_admin and (env.http_status == 404 or env.code == 404):
            return None
        if env.http_status != 200 or env.code != 200 or not isinstance(env.data, Mapping):
            raise OpenListUnavailableError("Failed to query OpenList storage list")

        content = env.data.get("content") or []
        if not isinstance(content, list):
            raise OpenListUnavailableError("Invalid OpenList storage list payload")
        return [item for item in content if isinstance(item, Mapping)]

    async def test_connectivity(self) -> OpenListConnectionStatus:
        """Verify connectivity, non-guest role, root base_path, share permission, and mounts."""
        snap = self._settings_getter()
        if not snap.openlist_base_url.strip():
            return OpenListConnectionStatus(
                ok=False,
                message="未配置 OPENLIST_BASE_URL",
            )

        try:
            me_env = await self._request_json("GET", "/api/me", snap=snap)
        except (OpenListUnavailableError, ApiResponseTooLargeError) as exc:
            return OpenListConnectionStatus(
                ok=False,
                message=redact_sensitive_text(str(exc)),
            )

        if me_env.http_status != 200 or me_env.code != 200 or not isinstance(me_env.data, Mapping):
            return OpenListConnectionStatus(
                ok=False,
                message=f"OpenList /api/me 返回异常状态 (code={me_env.code})",
            )

        data = me_env.data
        username = str(data.get("username") or "")
        role = int(data.get("role", 1))
        disabled = bool(data.get("disabled", False))
        raw_base_path = str(data.get("base_path") or "/")
        try:
            norm_base = normalize_posix_path(raw_base_path, allow_root=True)
        except ValueError:
            norm_base = raw_base_path

        permission = int(data.get("permission", 0) or 0)
        can_share = ((permission >> 14) & 1) == 1
        can_write_content = ((permission >> 3) & 1) == 1
        can_fs_link = role == 2

        mounted_storages: dict[str, str] | None = None
        storage_warning = ""
        if role == 2:
            try:
                storages = await self._fetch_admin_storages(snap, strict_admin=True)
            except (OpenListUnavailableError, ApiResponseTooLargeError) as exc:
                return OpenListConnectionStatus(
                    ok=False,
                    username=username,
                    role=role,
                    base_path=norm_base,
                    can_share=can_share,
                    can_write_content=can_write_content,
                    can_fs_link=can_fs_link,
                    mounted_storages=None,
                    message=redact_sensitive_text(str(exc)),
                )

            mounted_storages = {}
            if storages is not None:
                provider_paths = (
                    ("baidu", snap.openlist_baidu_path),
                    ("pikpak", snap.openlist_pikpak_path),
                    ("quark", snap.openlist_quark_path),
                )
                for pid, raw_path in provider_paths:
                    if not raw_path.strip():
                        continue
                    try:
                        norm_p = normalize_posix_path(raw_path, allow_root=False)
                    except ValueError:
                        continue
                    matched = _match_longest_storage_mount(norm_p, storages)
                    if matched is not None:
                        st, norm_mount = matched
                        mounted_storages[pid] = f"{st.get('id')}:{st.get('driver')}:{norm_mount}"

        reasons: list[str] = []
        if role == 1:
            reasons.append("不能使用访客账号 (role == 1)")
        if disabled:
            reasons.append("账号已被禁用 (disabled == true)")
        if norm_base != "/":
            reasons.append(f"账号 base_path 必须为 '/'（当前为 '{norm_base}'）")
        if not can_share:
            reasons.append("账号缺少 CanShare 分享权限位 (bit 14)")
        if storage_warning:
            reasons.append(storage_warning)

        ok = role != 1 and not disabled and norm_base == "/" and can_share
        message = "连接与权限校验通过" if ok else "；".join(reasons)

        return OpenListConnectionStatus(
            ok=ok,
            username=username,
            role=role,
            base_path=norm_base,
            can_share=can_share,
            can_write_content=can_write_content,
            can_fs_link=can_fs_link,
            mounted_storages=mounted_storages,
            message=message,
        )

    async def resolve_openlist_binding_id(
        self,
        provider_id: str,
        openlist_base_path: str,
    ) -> str | None:
        """Compute current OpenList instance + mount epoch + storage mount signature binding ID."""
        snap = self._settings_getter()
        if not snap.openlist_base_url.strip():
            return None

        norm_target = normalize_posix_path(openlist_base_path, allow_root=False)
        storages = await self._fetch_admin_storages(snap, strict_admin=False)
        storage_sig = ""
        if storages is not None:
            matched = _match_longest_storage_mount(norm_target, storages)
            if matched is not None:
                st, norm_mount = matched
                storage_sig = f"{st.get('id')}:{st.get('driver')}:{norm_mount}"
            else:
                storage_sig = "unmounted"

        if self._binding_builder is not None:
            return self._binding_builder(provider_id, storage_sig)

        inst_epoch = snap.openlist_instance_epoch or "0"
        mount_epoch = snap.get_mount_epoch(provider_id) or "0"
        if storage_sig:
            return f"ol:{inst_epoch}:{provider_id}:{mount_epoch}:{storage_sig}"
        return f"ol:{inst_epoch}:{provider_id}:{mount_epoch}"

    async def verify_task_bindings(self, task: TaskRecord) -> None:
        """Ensure task's provider account binding and OpenList mount binding match current state."""
        if not task.openlist_binding_id or not task.openlist_base_path:
            raise BindingMismatchError("Task does not carry an active OpenList binding")

        try:
            normalize_posix_path(task.openlist_base_path, allow_root=False)
        except ValueError as exc:
            raise BindingMismatchError("Task openlist_base_path is malformed") from exc

        cred = await self._storage.get_credential(task.provider)
        if (
            cred is None
            or not cred.account_binding_id
            or cred.account_binding_id != task.account_binding_id
        ):
            raise BindingMismatchError(
                "Provider account_binding_id does not match current credential"
            )

        current_ol_binding = await self.resolve_openlist_binding_id(
            task.provider,
            task.openlist_base_path,
        )
        if current_ol_binding != task.openlist_binding_id:
            raise BindingMismatchError("OpenList instance or mount binding has changed")

    async def check_task_openlist_binding(self, task: TaskRecord) -> bool:
        """Boolean wrapper around verify_task_bindings for non-throwing binding checks."""
        try:
            await self.verify_task_bindings(task)
            return True
        except BindingMismatchError:
            return False

    def _should_attempt_refresh(self, snap: RuntimeSettingsSnapshot, base_url: str) -> bool:
        sig = self._current_auth_sig(snap, base_url)
        if self._refresh_config_sig != sig:
            self._refresh_config_sig = sig
            self._refresh_supported = None
        return self._refresh_supported is not False

    async def _fs_list_call(
        self,
        openlist_path: str,
        *,
        page: int,
        per_page: int,
        want_refresh: bool,
        snap: RuntimeSettingsSnapshot,
        tracker: _ProbeTracker | None = None,
    ) -> _ApiEnvelope:
        """Call POST /api/fs/list with automatic 403 refresh=True -> refresh=False fallback."""
        base_url = self._require_base_url(snap)
        do_refresh = want_refresh and self._should_attempt_refresh(snap, base_url)

        if tracker is not None:
            if tracker.fs_list_calls >= MAX_OPENLIST_DIR_REQUESTS:
                tracker.truncated_reason = "max_dir_requests_exceeded"
                return _ApiEnvelope(
                    http_status=429, code=429, message="dir_budget_exceeded", data=None
                )
            tracker.fs_list_calls += 1

        env = await self._request_json(
            "POST",
            "/api/fs/list",
            json_body={
                "path": openlist_path,
                "password": "",
                "page": page,
                "per_page": per_page,
                "refresh": do_refresh,
            },
            snap=snap,
        )

        if do_refresh and (env.http_status == 403 or env.code == 403):
            # Missing bit 3 (CanWriteContent) -> "Refresh without permission": remember & degrade.
            self._refresh_supported = False
            if tracker is not None:
                if tracker.fs_list_calls >= MAX_OPENLIST_DIR_REQUESTS:
                    tracker.truncated_reason = "max_dir_requests_exceeded"
                    return _ApiEnvelope(
                        http_status=429,
                        code=429,
                        message="dir_budget_exceeded",
                        data=None,
                    )
                tracker.fs_list_calls += 1
            env = await self._request_json(
                "POST",
                "/api/fs/list",
                json_body={
                    "path": openlist_path,
                    "password": "",
                    "page": page,
                    "per_page": per_page,
                    "refresh": False,
                },
                snap=snap,
            )
        elif do_refresh and env.http_status == 200 and env.code == 200:
            self._refresh_supported = True

        return env

    async def refresh_directory(self, openlist_path: str) -> bool:
        """Refresh an OpenList directory cache; returns False when OpenList is disabled."""
        snap = self._settings_getter()
        if not snap.openlist_base_url.strip():
            return False

        norm_path = normalize_posix_path(openlist_path, allow_root=True)
        env = await self._fs_list_call(
            norm_path,
            page=1,
            per_page=1,
            want_refresh=True,
            snap=snap,
        )
        if env.http_status != 200 or env.code != 200:
            raise OpenListUnavailableError(
                f"Failed to refresh OpenList directory (code={env.code})"
            )
        return True

    async def _traverse_directory(
        self,
        dir_path: str,
        *,
        depth: int,
        want_initial_refresh: bool,
        snap: RuntimeSettingsSnapshot,
        tracker: _ProbeTracker,
        media_files: list[ProbeMediaFile],
        remaining_retries: list[float],
        base_path_for_retry: str,
        allow_visibility_retry: bool,
    ) -> bool:
        """Recursively traverse a directory. Returns True iff 100% complete without truncation."""
        if depth > MAX_OPENLIST_RECURSION_DEPTH:
            tracker.truncated_reason = "max_recursion_depth_exceeded"
            return False

        page = 1
        fetched_count = 0
        subdirs: list[str] = []

        while True:
            use_refresh = want_initial_refresh and page == 1
            env = await self._fs_list_call(
                dir_path,
                page=page,
                per_page=_PROBE_LIST_PAGE_SIZE,
                want_refresh=use_refresh,
                snap=snap,
                tracker=tracker,
            )
            if tracker.truncated_reason is not None:
                return False

            # Target directory may not yet be visible due to cloud-to-OpenList eventual consistency.
            while (
                page == 1
                and allow_visibility_retry
                and (env.http_status != 200 or env.code != 200)
                and remaining_retries
            ):
                delay = remaining_retries.pop(0)
                await asyncio.sleep(delay)
                refresh_env = await self._fs_list_call(
                    base_path_for_retry,
                    page=1,
                    per_page=1,
                    want_refresh=True,
                    snap=snap,
                    tracker=tracker,
                )
                if tracker.truncated_reason is not None:
                    return False
                if refresh_env.http_status != 200 or refresh_env.code != 200:
                    tracker.truncated_reason = "base_refresh_failed"
                    return False
                env = await self._fs_list_call(
                    dir_path,
                    page=1,
                    per_page=_PROBE_LIST_PAGE_SIZE,
                    want_refresh=True,
                    snap=snap,
                    tracker=tracker,
                )
                if tracker.truncated_reason is not None:
                    return False

            allow_visibility_retry = False

            if env.http_status != 200 or env.code != 200 or not isinstance(env.data, Mapping):
                tracker.truncated_reason = "fs_list_error"
                return False

            raw_content = env.data.get("content")
            if raw_content is None:
                items: list[Any] = []
            elif isinstance(raw_content, list):
                items = raw_content
            else:
                tracker.truncated_reason = "invalid_fs_list_content"
                return False

            raw_total = env.data.get("total")
            total: int | None = None
            if raw_total is not None:
                try:
                    total = max(0, int(raw_total))
                except (TypeError, ValueError):
                    tracker.truncated_reason = "invalid_total"
                    return False

            for entry in items:
                if not isinstance(entry, Mapping):
                    tracker.truncated_reason = "invalid_entry"
                    return False
                name = str(entry.get("name") or "").strip()
                if not _is_valid_single_segment_name(name):
                    tracker.truncated_reason = "invalid_entry_name"
                    return False

                child_path = f"{dir_path}/{name}" if dir_path != "/" else f"/{name}"
                if bool(entry.get("is_dir", False)):
                    if depth + 1 > MAX_OPENLIST_RECURSION_DEPTH:
                        tracker.truncated_reason = "max_recursion_depth_exceeded"
                        return False
                    subdirs.append(child_path)
                else:
                    ext = PurePosixPath(name).suffix.lower()
                    if ext in ALLOWED_MEDIA_EXTS:
                        size = max(0, int(entry.get("size") or 0))
                        media_files.append(
                            ProbeMediaFile(
                                openlist_path=child_path,
                                name=name,
                                size=size,
                                ext=ext,
                            )
                        )
                        if len(media_files) > tracker.max_files:
                            tracker.truncated_reason = "max_delivery_files_exceeded"
                            return False

            fetched_count += len(items)

            if total is not None:
                if fetched_count >= total:
                    break
                if not items:
                    tracker.truncated_reason = "pagination_incomplete"
                    return False
            else:
                if len(items) < _PROBE_LIST_PAGE_SIZE:
                    break

            page += 1

        subdirs.sort()
        for subdir_path in subdirs:
            ok = await self._traverse_directory(
                subdir_path,
                depth=depth + 1,
                want_initial_refresh=False,
                snap=snap,
                tracker=tracker,
                media_files=media_files,
                remaining_retries=remaining_retries,
                base_path_for_retry=base_path_for_retry,
                allow_visibility_retry=False,
            )
            if not ok:
                return False

        return True

    async def probe_task_media(
        self,
        task: TaskRecord,
        *,
        retry_delays: Sequence[float] = OPENLIST_REFRESH_RETRY_DELAYS_SECONDS,
    ) -> ProbeResult:
        """Refresh OpenList snapshot path and perform bounded completeness media probe (§5.8.2)."""
        snap = self._settings_getter()
        if not snap.openlist_base_url.strip():
            return ProbeResult(
                eligible=False,
                media_files=(),
                complete_traversal=False,
                truncated_reason="openlist_disabled",
            )

        # Verify provider account + OpenList mount bindings BEFORE touching OpenList paths.
        await self.verify_task_bindings(task)

        assert task.openlist_base_path is not None
        base_path = normalize_posix_path(task.openlist_base_path, allow_root=False)
        tracker = _ProbeTracker(max_files=snap.max_delivery_files)
        media_files: list[ProbeMediaFile] = []
        remaining_retries = [max(0.0, float(d)) for d in retry_delays]

        try:
            if task.no_subdir:
                items = await self._storage.list_transfer_items(task.task_id)
                if not items:
                    return ProbeResult(
                        eligible=False,
                        media_files=(),
                        complete_traversal=True,
                        truncated_reason=None,
                    )

                base_env = await self._fs_list_call(
                    base_path,
                    page=1,
                    per_page=1,
                    want_refresh=True,
                    snap=snap,
                    tracker=tracker,
                )
                if tracker.truncated_reason is not None:
                    return ProbeResult(
                        eligible=False,
                        media_files=(),
                        complete_traversal=False,
                        truncated_reason=tracker.truncated_reason,
                    )
                if base_env.http_status != 200 or base_env.code != 200:
                    return ProbeResult(
                        eligible=False,
                        media_files=(),
                        complete_traversal=False,
                        truncated_reason="base_refresh_failed",
                    )

                first_visibility_check = True
                for item in items:
                    if not _is_valid_single_segment_name(item.name):
                        return ProbeResult(
                            eligible=False,
                            media_files=tuple(media_files),
                            complete_traversal=False,
                            truncated_reason="invalid_item_name",
                        )
                    mapped_path = f"{base_path}/{item.name}"
                    if item.is_dir:
                        ok = await self._traverse_directory(
                            mapped_path,
                            depth=0,
                            want_initial_refresh=True,
                            snap=snap,
                            tracker=tracker,
                            media_files=media_files,
                            remaining_retries=remaining_retries,
                            base_path_for_retry=base_path,
                            allow_visibility_retry=first_visibility_check,
                        )
                        first_visibility_check = False
                        if not ok:
                            return ProbeResult(
                                eligible=False,
                                media_files=tuple(media_files),
                                complete_traversal=False,
                                truncated_reason=tracker.truncated_reason,
                            )
                    else:
                        ext = PurePosixPath(item.name).suffix.lower()
                        if ext not in ALLOWED_MEDIA_EXTS:
                            continue

                        get_env = await self._request_json(
                            "POST",
                            "/api/fs/get",
                            json_body={"path": mapped_path, "password": ""},
                            snap=snap,
                        )
                        while (
                            first_visibility_check
                            and (get_env.http_status != 200 or get_env.code != 200)
                            and remaining_retries
                        ):
                            delay = remaining_retries.pop(0)
                            await asyncio.sleep(delay)
                            refresh_env = await self._fs_list_call(
                                base_path,
                                page=1,
                                per_page=1,
                                want_refresh=True,
                                snap=snap,
                                tracker=tracker,
                            )
                            if tracker.truncated_reason is not None:
                                return ProbeResult(
                                    eligible=False,
                                    media_files=tuple(media_files),
                                    complete_traversal=False,
                                    truncated_reason=tracker.truncated_reason,
                                )
                            if refresh_env.http_status != 200 or refresh_env.code != 200:
                                return ProbeResult(
                                    eligible=False,
                                    media_files=tuple(media_files),
                                    complete_traversal=False,
                                    truncated_reason="base_refresh_failed",
                                )
                            get_env = await self._request_json(
                                "POST",
                                "/api/fs/get",
                                json_body={"path": mapped_path, "password": ""},
                                snap=snap,
                            )

                        first_visibility_check = False
                        if (
                            get_env.http_status != 200
                            or get_env.code != 200
                            or not isinstance(get_env.data, Mapping)
                        ):
                            return ProbeResult(
                                eligible=False,
                                media_files=tuple(media_files),
                                complete_traversal=False,
                                truncated_reason="target_not_visible",
                            )

                        if bool(get_env.data.get("is_dir", False)):
                            ok = await self._traverse_directory(
                                mapped_path,
                                depth=0,
                                want_initial_refresh=True,
                                snap=snap,
                                tracker=tracker,
                                media_files=media_files,
                                remaining_retries=remaining_retries,
                                base_path_for_retry=base_path,
                                allow_visibility_retry=False,
                            )
                            if not ok:
                                return ProbeResult(
                                    eligible=False,
                                    media_files=tuple(media_files),
                                    complete_traversal=False,
                                    truncated_reason=tracker.truncated_reason,
                                )
                        else:
                            size = max(0, int(get_env.data.get("size") or 0))
                            media_files.append(
                                ProbeMediaFile(
                                    openlist_path=mapped_path,
                                    name=item.name,
                                    size=size,
                                    ext=ext,
                                )
                            )
                            if len(media_files) > tracker.max_files:
                                return ProbeResult(
                                    eligible=False,
                                    media_files=tuple(media_files),
                                    complete_traversal=False,
                                    truncated_reason="max_delivery_files_exceeded",
                                )
            else:
                if not task.task_dir_path:
                    return ProbeResult(
                        eligible=False,
                        media_files=(),
                        complete_traversal=False,
                        truncated_reason="missing_task_dir_path",
                    )
                norm_task_dir = validate_task_dir_path(
                    task.task_dir_path,
                    task.base_save_path,
                    task.task_id,
                )
                task_dir_name = PurePosixPath(norm_task_dir).name
                openlist_task_dir = f"{base_path}/{task_dir_name}"

                base_env = await self._fs_list_call(
                    base_path,
                    page=1,
                    per_page=1,
                    want_refresh=True,
                    snap=snap,
                    tracker=tracker,
                )
                if tracker.truncated_reason is not None:
                    return ProbeResult(
                        eligible=False,
                        media_files=(),
                        complete_traversal=False,
                        truncated_reason=tracker.truncated_reason,
                    )
                if base_env.http_status != 200 or base_env.code != 200:
                    return ProbeResult(
                        eligible=False,
                        media_files=(),
                        complete_traversal=False,
                        truncated_reason="base_refresh_failed",
                    )

                ok = await self._traverse_directory(
                    openlist_task_dir,
                    depth=0,
                    want_initial_refresh=True,
                    snap=snap,
                    tracker=tracker,
                    media_files=media_files,
                    remaining_retries=remaining_retries,
                    base_path_for_retry=base_path,
                    allow_visibility_retry=True,
                )
                if not ok:
                    return ProbeResult(
                        eligible=False,
                        media_files=tuple(media_files),
                        complete_traversal=False,
                        truncated_reason=tracker.truncated_reason,
                    )

        except ApiResponseTooLargeError:
            return ProbeResult(
                eligible=False,
                media_files=tuple(media_files),
                complete_traversal=False,
                truncated_reason="response_too_large",
            )
        except (OpenListUnavailableError, ValueError):
            return ProbeResult(
                eligible=False,
                media_files=tuple(media_files),
                complete_traversal=False,
                truncated_reason="openlist_error",
            )

        media_files.sort(key=lambda item: item.openlist_path)
        eligible = 1 <= len(media_files) <= snap.max_delivery_files
        return ProbeResult(
            eligible=eligible,
            media_files=tuple(media_files),
            complete_traversal=True,
            truncated_reason=None,
        )

    async def revoke_share(self, share_id: str) -> None:
        """Revoke an OpenList share by ID; HTTP/JSON 404 or 'not found' is idempotent success."""
        cleaned_id = (share_id or "").strip()
        if not cleaned_id:
            return

        snap = self._settings_getter()
        encoded_id = quote(cleaned_id, safe="")
        env = await self._request_json(
            "POST",
            f"/api/share/delete?id={encoded_id}",
            json_body={},
            snap=snap,
        )
        msg_lower = env.message.lower()
        if env.http_status == 200 and env.code == 200:
            return
        if (
            env.http_status == 404
            or env.code == 404
            or "not found" in msg_lower
            or "not exist" in msg_lower
            or "does not exist" in msg_lower
        ):
            return

        raise OpenListUnavailableError("Failed to revoke OpenList share")

    async def create_or_get_task_share(
        self,
        task_id: str,
        *,
        now: float | None = None,
    ) -> ShareLinkResult:
        """Create, reuse, or replace the active /@s/<share_id> link under task_id lock (§5.8.3)."""
        async with self._task_lock_factory(task_id):
            task: TaskRecord | None = await self._storage.get_task(task_id)
            if task is None:
                raise OpenListUnavailableError("Task deleted")
            if task.no_subdir:
                raise YunBotError(ErrorCode.INVALID_LINK, "Direct mode forbids OpenList share")
            if task.status not in SHAREABLE_TASK_STATUSES:
                raise YunBotError(ErrorCode.TASK_BUSY)

            snap = self._settings_getter()
            public_base = self._public_base_url(snap)
            await self.verify_task_bindings(task)

            if not task.task_dir_path:
                raise YunBotError(ErrorCode.INTERNAL_ERROR, task_id=task_id)
            try:
                norm_task_dir = validate_task_dir_path(
                    task.task_dir_path,
                    task.base_save_path,
                    task.task_id,
                )
            except ValueError as exc:
                raise YunBotError(ErrorCode.INTERNAL_ERROR, task_id=task_id) from exc

            assert task.openlist_base_path is not None
            norm_ol_base = normalize_posix_path(task.openlist_base_path, allow_root=False)
            cur_now = time.time() if now is None else float(now)

            if (
                task.openlist_share_id
                and task.openlist_share_expires_at is not None
                and (task.openlist_share_expires_at - cur_now) > OPENLIST_SHARE_REUSE_MARGIN_SECONDS
            ):
                share_url = OPENLIST_SHARE_URL_TEMPLATE.format(
                    base=public_base,
                    share_id=quote(task.openlist_share_id, safe=""),
                )
                return ShareLinkResult(
                    share_id=task.openlist_share_id,
                    share_url=share_url,
                    expires_at=task.openlist_share_expires_at,
                    reused=True,
                )

            if task.openlist_share_id:
                still_unexpired = (
                    task.openlist_share_expires_at is None
                    or task.openlist_share_expires_at > cur_now
                )
                try:
                    await self.revoke_share(task.openlist_share_id)
                except (OpenListUnavailableError, ApiResponseTooLargeError) as exc:
                    if still_unexpired:
                        raise OpenListUnavailableError(
                            "Failed to revoke existing unexpired OpenList share before replacement"
                        ) from exc
                    logger.warning(
                        "Ignoring revoke failure on already-expired share for task %s: %s",
                        task_id,
                        redact_sensitive_text(str(exc)),
                    )

                await self._storage.update_task_fields(
                    task_id,
                    openlist_share_id=None,
                    openlist_share_expires_at=None,
                )

            expires_at = cur_now + (snap.openlist_share_ttl_hours * 3600)
            expires_rfc3339 = datetime.fromtimestamp(expires_at, tz=UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            openlist_task_dir = f"{norm_ol_base}/{PurePosixPath(norm_task_dir).name}"

            create_env = await self._request_json(
                "POST",
                "/api/share/create",
                json_body={
                    "files": [openlist_task_dir],
                    "expires": expires_rfc3339,
                    "pwd": "",
                    "max_accessed": 0,
                },
                snap=snap,
            )
            if (
                create_env.http_status != 200
                or create_env.code != 200
                or not isinstance(create_env.data, Mapping)
            ):
                raise OpenListUnavailableError(
                    f"OpenList share creation failed (code={create_env.code})"
                )

            new_id = str(create_env.data.get("id") or "").strip()
            if not new_id:
                raise OpenListUnavailableError("OpenList share creation returned empty id")

            try:
                await self._storage.update_task_fields(
                    task_id,
                    openlist_share_id=new_id,
                    openlist_share_expires_at=expires_at,
                )
            except BaseException:
                try:
                    await self.revoke_share(new_id)
                except Exception as revoke_exc:
                    logger.warning(
                        "Compensating revoke_share failed after DB error for task %s: %s",
                        task_id,
                        redact_sensitive_text(str(revoke_exc)),
                    )
                raise

            share_url = OPENLIST_SHARE_URL_TEMPLATE.format(
                base=public_base,
                share_id=quote(new_id, safe=""),
            )
            return ShareLinkResult(
                share_id=new_id,
                share_url=share_url,
                expires_at=expires_at,
                reused=False,
            )

    async def download_media_to_temp(
        self,
        task: TaskRecord,
        openlist_file_path: str,
        dest_path: Path,
        *,
        current_temp_bytes_getter: Callable[[], int] | None = None,
    ) -> int:
        """Stream a media file to dest_path with hop-by-hop header isolation (§5.8.4)."""
        snap = self._settings_getter()
        base_url = self._require_base_url(snap)
        await self.verify_task_bindings(task)

        assert task.openlist_base_path is not None
        norm_ol_base = normalize_posix_path(task.openlist_base_path, allow_root=False)
        norm_file_path = normalize_posix_path(openlist_file_path, allow_root=False)
        file_posix = PurePosixPath(norm_file_path)
        base_posix = PurePosixPath(norm_ol_base)
        if norm_file_path == norm_ol_base or not file_posix.is_relative_to(base_posix):
            raise BindingMismatchError("Target media path is outside task openlist_base_path")

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.unlink(missing_ok=True)

        # 1. Fetch metadata from POST /api/fs/get (ignore data.header Markdown string!).
        get_env = await self._request_json(
            "POST",
            "/api/fs/get",
            json_body={"path": norm_file_path, "password": ""},
            snap=snap,
        )
        if (
            get_env.http_status != 200
            or get_env.code != 200
            or not isinstance(get_env.data, Mapping)
        ):
            raise OpenListUnavailableError(f"OpenList /api/fs/get failed (code={get_env.code})")

        if bool(get_env.data.get("is_dir", False)):
            raise OpenListUnavailableError("Target OpenList path is a directory, not a media file")

        size = max(0, int(get_env.data.get("size") or 0))
        raw_url = str(get_env.data.get("raw_url") or "").strip()

        # 2. Pre-check Telegram upload byte cap, temp quota, and real free disk space.
        if size > TG_UPLOAD_SAFE_LIMIT_BYTES:
            raise FileTooLargeForTelegramError(dest_path.name)

        other_temp_bytes = (
            max(0, int(current_temp_bytes_getter())) if current_temp_bytes_getter is not None else 0
        )
        max_temp_bytes = snap.max_temp_disk_mb * 1024 * 1024
        if size > 0 and (other_temp_bytes + size) > max_temp_bytes:
            raise TempDiskFullError("File size exceeds temporary upload directory quota")

        disk_free = shutil.disk_usage(dest_path.parent).free
        if disk_free < (size + STREAM_MIN_FREE_DISK_BYTES):
            raise TempDiskFullError("Insufficient free disk space in temporary upload directory")

        # 3. Resolve initial URL & fetch storage HTTP headers via POST /api/fs/link if external.
        resolved_raw_url = urljoin(f"{base_url}/", raw_url) if raw_url else ""
        base_origin = _url_origin(base_url)
        raw_origin = _url_origin(resolved_raw_url) if resolved_raw_url else None

        candidate_headers: dict[str, str] = {}
        if resolved_raw_url and raw_origin is not None and raw_origin == base_origin:
            start_url = resolved_raw_url
        else:
            link_env = await self._request_json(
                "POST",
                "/api/fs/link",
                json_body={"path": norm_file_path},
                snap=snap,
            )
            if (
                link_env.http_status == 200
                and link_env.code == 200
                and isinstance(link_env.data, Mapping)
            ):
                link_url = str(link_env.data.get("url") or "").strip()
                start_url = urljoin(f"{base_url}/", link_url) if link_url else resolved_raw_url
                candidate_headers = _flatten_stream_headers(link_env.data.get("header"))
            elif link_env.http_status == 403 or link_env.code == 403:
                start_url = resolved_raw_url
                candidate_headers = {}
            else:
                raise OpenListUnavailableError(
                    f"OpenList /api/fs/link failed (code={link_env.code})"
                )

        if not start_url:
            raise OpenListUnavailableError("OpenList returned an empty media download URL")

        start_origin = _url_origin(start_url)
        if start_origin is None:
            raise OpenListUnavailableError("Invalid media download URL scheme or host")

        initial_external_host: str | None = start_origin[1] if start_origin != base_origin else None
        saw_https = start_origin[0] == "https"

        # 4. Manual hop-by-hop redirect loop (allow_redirects=False, max STREAM_MAX_REDIRECTS hops).
        visited_urls: set[str] = set()
        current_url = start_url
        stream_timeout = aiohttp.ClientTimeout(
            total=None,
            connect=STREAM_CONNECT_TIMEOUT_SECONDS,
            sock_connect=STREAM_CONNECT_TIMEOUT_SECONDS,
            sock_read=API_REQUEST_TIMEOUT_SECONDS,
        )

        try:
            for hop_idx in range(STREAM_MAX_REDIRECTS + 1):
                hop_origin = _url_origin(current_url)
                if hop_origin is None:
                    raise OpenListUnavailableError("Invalid redirect URL scheme or host")

                hop_scheme, hop_host, _hop_port = hop_origin
                if saw_https and hop_scheme != "https":
                    raise OpenListUnavailableError(
                        "Blocked insecure HTTPS to HTTP redirect downgrade"
                    )
                if hop_scheme == "https":
                    saw_https = True
                if initial_external_host is None and hop_origin != base_origin:
                    initial_external_host = hop_host

                visited_urls.add(current_url)
                hop_headers = _build_hop_headers(
                    current_url,
                    base_url,
                    task.provider,
                    candidate_headers,
                    initial_external_host=initial_external_host,
                )

                try:
                    async with self._session.get(
                        current_url,
                        headers=hop_headers,
                        allow_redirects=False,
                        timeout=stream_timeout,
                    ) as resp:
                        if resp.status in _REDIRECT_STATUSES:
                            location = resp.headers.get("Location", "").strip()
                            if not location:
                                raise OpenListUnavailableError(
                                    "Redirect response missing Location header"
                                )
                            if hop_idx >= STREAM_MAX_REDIRECTS:
                                raise OpenListUnavailableError(
                                    f"Exceeded maximum stream redirects ({STREAM_MAX_REDIRECTS})"
                                )
                            next_url = urljoin(current_url, location)
                            if next_url in visited_urls:
                                raise OpenListUnavailableError(
                                    "Redirect loop detected during media download"
                                )
                            current_url = next_url
                            continue

                        if resp.status != 200:
                            raise OpenListUnavailableError(
                                f"Media download failed with HTTP {resp.status}"
                            )

                        raw_cl = resp.headers.get("Content-Length", "").strip()
                        if raw_cl.isdigit():
                            cl = int(raw_cl)
                            if cl > TG_UPLOAD_SAFE_LIMIT_BYTES:
                                raise FileTooLargeForTelegramError(dest_path.name)
                            live_max_temp = self._settings_getter().max_temp_disk_mb * 1024 * 1024
                            if (other_temp_bytes + cl) > live_max_temp:
                                raise TempDiskFullError(
                                    "Content-Length exceeds temporary upload quota"
                                )
                            if shutil.disk_usage(dest_path.parent).free < (
                                cl + STREAM_MIN_FREE_DISK_BYTES
                            ):
                                raise TempDiskFullError(
                                    "Insufficient free disk space for Content-Length"
                                )

                        written = 0
                        with dest_path.open("wb") as fh:
                            async for chunk in resp.content.iter_chunked(STREAM_CHUNK_SIZE_BYTES):
                                if not chunk:
                                    continue
                                written += len(chunk)
                                if written > TG_UPLOAD_SAFE_LIMIT_BYTES:
                                    raise FileTooLargeForTelegramError(dest_path.name)
                                live_max_temp = (
                                    self._settings_getter().max_temp_disk_mb * 1024 * 1024
                                )
                                if (other_temp_bytes + written) > live_max_temp:
                                    raise TempDiskFullError(
                                        "Temporary upload directory quota exceeded during stream"
                                    )
                                try:
                                    fh.write(chunk)
                                except OSError as os_exc:
                                    if os_exc.errno == errno.ENOSPC:
                                        raise TempDiskFullError(
                                            "Filesystem reported ENOSPC during media write"
                                        ) from os_exc
                                    raise

                        return written

                except (aiohttp.ClientError, TimeoutError) as exc:
                    logger.warning(
                        "Media stream request failed on hop %d: %s",
                        hop_idx,
                        redact_sensitive_text(str(exc)),
                    )
                    raise OpenListUnavailableError("Media download stream interrupted") from exc

            raise OpenListUnavailableError("Stream redirect loop terminated unexpectedly")
        except BaseException:
            dest_path.unlink(missing_ok=True)
            raise
