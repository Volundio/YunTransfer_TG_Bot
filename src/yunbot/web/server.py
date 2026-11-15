"""Admin-only aiohttp.web server, R02 authentication middleware, and dynamic provider APIs.

Implements DEVELOPMENT.md §2.2, §5.2 and R02:
- Only `GET /login` (and `GET /` -> `302 /login`) is publicly reachable without a session.
- `POST /api/auth/exchange` is the sole unauthenticated `/api/*` exception, strictly enforcing
  body size <= 64 KiB, `Content-Type: application/json`, `Origin == WEB_BASE_URL`, trusted-proxy
  IP sliding-window rate limiting, and single-lock atomic OTT consumption.
- Every other `/api/*` endpoint (both `GET` reads and `POST` writes) requires a valid admin
  session Cookie; all non-`GET/HEAD` requests additionally require JSON + matching `Origin`.
- Zero mutating `GET/HEAD` endpoints (`POST /api/providers/{id}/auth/poll`).
- Zero hardcoded cloud provider branches in Tab 2 routes; driven by `ProviderSpec`.
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import logging
from collections.abc import Callable, Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from aiohttp import web

from yunbot.config.bootstrap import (
    parse_bounded_int,
    parse_http_url,
    parse_strict_bool,
    validate_clean_string,
    validate_log_level,
)
from yunbot.models import (
    DELETABLE_TASK_STATUSES,
    MAX_DELIVERY_FILES_MAX,
    MAX_DELIVERY_FILES_MIN,
    MAX_GROUP_WHITELIST_COUNT,
    MAX_RETAINED_TASKS_MAX,
    MAX_RETAINED_TASKS_MIN,
    MAX_TEMP_DISK_MB_MAX,
    MAX_TEMP_DISK_MB_MIN,
    OPENLIST_SHARE_TTL_HOURS_MAX,
    OPENLIST_SHARE_TTL_HOURS_MIN,
    PENDING_INPUT_TTL_SECONDS_MAX,
    PENDING_INPUT_TTL_SECONDS_MIN,
    WEB_MAX_BODY_BYTES,
    AccessEntry,
    AccessListType,
    AuthMode,
    BindingMismatchError,
    BootstrapConfigSnapshot,
    ErrorCode,
    GroupWhitelistEntry,
    OpenListConnectionStatus,
    ProviderAccountStatus,
    RuntimeSettingsSnapshot,
    TaskRecord,
    TaskStatus,
    YunBotError,
    normalize_posix_path,
    redact_sensitive_text,
    validate_save_path,
)
from yunbot.providers.base import CloudProvider, ProviderSpec
from yunbot.providers.registry import ProviderRegistry
from yunbot.web.auth import WebAuthManager

logger = logging.getLogger(__name__)

STATIC_INDEX_PATH: Path = Path(__file__).resolve().parent / "static" / "index.html"
AUTH_MANAGER_APP_KEY: web.AppKey[WebAuthManager] = web.AppKey("auth_manager", WebAuthManager)

CSP_HEADER_VALUE: str = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

READONLY_TRUST_ROOT_KEYS: frozenset[str] = frozenset(
    {
        "TELEGRAM_ADMIN_ID",
        "WEB_BASE_URL",
        "WEB_TRUSTED_PROXIES",
        "WEB_ORIGIN",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_API_ID",
        "TELEGRAM_API_HASH",
        "TELEGRAM_API_BASE_URL",
        "WEB_INTERNAL_PORT",
        "DATA_DIR",
        "SHARED_UPLOAD_DIR",
        "TZ",
    }
)

SECRET_SETTING_CLEAR_FLAGS: dict[str, str] = {
    "OPENLIST_TOKEN": "CLEAR_OPENLIST_TOKEN",
    "OPENLIST_PASSWORD": "CLEAR_OPENLIST_PASSWORD",
    "BAIDU_CLIENT_SECRET": "CLEAR_BAIDU_CLIENT_SECRET",
}


# ==============================================================================
# Injected Application-Layer Protocols (Single-Direction DAG, §4.1)
# ==============================================================================


@runtime_checkable
class RuntimeConfigService(Protocol):
    """Contract for runtime configuration center injected into WebServer."""

    @property
    def bootstrap(self) -> BootstrapConfigSnapshot: ...

    def snapshot(self) -> RuntimeSettingsSnapshot: ...

    async def update_settings(
        self,
        updates: Mapping[str, Any],
        *,
        updated_by: int,
    ) -> RuntimeSettingsSnapshot: ...

    async def bump_openlist_mount_epochs(
        self,
        *,
        updated_by: int,
    ) -> RuntimeSettingsSnapshot: ...


@runtime_checkable
class OpenListService(Protocol):
    """Contract for OpenList connectivity and binding inspection."""

    async def test_connectivity(self) -> OpenListConnectionStatus: ...


@runtime_checkable
class AccessService(Protocol):
    """Contract for user whitelist/blacklist and group whitelist management."""

    async def list_access_entries(self) -> Sequence[AccessEntry]: ...

    async def list_group_whitelist(self) -> Sequence[GroupWhitelistEntry]: ...

    async def add_user(
        self, user_id: int, list_type: AccessListType, *, operator_id: int
    ) -> None: ...

    async def remove_user(self, user_id: int, *, operator_id: int) -> None: ...

    async def add_group(self, chat_id: int, *, operator_id: int) -> None: ...

    async def remove_group(self, chat_id: int, *, operator_id: int) -> None: ...

    async def reset_to_initial(self, *, operator_id: int) -> None: ...


@runtime_checkable
class TaskStorageReader(Protocol):
    """Read-only task query contract injected from storage."""

    async def list_tasks(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        status: TaskStatus | None = None,
    ) -> Sequence[TaskRecord]: ...

    async def count_tasks(self, *, status: TaskStatus | None = None) -> int: ...


@runtime_checkable
class TaskDeletionServiceProtocol(Protocol):
    """Contract for safe cloud-linked or detach-only task deletion (§5.10.2)."""

    async def delete_task_with_cloud_files(
        self,
        task_id: str,
        *,
        operator_id: int,
        detach_only: bool = False,
    ) -> Any: ...


# ==============================================================================
# Pure Helpers & Flexible Signature Adapters
# ==============================================================================


def _apply_security_headers(request: web.BaseRequest, response: web.StreamResponse) -> None:
    response.headers["Content-Security-Policy"] = CSP_HEADER_VALUE
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if (
        request.path == "/api"
        or request.path.startswith("/api/")
        or request.path in ("/", "/login")
    ):
        response.headers["Cache-Control"] = "no-store"


def _json_error(status: int, error: str, message: str) -> web.Response:
    safe_msg = redact_sensitive_text(message)
    return web.json_response(
        {"ok": False, "error": error, "message": safe_msg},
        status=status,
    )


def _is_json_content_type(request: web.BaseRequest) -> bool:
    raw_ct = request.headers.get("Content-Type", "")
    if not raw_ct:
        return False
    media_type = raw_ct.split(";", 1)[0].strip().lower()
    return media_type == "application/json"


async def _read_json_object(
    request: web.Request,
    *,
    allow_empty: bool = False,
) -> dict[str, Any]:
    """Read bounded request body and parse as a JSON object (`dict`)."""
    if request.content_length is not None and request.content_length > WEB_MAX_BODY_BYTES:
        raise web.HTTPRequestEntityTooLarge(
            max_size=WEB_MAX_BODY_BYTES,
            actual_size=request.content_length,
        )
    raw = await request.read()
    if len(raw) > WEB_MAX_BODY_BYTES:
        raise web.HTTPRequestEntityTooLarge(
            max_size=WEB_MAX_BODY_BYTES,
            actual_size=len(raw),
        )
    if not raw or not raw.strip():
        if allow_empty:
            return {}
        raise ValueError("请求体不能为空，且必须为 JSON 对象")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("无效的 JSON 请求体") from exc
    if not isinstance(parsed, dict):
        raise ValueError("JSON 请求体顶层必须为对象")
    return parsed


def _to_jsonable(value: Any) -> Any:
    """Recursively convert dataclasses, enums, tuples/sets, and redact strings for JSON."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Enum):
        raw_val = value.value
        return redact_sensitive_text(raw_val) if isinstance(raw_val, str) else raw_val
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(k): _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, Sequence | set | frozenset) and not isinstance(value, bytes | bytearray):
        return [_to_jsonable(item) for item in value]
    return redact_sensitive_text(str(value))


def _provider_supports_mode(spec: ProviderSpec, mode: AuthMode) -> bool:
    return spec.auth_mode == mode or mode in spec.extra_auth_modes


def _serialize_account_status(account: ProviderAccountStatus) -> dict[str, Any]:
    return {
        "provider_id": account.provider_id,
        "authorized": bool(account.authorized),
        "account_binding_id": account.account_binding_id,
        "account_label": redact_sensitive_text(account.account_label or ""),
        "auth_mode_used": account.auth_mode_used,
        "updated_at": account.updated_at,
        "message": redact_sensitive_text(account.message or ""),
    }


def _get_runtime_snapshot(runtime_config: Any) -> RuntimeSettingsSnapshot:
    for attr in ("snapshot", "get_snapshot"):
        fn = getattr(runtime_config, attr, None)
        if callable(fn):
            res = fn()
            if isinstance(res, RuntimeSettingsSnapshot):
                return res
    for prop in ("current", "settings"):
        val = getattr(runtime_config, prop, None)
        if isinstance(val, RuntimeSettingsSnapshot):
            return val
    raise RuntimeError("runtime_config does not expose a RuntimeSettingsSnapshot")


def _mask_runtime_settings(snap: RuntimeSettingsSnapshot) -> dict[str, Any]:
    """Serialize RuntimeSettingsSnapshot strictly masking all secret fields."""
    return {
        "whitelist_enabled": snap.whitelist_enabled,
        "openlist_base_url": snap.openlist_base_url,
        "openlist_public_url": snap.openlist_public_url,
        "has_openlist_token": bool(snap.openlist_token),
        "openlist_username": snap.openlist_username,
        "has_openlist_password": bool(snap.openlist_password),
        "openlist_baidu_path": snap.openlist_baidu_path,
        "openlist_pikpak_path": snap.openlist_pikpak_path,
        "openlist_quark_path": snap.openlist_quark_path,
        "openlist_share_ttl_hours": snap.openlist_share_ttl_hours,
        "baidu_client_id": snap.baidu_client_id,
        "has_baidu_client_secret": bool(snap.baidu_client_secret),
        "baidu_save_path": snap.baidu_save_path,
        "pikpak_save_path": snap.pikpak_save_path,
        "pikpak_direct_exclusive_dir": snap.pikpak_direct_exclusive_dir,
        "quark_save_path": snap.quark_save_path,
        "max_delivery_files": snap.max_delivery_files,
        "max_temp_disk_mb": snap.max_temp_disk_mb,
        "pending_input_ttl_seconds": snap.pending_input_ttl_seconds,
        "max_retained_tasks": snap.max_retained_tasks,
        "log_level": snap.log_level,
    }


def _serialize_epochs(snap: RuntimeSettingsSnapshot) -> dict[str, Any]:
    return {
        "instance_epoch": snap.openlist_instance_epoch,
        "mount_epochs": dict(snap.openlist_mount_epochs),
    }


def _build_editable_validators(
    providers: Sequence[CloudProvider],
) -> dict[str, tuple[Callable[[Any], Any], bool]]:
    """Build `(validator, is_secret)` table for all Web-editable runtime settings."""
    table: dict[str, tuple[Callable[[Any], Any], bool]] = {
        "WHITELIST_ENABLED": (
            lambda v: parse_strict_bool(v, field_name="WHITELIST_ENABLED"),
            False,
        ),
        "OPENLIST_BASE_URL": (
            lambda v: parse_http_url(v, field_name="OPENLIST_BASE_URL", allow_empty=True),
            False,
        ),
        "OPENLIST_PUBLIC_URL": (
            lambda v: parse_http_url(v, field_name="OPENLIST_PUBLIC_URL", allow_empty=True),
            False,
        ),
        "OPENLIST_TOKEN": (
            lambda v: validate_clean_string(v, field_name="OPENLIST_TOKEN"),
            True,
        ),
        "OPENLIST_USERNAME": (
            lambda v: validate_clean_string(v, field_name="OPENLIST_USERNAME"),
            False,
        ),
        "OPENLIST_PASSWORD": (
            lambda v: validate_clean_string(v, field_name="OPENLIST_PASSWORD", strip=False),
            True,
        ),
        "OPENLIST_BAIDU_PATH": (
            lambda v: normalize_posix_path(v, allow_root=False),
            False,
        ),
        "OPENLIST_PIKPAK_PATH": (
            lambda v: normalize_posix_path(v, allow_root=False),
            False,
        ),
        "OPENLIST_QUARK_PATH": (
            lambda v: normalize_posix_path(v, allow_root=False),
            False,
        ),
        "OPENLIST_SHARE_TTL_HOURS": (
            lambda v: parse_bounded_int(
                v,
                field_name="OPENLIST_SHARE_TTL_HOURS",
                min_value=OPENLIST_SHARE_TTL_HOURS_MIN,
                max_value=OPENLIST_SHARE_TTL_HOURS_MAX,
            ),
            False,
        ),
        "BAIDU_CLIENT_ID": (
            lambda v: validate_clean_string(v, field_name="BAIDU_CLIENT_ID"),
            False,
        ),
        "BAIDU_CLIENT_SECRET": (
            lambda v: validate_clean_string(v, field_name="BAIDU_CLIENT_SECRET"),
            True,
        ),
        "BAIDU_SAVE_PATH": (validate_save_path, False),
        "PIKPAK_SAVE_PATH": (validate_save_path, False),
        "PIKPAK_DIRECT_EXCLUSIVE_DIR": (
            lambda v: parse_strict_bool(v, field_name="PIKPAK_DIRECT_EXCLUSIVE_DIR"),
            False,
        ),
        "QUARK_SAVE_PATH": (validate_save_path, False),
        "MAX_DELIVERY_FILES": (
            lambda v: parse_bounded_int(
                v,
                field_name="MAX_DELIVERY_FILES",
                min_value=MAX_DELIVERY_FILES_MIN,
                max_value=MAX_DELIVERY_FILES_MAX,
            ),
            False,
        ),
        "MAX_TEMP_DISK_MB": (
            lambda v: parse_bounded_int(
                v,
                field_name="MAX_TEMP_DISK_MB",
                min_value=MAX_TEMP_DISK_MB_MIN,
                max_value=MAX_TEMP_DISK_MB_MAX,
            ),
            False,
        ),
        "PENDING_INPUT_TTL_SECONDS": (
            lambda v: parse_bounded_int(
                v,
                field_name="PENDING_INPUT_TTL_SECONDS",
                min_value=PENDING_INPUT_TTL_SECONDS_MIN,
                max_value=PENDING_INPUT_TTL_SECONDS_MAX,
            ),
            False,
        ),
        "MAX_RETAINED_TASKS": (
            lambda v: parse_bounded_int(
                v,
                field_name="MAX_RETAINED_TASKS",
                min_value=MAX_RETAINED_TASKS_MIN,
                max_value=MAX_RETAINED_TASKS_MAX,
            ),
            False,
        ),
        "LOG_LEVEL": (validate_log_level, False),
    }

    for provider in providers:
        save_key = provider.spec.save_path_key.upper()
        ol_key = provider.spec.openlist_path_key.upper()
        if save_key not in table:
            table[save_key] = (validate_save_path, False)
        if ol_key not in table:
            table[ol_key] = (lambda v: normalize_posix_path(v, allow_root=False), False)
    return table


async def _call_maybe_async(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    res = fn(*args, **kwargs)
    if inspect.isawaitable(res):
        return await res
    return res


def _bind_operator_kwarg(
    fn: Callable[..., Any],
    admin_id: int,
    extra_kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Match operator/admin keyword parameter name across parallel service implementations."""
    kwargs = dict(extra_kwargs or {})
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        kwargs["operator_id"] = admin_id
        return kwargs

    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    for candidate in ("updated_by", "operator_id", "created_by", "actor_id", "admin_id"):
        if candidate in params:
            kwargs[candidate] = admin_id
            break
    else:
        if has_var_kw:
            kwargs["updated_by"] = admin_id

    if not has_var_kw:
        kwargs = {k: v for k, v in kwargs.items() if k in params}
    return kwargs


async def _invoke_update_settings(
    runtime_config: Any,
    updates: dict[str, Any],
    *,
    admin_id: int,
) -> RuntimeSettingsSnapshot:
    fn = runtime_config.update_settings
    try:
        sig = inspect.signature(fn)
        positional_params = [
            p
            for p in sig.parameters.values()
            if p.kind
            in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
    except (TypeError, ValueError):
        positional_params = [inspect.Parameter("updates", inspect.Parameter.POSITIONAL_OR_KEYWORD)]

    op_kwargs = _bind_operator_kwarg(fn, admin_id)
    if positional_params:
        try:
            res = await _call_maybe_async(fn, updates, **op_kwargs)
        except KeyError:
            lowered = {k.lower(): v for k, v in updates.items()}
            res = await _call_maybe_async(fn, lowered, **op_kwargs)
    else:
        merged = {k.lower(): v for k, v in updates.items()}
        merged.update(op_kwargs)
        res = await _call_maybe_async(fn, **merged)

    if isinstance(res, RuntimeSettingsSnapshot):
        return res
    return _get_runtime_snapshot(runtime_config)


def _resolve_provider_paths(snap: RuntimeSettingsSnapshot, spec: ProviderSpec) -> tuple[str, str]:
    try:
        save_path = snap.get_save_path(spec.save_path_key)
    except KeyError:
        save_path = getattr(snap, spec.save_path_key.lower(), spec.default_save_path)
    try:
        openlist_path = snap.get_openlist_path(spec.openlist_path_key)
    except KeyError:
        openlist_path = getattr(snap, spec.openlist_path_key.lower(), spec.default_openlist_path)
    return save_path, openlist_path


def _resolve_oauth_config_fields(
    snap: RuntimeSettingsSnapshot, spec: ProviderSpec
) -> list[dict[str, Any]]:
    """Build non-sensitive OAuth client config descriptors dynamically without provider branches."""
    if not _provider_supports_mode(spec, AuthMode.OAUTH_CODE):
        return []

    fields_out: list[dict[str, Any]] = []
    if spec.secret_fields and not _provider_supports_mode(spec, AuthMode.SECRET_FIELDS):
        for f in spec.secret_fields:
            attr_val = getattr(snap, f.key.lower(), "")
            fields_out.append(
                {
                    "key": f.key,
                    "label": f.label,
                    "secret": f.secret,
                    "required": f.required,
                    "placeholder": f.placeholder,
                    "help_text": f.help_text,
                    "configured": bool(attr_val),
                    "current_value": "" if f.secret else str(attr_val or ""),
                }
            )
        return fields_out

    pid_lower = spec.provider_id.lower()
    pid_upper = spec.provider_id.upper()
    cid_attr = f"{pid_lower}_client_id"
    csec_attr = f"{pid_lower}_client_secret"
    if hasattr(snap, cid_attr):
        cid_val = str(getattr(snap, cid_attr) or "")
        fields_out.append(
            {
                "key": f"{pid_upper}_CLIENT_ID",
                "label": f"{spec.display_name} AppKey / Client ID",
                "secret": False,
                "required": False,
                "placeholder": f"输入 {pid_upper}_CLIENT_ID",
                "help_text": "",
                "configured": bool(cid_val),
                "current_value": cid_val,
            }
        )
    if hasattr(snap, csec_attr):
        csec_val = str(getattr(snap, csec_attr) or "")
        fields_out.append(
            {
                "key": f"{pid_upper}_CLIENT_SECRET",
                "label": f"{spec.display_name} SecretKey / Client Secret",
                "secret": True,
                "required": False,
                "placeholder": "留空保持原密钥不变",
                "help_text": "",
                "configured": bool(csec_val),
                "current_value": "",
            }
        )
    return fields_out


async def _serialize_provider_card(
    provider: CloudProvider,
    snap: RuntimeSettingsSnapshot,
    runtime_config: Any,
) -> dict[str, Any]:
    spec = provider.spec
    try:
        account = await provider.get_account_status()
    except Exception as exc:
        logger.warning("Failed to query account status for %s: %s", spec.provider_id, exc)
        account = ProviderAccountStatus(
            provider_id=spec.provider_id,
            authorized=False,
            message="读取账号状态失败",
        )

    try:
        oauth_url = provider.get_oauth_authorize_url()
    except Exception:
        oauth_url = None

    save_path, openlist_path = _resolve_provider_paths(snap, spec)
    check_excl = getattr(runtime_config, "is_direct_exclusive_dir_confirmed", None)
    if callable(check_excl):
        direct_confirmed = bool(check_excl(spec.provider_id))
    elif spec.requires_exclusive_dir_for_direct:
        direct_confirmed = bool(
            getattr(snap, f"{spec.provider_id.lower()}_direct_exclusive_dir", False)
        )
    else:
        direct_confirmed = True

    return {
        "provider_id": spec.provider_id,
        "display_name": spec.display_name,
        "command": spec.command,
        "password_policy": spec.password_policy.value,
        "auth_mode": spec.auth_mode.value,
        "extra_auth_modes": [m.value for m in spec.extra_auth_modes],
        "save_path_key": spec.save_path_key,
        "openlist_path_key": spec.openlist_path_key,
        "default_save_path": spec.default_save_path,
        "default_openlist_path": spec.default_openlist_path,
        "save_path": save_path,
        "openlist_path": openlist_path,
        "requires_exclusive_dir_for_direct": spec.requires_exclusive_dir_for_direct,
        "direct_exclusive_dir_confirmed": direct_confirmed,
        "secret_fields": [
            {
                "key": f.key,
                "label": f.label,
                "secret": f.secret,
                "required": f.required,
                "placeholder": f.placeholder,
                "help_text": f.help_text,
            }
            for f in spec.secret_fields
        ],
        "oauth_config_fields": _resolve_oauth_config_fields(snap, spec),
        "oauth_authorize_url": oauth_url,
        "account": _serialize_account_status(account),
    }


# ==============================================================================
# Application Factory & Route Handlers
# ==============================================================================


class _WebPanelHandler:
    """Request handler collection bound to injected domain services."""

    def __init__(
        self,
        *,
        bootstrap: BootstrapConfigSnapshot,
        runtime_config: Any,
        providers: ProviderRegistry,
        storage: Any,
        access: Any,
        openlist: Any = None,
        deletion_service: Any = None,
        auth_manager: WebAuthManager,
        index_html: str,
    ) -> None:
        self.bootstrap = bootstrap
        self.runtime_config = runtime_config
        self.providers = providers
        self.storage = storage
        self.access = access
        self.openlist = openlist
        self.deletion_service = deletion_service
        self.auth = auth_manager
        self.index_html = index_html

    @property
    def admin_id(self) -> int:
        return self.bootstrap.telegram_admin_id

    # ------------------------------------------------------------------
    # Middlewares (Security Headers + R02 Exact Auth Matrix)
    # ------------------------------------------------------------------

    @web.middleware
    async def security_and_error_middleware(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Any],
    ) -> web.StreamResponse:
        try:
            response = await handler(request)
        except web.HTTPRequestEntityTooLarge:
            response = _json_error(
                413,
                "PAYLOAD_TOO_LARGE",
                f"请求体超过最大允许上限 ({WEB_MAX_BODY_BYTES} 字节)",
            )
        except web.HTTPMethodNotAllowed as exc:
            response = _json_error(405, "METHOD_NOT_ALLOWED", "不允许的 HTTP 请求方法")
            response.headers["Allow"] = ",".join(sorted(exc.allowed_methods))
        except web.HTTPNotFound:
            response = _json_error(404, "NOT_FOUND", "请求的接口或页面不存在")
        except web.HTTPException as exc:
            _apply_security_headers(request, exc)
            raise
        except BindingMismatchError as exc:
            response = _json_error(409, ErrorCode.BINDING_MISMATCH.value, exc.user_message)
        except YunBotError as exc:
            status_map = {
                ErrorCode.RATE_LIMITED: 429,
                ErrorCode.TASK_BUSY: 409,
                ErrorCode.BINDING_MISMATCH: 409,
                ErrorCode.ACCESS_DENIED: 403,
                ErrorCode.UNAUTHORIZED_PANEL_ACTION: 403,
            }
            http_status = status_map.get(exc.code, 400)
            response = _json_error(http_status, exc.code.value, exc.user_message)
        except ValueError as exc:
            response = _json_error(400, "INVALID_ARGUMENT", str(exc))
        except Exception:
            logger.exception("Unhandled error in web request %s %s", request.method, request.path)
            response = _json_error(500, ErrorCode.INTERNAL_ERROR.value, "服务器内部错误")

        _apply_security_headers(request, response)
        return response

    @web.middleware
    async def auth_boundary_middleware(
        self,
        request: web.Request,
        handler: Callable[[web.Request], Any],
    ) -> web.StreamResponse:
        # Preserve 405 Method Not Allowed on registered routes before session checks
        # (e.g. rejecting GET /api/providers/{id}/auth/poll with 405 per R02).
        http_exc = getattr(request.match_info, "http_exception", None)
        if isinstance(http_exc, web.HTTPMethodNotAllowed):
            raise http_exc

        path = request.path

        # 1. Public unauthenticated entry: GET/HEAD /login and GET/HEAD /
        if path in ("/login", "/") and request.method in ("GET", "HEAD"):
            return await handler(request)

        # 2. Sole unauthenticated API exception: POST /api/auth/exchange
        if path == "/api/auth/exchange" and request.method == "POST":
            return await handler(request)

        # 3. All other /api/* routes strictly require a valid admin session Cookie
        if path == "/api" or path.startswith("/api/"):
            raw_cookie = request.cookies.get(self.auth.session_manager.cookie_name)
            if not self.auth.session_manager.validate_session(raw_cookie):
                return _json_error(
                    401,
                    "UNAUTHORIZED",
                    "未登录或管理员会话已过期，请在 Telegram 私聊发送 /web 获取登录链接",
                )

            if request.method not in ("GET", "HEAD"):
                if (
                    request.content_length is not None
                    and request.content_length > WEB_MAX_BODY_BYTES
                ):
                    raise web.HTTPRequestEntityTooLarge(
                        max_size=WEB_MAX_BODY_BYTES,
                        actual_size=request.content_length,
                    )
                if not _is_json_content_type(request):
                    return _json_error(
                        415,
                        "UNSUPPORTED_MEDIA_TYPE",
                        "Content-Type 必须为 application/json",
                    )
                if not self.auth.is_valid_origin(request.headers.get("Origin")):
                    return _json_error(
                        403,
                        "FORBIDDEN_ORIGIN",
                        "Origin 校验未通过",
                    )

            return await handler(request)

        raise web.HTTPNotFound()

    # ------------------------------------------------------------------
    # Static Entry & Auth Exchange Routes
    # ------------------------------------------------------------------

    async def handle_root(self, request: web.Request) -> web.StreamResponse:
        raw_cookie = request.cookies.get(self.auth.session_manager.cookie_name)
        if not self.auth.session_manager.validate_session(raw_cookie):
            raise web.HTTPFound(location="/login")
        return web.Response(text=self.index_html, content_type="text/html", charset="utf-8")

    async def handle_login_page(self, _request: web.Request) -> web.StreamResponse:
        return web.Response(text=self.index_html, content_type="text/html", charset="utf-8")

    async def handle_auth_exchange(self, request: web.Request) -> web.Response:
        """Sole unauthenticated API endpoint (`R02` strict 5-step validation order)."""
        # Step 1: Body size <= WEB_MAX_BODY_BYTES
        if request.content_length is not None and request.content_length > WEB_MAX_BODY_BYTES:
            raise web.HTTPRequestEntityTooLarge(
                max_size=WEB_MAX_BODY_BYTES,
                actual_size=request.content_length,
            )

        # Step 2: Content-Type starts with application/json
        if not _is_json_content_type(request):
            return _json_error(
                415,
                "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type 必须为 application/json",
            )

        # Step 3: Origin == bootstrap.web_origin
        if not self.auth.is_valid_origin(request.headers.get("Origin")):
            return _json_error(
                403,
                "FORBIDDEN_ORIGIN",
                "请求 Origin 与 WEB_BASE_URL 不一致",
            )

        # Step 4: Trusted-proxy client IP sliding-window rate limit check
        client_ip = self.auth.extract_request_ip(request)
        if self.auth.rate_limiter.is_limited(client_ip):
            return _json_error(
                429,
                ErrorCode.RATE_LIMITED.value,
                "登录失败次数过多，请稍后再试",
            )

        # Step 5: Parse JSON and atomically consume OTT under single lock
        try:
            payload = await _read_json_object(request, allow_empty=False)
        except ValueError as exc:
            self.auth.rate_limiter.record_failure(client_ip)
            return _json_error(400, "INVALID_JSON", str(exc))

        raw_ott = payload.get("ott")
        if not isinstance(raw_ott, str) or not raw_ott.strip():
            self.auth.rate_limiter.record_failure(client_ip)
            return _json_error(401, "INVALID_OTT", "一次性登录令牌无效或已过期")

        if not self.auth.consume_ott(raw_ott.strip()):
            self.auth.rate_limiter.record_failure(client_ip)
            return _json_error(401, "INVALID_OTT", "一次性登录令牌无效或已过期")

        session_token = self.auth.session_manager.create_session()
        resp = web.json_response({"ok": True})
        self.auth.session_manager.apply_session_cookie(resp, session_token)
        return resp

    async def handle_auth_logout(self, request: web.Request) -> web.Response:
        await _read_json_object(request, allow_empty=True)
        raw_cookie = request.cookies.get(self.auth.session_manager.cookie_name)
        self.auth.session_manager.destroy_session(raw_cookie)
        resp = web.json_response({"ok": True})
        self.auth.session_manager.clear_session_cookie(resp)
        return resp

    # ------------------------------------------------------------------
    # Tab 1: Bootstrap, System Settings & OpenList Connectivity/Rebind
    # ------------------------------------------------------------------

    async def handle_bootstrap(self, _request: web.Request) -> web.Response:
        snap = _get_runtime_snapshot(self.runtime_config)
        provider_cards = [
            await _serialize_provider_card(p, snap, self.runtime_config)
            for p in self.providers.all_providers()
        ]
        return web.json_response(
            {
                "ok": True,
                "trust_roots": {
                    "telegram_admin_id": self.bootstrap.telegram_admin_id,
                    "web_base_url": self.bootstrap.web_base_url,
                    "web_origin": self.auth.web_origin,
                    "web_trusted_proxies": list(self.bootstrap.web_trusted_proxies),
                },
                "settings": _mask_runtime_settings(snap),
                "openlist_epochs": _serialize_epochs(snap),
                "providers": provider_cards,
                "constraints": {
                    "openlist_share_ttl_hours": [
                        OPENLIST_SHARE_TTL_HOURS_MIN,
                        OPENLIST_SHARE_TTL_HOURS_MAX,
                    ],
                    "max_delivery_files": [MAX_DELIVERY_FILES_MIN, MAX_DELIVERY_FILES_MAX],
                    "max_temp_disk_mb": [MAX_TEMP_DISK_MB_MIN, MAX_TEMP_DISK_MB_MAX],
                    "pending_input_ttl_seconds": [
                        PENDING_INPUT_TTL_SECONDS_MIN,
                        PENDING_INPUT_TTL_SECONDS_MAX,
                    ],
                    "max_retained_tasks": [MAX_RETAINED_TASKS_MIN, MAX_RETAINED_TASKS_MAX],
                    "max_group_whitelist_count": MAX_GROUP_WHITELIST_COUNT,
                },
            }
        )

    async def handle_update_settings(self, request: web.Request) -> web.Response:
        payload = await _read_json_object(request, allow_empty=False)
        raw_settings: Mapping[str, Any]
        if "settings" in payload and isinstance(payload["settings"], dict):
            merged: dict[str, Any] = {k: v for k, v in payload.items() if k != "settings"}
            merged.update(payload["settings"])
            raw_settings = merged
        else:
            raw_settings = payload

        validators = _build_editable_validators(self.providers.all_providers())
        clear_flags_active: set[str] = set()
        for secret_key, clear_flag in SECRET_SETTING_CLEAR_FLAGS.items():
            for raw_k, raw_v in raw_settings.items():
                if str(raw_k).strip().upper() == clear_flag:
                    if parse_strict_bool(raw_v, field_name=clear_flag):
                        clear_flags_active.add(secret_key)

        updates: dict[str, Any] = {}
        for raw_key, raw_val in raw_settings.items():
            norm_key = str(raw_key).strip().upper()
            if norm_key in SECRET_SETTING_CLEAR_FLAGS.values():
                continue
            if norm_key in READONLY_TRUST_ROOT_KEYS:
                return _json_error(
                    403,
                    "READONLY_TRUST_ROOT",
                    f"配置项 {norm_key} 为只读环境变量信任根，禁止通过 Web 修改",
                )
            if norm_key not in validators:
                return _json_error(
                    400,
                    "UNKNOWN_SETTING_KEY",
                    f"未知或不支持在线修改的配置项: {norm_key}",
                )

            validator_fn, is_secret = validators[norm_key]
            if is_secret:
                if norm_key in clear_flags_active:
                    updates[norm_key] = ""
                    continue
                if raw_val is None or (isinstance(raw_val, str) and not raw_val.strip()):
                    # Blank/omitted secret preserves existing secret unless clear_* is set
                    continue
            updates[norm_key] = validator_fn(raw_val)

        for secret_key in clear_flags_active:
            updates.setdefault(secret_key, "")

        if updates:
            snap = await _invoke_update_settings(
                self.runtime_config, updates, admin_id=self.admin_id
            )
            invalidate_fn = getattr(self.openlist, "invalidate_caches", None)
            if callable(invalidate_fn):
                await _call_maybe_async(invalidate_fn)
        else:
            snap = _get_runtime_snapshot(self.runtime_config)

        return web.json_response(
            {
                "ok": True,
                "settings": _mask_runtime_settings(snap),
                "openlist_epochs": _serialize_epochs(snap),
            }
        )

    async def handle_openlist_test(self, request: web.Request) -> web.Response:
        await _read_json_object(request, allow_empty=True)
        if self.openlist is None:
            status = OpenListConnectionStatus(
                ok=False,
                message="尚未注入或配置 OpenList 客户端",
            )
        else:
            try:
                status = await self.openlist.test_connectivity()
            except YunBotError as exc:
                status = OpenListConnectionStatus(ok=False, message=exc.user_message)

        return web.json_response(
            {
                "ok": bool(status.ok),
                "username": status.username,
                "role": status.role,
                "base_path": status.base_path,
                "can_share": bool(status.can_share),
                "can_write_content": bool(status.can_write_content),
                "can_fs_link": bool(status.can_fs_link),
                "mounted_storages": status.mounted_storages or {},
                "message": redact_sensitive_text(status.message or ""),
            }
        )

    async def handle_openlist_rebind(self, request: web.Request) -> web.Response:
        payload = await _read_json_object(request, allow_empty=True)
        fn = self.runtime_config.bump_openlist_mount_epochs
        extra: dict[str, Any] = {}
        provider_id = payload.get("provider_id")
        if isinstance(provider_id, str) and provider_id.strip():
            extra["provider_id"] = provider_id.strip()
        kwargs = _bind_operator_kwarg(fn, self.admin_id, extra)
        res = await _call_maybe_async(fn, **kwargs)
        invalidate_fn = getattr(self.openlist, "invalidate_caches", None)
        if callable(invalidate_fn):
            await _call_maybe_async(invalidate_fn)
        snap = (
            res
            if isinstance(res, RuntimeSettingsSnapshot)
            else _get_runtime_snapshot(self.runtime_config)
        )
        return web.json_response(
            {
                "ok": True,
                "openlist_epochs": _serialize_epochs(snap),
            }
        )

    # ------------------------------------------------------------------
    # Tab 2: Protocol-Driven Provider Auth Routes (Zero Provider Branches)
    # ------------------------------------------------------------------

    def _require_provider(self, request: web.Request) -> CloudProvider:
        provider_id = request.match_info.get("provider_id", "").strip()
        provider = self.providers.find(provider_id)
        if provider is None:
            raise web.HTTPNotFound()
        return provider

    async def handle_provider_credentials(self, request: web.Request) -> web.Response:
        provider = self._require_provider(request)
        if not _provider_supports_mode(provider.spec, AuthMode.SECRET_FIELDS):
            return _json_error(
                400,
                "UNSUPPORTED_AUTH_MODE",
                f"{provider.spec.display_name} 不支持密钥字段直接写入模式",
            )

        payload = await _read_json_object(request, allow_empty=False)
        raw_fields = payload.get("fields") if isinstance(payload.get("fields"), dict) else payload

        clean_fields: dict[str, str] = {}
        spec_keys = {f.key: f for f in provider.spec.secret_fields}
        pid_upper = provider.spec.provider_id.upper()
        pid_lower = provider.spec.provider_id.lower()
        if spec_keys:
            for key, f_spec in spec_keys.items():
                val: Any = None
                for cand in (
                    key,
                    key.lower(),
                    key.upper(),
                    f"{pid_upper}_{key.upper()}",
                    f"{pid_lower}_{key.lower()}",
                ):
                    if cand in raw_fields and raw_fields[cand] is not None:
                        val = raw_fields[cand]
                        break
                str_val = validate_clean_string(
                    val if isinstance(val, str) else "",
                    field_name=key,
                )
                if f_spec.required and not str_val:
                    return _json_error(
                        400,
                        "MISSING_SECRET_FIELD",
                        f"缺少必填凭证字段: {f_spec.label} ({key})",
                    )
                if str_val or not f_spec.required:
                    clean_fields[key] = str_val
        else:
            for k, v in raw_fields.items():
                if isinstance(v, str) and v.strip():
                    clean_fields[str(k)] = validate_clean_string(v, field_name=str(k))

        account = await provider.save_secret_credentials(clean_fields)
        return web.json_response(
            {
                "ok": True,
                "account": _serialize_account_status(account),
            }
        )

    async def handle_provider_auth_code(self, request: web.Request) -> web.Response:
        provider = self._require_provider(request)
        if not _provider_supports_mode(provider.spec, AuthMode.OAUTH_CODE):
            return _json_error(
                400,
                "UNSUPPORTED_AUTH_MODE",
                f"{provider.spec.display_name} 不支持 OAuth 授权码模式",
            )

        payload = await _read_json_object(request, allow_empty=False)
        validators = _build_editable_validators(self.providers.all_providers())
        pid_upper = provider.spec.provider_id.upper()

        # Generically persist any accompanying editable OAuth client settings before code exchange
        candidate_sources: list[Mapping[str, Any]] = [payload]
        if isinstance(payload.get("fields"), dict):
            candidate_sources.append(payload["fields"])
        if isinstance(payload.get("settings"), dict):
            candidate_sources.append(payload["settings"])

        setting_updates: dict[str, Any] = {}
        shorthand_map = {
            "CLIENT_ID": f"{pid_upper}_CLIENT_ID",
            "CLIENT_SECRET": f"{pid_upper}_CLIENT_SECRET",
        }
        for src in candidate_sources:
            for raw_k, raw_v in src.items():
                norm_k = str(raw_k).strip().upper()
                if norm_k == "CODE" or norm_k in ("FIELDS", "SETTINGS"):
                    continue
                target_k = shorthand_map.get(norm_k, norm_k)
                if target_k in READONLY_TRUST_ROOT_KEYS:
                    return _json_error(
                        403,
                        "READONLY_TRUST_ROOT",
                        f"配置项 {target_k} 为只读环境变量信任根",
                    )
                if target_k in validators and isinstance(raw_v, str) and raw_v.strip():
                    validator_fn, _ = validators[target_k]
                    setting_updates[target_k] = validator_fn(raw_v)

        if setting_updates:
            await _invoke_update_settings(
                self.runtime_config, setting_updates, admin_id=self.admin_id
            )

        raw_code = payload.get("code")
        code = validate_clean_string(
            raw_code if isinstance(raw_code, str) else "",
            field_name="code",
        )
        if not code:
            return _json_error(400, "MISSING_AUTH_CODE", "授权码 code 不能为空")

        account = await provider.exchange_oauth_code(code)
        return web.json_response(
            {
                "ok": True,
                "account": _serialize_account_status(account),
                "oauth_authorize_url": provider.get_oauth_authorize_url(),
            }
        )

    async def handle_provider_auth_start(self, request: web.Request) -> web.Response:
        provider = self._require_provider(request)
        if not _provider_supports_mode(provider.spec, AuthMode.INTERACTIVE_FLOW):
            return _json_error(
                400,
                "UNSUPPORTED_AUTH_MODE",
                f"{provider.spec.display_name} 不支持设备码交互授权模式",
            )
        await _read_json_object(request, allow_empty=True)
        flow = await provider.start_interactive_auth()
        return web.json_response(
            {
                "ok": True,
                "verification_uri": flow.verification_uri,
                "user_code": flow.user_code,
                "expires_in": int(flow.expires_in),
                "interval": int(flow.interval),
            }
        )

    async def handle_provider_auth_poll(self, request: web.Request) -> web.Response:
        """Strictly `POST` device-code poll endpoint (`R02` — never `GET`)."""
        provider = self._require_provider(request)
        if not _provider_supports_mode(provider.spec, AuthMode.INTERACTIVE_FLOW):
            return _json_error(
                400,
                "UNSUPPORTED_AUTH_MODE",
                f"{provider.spec.display_name} 不支持设备码交互授权模式",
            )
        await _read_json_object(request, allow_empty=True)
        result = await provider.poll_interactive_auth()
        return web.json_response(
            {
                "ok": True,
                "status": result.status,
                "account": _serialize_account_status(result.account)
                if result.account is not None
                else None,
                "message": redact_sensitive_text(result.message or ""),
            }
        )

    async def handle_provider_auth_cancel(self, request: web.Request) -> web.Response:
        provider = self._require_provider(request)
        if not _provider_supports_mode(provider.spec, AuthMode.INTERACTIVE_FLOW):
            return _json_error(
                400,
                "UNSUPPORTED_AUTH_MODE",
                f"{provider.spec.display_name} 不支持设备码交互授权模式",
            )
        await _read_json_object(request, allow_empty=True)
        await provider.cancel_interactive_auth()
        return web.json_response({"ok": True})

    # ------------------------------------------------------------------
    # Tab 3: User Whitelist/Blacklist & Group Whitelist Management
    # ------------------------------------------------------------------

    async def _read_access_payload(self) -> dict[str, Any]:
        snap = _get_runtime_snapshot(self.runtime_config)
        entries: Sequence[Any] = ()
        groups: Sequence[Any] = ()

        found_users = False
        for target in (self.access, self.storage):
            if target is None:
                continue
            for m_name in ("list_access_entries", "get_access_entries", "list_users"):
                fn = getattr(target, m_name, None)
                if callable(fn):
                    entries = await _call_maybe_async(fn)
                    found_users = True
                    break
            if found_users:
                break

        found_groups = False
        for target in (self.access, self.storage):
            if target is None:
                continue
            for m_name in (
                "list_group_whitelist",
                "get_group_whitelist",
                "list_groups",
            ):
                fn = getattr(target, m_name, None)
                if callable(fn):
                    groups = await _call_maybe_async(fn)
                    found_groups = True
                    break
            if found_groups:
                break

        whitelist_out: list[dict[str, Any]] = []
        blacklist_out: list[dict[str, Any]] = []
        for item in entries:
            if isinstance(item, AccessEntry):
                serialized = {
                    "user_id": item.user_id,
                    "list_type": item.list_type.value,
                    "created_at": item.created_at,
                    "created_by": item.created_by,
                }
                if item.list_type == AccessListType.WHITELIST:
                    whitelist_out.append(serialized)
                else:
                    blacklist_out.append(serialized)
            elif isinstance(item, Mapping):
                lt = str(item.get("list_type", "whitelist"))
                serialized = {
                    "user_id": int(item["user_id"]),
                    "list_type": lt,
                    "created_at": item.get("created_at", 0.0),
                    "created_by": item.get("created_by", self.admin_id),
                }
                if lt == AccessListType.WHITELIST.value:
                    whitelist_out.append(serialized)
                else:
                    blacklist_out.append(serialized)

        groups_out: list[dict[str, Any]] = []
        for grp in groups:
            if isinstance(grp, GroupWhitelistEntry):
                groups_out.append(
                    {
                        "chat_id": grp.chat_id,
                        "created_at": grp.created_at,
                        "created_by": grp.created_by,
                    }
                )
            elif isinstance(grp, Mapping):
                groups_out.append(
                    {
                        "chat_id": int(grp["chat_id"]),
                        "created_at": grp.get("created_at", 0.0),
                        "created_by": grp.get("created_by", self.admin_id),
                    }
                )
            elif isinstance(grp, int):
                groups_out.append({"chat_id": grp, "created_at": 0.0, "created_by": self.admin_id})

        return {
            "ok": True,
            "whitelist_enabled": snap.whitelist_enabled,
            "whitelist": whitelist_out,
            "blacklist": blacklist_out,
            "group_whitelist": groups_out,
            "max_group_whitelist_count": MAX_GROUP_WHITELIST_COUNT,
        }

    async def handle_get_access(self, _request: web.Request) -> web.Response:
        return web.json_response(await self._read_access_payload())

    async def handle_access_users(self, request: web.Request) -> web.Response:
        payload = await _read_json_object(request, allow_empty=False)
        action = str(payload.get("action", "")).strip().lower()
        if action not in ("add", "remove"):
            return _json_error(400, "INVALID_ACTION", "action 必须为 'add' 或 'remove'")

        user_id = parse_bounded_int(payload.get("user_id", ""), field_name="user_id", min_value=1)

        raw_lt = payload.get("list_type")
        list_type: AccessListType | None = None
        if raw_lt is not None and str(raw_lt).strip():
            try:
                list_type = AccessListType(str(raw_lt).strip().lower())
            except ValueError:
                return _json_error(
                    400,
                    "INVALID_LIST_TYPE",
                    "list_type 必须为 'whitelist' 或 'blacklist'",
                )

        if action == "add":
            if list_type is None:
                return _json_error(400, "MISSING_LIST_TYPE", "添加名单时必须指定 list_type")
            if list_type == AccessListType.BLACKLIST and user_id == self.admin_id:
                return _json_error(400, "ADMIN_BLACKLIST_FORBIDDEN", "禁止将管理员加入黑名单")

            executed = False
            if self.access is not None:
                typed_method = (
                    "add_whitelist" if list_type == AccessListType.WHITELIST else "add_blacklist"
                )
                typed_fn = getattr(self.access, typed_method, None)
                if callable(typed_fn):
                    kwargs = _bind_operator_kwarg(typed_fn, self.admin_id)
                    await _call_maybe_async(typed_fn, user_id, **kwargs)
                    executed = True

            if not executed:
                for target, m_names in (
                    (self.access, ("add_user", "set_user_access", "upsert_user")),
                    (self.storage, ("upsert_access_entry", "set_access_entry")),
                ):
                    if target is None:
                        continue
                    for m_name in m_names:
                        fn = getattr(target, m_name, None)
                        if callable(fn):
                            kwargs = _bind_operator_kwarg(fn, self.admin_id)
                            await _call_maybe_async(fn, user_id, list_type, **kwargs)
                            executed = True
                            break
                    if executed:
                        break
            if not executed:
                raise RuntimeError("No user access mutation service configured")
        else:
            executed = False
            for target, m_names in (
                (self.access, ("remove_user", "delete_user")),
                (self.storage, ("remove_access_entry", "delete_access_entry")),
            ):
                if target is None:
                    continue
                for m_name in m_names:
                    fn = getattr(target, m_name, None)
                    if callable(fn):
                        extra = {"list_type": list_type} if list_type is not None else {}
                        kwargs = _bind_operator_kwarg(fn, self.admin_id, extra)
                        await _call_maybe_async(fn, user_id, **kwargs)
                        executed = True
                        break
                if executed:
                    break
            if not executed:
                raise RuntimeError("No user access removal service configured")

        return web.json_response(await self._read_access_payload())

    async def handle_access_groups(self, request: web.Request) -> web.Response:
        payload = await _read_json_object(request, allow_empty=False)
        action = str(payload.get("action", "")).strip().lower()
        if action not in ("add", "remove"):
            return _json_error(400, "INVALID_ACTION", "action 必须为 'add' 或 'remove'")

        chat_id = parse_bounded_int(
            payload.get("chat_id", ""),
            field_name="chat_id",
            max_value=-1,
        )

        if action == "add":
            current = await self._read_access_payload()
            existing_ids = {g["chat_id"] for g in current["group_whitelist"]}
            if chat_id not in existing_ids and len(existing_ids) >= MAX_GROUP_WHITELIST_COUNT:
                return _json_error(
                    400,
                    "GROUP_LIMIT_EXCEEDED",
                    f"白名单群组数量已达上限 ({MAX_GROUP_WHITELIST_COUNT})",
                )

            executed = False
            for target, m_names in (
                (self.access, ("add_group", "add_group_whitelist")),
                (self.storage, ("add_group_whitelist", "upsert_group_whitelist")),
            ):
                if target is None:
                    continue
                for m_name in m_names:
                    fn = getattr(target, m_name, None)
                    if callable(fn):
                        kwargs = _bind_operator_kwarg(fn, self.admin_id)
                        await _call_maybe_async(fn, chat_id, **kwargs)
                        executed = True
                        break
                if executed:
                    break
            if not executed:
                raise RuntimeError("No group whitelist mutation service configured")
        else:
            executed = False
            for target, m_names in (
                (self.access, ("remove_group", "remove_group_whitelist", "delete_group")),
                (self.storage, ("remove_group_whitelist", "delete_group_whitelist")),
            ):
                if target is None:
                    continue
                for m_name in m_names:
                    fn = getattr(target, m_name, None)
                    if callable(fn):
                        kwargs = _bind_operator_kwarg(fn, self.admin_id)
                        await _call_maybe_async(fn, chat_id, **kwargs)
                        executed = True
                        break
                if executed:
                    break
            if not executed:
                raise RuntimeError("No group whitelist removal service configured")

        return web.json_response(await self._read_access_payload())

    async def handle_access_reset(self, request: web.Request) -> web.Response:
        payload = await _read_json_object(request, allow_empty=False)
        if payload.get("confirm") is not True:
            return _json_error(400, "CONFIRMATION_REQUIRED", "重置名单必须显式传入 confirm: true")

        executed = False
        for target, m_names in (
            (
                self.access,
                ("reset_to_initial", "reset_access_lists", "reset_from_bootstrap", "reset"),
            ),
            (
                self.runtime_config,
                ("reset_access_lists_to_initial", "reset_to_initial", "reset_access_lists"),
            ),
            (self.storage, ("reset_access_lists",)),
        ):
            if target is None:
                continue
            for m_name in m_names:
                fn = getattr(target, m_name, None)
                if callable(fn):
                    kwargs = _bind_operator_kwarg(fn, self.admin_id)
                    await _call_maybe_async(fn, **kwargs)
                    executed = True
                    break
            if executed:
                break
        if not executed:
            raise RuntimeError("No access reset service configured")

        if self.access is not None:
            for mem_attr in ("_membership", "membership"):
                mem_obj = getattr(self.access, mem_attr, None)
                inv_fn = getattr(mem_obj, "invalidate", None)
                if callable(inv_fn):
                    await _call_maybe_async(inv_fn)
                    break

        return web.json_response(await self._read_access_payload())

    # ------------------------------------------------------------------
    # Tab 4: Global Tasks Listing & Secondary-Confirmed Deletion
    # ------------------------------------------------------------------

    async def _resolve_current_account_bindings(
        self, provider_ids: set[str]
    ) -> dict[str, str | None]:
        bindings: dict[str, str | None] = {}
        for pid in provider_ids:
            prov = self.providers.find(pid)
            if prov is None:
                bindings[pid] = None
                continue
            try:
                st = await prov.get_account_status()
                bindings[pid] = st.account_binding_id if st.authorized else None
            except Exception:
                bindings[pid] = None
        return bindings

    async def _check_openlist_binding_matched(
        self,
        task: TaskRecord,
        snap: RuntimeSettingsSnapshot,
        ol_binding_cache: dict[tuple[str, str], str | None],
    ) -> bool:
        if self.openlist is not None:
            for check_name in ("is_task_binding_valid", "is_binding_matched", "check_task_binding"):
                check_fn = getattr(self.openlist, check_name, None)
                if callable(check_fn):
                    try:
                        return bool(await _call_maybe_async(check_fn, task))
                    except Exception:
                        return False

        if not snap.openlist_base_url.strip():
            return task.openlist_binding_id is None

        if task.openlist_binding_id is None:
            return False

        cache_key = (task.provider, task.openlist_base_path or "")
        if cache_key not in ol_binding_cache:
            resolved: str | None = None
            if self.openlist is not None:
                resolve_fn = getattr(self.openlist, "resolve_openlist_binding_id", None)
                if callable(resolve_fn) and task.openlist_base_path:
                    try:
                        resolved = await _call_maybe_async(
                            resolve_fn, task.provider, task.openlist_base_path
                        )
                    except Exception:
                        resolved = None
                else:
                    for getter in (
                        "get_current_binding_id",
                        "compute_binding_id",
                        "resolve_binding_id",
                    ):
                        fn = getattr(self.openlist, getter, None)
                        if callable(fn):
                            try:
                                resolved = await _call_maybe_async(fn, task.provider)
                            except Exception:
                                resolved = None
                            break
            ol_binding_cache[cache_key] = resolved

        cached_binding = ol_binding_cache[cache_key]
        if cached_binding is not None:
            return task.openlist_binding_id == cached_binding

        # Fallback epoch prefix match if OpenList storage signature lookup is offline
        inst_epoch = snap.openlist_instance_epoch
        mount_epoch = snap.get_mount_epoch(task.provider)
        if inst_epoch and mount_epoch:
            return (
                inst_epoch in task.openlist_binding_id and mount_epoch in task.openlist_binding_id
            )
        return False

    async def handle_list_tasks(self, request: web.Request) -> web.Response:
        raw_limit = request.query.get("limit", "20")
        raw_offset = request.query.get("offset", "0")
        raw_status = request.query.get("status", "").strip()

        limit = parse_bounded_int(raw_limit, field_name="limit", min_value=1, max_value=100)
        offset = parse_bounded_int(raw_offset, field_name="offset", min_value=0)

        status_filter: TaskStatus | None = None
        if raw_status and raw_status.lower() != "all":
            try:
                status_filter = TaskStatus(raw_status.lower())
            except ValueError:
                return _json_error(
                    400, "INVALID_TASK_STATUS", f"未知的任务状态筛选值: {raw_status}"
                )

        tasks_seq: Sequence[TaskRecord] = ()
        total_count = 0
        if self.storage is not None:
            list_fn = getattr(self.storage, "list_tasks", None) or getattr(
                self.storage, "list_global_tasks", None
            )
            if callable(list_fn):
                res = await _call_maybe_async(
                    list_fn, limit=limit, offset=offset, status=status_filter
                )
                if isinstance(res, tuple) and len(res) == 2 and isinstance(res[1], int):
                    tasks_seq, total_count = res[0], res[1]
                else:
                    tasks_seq = res
                    count_fn = getattr(self.storage, "count_tasks", None)
                    if callable(count_fn):
                        total_count = int(await _call_maybe_async(count_fn, status=status_filter))
                    else:
                        total_count = len(tasks_seq)

        snap = _get_runtime_snapshot(self.runtime_config)
        distinct_providers = {t.provider for t in tasks_seq}
        current_acc_bindings = await self._resolve_current_account_bindings(distinct_providers)
        ol_binding_cache: dict[tuple[str, str], str | None] = {}

        items_out: list[dict[str, Any]] = []
        for task in tasks_seq:
            prov_obj = self.providers.find(task.provider)
            prov_name = prov_obj.spec.display_name if prov_obj is not None else task.provider
            cur_acc = current_acc_bindings.get(task.provider)
            acc_matched = bool(cur_acc and task.account_binding_id == cur_acc)
            ol_matched = await self._check_openlist_binding_matched(task, snap, ol_binding_cache)

            items_out.append(
                {
                    "task_id": task.task_id,
                    "chat_id": task.chat_id,
                    "user_id": task.user_id,
                    "provider": task.provider,
                    "provider_display_name": prov_name,
                    "account_binding_id": task.account_binding_id,
                    "openlist_binding_id": task.openlist_binding_id,
                    "share_title": task.share_title,
                    "base_save_path": task.base_save_path,
                    "openlist_base_path": task.openlist_base_path,
                    "no_subdir": bool(task.no_subdir),
                    "mode": "direct" if task.no_subdir else "subdir",
                    "task_dir_path": task.task_dir_path,
                    "status": task.status.value,
                    "transfer_uncertain": bool(task.transfer_uncertain),
                    "remote_task_ref": task.remote_task_ref,
                    "item_count": task.item_count,
                    "tg_send_eligible": bool(task.tg_send_eligible),
                    "has_openlist_share": bool(task.openlist_share_id),
                    "openlist_share_expires_at": task.openlist_share_expires_at,
                    "error_code": task.error_code,
                    "error_message": redact_sensitive_text(task.error_message or "")
                    if task.error_message
                    else None,
                    "created_at": task.created_at,
                    "updated_at": task.updated_at,
                    "account_binding_matched": acc_matched,
                    "openlist_binding_matched": ol_matched,
                    "deletable": task.status in DELETABLE_TASK_STATUSES,
                }
            )

        return web.json_response(
            {
                "ok": True,
                "tasks": items_out,
                "total": total_count,
                "limit": limit,
                "offset": offset,
            }
        )

    async def handle_delete_task(self, request: web.Request) -> web.Response:
        task_id = validate_clean_string(
            request.match_info.get("task_id", ""),
            field_name="task_id",
        )
        if not task_id or len(task_id) > 64:
            return _json_error(400, "INVALID_TASK_ID", "无效的 task_id")

        payload = await _read_json_object(request, allow_empty=False)
        if payload.get("confirm") is not True:
            return _json_error(400, "CONFIRMATION_REQUIRED", "删除任务必须显式传入 confirm: true")

        detach_only = payload.get("detach_only", False)
        if not isinstance(detach_only, bool):
            return _json_error(400, "INVALID_DETACH_ONLY", "detach_only 必须为布尔值")

        if self.deletion_service is None:
            raise RuntimeError("Task deletion_service is not configured")

        try:
            outcome = await self.deletion_service.delete_task_with_cloud_files(
                task_id,
                operator_id=self.admin_id,
                detach_only=detach_only,
            )
        except KeyError:
            return _json_error(404, "TASK_NOT_FOUND", "任务不存在或已被删除")

        resp_data: dict[str, Any] = {"ok": True, "task_id": task_id, "detach_only": detach_only}
        if isinstance(outcome, str):
            resp_data["message"] = redact_sensitive_text(outcome)
        elif isinstance(outcome, Mapping):
            for k, v in outcome.items():
                if k != "ok":
                    resp_data[str(k)] = _to_jsonable(v)
        elif dataclasses.is_dataclass(outcome) and not isinstance(outcome, type):
            converted = _to_jsonable(outcome)
            if isinstance(converted, Mapping):
                for k, v in converted.items():
                    if k != "ok":
                        resp_data[str(k)] = v

        return web.json_response(resp_data)


def _resolve_deletion_service(deletion_service: Any, coordinator: Any) -> Any:
    if deletion_service is not None:
        return deletion_service
    if coordinator is not None:
        nested = getattr(coordinator, "deletion_service", None)
        if nested is not None:
            return nested
        if callable(getattr(coordinator, "delete_task_with_cloud_files", None)):
            return coordinator
    return None


def create_web_app(
    *,
    runtime_config: Any,
    providers: ProviderRegistry,
    storage: Any,
    access: Any,
    openlist: Any = None,
    deletion_service: Any = None,
    coordinator: Any = None,
    bootstrap: BootstrapConfigSnapshot | None = None,
    auth_manager: WebAuthManager | None = None,
    static_index_path: Path = STATIC_INDEX_PATH,
) -> web.Application:
    """Create the configured `aiohttp.web.Application` with R02 middlewares and routes."""
    resolved_bootstrap = bootstrap or getattr(runtime_config, "bootstrap", None)
    if not isinstance(resolved_bootstrap, BootstrapConfigSnapshot):
        raise ValueError("bootstrap BootstrapConfigSnapshot is required")

    resolved_auth = auth_manager or WebAuthManager.from_bootstrap(resolved_bootstrap)
    index_html = static_index_path.read_text(encoding="utf-8")

    panel = _WebPanelHandler(
        bootstrap=resolved_bootstrap,
        runtime_config=runtime_config,
        providers=providers,
        storage=storage,
        access=access,
        openlist=openlist,
        deletion_service=_resolve_deletion_service(deletion_service, coordinator),
        auth_manager=resolved_auth,
        index_html=index_html,
    )

    app = web.Application(
        client_max_size=WEB_MAX_BODY_BYTES,
        middlewares=[
            panel.security_and_error_middleware,
            panel.auth_boundary_middleware,
        ],
    )
    app[AUTH_MANAGER_APP_KEY] = resolved_auth

    app.router.add_get("/", panel.handle_root)
    app.router.add_get("/login", panel.handle_login_page)

    app.router.add_post("/api/auth/exchange", panel.handle_auth_exchange)
    app.router.add_post("/api/auth/logout", panel.handle_auth_logout)

    app.router.add_get("/api/bootstrap", panel.handle_bootstrap)
    app.router.add_post("/api/settings", panel.handle_update_settings)
    app.router.add_post("/api/openlist/test", panel.handle_openlist_test)
    app.router.add_post("/api/openlist/rebind", panel.handle_openlist_rebind)

    app.router.add_post(
        "/api/providers/{provider_id}/credentials", panel.handle_provider_credentials
    )
    app.router.add_post("/api/providers/{provider_id}/auth/code", panel.handle_provider_auth_code)
    app.router.add_post("/api/providers/{provider_id}/auth/start", panel.handle_provider_auth_start)
    app.router.add_post("/api/providers/{provider_id}/auth/poll", panel.handle_provider_auth_poll)
    app.router.add_post(
        "/api/providers/{provider_id}/auth/cancel", panel.handle_provider_auth_cancel
    )

    app.router.add_get("/api/access", panel.handle_get_access)
    app.router.add_post("/api/access/users", panel.handle_access_users)
    app.router.add_post("/api/access/groups", panel.handle_access_groups)
    app.router.add_post("/api/access/reset", panel.handle_access_reset)

    app.router.add_get("/api/tasks", panel.handle_list_tasks)
    app.router.add_post("/api/tasks/{task_id}/delete", panel.handle_delete_task)

    return app


class WebServer:
    """Lifecycle wrapper managing `aiohttp.web.AppRunner` and `TCPSite`."""

    def __init__(
        self,
        *,
        runtime_config: Any,
        providers: ProviderRegistry,
        storage: Any,
        access: Any,
        openlist: Any = None,
        deletion_service: Any = None,
        coordinator: Any = None,
        bootstrap: BootstrapConfigSnapshot | None = None,
        auth_manager: WebAuthManager | None = None,
    ) -> None:
        self._bootstrap: BootstrapConfigSnapshot = bootstrap or runtime_config.bootstrap
        self.auth_manager = auth_manager or WebAuthManager.from_bootstrap(self._bootstrap)
        self.app = create_web_app(
            runtime_config=runtime_config,
            providers=providers,
            storage=storage,
            access=access,
            openlist=openlist,
            deletion_service=deletion_service,
            coordinator=coordinator,
            bootstrap=self._bootstrap,
            auth_manager=self.auth_manager,
        )
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    @property
    def ott_manager(self) -> Any:
        return self.auth_manager.ott_manager

    @property
    def session_manager(self) -> Any:
        return self.auth_manager.session_manager

    def issue_ott(self) -> str:
        """Issue a 5-minute single-use login OTT for `/web` private admin command."""
        return self.auth_manager.issue_ott()

    def cleanup_expired(self) -> None:
        """Purge expired OTTs, admin sessions, and IP rate-limit buckets."""
        self.auth_manager.cleanup_expired()

    @property
    def bound_port(self) -> int | None:
        if self._site is None or self._site._server is None:
            return None
        sockets = getattr(self._site._server, "sockets", None)
        if not sockets:
            return None
        return int(sockets[0].getsockname()[1])

    async def start(self, host: str = "0.0.0.0", port: int | None = None) -> None:
        if self._runner is not None:
            return
        listen_port = self._bootstrap.web_internal_port if port is None else int(port)
        self._runner = web.AppRunner(self.app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host=host, port=listen_port)
        await self._site.start()
        logger.info("Admin Web Panel listening on %s:%s", host, self.bound_port or listen_port)

    async def stop(self) -> None:
        if self._runner is None:
            return
        runner = self._runner
        self._runner = None
        self._site = None
        await runner.cleanup()
        logger.info("Admin Web Panel stopped")
