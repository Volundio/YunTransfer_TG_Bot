"""Startup environment parsing and read-only trust-root validators (§3.3, §4.1).

Depends strictly on the Python 3.12 standard library and ``models``.
Never imports or uses ``pydantic``.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from yunbot.models import (
    MAX_DELIVERY_FILES,
    MAX_DELIVERY_FILES_MAX,
    MAX_DELIVERY_FILES_MIN,
    MAX_GROUP_WHITELIST_COUNT,
    MAX_RETAINED_TASKS,
    MAX_RETAINED_TASKS_MAX,
    MAX_RETAINED_TASKS_MIN,
    MAX_TEMP_DISK_MB,
    MAX_TEMP_DISK_MB_MAX,
    MAX_TEMP_DISK_MB_MIN,
    OPENLIST_SHARE_TTL_HOURS,
    OPENLIST_SHARE_TTL_HOURS_MAX,
    OPENLIST_SHARE_TTL_HOURS_MIN,
    PENDING_INPUT_TTL_SECONDS,
    PENDING_INPUT_TTL_SECONDS_MAX,
    PENDING_INPUT_TTL_SECONDS_MIN,
    BootstrapConfigSnapshot,
    normalize_posix_path,
    validate_save_path,
)

VALID_LOG_LEVELS: frozenset[str] = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

_TRUE_LITERALS: frozenset[str] = frozenset({"1", "true", "yes", "on"})
_FALSE_LITERALS: frozenset[str] = frozenset({"0", "false", "no", "off"})

DEFAULT_TZ: str = "Asia/Shanghai"
DEFAULT_TELEGRAM_API_BASE_URL: str = "http://telegram-bot-api:8081"
DEFAULT_WEB_INTERNAL_PORT: int = 8082
DEFAULT_WEB_BASE_URL: str = "http://127.0.0.1:38082"
DEFAULT_OPENLIST_BAIDU_PATH: str = "/baidu/转存文件"
DEFAULT_OPENLIST_PIKPAK_PATH: str = "/pikpak/转存文件"
DEFAULT_OPENLIST_QUARK_PATH: str = "/quark/转存文件"
DEFAULT_BAIDU_SAVE_PATH: str = "/转存文件"
DEFAULT_PIKPAK_SAVE_PATH: str = "/My Pack/转存文件"
DEFAULT_QUARK_SAVE_PATH: str = "/转存文件"
DEFAULT_DATA_DIR: str = "/app/data"
DEFAULT_SHARED_UPLOAD_DIR: str = "/var/tmp/yunbot-uploads"
DEFAULT_LOG_LEVEL: str = "INFO"


def _reject_control_or_whitespace(value: str, field_name: str) -> None:
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{field_name} must not contain whitespace or control characters")


def parse_strict_bool(raw: bool | str, *, field_name: str) -> bool:
    """Parse strict boolean literals ('1/true/yes/on' vs '0/false/no/off') or bool."""
    if isinstance(raw, bool):
        return raw
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a boolean or boolean string")
    lowered = raw.strip().lower()
    if lowered in _TRUE_LITERALS:
        return True
    if lowered in _FALSE_LITERALS:
        return False
    raise ValueError(f"Invalid boolean value for {field_name}: {raw!r}")


def parse_bounded_int(
    raw: int | str,
    *,
    field_name: str,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    """Parse an integer (rejecting booleans and floats) and enforce [min_value, max_value]."""
    if isinstance(raw, bool):
        raise ValueError(f"{field_name} must be an integer, not bool")
    if isinstance(raw, int):
        parsed = raw
    elif isinstance(raw, str):
        stripped = raw.strip()
        if not stripped or not stripped.lstrip("+-").isdigit():
            raise ValueError(f"{field_name} must be a valid integer")
        parsed = int(stripped, 10)
    else:
        raise ValueError(f"{field_name} must be an integer")

    if min_value is not None and parsed < min_value:
        raise ValueError(f"{field_name} must be >= {min_value} (got {parsed})")
    if max_value is not None and parsed > max_value:
        raise ValueError(f"{field_name} must be <= {max_value} (got {parsed})")
    return parsed


def validate_timezone(raw_tz: str) -> str:
    """Validate an IANA timezone name via stdlib zoneinfo.ZoneInfo."""
    if not isinstance(raw_tz, str):
        raise ValueError("TZ must be a string")
    tz_name = raw_tz.strip()
    if not tz_name or "\x00" in tz_name:
        raise ValueError("TZ must be a non-empty timezone name")
    try:
        ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError, KeyError) as exc:
        raise ValueError(f"Invalid TZ timezone: {tz_name!r}") from exc
    return tz_name


def parse_root_origin_url(
    raw_url: str, *, field_name: str = "WEB_BASE_URL"
) -> tuple[str, str, bool]:
    """Validate a root-origin HTTP/HTTPS URL (no subpath, params, query, or fragment).

    Returns ``(normalized_base_url, web_origin, is_https)``.
    """
    if not isinstance(raw_url, str):
        raise ValueError(f"{field_name} must be a string")
    stripped = raw_url.strip()
    if not stripped:
        raise ValueError(f"{field_name} must be a non-empty HTTP/HTTPS root URL")
    _reject_control_or_whitespace(stripped, field_name)

    parsed = urlparse(stripped)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"{field_name} scheme must be 'http' or 'https'")
    if not parsed.hostname or not parsed.netloc:
        raise ValueError(f"{field_name} must include a valid host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not include userinfo credentials")
    if parsed.netloc.endswith(":"):
        raise ValueError(f"{field_name} has an empty port")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} has an invalid port") from exc

    if parsed.path not in ("", "/"):
        raise ValueError(f"{field_name} must be a root origin URL without subpath")
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must not include params, query, or fragment")

    origin = f"{scheme}://{parsed.netloc}"
    return origin, origin, scheme == "https"


def parse_http_url(
    raw_url: str,
    *,
    field_name: str,
    allow_empty: bool = False,
) -> str:
    """Validate an HTTP/HTTPS URL and strip trailing slashes."""
    if not isinstance(raw_url, str):
        raise ValueError(f"{field_name} must be a string")
    stripped = raw_url.strip()
    if not stripped:
        if allow_empty:
            return ""
        raise ValueError(f"{field_name} must be a non-empty HTTP/HTTPS URL")
    _reject_control_or_whitespace(stripped, field_name)

    parsed = urlparse(stripped)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"{field_name} scheme must be 'http' or 'https'")
    if not parsed.hostname or not parsed.netloc:
        raise ValueError(f"{field_name} must include a valid host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not include userinfo credentials")
    if parsed.netloc.endswith(":"):
        raise ValueError(f"{field_name} has an empty port")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(f"{field_name} has an invalid port") from exc
    if parsed.params or parsed.query or parsed.fragment:
        raise ValueError(f"{field_name} must not include params, query, or fragment")

    clean_path = ""
    if parsed.path and parsed.path != "/":
        clean_path = normalize_posix_path(parsed.path, allow_root=False)
    return f"{scheme}://{parsed.netloc}{clean_path}"


def parse_trusted_proxies(raw: str) -> tuple[str, ...]:
    """Parse comma-separated IP/CIDR entries into canonical network strings."""
    stripped = raw.strip()
    if not stripped:
        return ()

    networks: list[str] = []
    seen: set[str] = set()
    for part in stripped.split(","):
        token = part.strip()
        if not token:
            raise ValueError("WEB_TRUSTED_PROXIES contains an empty entry")
        try:
            canonical = str(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid IP/CIDR in WEB_TRUSTED_PROXIES: {token!r}") from exc
        if canonical not in seen:
            seen.add(canonical)
            networks.append(canonical)
    return tuple(networks)


def parse_id_tuple(
    raw: str,
    *,
    field_name: str,
    sign: str,
    max_count: int | None = None,
) -> tuple[int, ...]:
    """Parse comma-separated Telegram user (>0) or group (<0) integer IDs."""
    stripped = raw.strip()
    if not stripped:
        return ()

    ids: list[int] = []
    seen: set[int] = set()
    for part in stripped.split(","):
        token = part.strip()
        if not token:
            raise ValueError(f"{field_name} contains an empty ID entry")
        val = parse_bounded_int(token, field_name=field_name)
        if sign == "positive" and val <= 0:
            raise ValueError(f"{field_name} entries must be positive integers (> 0)")
        if sign == "negative" and val >= 0:
            raise ValueError(f"{field_name} entries must be negative group IDs (< 0)")
        if val not in seen:
            seen.add(val)
            ids.append(val)

    if max_count is not None and len(ids) > max_count:
        raise ValueError(f"{field_name} count ({len(ids)}) exceeds maximum {max_count}")
    return tuple(ids)


def validate_log_level(raw_level: str) -> str:
    """Validate and uppercase Python logging level name."""
    if not isinstance(raw_level, str):
        raise ValueError("LOG_LEVEL must be a string")
    normalized = raw_level.strip().upper()
    if normalized not in VALID_LOG_LEVELS:
        raise ValueError(
            f"Invalid LOG_LEVEL {raw_level!r}; expected one of {sorted(VALID_LOG_LEVELS)}"
        )
    return normalized


def validate_clean_string(raw: str, *, field_name: str, strip: bool = True) -> str:
    """Validate a string configuration value without NUL bytes."""
    if not isinstance(raw, str):
        raise ValueError(f"{field_name} must be a string")
    if "\x00" in raw:
        raise ValueError(f"{field_name} must not contain NUL bytes")
    return raw.strip() if strip else raw


def load_bootstrap_config(environ: Mapping[str, str] | None = None) -> BootstrapConfigSnapshot:
    """Load and validate all startup environment variables per DEVELOPMENT.md §3.3."""
    env: Mapping[str, str] = os.environ if environ is None else environ

    raw_bot_token = validate_clean_string(
        env.get("TELEGRAM_BOT_TOKEN", ""), field_name="TELEGRAM_BOT_TOKEN"
    )
    if not raw_bot_token:
        raise ValueError("TELEGRAM_BOT_TOKEN is required and must be non-empty")
    _reject_control_or_whitespace(raw_bot_token, "TELEGRAM_BOT_TOKEN")

    if "TELEGRAM_ADMIN_ID" not in env or not env["TELEGRAM_ADMIN_ID"].strip():
        raise ValueError("TELEGRAM_ADMIN_ID is required and must be a positive integer")
    admin_id = parse_bounded_int(
        env["TELEGRAM_ADMIN_ID"],
        field_name="TELEGRAM_ADMIN_ID",
        min_value=1,
    )

    tz = validate_timezone(env["TZ"] if "TZ" in env else DEFAULT_TZ)
    telegram_api_base_url = parse_http_url(
        env["TELEGRAM_API_BASE_URL"]
        if "TELEGRAM_API_BASE_URL" in env
        else DEFAULT_TELEGRAM_API_BASE_URL,
        field_name="TELEGRAM_API_BASE_URL",
        allow_empty=False,
    )
    web_internal_port = parse_bounded_int(
        env["WEB_INTERNAL_PORT"] if "WEB_INTERNAL_PORT" in env else DEFAULT_WEB_INTERNAL_PORT,
        field_name="WEB_INTERNAL_PORT",
        min_value=1,
        max_value=65535,
    )
    web_base_url, web_origin, web_cookie_secure = parse_root_origin_url(
        env["WEB_BASE_URL"] if "WEB_BASE_URL" in env else DEFAULT_WEB_BASE_URL,
        field_name="WEB_BASE_URL",
    )
    web_trusted_proxies = parse_trusted_proxies(env.get("WEB_TRUSTED_PROXIES", ""))

    initial_whitelist_enabled = parse_strict_bool(
        env["WHITELIST_ENABLED"] if "WHITELIST_ENABLED" in env else True,
        field_name="WHITELIST_ENABLED",
    )
    initial_whitelist_ids = parse_id_tuple(
        env.get("INITIAL_WHITELIST_IDS", ""),
        field_name="INITIAL_WHITELIST_IDS",
        sign="positive",
    )
    initial_blacklist_ids = parse_id_tuple(
        env.get("INITIAL_BLACKLIST_IDS", ""),
        field_name="INITIAL_BLACKLIST_IDS",
        sign="positive",
    )
    initial_group_whitelist_ids = parse_id_tuple(
        env.get("INITIAL_GROUP_WHITELIST_IDS", ""),
        field_name="INITIAL_GROUP_WHITELIST_IDS",
        sign="negative",
        max_count=MAX_GROUP_WHITELIST_COUNT,
    )

    openlist_base_url = parse_http_url(
        env.get("OPENLIST_BASE_URL", ""),
        field_name="OPENLIST_BASE_URL",
        allow_empty=True,
    )
    openlist_public_url = parse_http_url(
        env.get("OPENLIST_PUBLIC_URL", ""),
        field_name="OPENLIST_PUBLIC_URL",
        allow_empty=True,
    )
    openlist_token = validate_clean_string(
        env.get("OPENLIST_TOKEN", ""), field_name="OPENLIST_TOKEN"
    )
    openlist_username = validate_clean_string(
        env.get("OPENLIST_USERNAME", ""), field_name="OPENLIST_USERNAME"
    )
    openlist_password = validate_clean_string(
        env.get("OPENLIST_PASSWORD", ""), field_name="OPENLIST_PASSWORD"
    )

    openlist_baidu_path = normalize_posix_path(
        env["OPENLIST_BAIDU_PATH"] if "OPENLIST_BAIDU_PATH" in env else DEFAULT_OPENLIST_BAIDU_PATH,
        allow_root=False,
    )
    openlist_pikpak_path = normalize_posix_path(
        env["OPENLIST_PIKPAK_PATH"]
        if "OPENLIST_PIKPAK_PATH" in env
        else DEFAULT_OPENLIST_PIKPAK_PATH,
        allow_root=False,
    )
    openlist_quark_path = normalize_posix_path(
        env["OPENLIST_QUARK_PATH"] if "OPENLIST_QUARK_PATH" in env else DEFAULT_OPENLIST_QUARK_PATH,
        allow_root=False,
    )
    openlist_share_ttl_hours = parse_bounded_int(
        env["OPENLIST_SHARE_TTL_HOURS"]
        if "OPENLIST_SHARE_TTL_HOURS" in env
        else OPENLIST_SHARE_TTL_HOURS,
        field_name="OPENLIST_SHARE_TTL_HOURS",
        min_value=OPENLIST_SHARE_TTL_HOURS_MIN,
        max_value=OPENLIST_SHARE_TTL_HOURS_MAX,
    )

    baidu_client_id = validate_clean_string(
        env.get("BAIDU_CLIENT_ID", ""), field_name="BAIDU_CLIENT_ID"
    )
    baidu_client_secret = validate_clean_string(
        env.get("BAIDU_CLIENT_SECRET", ""), field_name="BAIDU_CLIENT_SECRET"
    )
    baidu_save_path = validate_save_path(
        env["BAIDU_SAVE_PATH"] if "BAIDU_SAVE_PATH" in env else DEFAULT_BAIDU_SAVE_PATH
    )

    pikpak_save_path = validate_save_path(
        env["PIKPAK_SAVE_PATH"] if "PIKPAK_SAVE_PATH" in env else DEFAULT_PIKPAK_SAVE_PATH
    )
    pikpak_pat = validate_clean_string(env.get("PIKPAK_PAT", ""), field_name="PIKPAK_PAT")
    pikpak_direct_exclusive_dir = parse_strict_bool(
        env["PIKPAK_DIRECT_EXCLUSIVE_DIR"] if "PIKPAK_DIRECT_EXCLUSIVE_DIR" in env else False,
        field_name="PIKPAK_DIRECT_EXCLUSIVE_DIR",
    )

    quark_save_path = validate_save_path(
        env["QUARK_SAVE_PATH"] if "QUARK_SAVE_PATH" in env else DEFAULT_QUARK_SAVE_PATH
    )
    quark_cookie = validate_clean_string(env.get("QUARK_COOKIE", ""), field_name="QUARK_COOKIE")

    max_delivery_files = parse_bounded_int(
        env["MAX_DELIVERY_FILES"] if "MAX_DELIVERY_FILES" in env else MAX_DELIVERY_FILES,
        field_name="MAX_DELIVERY_FILES",
        min_value=MAX_DELIVERY_FILES_MIN,
        max_value=MAX_DELIVERY_FILES_MAX,
    )
    max_temp_disk_mb = parse_bounded_int(
        env["MAX_TEMP_DISK_MB"] if "MAX_TEMP_DISK_MB" in env else MAX_TEMP_DISK_MB,
        field_name="MAX_TEMP_DISK_MB",
        min_value=MAX_TEMP_DISK_MB_MIN,
        max_value=MAX_TEMP_DISK_MB_MAX,
    )
    pending_input_ttl_seconds = parse_bounded_int(
        env["PENDING_INPUT_TTL_SECONDS"]
        if "PENDING_INPUT_TTL_SECONDS" in env
        else PENDING_INPUT_TTL_SECONDS,
        field_name="PENDING_INPUT_TTL_SECONDS",
        min_value=PENDING_INPUT_TTL_SECONDS_MIN,
        max_value=PENDING_INPUT_TTL_SECONDS_MAX,
    )
    max_retained_tasks = parse_bounded_int(
        env["MAX_RETAINED_TASKS"] if "MAX_RETAINED_TASKS" in env else MAX_RETAINED_TASKS,
        field_name="MAX_RETAINED_TASKS",
        min_value=MAX_RETAINED_TASKS_MIN,
        max_value=MAX_RETAINED_TASKS_MAX,
    )

    data_dir = validate_clean_string(
        env["DATA_DIR"] if "DATA_DIR" in env else DEFAULT_DATA_DIR,
        field_name="DATA_DIR",
    )
    if not data_dir:
        raise ValueError("DATA_DIR must be non-empty")

    shared_upload_dir = validate_clean_string(
        env["SHARED_UPLOAD_DIR"] if "SHARED_UPLOAD_DIR" in env else DEFAULT_SHARED_UPLOAD_DIR,
        field_name="SHARED_UPLOAD_DIR",
    )
    if not shared_upload_dir:
        raise ValueError("SHARED_UPLOAD_DIR must be non-empty")

    log_level = validate_log_level(env["LOG_LEVEL"] if "LOG_LEVEL" in env else DEFAULT_LOG_LEVEL)

    return BootstrapConfigSnapshot(
        tz=tz,
        telegram_bot_token=raw_bot_token,
        telegram_admin_id=admin_id,
        telegram_api_base_url=telegram_api_base_url,
        web_internal_port=web_internal_port,
        web_base_url=web_base_url,
        web_origin=web_origin,
        web_cookie_secure=web_cookie_secure,
        web_trusted_proxies=web_trusted_proxies,
        initial_whitelist_enabled=initial_whitelist_enabled,
        initial_whitelist_ids=initial_whitelist_ids,
        initial_blacklist_ids=initial_blacklist_ids,
        initial_group_whitelist_ids=initial_group_whitelist_ids,
        openlist_base_url=openlist_base_url,
        openlist_public_url=openlist_public_url,
        openlist_token=openlist_token,
        openlist_username=openlist_username,
        openlist_password=openlist_password,
        openlist_baidu_path=openlist_baidu_path,
        openlist_pikpak_path=openlist_pikpak_path,
        openlist_quark_path=openlist_quark_path,
        openlist_share_ttl_hours=openlist_share_ttl_hours,
        baidu_client_id=baidu_client_id,
        baidu_client_secret=baidu_client_secret,
        baidu_save_path=baidu_save_path,
        pikpak_save_path=pikpak_save_path,
        pikpak_pat=pikpak_pat,
        pikpak_direct_exclusive_dir=pikpak_direct_exclusive_dir,
        quark_save_path=quark_save_path,
        quark_cookie=quark_cookie,
        max_delivery_files=max_delivery_files,
        max_temp_disk_mb=max_temp_disk_mb,
        pending_input_ttl_seconds=pending_input_ttl_seconds,
        max_retained_tasks=max_retained_tasks,
        data_dir=data_dir,
        shared_upload_dir=shared_upload_dir,
        log_level=log_level,
    )
