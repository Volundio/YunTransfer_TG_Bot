"""Core domain models, enums, exceptions, pure helpers, and global constants.

Depends strictly on the Python 3.12 standard library.
"""

from __future__ import annotations

import asyncio
import json
import logging
import posixpath
import re
import secrets
from collections.abc import Coroutine
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

# ==============================================================================
# §2.4 Global Constants & Resource Boundaries (Single Source of Truth)
# ==============================================================================

OPENLIST_SHARE_URL_TEMPLATE: str = "{base}/@s/{share_id}"
OPENLIST_SHARE_TTL_HOURS: int = 24
OPENLIST_SHARE_TTL_HOURS_MIN: int = 1
OPENLIST_SHARE_TTL_HOURS_MAX: int = 720
OPENLIST_SHARE_REUSE_MARGIN_SECONDS: int = 60
OPENLIST_REFRESH_RETRY_DELAYS_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)

MAX_DELIVERY_FILES: int = 10
MAX_DELIVERY_FILES_MIN: int = 1
MAX_DELIVERY_FILES_MAX: int = 50

ALLOWED_VIDEO_EXTS: frozenset[str] = frozenset(
    {
        ".mp4",
        ".m4v",
        ".mov",
        ".mkv",
        ".webm",
        ".avi",
        ".flv",
        ".ts",
        ".m2ts",
        ".wmv",
        ".mpg",
        ".mpeg",
        ".3gp",
    }
)
ALLOWED_IMAGE_EXTS: frozenset[str] = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp",
        ".gif",
        ".bmp",
        ".heic",
        ".heif",
        ".avif",
    }
)
ALLOWED_MEDIA_EXTS: frozenset[str] = ALLOWED_VIDEO_EXTS | ALLOWED_IMAGE_EXTS

MAX_OPENLIST_DIR_REQUESTS: int = 32
MAX_OPENLIST_RECURSION_DEPTH: int = 10
OPENLIST_STREAM_HEADER_ALLOWLIST: frozenset[str] = frozenset(
    {"user-agent", "referer", "origin", "cookie"}
)
QUARK_COOKIE_ALLOWED_SUFFIXES: tuple[str, ...] = (".quark.cn",)

MAX_API_JSON_BYTES: int = 4_194_304  # 4 MiB
API_REQUEST_TIMEOUT_SECONDS: float = 30.0
STREAM_CONNECT_TIMEOUT_SECONDS: float = 30.0
STREAM_MAX_REDIRECTS: int = 5
STREAM_CHUNK_SIZE_BYTES: int = 524_288  # 512 KiB
STREAM_MIN_FREE_DISK_BYTES: int = 67_108_864  # 64 MiB

MAX_TEMP_DISK_MB: int = 2560
MAX_TEMP_DISK_MB_MIN: int = 2048
MAX_TEMP_DISK_MB_MAX: int = 102400

TG_UPLOAD_SAFE_LIMIT_BYTES: int = 2_091_909_120  # 1995 MiB
TG_PHOTO_SAFE_LIMIT_BYTES: int = 9_961_472  # 9.5 MiB
SAFE_FILENAME_MAX_UTF8_BYTES: int = 180
TG_LOCAL_UPLOAD_TIMEOUT_SECONDS: float = 3600.0
TG_PHOTO_UPLOAD_TIMEOUT_SECONDS: float = 300.0
TG_API_STARTUP_MAX_WAIT_SECONDS: float = 60.0
TG_API_STARTUP_BACKOFF_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0, 8.0)

TRANSFER_QUEUE_MAXSIZE: int = 64
TRANSFER_WORKERS: int = 3
DIRECT_MODE_CONCURRENCY: int = 2
DIR_LOCK_WAIT_TIMEOUT_SECONDS: float = 15.0
MAX_BATCH_LINKS_PER_MESSAGE: int = 20

DELIVERY_QUEUE_MAXSIZE: int = 32
DELIVERY_WORKERS: int = 1
MAX_ACTIVE_DELIVERIES_PER_USER: int = 1

MAX_SHARE_ENUM_ITEMS: int = 5000
MAX_SNAPSHOT_ITEMS_PER_PHASE: int = 10000
MAX_TRANSFER_DURATION_SECONDS: float = 1800.0

PENDING_INPUT_TTL_SECONDS: int = 600
PENDING_INPUT_TTL_SECONDS_MIN: int = 60
PENDING_INPUT_TTL_SECONDS_MAX: int = 3600

MAX_RETAINED_TASKS: int = 1000
MAX_RETAINED_TASKS_MIN: int = 50
MAX_RETAINED_TASKS_MAX: int = 50000
UNCERTAIN_TASK_RETENTION_SECONDS: float = 604_800.0  # 7 days

TASK_ID_LENGTH: int = 12
TASK_DIR_PATTERN: str = r"^\d{8}_[0-9a-f]{12}$"
TASK_DIR_REGEX: re.Pattern[str] = re.compile(TASK_DIR_PATTERN)

DIR_LOCK_IDLE_MAXSIZE: int = 64
DIR_LOCK_HARD_MAXSIZE: int = 256
TASK_LOCK_IDLE_MAXSIZE: int = 256
TASK_LOCK_HARD_MAXSIZE: int = 1024

WEB_MAX_BODY_BYTES: int = 65_536  # 64 KiB
WEB_OTT_TTL_SECONDS: int = 300
WEB_OTT_MAXSIZE: int = 3
WEB_SESSION_TTL_SECONDS: int = 7200
WEB_SESSION_MAXSIZE: int = 5
WEB_LOGIN_RATE_LIMIT_MAX_IPS: int = 256
WEB_LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300
WEB_LOGIN_RATE_LIMIT_MAX_FAILS: int = 5

GROUP_MEMBER_CACHE_TTL_SECONDS: int = 300
GROUP_MEMBER_CACHE_MAXSIZE: int = 1024
MAX_GROUP_WHITELIST_COUNT: int = 20
GROUP_PROBE_CONCURRENCY: int = 3

BAIDU_SHARE_PAGE_SIZE: int = 100
BAIDU_TRANSFER_BATCH_SIZE: int = 100
BAIDU_FILEMETAS_BATCH_SIZE: int = 100
BAIDU_LIST_PAGE_SIZE: int = 1000
BAIDU_LIST_MAX_PAGES: int = 5

QUARK_DETAIL_PAGE_SIZE: int = 50
QUARK_SAVE_BATCH_SIZE: int = 50
QUARK_PATH_LIST_BATCH_SIZE: int = 50
QUARK_TASK_POLL_DELAYS_SECONDS: tuple[float, ...] = (0.5, 1.0, 2.0)
QUARK_TASK_POLL_TIMEOUT_SECONDS: float = 90.0
QUARK_KEEPALIVE_INTERVAL_SECONDS: float = 14400.0

PIKPAK_CLI_VERSION: str = "v0.6.0"
PIKPAK_LS_PAGE_SIZE: int = 500
PIKPAK_SHARE_PAGE_SIZE: int = 100
PIKPAK_TASK_POLL_DELAYS_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)
PIKPAK_TASK_POLL_TIMEOUT_SECONDS: float = 120.0
CLI_MAX_OUTPUT_BYTES: int = 1_048_576  # 1 MiB
CLI_COMMAND_TIMEOUT_SECONDS: float = 120.0

TG_PROGRESS_MIN_INTERVAL_SECONDS: float = 3.5
TG_MESSAGE_CHUNK_CHARS: int = 3800
JANITOR_INTERVAL_SECONDS: float = 600.0

# ==============================================================================
# Core Enums & Error Message Templates (§5.10.4)
# ==============================================================================


class TaskStatus(StrEnum):
    QUEUED = "queued"
    TRANSFERRING = "transferring"
    READY = "ready"
    PARTIAL = "partial"
    DELIVERING = "delivering"
    DELETING = "deleting"
    DELETE_FAILED = "delete_failed"
    FAILED = "failed"


IN_FLIGHT_TASK_STATUSES: frozenset[TaskStatus] = frozenset(
    {
        TaskStatus.QUEUED,
        TaskStatus.TRANSFERRING,
        TaskStatus.DELIVERING,
        TaskStatus.DELETING,
    }
)
SHAREABLE_TASK_STATUSES: frozenset[TaskStatus] = frozenset({TaskStatus.READY, TaskStatus.PARTIAL})
DELETABLE_TASK_STATUSES: frozenset[TaskStatus] = frozenset(
    {
        TaskStatus.READY,
        TaskStatus.PARTIAL,
        TaskStatus.FAILED,
        TaskStatus.DELETE_FAILED,
    }
)


class PasswordPolicy(StrEnum):
    REQUIRED = "REQUIRED"
    OPTIONAL_TRY_FIRST = "OPTIONAL_TRY_FIRST"
    NONE = "NONE"


class AuthMode(StrEnum):
    SECRET_FIELDS = "secret_fields"
    OAUTH_CODE = "oauth_code"
    INTERACTIVE_FLOW = "interactive_flow"


class AccessListType(StrEnum):
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"


class SnapshotPhase(StrEnum):
    BEFORE = "before"
    AFTER = "after"


class ErrorCode(StrEnum):
    ACCESS_DENIED = "ACCESS_DENIED"
    UNAUTHORIZED_PANEL_ACTION = "UNAUTHORIZED_PANEL_ACTION"
    INVALID_LINK = "INVALID_LINK"
    AMBIGUOUS_INPUT = "AMBIGUOUS_INPUT"
    DIRECT_UNSAFE_DIR = "DIRECT_UNSAFE_DIR"
    NEED_PASSWORD = "NEED_PASSWORD"
    PENDING_EXPIRED = "PENDING_EXPIRED"
    INVALID_PASSWORD = "INVALID_PASSWORD"
    SHARE_EXPIRED = "SHARE_EXPIRED"
    PROVIDER_AUTH_INVALID = "PROVIDER_AUTH_INVALID"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    ENUM_LIMIT_EXCEEDED = "ENUM_LIMIT_EXCEEDED"
    TRANSFER_PARTIAL = "TRANSFER_PARTIAL"
    RATE_LIMITED = "RATE_LIMITED"
    QUEUE_FULL = "QUEUE_FULL"
    USER_DELIVERY_EXISTS = "USER_DELIVERY_EXISTS"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    TEMP_DISK_FULL = "TEMP_DISK_FULL"
    OPENLIST_UNAVAILABLE = "OPENLIST_UNAVAILABLE"
    TASK_BUSY = "TASK_BUSY"
    ITEM_SKIPPED = "ITEM_SKIPPED"
    DELETE_UNCERTAIN_EMPTY = "DELETE_UNCERTAIN_EMPTY"
    DELETE_PARTIAL = "DELETE_PARTIAL"
    INTERNAL_ERROR = "INTERNAL_ERROR"


ERROR_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.ACCESS_DENIED: "⛔ 无访问权限（你的 Telegram ID：{user_id}）。如需开通请联系管理员。",
    ErrorCode.UNAUTHORIZED_PANEL_ACTION: "⛔ 仅该任务的发起人或管理员可操作此按钮。",
    ErrorCode.INVALID_LINK: "❌ 未识别到有效的受支持网盘分享链接，请检查后重试。",
    ErrorCode.AMBIGUOUS_INPUT: (
        "⚠️ 检测到冲突或无法归属的提取码，请核对每个分享链接对应的提取码后重试。"
    ),
    ErrorCode.DIRECT_UNSAFE_DIR: (
        "⚠️ PikPak 直存模式（-n）要求目标目录由机器人独占写入；"
        "当前未开启该安全确认，请去掉 -n 使用默认独立子目录模式。"
    ),
    ErrorCode.NEED_PASSWORD: "🔑 该分享链接需要提取码，请发送提取码（群聊请直接回复本条消息）。",
    ErrorCode.PENDING_EXPIRED: "⌛ 等待补全信息已超时，请重新完整发送分享链接与提取码。",
    ErrorCode.INVALID_PASSWORD: "❌ 提取码错误，请核对后重新发送分享链接与提取码。",
    ErrorCode.SHARE_EXPIRED: "❌ 分享链接已失效或不存在。",
    ErrorCode.PROVIDER_AUTH_INVALID: (
        "⚠️ {provider_name} 尚未完成授权或凭证已过期，请联系管理员在后台更新授权。"
    ),
    ErrorCode.BINDING_MISMATCH: (
        "⚠️ 该历史任务绑定的网盘账号或 OpenList 挂载已变更，"
        "为防误操作其他数据已拒绝执行；请联系管理员处理。"
    ),
    ErrorCode.QUOTA_EXCEEDED: "⚠️ {provider_name} 存储空间或单次转存上限不足，转存未能完成。",
    ErrorCode.ENUM_LIMIT_EXCEEDED: (
        "⚠️ 分享文件数或目标目录条目数超过单任务安全上限，已停止处理后续批次。"
    ),
    ErrorCode.TRANSFER_PARTIAL: "⚠️ 任务部分完成：成功 {ok_count} 项，失败 {fail_count} 项。",
    ErrorCode.RATE_LIMITED: "⏳ {provider_name} 请求过于频繁，请稍后重试。",
    ErrorCode.QUEUE_FULL: "⏳ 当前排队任务较多，请稍后再试。",
    ErrorCode.USER_DELIVERY_EXISTS: (
        "⏳ 该用户已有正在排队或发送中的文件投递任务，请等待当前任务完成后再试。"
    ),
    ErrorCode.FILE_TOO_LARGE: (
        "⚠️ 文件「{file_name}」超过 Telegram 2000 MiB 上传限制，已跳过直接发送。"
    ),
    ErrorCode.TEMP_DISK_FULL: "⚠️ 服务器临时中转空间不足，无法直接发送该大文件。",
    ErrorCode.OPENLIST_UNAVAILABLE: (
        "⚠️ OpenList 服务暂不可用或权限不足，网盘文件不受影响，请稍后再试。"
    ),
    ErrorCode.TASK_BUSY: "⏳ 该任务正在执行其他操作，请勿重复点击。",
    ErrorCode.ITEM_SKIPPED: (
        "ℹ️ 以下 {skip_count} 项已在云端被移动或改名，为防误删已自动跳过：{names}"
    ),
    ErrorCode.DELETE_UNCERTAIN_EMPTY: (
        "ℹ️ 已移除中断的任务记录；因上次转存在云端确认落库前中断，"
        "请自行检查网盘目录是否留有残余文件。"
    ),
    ErrorCode.DELETE_PARTIAL: (
        "⚠️ 部分云端文件删除未完成（剩余 {remain_count} 项），可稍后点击重试删除。"
    ),
    ErrorCode.INTERNAL_ERROR: "❌ 处理任务 {task_id} 时发生内部错误，请稍后重试或联系管理员。",
}


def format_error_message(code: ErrorCode, **kwargs: Any) -> str:
    """Render user-safe localized error text without leaking internal details."""
    template = ERROR_MESSAGES[code]
    safe_kwargs = {
        "user_id": "",
        "provider_name": "网盘",
        "ok_count": 0,
        "fail_count": 0,
        "file_name": "",
        "skip_count": 0,
        "names": "",
        "remain_count": 0,
        "task_id": "",
    }
    safe_kwargs.update(kwargs)
    return template.format(**safe_kwargs)


# ==============================================================================
# Domain Exceptions
# ==============================================================================


class YunBotError(Exception):
    """Base structured domain error carrying an ErrorCode."""

    def __init__(self, code: ErrorCode, message: str = "", **context: Any) -> None:
        self.code = code
        self.context = context
        rendered = message or format_error_message(code, **context)
        super().__init__(rendered)

    @property
    def user_message(self) -> str:
        return format_error_message(self.code, **self.context)


class ProviderNeedPasswordError(YunBotError):
    def __init__(self, message: str = "", **context: Any) -> None:
        super().__init__(ErrorCode.NEED_PASSWORD, message, **context)


class ProviderInvalidPasswordError(YunBotError):
    def __init__(self, message: str = "", **context: Any) -> None:
        super().__init__(ErrorCode.INVALID_PASSWORD, message, **context)


class ProviderShareExpiredError(YunBotError):
    def __init__(self, message: str = "", **context: Any) -> None:
        super().__init__(ErrorCode.SHARE_EXPIRED, message, **context)


class ProviderAuthInvalidError(YunBotError):
    def __init__(self, provider_name: str = "网盘", message: str = "") -> None:
        super().__init__(ErrorCode.PROVIDER_AUTH_INVALID, message, provider_name=provider_name)


class ProviderQuotaExceededError(YunBotError):
    def __init__(self, provider_name: str = "网盘", message: str = "") -> None:
        super().__init__(ErrorCode.QUOTA_EXCEEDED, message, provider_name=provider_name)


class ProviderRateLimitedError(YunBotError):
    def __init__(self, provider_name: str = "网盘", message: str = "") -> None:
        super().__init__(ErrorCode.RATE_LIMITED, message, provider_name=provider_name)


class DirectUnsafeDirError(YunBotError):
    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCode.DIRECT_UNSAFE_DIR, message)


class EnumLimitExceededError(YunBotError):
    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCode.ENUM_LIMIT_EXCEEDED, message)


class BindingMismatchError(YunBotError):
    def __init__(self, message: str = "", **context: Any) -> None:
        super().__init__(ErrorCode.BINDING_MISMATCH, message, **context)


class OpenListUnavailableError(YunBotError):
    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCode.OPENLIST_UNAVAILABLE, message)


class ApiResponseTooLargeError(YunBotError):
    def __init__(self, message: str = "API JSON response exceeded MAX_API_JSON_BYTES") -> None:
        super().__init__(ErrorCode.INTERNAL_ERROR, message)


class FileTooLargeForTelegramError(YunBotError):
    def __init__(self, file_name: str, message: str = "") -> None:
        super().__init__(ErrorCode.FILE_TOO_LARGE, message, file_name=file_name)


class TempDiskFullError(YunBotError):
    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCode.TEMP_DISK_FULL, message)


# ==============================================================================
# Immutable DTOs & Snapshots (@dataclass(frozen=True, slots=True))
# ==============================================================================


@dataclass(frozen=True, slots=True)
class RecognizedShareUrl:
    """Result returned by a provider's pure-function ShareRecognizer."""

    provider_id: str
    normalized_url: str
    external_id: str
    embedded_code: str | None = None
    sub_dir_fid: str = "0"


@dataclass(frozen=True, slots=True)
class ParsedShareItem:
    """Single recognized share link paired with its resolved extraction code."""

    share: RecognizedShareUrl
    code: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedInput:
    """Output of parsing.py pure function parser."""

    no_subdir: bool = False
    share: RecognizedShareUrl | None = None
    code: str | None = None
    shares: tuple[ParsedShareItem, ...] = ()
    ambiguous: bool = False
    invalid_link_candidate: bool = False


@dataclass(frozen=True, slots=True)
class ShareLinkInfo:
    """Complete assembled share link ready to enqueue into TransferCoordinator."""

    provider_id: str
    url: str
    external_id: str
    code: str | None = None
    no_subdir: bool = False
    sub_dir_fid: str = "0"


@dataclass(frozen=True, slots=True)
class TransferredEntry:
    """Single top-level cloud entry confirmed transferred in -n direct mode."""

    item_id: str
    path: str
    name: str
    is_dir: bool


@dataclass(frozen=True, slots=True)
class SnapshotTempEntry:
    """Single directory listing entry written to SQLite snapshot_temp_items."""

    item_id: str
    name: str
    is_dir: bool


@dataclass(frozen=True, slots=True)
class TransferOutcome:
    """Bounded summary returned by CloudProvider.transfer() (never carries full item list)."""

    share_title: str
    succeeded_count: int
    failed_count: int = 0
    total_discovered: int = 0
    truncated_by_limit: bool = False
    uncertain: bool = False
    error_code: ErrorCode | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class DeleteItemsOutcome:
    """Result of verified item-by-item cloud deletion in -n direct mode."""

    deleted_ids: tuple[str, ...] = ()
    skipped_items: tuple[TransferItemRecord, ...] = ()
    failed_items: tuple[TransferItemRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class ProviderCredentialRecord:
    """Row representation for provider_credentials table."""

    provider: str
    access_token: str
    refresh_token: str
    account_binding_id: str
    extra_json: str
    updated_at: float


@dataclass(frozen=True, slots=True)
class PendingInputRecord:
    """Row representation for pending_inputs table."""

    chat_id: int
    user_id: int
    provider_hint: str | None
    url: str | None
    external_id: str | None
    code: str | None
    no_subdir: bool
    prompt_message_id: int | None
    updated_at: float


@dataclass(frozen=True, slots=True)
class TaskRecord:
    """Row representation for transfer_tasks table."""

    task_id: str
    chat_id: int
    user_id: int
    provider: str
    account_binding_id: str
    openlist_binding_id: str | None
    share_title: str
    base_save_path: str
    openlist_base_path: str | None
    no_subdir: bool
    task_dir_path: str | None
    status: TaskStatus
    delivery_prev_status: TaskStatus | None
    transfer_uncertain: bool
    remote_task_ref: str | None
    item_count: int
    tg_send_eligible: bool
    openlist_share_id: str | None
    openlist_share_expires_at: float | None
    error_code: str | None
    error_message: str | None
    panel_message_id: int | None
    panel_closed: bool
    created_at: float
    updated_at: float


@dataclass(frozen=True, slots=True)
class TransferItemRecord:
    """Row representation for transfer_items table."""

    id: int
    task_id: str
    item_id: str
    path: str
    name: str
    is_dir: bool


@dataclass(frozen=True, slots=True)
class AccessEntry:
    """Row representation for access_list table."""

    user_id: int
    list_type: AccessListType
    created_at: float
    created_by: int


@dataclass(frozen=True, slots=True)
class GroupWhitelistEntry:
    """Row representation for group_whitelist table."""

    chat_id: int
    created_at: float
    created_by: int


@dataclass(frozen=True, slots=True)
class ProbeMediaFile:
    """Single media file discovered during OpenList integrity probe."""

    openlist_path: str
    name: str
    size: int
    ext: str


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Result of OpenList media integrity probe (§5.8.2)."""

    eligible: bool
    media_files: tuple[ProbeMediaFile, ...] = ()
    complete_traversal: bool = False
    truncated_reason: str | None = None


@dataclass(frozen=True, slots=True)
class ShareLinkResult:
    """Public OpenList /@s/<share_id> share result."""

    share_id: str
    share_url: str
    expires_at: float
    reused: bool = False


@dataclass(frozen=True, slots=True)
class OpenListConnectionStatus:
    """Connectivity & permission check summary returned by POST /api/openlist/test."""

    ok: bool
    username: str = ""
    role: int = -1
    base_path: str = ""
    can_share: bool = False
    can_write_content: bool = False
    can_fs_link: bool = False
    mounted_storages: dict[str, str] | None = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class ProviderAccountStatus:
    """Non-sensitive provider authorization status for Web Panel & binding checks."""

    provider_id: str
    authorized: bool
    account_binding_id: str | None = None
    account_label: str = ""
    auth_mode_used: str = ""
    updated_at: float | None = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class InteractiveAuthStart:
    """Device-code interactive flow initiation payload."""

    verification_uri: str
    user_code: str
    expires_in: int
    interval: int


@dataclass(frozen=True, slots=True)
class InteractiveAuthPollResult:
    """Device-code poll result returned by POST /api/providers/{id}/auth/poll."""

    status: str  # "pending" | "success" | "expired" | "error"
    account: ProviderAccountStatus | None = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class BootstrapConfigSnapshot:
    """Immutable startup configuration parsed from environment variables."""

    tz: str
    telegram_bot_token: str
    telegram_admin_id: int
    telegram_api_base_url: str
    web_internal_port: int
    web_base_url: str
    web_origin: str
    web_cookie_secure: bool
    web_trusted_proxies: tuple[str, ...]
    initial_whitelist_enabled: bool
    initial_whitelist_ids: tuple[int, ...]
    initial_blacklist_ids: tuple[int, ...]
    initial_group_whitelist_ids: tuple[int, ...]
    openlist_base_url: str
    openlist_public_url: str
    openlist_token: str
    openlist_username: str
    openlist_password: str
    openlist_baidu_path: str
    openlist_pikpak_path: str
    openlist_quark_path: str
    openlist_share_ttl_hours: int
    baidu_client_id: str
    baidu_client_secret: str
    baidu_save_path: str
    pikpak_save_path: str
    pikpak_pat: str
    pikpak_direct_exclusive_dir: bool
    quark_save_path: str
    quark_cookie: str
    max_delivery_files: int
    max_temp_disk_mb: int
    pending_input_ttl_seconds: int
    max_retained_tasks: int
    data_dir: str
    shared_upload_dir: str
    log_level: str


@dataclass(frozen=True, slots=True)
class RuntimeSettingsSnapshot:
    """Effective runtime configuration snapshot (SQLite > Env > Default)."""

    whitelist_enabled: bool
    openlist_base_url: str
    openlist_public_url: str
    openlist_token: str
    openlist_username: str
    openlist_password: str
    openlist_baidu_path: str
    openlist_pikpak_path: str
    openlist_quark_path: str
    openlist_share_ttl_hours: int
    baidu_client_id: str
    baidu_client_secret: str
    baidu_save_path: str
    pikpak_save_path: str
    pikpak_direct_exclusive_dir: bool
    quark_save_path: str
    max_delivery_files: int
    max_temp_disk_mb: int
    pending_input_ttl_seconds: int
    max_retained_tasks: int
    log_level: str
    openlist_instance_epoch: str
    openlist_mount_epochs: tuple[tuple[str, str], ...]

    def get_mount_epoch(self, provider_id: str) -> str:
        for k, v in self.openlist_mount_epochs:
            if k == provider_id:
                return v
        return ""

    def get_save_path(self, save_path_key: str) -> str:
        mapping = {
            "BAIDU_SAVE_PATH": self.baidu_save_path,
            "PIKPAK_SAVE_PATH": self.pikpak_save_path,
            "QUARK_SAVE_PATH": self.quark_save_path,
        }
        if save_path_key not in mapping:
            raise KeyError(f"Unknown save_path_key: {save_path_key}")
        return mapping[save_path_key]

    def get_openlist_path(self, openlist_path_key: str) -> str:
        mapping = {
            "OPENLIST_BAIDU_PATH": self.openlist_baidu_path,
            "OPENLIST_PIKPAK_PATH": self.openlist_pikpak_path,
            "OPENLIST_QUARK_PATH": self.openlist_quark_path,
        }
        if openlist_path_key not in mapping:
            raise KeyError(f"Unknown openlist_path_key: {openlist_path_key}")
        return mapping[openlist_path_key]


# ==============================================================================
# Pure Utility Functions (IDs, Path Hardening, Safe Filenames, Log Redaction)
# ==============================================================================


def generate_task_id() -> str:
    """Generate a 12-character lowercase hex task_id so callback_data stays <= 64B."""
    return secrets.token_hex(TASK_ID_LENGTH // 2)


def normalize_posix_path(raw_path: str, *, allow_root: bool = False) -> str:
    """Validate and normalize a cloud/OpenList POSIX absolute path.

    Rejects empty strings, NUL bytes, backslashes, relative paths, and '.' / '..' segments.
    """
    if not isinstance(raw_path, str):
        raise ValueError("Path must be a string")
    stripped = raw_path.strip()
    if not stripped or "\x00" in stripped or "\\" in stripped:
        raise ValueError("Invalid characters in path")
    if not stripped.startswith("/"):
        raise ValueError("Path must be an absolute POSIX path starting with '/'")

    parts = [seg for seg in stripped.split("/") if seg != ""]
    for seg in parts:
        if seg in (".", ".."):
            raise ValueError("Relative '.' or '..' segments are forbidden")

    normalized = "/" + "/".join(parts) if parts else "/"
    assert posixpath.normpath(normalized) == normalized
    if normalized == "/" and not allow_root:
        raise ValueError("Root path '/' is forbidden for save_path")
    return normalized


def validate_save_path(raw_path: str) -> str:
    """Validate a provider base_save_path (must be absolute and strictly not '/')."""
    return normalize_posix_path(raw_path, allow_root=False)


def validate_task_dir_path(task_dir_path: str, base_save_path: str, task_id: str) -> str:
    """Enforce default-mode subdirectory deletion invariant (§5.10.2 Branch A)."""
    norm_base = validate_save_path(base_save_path)
    norm_dir = normalize_posix_path(task_dir_path, allow_root=False)
    if norm_dir == norm_base:
        raise ValueError("task_dir_path must not equal base_save_path")

    p_dir = PurePosixPath(norm_dir)
    p_base = PurePosixPath(norm_base)
    if p_dir.parent != p_base:
        raise ValueError("task_dir_path parent must strictly equal base_save_path")
    if not TASK_DIR_REGEX.fullmatch(p_dir.name):
        raise ValueError("task_dir_path name does not match TASK_DIR_PATTERN")
    if not p_dir.name.endswith(f"_{task_id}"):
        raise ValueError("task_dir_path suffix does not match task_id")
    return norm_dir


def validate_direct_item_path(item_path: str, base_save_path: str) -> str:
    """Enforce -n direct-mode item deletion path invariant (§5.10.2 Branch B)."""
    norm_base = validate_save_path(base_save_path)
    norm_item = normalize_posix_path(item_path, allow_root=False)
    if norm_item == norm_base:
        raise ValueError("item_path must not equal base_save_path")

    p_item = PurePosixPath(norm_item)
    p_base = PurePosixPath(norm_base)
    if not p_item.is_relative_to(p_base):
        raise ValueError("item_path must reside strictly inside base_save_path")
    return norm_item


def sanitize_upload_filename(
    raw_name: str, *, max_utf8_bytes: int = SAFE_FILENAME_MAX_UTF8_BYTES
) -> str:
    """Sanitize a media filename and truncate to <= max_utf8_bytes preserving extension."""
    cleaned = re.sub(r"[\x00-\x1f\x7f/\\]+", "_", (raw_name or "").strip())
    cleaned = cleaned.lstrip(".")
    if not cleaned:
        cleaned = "file"

    dot_idx = cleaned.rfind(".")
    if dot_idx > 0 and len(cleaned) - dot_idx <= 12:
        stem = cleaned[:dot_idx]
        ext = cleaned[dot_idx:]
    else:
        stem = cleaned
        ext = ""

    ext_bytes = ext.encode("utf-8")
    if len(ext_bytes) >= max_utf8_bytes:
        ext = ""
        ext_bytes = b""

    budget = max_utf8_bytes - len(ext_bytes)
    encoded_stem = stem.encode("utf-8")
    if len(encoded_stem) <= budget:
        return f"{stem}{ext}"

    # Truncate UTF-8 cleanly without splitting multi-byte codepoints
    truncated_stem = encoded_stem[:budget].decode("utf-8", errors="ignore").rstrip()
    if not truncated_stem:
        truncated_stem = "f"
    return f"{truncated_stem}{ext}"


def chunk_telegram_text(text: str, *, max_chars: int = TG_MESSAGE_CHUNK_CHARS) -> list[str]:
    """Split long Telegram text safely on newline boundaries within max_chars."""
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= max_chars:
            chunks.append(remaining)
            break
        split_at = remaining.rfind("\n", 0, max_chars)
        if split_at <= 0:
            split_at = max_chars
        chunks.append(remaining[:split_at])
        remaining = remaining[split_at:].lstrip("\n")
    return chunks


_SENSITIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(#token=)[A-Za-z0-9_\-]+"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)((?:access_token|refresh_token|client_secret|password|pwd|stoken|sign|token)=)[^&\s\"']+"
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"(?i)(Authorization\s*:\s*)[^\r\n,]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(Cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), "[REDACTED_BOT_TOKEN]"),
    (
        re.compile(
            r'(?i)("(?:access_token|refresh_token|client_secret|password|pwd|cookie|ott|pat|token)"\s*:\s*)"[^"]*"'
        ),
        r'\1"[REDACTED]"',
    ),
)


def redact_sensitive_text(text: str) -> str:
    """Mask tokens, OTTs, cookies, passwords, and Bot tokens from log/exception strings."""
    if not text:
        return text
    result = text
    for pattern, repl in _SENSITIVE_PATTERNS:
        result = pattern.sub(repl, result)
    return result


class RedactingLogFilter(logging.Filter):
    """Logging filter ensuring secrets never leak via msg or formatted args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
            record.msg = redact_sensitive_text(rendered)
            record.args = ()
            if record.exc_text:
                record.exc_text = redact_sensitive_text(record.exc_text)
        except Exception:
            record.msg = "[LOG_REDACTION_ERROR]"
            record.args = ()
        return True


async def read_bounded_json(resp: Any, *, max_bytes: int = MAX_API_JSON_BYTES) -> Any:
    """Read an HTTP JSON response body in chunks, aborting immediately if > max_bytes."""
    content_length = None
    headers = getattr(resp, "headers", None)
    if headers is not None:
        raw_cl = headers.get("Content-Length")
        if raw_cl and raw_cl.isdigit():
            content_length = int(raw_cl)
    if content_length is not None and content_length > max_bytes:
        raise ApiResponseTooLargeError(
            f"Response Content-Length {content_length} exceeds limit {max_bytes}"
        )

    buf = bytearray()
    async for chunk in resp.content.iter_chunked(65536):
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise ApiResponseTooLargeError(f"Response body exceeded limit {max_bytes}")
    return json.loads(buf.decode("utf-8", errors="replace"))


def restore_task_cancellations(count: int) -> None:
    """Re-apply `count` absorbed cancellation requests onto the current asyncio Task."""
    if count <= 0:
        return
    cur = asyncio.current_task()
    if cur is not None:
        for _ in range(count):
            cur.cancel()


async def run_uninterruptible[T](
    coro: Coroutine[Any, Any, T],
) -> tuple[T, asyncio.CancelledError | None, int, int]:
    """Run `coro` to completion even if the caller Task is repeatedly cancelled.

    Returns `(result, first_during_cancel, pre_cancel_count, total_absorbed_cancels)`.
    """
    cur = asyncio.current_task()
    pre_cancels = 0
    while cur is not None and cur.cancelling() > 0:
        cur.uncancel()
        pre_cancels += 1

    task = asyncio.create_task(coro)
    first_cancel: asyncio.CancelledError | None = None
    during_cancels = 0

    while True:
        try:
            res = await asyncio.shield(task)
            return res, first_cancel, pre_cancels, pre_cancels + during_cancels
        except asyncio.CancelledError as exc:
            cur = asyncio.current_task()
            if cur is not None and cur.cancelling() > 0:
                if first_cancel is None:
                    first_cancel = exc
                while cur.cancelling() > 0:
                    cur.uncancel()
                    during_cancels += 1
            if task.done():
                if task.cancelled():
                    restore_task_cancellations(pre_cancels + during_cancels)
                    raise exc
                err = task.exception()
                if err is not None:
                    restore_task_cancellations(pre_cancels + during_cancels)
                    raise err from None
                return task.result(), first_cancel, pre_cancels, pre_cancels + during_cancels
            if first_cancel is None:
                first_cancel = exc


async def await_cleanup_uninterruptibly[T](coro: Coroutine[Any, Any, T]) -> T:
    """Execute a critical state/DB cleanup coroutine without interruption by repeated cancels.

    Preserves caller `cancelling()` counts for outer `except CancelledError:` / `asyncio.timeout`
    handlers, and raises `CancelledError` after cleanup completes if a fresh cancel arrived during
    normal `finally:` cleanup.
    """
    res, first_cancel, pre_cancels, total_absorbed = await run_uninterruptible(coro)
    restore_task_cancellations(total_absorbed)
    if pre_cancels == 0 and first_cancel is not None:
        raise first_cancel
    return res
