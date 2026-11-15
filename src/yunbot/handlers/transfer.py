"""Telegram transfer commands, message assembly bridge, panel callbacks, and synchronizer.

Strictly adheres to DEVELOPMENT.md §1.1, §5.1, §5.8~§5.10, and AGENTS.md §2, §4, §5.
Zero hardcoded provider names/commands: discovers all commands dynamically from ProviderRegistry.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from aiogram import Bot, F, Router, types
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.filters import Filter
from aiogram.types import ForceReply, InlineKeyboardMarkup, LinkPreviewOptions

from yunbot.handlers.keyboards import (
    PanelAction,
    build_task_panel_keyboard,
    decode_panel_callback,
    format_deletion_outcome_text,
    render_task_panel_text,
)
from yunbot.models import (
    IN_FLIGHT_TASK_STATUSES,
    MAX_BATCH_LINKS_PER_MESSAGE,
    SHAREABLE_TASK_STATUSES,
    TASK_LOCK_HARD_MAXSIZE,
    TG_MESSAGE_CHUNK_CHARS,
    TG_PROGRESS_MIN_INTERVAL_SECONDS,
    ErrorCode,
    RecognizedShareUrl,
    ShareLinkInfo,
    ShareLinkResult,
    TaskRecord,
    YunBotError,
    chunk_telegram_text,
    format_error_message,
    redact_sensitive_text,
)
from yunbot.providers.base import ProviderSpec
from yunbot.providers.registry import ProviderRegistry

LOGGER = logging.getLogger(__name__)


class AssembleAction(StrEnum):
    """Canonical assembly outcome actions bridging `assembler.py` and `handlers/transfer.py`."""

    READY = "ready"
    NEED_PASSWORD = "need_password"
    NEED_LINK = "need_link"
    IGNORE = "ignore"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class AssembleResult:
    """Canonical immutable DTO for message assembly outcomes."""

    action: AssembleAction | str
    share: ShareLinkInfo | None = None
    shares: tuple[ShareLinkInfo, ...] = ()
    skipped_need_password: tuple[RecognizedShareUrl, ...] = ()
    error_code: ErrorCode | None = None
    message: str | None = None


@runtime_checkable
class AssemblerProtocol(Protocol):
    """Duck-typed input assembler contract (`assembler.py`)."""

    async def handle_private_input(
        self,
        *,
        chat_id: int,
        user_id: int,
        text: str,
        forced_provider_id: str | None = None,
    ) -> Any: ...

    async def handle_group_command(
        self,
        *,
        chat_id: int,
        user_id: int,
        text: str,
        forced_provider_id: str | None = None,
    ) -> Any: ...

    async def handle_group_reply(
        self,
        *,
        chat_id: int,
        user_id: int,
        reply_to_message_id: int,
        text: str,
    ) -> Any: ...

    async def save_password_prompt(self, *args: Any, **kwargs: Any) -> Any: ...


@runtime_checkable
class CoordinatorProtocol(Protocol):
    """Duck-typed transfer coordinator contract (`coordinator.py`)."""

    async def enqueue_transfer(
        self,
        *,
        chat_id: int,
        user_id: int,
        share: ShareLinkInfo,
        panel_message_id: int | None = None,
    ) -> TaskRecord: ...


@runtime_checkable
class DeliveryProtocol(Protocol):
    """Duck-typed media delivery service contract (`delivery.py`)."""

    async def enqueue_delivery(
        self,
        task_id: str,
        *,
        operator_id: int,
        notify_chat_id: int,
    ) -> Any: ...


@runtime_checkable
class OpenListShareProtocol(Protocol):
    """Duck-typed OpenList share lifecycle contract (`openlist.py`)."""

    async def create_or_get_task_share(self, task_id: str) -> ShareLinkResult: ...


def _resolve_provider_name(registry: ProviderRegistry, provider_id: str) -> str:
    provider = registry.find(provider_id)
    if provider is not None:
        return provider.spec.display_name
    return provider_id


async def _mention_matches_bot(mention: str | None, bot: Bot | Any | None) -> bool:
    if not mention or bot is None:
        return True
    me = getattr(bot, "_me", None)
    if me is None and hasattr(bot, "me"):
        try:
            me = await bot.me()
        except Exception:
            me = None
    username = getattr(me, "username", None)
    if username:
        return mention.lower() == str(username).lower()
    return True


def _split_leading_command(text: str) -> tuple[str, str | None, str] | None:
    """Parse `/cmd[@mention][ whitespace+remainder]` into `(cmd_lower, mention, remainder)`."""
    stripped = text.lstrip()
    if not stripped.startswith("/"):
        return None
    parts = stripped.split(maxsplit=1)
    first_token = parts[0]
    remainder = parts[1] if len(parts) > 1 else ""
    body = first_token[1:]
    if not body:
        return None
    if "@" in body:
        cmd_name, _, mention = body.partition("@")
        if not cmd_name or not mention:
            return None
        return cmd_name.lower(), mention, remainder
    return body.lower(), None, remainder


class _StaticCommandsFilter(Filter):
    """Match fixed commands (such as `/start`, `/help`) with optional `@BotUsername`."""

    def __init__(self, commands: tuple[str, ...]) -> None:
        self._commands = frozenset(c.lstrip("/").lower() for c in commands)

    async def __call__(
        self,
        message: types.Message,
        bot: Bot | None = None,
    ) -> bool:
        if not message.text:
            return False
        parsed = _split_leading_command(message.text)
        if parsed is None:
            return False
        cmd_name, mention, _ = parsed
        if cmd_name not in self._commands:
            return False
        return await _mention_matches_bot(mention, bot)


class _DynamicProviderCommandFilter(Filter):
    """Match commands dynamically against `ProviderRegistry.all_specs()`."""

    def __init__(self, registry: ProviderRegistry) -> None:
        self._registry = registry

    async def __call__(
        self,
        message: types.Message,
        bot: Bot | None = None,
    ) -> bool | dict[str, Any]:
        if not message.text:
            return False
        parsed = _split_leading_command(message.text)
        if parsed is None:
            return False
        cmd_name, mention, remainder = parsed
        registered_commands = {
            spec.command.lstrip("/").lower(): spec for spec in self._registry.all_specs()
        }
        spec = registered_commands.get(cmd_name)
        if spec is None:
            return False
        if not await _mention_matches_bot(mention, bot):
            return False
        return {"provider_spec": spec, "command_remainder": remainder}


class _GroupBotReplyFilter(Filter):
    """Match non-command replies to Bot messages inside group/supergroup chats."""

    async def __call__(
        self,
        message: types.Message,
        bot: Bot | None = None,
    ) -> bool:
        if message.chat.type not in ("group", "supergroup"):
            return False
        if message.from_user is None or not message.text:
            return False
        if message.text.lstrip().startswith("/"):
            return False
        reply = message.reply_to_message
        if reply is None or reply.from_user is None or not reply.from_user.is_bot:
            return False
        me = getattr(bot, "_me", None) if bot is not None else None
        if me is not None and getattr(me, "id", None) is not None:
            return reply.from_user.id == me.id
        return True


class _PrivatePlainTextFilter(Filter):
    """Match non-command plain text messages in private chats."""

    async def __call__(self, message: types.Message) -> bool:
        if message.chat.type != "private":
            return False
        if not message.text:
            return False
        return not message.text.lstrip().startswith("/")


async def _invoke_check_access(
    access: Any,
    *,
    user_id: int,
    chat_id: int,
    chat_type: str,
) -> tuple[bool, str | None]:
    try:
        fn = access.check_access
        sig = inspect.signature(fn)
        params = sig.parameters
        has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

        kwargs: dict[str, Any] = {}
        if "user_id" in params or has_var_kw:
            kwargs["user_id"] = user_id
        if "chat_id" in params or has_var_kw:
            kwargs["chat_id"] = chat_id
        if "chat_type" in params:
            kwargs["chat_type"] = chat_type
        if "is_private" in params:
            kwargs["is_private"] = chat_type == "private"

        if kwargs and ("user_id" in kwargs or has_var_kw):
            raw = fn(**kwargs)
        else:
            raw = fn(user_id, chat_id)
        decision = await raw if inspect.isawaitable(raw) else raw
    except YunBotError as err:
        return False, err.user_message

    allowed = bool(decision.allowed) if hasattr(decision, "allowed") else bool(decision)
    if not allowed:
        return False, format_error_message(ErrorCode.ACCESS_DENIED, user_id=user_id)
    return True, None


async def _call_assembler_input(
    fn: Callable[..., Any],
    *,
    chat_id: int,
    user_id: int,
    text: str,
    forced_provider_id: str | None,
) -> Any:
    sig = inspect.signature(fn)
    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

    kwargs: dict[str, Any] = {
        "chat_id": chat_id,
        "user_id": user_id,
        "text": text,
    }
    if "forced_provider_id" in params or has_var_kw:
        kwargs["forced_provider_id"] = forced_provider_id
    elif "provider_id" in params:
        kwargs["provider_id"] = forced_provider_id
    elif "provider_hint" in params:
        kwargs["provider_hint"] = forced_provider_id

    res = fn(**kwargs)
    return await res if inspect.isawaitable(res) else res


async def _call_handle_group_reply(
    assembler: Any,
    *,
    chat_id: int,
    user_id: int,
    reply_to_message_id: int,
    text: str,
) -> Any:
    fn = assembler.handle_group_reply
    sig = inspect.signature(fn)
    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

    kwargs: dict[str, Any] = {
        "chat_id": chat_id,
        "user_id": user_id,
        "text": text,
    }
    if "reply_to_message_id" in params or has_var_kw:
        kwargs["reply_to_message_id"] = reply_to_message_id
    elif "prompt_message_id" in params:
        kwargs["prompt_message_id"] = reply_to_message_id
    elif "reply_message_id" in params:
        kwargs["reply_message_id"] = reply_to_message_id
    else:
        res = fn(chat_id, user_id, reply_to_message_id, text)
        return await res if inspect.isawaitable(res) else res

    res = fn(**kwargs)
    return await res if inspect.isawaitable(res) else res


async def _call_save_password_prompt(
    assembler: Any,
    *,
    chat_id: int,
    user_id: int,
    prompt_message_id: int,
    share: ShareLinkInfo | RecognizedShareUrl | None = None,
    no_subdir: bool | None = None,
) -> None:
    if assembler is None or not hasattr(assembler, "save_password_prompt"):
        return
    fn = assembler.save_password_prompt
    sig = inspect.signature(fn)
    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

    kwargs: dict[str, Any] = {}
    if "chat_id" in params or has_var_kw:
        kwargs["chat_id"] = chat_id
    if "user_id" in params or has_var_kw:
        kwargs["user_id"] = user_id
    if "prompt_message_id" in params or has_var_kw:
        kwargs["prompt_message_id"] = prompt_message_id
    elif "message_id" in params:
        kwargs["message_id"] = prompt_message_id

    if share is not None:
        share_url = share.normalized_url if isinstance(share, RecognizedShareUrl) else share.url
        eff_no_subdir = (
            bool(no_subdir)
            if isinstance(share, RecognizedShareUrl)
            else bool(share.no_subdir or no_subdir)
        )
        if "share" in params or has_var_kw:
            kwargs["share"] = share
        if "provider_id" in params:
            kwargs["provider_id"] = share.provider_id
        if "provider_hint" in params:
            kwargs["provider_hint"] = share.provider_id
        if "url" in params:
            kwargs["url"] = share_url
        if "external_id" in params:
            kwargs["external_id"] = share.external_id
        if "no_subdir" in params:
            kwargs["no_subdir"] = eff_no_subdir
        if "sub_dir_fid" in params:
            kwargs["sub_dir_fid"] = share.sub_dir_fid
    elif no_subdir is not None and ("no_subdir" in params or has_var_kw):
        kwargs["no_subdir"] = no_subdir

    res = fn(**kwargs) if kwargs else fn(chat_id, user_id, prompt_message_id)
    if inspect.isawaitable(res):
        await res


async def _call_delete_task(
    deletion_service: Any,
    task_id: str,
    operator_id: int,
) -> Any:
    fn = deletion_service.delete_task_with_cloud_files
    sig = inspect.signature(fn)
    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    if "operator_id" in params or has_var_kw:
        res = fn(task_id, operator_id=operator_id)
    else:
        res = fn(task_id)
    return await res if inspect.isawaitable(res) else res


async def _call_enqueue_delivery(
    delivery: Any,
    task_id: str,
    *,
    operator_id: int,
    notify_chat_id: int,
) -> Any:
    fn = delivery.enqueue_delivery
    sig = inspect.signature(fn)
    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

    kwargs: dict[str, Any] = {}
    if "operator_id" in params or has_var_kw:
        kwargs["operator_id"] = operator_id
    if "notify_chat_id" in params or has_var_kw:
        kwargs["notify_chat_id"] = notify_chat_id
    elif "chat_id" in params:
        kwargs["chat_id"] = notify_chat_id

    res = fn(task_id, **kwargs)
    return await res if inspect.isawaitable(res) else res


def _normalize_action_token(raw_action: Any) -> str:
    if raw_action is None:
        return "IGNORE"
    name = getattr(raw_action, "name", None)
    if isinstance(name, str) and name:
        return name.upper()
    val = getattr(raw_action, "value", raw_action)
    return str(val).strip().upper()


def _render_help_text(registry: ProviderRegistry) -> str:
    specs = registry.all_specs()
    provider_lines: list[str] = []
    for spec in specs:
        cmd = spec.command.lstrip("/")
        provider_lines.append(f"• /{cmd} <分享链接> [提取码] — 转存至 {spec.display_name}")

    providers_section = (
        "\n".join(provider_lines)
        if provider_lines
        else "• 当前暂未注册网盘插件，请联系管理员检查配置。"
    )

    lines: list[str] = [
        "☁️ YunTransfer 网盘转存与媒体交付机器人",
        "",
        "【支持的网盘命令】",
        providers_section,
        "",
        "【转存与交付说明】",
        "• 自动创建 `<基准目录>/<yyyymmdd>_<task_id>` 专属子目录保存文件；",
        "• 支持生成 24h 免密 OpenList 分享链接及视频/图片 Telegram 直发。",
        "",
        "【交互说明】",
        (
            "• 私聊：可直接发送单条或多条分享链接"
            f"（单次最多批量识别 {MAX_BATCH_LINKS_PER_MESSAGE} 条，支持多网盘混发；"
            "单链接与提取码也支持分两条乱序发送）。"
        ),
        (
            "• 群聊：请使用上述显式网盘命令（同样支持一次附带多条同网盘链接批量转存）；"
            "若缺少提取码，请直接回复机器人的提示消息补全。"
        ),
        "• 历史任务：发送 /tasks 查看任务记录、状态详情或执行连带删除。",
    ]
    return "\n".join(lines)


async def _safe_edit_message(
    message: types.Message,
    text: str,
    *,
    bot: Bot | None = None,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    chunks = chunk_telegram_text(text, max_chars=TG_MESSAGE_CHUNK_CHARS)
    primary = chunks[0] if chunks else text[:TG_MESSAGE_CHUNK_CHARS]
    resolved_bot = message.bot or bot
    try:
        if message.bot is not None:
            await message.edit_text(
                primary,
                reply_markup=reply_markup,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        elif resolved_bot is not None:
            await resolved_bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=message.message_id,
                text=primary,
                reply_markup=reply_markup,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
    except TelegramBadRequest as exc:
        lowered = str(exc).lower()
        if "message is not modified" in lowered or "message to edit not found" in lowered:
            return
        raise


async def _safe_edit_callback_panel(
    callback: types.CallbackQuery,
    text: str,
    reply_markup: InlineKeyboardMarkup | None,
) -> None:
    msg = callback.message
    if msg is None:
        return
    chunks = chunk_telegram_text(text, max_chars=TG_MESSAGE_CHUNK_CHARS)
    primary = chunks[0] if chunks else text[:TG_MESSAGE_CHUNK_CHARS]
    try:
        if isinstance(msg, types.Message) and msg.bot is not None:
            await msg.edit_text(
                primary,
                reply_markup=reply_markup,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        elif callback.bot is not None:
            await callback.bot.edit_message_text(
                chat_id=msg.chat.id,
                message_id=msg.message_id,
                text=primary,
                reply_markup=reply_markup,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
    except TelegramBadRequest as exc:
        lowered = str(exc).lower()
        if "message is not modified" in lowered or "message to edit not found" in lowered:
            return
        raise


async def _clear_callback_markup(callback: types.CallbackQuery) -> None:
    msg = callback.message
    if msg is None:
        return
    try:
        if isinstance(msg, types.Message) and msg.bot is not None:
            await msg.edit_reply_markup(reply_markup=None)
        elif callback.bot is not None:
            await callback.bot.edit_message_reply_markup(
                chat_id=msg.chat.id,
                message_id=msg.message_id,
                reply_markup=None,
            )
    except TelegramBadRequest as exc:
        lowered = str(exc).lower()
        if "message is not modified" in lowered or "message to edit not found" in lowered:
            return
        raise


def _serialize_markup_fingerprint(markup: InlineKeyboardMarkup | None) -> str:
    if markup is None:
        return ""
    rows = [[(btn.text, btn.callback_data) for btn in row] for row in markup.inline_keyboard]
    return json.dumps(rows, ensure_ascii=False)


class TelegramPanelSynchronizer:
    """Synchronizes background task lifecycle transitions onto Telegram status cards.

    Enforces `TG_PROGRESS_MIN_INTERVAL_SECONDS = 3.5` per-task throttling on intermediate
    progress edits while guaranteeing immediate delivery of terminal/state-change edits
    and `ProviderNeedPasswordError` ForceReply prompts.
    """

    def __init__(
        self,
        *,
        bot: Bot,
        storage: Any,
        registry: ProviderRegistry,
        assembler: Any | None = None,
        min_interval_seconds: float = TG_PROGRESS_MIN_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._bot = bot
        self._storage = storage
        self._registry = registry
        self._assembler = assembler
        self._min_interval_seconds = min_interval_seconds
        self._clock = clock
        self._last_edit_at: dict[str, float] = {}
        self._last_fingerprint: dict[str, tuple[str, str]] = {}

    def _prune_cache_if_needed(self) -> None:
        if len(self._last_edit_at) >= TASK_LOCK_HARD_MAXSIZE:
            oldest_key = next(iter(self._last_edit_at))
            self._last_edit_at.pop(oldest_key, None)
            self._last_fingerprint.pop(oldest_key, None)

    def _evict_task(self, task_id: str) -> None:
        self._last_edit_at.pop(task_id, None)
        self._last_fingerprint.pop(task_id, None)

    async def _resolve_task(self, task_or_id: TaskRecord | str) -> TaskRecord | None:
        if isinstance(task_or_id, TaskRecord):
            return task_or_id
        return await self._storage.get_task(task_or_id)

    async def sync_task(
        self,
        task_or_id: TaskRecord | str,
        *,
        force: bool = True,
        extra_notice: str | None = None,
    ) -> bool:
        """Render and edit a task's Telegram status card; returns True if an edit ran."""
        task = await self._resolve_task(task_or_id)
        if task is None or task.panel_message_id is None:
            return False

        now = self._clock()
        if not force:
            last_ts = self._last_edit_at.get(task.task_id)
            if last_ts is not None and (now - last_ts) < self._min_interval_seconds:
                return False

        provider_name = _resolve_provider_name(self._registry, task.provider)
        text = render_task_panel_text(
            task,
            provider_name,
            extra_notice=extra_notice,
        )
        chunks = chunk_telegram_text(text, max_chars=TG_MESSAGE_CHUNK_CHARS)
        rendered_text = chunks[0] if chunks else text[:TG_MESSAGE_CHUNK_CHARS]
        kb = build_task_panel_keyboard(task, confirm_delete=False)
        fp = (rendered_text, _serialize_markup_fingerprint(kb))

        if self._last_fingerprint.get(task.task_id) == fp:
            return False

        self._prune_cache_if_needed()
        self._last_edit_at[task.task_id] = now
        self._last_fingerprint[task.task_id] = fp

        try:
            await self._bot.edit_message_text(
                chat_id=task.chat_id,
                message_id=task.panel_message_id,
                text=rendered_text,
                reply_markup=kb,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        except TelegramBadRequest as exc:
            lowered = str(exc).lower()
            if "message is not modified" in lowered or "message to edit not found" in lowered:
                return False
            LOGGER.warning(
                "Telegram panel edit rejected for task %s: %s",
                task.task_id,
                redact_sensitive_text(str(exc)),
            )
            return False

        if task.status not in IN_FLIGHT_TASK_STATUSES:
            self._last_edit_at.pop(task.task_id, None)
        return True

    async def on_progress(
        self,
        task_or_id: TaskRecord | str,
        stage: str = "",
        done: int = 0,
        total: int = 0,
    ) -> bool:
        """Throttled progress callback (`>= 3.5s` between edits per task)."""
        parts: list[str] = []
        if stage:
            parts.append(redact_sensitive_text(stage))
        if total > 0:
            parts.append(f"{done} / {total}")
        elif done > 0:
            parts.append(f"已处理 {done} 项")
        notice = f"⏳ 实时进度：{' · '.join(parts)}" if parts else None
        return await self.sync_task(task_or_id, force=False, extra_notice=notice)

    async def on_status_changed(self, task_or_id: TaskRecord | str) -> bool:
        """Immediate unthrottled update when status changes (e.g. `deleting`, `delivering`)."""
        return await self.sync_task(task_or_id, force=True)

    async def on_completed(self, task_or_id: TaskRecord | str) -> bool:
        """Immediate unthrottled update when transfer finishes (`ready`/`partial`/`failed`)."""
        return await self.sync_task(task_or_id, force=True)

    async def on_deleted(
        self,
        task: TaskRecord,
        result: Any = None,
    ) -> None:
        """Finalize and strip buttons from panel card after cloud + record deletion."""
        self._evict_task(task.task_id)
        if task.panel_message_id is None:
            return
        provider_name = _resolve_provider_name(self._registry, task.provider)
        outcome_text = format_deletion_outcome_text(task, result, None, provider_name)
        chunks = chunk_telegram_text(outcome_text, max_chars=TG_MESSAGE_CHUNK_CHARS)
        primary = chunks[0] if chunks else outcome_text[:TG_MESSAGE_CHUNK_CHARS]
        try:
            await self._bot.edit_message_text(
                chat_id=task.chat_id,
                message_id=task.panel_message_id,
                text=primary,
                reply_markup=None,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        except TelegramBadRequest as exc:
            lowered = str(exc).lower()
            if "message is not modified" in lowered or "message to edit not found" in lowered:
                return
            LOGGER.warning(
                "Telegram panel delete update failed for task %s: %s",
                task.task_id,
                redact_sensitive_text(str(exc)),
            )

    async def on_need_password(
        self,
        task: TaskRecord | None = None,
        *,
        chat_id: int | None = None,
        user_id: int | None = None,
        share: ShareLinkInfo | None = None,
        panel_message_id: int | None = None,
    ) -> int | None:
        """Handle `ProviderNeedPasswordError` by sending `ForceReply` and saving prompt."""
        resolved_chat_id = chat_id if chat_id is not None else (task.chat_id if task else None)
        resolved_user_id = user_id if user_id is not None else (task.user_id if task else None)
        resolved_panel_id = (
            panel_message_id
            if panel_message_id is not None
            else (task.panel_message_id if task else None)
        )
        if task is not None:
            self._evict_task(task.task_id)

        if resolved_chat_id is None or resolved_user_id is None:
            return None

        prompt_text = format_error_message(ErrorCode.NEED_PASSWORD)
        if resolved_panel_id is not None:
            try:
                await self._bot.edit_message_text(
                    chat_id=resolved_chat_id,
                    message_id=resolved_panel_id,
                    text=prompt_text,
                    reply_markup=None,
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
            except TelegramBadRequest:
                pass

        sent_prompt = await self._bot.send_message(
            chat_id=resolved_chat_id,
            text=prompt_text,
            reply_markup=ForceReply(selective=True),
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )
        await _call_save_password_prompt(
            self._assembler,
            chat_id=resolved_chat_id,
            user_id=resolved_user_id,
            prompt_message_id=sent_prompt.message_id,
            share=share,
        )
        return sent_prompt.message_id


def build_transfer_router(
    *,
    storage: Any,
    access: Any,
    assembler: Any,
    registry: ProviderRegistry,
    coordinator: Any,
    delivery: Any,
    openlist: Any,
    deletion_service: Any,
) -> Router:
    """Create aiogram Router for transfer commands, message assembly, and panel callbacks."""
    router = Router(name="transfer")

    async def _reply_with_backoff(
        message: types.Message,
        text: str,
        *,
        reply_markup: Any = None,
    ) -> types.Message:
        try:
            return await message.reply(
                text,
                reply_markup=reply_markup,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        except TelegramRetryAfter as err:
            await asyncio.sleep(min(max(float(err.retry_after), 0.1), 5.0))
            return await message.reply(
                text,
                reply_markup=reply_markup,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )

    async def _enqueue_ready_share(
        message: types.Message,
        *,
        chat_id: int,
        user_id: int,
        share: ShareLinkInfo,
        batch_index: int | None = None,
        batch_total: int | None = None,
    ) -> None:
        initial_text = (
            f"⏳ [{batch_index}/{batch_total}] 已加入转存队列..."
            if batch_index is not None and batch_total is not None and batch_total > 1
            else "⏳ 已加入转存队列..."
        )
        sent = await _reply_with_backoff(message, initial_text)
        try:
            await coordinator.enqueue_transfer(
                chat_id=chat_id,
                user_id=user_id,
                share=share,
                panel_message_id=sent.message_id,
            )
        except YunBotError as err:
            await _safe_edit_message(
                sent,
                err.user_message,
                bot=message.bot,
                reply_markup=None,
            )
        except Exception:
            LOGGER.exception("Unexpected error enqueuing transfer for user %s", user_id)
            await _safe_edit_message(
                sent,
                format_error_message(ErrorCode.INTERNAL_ERROR, task_id=""),
                bot=message.bot,
                reply_markup=None,
            )

    async def _notify_skipped_batch_passwords(
        message: types.Message,
        *,
        skipped_pwd: tuple[RecognizedShareUrl, ...] | list[RecognizedShareUrl],
        no_subdir: bool,
        chat_id: int,
        user_id: int,
        is_group: bool,
    ) -> None:
        if len(skipped_pwd) == 1:
            missing = skipped_pwd[0]
            prompt_text = (
                f"🔑 其余链接已加入转存队列；链接 {redact_sensitive_text(missing.normalized_url)} "
                "需要提取码，请发送提取码（群聊请直接回复本条消息）。"
            )
            if is_group:
                sent_prompt = await _reply_with_backoff(
                    message,
                    prompt_text,
                    reply_markup=ForceReply(selective=True),
                )
                await _call_save_password_prompt(
                    assembler,
                    chat_id=chat_id,
                    user_id=user_id,
                    prompt_message_id=sent_prompt.message_id,
                    share=missing,
                    no_subdir=no_subdir,
                )
            else:
                await _reply_with_backoff(message, prompt_text)
            return

        listed = "\n".join(
            f"• {redact_sensitive_text(item.normalized_url)}" for item in skipped_pwd[:10]
        )
        if len(skipped_pwd) > 10:
            listed = f"{listed}\n…等共 {len(skipped_pwd)} 条"
        multi_prompt = (
            f"🔑 其余链接已加入转存队列；以下 {len(skipped_pwd)} 条加密链接缺少提取码未入队，"
            f"请附上对应提取码后重新发送：\n{listed}"
        )
        await _reply_with_backoff(message, multi_prompt)

    async def _handle_assemble_outcome(
        message: types.Message,
        res: Any,
        *,
        chat_id: int,
        user_id: int,
        is_group: bool,
    ) -> None:
        if res is None:
            return

        action = _normalize_action_token(getattr(res, "action", None))
        if action in ("IGNORE", "IGNORED", "NOOP", "NONE"):
            return

        if action == "READY":
            raw_shares = getattr(res, "shares", None)
            if isinstance(raw_shares, (list, tuple)) and raw_shares:
                ready_shares = list(raw_shares)
            else:
                single_share = getattr(res, "share", None)
                ready_shares = [single_share] if single_share is not None else []

            if not ready_shares:
                await message.reply(
                    format_error_message(ErrorCode.INVALID_LINK),
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
                return

            total_batch = len(ready_shares)
            for idx, share_item in enumerate(ready_shares, start=1):
                await _enqueue_ready_share(
                    message,
                    chat_id=chat_id,
                    user_id=user_id,
                    share=share_item,
                    batch_index=idx if total_batch > 1 else None,
                    batch_total=total_batch if total_batch > 1 else None,
                )

            skipped_pwd = getattr(res, "skipped_need_password", None) or ()
            if skipped_pwd:
                await _notify_skipped_batch_passwords(
                    message,
                    skipped_pwd=skipped_pwd,
                    no_subdir=bool(getattr(res, "no_subdir", False)),
                    chat_id=chat_id,
                    user_id=user_id,
                    is_group=is_group,
                )
            return

        if action in ("NEED_PASSWORD", "NEED_CODE", "WAIT_CODE", "AWAIT_PASSWORD"):
            custom_text = getattr(res, "message", None)
            prompt_text = (
                redact_sensitive_text(custom_text.strip())
                if isinstance(custom_text, str) and custom_text.strip()
                else format_error_message(ErrorCode.NEED_PASSWORD)
            )
            if is_group:
                sent_prompt = await message.reply(
                    prompt_text,
                    reply_markup=ForceReply(selective=True),
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
                await _call_save_password_prompt(
                    assembler,
                    chat_id=chat_id,
                    user_id=user_id,
                    prompt_message_id=sent_prompt.message_id,
                    share=getattr(res, "share", None),
                )
            else:
                await message.reply(
                    prompt_text,
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
            return

        if action in ("NEED_LINK", "WAIT_LINK", "AWAIT_LINK"):
            custom_text = getattr(res, "message", None)
            reply_text = (
                redact_sensitive_text(custom_text.strip())
                if isinstance(custom_text, str) and custom_text.strip()
                else "🔗 已记录提取码，请继续发送网盘分享链接。"
            )
            await message.reply(
                reply_text,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        err_code = getattr(res, "error_code", None)
        if isinstance(err_code, ErrorCode):
            await message.reply(
                format_error_message(err_code, user_id=user_id),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return
        if isinstance(err_code, str) and err_code:
            try:
                await message.reply(
                    format_error_message(ErrorCode(err_code), user_id=user_id),
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
                return
            except ValueError:
                pass

        action_to_code = {
            "INVALID_LINK": ErrorCode.INVALID_LINK,
            "INVALID": ErrorCode.INVALID_LINK,
            "NO_MATCH": ErrorCode.INVALID_LINK,
            "AMBIGUOUS": ErrorCode.AMBIGUOUS_INPUT,
            "AMBIGUOUS_INPUT": ErrorCode.AMBIGUOUS_INPUT,
            "PENDING_EXPIRED": ErrorCode.PENDING_EXPIRED,
            "EXPIRED": ErrorCode.PENDING_EXPIRED,
        }
        mapped_code = action_to_code.get(action)
        if mapped_code is not None:
            await message.reply(
                format_error_message(mapped_code, user_id=user_id),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        custom_msg = getattr(res, "message", None)
        fallback_text = (
            redact_sensitive_text(custom_msg.strip())
            if isinstance(custom_msg, str) and custom_msg.strip()
            else format_error_message(ErrorCode.INVALID_LINK)
        )
        await message.reply(
            fallback_text,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )

    @router.message(_StaticCommandsFilter(("start", "help")))
    async def handle_start_or_help(message: types.Message) -> None:
        if message.from_user is None:
            await message.reply(
                format_error_message(ErrorCode.ACCESS_DENIED, user_id="未知"),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        user_id = message.from_user.id
        allowed, deny_msg = await _invoke_check_access(
            access,
            user_id=user_id,
            chat_id=message.chat.id,
            chat_type=message.chat.type,
        )
        if not allowed:
            await message.reply(
                deny_msg or format_error_message(ErrorCode.ACCESS_DENIED, user_id=user_id),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        help_text = _render_help_text(registry)
        for chunk in chunk_telegram_text(help_text, max_chars=TG_MESSAGE_CHUNK_CHARS):
            await message.reply(
                chunk,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )

    @router.message(_DynamicProviderCommandFilter(registry))
    async def handle_provider_command(
        message: types.Message,
        provider_spec: ProviderSpec,
        command_remainder: str,
    ) -> None:
        if message.from_user is None:
            await message.reply(
                format_error_message(ErrorCode.ACCESS_DENIED, user_id="未知"),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        user_id = message.from_user.id
        chat_id = message.chat.id
        chat_type = message.chat.type
        allowed, deny_msg = await _invoke_check_access(
            access,
            user_id=user_id,
            chat_id=chat_id,
            chat_type=chat_type,
        )
        if not allowed:
            await message.reply(
                deny_msg or format_error_message(ErrorCode.ACCESS_DENIED, user_id=user_id),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        is_group = chat_type in ("group", "supergroup")
        try:
            if chat_type == "private":
                res = await _call_assembler_input(
                    assembler.handle_private_input,
                    chat_id=chat_id,
                    user_id=user_id,
                    text=command_remainder,
                    forced_provider_id=provider_spec.provider_id,
                )
            else:
                res = await _call_assembler_input(
                    assembler.handle_group_command,
                    chat_id=chat_id,
                    user_id=user_id,
                    text=command_remainder,
                    forced_provider_id=provider_spec.provider_id,
                )
        except YunBotError as err:
            await message.reply(
                err.user_message,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        await _handle_assemble_outcome(
            message,
            res,
            chat_id=chat_id,
            user_id=user_id,
            is_group=is_group,
        )

    @router.message(_GroupBotReplyFilter())
    async def handle_group_force_reply(message: types.Message) -> None:
        if message.from_user is None or message.reply_to_message is None or not message.text:
            return

        user_id = message.from_user.id
        chat_id = message.chat.id
        reply_to_id = message.reply_to_message.message_id

        try:
            res = await _call_handle_group_reply(
                assembler,
                chat_id=chat_id,
                user_id=user_id,
                reply_to_message_id=reply_to_id,
                text=message.text,
            )
        except YunBotError as err:
            await message.reply(
                err.user_message,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        if res is None:
            return
        action = _normalize_action_token(getattr(res, "action", None))
        if action in ("IGNORE", "IGNORED", "NOOP", "NONE"):
            return

        allowed, deny_msg = await _invoke_check_access(
            access,
            user_id=user_id,
            chat_id=chat_id,
            chat_type=message.chat.type,
        )
        if not allowed:
            await message.reply(
                deny_msg or format_error_message(ErrorCode.ACCESS_DENIED, user_id=user_id),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        await _handle_assemble_outcome(
            message,
            res,
            chat_id=chat_id,
            user_id=user_id,
            is_group=True,
        )

    @router.message(_PrivatePlainTextFilter())
    async def handle_private_plain_text(message: types.Message) -> None:
        if message.from_user is None or not message.text:
            return

        user_id = message.from_user.id
        chat_id = message.chat.id
        allowed, deny_msg = await _invoke_check_access(
            access,
            user_id=user_id,
            chat_id=chat_id,
            chat_type=message.chat.type,
        )
        if not allowed:
            await message.reply(
                deny_msg or format_error_message(ErrorCode.ACCESS_DENIED, user_id=user_id),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        try:
            res = await _call_assembler_input(
                assembler.handle_private_input,
                chat_id=chat_id,
                user_id=user_id,
                text=message.text,
                forced_provider_id=None,
            )
        except YunBotError as err:
            await message.reply(
                err.user_message,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        await _handle_assemble_outcome(
            message,
            res,
            chat_id=chat_id,
            user_id=user_id,
            is_group=False,
        )

    @router.callback_query(F.data.startswith("tp:"))
    async def handle_panel_callback(callback: types.CallbackQuery) -> None:
        parsed = decode_panel_callback(callback.data)
        if parsed is None:
            await callback.answer("无效的操作请求。")
            return

        task = await storage.get_task(parsed.task_id)
        if task is None:
            await callback.answer("该任务记录已不存在。")
            await _clear_callback_markup(callback)
            return

        operator_id = callback.from_user.id
        if not access.can_manage_task(operator_id, task.user_id):
            await callback.answer(
                format_error_message(ErrorCode.UNAUTHORIZED_PANEL_ACTION),
                show_alert=True,
            )
            return

        provider_name = _resolve_provider_name(registry, task.provider)

        if parsed.action == PanelAction.SHARE:
            if task.no_subdir or task.status not in SHAREABLE_TASK_STATUSES:
                err_code = (
                    ErrorCode.TASK_BUSY
                    if task.status in IN_FLIGHT_TASK_STATUSES
                    else ErrorCode.OPENLIST_UNAVAILABLE
                )
                await callback.answer(format_error_message(err_code), show_alert=True)
                return

            try:
                share_res = await openlist.create_or_get_task_share(task.task_id)
            except YunBotError as err:
                await callback.answer(err.user_message[:200], show_alert=True)
                return
            except Exception:
                LOGGER.exception("Unexpected error creating share for task %s", task.task_id)
                await callback.answer(
                    format_error_message(ErrorCode.OPENLIST_UNAVAILABLE),
                    show_alert=True,
                )
                return

            share_url = share_res.share_url if hasattr(share_res, "share_url") else str(share_res)
            expires_at = getattr(share_res, "expires_at", None)
            if isinstance(expires_at, (int, float)) and expires_at > 0:
                exp_str = datetime.fromtimestamp(expires_at, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
                reply_text = f"🔗 OpenList 免密分享链接：\n{share_url}\n⏱️ 过期时间：{exp_str}"
            else:
                reply_text = f"🔗 OpenList 免密分享链接：\n{share_url}"

            msg = callback.message
            if isinstance(msg, types.Message) and msg.bot is not None:
                await msg.reply(
                    reply_text,
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
            elif msg is not None and callback.bot is not None:
                await callback.bot.send_message(
                    chat_id=msg.chat.id,
                    text=reply_text,
                    link_preview_options=LinkPreviewOptions(is_disabled=True),
                )
            await callback.answer("已返回分享链接")
            return

        if parsed.action == PanelAction.DELIVER:
            if callback.message is None:
                await callback.answer("无法定位当前会话。")
                return
            notify_chat_id = callback.message.chat.id
            try:
                dl_res = await _call_enqueue_delivery(
                    delivery,
                    task.task_id,
                    operator_id=operator_id,
                    notify_chat_id=notify_chat_id,
                )
            except YunBotError as err:
                await callback.answer(err.user_message[:200], show_alert=True)
                return
            except Exception:
                LOGGER.exception("Unexpected error enqueuing delivery for %s", task.task_id)
                await callback.answer(
                    format_error_message(ErrorCode.INTERNAL_ERROR, task_id=task.task_id)[:200],
                    show_alert=True,
                )
                return

            refreshed = await storage.get_task(task.task_id)
            if refreshed is not None:
                await _safe_edit_callback_panel(
                    callback,
                    render_task_panel_text(refreshed, provider_name),
                    build_task_panel_keyboard(refreshed, confirm_delete=False),
                )

            ahead = (
                dl_res
                if isinstance(dl_res, int) and not isinstance(dl_res, bool)
                else getattr(dl_res, "ahead", None)
            )
            if isinstance(ahead, int) and ahead > 0:
                await callback.answer(f"📤 已加入发送队列（前方排队 {ahead} 项）")
            else:
                await callback.answer("📤 已加入媒体发送队列")
            return

        if parsed.action == PanelAction.REMOVE:
            if task.status in IN_FLIGHT_TASK_STATUSES:
                await callback.answer(
                    format_error_message(ErrorCode.TASK_BUSY),
                    show_alert=True,
                )
                return
            confirm_notice = (
                "⚠️ 二次确认：此操作将连带删除本任务归属的云端转存文件并撤销关联分享，是否确认继续？"
            )
            await _safe_edit_callback_panel(
                callback,
                render_task_panel_text(
                    task,
                    provider_name,
                    extra_notice=confirm_notice,
                ),
                build_task_panel_keyboard(task, confirm_delete=True),
            )
            await callback.answer("请再次确认连带删除")
            return

        if parsed.action == PanelAction.REMOVE_CANCEL:
            await _safe_edit_callback_panel(
                callback,
                render_task_panel_text(task, provider_name),
                build_task_panel_keyboard(task, confirm_delete=False),
            )
            await callback.answer("已取消删除")
            return

        if parsed.action == PanelAction.REMOVE_CONFIRM:
            if task.status in IN_FLIGHT_TASK_STATUSES:
                await callback.answer(
                    format_error_message(ErrorCode.TASK_BUSY),
                    show_alert=True,
                )
                return

            try:
                del_result = await _call_delete_task(
                    deletion_service,
                    task.task_id,
                    operator_id,
                )
            except YunBotError as err:
                latest = await storage.get_task(task.task_id)
                if latest is not None:
                    await _safe_edit_callback_panel(
                        callback,
                        render_task_panel_text(latest, provider_name),
                        build_task_panel_keyboard(latest, confirm_delete=False),
                    )
                await callback.answer(err.user_message[:200], show_alert=True)
                return
            except Exception:
                LOGGER.exception("Unexpected error deleting task %s", task.task_id)
                await callback.answer(
                    format_error_message(ErrorCode.INTERNAL_ERROR, task_id=task.task_id)[:200],
                    show_alert=True,
                )
                return

            after_task = await storage.get_task(task.task_id)
            outcome_text = format_deletion_outcome_text(
                task,
                del_result,
                after_task,
                provider_name,
            )
            if after_task is not None:
                await _safe_edit_callback_panel(
                    callback,
                    render_task_panel_text(
                        after_task,
                        provider_name,
                        extra_notice=outcome_text,
                    ),
                    build_task_panel_keyboard(after_task, confirm_delete=False),
                )
                await callback.answer(outcome_text[:200], show_alert=True)
            else:
                await _safe_edit_callback_panel(callback, outcome_text, None)
                await callback.answer("已处理删除请求")
            return

        if parsed.action == PanelAction.DONE:
            update_fn = getattr(storage, "update_task_fields", None)
            if callable(update_fn):
                await update_fn(task.task_id, panel_closed=True)
            else:
                close_fn = getattr(storage, "close_task_panel", None)
                if callable(close_fn):
                    await close_fn(task.task_id)
            await _clear_callback_markup(callback)
            await callback.answer("已关闭操作面板")
            return

    return router
