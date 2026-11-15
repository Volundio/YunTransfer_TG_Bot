"""`/tasks` transfer history pagination, inspection, and verified deletion router.

Strictly adheres to DEVELOPMENT.md §1.1.4, §5.10.2, and AGENTS.md §4.1, §5.1.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from aiogram import Bot, F, Router, types
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Filter
from aiogram.types import InlineKeyboardMarkup, LinkPreviewOptions

from yunbot.handlers.keyboards import (
    STATUS_BADGES,
    TasksAction,
    build_tasks_detail_keyboard,
    build_tasks_list_keyboard,
    decode_tasks_callback,
    format_deletion_outcome_text,
    render_task_panel_text,
)
from yunbot.models import (
    IN_FLIGHT_TASK_STATUSES,
    TG_MESSAGE_CHUNK_CHARS,
    ErrorCode,
    TaskRecord,
    YunBotError,
    chunk_telegram_text,
    format_error_message,
    redact_sensitive_text,
)
from yunbot.providers.registry import ProviderRegistry

LOGGER = logging.getLogger(__name__)
TASKS_PAGE_SIZE: int = 5


@runtime_checkable
class TasksStorageProtocol(Protocol):
    """Duck-typed storage interface required by `/tasks` handlers."""

    async def get_task(self, task_id: str) -> TaskRecord | None: ...

    async def list_tasks(
        self,
        *,
        user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> Sequence[TaskRecord]: ...


@runtime_checkable
class TasksAccessProtocol(Protocol):
    """Duck-typed access policy interface required by `/tasks` handlers."""

    async def check_access(self, user_id: int, chat_id: int, *args: Any, **kwargs: Any) -> bool: ...

    def can_manage_task(self, operator_id: int, task_user_id: int) -> bool: ...


@runtime_checkable
class TaskDeletionProtocol(Protocol):
    """Duck-typed cloud + DB task deletion service interface."""

    async def delete_task_with_cloud_files(
        self,
        task_id: str,
        *,
        operator_id: int,
    ) -> Any: ...


def _is_admin_user(access: Any, user_id: int) -> bool:
    is_admin_fn = getattr(access, "is_admin", None)
    if callable(is_admin_fn):
        return bool(is_admin_fn(user_id))
    admin_id = getattr(access, "admin_id", None)
    if isinstance(admin_id, int):
        return user_id == admin_id
    can_manage = getattr(access, "can_manage_task", None)
    if callable(can_manage):
        return bool(can_manage(user_id, 0))
    return False


async def _invoke_check_access(
    access: Any,
    *,
    user_id: int,
    chat_id: int,
    chat_type: str,
) -> tuple[bool, str | None]:
    """Call `access.check_access(...)` supporting flexible signatures and YunBotError."""
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

    if hasattr(decision, "allowed"):
        allowed = bool(decision.allowed)
    else:
        allowed = bool(decision)
    if not allowed:
        return False, format_error_message(ErrorCode.ACCESS_DENIED, user_id=user_id)
    return True, None


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


def _resolve_provider_name(registry: ProviderRegistry, provider_id: str) -> str:
    provider = registry.find(provider_id)
    if provider is not None:
        return provider.spec.display_name
    return provider_id


async def _fetch_tasks_page(
    storage: Any,
    *,
    user_id: int | None,
    offset: int,
    page_size: int = TASKS_PAGE_SIZE,
) -> tuple[list[TaskRecord], bool, int | None]:
    """Fetch one page of tasks, returning `(items, has_next, total_count)`."""
    fn = storage.list_tasks
    sig = inspect.signature(fn)
    params = sig.parameters
    has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

    query_limit = page_size + 1
    kwargs: dict[str, Any] = {}
    if "user_id" in params or has_var_kw:
        kwargs["user_id"] = user_id
    if "limit" in params or has_var_kw:
        kwargs["limit"] = query_limit
    if "offset" in params or has_var_kw:
        kwargs["offset"] = offset

    raw = await fn(**kwargs) if kwargs else await fn(user_id, query_limit, offset)

    total: int | None = None
    if (
        isinstance(raw, tuple)
        and len(raw) == 2
        and isinstance(raw[1], int)
        and not isinstance(raw[0], TaskRecord)
    ):
        seq = list(raw[0])
        total = raw[1]
        items = seq[:page_size]
        has_next = (offset + len(items)) < total
        return items, has_next, total

    seq = list(raw)
    has_next = len(seq) > page_size
    items = seq[:page_size]

    count_fn = getattr(storage, "count_tasks", None)
    if callable(count_fn):
        try:
            count_sig = inspect.signature(count_fn)
            if "user_id" in count_sig.parameters or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in count_sig.parameters.values()
            ):
                c_res = count_fn(user_id=user_id)
            else:
                c_res = count_fn(user_id)
            total = int(await c_res if inspect.isawaitable(c_res) else c_res)
        except Exception:
            total = None

    return items, has_next, total


def _render_tasks_list_text(
    tasks: Sequence[TaskRecord],
    *,
    registry: ProviderRegistry,
    is_admin: bool,
    offset: int,
    total: int | None,
) -> str:
    header_scope = "全局转存任务列表（管理员视图）" if is_admin else "我的转存任务列表"
    if not tasks:
        return f"📋 {header_scope}\n\n暂无历史转存任务记录。"

    count_hint = (
        f"（共 {total} 条，当前第 {offset + 1}~{offset + len(tasks)} 条）"
        if total is not None
        else f"（第 {offset + 1}~{offset + len(tasks)} 条）"
    )
    lines: list[str] = [f"📋 {header_scope}{count_hint}", ""]

    for idx, task in enumerate(tasks, start=offset + 1):
        provider_name = _resolve_provider_name(registry, task.provider)
        title = redact_sensitive_text((task.share_title or "").strip()) or "未命名分享"
        badge = STATUS_BADGES.get(task.status, str(task.status))
        mode_tag = "-n直存" if task.no_subdir else "子目录"
        ts_str = datetime.fromtimestamp(task.created_at, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
        owner_part = f" | 用户: {task.user_id}" if is_admin else ""
        uncertain_part = " | ⚠️待对账" if task.transfer_uncertain else ""
        lines.append(
            f"{idx}. [{provider_name} · {mode_tag}] {title}\n"
            f"   ID: {task.task_id} | {badge} | {task.item_count} 项{owner_part}{uncertain_part}\n"
            f"   创建: {ts_str}"
        )

    lines.append("\n点击下方任务按钮查看详情或执行连带删除：")
    return "\n".join(lines)


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


class _TasksCommandFilter(Filter):
    """Match `/tasks` and `/tasks@BotUsername`."""

    async def __call__(
        self,
        message: types.Message,
        bot: Bot | None = None,
    ) -> bool:
        text = message.text
        if not text:
            return False
        stripped = text.lstrip()
        if not stripped.startswith("/"):
            return False
        first_token = stripped.split(maxsplit=1)[0]
        body = first_token[1:]
        if "@" in body:
            cmd_name, _, mention = body.partition("@")
            if not mention:
                return False
        else:
            cmd_name, mention = body, None
        if cmd_name.lower() != "tasks":
            return False
        return await _mention_matches_bot(mention, bot)


async def _safe_edit_callback_message(
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


def build_tasks_router(
    *,
    storage: Any,
    access: Any,
    registry: ProviderRegistry,
    deletion_service: Any,
) -> Router:
    """Create aiogram Router for `/tasks` pagination, inspection, and verified deletion."""
    router = Router(name="tasks")

    @router.message(_TasksCommandFilter())
    async def handle_tasks_command(message: types.Message) -> None:
        if message.from_user is None:
            await message.reply(
                format_error_message(ErrorCode.ACCESS_DENIED, user_id="未知"),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        operator_id = message.from_user.id
        allowed, deny_msg = await _invoke_check_access(
            access,
            user_id=operator_id,
            chat_id=message.chat.id,
            chat_type=message.chat.type,
        )
        if not allowed:
            await message.reply(
                deny_msg or format_error_message(ErrorCode.ACCESS_DENIED, user_id=operator_id),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        is_admin = _is_admin_user(access, operator_id)
        filter_uid = None if is_admin else operator_id
        tasks, has_next, total = await _fetch_tasks_page(
            storage,
            user_id=filter_uid,
            offset=0,
            page_size=TASKS_PAGE_SIZE,
        )
        text = _render_tasks_list_text(
            tasks,
            registry=registry,
            is_admin=is_admin,
            offset=0,
            total=total,
        )
        kb = build_tasks_list_keyboard(
            tasks,
            offset=0,
            page_size=TASKS_PAGE_SIZE,
            has_next=has_next,
        )
        chunks = chunk_telegram_text(text, max_chars=TG_MESSAGE_CHUNK_CHARS)
        for chunk in chunks[:-1]:
            await message.reply(
                chunk,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        await message.reply(
            chunks[-1],
            reply_markup=kb,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )

    @router.callback_query(F.data.startswith("tk:"))
    async def handle_tasks_callback(callback: types.CallbackQuery) -> None:
        parsed = decode_tasks_callback(callback.data)
        if parsed is None:
            await callback.answer("无效的任务操作请求。")
            return

        operator_id = callback.from_user.id
        is_admin = _is_admin_user(access, operator_id)

        if parsed.action == TasksAction.PAGE:
            msg = callback.message
            if isinstance(msg, types.Message) and msg.reply_to_message is not None:
                origin_user = msg.reply_to_message.from_user
                if origin_user is not None and not access.can_manage_task(
                    operator_id, origin_user.id
                ):
                    await callback.answer(
                        format_error_message(ErrorCode.UNAUTHORIZED_PANEL_ACTION),
                        show_alert=True,
                    )
                    return

            chat_id = msg.chat.id if msg is not None else operator_id
            chat_type = msg.chat.type if msg is not None else "private"
            allowed, _ = await _invoke_check_access(
                access,
                user_id=operator_id,
                chat_id=chat_id,
                chat_type=chat_type,
            )
            if not allowed:
                await callback.answer(
                    format_error_message(ErrorCode.UNAUTHORIZED_PANEL_ACTION),
                    show_alert=True,
                )
                return

            filter_uid = None if is_admin else operator_id
            offset = parsed.offset
            tasks, has_next, total = await _fetch_tasks_page(
                storage,
                user_id=filter_uid,
                offset=offset,
                page_size=TASKS_PAGE_SIZE,
            )
            if not tasks and offset > 0:
                offset = max(0, offset - TASKS_PAGE_SIZE)
                tasks, has_next, total = await _fetch_tasks_page(
                    storage,
                    user_id=filter_uid,
                    offset=offset,
                    page_size=TASKS_PAGE_SIZE,
                )

            text = _render_tasks_list_text(
                tasks,
                registry=registry,
                is_admin=is_admin,
                offset=offset,
                total=total,
            )
            kb = build_tasks_list_keyboard(
                tasks,
                offset=offset,
                page_size=TASKS_PAGE_SIZE,
                has_next=has_next,
            )
            await _safe_edit_callback_message(callback, text, kb)
            await callback.answer()
            return

        assert parsed.task_id is not None
        task = await storage.get_task(parsed.task_id)
        if task is None:
            await callback.answer("该任务记录已不存在。", show_alert=True)
            await _safe_edit_callback_message(
                callback,
                "ℹ️ 该任务记录已不存在或已被清理。",
                build_tasks_detail_keyboard(None, offset=parsed.offset),
            )
            return

        if not access.can_manage_task(operator_id, task.user_id):
            await callback.answer(
                format_error_message(ErrorCode.UNAUTHORIZED_PANEL_ACTION),
                show_alert=True,
            )
            return

        provider_name = _resolve_provider_name(registry, task.provider)
        owner_uid = task.user_id if is_admin else None

        if parsed.action == TasksAction.VIEW:
            detail_text = render_task_panel_text(
                task,
                provider_name,
                owner_user_id=owner_uid,
            )
            detail_kb = build_tasks_detail_keyboard(
                task,
                offset=parsed.offset,
                confirm_delete=False,
            )
            await _safe_edit_callback_message(callback, detail_text, detail_kb)
            await callback.answer()
            return

        if parsed.action == TasksAction.REMOVE:
            if task.status in IN_FLIGHT_TASK_STATUSES:
                await callback.answer(
                    format_error_message(ErrorCode.TASK_BUSY),
                    show_alert=True,
                )
                return
            warn_notice = (
                "⚠️ 二次确认：此操作将连带删除本任务归属的云端转存文件并撤销关联分享，是否确认继续？"
            )
            detail_text = render_task_panel_text(
                task,
                provider_name,
                owner_user_id=owner_uid,
                extra_notice=warn_notice,
            )
            detail_kb = build_tasks_detail_keyboard(
                task,
                offset=parsed.offset,
                confirm_delete=True,
            )
            await _safe_edit_callback_message(callback, detail_text, detail_kb)
            await callback.answer("请确认是否执行连带删除")
            return

        if parsed.action == TasksAction.REMOVE_CONFIRM:
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
                    await _safe_edit_callback_message(
                        callback,
                        render_task_panel_text(
                            latest,
                            provider_name,
                            owner_user_id=owner_uid,
                        ),
                        build_tasks_detail_keyboard(
                            latest,
                            offset=parsed.offset,
                            confirm_delete=False,
                        ),
                    )
                await callback.answer(err.user_message[:200], show_alert=True)
                return
            except Exception:
                LOGGER.exception("Unexpected error deleting task %s", task.task_id)
                err_msg = format_error_message(
                    ErrorCode.INTERNAL_ERROR,
                    task_id=task.task_id,
                )
                await callback.answer(err_msg[:200], show_alert=True)
                return

            after_task = await storage.get_task(task.task_id)
            outcome_text = format_deletion_outcome_text(
                task,
                del_result,
                after_task,
                provider_name,
            )
            if after_task is not None:
                rendered = render_task_panel_text(
                    after_task,
                    provider_name,
                    owner_user_id=owner_uid,
                    extra_notice=outcome_text,
                )
                await _safe_edit_callback_message(
                    callback,
                    rendered,
                    build_tasks_detail_keyboard(
                        after_task,
                        offset=parsed.offset,
                        confirm_delete=False,
                    ),
                )
                await callback.answer(outcome_text[:200], show_alert=True)
            else:
                await _safe_edit_callback_message(
                    callback,
                    outcome_text,
                    build_tasks_detail_keyboard(None, offset=parsed.offset),
                )
                await callback.answer("已处理删除请求")

    return router
