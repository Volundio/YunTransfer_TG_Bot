"""Inline keyboard builders, status card rendering, and <= 64B callback_data codec.

Strictly adheres to DEVELOPMENT.md §1.1.3, §2.4, §5.10, and AGENTS.md §4~§5.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from yunbot.models import (
    DELETABLE_TASK_STATUSES,
    IN_FLIGHT_TASK_STATUSES,
    SHAREABLE_TASK_STATUSES,
    ErrorCode,
    TaskRecord,
    TaskStatus,
    format_error_message,
    redact_sensitive_text,
)

MAX_CALLBACK_DATA_BYTES: int = 64
MAX_PAGINATION_OFFSET: int = 999_999_999


class PanelAction(StrEnum):
    """Compact 2-char action codes for task panel callbacks (`tp:<act>:<task_id>`)."""

    SHARE = "sh"
    DELIVER = "dl"
    REMOVE = "rm"
    REMOVE_CONFIRM = "rc"
    REMOVE_CANCEL = "rx"
    DONE = "dn"


class TasksAction(StrEnum):
    """Compact 2-char action codes for /tasks history callbacks (`tk:<act>:...`)."""

    PAGE = "pg"
    VIEW = "vw"
    REMOVE = "rm"
    REMOVE_CONFIRM = "rc"


@dataclass(frozen=True, slots=True)
class PanelCallbackData:
    """Decoded `tp:<act>:<task_id>` payload."""

    action: PanelAction
    task_id: str


@dataclass(frozen=True, slots=True)
class TasksCallbackData:
    """Decoded `tk:*` payload."""

    action: TasksAction
    offset: int
    task_id: str | None = None


STATUS_BADGES: dict[TaskStatus, str] = {
    TaskStatus.QUEUED: "⏳ 排队等待中",
    TaskStatus.TRANSFERRING: "🔄 正在转存中",
    TaskStatus.READY: "✅ 转存已完成",
    TaskStatus.PARTIAL: "⚠️ 部分转存完成",
    TaskStatus.DELIVERING: "📤 正在通过 Telegram 发送媒体",
    TaskStatus.DELETING: "🗑️ 正在清理云端文件",
    TaskStatus.DELETE_FAILED: "⚠️ 云端删除未完全完成",
    TaskStatus.FAILED: "❌ 任务失败",
}


def ensure_callback_data_limit(cb: str) -> str:
    """Guarantee Telegram's 64-byte UTF-8 callback_data hard limit."""
    encoded_len = len(cb.encode("utf-8"))
    assert encoded_len <= MAX_CALLBACK_DATA_BYTES, (
        f"callback_data exceeds {MAX_CALLBACK_DATA_BYTES}B: {encoded_len}B"
    )
    if encoded_len > MAX_CALLBACK_DATA_BYTES:
        raise ValueError(f"callback_data exceeds {MAX_CALLBACK_DATA_BYTES} UTF-8 bytes")
    return cb


def _validate_task_id_token(task_id: str) -> str:
    cleaned = task_id.strip()
    if not cleaned or ":" in cleaned:
        raise ValueError("Invalid task_id for callback_data")
    return cleaned


def _clamp_offset(offset: int) -> int:
    if offset < 0:
        return 0
    if offset > MAX_PAGINATION_OFFSET:
        return MAX_PAGINATION_OFFSET
    return offset


def encode_panel_callback(action: PanelAction | str, task_id: str) -> str:
    """Encode `tp:<act>:<task_id>` ensuring <= 64 UTF-8 bytes (18B for 12-char hex ID)."""
    act = PanelAction(action)
    tid = _validate_task_id_token(task_id)
    cb = f"tp:{act.value}:{tid}"
    return ensure_callback_data_limit(cb)


def decode_panel_callback(data: str | None) -> PanelCallbackData | None:
    """Decode `tp:<act>:<task_id>` safely, returning None on malformed payloads."""
    if not data or len(data.encode("utf-8")) > MAX_CALLBACK_DATA_BYTES:
        return None
    parts = data.split(":")
    if len(parts) != 3 or parts[0] != "tp" or not parts[2]:
        return None
    try:
        act = PanelAction(parts[1])
    except ValueError:
        return None
    return PanelCallbackData(action=act, task_id=parts[2])


def encode_tasks_page_callback(offset: int) -> str:
    """Encode `tk:pg:<offset>` ensuring <= 64 UTF-8 bytes."""
    cb = f"tk:{TasksAction.PAGE.value}:{_clamp_offset(offset)}"
    return ensure_callback_data_limit(cb)


def encode_tasks_item_callback(
    action: TasksAction | str,
    task_id: str,
    offset: int,
) -> str:
    """Encode `tk:<vw|rm|rc>:<task_id>:<offset>` ensuring <= 64 UTF-8 bytes."""
    act = TasksAction(action)
    if act == TasksAction.PAGE:
        raise ValueError("Use encode_tasks_page_callback for PAGE action")
    tid = _validate_task_id_token(task_id)
    cb = f"tk:{act.value}:{tid}:{_clamp_offset(offset)}"
    return ensure_callback_data_limit(cb)


def decode_tasks_callback(data: str | None) -> TasksCallbackData | None:
    """Decode `tk:*` callback_data safely, returning None on malformed payloads."""
    if not data or len(data.encode("utf-8")) > MAX_CALLBACK_DATA_BYTES:
        return None
    parts = data.split(":")
    if len(parts) < 3 or parts[0] != "tk":
        return None
    try:
        act = TasksAction(parts[1])
    except ValueError:
        return None

    if act == TasksAction.PAGE:
        if len(parts) != 3 or not parts[2].isdigit():
            return None
        return TasksCallbackData(action=act, offset=_clamp_offset(int(parts[2])))

    if len(parts) != 4 or not parts[2] or not parts[3].isdigit():
        return None
    return TasksCallbackData(
        action=act,
        task_id=parts[2],
        offset=_clamp_offset(int(parts[3])),
    )


def build_task_panel_keyboard(
    task: TaskRecord,
    *,
    confirm_delete: bool = False,
) -> InlineKeyboardMarkup | None:
    """Build inline action buttons for a transfer task card (DEVELOPMENT.md §1.1.3).

    Returns None when the panel is closed or the task is in-flight (`queued`,
    `transferring`, `delivering`, `deleting`).
    """
    if task.panel_closed or task.status in IN_FLIGHT_TASK_STATUSES:
        return None

    tid = task.task_id
    if confirm_delete:
        return InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="⚠️ 确认连带删除",
                        callback_data=encode_panel_callback(PanelAction.REMOVE_CONFIRM, tid),
                    ),
                    InlineKeyboardButton(
                        text="↩️ 取消",
                        callback_data=encode_panel_callback(PanelAction.REMOVE_CANCEL, tid),
                    ),
                ]
            ]
        )

    if task.status in SHAREABLE_TASK_STATUSES:
        rows: list[list[InlineKeyboardButton]] = []
        if not task.no_subdir and task.openlist_binding_id is not None:
            rows.append(
                [
                    InlineKeyboardButton(
                        text="🔗 返回OpenList分享链接",
                        callback_data=encode_panel_callback(PanelAction.SHARE, tid),
                    )
                ]
            )
        if task.openlist_binding_id is not None and task.tg_send_eligible:
            rows.append(
                [
                    InlineKeyboardButton(
                        text="📤 通过Telegram直接发送",
                        callback_data=encode_panel_callback(PanelAction.DELIVER, tid),
                    )
                ]
            )
        rows.append(
            [
                InlineKeyboardButton(
                    text="🗑️ 删除本次转存",
                    callback_data=encode_panel_callback(PanelAction.REMOVE, tid),
                ),
                InlineKeyboardButton(
                    text="✅ 完成",
                    callback_data=encode_panel_callback(PanelAction.DONE, tid),
                ),
            ]
        )
        return InlineKeyboardMarkup(inline_keyboard=rows)

    if task.status in (TaskStatus.FAILED, TaskStatus.DELETE_FAILED):
        delete_label = "🗑️ 重试删除" if task.status == TaskStatus.DELETE_FAILED else "🗑️ 删除本次转存"
        return InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text=delete_label,
                        callback_data=encode_panel_callback(PanelAction.REMOVE, tid),
                    ),
                    InlineKeyboardButton(
                        text="✅ 完成",
                        callback_data=encode_panel_callback(PanelAction.DONE, tid),
                    ),
                ]
            ]
        )

    return None


def render_task_panel_text(
    task: TaskRecord,
    provider_name: str,
    *,
    owner_user_id: int | None = None,
    extra_notice: str | None = None,
) -> str:
    """Render user-safe, secret-redacted transfer status card text."""
    title = redact_sensitive_text((task.share_title or "").strip()) or "未命名分享"
    display_provider = redact_sensitive_text((provider_name or task.provider).strip())
    badge = STATUS_BADGES.get(task.status, str(task.status))

    if task.no_subdir:
        mode_desc = "-n 直接转存"
        target_path = task.base_save_path
    else:
        mode_desc = "独立子目录"
        target_path = task.task_dir_path or task.base_save_path

    lines: list[str] = [
        f"📦 分享名称：{title}",
        f"☁️ 目标网盘：{display_provider}",
        f"📁 转存模式：{mode_desc}",
        f"📂 保存路径：{redact_sensitive_text(target_path)}",
        f"📌 当前状态：{badge}",
        f"📊 已确认条目：{task.item_count} 项",
        f"🆔 任务编号：{task.task_id}",
    ]
    if owner_user_id is not None:
        lines.append(f"👤 发起用户：{owner_user_id}")

    if task.transfer_uncertain:
        lines.append(
            "⚠️ 待核查提示：转存在云端确认落库前曾发生中断，"
            "目标目录可能存在未登记残留文件（系统绝不自动重放不确定批次）。"
        )

    err_text = redact_sensitive_text((task.error_message or "").strip())
    if not err_text and task.error_code:
        try:
            code_enum = ErrorCode(task.error_code)
            err_text = format_error_message(
                code_enum,
                provider_name=display_provider,
                task_id=task.task_id,
            )
        except ValueError:
            err_text = ""

    if err_text:
        lines.append(f"💬 详情说明：{err_text}")

    if extra_notice:
        lines.append(redact_sensitive_text(extra_notice.strip()))

    if task.panel_closed:
        lines.append("✅ 操作面板已归档关闭")

    return "\n".join(lines)


def build_tasks_list_keyboard(
    tasks: Sequence[TaskRecord],
    *,
    offset: int,
    page_size: int,
    has_next: bool,
) -> InlineKeyboardMarkup | None:
    """Build `/tasks` list inline keyboard with per-task view buttons and pagination."""
    rows: list[list[InlineKeyboardButton]] = []
    safe_offset = _clamp_offset(offset)

    for task in tasks:
        short_title = redact_sensitive_text((task.share_title or "").strip()) or task.task_id
        if len(short_title) > 18:
            short_title = f"{short_title[:17]}…"
        status_icon = STATUS_BADGES.get(task.status, "📌").split(" ", 1)[0]
        btn_label = f"{status_icon} {short_title} ({task.task_id[:6]})"
        rows.append(
            [
                InlineKeyboardButton(
                    text=btn_label,
                    callback_data=encode_tasks_item_callback(
                        TasksAction.VIEW,
                        task.task_id,
                        safe_offset,
                    ),
                )
            ]
        )

    nav_row: list[InlineKeyboardButton] = []
    if safe_offset > 0:
        prev_offset = max(0, safe_offset - page_size)
        nav_row.append(
            InlineKeyboardButton(
                text="⬅️ 上一页",
                callback_data=encode_tasks_page_callback(prev_offset),
            )
        )
    if has_next:
        next_offset = _clamp_offset(safe_offset + page_size)
        nav_row.append(
            InlineKeyboardButton(
                text="下一页 ➡️",
                callback_data=encode_tasks_page_callback(next_offset),
            )
        )
    if nav_row:
        rows.append(nav_row)

    if not rows:
        return None
    return InlineKeyboardMarkup(inline_keyboard=rows)


def build_tasks_detail_keyboard(
    task: TaskRecord | None,
    *,
    offset: int,
    confirm_delete: bool = False,
) -> InlineKeyboardMarkup:
    """Build `/tasks` single-task detail or delete-confirmation keyboard."""
    safe_offset = _clamp_offset(offset)
    back_btn = InlineKeyboardButton(
        text="⬅️ 返回列表",
        callback_data=encode_tasks_page_callback(safe_offset),
    )

    if task is None:
        return InlineKeyboardMarkup(inline_keyboard=[[back_btn]])

    tid = task.task_id
    if confirm_delete and task.status in DELETABLE_TASK_STATUSES:
        return InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="⚠️ 确认连带删除",
                        callback_data=encode_tasks_item_callback(
                            TasksAction.REMOVE_CONFIRM,
                            tid,
                            safe_offset,
                        ),
                    ),
                    InlineKeyboardButton(
                        text="↩️ 取消",
                        callback_data=encode_tasks_item_callback(
                            TasksAction.VIEW,
                            tid,
                            safe_offset,
                        ),
                    ),
                ],
                [back_btn],
            ]
        )

    action_row: list[InlineKeyboardButton] = []
    if task.status in DELETABLE_TASK_STATUSES:
        del_label = "🗑️ 重试删除" if task.status == TaskStatus.DELETE_FAILED else "🗑️ 连带删除"
        action_row.append(
            InlineKeyboardButton(
                text=del_label,
                callback_data=encode_tasks_item_callback(
                    TasksAction.REMOVE,
                    tid,
                    safe_offset,
                ),
            )
        )
    else:
        action_row.append(
            InlineKeyboardButton(
                text="🔄 刷新状态",
                callback_data=encode_tasks_item_callback(
                    TasksAction.VIEW,
                    tid,
                    safe_offset,
                ),
            )
        )

    action_row.append(back_btn)
    return InlineKeyboardMarkup(inline_keyboard=[action_row])


def format_deletion_outcome_text(
    before_task: TaskRecord,
    result: Any,
    after_task: TaskRecord | None,
    provider_name: str,
) -> str:
    """Format accurate cloud + record deletion status (DEVELOPMENT.md §5.10.2).

    Strictly honors `DELETE_UNCERTAIN_EMPTY` (never lying that cloud files were cleaned
    when a -n task crashed before confirming items), `ITEM_SKIPPED`, and `DELETE_PARTIAL`.
    """
    title = redact_sensitive_text((before_task.share_title or "").strip()) or "未命名分享"
    display_provider = redact_sensitive_text((provider_name or before_task.provider).strip())

    raw_code = (
        getattr(result, "error_code", None)
        or getattr(result, "notice_code", None)
        or getattr(result, "code", None)
    )
    code_str = getattr(raw_code, "value", raw_code)
    failed_items = getattr(result, "failed_items", ()) or ()
    skipped_items = getattr(result, "skipped_items", ()) or ()
    deleted_ids = getattr(result, "deleted_ids", ()) or ()
    deleted_count = int(getattr(result, "deleted_count", 0) or len(deleted_ids))

    if (
        (after_task is not None and after_task.status == TaskStatus.DELETE_FAILED)
        or bool(failed_items)
        or code_str == ErrorCode.DELETE_PARTIAL.value
    ):
        remain_count = (
            len(failed_items)
            if failed_items
            else max(1, after_task.item_count if after_task is not None else 1)
        )
        partial_msg = format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=remain_count)
        if after_task is not None and after_task.error_message:
            err_detail = redact_sensitive_text(after_task.error_message.strip())
            if err_detail and err_detail != partial_msg:
                return f"{partial_msg}\n{err_detail}"
        return partial_msg

    is_uncertain_empty = (
        code_str == ErrorCode.DELETE_UNCERTAIN_EMPTY.value
        or bool(getattr(result, "uncertain_empty", False))
        or (
            before_task.no_subdir
            and before_task.transfer_uncertain
            and before_task.item_count == 0
            and deleted_count == 0
            and not skipped_items
        )
    )
    if is_uncertain_empty:
        return format_error_message(ErrorCode.DELETE_UNCERTAIN_EMPTY)

    lines: list[str] = [
        f"🗑️ 已删除任务「{title}」（{display_provider}）并清理已确认归属的云端文件。"
    ]

    if skipped_items:
        names = [
            redact_sensitive_text(str(getattr(item, "name", item)).strip())
            for item in skipped_items
        ]
        shown = "、".join(n for n in names[:10] if n)
        if len(names) > 10:
            shown = f"{shown} 等"
        lines.append(
            format_error_message(
                ErrorCode.ITEM_SKIPPED,
                skip_count=len(skipped_items),
                names=shown or "未知条目",
            )
        )
    elif code_str == ErrorCode.ITEM_SKIPPED.value:
        custom_msg = redact_sensitive_text(str(getattr(result, "message", "")).strip())
        lines.append(
            custom_msg or format_error_message(ErrorCode.ITEM_SKIPPED, skip_count=0, names="")
        )

    if before_task.transfer_uncertain:
        lines.append(
            "ℹ️ 注意：该任务曾标记转存中断不确定批次，建议顺带检查目标目录是否留有未登记残余文件。"
        )

    if isinstance(result, str) and result.strip():
        cleaned_res = redact_sensitive_text(result.strip())
        if cleaned_res not in lines:
            lines.append(cleaned_res)

    return "\n".join(lines)
