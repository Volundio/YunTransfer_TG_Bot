"""Telegram interaction layer (`handlers/`) public router factories and panel utilities."""

from __future__ import annotations

from yunbot.handlers.admin import GROUP_WEB_REJECT_MESSAGE, build_admin_router
from yunbot.handlers.keyboards import (
    MAX_CALLBACK_DATA_BYTES,
    STATUS_BADGES,
    PanelAction,
    PanelCallbackData,
    TasksAction,
    TasksCallbackData,
    build_task_panel_keyboard,
    build_tasks_detail_keyboard,
    build_tasks_list_keyboard,
    decode_panel_callback,
    decode_tasks_callback,
    encode_panel_callback,
    encode_tasks_item_callback,
    encode_tasks_page_callback,
    ensure_callback_data_limit,
    format_deletion_outcome_text,
    render_task_panel_text,
)
from yunbot.handlers.tasks import TASKS_PAGE_SIZE, build_tasks_router
from yunbot.handlers.transfer import (
    AssembleAction,
    AssembleResult,
    TelegramPanelSynchronizer,
    build_transfer_router,
)

__all__ = [
    "AssembleAction",
    "AssembleResult",
    "GROUP_WEB_REJECT_MESSAGE",
    "MAX_CALLBACK_DATA_BYTES",
    "PanelAction",
    "PanelCallbackData",
    "STATUS_BADGES",
    "TASKS_PAGE_SIZE",
    "TasksAction",
    "TasksCallbackData",
    "TelegramPanelSynchronizer",
    "build_admin_router",
    "build_task_panel_keyboard",
    "build_tasks_detail_keyboard",
    "build_tasks_list_keyboard",
    "build_tasks_router",
    "build_transfer_router",
    "decode_panel_callback",
    "decode_tasks_callback",
    "encode_panel_callback",
    "encode_tasks_item_callback",
    "encode_tasks_page_callback",
    "ensure_callback_data_limit",
    "format_deletion_outcome_text",
    "render_task_panel_text",
]
