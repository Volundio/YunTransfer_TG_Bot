"""Administrator `/web` command router issuing single-use OTT login URLs.

Strictly adheres to DEVELOPMENT.md §2.2, §5.2.1, and AGENTS.md §2.7, §5.1.
Never logs OTT values or full login URLs.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from aiogram import Bot, Router, types
from aiogram.filters import Filter
from aiogram.types import LinkPreviewOptions

from yunbot.models import WEB_OTT_TTL_SECONDS, ErrorCode, format_error_message

GROUP_WEB_REJECT_MESSAGE: str = (
    "⚠️ 为保护管理后台安全，请在与机器人的私聊中发送 /web 获取一次性登录链接。"
)


async def _mention_matches_bot(mention: str | None, bot: Bot | Any | None) -> bool:
    if not mention:
        return True
    if bot is None:
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


class _WebCommandFilter(Filter):
    """Match `/web` and `/web@BotUsername` safely offline and online."""

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
        if cmd_name.lower() != "web":
            return False
        return await _mention_matches_bot(mention, bot)


def build_admin_router(
    *,
    admin_id: int,
    web_base_url: str,
    issue_ott: Callable[[], str],
) -> Router:
    """Create aiogram Router handling `/web` OTT issuance exclusively in admin private chat."""
    router = Router(name="admin")
    normalized_base = web_base_url.rstrip("/")

    @router.message(_WebCommandFilter())
    async def handle_web_command(message: types.Message) -> None:
        if message.from_user is None or message.from_user.id != admin_id:
            uid: int | str = message.from_user.id if message.from_user is not None else "未知"
            await message.reply(
                format_error_message(ErrorCode.ACCESS_DENIED, user_id=uid),
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        if message.chat.type != "private":
            await message.reply(
                GROUP_WEB_REJECT_MESSAGE,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return

        ott_or_coro = issue_ott()
        ott: str = await ott_or_coro if inspect.isawaitable(ott_or_coro) else str(ott_or_coro)
        url = f"{normalized_base}/login#token={ott}"
        ttl_minutes = max(1, WEB_OTT_TTL_SECONDS // 60)
        reply_text = (
            "🔐 管理后台一次性登录链接（单次有效，请勿转发或截图）：\n"
            f"{url}\n\n"
            f"⏱️ 有效期 {ttl_minutes} 分钟，打开后将自动消费销毁。"
        )
        await message.reply(
            reply_text,
            link_preview_options=LinkPreviewOptions(is_disabled=True),
        )

    return router
