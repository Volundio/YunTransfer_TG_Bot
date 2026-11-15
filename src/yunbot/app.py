"""Composition Root: single-event-loop service wiring and 4-step graceful shutdown (§2.3, §4.1).

Strict Shutdown Sequence (AGENTS.md §2.1, DEVELOPMENT.md §4.1):
1. Stop Telegram polling and built-in Admin Web server (`aiohttp.web`).
2. Stop Janitor and cancel/reap in-flight Transfer/Delivery workers, CLI subprocesses,
   and residual temporary upload files.
3. Close singleton business `aiohttp.ClientSession` and Telegram `Bot` HTTP session.
4. Execute `PRAGMA wal_checkpoint(PASSIVE)` and close `SQLiteStorage`.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import os
import shutil
import time
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any

import aiohttp
from aiogram import Bot, Dispatcher
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.exceptions import TelegramAPIError
from aiogram.types import BotCommand, LinkPreviewOptions

from yunbot.config.runtime import RuntimeConfig
from yunbot.domain.access import AccessController
from yunbot.domain.assembler import InputAssembler
from yunbot.domain.membership import GroupMembershipProber
from yunbot.domain.parsing import BaiduShareRecognizer, PikPakShareRecognizer, QuarkShareRecognizer
from yunbot.handlers.admin import build_admin_router
from yunbot.handlers.tasks import build_tasks_router
from yunbot.handlers.transfer import TelegramPanelSynchronizer, build_transfer_router
from yunbot.models import (
    TG_API_STARTUP_BACKOFF_SECONDS,
    TG_API_STARTUP_MAX_WAIT_SECONDS,
    TG_LOCAL_UPLOAD_TIMEOUT_SECONDS,
    TG_PHOTO_UPLOAD_TIMEOUT_SECONDS,
    BootstrapConfigSnapshot,
    redact_sensitive_text,
)
from yunbot.providers.baidu import BaiduProvider
from yunbot.providers.pikpak_cli import PikPakCliProvider
from yunbot.providers.quark import QuarkProvider
from yunbot.providers.registry import ProviderRegistry
from yunbot.services.coordinator import TaskDeletionService, TransferCoordinator
from yunbot.services.delivery import DeliveryService
from yunbot.services.janitor import Janitor
from yunbot.services.openlist import OpenListClient
from yunbot.storage import SQLiteStorage
from yunbot.web.server import WebServer

LOGGER = logging.getLogger(__name__)

ALLOWED_POLLING_UPDATES: tuple[str, ...] = ("message", "callback_query")


def _safe_mkdir(path: Path, *, mode: int | None = None) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if mode is not None:
        with contextlib.suppress(OSError):
            os.chmod(path, mode)


def _purge_directory_contents(directory: Path) -> int:
    """Remove residual files/subdirectories inside `directory` without removing `directory`."""
    if not directory.exists():
        return 0
    removed = 0
    for child in list(directory.iterdir()):
        try:
            if child.is_symlink() or child.is_file():
                child.unlink(missing_ok=True)
                removed += 1
            elif child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed


class _BotMediaSenderAdapter:
    """Adapts `aiogram.Bot` to `TelegramMediaSender` strictly using `file://` URI strings."""

    def __init__(self, bot: Any) -> None:
        self._bot = bot
        self._msg_accepts_preview = self._has_kwarg(bot.send_message, "link_preview_options")
        self._video_accepts_timeout = self._has_kwarg(bot.send_video, "request_timeout")
        self._anim_accepts_timeout = self._has_kwarg(bot.send_animation, "request_timeout")
        self._photo_accepts_timeout = self._has_kwarg(bot.send_photo, "request_timeout")
        self._doc_accepts_timeout = self._has_kwarg(bot.send_document, "request_timeout")

    @staticmethod
    def _has_kwarg(fn: Callable[..., Any], kwarg: str) -> bool:
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            return False
        for param in sig.parameters.values():
            if param.kind == inspect.Parameter.VAR_KEYWORD:
                return True
            if param.name == kwarg and param.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            ):
                return True
        return False

    async def send_video(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
        supports_streaming: bool = True,
        request_timeout: int = int(TG_LOCAL_UPLOAD_TIMEOUT_SECONDS),
    ) -> Any:
        kwargs: dict[str, Any] = {
            "caption": caption,
            "supports_streaming": supports_streaming,
        }
        if self._video_accepts_timeout:
            kwargs["request_timeout"] = request_timeout
        return await self._bot.send_video(chat_id, uri, **kwargs)

    async def send_animation(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
        request_timeout: int = int(TG_LOCAL_UPLOAD_TIMEOUT_SECONDS),
    ) -> Any:
        kwargs: dict[str, Any] = {"caption": caption}
        if self._anim_accepts_timeout:
            kwargs["request_timeout"] = request_timeout
        return await self._bot.send_animation(chat_id, uri, **kwargs)

    async def send_photo(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
        request_timeout: int = int(TG_PHOTO_UPLOAD_TIMEOUT_SECONDS),
    ) -> Any:
        kwargs: dict[str, Any] = {"caption": caption}
        if self._photo_accepts_timeout:
            kwargs["request_timeout"] = request_timeout
        return await self._bot.send_photo(chat_id, uri, **kwargs)

    async def send_document(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
        request_timeout: int = int(TG_LOCAL_UPLOAD_TIMEOUT_SECONDS),
    ) -> Any:
        kwargs: dict[str, Any] = {"caption": caption}
        if self._doc_accepts_timeout:
            kwargs["request_timeout"] = request_timeout
        return await self._bot.send_document(chat_id, uri, **kwargs)

    async def send_message(self, chat_id: int, text: str, /) -> Any:
        if self._msg_accepts_preview:
            return await self._bot.send_message(
                chat_id,
                text,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
        return await self._bot.send_message(chat_id, text)


async def _probe_group_member(bot: Any, chat_id: int, user_id: int) -> bool:
    """Return True iff `user_id` is currently a member of group `chat_id` via Bot API."""
    try:
        member = await bot.get_chat_member(chat_id=chat_id, user_id=user_id)
    except TelegramAPIError as exc:
        LOGGER.debug(
            "get_chat_member returned non-member or inaccessible group chat=%s user=%s err=%s",
            chat_id,
            user_id,
            redact_sensitive_text(str(exc)),
        )
        return False
    except Exception as exc:
        LOGGER.warning(
            "Unexpected error probing group membership chat=%s user=%s err=%s",
            chat_id,
            user_id,
            redact_sensitive_text(str(exc)),
        )
        return False

    raw_status = getattr(member, "status", "")
    status = str(getattr(raw_status, "value", raw_status) or "").lower()
    if status in ("creator", "administrator", "member"):
        return True
    if status == "restricted":
        return bool(getattr(member, "is_member", False))
    return False


class Application:
    """Single-process Composition Root managing all services and 4-step graceful shutdown."""

    def __init__(
        self,
        bootstrap: BootstrapConfigSnapshot,
        *,
        bot: Bot | Any | None = None,
        business_session: aiohttp.ClientSession | None = None,
        pikpak_binary_path: str = "/usr/local/bin/pikpak",
        web_bind_host: str = "0.0.0.0",
        web_port_override: int | None = None,
        startup_max_wait_seconds: float = TG_API_STARTUP_MAX_WAIT_SECONDS,
        startup_backoff_seconds: Sequence[float] = TG_API_STARTUP_BACKOFF_SECONDS,
        sleep_func: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic_func: Callable[[], float] = time.monotonic,
    ) -> None:
        self.bootstrap = bootstrap
        self._injected_bot = bot
        self._injected_business_session = business_session
        self._pikpak_binary_path = pikpak_binary_path
        self._web_bind_host = web_bind_host
        self._web_port_override = web_port_override
        self._startup_max_wait = float(startup_max_wait_seconds)
        self._startup_backoff = tuple(float(d) for d in startup_backoff_seconds) or (1.0,)
        self._sleep = sleep_func
        self._monotonic = monotonic_func

        self.storage: SQLiteStorage | None = None
        self.runtime_config: RuntimeConfig | None = None
        self.business_session: aiohttp.ClientSession | None = None
        self.bot: Bot | Any | None = None
        self.registry: ProviderRegistry | None = None
        self.coordinator: TransferCoordinator | None = None
        self.openlist: OpenListClient | None = None
        self.deletion_service: TaskDeletionService | None = None
        self.membership: GroupMembershipProber | None = None
        self.access: AccessController | None = None
        self.assembler: InputAssembler | None = None
        self.panel_sync: TelegramPanelSynchronizer | None = None
        self.delivery_service: DeliveryService | None = None
        self.web_server: WebServer | None = None
        self.janitor: Janitor | None = None
        self.dispatcher: Dispatcher | None = None

        self._polling_task: asyncio.Task[None] | None = None
        self._polling_active = False
        self._started = False
        self._stopping = False

    async def wait_for_bot_api_ready(self) -> Any:
        """Probe local `telegram-bot-api` via `get_me()` with bounded exponential backoff."""
        if self.bot is None:
            raise RuntimeError("Bot is not initialized")

        deadline = self._monotonic() + self._startup_max_wait
        attempt = 0
        last_error: Exception | None = None

        while True:
            try:
                me = await self.bot.get_me()
                with contextlib.suppress(AttributeError, TypeError):
                    self.bot._me = me
                LOGGER.info(
                    "Connected to local Telegram Bot API (@%s)",
                    getattr(me, "username", "bot"),
                )
                return me
            except Exception as exc:
                last_error = exc
                now = self._monotonic()
                remaining = deadline - now
                if remaining <= 0:
                    safe_err = redact_sensitive_text(str(last_error))
                    raise RuntimeError(
                        f"Timed out waiting {self._startup_max_wait:.1f}s "
                        f"for Telegram Bot API readiness: {safe_err}"
                    ) from last_error

                backoff_idx = min(attempt, len(self._startup_backoff) - 1)
                delay = min(self._startup_backoff[backoff_idx], remaining)
                LOGGER.warning(
                    "Telegram Bot API not ready yet (attempt=%d, retry_in=%.1fs): %s",
                    attempt + 1,
                    delay,
                    redact_sensitive_text(str(exc)),
                )
                attempt += 1
                await self._sleep(delay)

    async def _seed_initial_provider_credentials(
        self,
        *,
        pikpak_provider: PikPakCliProvider,
        quark_provider: QuarkProvider,
    ) -> None:
        """Best-effort seed initial `QUARK_COOKIE` / `PIKPAK_PAT` only when DB is empty."""
        assert self.storage is not None

        if self.bootstrap.quark_cookie.strip():
            existing_quark = await self.storage.get_credential("quark")
            if existing_quark is None:
                try:
                    await quark_provider.seed_initial_cookie_if_empty(self.bootstrap.quark_cookie)
                except Exception as exc:
                    LOGGER.warning(
                        "Initial QUARK_COOKIE verification skipped on startup: %s",
                        redact_sensitive_text(str(exc)),
                    )

        if self.bootstrap.pikpak_pat.strip():
            existing_pikpak = await self.storage.get_credential("pikpak")
            if existing_pikpak is None:
                try:
                    await pikpak_provider.seed_initial_pat_if_empty(self.bootstrap.pikpak_pat)
                except Exception as exc:
                    LOGGER.warning(
                        "Initial PIKPAK_PAT verification skipped on startup: %s",
                        redact_sensitive_text(str(exc)),
                    )

    async def _register_bot_commands(self) -> None:
        if self.bot is None or self.registry is None:
            return
        set_cmds = getattr(self.bot, "set_my_commands", None)
        if not callable(set_cmds):
            return
        commands: list[BotCommand] = [
            BotCommand(command="start", description="查看使用说明与支持的网盘命令"),
            BotCommand(command="help", description="查看转存与 -n 直存帮助"),
        ]
        for spec in self.registry.all_specs():
            cmd = spec.command.lstrip("/").lower()
            commands.append(
                BotCommand(
                    command=cmd,
                    description=f"转存{spec.display_name}分享链接（支持 -n 直存）",
                )
            )
        commands.append(BotCommand(command="tasks", description="查看历史转存任务与连带删除"))
        commands.append(BotCommand(command="web", description="管理员私聊获取后台登录链接"))
        try:
            await set_cmds(commands)
        except Exception as exc:
            LOGGER.warning(
                "Skipping BotCommand menu registration: %s",
                redact_sensitive_text(str(exc)),
            )

    async def start(
        self,
        *,
        enable_polling: bool = True,
        seed_initial_credentials: bool = True,
    ) -> None:
        """Initialize storage, config, HTTP sessions, providers, workers, Web, and polling."""
        if self._started:
            return

        data_dir = Path(self.bootstrap.data_dir)
        pikpak_dir = data_dir / "pikpak"
        upload_dir = Path(self.bootstrap.shared_upload_dir)

        try:
            _safe_mkdir(data_dir, mode=0o700)
            _safe_mkdir(pikpak_dir, mode=0o700)
            _safe_mkdir(upload_dir)

            # 1. SQLite WAL + migrations + upload temp wipe + exact crash recovery (§5.10.1)
            self.storage = SQLiteStorage(data_dir / "bot.db")
            recovered = await self.storage.initialize(upload_temp_dir=upload_dir)
            LOGGER.info("SQLite WAL initialized (crash_recovery=%s)", recovered)

            # 2. Dynamic runtime configuration & initial access list seeding (§3.3)
            self.runtime_config = RuntimeConfig(self.bootstrap, self.storage)
            await self.runtime_config.initialize()

            # 3. Dual isolated HTTP sessions (§2.3):
            #    - Singleton business ClientSession with DummyCookieJar (zero shared cookies)
            #    - Dedicated aiogram Bot session connected to local telegram-bot-api
            if self._injected_business_session is not None:
                self.business_session = self._injected_business_session
            else:
                self.business_session = aiohttp.ClientSession(
                    cookie_jar=aiohttp.DummyCookieJar(),
                )

            if self._injected_bot is not None:
                self.bot = self._injected_bot
            else:
                api_server = TelegramAPIServer.from_base(
                    self.bootstrap.telegram_api_base_url,
                    is_local=True,
                )
                tg_session = AiohttpSession(
                    api=api_server,
                    timeout=TG_LOCAL_UPLOAD_TIMEOUT_SECONDS,
                )
                self.bot = Bot(
                    token=self.bootstrap.telegram_bot_token,
                    session=tg_session,
                )

            # 4. Cloud Providers & Registry (§5.5~§5.7)
            baidu_provider = BaiduProvider(
                session=self.business_session,
                credential_store=self.storage,
                config_reader=self.runtime_config,
                recognizer=BaiduShareRecognizer(),
            )
            pikpak_provider = PikPakCliProvider(
                credential_store=self.storage,
                snapshot_store=self.storage,
                config_reader=self.runtime_config,
                pikpak_dir=pikpak_dir,
                binary_path=self._pikpak_binary_path,
                recognizer=PikPakShareRecognizer(),
            )
            quark_provider = QuarkProvider(
                session=self.business_session,
                credential_store=self.storage,
                config_reader=self.runtime_config,
                recognizer=QuarkShareRecognizer(),
            )

            self.registry = ProviderRegistry()
            self.registry.register(baidu_provider)
            self.registry.register(pikpak_provider)
            self.registry.register(quark_provider)

            if seed_initial_credentials:
                await self._seed_initial_provider_credentials(
                    pikpak_provider=pikpak_provider,
                    quark_provider=quark_provider,
                )

            # 5. Coordinator, OpenList, Deletion, Access, Assembler & Delivery (§5.1~§5.10)
            self.coordinator = TransferCoordinator(
                storage=self.storage,
                registry=self.registry,
                runtime_config=self.runtime_config,
                bootstrap=self.bootstrap,
            )

            runtime_cfg = self.runtime_config
            self.openlist = OpenListClient(
                session=self.business_session,
                settings_getter=runtime_cfg.snapshot,
                storage=self.storage,
                task_lock_factory=self.coordinator.acquire_task_lock,
                binding_builder=lambda pid, sig: runtime_cfg.build_openlist_binding_id(
                    pid,
                    storage_signature=sig,
                ),
            )
            self.coordinator.set_openlist(self.openlist)

            self.deletion_service = TaskDeletionService(
                storage=self.storage,
                registry=self.registry,
                coordinator=self.coordinator,
                runtime_config=self.runtime_config,
                openlist=self.openlist,
                bootstrap=self.bootstrap,
            )

            bot_ref = self.bot
            self.membership = GroupMembershipProber(
                probe_member=lambda chat_id, user_id: _probe_group_member(
                    bot_ref,
                    chat_id,
                    user_id,
                ),
            )
            self.access = AccessController(
                self.storage,
                self.runtime_config,
                self.membership,
                admin_id=self.bootstrap.telegram_admin_id,
            )
            self.assembler = InputAssembler(
                self.storage,
                self.runtime_config,
                self.registry,
            )

            self.panel_sync = TelegramPanelSynchronizer(
                bot=self.bot,
                storage=self.storage,
                registry=self.registry,
                assembler=self.assembler,
            )
            self.coordinator.set_callbacks(
                on_panel_update=self.panel_sync.on_status_changed,
                on_need_password=self.panel_sync.on_need_password,
                on_progress_update=self.panel_sync.on_progress,
            )
            self.deletion_service.set_callbacks(
                on_panel_update=self.panel_sync.on_status_changed,
                on_task_deleted=self.panel_sync.on_deleted,
            )

            self.delivery_service = DeliveryService(
                storage=self.storage,
                coordinator=self.coordinator,
                openlist=self.openlist,
                sender=_BotMediaSenderAdapter(self.bot),
                runtime_config=self.runtime_config,
                bootstrap=self.bootstrap,
                on_panel_update=self.panel_sync.on_status_changed,
            )

            # 6. Admin Web Panel (`aiohttp.web`, §5.2) & Janitor (§5.10.3)
            self.web_server = WebServer(
                runtime_config=self.runtime_config,
                providers=self.registry,
                storage=self.storage,
                access=self.access,
                openlist=self.openlist,
                deletion_service=self.deletion_service,
                coordinator=self.coordinator,
                bootstrap=self.bootstrap,
            )
            self.janitor = Janitor(
                storage=self.storage,
                coordinator=self.coordinator,
                registry=self.registry,
                runtime_config=self.runtime_config,
                openlist=self.openlist,
                bootstrap=self.bootstrap,
                delivery=self.delivery_service,
                web_auth_cleanup=self.web_server.cleanup_expired,
                membership_cleanup=self.membership.prune_expired,
            )

            # 7. Telegram Dispatcher & Routers (§5.1, §5.2.1, §5.10.2)
            self.dispatcher = Dispatcher()
            self.dispatcher.include_router(
                build_admin_router(
                    admin_id=self.bootstrap.telegram_admin_id,
                    web_base_url=self.bootstrap.web_base_url,
                    issue_ott=self.web_server.issue_ott,
                )
            )
            self.dispatcher.include_router(
                build_tasks_router(
                    storage=self.storage,
                    access=self.access,
                    registry=self.registry,
                    deletion_service=self.deletion_service,
                )
            )
            self.dispatcher.include_router(
                build_transfer_router(
                    storage=self.storage,
                    access=self.access,
                    assembler=self.assembler,
                    registry=self.registry,
                    coordinator=self.coordinator,
                    delivery=self.delivery_service,
                    openlist=self.openlist,
                    deletion_service=self.deletion_service,
                )
            )

            # 8. Start background workers, janitor, Web server, and optional polling
            await self.coordinator.start()
            await self.delivery_service.start()
            await self.janitor.start()
            await self.web_server.start(
                host=self._web_bind_host,
                port=(
                    self.bootstrap.web_internal_port
                    if self._web_port_override is None
                    else self._web_port_override
                ),
            )

            if enable_polling:
                await self.wait_for_bot_api_ready()
                await self._register_bot_commands()
                self._polling_active = True
                self._polling_task = asyncio.create_task(
                    self._run_polling(),
                    name="yunbot-telegram-polling",
                )

            self._started = True
        except BaseException:
            await self.stop()
            raise

    async def _run_polling(self) -> None:
        assert self.dispatcher is not None and self.bot is not None
        try:
            await self.dispatcher.start_polling(
                self.bot,
                allowed_updates=list(ALLOWED_POLLING_UPDATES),
                handle_signals=False,
                close_bot_session=False,
            )
        finally:
            self._polling_active = False

    async def stop(self) -> None:
        """Execute strict 4-step graceful shutdown (§4.1, AGENTS.md §2.1)."""
        if self._stopping:
            return
        self._stopping = True

        try:
            # ------------------------------------------------------------------
            # Step 1: Stop Telegram polling and built-in Admin Web server
            # ------------------------------------------------------------------
            if self._polling_task is not None:
                if not self._polling_task.done() and self.dispatcher is not None:
                    with contextlib.suppress(RuntimeError):
                        await self.dispatcher.stop_polling()
                try:
                    await asyncio.wait_for(self._polling_task, timeout=10.0)
                except TimeoutError:
                    self._polling_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await self._polling_task
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    LOGGER.warning(
                        "Telegram polling exited with error during shutdown: %s",
                        redact_sensitive_text(str(exc)),
                    )
                self._polling_task = None
                self._polling_active = False

            if self.web_server is not None:
                try:
                    await self.web_server.stop()
                except Exception as exc:
                    LOGGER.warning(
                        "Admin Web server stop error: %s",
                        redact_sensitive_text(str(exc)),
                    )

            # ------------------------------------------------------------------
            # Step 2: Stop Janitor & reap in-flight workers, CLI PGIDs, temp files
            # ------------------------------------------------------------------
            if self.janitor is not None:
                try:
                    await self.janitor.stop()
                except Exception as exc:
                    LOGGER.warning(
                        "Janitor stop error: %s",
                        redact_sensitive_text(str(exc)),
                    )

            if self.coordinator is not None:
                try:
                    await self.coordinator.stop()
                except Exception as exc:
                    LOGGER.warning(
                        "Coordinator stop error: %s",
                        redact_sensitive_text(str(exc)),
                    )

            if self.delivery_service is not None:
                try:
                    await self.delivery_service.stop()
                except Exception as exc:
                    LOGGER.warning(
                        "DeliveryService stop error: %s",
                        redact_sensitive_text(str(exc)),
                    )

            if self.registry is not None:
                try:
                    await self.registry.close_all()
                except Exception as exc:
                    LOGGER.warning(
                        "ProviderRegistry close_all error: %s",
                        redact_sensitive_text(str(exc)),
                    )

            with contextlib.suppress(OSError):
                _purge_directory_contents(Path(self.bootstrap.shared_upload_dir))

            # ------------------------------------------------------------------
            # Step 3: Close business HTTP session and Telegram Bot HTTP session
            # ------------------------------------------------------------------
            if self.business_session is not None:
                try:
                    if not self.business_session.closed:
                        await self.business_session.close()
                except Exception as exc:
                    LOGGER.warning(
                        "Business HTTP session close error: %s",
                        redact_sensitive_text(str(exc)),
                    )

            if self.bot is not None:
                bot_session = getattr(self.bot, "session", None)
                close_fn = getattr(bot_session, "close", None)
                if callable(close_fn):
                    try:
                        res = close_fn()
                        if inspect.isawaitable(res):
                            await res
                    except Exception as exc:
                        LOGGER.warning(
                            "Bot HTTP session close error: %s",
                            redact_sensitive_text(str(exc)),
                        )

            # ------------------------------------------------------------------
            # Step 4: PRAGMA wal_checkpoint(PASSIVE) and close SQLiteStorage
            # ------------------------------------------------------------------
            if self.storage is not None:
                try:
                    await self.storage.checkpoint_and_close()
                except Exception as exc:
                    LOGGER.warning(
                        "SQLiteStorage checkpoint_and_close error: %s",
                        redact_sensitive_text(str(exc)),
                    )
        finally:
            self._started = False
            self._stopping = False

    async def run(self, *, stop_event: asyncio.Event | None = None) -> None:
        """Start full application and block until `stop_event` fires or polling exits."""
        ev = stop_event or asyncio.Event()
        await self.start(enable_polling=True)
        try:
            assert self._polling_task is not None
            stop_waiter = asyncio.create_task(ev.wait(), name="yunbot-stop-waiter")
            try:
                done, _ = await asyncio.wait(
                    {self._polling_task, stop_waiter},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if self._polling_task in done and not ev.is_set():
                    exc = self._polling_task.exception()
                    if exc is not None:
                        raise exc
            finally:
                if not stop_waiter.done():
                    stop_waiter.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await stop_waiter
        finally:
            await self.stop()
