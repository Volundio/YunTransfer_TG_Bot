"""Telegram media delivery engine: atomic queue & per-user quota admission,
streaming temp-file download orchestration, preview-first `Path.as_uri()` zero-copy upload,
and post-delivery mutex OpenList share fallback (§5.9, R03, R06, R07).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, runtime_checkable

from yunbot.models import (
    ALLOWED_IMAGE_EXTS,
    DELIVERY_QUEUE_MAXSIZE,
    DELIVERY_WORKERS,
    IN_FLIGHT_TASK_STATUSES,
    MAX_ACTIVE_DELIVERIES_PER_USER,
    SHAREABLE_TASK_STATUSES,
    TG_LOCAL_UPLOAD_TIMEOUT_SECONDS,
    TG_PHOTO_SAFE_LIMIT_BYTES,
    TG_PHOTO_UPLOAD_TIMEOUT_SECONDS,
    TG_UPLOAD_SAFE_LIMIT_BYTES,
    BindingMismatchError,
    BootstrapConfigSnapshot,
    ErrorCode,
    FileTooLargeForTelegramError,
    OpenListUnavailableError,
    ProbeMediaFile,
    ProbeResult,
    ShareLinkResult,
    TaskRecord,
    TempDiskFullError,
    YunBotError,
    await_cleanup_uninterruptibly,
    chunk_telegram_text,
    format_error_message,
    redact_sensitive_text,
    sanitize_upload_filename,
)
from yunbot.services.coordinator import (
    PanelUpdateCallback,
    TransferCoordinator,
    resolve_runtime_snapshot,
)

LOGGER = logging.getLogger(__name__)

_STREAMING_VIDEO_EXTS: frozenset[str] = frozenset({".mp4", ".m4v", ".mov"})
_STATIC_PHOTO_EXTS: frozenset[str] = ALLOWED_IMAGE_EXTS - frozenset({".gif"})


# ==============================================================================
# Collaborator Protocols (§4.1, §5.9)
# ==============================================================================


@runtime_checkable
class TelegramMediaSender(Protocol):
    """Telegram media & text sender compatible with both `aiogram.Bot` and offline test fakes.

    All media methods MUST receive a `file://` URI string (`Path.as_uri()`), NEVER `FSInputFile`.
    """

    async def send_video(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
        supports_streaming: bool = True,
    ) -> Any: ...

    async def send_animation(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
    ) -> Any: ...

    async def send_photo(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
    ) -> Any: ...

    async def send_document(
        self,
        chat_id: int,
        uri: str,
        /,
        *,
        caption: str | None = None,
    ) -> Any: ...

    async def send_message(self, chat_id: int, text: str, /) -> Any: ...


@runtime_checkable
class DeliveryStorage(Protocol):
    """Persistence contract required by DeliveryService."""

    async def get_task(self, task_id: str) -> TaskRecord | None: ...

    async def enter_delivering(self, task_id: str) -> TaskRecord | None: ...

    async def restore_from_delivering(self, task_id: str) -> TaskRecord | None: ...


@runtime_checkable
class DeliveryOpenListClient(Protocol):
    """OpenList contract required by DeliveryService."""

    async def verify_task_bindings(self, task: TaskRecord) -> bool | None: ...

    async def probe_task_media(self, task: TaskRecord) -> ProbeResult: ...

    async def download_media_to_temp(
        self,
        task: TaskRecord,
        openlist_path: str,
        local_path: Path,
        *,
        current_temp_bytes_getter: Callable[[], int],
    ) -> int: ...

    async def create_or_get_task_share(self, task_id: str) -> ShareLinkResult: ...


def _accepts_kwarg(fn: Callable[..., Any], kwarg_name: str) -> bool:
    """Return True if callable `fn` accepts `kwarg_name` explicitly or via `**kwargs`."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    for param in sig.parameters.values():
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            return True
        if param.name == kwarg_name and param.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return True
    return False


@dataclass(slots=True)
class _DeliveryJob:
    task_id: str
    user_id: int
    notify_chat_id: int
    cleaned_up: bool = False


class DeliveryService:
    """Bounded zero-copy Telegram media delivery engine with post-delivery share fallback."""

    def __init__(
        self,
        *,
        storage: DeliveryStorage,
        coordinator: TransferCoordinator,
        openlist: DeliveryOpenListClient | None,
        sender: TelegramMediaSender,
        runtime_config: Any = None,
        bootstrap: BootstrapConfigSnapshot | None = None,
        admin_id: int | None = None,
        upload_dir: str | Path | None = None,
        on_panel_update: PanelUpdateCallback | None = None,
        queue_maxsize: int = DELIVERY_QUEUE_MAXSIZE,
        worker_count: int = DELIVERY_WORKERS,
        max_active_per_user: int = MAX_ACTIVE_DELIVERIES_PER_USER,
    ) -> None:
        resolved_admin = (
            admin_id
            if admin_id is not None
            else (bootstrap.telegram_admin_id if bootstrap is not None else None)
        )
        if resolved_admin is None or resolved_admin <= 0:
            raise ValueError("admin_id or bootstrap.telegram_admin_id (> 0) is required")

        raw_upload_dir = (
            upload_dir
            if upload_dir is not None
            else (bootstrap.shared_upload_dir if bootstrap is not None else None)
        )
        if raw_upload_dir is None:
            raise ValueError("upload_dir or bootstrap.shared_upload_dir is required")

        if queue_maxsize <= 0:
            raise ValueError("queue_maxsize must be positive")
        if worker_count <= 0:
            raise ValueError("worker_count must be positive")
        if max_active_per_user <= 0:
            raise ValueError("max_active_per_user must be positive")

        self._storage = storage
        self._coordinator = coordinator
        self._openlist = openlist
        self._sender = sender
        self._runtime_config = runtime_config
        self._admin_id = resolved_admin
        self._upload_dir = Path(raw_upload_dir)
        self._on_panel_update = on_panel_update

        self._queue_maxsize = queue_maxsize
        self._worker_count = worker_count
        self._max_active_per_user = max_active_per_user

        self._admission_lock = threading.Lock()
        self._reserved_total: int = 0
        self._active_by_user: dict[int, int] = {}
        self._queue: asyncio.Queue[_DeliveryJob] = asyncio.Queue(maxsize=queue_maxsize)
        self._active_temp_files: set[str] = set()
        self._workers: list[asyncio.Task[None]] = []
        self._closed = False

        self._video_has_timeout = _accepts_kwarg(sender.send_video, "request_timeout")
        self._anim_has_timeout = _accepts_kwarg(sender.send_animation, "request_timeout")
        self._photo_has_timeout = _accepts_kwarg(sender.send_photo, "request_timeout")
        self._doc_has_timeout = _accepts_kwarg(sender.send_document, "request_timeout")

    @property
    def reserved_total(self) -> int:
        with self._admission_lock:
            return self._reserved_total

    def active_count_for_user(self, user_id: int) -> int:
        with self._admission_lock:
            return self._active_by_user.get(user_id, 0)

    def active_temp_filenames(self) -> frozenset[str]:
        return frozenset(self._active_temp_files)

    def set_openlist(self, openlist: DeliveryOpenListClient | None) -> None:
        self._openlist = openlist

    def set_callbacks(self, *, on_panel_update: PanelUpdateCallback | None = None) -> None:
        if on_panel_update is not None:
            self._on_panel_update = on_panel_update

    async def start(self) -> None:
        self._upload_dir.mkdir(parents=True, exist_ok=True)
        if any(not w.done() for w in self._workers):
            return
        with self._admission_lock:
            self._closed = False
        self._workers = [
            asyncio.create_task(self._worker_loop(i), name=f"yunbot-delivery-worker-{i}")
            for i in range(self._worker_count)
        ]

    async def stop(self) -> None:
        with self._admission_lock:
            self._closed = True
        workers = self._workers
        self._workers = []
        for w in workers:
            if not w.done():
                w.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        # Drain any unstarted queued jobs and restore their DB state & quotas cleanly
        while not self._queue.empty():
            try:
                job = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            try:
                await self._finalize_job_state(job)
            finally:
                self._queue.task_done()

    def _release_quota(self, user_id: int) -> None:
        with self._admission_lock:
            if self._reserved_total > 0:
                self._reserved_total -= 1
            cur = self._active_by_user.get(user_id, 0)
            if cur <= 1:
                self._active_by_user.pop(user_id, None)
            else:
                self._active_by_user[user_id] = cur - 1

    async def _restore_task_after_delivery(self, task_id: str) -> TaskRecord | None:
        async with self._coordinator.acquire_task_lock(task_id):
            res = await self._storage.restore_from_delivering(task_id)
            if isinstance(res, TaskRecord):
                return res
            return await self._storage.get_task(task_id)

    async def _finalize_job_state(self, job: _DeliveryJob) -> TaskRecord | None:
        if job.cleaned_up:
            return None
        restored: TaskRecord | None = None
        try:
            restored = await await_cleanup_uninterruptibly(
                self._restore_task_after_delivery(job.task_id)
            )
        except BaseException:
            if isinstance(sys.exc_info()[1], asyncio.CancelledError):
                raise
            LOGGER.error(
                "Failed to restore task from delivering task=%s",
                job.task_id,
            )
        finally:
            if not job.cleaned_up:
                job.cleaned_up = True
                self._release_quota(job.user_id)
        return restored

    def _ensure_openlist_enabled(self, task: TaskRecord) -> DeliveryOpenListClient:
        if self._openlist is None or not task.openlist_binding_id or not task.openlist_base_path:
            raise OpenListUnavailableError()
        if self._runtime_config is not None:
            snap = resolve_runtime_snapshot(self._runtime_config)
            if not snap.openlist_base_url.strip():
                raise OpenListUnavailableError()
        is_enabled_attr = getattr(self._openlist, "is_enabled", None)
        if is_enabled_attr is not None:
            enabled = is_enabled_attr() if callable(is_enabled_attr) else bool(is_enabled_attr)
            if not enabled:
                raise OpenListUnavailableError()
        return self._openlist

    async def enqueue_delivery(
        self,
        task_id: str,
        *,
        operator_id: int,
        notify_chat_id: int,
    ) -> int:
        """Atomically reserve queue + per-`task.user_id` quota, transition DB to `delivering`,
        and enqueue job. Returns `ahead` count of deliveries ahead of this job.
        """
        if self._closed:
            raise YunBotError(ErrorCode.QUEUE_FULL)

        task = await self._storage.get_task(task_id)
        if task is None:
            raise YunBotError(ErrorCode.INTERNAL_ERROR, task_id=task_id)
        if operator_id != task.user_id and operator_id != self._admin_id:
            raise YunBotError(ErrorCode.UNAUTHORIZED_PANEL_ACTION)

        openlist = self._ensure_openlist_enabled(task)
        verified = await openlist.verify_task_bindings(task)
        if verified is False:
            raise BindingMismatchError()

        target_user_id = task.user_id
        with self._admission_lock:
            if self._closed or self._reserved_total >= self._queue_maxsize:
                raise YunBotError(ErrorCode.QUEUE_FULL)
            if self._active_by_user.get(target_user_id, 0) >= self._max_active_per_user:
                raise YunBotError(ErrorCode.USER_DELIVERY_EXISTS)
            ahead = self._reserved_total
            self._reserved_total += 1
            self._active_by_user[target_user_id] = self._active_by_user.get(target_user_id, 0) + 1

        db_entered_delivering = False
        enqueued = False
        delivering_task: TaskRecord | None = None
        try:
            async with self._coordinator.acquire_task_lock(task_id):
                fresh = await self._storage.get_task(task_id)
                if fresh is None:
                    raise YunBotError(ErrorCode.INTERNAL_ERROR, task_id=task_id)
                if fresh.status in IN_FLIGHT_TASK_STATUSES:
                    raise YunBotError(ErrorCode.TASK_BUSY)
                if fresh.status not in SHAREABLE_TASK_STATUSES or not fresh.tg_send_eligible:
                    raise OpenListUnavailableError()
                entered = await self._storage.enter_delivering(task_id)
                db_entered_delivering = True
                delivering_task = (
                    entered
                    if isinstance(entered, TaskRecord)
                    else await self._storage.get_task(task_id)
                )

            with self._admission_lock:
                if self._closed:
                    raise YunBotError(ErrorCode.QUEUE_FULL)
                job = _DeliveryJob(
                    task_id=task_id,
                    user_id=target_user_id,
                    notify_chat_id=notify_chat_id,
                )
                self._queue.put_nowait(job)
                enqueued = True
        except BaseException:
            if not enqueued:
                try:
                    if db_entered_delivering:
                        await await_cleanup_uninterruptibly(
                            self._restore_task_after_delivery(task_id)
                        )
                except BaseException:
                    if not isinstance(sys.exc_info()[1], asyncio.CancelledError):
                        LOGGER.error(
                            "Failed to rollback delivering state on enqueue error task=%s",
                            task_id,
                        )
                finally:
                    self._release_quota(target_user_id)
            raise

        if delivering_task is not None and self._on_panel_update is not None:
            try:
                await self._on_panel_update(delivering_task)
            except Exception as exc:
                LOGGER.warning(
                    "Panel update after enter_delivering failed task=%s err=%s",
                    task_id,
                    redact_sensitive_text(str(exc)),
                )

        return ahead

    async def _worker_loop(self, _worker_idx: int) -> None:
        while not self._closed:
            job = await self._queue.get()
            try:
                await self._process_delivery_job(job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.error(
                    "Unhandled delivery worker error task=%s err=%s",
                    job.task_id,
                    redact_sensitive_text(str(exc)),
                )
            finally:
                try:
                    if not job.cleaned_up:
                        await self._finalize_job_state(job)
                finally:
                    self._queue.task_done()

    def _compute_temp_dir_bytes(self, *, exclude: Path | None = None) -> int:
        if not self._upload_dir.exists():
            return 0
        total = 0
        exclude_name = exclude.name if exclude is not None else None
        try:
            with os.scandir(self._upload_dir) as it:
                for entry in it:
                    if exclude_name is not None and entry.name == exclude_name:
                        continue
                    try:
                        if entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except FileNotFoundError:
                        continue
        except OSError:
            return 0
        return total

    async def _call_download_media(
        self,
        openlist: DeliveryOpenListClient,
        task: TaskRecord,
        openlist_path: str,
        local_path: Path,
    ) -> int:
        fn = openlist.download_media_to_temp
        getter = lambda: self._compute_temp_dir_bytes(exclude=local_path)  # noqa: E731
        if _accepts_kwarg(fn, "current_temp_bytes_getter"):
            return await fn(
                task,
                openlist_path,
                local_path,
                current_temp_bytes_getter=getter,
            )
        return await fn(task, openlist_path, local_path)  # type: ignore[call-arg]

    async def _send_video(self, chat_id: int, uri: str, *, caption: str | None) -> None:
        if self._video_has_timeout:
            await self._sender.send_video(  # type: ignore[call-arg]
                chat_id,
                uri,
                caption=caption,
                supports_streaming=True,
                request_timeout=int(TG_LOCAL_UPLOAD_TIMEOUT_SECONDS),
            )
        else:
            await self._sender.send_video(
                chat_id,
                uri,
                caption=caption,
                supports_streaming=True,
            )

    async def _send_animation(self, chat_id: int, uri: str, *, caption: str | None) -> None:
        if self._anim_has_timeout:
            await self._sender.send_animation(  # type: ignore[call-arg]
                chat_id,
                uri,
                caption=caption,
                request_timeout=int(TG_LOCAL_UPLOAD_TIMEOUT_SECONDS),
            )
        else:
            await self._sender.send_animation(chat_id, uri, caption=caption)

    async def _send_photo(self, chat_id: int, uri: str, *, caption: str | None) -> None:
        if self._photo_has_timeout:
            await self._sender.send_photo(  # type: ignore[call-arg]
                chat_id,
                uri,
                caption=caption,
                request_timeout=int(TG_PHOTO_UPLOAD_TIMEOUT_SECONDS),
            )
        else:
            await self._sender.send_photo(chat_id, uri, caption=caption)

    async def _send_document(self, chat_id: int, uri: str, *, caption: str | None) -> None:
        if self._doc_has_timeout:
            await self._sender.send_document(  # type: ignore[call-arg]
                chat_id,
                uri,
                caption=caption,
                request_timeout=int(TG_LOCAL_UPLOAD_TIMEOUT_SECONDS),
            )
        else:
            await self._sender.send_document(chat_id, uri, caption=caption)

    async def _upload_local_media(
        self,
        *,
        chat_id: int,
        local_path: Path,
        media: ProbeMediaFile,
        actual_size: int,
    ) -> None:
        uri = local_path.as_uri()
        if not uri.startswith("file://"):
            raise ValueError("Media upload URI must strictly use file:// scheme")

        ext = (media.ext or PurePosixPath(media.name).suffix).lower()
        caption = media.name[:1024] if media.name else None

        if ext in _STREAMING_VIDEO_EXTS:
            try:
                await self._send_video(chat_id, uri, caption=caption)
                return
            except Exception as exc:
                LOGGER.info(
                    "send_video preview rejected, falling back to send_document err=%s",
                    redact_sensitive_text(str(exc)),
                )
                await self._send_document(chat_id, uri, caption=caption)
                return

        if ext == ".gif":
            try:
                await self._send_animation(chat_id, uri, caption=caption)
                return
            except Exception as exc:
                LOGGER.info(
                    "send_animation preview rejected, falling back to send_document err=%s",
                    redact_sensitive_text(str(exc)),
                )
                await self._send_document(chat_id, uri, caption=caption)
                return

        if ext in _STATIC_PHOTO_EXTS and actual_size <= TG_PHOTO_SAFE_LIMIT_BYTES:
            try:
                await self._send_photo(chat_id, uri, caption=caption)
                return
            except Exception as exc:
                LOGGER.info(
                    "send_photo preview rejected, falling back to send_document err=%s",
                    redact_sensitive_text(str(exc)),
                )
                await self._send_document(chat_id, uri, caption=caption)
                return

        await self._send_document(chat_id, uri, caption=caption)

    async def _safe_send_text(self, chat_id: int, text: str) -> None:
        if not text:
            return
        for chunk in chunk_telegram_text(text):
            try:
                await self._sender.send_message(chat_id, chunk)
            except Exception as exc:
                LOGGER.warning(
                    "Failed to send delivery notice chat_id=%s err=%s",
                    chat_id,
                    redact_sensitive_text(str(exc)),
                )
                return

    async def _process_delivery_job(self, job: _DeliveryJob) -> None:
        task: TaskRecord | None = None
        restored_task: TaskRecord | None = None
        need_share_fallback = False
        skipped_notices: list[str] = []

        try:
            task = await self._storage.get_task(job.task_id)
            if task is None:
                return

            self._upload_dir.mkdir(parents=True, exist_ok=True)
            openlist = self._ensure_openlist_enabled(task)
            probe = await openlist.probe_task_media(task)
            if not probe.eligible or not probe.media_files:
                if not task.no_subdir:
                    need_share_fallback = True
                skipped_notices.append(format_error_message(ErrorCode.OPENLIST_UNAVAILABLE))
            else:
                for idx, media in enumerate(probe.media_files):
                    safe_name = sanitize_upload_filename(media.name)
                    local_path = self._upload_dir / f"{job.task_id}_{idx}_{safe_name}"
                    self._active_temp_files.add(local_path.name)
                    try:
                        size = await self._call_download_media(
                            openlist,
                            task,
                            media.openlist_path,
                            local_path,
                        )
                        if size > TG_UPLOAD_SAFE_LIMIT_BYTES:
                            raise FileTooLargeForTelegramError(media.name)
                        await self._upload_local_media(
                            chat_id=job.notify_chat_id,
                            local_path=local_path,
                            media=media,
                            actual_size=size,
                        )
                    except (
                        FileTooLargeForTelegramError,
                        TempDiskFullError,
                        OpenListUnavailableError,
                    ) as exc:
                        # R03: NEVER create OpenList share while status == 'delivering'!
                        if not task.no_subdir:
                            need_share_fallback = True
                        skipped_notices.append(exc.user_message)
                    except Exception as exc:
                        LOGGER.warning(
                            "Media upload failed task=%s file=%s err=%s",
                            job.task_id,
                            safe_name,
                            redact_sensitive_text(str(exc)),
                        )
                        if not task.no_subdir:
                            need_share_fallback = True
                        skipped_notices.append(
                            format_error_message(ErrorCode.INTERNAL_ERROR, task_id=job.task_id)
                        )
                    finally:
                        local_path.unlink(missing_ok=True)
                        self._active_temp_files.discard(local_path.name)
        except YunBotError as exc:
            if task is not None and not task.no_subdir:
                need_share_fallback = True
            skipped_notices.append(exc.user_message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOGGER.error(
                "Delivery failed with unexpected error task=%s err=%s",
                job.task_id,
                redact_sensitive_text(str(exc)),
            )
            if task is not None and not task.no_subdir:
                need_share_fallback = True
            skipped_notices.append(
                format_error_message(ErrorCode.INTERNAL_ERROR, task_id=job.task_id)
            )
        finally:
            restored_task = await self._finalize_job_state(job)

        if restored_task is not None and self._on_panel_update is not None:
            try:
                await self._on_panel_update(restored_task)
            except Exception:
                pass

        # R03: Post-delivery mutex share fallback AFTER restoring `delivery_prev_status`
        if (
            task is not None
            and not task.no_subdir
            and need_share_fallback
            and restored_task is not None
            and self._openlist is not None
        ):
            try:
                share_res = await self._openlist.create_or_get_task_share(job.task_id)
                skipped_notices.append(f"🔗 OpenList 目录分享链接：\n{share_res.share_url}")
            except Exception as exc:
                LOGGER.warning(
                    "Post-delivery OpenList share fallback failed task=%s err=%s",
                    job.task_id,
                    redact_sensitive_text(str(exc)),
                )
                skipped_notices.append(format_error_message(ErrorCode.OPENLIST_UNAVAILABLE))

        if skipped_notices:
            await self._safe_send_text(job.notify_chat_id, "\n".join(skipped_notices))
