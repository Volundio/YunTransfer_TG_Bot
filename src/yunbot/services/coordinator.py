"""Pre-worker mode-admission transfer scheduler, ref-counted lock registry,
unified top-level directory lock coordinator, and dual-mode cloud deletion service (§5.4, §5.10).

Strict Global Lock Acquisition Order (R06):
`Scheduler/Admission short memory state` -> `task_id lock`
-> `(provider_id, account_binding_id, base_save_path) directory lock` -> `SQLite short transaction`.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from collections import Counter, OrderedDict, deque
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable
from zoneinfo import ZoneInfo

from yunbot.models import (
    DIR_LOCK_HARD_MAXSIZE,
    DIR_LOCK_IDLE_MAXSIZE,
    DIR_LOCK_WAIT_TIMEOUT_SECONDS,
    DIRECT_MODE_CONCURRENCY,
    IN_FLIGHT_TASK_STATUSES,
    MAX_TRANSFER_DURATION_SECONDS,
    TASK_LOCK_HARD_MAXSIZE,
    TASK_LOCK_IDLE_MAXSIZE,
    TG_PROGRESS_MIN_INTERVAL_SECONDS,
    TRANSFER_QUEUE_MAXSIZE,
    TRANSFER_WORKERS,
    BindingMismatchError,
    BootstrapConfigSnapshot,
    ErrorCode,
    OpenListUnavailableError,
    ProbeResult,
    ProviderAuthInvalidError,
    ProviderNeedPasswordError,
    RuntimeSettingsSnapshot,
    ShareLinkInfo,
    TaskRecord,
    TaskStatus,
    TransferItemRecord,
    TransferredEntry,
    YunBotError,
    await_cleanup_uninterruptibly,
    format_error_message,
    generate_task_id,
    normalize_posix_path,
    redact_sensitive_text,
    validate_direct_item_path,
    validate_save_path,
    validate_task_dir_path,
)
from yunbot.providers.registry import ProviderRegistry

LOGGER = logging.getLogger(__name__)

DirLockKey = tuple[str, str, str]
PanelUpdateCallback = Callable[[TaskRecord], Awaitable[Any]]
NeedPasswordCallback = Callable[..., Awaitable[Any]]
PanelProgressCallback = Callable[[TaskRecord, str, int, int], Awaitable[Any]]
TaskDeletedCallback = Callable[[TaskRecord, Any], Awaitable[Any]]


# ==============================================================================
# Collaborator Protocols (Duck-Typed Acyclic Boundaries, §4.1)
# ==============================================================================


@runtime_checkable
class CoordinatorStorage(Protocol):
    """Persistence operations required by TransferCoordinator and TaskDeletionService."""

    async def create_task(self, record: TaskRecord) -> Any: ...

    async def get_task(self, task_id: str) -> TaskRecord | None: ...

    async def update_task_fields(self, task_id: str, **fields: Any) -> Any: ...

    async def delete_task(self, task_id: str) -> Any: ...

    async def append_transfer_items_batch(
        self,
        task_id: str,
        batch: Sequence[TransferredEntry],
    ) -> int | None: ...

    async def list_transfer_items(self, task_id: str) -> Sequence[TransferItemRecord]: ...

    async def retain_only_failed_transfer_items(
        self,
        task_id: str,
        failed_item_ids: Sequence[str],
    ) -> Any: ...

    async def enter_deleting(self, task_id: str) -> TaskRecord | None: ...


@runtime_checkable
class CoordinatorOpenListClient(Protocol):
    """OpenList operations required by TransferCoordinator and TaskDeletionService."""

    async def resolve_openlist_binding_id(self, *args: Any, **kwargs: Any) -> str | None: ...

    async def probe_task_media(self, task: TaskRecord) -> ProbeResult: ...

    async def verify_task_bindings(self, task: TaskRecord) -> bool | None: ...

    async def revoke_share(self, share_id: str) -> Any: ...


def resolve_runtime_snapshot(runtime_config: Any) -> RuntimeSettingsSnapshot:
    """Extract RuntimeSettingsSnapshot from a RuntimeConfig service or snapshot value."""
    if isinstance(runtime_config, RuntimeSettingsSnapshot):
        return runtime_config
    snap_attr = getattr(runtime_config, "snapshot", None)
    if isinstance(snap_attr, RuntimeSettingsSnapshot):
        return snap_attr
    if callable(snap_attr):
        res = snap_attr()
        if isinstance(res, RuntimeSettingsSnapshot):
            return res
    get_snap = getattr(runtime_config, "get_snapshot", None)
    if callable(get_snap):
        res = get_snap()
        if isinstance(res, RuntimeSettingsSnapshot):
            return res
    raise TypeError(
        "Unsupported runtime_config; expected RuntimeSettingsSnapshot or object with .snapshot"
    )


async def update_task_fields(storage: Any, task_id: str, **fields: Any) -> Any:
    """Invoke storage task update using normalized primitive/enum values."""
    normalized: dict[str, Any] = {}
    for key, val in fields.items():
        if key == "error_code" and isinstance(val, StrEnum):
            normalized[key] = val.value
        else:
            normalized[key] = val

    update_fn = getattr(storage, "update_task_fields", None)
    if callable(update_fn):
        return await update_fn(task_id, **normalized)
    alt_fn = getattr(storage, "update_task", None)
    if callable(alt_fn):
        return await alt_fn(task_id, **normalized)
    raise AttributeError(
        "Storage object must provide update_task_fields(task_id, **fields) or update_task"
    )


async def _invoke_need_password(
    cb: NeedPasswordCallback,
    task: TaskRecord,
    share: ShareLinkInfo,
) -> None:
    """Invoke need-password callback whether `share` is positional or keyword-only."""
    sig = inspect.signature(cb)
    params = list(sig.parameters.values())
    has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
    has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
    pos_params = [
        p
        for p in params
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    kw_only_names = {p.name for p in params if p.kind == inspect.Parameter.KEYWORD_ONLY}

    if "share" in kw_only_names or (
        len(pos_params) == 1 and not has_varargs and ("share" in sig.parameters or has_varkw)
    ):
        await cb(task, share=share)
    else:
        await cb(task, share)


async def _invoke_flexible_binding_resolver(
    fn: Callable[..., Any],
    provider_id: str,
    openlist_base_path: str,
) -> str | None:
    """Call resolve_openlist_binding_id / build_openlist_binding_id matching its signature."""
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
    has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)

    pos_args: list[Any] = []
    kw_args: dict[str, Any] = {}

    if has_varargs and not [
        p
        for p in params
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]:
        pos_args = [provider_id, openlist_base_path]
    else:
        pos_index = 0
        for p in params:
            if p.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            name = p.name.lower()
            if "provider" in name:
                val: Any = provider_id
            elif "path" in name:
                val = openlist_base_path
            elif pos_index == 0:
                val = provider_id
            elif pos_index == 1:
                val = openlist_base_path
            else:
                if p.default is not inspect.Parameter.empty:
                    continue
                val = None

            if p.kind == inspect.Parameter.KEYWORD_ONLY:
                kw_args[p.name] = val
            else:
                pos_args.append(val)
                pos_index += 1

        if not pos_args and not kw_args and has_varkw:
            kw_args = {
                "provider_id": provider_id,
                "openlist_base_path": openlist_base_path,
            }

    outcome = fn(*pos_args, **kw_args)
    if inspect.isawaitable(outcome):
        outcome = await outcome
    if outcome is None:
        return None
    text = str(outcome).strip()
    return text or None


# ==============================================================================
# 1. RefCountedLockRegistry (§5.4.3, R06)
# ==============================================================================


@dataclass(slots=True)
class _LockEntry:
    lock: asyncio.Lock
    ref_count: int = 0


class RefCountedLockRegistry[K]:
    """Bounded reference-counted asyncio.Lock pool that NEVER evicts active/contended keys."""

    def __init__(
        self,
        *,
        idle_maxsize: int,
        hard_maxsize: int,
        busy_error_code: ErrorCode = ErrorCode.QUEUE_FULL,
        on_unlocked: Callable[[K], None] | None = None,
    ) -> None:
        if idle_maxsize <= 0 or hard_maxsize < idle_maxsize:
            raise ValueError("Require 0 < idle_maxsize <= hard_maxsize")
        self._idle_maxsize = idle_maxsize
        self._hard_maxsize = hard_maxsize
        self._busy_error_code = busy_error_code
        self._on_unlocked = on_unlocked
        self._entries: OrderedDict[K, _LockEntry] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    def ref_count(self, key: K) -> int:
        entry = self._entries.get(key)
        return 0 if entry is None else entry.ref_count

    def is_locked(self, key: K) -> bool:
        """Return True iff key is currently held or has an active acquirer/waiter."""
        entry = self._entries.get(key)
        if entry is None:
            return False
        return entry.lock.locked() or entry.ref_count > 0

    def _evict_idle_excess(self, *, target_len: int | None = None) -> None:
        limit = self._idle_maxsize if target_len is None else target_len
        if len(self._entries) <= limit:
            return
        idle_keys: list[K] = []
        excess = len(self._entries) - limit
        for k, ent in self._entries.items():
            if ent.ref_count == 0 and not ent.lock.locked():
                idle_keys.append(k)
                if len(idle_keys) >= excess:
                    break
        for k in idle_keys:
            del self._entries[k]

    @asynccontextmanager
    async def acquire(self, key: K, *, timeout: float | None = None) -> AsyncIterator[None]:
        entry = self._entries.get(key)
        if entry is not None:
            self._entries.move_to_end(key)
            entry.ref_count += 1
        else:
            if len(self._entries) >= self._hard_maxsize:
                self._evict_idle_excess(target_len=self._hard_maxsize - 1)
                if len(self._entries) >= self._hard_maxsize:
                    raise YunBotError(self._busy_error_code)
            entry = _LockEntry(lock=asyncio.Lock(), ref_count=1)
            self._entries[key] = entry
            self._evict_idle_excess()

        acquired = False
        try:
            if timeout is None:
                await entry.lock.acquire()
            else:
                await asyncio.wait_for(entry.lock.acquire(), timeout=timeout)
            acquired = True
            yield
        finally:
            if acquired:
                entry.lock.release()
            entry.ref_count -= 1
            assert entry.ref_count >= 0
            if self._entries.get(key) is entry:
                self._entries.move_to_end(key)
            completely_free = entry.ref_count == 0 and not entry.lock.locked()
            self._evict_idle_excess()
            if completely_free and self._on_unlocked is not None:
                self._on_unlocked(key)


# ==============================================================================
# 2. BoundedTransferScheduler (§5.4.2, §5.4.3, R06)
# ==============================================================================


@dataclass(slots=True)
class _ScheduledTransfer:
    task_id: str
    share: ShareLinkInfo
    dir_key: DirLockKey
    no_subdir: bool
    direct_slot_held: bool = False
    claiming_held: bool = False
    dir_claim_held: bool = False


class BoundedTransferScheduler:
    """Pre-worker mode-admission scheduler sharing a single bounded waiting capacity.

    Invariants (R06):
    1. `len(waiting) + claiming_count + pending_reservations <= queue_maxsize` at all times;
       lock-contention requeues convert an existing `claiming_count` back into `waiting`
       so capacity is never exceeded and no unbounded `create_task` is used.
    2. `-n` direct tasks are ONLY dispatched to a worker when
       `active_direct_count < direct_concurrency` AND `not is_dir_busy(dir_key)`.
       Since `direct_concurrency < worker_count`, blocked/excess `-n` tasks remain in
       `waiting` without occupying the remaining worker(s) needed by runnable default tasks.
    """

    def __init__(
        self,
        *,
        dir_locks: RefCountedLockRegistry[DirLockKey],
        queue_maxsize: int = TRANSFER_QUEUE_MAXSIZE,
        worker_count: int = TRANSFER_WORKERS,
        direct_concurrency: int = DIRECT_MODE_CONCURRENCY,
    ) -> None:
        if queue_maxsize <= 0:
            raise ValueError("queue_maxsize must be positive")
        if worker_count <= 0:
            raise ValueError("worker_count must be positive")
        if direct_concurrency <= 0:
            raise ValueError("direct_concurrency must be positive")
        if worker_count > 1 and direct_concurrency >= worker_count:
            raise ValueError("direct_concurrency must be strictly less than worker_count")

        self._dir_locks = dir_locks
        self._queue_maxsize = queue_maxsize
        self._worker_count = worker_count
        self._direct_concurrency = direct_concurrency

        self._waiting: deque[_ScheduledTransfer] = deque()
        self._pending_reservations: int = 0
        self._claiming_count: int = 0
        self._active_direct_count: int = 0
        self._claimed_dir_keys: Counter[DirLockKey] = Counter()
        self._wakeup = asyncio.Event()
        self._closed = False

    @property
    def waiting_count(self) -> int:
        return len(self._waiting)

    @property
    def active_direct_count(self) -> int:
        return self._active_direct_count

    @property
    def reserved_waiting_capacity(self) -> int:
        return len(self._waiting) + self._claiming_count + self._pending_reservations

    def notify_wakeup(self) -> None:
        self._wakeup.set()

    def reopen(self) -> None:
        self._closed = False

    def close(self) -> None:
        self._closed = True
        self._waiting.clear()
        self._pending_reservations = 0
        self._claiming_count = 0
        self._active_direct_count = 0
        self._claimed_dir_keys.clear()
        self._wakeup.set()

    def reserve_slot(self) -> None:
        if self._closed:
            raise YunBotError(ErrorCode.QUEUE_FULL)
        if self.reserved_waiting_capacity >= self._queue_maxsize:
            raise YunBotError(ErrorCode.QUEUE_FULL)
        self._pending_reservations += 1

    def release_reservation(self) -> None:
        if self._pending_reservations > 0:
            self._pending_reservations -= 1
            self._wakeup.set()

    def commit_reservation(self, job: _ScheduledTransfer) -> None:
        assert self._pending_reservations > 0
        self._pending_reservations -= 1
        self._waiting.append(job)
        self._wakeup.set()

    def _is_dir_busy(self, dir_key: DirLockKey) -> bool:
        return self._claimed_dir_keys[dir_key] > 0 or self._dir_locks.is_locked(dir_key)

    def _try_pop_runnable(self) -> _ScheduledTransfer | None:
        for idx, job in enumerate(self._waiting):
            if job.no_subdir:
                if self._active_direct_count >= self._direct_concurrency:
                    continue
                if self._is_dir_busy(job.dir_key):
                    continue
                del self._waiting[idx]
                self._active_direct_count += 1
                self._claiming_count += 1
                self._claimed_dir_keys[job.dir_key] += 1
                job.direct_slot_held = True
                job.claiming_held = True
                job.dir_claim_held = True
                return job

            if self._is_dir_busy(job.dir_key):
                continue
            del self._waiting[idx]
            self._claiming_count += 1
            self._claimed_dir_keys[job.dir_key] += 1
            job.claiming_held = True
            job.dir_claim_held = True
            return job
        return None

    async def next_runnable_job(self) -> _ScheduledTransfer | None:
        """Wait until a runnable job is admitted for a worker, or return None on shutdown."""
        while not self._closed:
            job = self._try_pop_runnable()
            if job is not None:
                if self._waiting:
                    # Other waiting jobs might also be runnable by sibling workers
                    self._wakeup.set()
                return job
            self._wakeup.clear()
            # Re-check after clear to prevent lost wakeup
            job = self._try_pop_runnable()
            if job is not None:
                if self._waiting:
                    self._wakeup.set()
                return job
            if self._closed:
                return None
            await self._wakeup.wait()
        return None

    def on_dir_lock_entered(self, job: _ScheduledTransfer) -> None:
        """Release pre-lock claim counters once real `dir_lock` is held."""
        if job.dir_claim_held:
            self._claimed_dir_keys[job.dir_key] -= 1
            if self._claimed_dir_keys[job.dir_key] <= 0:
                self._claimed_dir_keys.pop(job.dir_key, None)
            job.dir_claim_held = False
        if job.claiming_held:
            self._claiming_count -= 1
            assert self._claiming_count >= 0
            job.claiming_held = False
        self._wakeup.set()

    def requeue_after_lock_miss(self, job: _ScheduledTransfer) -> None:
        """Return a lock-contended job to the front of `_waiting` within bounded capacity."""
        if job.dir_claim_held:
            self._claimed_dir_keys[job.dir_key] -= 1
            if self._claimed_dir_keys[job.dir_key] <= 0:
                self._claimed_dir_keys.pop(job.dir_key, None)
            job.dir_claim_held = False
        if job.direct_slot_held:
            self._active_direct_count -= 1
            assert self._active_direct_count >= 0
            job.direct_slot_held = False
        if job.claiming_held:
            self._claiming_count -= 1
            assert self._claiming_count >= 0
            job.claiming_held = False
        if not self._closed:
            self._waiting.appendleft(job)
            assert self.reserved_waiting_capacity <= self._queue_maxsize
        self._wakeup.set()

    def release_job_claims(self, job: _ScheduledTransfer) -> None:
        """Idempotently release any remaining scheduler slots on job exit/cancellation."""
        changed = False
        if job.dir_claim_held:
            self._claimed_dir_keys[job.dir_key] -= 1
            if self._claimed_dir_keys[job.dir_key] <= 0:
                self._claimed_dir_keys.pop(job.dir_key, None)
            job.dir_claim_held = False
            changed = True
        if job.claiming_held:
            self._claiming_count -= 1
            assert self._claiming_count >= 0
            job.claiming_held = False
            changed = True
        if job.direct_slot_held:
            self._active_direct_count -= 1
            assert self._active_direct_count >= 0
            job.direct_slot_held = False
            changed = True
        if changed:
            self._wakeup.set()


# ==============================================================================
# 3. TransferCoordinator (§5.4, R01, R05, R06, R07)
# ==============================================================================


class TransferCoordinator:
    """Coordinates task admission, lock pools, unified directory locking, and transfer workers."""

    def __init__(
        self,
        *,
        storage: CoordinatorStorage,
        registry: ProviderRegistry,
        runtime_config: Any,
        bootstrap: BootstrapConfigSnapshot | None = None,
        openlist: CoordinatorOpenListClient | None = None,
        tz: str | None = None,
        on_panel_update: PanelUpdateCallback | None = None,
        on_need_password: NeedPasswordCallback | None = None,
        on_progress_update: PanelProgressCallback | None = None,
        queue_maxsize: int = TRANSFER_QUEUE_MAXSIZE,
        worker_count: int = TRANSFER_WORKERS,
        direct_concurrency: int = DIRECT_MODE_CONCURRENCY,
        dir_lock_wait_timeout: float = DIR_LOCK_WAIT_TIMEOUT_SECONDS,
        max_transfer_duration: float = MAX_TRANSFER_DURATION_SECONDS,
        progress_min_interval: float = TG_PROGRESS_MIN_INTERVAL_SECONDS,
        task_lock_idle_maxsize: int = TASK_LOCK_IDLE_MAXSIZE,
        task_lock_hard_maxsize: int = TASK_LOCK_HARD_MAXSIZE,
        dir_lock_idle_maxsize: int = DIR_LOCK_IDLE_MAXSIZE,
        dir_lock_hard_maxsize: int = DIR_LOCK_HARD_MAXSIZE,
    ) -> None:
        self._storage = storage
        self._registry = registry
        self._runtime_config = runtime_config
        self._openlist = openlist
        self._tz = tz or (bootstrap.tz if bootstrap is not None else "Asia/Shanghai")
        # Validate timezone early
        ZoneInfo(self._tz)

        self._on_panel_update = on_panel_update
        self._on_need_password = on_need_password
        self._on_progress_update = on_progress_update

        self._worker_count = worker_count
        self._dir_lock_wait_timeout = dir_lock_wait_timeout
        self._max_transfer_duration = max_transfer_duration
        self._progress_min_interval = progress_min_interval

        self._task_locks: RefCountedLockRegistry[str] = RefCountedLockRegistry(
            idle_maxsize=task_lock_idle_maxsize,
            hard_maxsize=task_lock_hard_maxsize,
            busy_error_code=ErrorCode.TASK_BUSY,
        )
        self._dir_locks: RefCountedLockRegistry[DirLockKey] = RefCountedLockRegistry(
            idle_maxsize=dir_lock_idle_maxsize,
            hard_maxsize=dir_lock_hard_maxsize,
            busy_error_code=ErrorCode.QUEUE_FULL,
            on_unlocked=self._on_dir_unlocked,
        )
        self._scheduler = BoundedTransferScheduler(
            dir_locks=self._dir_locks,
            queue_maxsize=queue_maxsize,
            worker_count=worker_count,
            direct_concurrency=direct_concurrency,
        )
        self._workers: list[asyncio.Task[None]] = []

    @property
    def task_locks(self) -> RefCountedLockRegistry[str]:
        return self._task_locks

    @property
    def dir_locks(self) -> RefCountedLockRegistry[DirLockKey]:
        return self._dir_locks

    @property
    def scheduler(self) -> BoundedTransferScheduler:
        return self._scheduler

    def set_openlist(self, openlist: CoordinatorOpenListClient | None) -> None:
        self._openlist = openlist

    def set_callbacks(
        self,
        *,
        on_panel_update: PanelUpdateCallback | None = None,
        on_need_password: NeedPasswordCallback | None = None,
        on_progress_update: PanelProgressCallback | None = None,
    ) -> None:
        if on_panel_update is not None:
            self._on_panel_update = on_panel_update
        if on_need_password is not None:
            self._on_need_password = on_need_password
        if on_progress_update is not None:
            self._on_progress_update = on_progress_update

    def _on_dir_unlocked(self, _dir_key: DirLockKey) -> None:
        self._scheduler.notify_wakeup()

    def acquire_task_lock(
        self,
        task_id: str,
        *,
        timeout: float | None = None,
    ) -> AsyncIterator[None]:
        return self._task_locks.acquire(task_id, timeout=timeout)

    def acquire_dir_lock(
        self,
        dir_key: DirLockKey,
        *,
        timeout: float | None = DIR_LOCK_WAIT_TIMEOUT_SECONDS,
    ) -> AsyncIterator[None]:
        return self._dir_locks.acquire(dir_key, timeout=timeout)

    async def start(self) -> None:
        if any(not w.done() for w in self._workers):
            return
        self._scheduler.reopen()
        self._workers = [
            asyncio.create_task(self._worker_loop(i), name=f"yunbot-transfer-worker-{i}")
            for i in range(self._worker_count)
        ]

    async def stop(self) -> None:
        self._scheduler.close()
        workers = self._workers
        self._workers = []
        for w in workers:
            if not w.done():
                w.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

    async def _resolve_openlist_snapshot(
        self,
        snap: RuntimeSettingsSnapshot,
        provider_id: str,
        openlist_path_key: str,
    ) -> tuple[str | None, str | None]:
        if not snap.openlist_base_url.strip():
            return None, None

        openlist_base_path = normalize_posix_path(
            snap.get_openlist_path(openlist_path_key),
            allow_root=False,
        )
        binding_id: str | None = None

        if self._openlist is not None:
            resolver = getattr(self._openlist, "resolve_openlist_binding_id", None)
            if callable(resolver):
                try:
                    binding_id = await _invoke_flexible_binding_resolver(
                        resolver,
                        provider_id,
                        openlist_base_path,
                    )
                except OpenListUnavailableError as exc:
                    LOGGER.warning(
                        "OpenList unavailable during binding snapshot provider=%s err=%s",
                        provider_id,
                        redact_sensitive_text(str(exc)),
                    )

        if not binding_id:
            rc_builder = getattr(self._runtime_config, "build_openlist_binding_id", None)
            if callable(rc_builder):
                binding_id = await _invoke_flexible_binding_resolver(
                    rc_builder,
                    provider_id,
                    openlist_base_path,
                )

        if not binding_id and snap.openlist_instance_epoch:
            mount_epoch = snap.get_mount_epoch(provider_id)
            binding_id = f"openlist:{snap.openlist_instance_epoch}:{provider_id}:{mount_epoch}"

        if not binding_id:
            return None, None
        return openlist_base_path, binding_id

    async def enqueue_transfer(
        self,
        *,
        chat_id: int,
        user_id: int,
        share: ShareLinkInfo,
        panel_message_id: int | None = None,
    ) -> TaskRecord:
        provider = self._registry.find(share.provider_id)
        if provider is None:
            raise YunBotError(ErrorCode.INVALID_LINK)

        provider.validate_transfer_mode(no_subdir=share.no_subdir)
        account_binding_id = await provider.get_current_binding_id()

        snap = resolve_runtime_snapshot(self._runtime_config)
        base_save_path = validate_save_path(snap.get_save_path(provider.spec.save_path_key))
        openlist_base_path, openlist_binding_id = await self._resolve_openlist_snapshot(
            snap,
            provider.spec.provider_id,
            provider.spec.openlist_path_key,
        )

        task_id = generate_task_id()
        now_ts = time.time()
        if not share.no_subdir:
            local_date = datetime.fromtimestamp(now_ts, tz=ZoneInfo(self._tz)).strftime("%Y%m%d")
            task_dir_path: str | None = validate_task_dir_path(
                f"{base_save_path}/{local_date}_{task_id}",
                base_save_path,
                task_id,
            )
        else:
            task_dir_path = None

        # Atomically reserve bounded waiting slot BEFORE writing to SQLite (R06)
        self._scheduler.reserve_slot()
        record = TaskRecord(
            task_id=task_id,
            chat_id=chat_id,
            user_id=user_id,
            provider=provider.spec.provider_id,
            account_binding_id=account_binding_id,
            openlist_binding_id=openlist_binding_id,
            share_title=share.external_id,
            base_save_path=base_save_path,
            openlist_base_path=openlist_base_path,
            no_subdir=share.no_subdir,
            task_dir_path=task_dir_path,
            status=TaskStatus.QUEUED,
            delivery_prev_status=None,
            transfer_uncertain=False,
            remote_task_ref=None,
            item_count=0,
            tg_send_eligible=False,
            openlist_share_id=None,
            openlist_share_expires_at=None,
            error_code=None,
            error_message=None,
            panel_message_id=panel_message_id,
            panel_closed=False,
            created_at=now_ts,
            updated_at=now_ts,
        )
        try:
            await self._storage.create_task(record)
        except BaseException:
            self._scheduler.release_reservation()
            raise

        dir_key: DirLockKey = (
            record.provider,
            record.account_binding_id,
            record.base_save_path,
        )
        self._scheduler.commit_reservation(
            _ScheduledTransfer(
                task_id=task_id,
                share=share,
                dir_key=dir_key,
                no_subdir=share.no_subdir,
            )
        )
        return record

    async def _worker_loop(self, _worker_idx: int) -> None:
        while True:
            job = await self._scheduler.next_runnable_job()
            if job is None:
                return
            try:
                await self._execute_scheduled_job(job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.error(
                    "Unhandled worker loop error task=%s err=%s",
                    job.task_id,
                    redact_sensitive_text(str(exc)),
                )
            finally:
                self._scheduler.release_job_claims(job)

    async def _execute_scheduled_job(self, job: _ScheduledTransfer) -> None:
        # Fast lock-race check before awaiting dir_lock (e.g. external deletion grabbed dir_lock)
        if self._dir_locks.is_locked(job.dir_key):
            self._scheduler.requeue_after_lock_miss(job)
            return

        provider = self._registry.find(job.share.provider_id)
        if provider is None:
            self._scheduler.on_dir_lock_entered(job)
            await self._finalize_failed(
                job.task_id,
                error_code=ErrorCode.INVALID_LINK,
                error_message=format_error_message(ErrorCode.INVALID_LINK),
                transfer_uncertain=False,
                item_count=0,
            )
            return

        task: TaskRecord | None = None
        created_dir_on_cloud = False
        entered_dir_lock = False
        entered_cloud_transfer = False
        persisted_items = 0
        last_progress_mono = 0.0

        async def on_remote_task(remote_ref: str) -> None:
            await update_task_fields(self._storage, job.task_id, remote_task_ref=remote_ref)

        async def on_progress(stage: str, current: int, total: int) -> None:
            nonlocal last_progress_mono, task
            if self._on_progress_update is None or task is None:
                return
            display_stage = stage.strip()
            if display_stage and display_stage.lower() == "transferring":
                display_stage = "云端转存中"
            elif display_stage:
                pct_suffix = ""
                base_title = display_stage
                if display_stage.endswith("%)") and " (" in display_stage:
                    head, _, tail = display_stage.rpartition(" (")
                    if head and tail[:-2].isdigit():
                        base_title = head.strip()
                        pct_suffix = f"云端进度 {tail[:-1]}"
                if base_title and task.share_title in ("", job.share.external_id, job.share.url):
                    task = replace(task, share_title=base_title)
                if base_title == task.share_title:
                    display_stage = pct_suffix or "云端转存中"
            now_mono = time.monotonic()
            if (now_mono - last_progress_mono) < self._progress_min_interval:
                return
            last_progress_mono = now_mono
            try:
                await self._on_progress_update(task, display_stage, current, total)
            except Exception as exc:
                LOGGER.debug(
                    "Progress callback ignored error task=%s err=%s",
                    job.task_id,
                    redact_sensitive_text(str(exc)),
                )

        async def on_items_batch(batch: Sequence[TransferredEntry]) -> None:
            nonlocal persisted_items
            if not batch:
                return
            inserted = await self._storage.append_transfer_items_batch(job.task_id, batch)
            if isinstance(inserted, int):
                persisted_items += inserted
            else:
                persisted_items += len(batch)

        async def _run_transfer_body() -> None:
            nonlocal task, created_dir_on_cloud, entered_dir_lock, entered_cloud_transfer

            if not job.no_subdir:
                # Default mode (R01): hold dir_lock ONLY while creating `<base>/<yyyymmdd>_<id>`
                async with self.acquire_dir_lock(
                    job.dir_key,
                    timeout=self._dir_lock_wait_timeout,
                ):
                    entered_dir_lock = True
                    self._scheduler.on_dir_lock_entered(job)
                    task = await self._storage.get_task(job.task_id)
                    if task is None or task.status != TaskStatus.QUEUED:
                        return
                    if await provider.get_current_binding_id() != task.account_binding_id:
                        raise BindingMismatchError()
                    assert task.task_dir_path is not None
                    await update_task_fields(
                        self._storage,
                        job.task_id,
                        status=TaskStatus.TRANSFERRING,
                    )
                    task = replace(task, status=TaskStatus.TRANSFERRING)
                    await provider.prepare_task_dir(task.task_dir_path)
                    created_dir_on_cloud = True

                # dir_lock and task_id lock are BOTH unheld during file transfer into subdir
                assert task is not None and task.task_dir_path is not None
                await self._safe_notify_panel(task)
                entered_cloud_transfer = True
                outcome = await provider.transfer(
                    job.share,
                    task.task_dir_path,
                    task_id=job.task_id,
                    collect_items=False,
                    on_items_batch=None,
                    on_remote_task=on_remote_task,
                    on_progress=on_progress,
                )
            else:
                # -n Direct mode (R01, R07): hold dir_lock across full transfer + batch DB commits
                async with self.acquire_dir_lock(
                    job.dir_key,
                    timeout=self._dir_lock_wait_timeout,
                ):
                    entered_dir_lock = True
                    self._scheduler.on_dir_lock_entered(job)
                    task = await self._storage.get_task(job.task_id)
                    if task is None or task.status != TaskStatus.QUEUED:
                        return
                    provider.validate_transfer_mode(no_subdir=True)
                    if await provider.get_current_binding_id() != task.account_binding_id:
                        raise BindingMismatchError()
                    await update_task_fields(
                        self._storage,
                        job.task_id,
                        status=TaskStatus.TRANSFERRING,
                        transfer_uncertain=True,
                    )
                    task = replace(
                        task,
                        status=TaskStatus.TRANSFERRING,
                        transfer_uncertain=True,
                    )
                    await self._safe_notify_panel(task)
                    entered_cloud_transfer = True
                    outcome = await provider.transfer(
                        job.share,
                        task.base_save_path,
                        task_id=job.task_id,
                        collect_items=True,
                        on_items_batch=on_items_batch,
                        on_remote_task=on_remote_task,
                        on_progress=on_progress,
                    )

            assert task is not None
            await self._complete_transfer_outcome(
                task=task,
                provider_display_name=provider.spec.display_name,
                outcome=outcome,
                persisted_items=persisted_items,
            )

        try:
            await asyncio.wait_for(_run_transfer_body(), timeout=self._max_transfer_duration)
        except TimeoutError:
            if not entered_dir_lock:
                self._scheduler.requeue_after_lock_miss(job)
                return
            await self._finalize_failed(
                job.task_id,
                error_code=ErrorCode.INTERNAL_ERROR,
                error_message=format_error_message(ErrorCode.INTERNAL_ERROR, task_id=job.task_id),
                transfer_uncertain=bool(job.no_subdir and entered_cloud_transfer),
                item_count=persisted_items,
            )
        except ProviderNeedPasswordError:
            if (
                not job.no_subdir
                and created_dir_on_cloud
                and task is not None
                and task.task_dir_path is not None
            ):
                try:
                    async with self.acquire_dir_lock(
                        job.dir_key,
                        timeout=self._dir_lock_wait_timeout,
                    ):
                        await provider.delete_directory(task.task_dir_path)
                except Exception as clean_exc:
                    LOGGER.warning(
                        "Failed to clean empty task_dir after NEED_PASSWORD task=%s err=%s",
                        job.task_id,
                        redact_sensitive_text(str(clean_exc)),
                    )
            async with self.acquire_task_lock(job.task_id):
                await self._storage.delete_task(job.task_id)
            if self._on_need_password is not None and task is not None:
                await _invoke_need_password(self._on_need_password, task, job.share)
        except YunBotError as exc:
            await self._finalize_failed(
                job.task_id,
                error_code=exc.code,
                error_message=exc.user_message,
                transfer_uncertain=bool(job.no_subdir and entered_cloud_transfer),
                item_count=persisted_items,
            )
        except asyncio.CancelledError:
            if entered_dir_lock:
                try:
                    await asyncio.shield(
                        update_task_fields(
                            self._storage,
                            job.task_id,
                            status=TaskStatus.FAILED,
                            transfer_uncertain=bool(job.no_subdir and entered_cloud_transfer),
                            item_count=persisted_items,
                            error_code=ErrorCode.INTERNAL_ERROR,
                            error_message="服务停止中断",
                        )
                    )
                except Exception:
                    pass
            raise
        except Exception as exc:
            LOGGER.error(
                "Transfer failed with unexpected error task=%s err=%s",
                job.task_id,
                redact_sensitive_text(str(exc)),
            )
            await self._finalize_failed(
                job.task_id,
                error_code=ErrorCode.INTERNAL_ERROR,
                error_message=format_error_message(ErrorCode.INTERNAL_ERROR, task_id=job.task_id),
                transfer_uncertain=bool(job.no_subdir and entered_cloud_transfer),
                item_count=persisted_items,
            )

    async def _complete_transfer_outcome(
        self,
        *,
        task: TaskRecord,
        provider_display_name: str,
        outcome: Any,
        persisted_items: int,
    ) -> None:
        share_title = (outcome.share_title or "").strip() or task.share_title
        clean_certain = (not outcome.uncertain) and (outcome.error_code is None)
        final_uncertain = False if not task.no_subdir else (not clean_certain)

        if outcome.succeeded_count <= 0:
            err_code = outcome.error_code or ErrorCode.INTERNAL_ERROR
            err_msg = outcome.error_message or format_error_message(
                err_code,
                task_id=task.task_id,
                provider_name=provider_display_name,
            )
            await self._finalize_failed(
                task.task_id,
                error_code=err_code,
                error_message=err_msg,
                transfer_uncertain=final_uncertain,
                item_count=persisted_items,
                share_title=share_title,
            )
            return

        is_partial = bool(
            outcome.failed_count > 0 or outcome.truncated_by_limit or outcome.uncertain
        )
        final_status = TaskStatus.PARTIAL if is_partial else TaskStatus.READY
        final_item_count = (
            persisted_items if (task.no_subdir and persisted_items > 0) else outcome.succeeded_count
        )

        if final_status == TaskStatus.PARTIAL:
            part_code = outcome.error_code or (
                ErrorCode.ENUM_LIMIT_EXCEEDED
                if outcome.truncated_by_limit
                else ErrorCode.TRANSFER_PARTIAL
            )
            err_code_str: str | None = part_code.value
            err_msg_str: str | None = outcome.error_message or format_error_message(
                part_code,
                ok_count=outcome.succeeded_count,
                fail_count=outcome.failed_count,
                provider_name=provider_display_name,
                task_id=task.task_id,
            )
        else:
            err_code_str = None
            err_msg_str = None

        tg_send_eligible = False
        if (
            self._openlist is not None
            and task.openlist_binding_id is not None
            and task.openlist_base_path is not None
        ):
            probe_view = replace(
                task,
                share_title=share_title,
                status=final_status,
                transfer_uncertain=final_uncertain,
                item_count=final_item_count,
                error_code=err_code_str,
                error_message=err_msg_str,
            )
            try:
                probe_res = await self._openlist.probe_task_media(probe_view)
                tg_send_eligible = bool(probe_res.eligible)
            except Exception as exc:
                LOGGER.warning(
                    "OpenList media probe skipped/failed task=%s err=%s",
                    task.task_id,
                    redact_sensitive_text(str(exc)),
                )
                tg_send_eligible = False

        async with self.acquire_task_lock(task.task_id):
            await update_task_fields(
                self._storage,
                task.task_id,
                share_title=share_title,
                status=final_status,
                transfer_uncertain=final_uncertain,
                item_count=final_item_count,
                tg_send_eligible=tg_send_eligible,
                error_code=err_code_str,
                error_message=err_msg_str,
            )
            updated = await self._storage.get_task(task.task_id)

        if updated is not None:
            await self._safe_notify_panel(updated)

    async def _finalize_failed(
        self,
        task_id: str,
        *,
        error_code: ErrorCode,
        error_message: str,
        transfer_uncertain: bool,
        item_count: int,
        share_title: str | None = None,
    ) -> None:
        fields: dict[str, Any] = {
            "status": TaskStatus.FAILED,
            "transfer_uncertain": transfer_uncertain,
            "item_count": item_count,
            "tg_send_eligible": False,
            "error_code": error_code.value,
            "error_message": error_message,
        }
        if share_title is not None:
            fields["share_title"] = share_title

        async with self.acquire_task_lock(task_id):
            existing = await self._storage.get_task(task_id)
            if existing is None:
                return
            await update_task_fields(self._storage, task_id, **fields)
            updated = await self._storage.get_task(task_id)

        if updated is not None:
            await self._safe_notify_panel(updated)

    async def _safe_notify_panel(self, task: TaskRecord) -> None:
        if self._on_panel_update is None:
            return
        try:
            await self._on_panel_update(task)
        except Exception as exc:
            LOGGER.warning(
                "Panel update callback failed task=%s err=%s",
                task.task_id,
                redact_sensitive_text(str(exc)),
            )


# ==============================================================================
# 4. TaskDeletionService (§5.10.2, R01, R05, R07)
# ==============================================================================


@dataclass(frozen=True, slots=True)
class TaskDeleteResult:
    """Outcome of a dual-mode verified task and cloud deletion operation."""

    deleted_record: bool
    status: TaskStatus | None
    skipped_items: tuple[TransferItemRecord, ...] = ()
    uncertain_empty_warning: bool = False
    remain_count: int = 0
    message: str = ""

    @property
    def uncertain_empty(self) -> bool:
        return self.uncertain_empty_warning


class TaskDeletionService:
    """Verified cloud + local task deletion enforcing ownership, bindings, and path invariants."""

    def __init__(
        self,
        *,
        storage: CoordinatorStorage,
        registry: ProviderRegistry,
        coordinator: TransferCoordinator,
        runtime_config: Any = None,
        openlist: CoordinatorOpenListClient | None = None,
        bootstrap: BootstrapConfigSnapshot | None = None,
        admin_id: int | None = None,
        on_panel_update: PanelUpdateCallback | None = None,
        on_task_deleted: TaskDeletedCallback | None = None,
        dir_lock_wait_timeout: float = DIR_LOCK_WAIT_TIMEOUT_SECONDS,
    ) -> None:
        resolved_admin = (
            admin_id
            if admin_id is not None
            else (bootstrap.telegram_admin_id if bootstrap is not None else None)
        )
        if resolved_admin is None or resolved_admin <= 0:
            raise ValueError("admin_id or bootstrap.telegram_admin_id (> 0) is required")

        self._storage = storage
        self._registry = registry
        self._coordinator = coordinator
        self._runtime_config = runtime_config
        self._openlist = openlist
        self._admin_id = resolved_admin
        self._on_panel_update = on_panel_update
        self._on_task_deleted = on_task_deleted
        self._dir_lock_wait_timeout = dir_lock_wait_timeout

    def set_openlist(self, openlist: CoordinatorOpenListClient | None) -> None:
        self._openlist = openlist

    def set_callbacks(
        self,
        *,
        on_panel_update: PanelUpdateCallback | None = None,
        on_task_deleted: TaskDeletedCallback | None = None,
    ) -> None:
        if on_panel_update is not None:
            self._on_panel_update = on_panel_update
        if on_task_deleted is not None:
            self._on_task_deleted = on_task_deleted

    async def _notify_deleted(self, task: TaskRecord, result: TaskDeleteResult) -> None:
        if self._on_task_deleted is None:
            return
        try:
            await self._on_task_deleted(task, result)
        except Exception as exc:
            LOGGER.warning(
                "Task deleted callback failed task=%s err=%s",
                task.task_id,
                redact_sensitive_text(str(exc)),
            )

    async def _check_openlist_status_for_task(self, task: TaskRecord) -> str:
        """Return 'matched', 'disabled_or_mismatched', or 'unavailable'."""
        if self._openlist is None or not task.openlist_binding_id:
            return "disabled_or_mismatched"
        if self._runtime_config is not None:
            snap = resolve_runtime_snapshot(self._runtime_config)
            if not snap.openlist_base_url.strip():
                return "disabled_or_mismatched"
        is_enabled_attr = getattr(self._openlist, "is_enabled", None)
        if is_enabled_attr is not None:
            enabled = is_enabled_attr() if callable(is_enabled_attr) else bool(is_enabled_attr)
            if not enabled:
                return "disabled_or_mismatched"

        verifier = getattr(self._openlist, "verify_task_bindings", None)
        if callable(verifier):
            try:
                res = await verifier(task)
                if res is False:
                    return "disabled_or_mismatched"
            except (BindingMismatchError, ProviderAuthInvalidError):
                return "disabled_or_mismatched"
            except Exception as exc:
                LOGGER.warning(
                    "OpenList binding verification error during delete task=%s err=%s",
                    task.task_id,
                    redact_sensitive_text(str(exc)),
                )
                return "unavailable"
        return "matched"

    async def _best_effort_refresh_openlist(self, task: TaskRecord) -> None:
        if self._openlist is None or not task.openlist_base_path:
            return
        state = await self._check_openlist_status_for_task(task)
        if state != "matched":
            return
        for method_name in ("refresh_path", "refresh_directory", "refresh_dir"):
            fn = getattr(self._openlist, method_name, None)
            if callable(fn):
                try:
                    await fn(task.openlist_base_path)
                except Exception as exc:
                    LOGGER.debug(
                        "Best-effort OpenList refresh ignored error task=%s err=%s",
                        task.task_id,
                        redact_sensitive_text(str(exc)),
                    )
                return

    async def _clear_share_fields_in_db(self, task_id: str) -> None:
        clear_fn = getattr(self._storage, "clear_task_share", None)
        if callable(clear_fn):
            await clear_fn(task_id)
            return
        await update_task_fields(
            self._storage,
            task_id,
            openlist_share_id=None,
            openlist_share_expires_at=None,
        )

    async def _clear_share_fields_locked(self, task_id: str) -> None:
        async with self._coordinator.acquire_task_lock(task_id):
            await self._clear_share_fields_in_db(task_id)

    async def _persist_partial_remaining_items(
        self,
        task_id: str,
        remaining_item_ids: Sequence[str],
    ) -> None:
        await self._storage.retain_only_failed_transfer_items(task_id, remaining_item_ids)
        await update_task_fields(
            self._storage,
            task_id,
            item_count=len(remaining_item_ids),
            tg_send_eligible=False,
        )

    @staticmethod
    def _callable_accepts_kwarg(fn: Callable[..., Any], kwarg_name: str) -> bool:
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

    async def _invoke_provider_delete_directory(
        self,
        provider: Any,
        validated_dir: str,
        *,
        expected_binding_id: str,
    ) -> None:
        current_binding = await provider.get_current_binding_id()
        if current_binding != expected_binding_id:
            raise BindingMismatchError()
        fn = provider.delete_directory
        if self._callable_accepts_kwarg(fn, "expected_binding_id"):
            await fn(validated_dir, expected_binding_id=expected_binding_id)
        else:
            await fn(validated_dir)

    async def _invoke_provider_delete_items(
        self,
        provider: Any,
        base_save_path: str,
        validated_items: Sequence[TransferItemRecord],
        *,
        expected_binding_id: str,
        deleted_ids_sink: list[str],
    ) -> Any:
        current_binding = await provider.get_current_binding_id()
        if current_binding != expected_binding_id:
            raise BindingMismatchError()
        fn = provider.delete_items
        kwargs: dict[str, Any] = {}
        if self._callable_accepts_kwarg(fn, "expected_binding_id"):
            kwargs["expected_binding_id"] = expected_binding_id
        if self._callable_accepts_kwarg(fn, "deleted_ids_sink"):
            kwargs["deleted_ids_sink"] = deleted_ids_sink
        return await fn(base_save_path, validated_items, **kwargs)

    async def _mark_delete_failed(
        self,
        task_id: str,
        *,
        remain_count: int | None = None,
        error_code: ErrorCode = ErrorCode.DELETE_PARTIAL,
        error_message: str | None = None,
        notify_panel: bool = True,
    ) -> TaskRecord | None:
        async with self._coordinator.acquire_task_lock(task_id):
            cur = await self._storage.get_task(task_id)
            if cur is None:
                return None
            fields: dict[str, Any] = {
                "status": TaskStatus.DELETE_FAILED,
                "tg_send_eligible": False,
            }
            if cur.no_subdir:
                remaining_items = tuple(await self._storage.list_transfer_items(task_id))
                actual_remain = (
                    remain_count
                    if remain_count is not None
                    else (len(remaining_items) if remaining_items else max(cur.item_count, 1))
                )
                if remaining_items:
                    fields["item_count"] = len(remaining_items)
            else:
                actual_remain = remain_count if remain_count is not None else 1

            msg = error_message or format_error_message(error_code, remain_count=actual_remain)
            fields["error_code"] = error_code.value
            fields["error_message"] = msg
            await update_task_fields(self._storage, task_id, **fields)
            updated = await self._storage.get_task(task_id)
        if notify_panel and updated is not None and self._on_panel_update is not None:
            try:
                await self._on_panel_update(updated)
            except Exception:
                pass
        return updated

    async def delete_task_with_cloud_files(
        self,
        task_id: str,
        *,
        operator_id: int,
        detach_only: bool = False,
    ) -> TaskDeleteResult:
        initial = await self._storage.get_task(task_id)
        if initial is None:
            return TaskDeleteResult(
                deleted_record=True,
                status=None,
                message="ℹ️ 任务记录不存在或已被移除。",
            )
        if operator_id != initial.user_id and operator_id != self._admin_id:
            raise YunBotError(ErrorCode.UNAUTHORIZED_PANEL_ACTION)

        entered_deleting = False
        try:
            async with self._coordinator.acquire_task_lock(task_id):
                task = await self._storage.get_task(task_id)
                if task is None:
                    return TaskDeleteResult(
                        deleted_record=True,
                        status=None,
                        message="ℹ️ 任务记录不存在或已被移除。",
                    )
                if operator_id != task.user_id and operator_id != self._admin_id:
                    raise YunBotError(ErrorCode.UNAUTHORIZED_PANEL_ACTION)
                if task.status in IN_FLIGHT_TASK_STATUSES:
                    raise YunBotError(ErrorCode.TASK_BUSY)

                if detach_only:
                    if operator_id != self._admin_id:
                        raise YunBotError(ErrorCode.UNAUTHORIZED_PANEL_ACTION)
                    await self._storage.delete_task(task_id)
                    detach_res = TaskDeleteResult(
                        deleted_record=True,
                        status=None,
                        message="✅ 已移除脱离绑定的本地历史任务记录。",
                    )
                    await self._notify_deleted(task, detach_res)
                    return detach_res

                provider = self._registry.find(task.provider)
                if provider is None:
                    raise BindingMismatchError()
                current_binding = await provider.get_current_binding_id()
                if current_binding != task.account_binding_id:
                    raise BindingMismatchError()

                entered = await self._storage.enter_deleting(task_id)
                entered_deleting = True
                deleting_task = (
                    entered
                    if isinstance(entered, TaskRecord)
                    else await self._storage.get_task(task_id)
                )

            if deleting_task is not None and self._on_panel_update is not None:
                try:
                    await self._on_panel_update(deleting_task)
                except Exception as exc:
                    LOGGER.warning(
                        "Panel update on enter_deleting failed task=%s err=%s",
                        task_id,
                        redact_sensitive_text(str(exc)),
                    )

            dir_key: DirLockKey = (task.provider, task.account_binding_id, task.base_save_path)
            if not task.no_subdir:
                return await self._delete_default_subdir_task(task, provider, dir_key)
            return await self._delete_direct_items_task(task, provider, dir_key)
        except asyncio.CancelledError:
            if entered_deleting:
                try:
                    await await_cleanup_uninterruptibly(
                        self._mark_delete_failed(task_id, notify_panel=False)
                    )
                except Exception:
                    pass
            raise
        except YunBotError as exc:
            if entered_deleting:
                await await_cleanup_uninterruptibly(
                    self._mark_delete_failed(
                        task_id,
                        error_code=exc.code,
                        error_message=exc.user_message,
                    )
                )
            raise
        except Exception as exc:
            if not entered_deleting:
                raise
            LOGGER.error(
                "Unexpected error during cloud task deletion task=%s err=%s",
                task_id,
                redact_sensitive_text(str(exc)),
            )
            updated = await await_cleanup_uninterruptibly(self._mark_delete_failed(task_id))
            remain = (
                updated.item_count
                if (updated is not None and updated.no_subdir and updated.item_count > 0)
                else 1
            )
            return TaskDeleteResult(
                deleted_record=False,
                status=TaskStatus.DELETE_FAILED,
                remain_count=remain,
                message=format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=remain),
            )

    async def _delete_default_subdir_task(
        self,
        task: TaskRecord,
        provider: Any,
        dir_key: DirLockKey,
    ) -> TaskDeleteResult:
        if not task.task_dir_path:
            raise YunBotError(ErrorCode.INTERNAL_ERROR, task_id=task.task_id)
        try:
            validated_dir = validate_task_dir_path(
                task.task_dir_path,
                task.base_save_path,
                task.task_id,
            )
        except ValueError as exc:
            raise YunBotError(ErrorCode.INTERNAL_ERROR, str(exc), task_id=task.task_id) from exc

        if task.openlist_share_id:
            ol_state = await self._check_openlist_status_for_task(task)
            if ol_state == "unavailable":
                await self._mark_delete_failed(task.task_id, remain_count=1)
                return TaskDeleteResult(
                    deleted_record=False,
                    status=TaskStatus.DELETE_FAILED,
                    remain_count=1,
                    message=format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=1),
                )
            if ol_state == "matched":
                assert self._openlist is not None
                try:
                    revoked = await self._openlist.revoke_share(task.openlist_share_id)
                    if revoked is False:
                        raise OpenListUnavailableError("revoke_share returned False")
                except Exception as exc:
                    LOGGER.warning(
                        "Failed to revoke OpenList share before deleting task=%s err=%s",
                        task.task_id,
                        redact_sensitive_text(str(exc)),
                    )
                    await self._mark_delete_failed(task.task_id, remain_count=1)
                    return TaskDeleteResult(
                        deleted_record=False,
                        status=TaskStatus.DELETE_FAILED,
                        remain_count=1,
                        message=format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=1),
                    )
                await await_cleanup_uninterruptibly(self._clear_share_fields_locked(task.task_id))

        try:
            async with self._coordinator.acquire_dir_lock(
                dir_key,
                timeout=self._dir_lock_wait_timeout,
            ):
                await self._invoke_provider_delete_directory(
                    provider,
                    validated_dir,
                    expected_binding_id=task.account_binding_id,
                )
                await self._storage.delete_task(task.task_id)
        except BindingMismatchError:
            raise
        except Exception as exc:
            LOGGER.warning(
                "Cloud directory deletion failed task=%s err=%s",
                task.task_id,
                redact_sensitive_text(str(exc)),
            )
            await self._mark_delete_failed(task.task_id, remain_count=1)
            return TaskDeleteResult(
                deleted_record=False,
                status=TaskStatus.DELETE_FAILED,
                remain_count=1,
                message=format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=1),
            )

        await self._best_effort_refresh_openlist(task)
        res = TaskDeleteResult(
            deleted_record=True,
            status=None,
            message="✅ 已撤销分享并删除云端目录与任务记录。",
        )
        await self._notify_deleted(task, res)
        return res

    async def _delete_direct_items_task(
        self,
        task: TaskRecord,
        provider: Any,
        dir_key: DirLockKey,
    ) -> TaskDeleteResult:
        try:
            async with self._coordinator.acquire_dir_lock(
                dir_key,
                timeout=self._dir_lock_wait_timeout,
            ):
                items = tuple(await self._storage.list_transfer_items(task.task_id))
                if not items:
                    current_binding = await provider.get_current_binding_id()
                    if current_binding != task.account_binding_id:
                        raise BindingMismatchError()
                    await self._storage.delete_task(task.task_id)
                    if task.transfer_uncertain:
                        empty_res = TaskDeleteResult(
                            deleted_record=True,
                            status=None,
                            uncertain_empty_warning=True,
                            message=format_error_message(ErrorCode.DELETE_UNCERTAIN_EMPTY),
                        )
                    else:
                        empty_res = TaskDeleteResult(
                            deleted_record=True,
                            status=None,
                            uncertain_empty_warning=False,
                            message="✅ 已删除任务记录。",
                        )
                else:
                    empty_res = None

                if empty_res is None:
                    validated_items: list[TransferItemRecord] = []
                    for item in items:
                        try:
                            norm_path = validate_direct_item_path(item.path, task.base_save_path)
                        except ValueError as exc:
                            raise YunBotError(
                                ErrorCode.INTERNAL_ERROR,
                                str(exc),
                                task_id=task.task_id,
                            ) from exc
                        validated_items.append(
                            replace(item, path=norm_path) if norm_path != item.path else item
                        )

                    confirmed_deleted_ids: list[str] = []
                    try:
                        outcome = await self._invoke_provider_delete_items(
                            provider,
                            task.base_save_path,
                            validated_items,
                            expected_binding_id=task.account_binding_id,
                            deleted_ids_sink=confirmed_deleted_ids,
                        )
                    except BaseException:
                        if confirmed_deleted_ids:
                            deleted_set = set(confirmed_deleted_ids)
                            still_remaining = [
                                it.item_id
                                for it in validated_items
                                if it.item_id not in deleted_set
                            ]
                            await await_cleanup_uninterruptibly(
                                self._persist_partial_remaining_items(task.task_id, still_remaining)
                            )
                        raise

                    skipped = tuple(outcome.skipped_items)
                    failed = tuple(outcome.failed_items)

                    if not failed:
                        await self._storage.delete_task(task.task_id)
                    else:
                        remain = len(failed)
                        await self._storage.retain_only_failed_transfer_items(
                            task.task_id,
                            [i.item_id for i in failed],
                        )
                        partial_msg = format_error_message(
                            ErrorCode.DELETE_PARTIAL, remain_count=remain
                        )
                        await update_task_fields(
                            self._storage,
                            task.task_id,
                            status=TaskStatus.DELETE_FAILED,
                            item_count=remain,
                            tg_send_eligible=False,
                            error_code=ErrorCode.DELETE_PARTIAL.value,
                            error_message=partial_msg,
                        )
        except YunBotError:
            raise
        except Exception as exc:
            LOGGER.warning(
                "Direct item deletion failed task=%s err=%s",
                task.task_id,
                redact_sensitive_text(str(exc)),
            )
            updated = await self._mark_delete_failed(task.task_id)
            remain = (
                updated.item_count
                if (updated is not None and updated.no_subdir and updated.item_count > 0)
                else 1
            )
            return TaskDeleteResult(
                deleted_record=False,
                status=TaskStatus.DELETE_FAILED,
                remain_count=remain,
                message=format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=remain),
            )

        if empty_res is not None:
            await self._notify_deleted(task, empty_res)
            return empty_res

        if not failed:
            await self._best_effort_refresh_openlist(task)
            lines = ["✅ 已删除任务记录及已确认归属的云端文件。"]
            if skipped:
                names = "、".join(i.name for i in skipped[:10])
                lines.append(
                    format_error_message(
                        ErrorCode.ITEM_SKIPPED,
                        skip_count=len(skipped),
                        names=names,
                    )
                )
            if task.transfer_uncertain:
                lines.append("⚠️ 该直存任务曾中断，若基准目录仍有未登记残留文件请人工核查。")
            res = TaskDeleteResult(
                deleted_record=True,
                status=None,
                skipped_items=skipped,
                uncertain_empty_warning=False,
                remain_count=0,
                message="\n".join(lines),
            )
            await self._notify_deleted(task, res)
            return res

        remain = len(failed)
        updated = await self._storage.get_task(task.task_id)
        if updated is not None and self._on_panel_update is not None:
            try:
                await self._on_panel_update(updated)
            except Exception:
                pass

        lines = [format_error_message(ErrorCode.DELETE_PARTIAL, remain_count=remain)]
        if skipped:
            names = "、".join(i.name for i in skipped[:10])
            lines.append(
                format_error_message(
                    ErrorCode.ITEM_SKIPPED,
                    skip_count=len(skipped),
                    names=names,
                )
            )
        return TaskDeleteResult(
            deleted_record=False,
            status=TaskStatus.DELETE_FAILED,
            skipped_items=skipped,
            uncertain_empty_warning=False,
            remain_count=remain,
            message="\n".join(lines),
        )
