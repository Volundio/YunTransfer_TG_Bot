"""Background maintenance & pruning loop (`Janitor`):
orphan temp-file cleanup, expired pending-input & Web session/OTT cleanup,
provider-agnostic low-frequency credential keepalive, WAL checkpointing,
and task-locked historical pruning with unexpired OpenList share revocation (§5.10.3, R04, R07).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from yunbot.models import (
    IN_FLIGHT_TASK_STATUSES,
    JANITOR_INTERVAL_SECONDS,
    MAX_RETAINED_TASKS,
    PENDING_INPUT_TTL_SECONDS,
    QUARK_KEEPALIVE_INTERVAL_SECONDS,
    TASK_ID_LENGTH,
    TG_LOCAL_UPLOAD_TIMEOUT_SECONDS,
    UNCERTAIN_TASK_RETENTION_SECONDS,
    BindingMismatchError,
    BootstrapConfigSnapshot,
    OpenListUnavailableError,
    ProviderAuthInvalidError,
    TaskRecord,
    TaskStatus,
    redact_sensitive_text,
)
from yunbot.providers.registry import ProviderRegistry
from yunbot.services.coordinator import TransferCoordinator, resolve_runtime_snapshot
from yunbot.services.delivery import DeliveryService

LOGGER = logging.getLogger(__name__)

_HEX_CHARS = frozenset("0123456789abcdef")


@runtime_checkable
class JanitorStorage(Protocol):
    """Persistence contract required by Janitor."""

    async def get_task(self, task_id: str) -> TaskRecord | None: ...

    async def delete_task(self, task_id: str) -> Any: ...

    async def count_non_inflight_tasks(self) -> int: ...

    async def list_prune_candidates(
        self,
        *,
        now: float,
        uncertain_retention_seconds: float,
        limit: int,
    ) -> Sequence[TaskRecord]: ...

    async def wal_checkpoint_truncate(self) -> Any: ...


@runtime_checkable
class JanitorOpenListClient(Protocol):
    """OpenList contract required by Janitor."""

    async def verify_task_bindings(self, task: TaskRecord) -> bool | None: ...

    async def revoke_share(self, share_id: str) -> Any: ...


async def _invoke_pending_cleanup(storage: Any, *, ttl_seconds: int, now: float) -> int:
    """Invoke storage expired pending_inputs cleanup matching its method/parameter names."""
    cutoff = now - float(ttl_seconds)
    for method_name in (
        "delete_expired_pending_inputs",
        "cleanup_expired_pending_inputs",
        "purge_expired_pending_inputs",
        "prune_expired_pending_inputs",
    ):
        fn = getattr(storage, method_name, None)
        if not callable(fn):
            continue
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        pos_args: list[Any] = []
        kw_args: dict[str, Any] = {}
        has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)

        for idx, p in enumerate(params):
            if p.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            pname = p.name.lower()
            if "ttl" in pname:
                val: Any = ttl_seconds
            elif pname in ("now", "current_time", "cur_now"):
                val = now
            elif "cutoff" in pname or "before" in pname or "expire" in pname:
                val = cutoff
            elif idx == 0:
                val = ttl_seconds
            elif idx == 1:
                val = now
            else:
                if p.default is not inspect.Parameter.empty:
                    continue
                val = None

            if p.kind == inspect.Parameter.KEYWORD_ONLY:
                kw_args[p.name] = val
            else:
                pos_args.append(val)

        if not pos_args and not kw_args and has_varkw:
            kw_args = {"ttl_seconds": ttl_seconds, "now": now}

        res = fn(*pos_args, **kw_args)
        if inspect.isawaitable(res):
            res = await res
        return int(res) if isinstance(res, int) else 0
    return 0


class Janitor:
    """Periodic background maintenance, keepalive, and task-locked pruning service."""

    def __init__(
        self,
        *,
        storage: JanitorStorage,
        coordinator: TransferCoordinator,
        registry: ProviderRegistry,
        runtime_config: Any = None,
        openlist: JanitorOpenListClient | None = None,
        bootstrap: BootstrapConfigSnapshot | None = None,
        upload_dir: str | Path | None = None,
        delivery: DeliveryService | None = None,
        web_auth_cleanup: Callable[[], Any] | None = None,
        membership_cleanup: Callable[[], Any] | None = None,
        interval_seconds: float = JANITOR_INTERVAL_SECONDS,
        keepalive_interval_seconds: float = QUARK_KEEPALIVE_INTERVAL_SECONDS,
        uncertain_retention_seconds: float = UNCERTAIN_TASK_RETENTION_SECONDS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        if keepalive_interval_seconds <= 0:
            raise ValueError("keepalive_interval_seconds must be positive")
        if uncertain_retention_seconds < 0:
            raise ValueError("uncertain_retention_seconds must be non-negative")

        raw_upload_dir = (
            upload_dir
            if upload_dir is not None
            else (bootstrap.shared_upload_dir if bootstrap is not None else None)
        )

        self._storage = storage
        self._coordinator = coordinator
        self._registry = registry
        self._runtime_config = runtime_config
        self._openlist = openlist
        self._upload_dir = Path(raw_upload_dir) if raw_upload_dir is not None else None
        self._delivery = delivery
        self._web_auth_cleanup = web_auth_cleanup
        self._membership_cleanup = membership_cleanup

        self._interval_seconds = interval_seconds
        self._keepalive_interval = keepalive_interval_seconds
        self._uncertain_retention = uncertain_retention_seconds

        self._last_keepalive_at: float | None = None
        self._stop_event = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None

    def set_collaborators(
        self,
        *,
        openlist: JanitorOpenListClient | None = None,
        delivery: DeliveryService | None = None,
        web_auth_cleanup: Callable[[], Any] | None = None,
        membership_cleanup: Callable[[], Any] | None = None,
    ) -> None:
        if openlist is not None:
            self._openlist = openlist
        if delivery is not None:
            self._delivery = delivery
        if web_auth_cleanup is not None:
            self._web_auth_cleanup = web_auth_cleanup
        if membership_cleanup is not None:
            self._membership_cleanup = membership_cleanup

    async def recover_on_startup(self) -> dict[str, int]:
        """Clear residual upload files on boot and delegate DB state self-healing (§5.10.1)."""
        removed_files = 0
        if self._upload_dir is not None:
            self._upload_dir.mkdir(parents=True, exist_ok=True)
            try:
                with os.scandir(self._upload_dir) as it:
                    entries = list(it)
                for entry in entries:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            Path(entry.path).unlink(missing_ok=True)
                            removed_files += 1
                    except OSError:
                        continue
            except OSError:
                pass

        recovered_tasks = 0
        for method_name in (
            "recover_interrupted_tasks",
            "startup_recover",
            "recover_on_startup",
        ):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                res = await fn()
                if isinstance(res, int):
                    recovered_tasks = res
                elif isinstance(res, dict):
                    recovered_tasks = sum(v for v in res.values() if isinstance(v, int))
                break

        return {
            "startup_upload_files_removed": removed_files,
            "startup_tasks_recovered": recovered_tasks,
        }

    async def start(self) -> None:
        if self._loop_task is not None and not self._loop_task.done():
            return
        self._stop_event.clear()
        self._loop_task = asyncio.create_task(self._run_loop(), name="yunbot-janitor-loop")

    async def stop(self) -> None:
        self._stop_event.set()
        task = self._loop_task
        self._loop_task = None
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self._interval_seconds)
                return
            except TimeoutError:
                pass
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.error(
                    "Janitor run_once iteration failed err=%s",
                    redact_sensitive_text(str(exc)),
                )

    async def _clean_orphan_uploads(self, cur_now: float) -> int:
        if self._upload_dir is None or not self._upload_dir.exists():
            return 0

        max_age = TG_LOCAL_UPLOAD_TIMEOUT_SECONDS * 2.0
        active_files = (
            self._delivery.active_temp_filenames() if self._delivery is not None else None
        )
        removed = 0
        try:
            with os.scandir(self._upload_dir) as it:
                entries = list(it)
        except OSError:
            return 0

        for entry in entries:
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue

            age = cur_now - st.st_mtime
            should_remove = False
            if age > max_age:
                should_remove = True
            elif active_files is not None:
                if entry.name not in active_files:
                    should_remove = True
            else:
                prefix = entry.name.split("_", 1)[0]
                if len(prefix) != TASK_ID_LENGTH or not all(ch in _HEX_CHARS for ch in prefix):
                    should_remove = True
                else:
                    task = await self._storage.get_task(prefix)
                    if task is None or task.status != TaskStatus.DELIVERING:
                        should_remove = True

            if should_remove:
                try:
                    Path(entry.path).unlink(missing_ok=True)
                    removed += 1
                except OSError:
                    continue
        return removed

    async def _run_optional_callback(self, cb: Callable[[], Any] | None, label: str) -> int:
        if cb is None:
            return 0
        try:
            res = cb()
            if inspect.isawaitable(res):
                res = await res
            return int(res) if isinstance(res, int) else 0
        except Exception as exc:
            LOGGER.warning(
                "Janitor %s callback failed err=%s",
                label,
                redact_sensitive_text(str(exc)),
            )
            return 0

    async def _maybe_run_provider_keepalives(self, cur_now: float) -> int:
        if (
            self._last_keepalive_at is not None
            and (cur_now - self._last_keepalive_at) < self._keepalive_interval
        ):
            return 0

        self._last_keepalive_at = cur_now
        executed = 0
        for provider in self._registry.all_providers():
            try:
                await provider.keepalive()
                executed += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.warning(
                    "Provider keepalive ignored error provider=%s err=%s",
                    provider.spec.provider_id,
                    redact_sensitive_text(str(exc)),
                )
        return executed

    async def _is_openlist_ready_and_matching(self, task: TaskRecord) -> bool:
        if self._openlist is None or not task.openlist_binding_id:
            return False
        if self._runtime_config is not None:
            snap = resolve_runtime_snapshot(self._runtime_config)
            if not snap.openlist_base_url.strip():
                return False
        is_enabled_attr = getattr(self._openlist, "is_enabled", None)
        if is_enabled_attr is not None:
            enabled = is_enabled_attr() if callable(is_enabled_attr) else bool(is_enabled_attr)
            if not enabled:
                return False

        verifier = getattr(self._openlist, "verify_task_bindings", None)
        if callable(verifier):
            try:
                res = await verifier(task)
                if res is False:
                    return False
            except (BindingMismatchError, ProviderAuthInvalidError, OpenListUnavailableError):
                return False
            except Exception as exc:
                LOGGER.warning(
                    "OpenList binding check failed during prune task=%s err=%s",
                    task.task_id,
                    redact_sensitive_text(str(exc)),
                )
                return False
        return True

    async def _prune_excess_tasks(self, cur_now: float, max_retained: int) -> int:
        total = await self._storage.count_non_inflight_tasks()
        if total <= max_retained:
            return 0

        excess = total - max_retained
        candidates = await self._storage.list_prune_candidates(
            now=cur_now,
            uncertain_retention_seconds=self._uncertain_retention,
            limit=excess + 32,
        )

        pruned = 0
        for cand in candidates:
            if pruned >= excess:
                break
            if await self._storage.count_non_inflight_tasks() <= max_retained:
                break

            async with self._coordinator.acquire_task_lock(cand.task_id):
                fresh = await self._storage.get_task(cand.task_id)
                if fresh is None or fresh.status in IN_FLIGHT_TASK_STATUSES:
                    continue

                if (fresh.status == TaskStatus.DELETE_FAILED or fresh.transfer_uncertain) and (
                    cur_now - fresh.updated_at
                ) < self._uncertain_retention:
                    continue

                has_unexpired_share = bool(fresh.openlist_share_id) and (
                    fresh.openlist_share_expires_at is None
                    or fresh.openlist_share_expires_at > cur_now
                )
                if has_unexpired_share:
                    assert fresh.openlist_share_id is not None
                    if not await self._is_openlist_ready_and_matching(fresh):
                        # Retain until natural share expiry when binding changed or OpenList down
                        continue
                    assert self._openlist is not None
                    try:
                        revoked = await self._openlist.revoke_share(fresh.openlist_share_id)
                        if revoked is False:
                            continue
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        LOGGER.warning(
                            "Retaining task=%s this round because revoke_share failed err=%s",
                            fresh.task_id,
                            redact_sensitive_text(str(exc)),
                        )
                        continue

                await self._storage.delete_task(fresh.task_id)
                pruned += 1

        return pruned

    async def run_once(self, *, now: float | None = None) -> dict[str, int]:
        """Execute one deterministic maintenance pass."""
        cur_now = time.time() if now is None else float(now)

        pending_ttl = PENDING_INPUT_TTL_SECONDS
        max_retained = MAX_RETAINED_TASKS
        if self._runtime_config is not None:
            snap = resolve_runtime_snapshot(self._runtime_config)
            pending_ttl = snap.pending_input_ttl_seconds
            max_retained = snap.max_retained_tasks

        orphan_files_removed = await self._clean_orphan_uploads(cur_now)
        expired_pending_removed = await _invoke_pending_cleanup(
            self._storage,
            ttl_seconds=pending_ttl,
            now=cur_now,
        )
        web_cleaned = await self._run_optional_callback(self._web_auth_cleanup, "web_auth_cleanup")
        membership_cleaned = await self._run_optional_callback(
            self._membership_cleanup,
            "membership_cleanup",
        )
        keepalive_executed = await self._maybe_run_provider_keepalives(cur_now)
        pruned_tasks = await self._prune_excess_tasks(cur_now, max_retained)

        checkpoint_fn = getattr(self._storage, "wal_checkpoint_truncate", None)
        if callable(checkpoint_fn):
            await checkpoint_fn()

        return {
            "orphan_files_removed": orphan_files_removed,
            "expired_pending_removed": expired_pending_removed,
            "web_auth_cleaned": web_cleaned,
            "membership_cleaned": membership_cleaned,
            "keepalive_executed": keepalive_executed,
            "pruned_tasks": pruned_tasks,
        }
