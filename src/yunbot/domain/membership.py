"""Bounded positive/negative LRU cache and concurrency-limited group membership prober (§5.3).

Strict Dependency Boundary:
Depends ONLY on Python 3.12 standard library and `models`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Sequence

from yunbot.models import (
    GROUP_MEMBER_CACHE_MAXSIZE,
    GROUP_MEMBER_CACHE_TTL_SECONDS,
    GROUP_PROBE_CONCURRENCY,
    MAX_GROUP_WHITELIST_COUNT,
)

logger = logging.getLogger(__name__)


class GroupMembershipProber:
    """Probes and caches whether a Telegram user belongs to any whitelisted group."""

    def __init__(
        self,
        probe_member: Callable[[int, int], Awaitable[bool]],
        *,
        ttl_seconds: int = GROUP_MEMBER_CACHE_TTL_SECONDS,
        maxsize: int = GROUP_MEMBER_CACHE_MAXSIZE,
        concurrency: int = GROUP_PROBE_CONCURRENCY,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if maxsize <= 0:
            raise ValueError("maxsize must be positive")
        if concurrency <= 0:
            raise ValueError("concurrency must be positive")

        self._probe_member = probe_member
        self._ttl_seconds = float(ttl_seconds)
        self._maxsize = int(maxsize)
        self._concurrency = int(concurrency)
        self._clock = clock
        self._semaphore = asyncio.Semaphore(self._concurrency)
        # Maps (chat_id, user_id) -> (is_member, expires_at) in LRU order.
        self._cache: OrderedDict[tuple[int, int], tuple[bool, float]] = OrderedDict()

    def _get_cached(self, chat_id: int, user_id: int, now: float) -> bool | None:
        key = (chat_id, user_id)
        entry = self._cache.get(key)
        if entry is None:
            return None
        is_member, expires_at = entry
        if now >= expires_at:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return is_member

    def _put_cached(self, chat_id: int, user_id: int, is_member: bool, now: float) -> None:
        key = (chat_id, user_id)
        expires_at = now + self._ttl_seconds
        if key in self._cache:
            self._cache[key] = (is_member, expires_at)
            self._cache.move_to_end(key)
            return

        if len(self._cache) >= self._maxsize:
            self.prune_expired(now=now)
            while len(self._cache) >= self._maxsize:
                self._cache.popitem(last=False)

        self._cache[key] = (is_member, expires_at)

    def prune_expired(self, *, now: float | None = None) -> int:
        """Evict all expired cache entries and return count of evicted entries."""
        ts = self._clock() if now is None else now
        expired_keys = [key for key, (_, expires_at) in self._cache.items() if ts >= expires_at]
        for key in expired_keys:
            del self._cache[key]
        return len(expired_keys)

    def invalidate(self, chat_id: int | None = None, user_id: int | None = None) -> None:
        """Invalidate cached membership entries matching chat_id and/or user_id."""
        if chat_id is None and user_id is None:
            self._cache.clear()
            return

        keys_to_remove = [
            (cid, uid)
            for (cid, uid) in self._cache
            if (chat_id is None or cid == chat_id) and (user_id is None or uid == user_id)
        ]
        for key in keys_to_remove:
            del self._cache[key]

    def clear(self) -> None:
        """Clear all cached positive and negative membership entries."""
        self._cache.clear()

    async def is_member_of_any_group(self, user_id: int, group_ids: Sequence[int]) -> bool:
        """Check if `user_id` belongs to any group in `group_ids[:MAX_GROUP_WHITELIST_COUNT]`."""
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
            return False
        if not group_ids:
            return False

        # Enforce hard cap on configured whitelist groups while preserving order and uniqueness.
        bounded_groups = list(dict.fromkeys(group_ids[:MAX_GROUP_WHITELIST_COUNT]))
        now = self._clock()

        uncached_groups: list[int] = []
        for chat_id in bounded_groups:
            cached = self._get_cached(chat_id, user_id, now)
            if cached is True:
                return True
            if cached is None:
                uncached_groups.append(chat_id)

        if not uncached_groups:
            return False

        found_event = asyncio.Event()

        async def _probe_single(chat_id: int) -> bool:
            if found_event.is_set():
                return False
            async with self._semaphore:
                if found_event.is_set():
                    return False
                rechecked = self._get_cached(chat_id, user_id, self._clock())
                if rechecked is not None:
                    if rechecked:
                        found_event.set()
                    return rechecked

                try:
                    result = bool(await self._probe_member(chat_id, user_id))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.debug(
                        "Group membership probe failed for chat_id=%s user_id=%s",
                        chat_id,
                        user_id,
                        exc_info=True,
                    )
                    result = False

                self._put_cached(chat_id, user_id, result, self._clock())
                if result:
                    found_event.set()
                return result

        tasks: set[asyncio.Task[bool]] = {
            asyncio.create_task(_probe_single(cid)) for cid in uncached_groups
        }
        try:
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for finished in done:
                    if finished.result() is True:
                        return True
            return False
        finally:
            remaining = [t for t in tasks if not t.done()]
            if remaining:
                for t in remaining:
                    t.cancel()
                await asyncio.gather(*remaining, return_exceptions=True)
