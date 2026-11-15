"""Access control policy (`Admin > Blacklist > Whitelist/Open`) and list management (§5.3).

Strict Dependency Boundary:
Depends ONLY on Python 3.12 standard library, `models`, and `membership`
(uses Protocol / duck-typed access to `storage` and `runtime_config`).
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from yunbot.domain.membership import GroupMembershipProber
from yunbot.models import (
    MAX_GROUP_WHITELIST_COUNT,
    AccessEntry,
    AccessListType,
    ErrorCode,
    GroupWhitelistEntry,
    RuntimeSettingsSnapshot,
)


@runtime_checkable
class AccessStore(Protocol):
    """Persistence contract for `access_list` and `group_whitelist` tables."""

    async def get_access_entry(self, user_id: int) -> AccessEntry | None: ...

    async def upsert_access_entry(self, entry: AccessEntry) -> None: ...

    async def delete_access_entry(self, user_id: int) -> bool: ...

    async def list_access_entries(
        self, list_type: AccessListType | None = None
    ) -> Sequence[AccessEntry]: ...

    async def list_group_whitelist(self) -> Sequence[GroupWhitelistEntry]: ...

    async def upsert_group_whitelist(self, entry: GroupWhitelistEntry) -> None: ...

    async def delete_group_whitelist(self, chat_id: int) -> bool: ...


@runtime_checkable
class AccessConfigReader(Protocol):
    """Read-only runtime configuration snapshot contract."""

    def snapshot(self) -> RuntimeSettingsSnapshot: ...


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """Outcome of an authorization check across private or group chats."""

    allowed: bool
    error_code: ErrorCode | None = None
    reason: str = ""


def _validate_positive_user_id(user_id: int) -> int:
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("user_id must be a positive integer")
    return user_id


def _validate_negative_group_id(chat_id: int) -> int:
    if isinstance(chat_id, bool) or not isinstance(chat_id, int) or chat_id >= 0:
        raise ValueError("Group chat_id must be a negative integer")
    return chat_id


def _coerce_list_type(raw: Any) -> AccessListType | None:
    if raw is None:
        return None
    if isinstance(raw, AccessEntry):
        return raw.list_type
    if isinstance(raw, AccessListType):
        return raw
    if isinstance(raw, str):
        return AccessListType(raw)
    list_type_attr = getattr(raw, "list_type", None)
    if list_type_attr is not None:
        return AccessListType(list_type_attr)
    return None


class AccessController:
    """Enforces `Admin > Blacklist (one-vote veto) > Whitelist / Open` authorization."""

    def __init__(
        self,
        storage: Any,
        runtime_config: Any,
        membership: GroupMembershipProber,
        *,
        admin_id: int,
    ) -> None:
        self._admin_id = _validate_positive_user_id(admin_id)
        self._storage = storage
        self._runtime_config = runtime_config
        self._membership = membership

    @property
    def admin_id(self) -> int:
        return self._admin_id

    def is_admin(self, user_id: int) -> bool:
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            return False
        return user_id == self._admin_id

    def can_manage_task(self, operator_id: int, task_user_id: int) -> bool:
        """Return True iff `operator_id` is the task initiator or the administrator (§4.1)."""
        if isinstance(operator_id, bool) or not isinstance(operator_id, int) or operator_id <= 0:
            return False
        return operator_id == task_user_id or operator_id == self._admin_id

    def _is_whitelist_enabled(self) -> bool:
        snap_fn = getattr(self._runtime_config, "snapshot", None)
        if callable(snap_fn):
            snap = snap_fn()
            return bool(snap.whitelist_enabled)
        return bool(getattr(self._runtime_config, "whitelist_enabled", True))

    async def _get_user_list_type(self, user_id: int) -> AccessListType | None:
        for method_name in ("get_access_entry", "get_user_access", "get_access_list_type"):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                res = await fn(user_id)
                return _coerce_list_type(res)

        list_fn = getattr(self._storage, "list_access_entries", None)
        if callable(list_fn):
            entries = await list_fn()
            for entry in entries:
                if getattr(entry, "user_id", None) == user_id:
                    return _coerce_list_type(entry)
        raise AttributeError("Storage does not implement get_access_entry")

    async def _list_group_ids(self) -> list[int]:
        for method_name in (
            "list_group_whitelist_ids",
            "list_group_whitelist",
            "list_group_whitelist_entries",
        ):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                rows = await fn()
                result: list[int] = []
                for row in rows:
                    if isinstance(row, int) and not isinstance(row, bool):
                        result.append(row)
                    else:
                        result.append(int(row.chat_id))
                return result
        raise AttributeError("Storage does not implement list_group_whitelist")

    async def _is_group_whitelisted(self, chat_id: int) -> bool:
        direct_fn = getattr(self._storage, "is_group_whitelisted", None)
        if callable(direct_fn):
            return bool(await direct_fn(chat_id))
        get_fn = getattr(self._storage, "get_group_whitelist_entry", None)
        if callable(get_fn):
            return (await get_fn(chat_id)) is not None
        group_ids = await self._list_group_ids()
        return chat_id in group_ids

    async def check_access(
        self,
        *,
        user_id: int,
        chat_id: int,
        chat_type: str,
    ) -> AccessDecision:
        """Evaluate access strictly in order: Admin -> Blacklist -> Open/Whitelist."""
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
            return AccessDecision(
                allowed=False,
                error_code=ErrorCode.ACCESS_DENIED,
                reason="invalid_user",
            )

        # 1. Admin always passes.
        if user_id == self._admin_id:
            return AccessDecision(allowed=True, reason="admin")

        # 2. Blacklist is a one-vote veto across both private and group chats (even in open mode).
        user_list_type = await self._get_user_list_type(user_id)
        if user_list_type == AccessListType.BLACKLIST:
            return AccessDecision(
                allowed=False,
                error_code=ErrorCode.ACCESS_DENIED,
                reason="blacklist",
            )

        # 3. Open mode (whitelist disabled).
        if not self._is_whitelist_enabled():
            return AccessDecision(allowed=True, reason="open_mode")

        # 4. Whitelist mode.
        normalized_chat_type = (chat_type or "").lower()
        if normalized_chat_type in ("group", "supergroup"):
            if user_list_type == AccessListType.WHITELIST:
                return AccessDecision(allowed=True, reason="user_whitelist")
            if isinstance(chat_id, int) and not isinstance(chat_id, bool) and chat_id < 0:
                if await self._is_group_whitelisted(chat_id):
                    return AccessDecision(allowed=True, reason="group_whitelist")
            return AccessDecision(
                allowed=False,
                error_code=ErrorCode.ACCESS_DENIED,
                reason="not_whitelisted",
            )

        if normalized_chat_type == "private":
            if user_list_type == AccessListType.WHITELIST:
                return AccessDecision(allowed=True, reason="user_whitelist")
            group_ids = await self._list_group_ids()
            if group_ids and await self._membership.is_member_of_any_group(user_id, group_ids):
                return AccessDecision(allowed=True, reason="group_member")
            return AccessDecision(
                allowed=False,
                error_code=ErrorCode.ACCESS_DENIED,
                reason="not_whitelisted",
            )

        return AccessDecision(
            allowed=False,
            error_code=ErrorCode.ACCESS_DENIED,
            reason="unsupported_chat_type",
        )

    async def _persist_access_entry(self, entry: AccessEntry) -> None:
        for method_name in ("upsert_access_entry", "set_access_entry", "save_access_entry"):
            fn = getattr(self._storage, method_name, None)
            if not callable(fn):
                continue
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
            if has_varargs or (len(params) == 1 and params[0].name not in ("user_id", "list_type")):
                await fn(entry)
                return

            kwargs: dict[str, Any] = {}
            args: list[Any] = []
            field_map = {
                "user_id": entry.user_id,
                "list_type": entry.list_type,
                "created_by": entry.created_by,
                "operator_id": entry.created_by,
                "actor_id": entry.created_by,
                "created_at": entry.created_at,
                "now": entry.created_at,
            }
            for p in params:
                if p.name in field_map:
                    if p.kind == inspect.Parameter.POSITIONAL_ONLY:
                        args.append(field_map[p.name])
                    else:
                        kwargs[p.name] = field_map[p.name]
            await fn(*args, **kwargs)
            return
        raise AttributeError("Storage does not implement upsert_access_entry")

    def _resolve_actor(self, created_by: int | None, operator_id: int | None) -> int:
        raw = created_by if created_by is not None else operator_id
        return self._admin_id if raw is None else _validate_positive_user_id(raw)

    async def add_whitelist(
        self,
        user_id: int,
        created_by: int | None = None,
        *,
        operator_id: int | None = None,
        now: float | None = None,
    ) -> AccessEntry:
        """Add or move `user_id` into the user whitelist."""
        uid = _validate_positive_user_id(user_id)
        actor = self._resolve_actor(created_by, operator_id)
        ts = time.time() if now is None else float(now)
        entry = AccessEntry(
            user_id=uid,
            list_type=AccessListType.WHITELIST,
            created_at=ts,
            created_by=actor,
        )
        await self._persist_access_entry(entry)
        return entry

    async def add_blacklist(
        self,
        user_id: int,
        created_by: int | None = None,
        *,
        operator_id: int | None = None,
        now: float | None = None,
    ) -> AccessEntry:
        """Add or move `user_id` into the blacklist (admin is strictly prohibited)."""
        uid = _validate_positive_user_id(user_id)
        if uid == self._admin_id:
            raise ValueError("Cannot add admin to blacklist")
        actor = self._resolve_actor(created_by, operator_id)
        ts = time.time() if now is None else float(now)
        entry = AccessEntry(
            user_id=uid,
            list_type=AccessListType.BLACKLIST,
            created_at=ts,
            created_by=actor,
        )
        await self._persist_access_entry(entry)
        return entry

    async def add_user(
        self,
        user_id: int,
        list_type: AccessListType | str,
        *,
        operator_id: int | None = None,
        created_by: int | None = None,
        now: float | None = None,
    ) -> AccessEntry:
        """Unified user list mutation helper (`WHITELIST` or `BLACKLIST`) for Web panel."""
        lt = AccessListType(list_type)
        if lt == AccessListType.BLACKLIST:
            return await self.add_blacklist(user_id, created_by, operator_id=operator_id, now=now)
        return await self.add_whitelist(user_id, created_by, operator_id=operator_id, now=now)

    async def remove_user(
        self,
        user_id: int,
        *,
        operator_id: int | None = None,
        list_type: AccessListType | None = None,
    ) -> bool:
        """Remove `user_id` from `access_list` (whitelist or blacklist)."""
        _ = (operator_id, list_type)
        uid = _validate_positive_user_id(user_id)
        for method_name in ("delete_access_entry", "remove_access_entry"):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                res = await fn(uid)
                return True if res is None else bool(res)
        raise AttributeError("Storage does not implement delete_access_entry")

    async def add_group(
        self,
        chat_id: int,
        created_by: int | None = None,
        *,
        operator_id: int | None = None,
        now: float | None = None,
    ) -> GroupWhitelistEntry:
        """Add negative `chat_id` to `group_whitelist`, enforcing `MAX_GROUP_WHITELIST_COUNT`."""
        gid = _validate_negative_group_id(chat_id)
        actor = self._resolve_actor(created_by, operator_id)
        existing_ids = await self._list_group_ids()
        if gid not in existing_ids and len(existing_ids) >= MAX_GROUP_WHITELIST_COUNT:
            raise ValueError(f"Group whitelist limit ({MAX_GROUP_WHITELIST_COUNT}) reached")

        ts = time.time() if now is None else float(now)
        entry = GroupWhitelistEntry(chat_id=gid, created_at=ts, created_by=actor)

        persisted = False
        for method_name in (
            "upsert_group_whitelist",
            "upsert_group_whitelist_entry",
            "add_group_whitelist",
        ):
            fn = getattr(self._storage, method_name, None)
            if not callable(fn):
                continue
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
            if has_varargs or (len(params) == 1 and params[0].name != "chat_id"):
                await fn(entry)
            else:
                kwargs: dict[str, Any] = {}
                args: list[Any] = []
                field_map = {
                    "chat_id": entry.chat_id,
                    "created_by": entry.created_by,
                    "operator_id": entry.created_by,
                    "actor_id": entry.created_by,
                    "created_at": entry.created_at,
                    "now": entry.created_at,
                }
                for p in params:
                    if p.name in field_map:
                        if p.kind == inspect.Parameter.POSITIONAL_ONLY:
                            args.append(field_map[p.name])
                        else:
                            kwargs[p.name] = field_map[p.name]
                await fn(*args, **kwargs)
            persisted = True
            break

        if not persisted:
            raise AttributeError("Storage does not implement upsert_group_whitelist")

        self._membership.invalidate(chat_id=gid)
        return entry

    async def remove_group(
        self,
        chat_id: int,
        *,
        operator_id: int | None = None,
    ) -> bool:
        """Remove `chat_id` from `group_whitelist` and invalidate its membership cache."""
        _ = operator_id
        gid = _validate_negative_group_id(chat_id)
        for method_name in (
            "delete_group_whitelist",
            "delete_group_whitelist_entry",
            "remove_group_whitelist",
        ):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                res = await fn(gid)
                self._membership.invalidate(chat_id=gid)
                return True if res is None else bool(res)
        raise AttributeError("Storage does not implement delete_group_whitelist")

    async def reset_to_initial(
        self,
        *,
        operator_id: int | None = None,
        updated_by: int | None = None,
    ) -> None:
        """Reset access lists to initial bootstrap values and clear membership cache."""
        actor = self._resolve_actor(updated_by, operator_id)
        reset_fn = getattr(self._runtime_config, "reset_access_lists_to_initial", None)
        if callable(reset_fn):
            await reset_fn(updated_by=actor)
            self._membership.clear()
            return
        storage_reset_fn = getattr(self._storage, "reset_access_lists", None)
        if callable(storage_reset_fn):
            await storage_reset_fn()
            self._membership.clear()
            return
        raise AttributeError("RuntimeConfig does not implement reset_access_lists_to_initial")

    async def list_access_entries(
        self, list_type: AccessListType | None = None
    ) -> list[AccessEntry]:
        """List user access entries, optionally filtered by `list_type`."""
        return await self.list_users(list_type)

    async def list_group_whitelist(self) -> list[GroupWhitelistEntry]:
        """List all whitelisted group entries."""
        return await self.list_groups()

    async def list_users(self, list_type: AccessListType | None = None) -> list[AccessEntry]:
        """List user access entries, optionally filtered by `list_type`."""
        fn = getattr(self._storage, "list_access_entries", None)
        if not callable(fn):
            raise AttributeError("Storage does not implement list_access_entries")
        sig = inspect.signature(fn)
        if len(sig.parameters) >= 1 and list_type is not None:
            rows = await fn(list_type)
        else:
            rows = await fn()
            if list_type is not None:
                rows = [r for r in rows if r.list_type == list_type]
        return list(rows)

    async def list_groups(self) -> list[GroupWhitelistEntry]:
        """List all whitelisted group entries."""
        for method_name in ("list_group_whitelist", "list_group_whitelist_entries"):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                rows = await fn()
                return [
                    r
                    if isinstance(r, GroupWhitelistEntry)
                    else GroupWhitelistEntry(
                        chat_id=int(r), created_at=0.0, created_by=self._admin_id
                    )
                    for r in rows
                ]
        raise AttributeError("Storage does not implement list_group_whitelist")
