"""SQLite WAL storage engine with 8 tables, incremental migrations, and crash recovery (§5.10, §6).

Strict Dependency Boundary:
Imports only the Python 3.12 standard library, ``aiosqlite``, and ``models``.
Satisfies ``CredentialStore`` and ``SnapshotStore`` structurally without importing ``providers``.
Never awaits external HTTP, CLI subprocesses, or upper-layer locks inside SQLite transactions.
"""

from __future__ import annotations

import asyncio
import shutil
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from enum import StrEnum
from pathlib import Path
from typing import Any

import aiosqlite

from yunbot.models import (
    MAX_GROUP_WHITELIST_COUNT,
    MAX_SNAPSHOT_ITEMS_PER_PHASE,
    TASK_DIR_REGEX,
    UNCERTAIN_TASK_RETENTION_SECONDS,
    AccessEntry,
    AccessListType,
    EnumLimitExceededError,
    ErrorCode,
    GroupWhitelistEntry,
    PendingInputRecord,
    ProviderCredentialRecord,
    SnapshotPhase,
    SnapshotTempEntry,
    TaskRecord,
    TaskStatus,
    TransferItemRecord,
    TransferredEntry,
    YunBotError,
    await_cleanup_uninterruptibly,
    normalize_posix_path,
    restore_task_cancellations,
    run_uninterruptible,
)

LATEST_SCHEMA_VERSION: int = 1
_SQL_CHUNK_SIZE: int = 400

_V1_DDL_STATEMENTS: tuple[str, ...] = (
    # 1. Dynamic system configuration & OpenList binding epochs
    """
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL,
        updated_at REAL NOT NULL,
        updated_by INTEGER NOT NULL
    )
    """,
    # 2. Mutually exclusive user whitelist / blacklist
    """
    CREATE TABLE IF NOT EXISTS access_list (
        user_id INTEGER PRIMARY KEY NOT NULL CHECK (user_id > 0),
        list_type TEXT NOT NULL CHECK (list_type IN ('whitelist', 'blacklist')),
        created_at REAL NOT NULL,
        created_by INTEGER NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_access_list_type ON access_list(list_type)",
    # 3. Group whitelist (negative Telegram chat IDs)
    """
    CREATE TABLE IF NOT EXISTS group_whitelist (
        chat_id INTEGER PRIMARY KEY NOT NULL CHECK (chat_id < 0),
        created_at REAL NOT NULL,
        created_by INTEGER NOT NULL
    )
    """,
    # 4. Cloud provider credentials & stable account bindings
    """
    CREATE TABLE IF NOT EXISTS provider_credentials (
        provider TEXT PRIMARY KEY NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT NOT NULL DEFAULT '',
        account_binding_id TEXT NOT NULL,
        extra_json TEXT NOT NULL DEFAULT '{}',
        updated_at REAL NOT NULL
    )
    """,
    # 5. Pending two-step link / password assembly state
    """
    CREATE TABLE IF NOT EXISTS pending_inputs (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL CHECK (user_id > 0),
        provider_hint TEXT,
        url TEXT,
        external_id TEXT,
        code TEXT,
        no_subdir INTEGER NOT NULL DEFAULT 0 CHECK (no_subdir IN (0, 1)),
        prompt_message_id INTEGER,
        updated_at REAL NOT NULL,
        PRIMARY KEY (chat_id, user_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_pending_inputs_updated_at ON pending_inputs(updated_at)",
    # 6. Transfer tasks master table with strict invariant CHECK constraints
    """
    CREATE TABLE IF NOT EXISTS transfer_tasks (
        task_id TEXT PRIMARY KEY NOT NULL,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL CHECK (user_id > 0),
        provider TEXT NOT NULL,
        account_binding_id TEXT NOT NULL,
        openlist_binding_id TEXT,
        share_title TEXT NOT NULL,
        base_save_path TEXT NOT NULL,
        openlist_base_path TEXT,
        no_subdir INTEGER NOT NULL DEFAULT 0 CHECK (no_subdir IN (0, 1)),
        task_dir_path TEXT,
        status TEXT NOT NULL CHECK (
            status IN (
                'queued',
                'transferring',
                'ready',
                'partial',
                'delivering',
                'deleting',
                'delete_failed',
                'failed'
            )
        ),
        delivery_prev_status TEXT CHECK (
            delivery_prev_status IN ('ready', 'partial')
        ),
        transfer_uncertain INTEGER NOT NULL DEFAULT 0 CHECK (transfer_uncertain IN (0, 1)),
        remote_task_ref TEXT,
        item_count INTEGER NOT NULL DEFAULT 0,
        tg_send_eligible INTEGER NOT NULL DEFAULT 0 CHECK (tg_send_eligible IN (0, 1)),
        openlist_share_id TEXT,
        openlist_share_expires_at REAL,
        error_code TEXT,
        error_message TEXT,
        panel_message_id INTEGER,
        panel_closed INTEGER NOT NULL DEFAULT 0 CHECK (panel_closed IN (0, 1)),
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        CHECK (
            (no_subdir = 0 AND task_dir_path IS NOT NULL)
            OR (
                no_subdir = 1
                AND task_dir_path IS NULL
                AND openlist_share_id IS NULL
                AND openlist_share_expires_at IS NULL
            )
        ),
        CHECK (
            (status = 'delivering' AND delivery_prev_status IS NOT NULL)
            OR (status != 'delivering' AND delivery_prev_status IS NULL)
        ),
        CHECK (
            (openlist_binding_id IS NOT NULL AND openlist_base_path IS NOT NULL)
            OR (
                openlist_binding_id IS NULL
                AND openlist_base_path IS NULL
                AND openlist_share_id IS NULL
                AND openlist_share_expires_at IS NULL
                AND tg_send_eligible = 0
            )
        )
    )
    """,
    (
        "CREATE INDEX IF NOT EXISTS idx_transfer_tasks_user_created "
        "ON transfer_tasks(user_id, created_at DESC)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS idx_transfer_tasks_status_created "
        "ON transfer_tasks(status, created_at DESC)"
    ),
    (
        "CREATE INDEX IF NOT EXISTS idx_transfer_tasks_dir_path "
        "ON transfer_tasks(provider, account_binding_id, task_dir_path) "
        "WHERE task_dir_path IS NOT NULL"
    ),
    # 7. Confirmed top-level entries for -n direct mode
    """
    CREATE TABLE IF NOT EXISTS transfer_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL REFERENCES transfer_tasks(task_id) ON DELETE CASCADE,
        item_id TEXT NOT NULL,
        path TEXT NOT NULL,
        name TEXT NOT NULL,
        is_dir INTEGER NOT NULL CHECK (is_dir IN (0, 1)),
        UNIQUE (task_id, item_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_transfer_items_task_id ON transfer_items(task_id)",
    "CREATE INDEX IF NOT EXISTS idx_transfer_items_item_id ON transfer_items(item_id)",
    # 8. Bounded temporary directory snapshot diff table for PikPak -n mode
    """
    CREATE TABLE IF NOT EXISTS snapshot_temp_items (
        task_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('before', 'after')),
        item_id TEXT NOT NULL,
        name TEXT NOT NULL,
        is_dir INTEGER NOT NULL CHECK (is_dir IN (0, 1)),
        PRIMARY KEY (task_id, phase, item_id)
    )
    """,
)


async def _migrate_v1(conn: aiosqlite.Connection) -> None:
    """Create initial v1 8-table schema and indexes inside the migration transaction."""
    for stmt in _V1_DDL_STATEMENTS:
        await conn.execute(stmt)


_MIGRATIONS: dict[int, Callable[[aiosqlite.Connection], Awaitable[None]]] = {
    1: _migrate_v1,
}

_TASK_BOOLEAN_COLUMNS: frozenset[str] = frozenset(
    {"no_subdir", "transfer_uncertain", "tg_send_eligible", "panel_closed"}
)

_UPDATABLE_TASK_COLUMNS: frozenset[str] = frozenset(
    {
        "account_binding_id",
        "openlist_binding_id",
        "share_title",
        "base_save_path",
        "openlist_base_path",
        "no_subdir",
        "task_dir_path",
        "status",
        "delivery_prev_status",
        "transfer_uncertain",
        "remote_task_ref",
        "item_count",
        "tg_send_eligible",
        "openlist_share_id",
        "openlist_share_expires_at",
        "error_code",
        "error_message",
        "panel_message_id",
        "panel_closed",
        "updated_at",
    }
)


def _row_to_task(row: aiosqlite.Row) -> TaskRecord:
    prev_raw = row["delivery_prev_status"]
    return TaskRecord(
        task_id=row["task_id"],
        chat_id=int(row["chat_id"]),
        user_id=int(row["user_id"]),
        provider=row["provider"],
        account_binding_id=row["account_binding_id"],
        openlist_binding_id=row["openlist_binding_id"],
        share_title=row["share_title"],
        base_save_path=row["base_save_path"],
        openlist_base_path=row["openlist_base_path"],
        no_subdir=bool(row["no_subdir"]),
        task_dir_path=row["task_dir_path"],
        status=TaskStatus(row["status"]),
        delivery_prev_status=TaskStatus(prev_raw) if prev_raw is not None else None,
        transfer_uncertain=bool(row["transfer_uncertain"]),
        remote_task_ref=row["remote_task_ref"],
        item_count=int(row["item_count"]),
        tg_send_eligible=bool(row["tg_send_eligible"]),
        openlist_share_id=row["openlist_share_id"],
        openlist_share_expires_at=(
            float(row["openlist_share_expires_at"])
            if row["openlist_share_expires_at"] is not None
            else None
        ),
        error_code=row["error_code"],
        error_message=row["error_message"],
        panel_message_id=(
            int(row["panel_message_id"]) if row["panel_message_id"] is not None else None
        ),
        panel_closed=bool(row["panel_closed"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


def _clear_directory_contents(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for child in directory.iterdir():
        if child.is_symlink() or child.is_file():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            shutil.rmtree(child, ignore_errors=True)


class SQLiteStorage:
    """Async SQLite WAL persistence engine satisfying CredentialStore and SnapshotStore."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._conn: aiosqlite.Connection | None = None
        self._op_lock = asyncio.Lock()

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("SQLiteStorage is not initialized or already closed")
        return self._conn

    @staticmethod
    async def _exec_boundary_sql(conn: aiosqlite.Connection, sql: str) -> None:
        cur = await conn.execute(sql)
        await cur.close()

    @staticmethod
    async def _drain_and_rollback(conn: aiosqlite.Connection) -> None:
        """Wait for any queued SQL on `conn`'s worker thread to settle, then rollback if open."""
        async with conn.execute("SELECT 1"):
            pass
        if conn.in_transaction:
            cur = await conn.execute("ROLLBACK")
            await cur.close()

    @asynccontextmanager
    async def _write_tx(self) -> AsyncIterator[aiosqlite.Connection]:
        """Serialize write transactions on the shared connection without external I/O."""
        async with self._op_lock:
            conn = self._require_conn()
            cur_task = asyncio.current_task()
            if cur_task is not None and cur_task.cancelling() > 0:
                await asyncio.sleep(0)

            _, begin_cancel, _, begin_absorbed = await run_uninterruptible(
                self._exec_boundary_sql(conn, "BEGIN IMMEDIATE")
            )
            if begin_cancel is not None:
                _, _, _, rb_absorbed = await run_uninterruptible(self._drain_and_rollback(conn))
                restore_task_cancellations(begin_absorbed + rb_absorbed)
                raise begin_cancel

            try:
                yield conn
            except BaseException:
                _, _, _, rb_absorbed = await run_uninterruptible(self._drain_and_rollback(conn))
                restore_task_cancellations(rb_absorbed)
                raise
            else:
                cur_task = asyncio.current_task()
                if cur_task is not None and cur_task.cancelling() > 0:
                    _, _, _, rb_absorbed = await run_uninterruptible(self._drain_and_rollback(conn))
                    restore_task_cancellations(rb_absorbed)
                    await asyncio.sleep(0)
                try:
                    await run_uninterruptible(self._exec_boundary_sql(conn, "COMMIT"))
                except BaseException:
                    _, _, _, rb_absorbed = await run_uninterruptible(self._drain_and_rollback(conn))
                    restore_task_cancellations(rb_absorbed)
                    raise

    async def initialize(
        self,
        *,
        upload_temp_dir: str | Path | None = None,
    ) -> dict[str, int]:
        """Connect SQLite WAL, apply PRAGMA user_version migrations, and run crash recovery."""
        async with self._op_lock:
            if self._conn is not None:
                old_conn = self._conn
                self._conn = None
                await await_cleanup_uninterruptibly(old_conn.close())

            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            if upload_temp_dir is not None:
                _clear_directory_contents(Path(upload_temp_dir))

            conn = await aiosqlite.connect(self._db_path, isolation_level=None)
            try:
                conn.row_factory = aiosqlite.Row
                await conn.execute("PRAGMA foreign_keys = ON")
                await conn.execute("PRAGMA journal_mode = WAL")
                await conn.execute("PRAGMA synchronous = NORMAL")
                await conn.execute("PRAGMA busy_timeout = 5000")

                await self._apply_migrations_unlocked(conn)
                recovered = await self._run_crash_recovery_unlocked(conn)
            except BaseException:
                await await_cleanup_uninterruptibly(conn.close())
                raise

            self._conn = conn
            return recovered

    async def _apply_migrations_unlocked(self, conn: aiosqlite.Connection) -> None:
        async with conn.execute("PRAGMA user_version") as cur:
            row = await cur.fetchone()
            current_version = int(row[0]) if row is not None else 0

        if current_version > LATEST_SCHEMA_VERSION:
            raise RuntimeError(
                f"Database user_version {current_version} is newer than supported "
                f"schema version {LATEST_SCHEMA_VERSION}"
            )

        for target_version in range(current_version + 1, LATEST_SCHEMA_VERSION + 1):
            migration_fn = _MIGRATIONS.get(target_version)
            if migration_fn is None:
                raise RuntimeError(f"Missing migration handler for version {target_version}")
            await conn.execute("BEGIN IMMEDIATE")
            try:
                await migration_fn(conn)
                await conn.execute(f"PRAGMA user_version = {target_version}")
            except BaseException:
                if conn.in_transaction:
                    await conn.execute("ROLLBACK")
                raise
            else:
                await conn.execute("COMMIT")

    async def _run_crash_recovery_unlocked(self, conn: aiosqlite.Connection) -> dict[str, int]:
        """Execute §5.10.1 exact startup self-healing in a single SQLite transaction."""
        now = time.time()
        await conn.execute("BEGIN IMMEDIATE")
        try:
            # 1. Clear leftover temporary directory snapshots
            await conn.execute("DELETE FROM snapshot_temp_items")

            # 2. queued -> failed (transfer_uncertain=0)
            cur = await conn.execute(
                """
                UPDATE transfer_tasks
                SET status = 'failed',
                    delivery_prev_status = NULL,
                    transfer_uncertain = 0,
                    tg_send_eligible = 0,
                    error_code = ?,
                    error_message = '服务重启中断',
                    updated_at = ?
                WHERE status = 'queued'
                """,
                (ErrorCode.INTERNAL_ERROR.value, now),
            )
            recovered_queued = max(cur.rowcount, 0)

            # 3. transferring -> failed (preserve transfer_items & task_dir_path; -n => uncertain=1)
            cur = await conn.execute(
                """
                UPDATE transfer_tasks
                SET status = 'failed',
                    delivery_prev_status = NULL,
                    transfer_uncertain = CASE WHEN no_subdir = 1 THEN 1 ELSE transfer_uncertain END,
                    tg_send_eligible = 0,
                    error_code = ?,
                    error_message = '服务重启中断',
                    updated_at = ?
                WHERE status = 'transferring'
                """,
                (ErrorCode.INTERNAL_ERROR.value, now),
            )
            recovered_transferring = max(cur.rowcount, 0)

            # 4. delivering -> restore directly from delivery_prev_status (never infer error_code)
            cur = await conn.execute(
                """
                UPDATE transfer_tasks
                SET status = CASE
                        WHEN delivery_prev_status IN ('ready', 'partial') THEN delivery_prev_status
                        ELSE 'failed'
                    END,
                    tg_send_eligible = CASE
                        WHEN delivery_prev_status IN ('ready', 'partial') THEN tg_send_eligible
                        ELSE 0
                    END,
                    error_code = CASE
                        WHEN delivery_prev_status IN ('ready', 'partial') THEN error_code
                        ELSE ?
                    END,
                    error_message = CASE
                        WHEN delivery_prev_status IN ('ready', 'partial') THEN error_message
                        ELSE '服务重启中断'
                    END,
                    delivery_prev_status = NULL,
                    updated_at = ?
                WHERE status = 'delivering'
                """,
                (ErrorCode.INTERNAL_ERROR.value, now),
            )
            recovered_delivering = max(cur.rowcount, 0)

            # 5. deleting -> delete_failed (tg_send_eligible=0)
            cur = await conn.execute(
                """
                UPDATE transfer_tasks
                SET status = 'delete_failed',
                    delivery_prev_status = NULL,
                    tg_send_eligible = 0,
                    error_code = ?,
                    error_message = '删除操作因服务重启中断，请重试删除',
                    updated_at = ?
                WHERE status = 'deleting'
                """,
                (ErrorCode.DELETE_PARTIAL.value, now),
            )
            recovered_deleting = max(cur.rowcount, 0)
        except BaseException:
            if conn.in_transaction:
                await conn.execute("ROLLBACK")
            raise
        else:
            await conn.execute("COMMIT")

        return {
            "queued": recovered_queued,
            "transferring": recovered_transferring,
            "delivering": recovered_delivering,
            "deleting": recovered_deleting,
        }

    async def get_schema_version(self) -> int:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute("PRAGMA user_version") as cur:
                row = await cur.fetchone()
                return int(row[0]) if row is not None else 0

    async def checkpoint_and_close(self) -> None:
        """Run PASSIVE WAL checkpoint and close the SQLite connection on shutdown (§4.1)."""
        async with self._op_lock:
            if self._conn is None:
                return
            conn = self._conn
            self._conn = None
            try:
                cur = await conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
                await cur.close()
            finally:
                await await_cleanup_uninterruptibly(conn.close())

    async def wal_checkpoint_truncate(self) -> None:
        """Run TRUNCATE WAL checkpoint during idle janitor maintenance (§5.10.3)."""
        async with self._op_lock:
            conn = self._require_conn()
            await conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    # ==========================================================================
    # 1. system_settings CRUD
    # ==========================================================================

    async def get_setting(self, key: str) -> str | None:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                "SELECT value FROM system_settings WHERE key = ?",
                (key,),
            ) as cur:
                row = await cur.fetchone()
                return str(row["value"]) if row is not None else None

    async def get_all_settings(self) -> dict[str, str]:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute("SELECT key, value FROM system_settings") as cur:
                rows = await cur.fetchall()
                return {str(row["key"]): str(row["value"]) for row in rows}

    async def set_settings(self, updates: Mapping[str, str], *, updated_by: int) -> None:
        if not updates:
            return
        now = time.time()
        params = [(str(k), str(v), now, int(updated_by)) for k, v in updates.items()]
        async with self._write_tx() as conn:
            await conn.executemany(
                """
                INSERT INTO system_settings (key, value, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                params,
            )

    # ==========================================================================
    # 2 & 3. access_list and group_whitelist CRUD
    # ==========================================================================

    async def get_access_entry(self, user_id: int) -> AccessEntry | None:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                "SELECT user_id, list_type, created_at, created_by "
                "FROM access_list WHERE user_id = ?",
                (user_id,),
            ) as cur:
                row = await cur.fetchone()
                if row is None:
                    return None
                return AccessEntry(
                    user_id=int(row["user_id"]),
                    list_type=AccessListType(row["list_type"]),
                    created_at=float(row["created_at"]),
                    created_by=int(row["created_by"]),
                )

    async def list_access_entries(
        self, list_type: AccessListType | None = None
    ) -> list[AccessEntry]:
        async with self._op_lock:
            conn = self._require_conn()
            if list_type is None:
                sql = (
                    "SELECT user_id, list_type, created_at, created_by "
                    "FROM access_list ORDER BY created_at ASC, user_id ASC"
                )
                params: tuple[Any, ...] = ()
            else:
                lt = AccessListType(list_type)
                sql = (
                    "SELECT user_id, list_type, created_at, created_by "
                    "FROM access_list WHERE list_type = ? ORDER BY created_at ASC, user_id ASC"
                )
                params = (lt.value,)
            async with conn.execute(sql, params) as cur:
                rows = await cur.fetchall()
                return [
                    AccessEntry(
                        user_id=int(r["user_id"]),
                        list_type=AccessListType(r["list_type"]),
                        created_at=float(r["created_at"]),
                        created_by=int(r["created_by"]),
                    )
                    for r in rows
                ]

    async def upsert_access_entry(
        self,
        user_id: int,
        list_type: AccessListType,
        *,
        created_by: int,
    ) -> None:
        if isinstance(user_id, bool) or user_id <= 0:
            raise ValueError("user_id must be a positive integer")
        lt = AccessListType(list_type)
        now = time.time()
        async with self._write_tx() as conn:
            await conn.execute(
                """
                INSERT INTO access_list (user_id, list_type, created_at, created_by)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    list_type = excluded.list_type,
                    created_at = excluded.created_at,
                    created_by = excluded.created_by
                """,
                (user_id, lt.value, now, int(created_by)),
            )

    async def remove_access_entry(self, user_id: int) -> bool:
        async with self._write_tx() as conn:
            cur = await conn.execute("DELETE FROM access_list WHERE user_id = ?", (user_id,))
            return cur.rowcount > 0

    async def list_group_whitelist(self) -> list[GroupWhitelistEntry]:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                "SELECT chat_id, created_at, created_by "
                "FROM group_whitelist ORDER BY created_at ASC, chat_id ASC"
            ) as cur:
                rows = await cur.fetchall()
                return [
                    GroupWhitelistEntry(
                        chat_id=int(r["chat_id"]),
                        created_at=float(r["created_at"]),
                        created_by=int(r["created_by"]),
                    )
                    for r in rows
                ]

    async def add_group_whitelist(self, chat_id: int, *, created_by: int) -> None:
        if isinstance(chat_id, bool) or chat_id >= 0:
            raise ValueError("Group chat_id must be a negative integer")
        now = time.time()
        async with self._write_tx() as conn:
            async with conn.execute(
                "SELECT 1 FROM group_whitelist WHERE chat_id = ?", (chat_id,)
            ) as cur:
                exists = await cur.fetchone() is not None

            if not exists:
                async with conn.execute("SELECT COUNT(*) FROM group_whitelist") as cur:
                    count_row = await cur.fetchone()
                    current_count = int(count_row[0]) if count_row is not None else 0
                if current_count >= MAX_GROUP_WHITELIST_COUNT:
                    raise ValueError(
                        f"Group whitelist cannot exceed {MAX_GROUP_WHITELIST_COUNT} groups"
                    )

            await conn.execute(
                """
                INSERT INTO group_whitelist (chat_id, created_at, created_by)
                VALUES (?, ?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET
                    created_at = excluded.created_at,
                    created_by = excluded.created_by
                """,
                (chat_id, now, int(created_by)),
            )

    async def remove_group_whitelist(self, chat_id: int) -> bool:
        async with self._write_tx() as conn:
            cur = await conn.execute("DELETE FROM group_whitelist WHERE chat_id = ?", (chat_id,))
            return cur.rowcount > 0

    async def replace_seeded_access_lists(
        self,
        *,
        whitelist_ids: Sequence[int],
        blacklist_ids: Sequence[int],
        group_ids: Sequence[int],
        admin_id: int,
        created_by: int,
    ) -> None:
        """Replace access lists from initial IDs (blacklist wins; admin never blacklisted)."""
        merged_users: dict[int, AccessListType] = {}
        for uid in whitelist_ids:
            if isinstance(uid, bool) or uid <= 0:
                raise ValueError("whitelist user_id must be a positive integer")
            merged_users[int(uid)] = AccessListType.WHITELIST

        for uid in blacklist_ids:
            if isinstance(uid, bool) or uid <= 0:
                raise ValueError("blacklist user_id must be a positive integer")
            if int(uid) == admin_id:
                continue
            merged_users[int(uid)] = AccessListType.BLACKLIST

        unique_groups: list[int] = []
        seen_groups: set[int] = set()
        for gid in group_ids:
            if isinstance(gid, bool) or gid >= 0:
                raise ValueError("group chat_id must be a negative integer")
            gid_int = int(gid)
            if gid_int not in seen_groups:
                seen_groups.add(gid_int)
                unique_groups.append(gid_int)

        if len(unique_groups) > MAX_GROUP_WHITELIST_COUNT:
            raise ValueError(
                f"Group whitelist count ({len(unique_groups)}) exceeds {MAX_GROUP_WHITELIST_COUNT}"
            )

        now = time.time()
        actor = int(created_by)
        async with self._write_tx() as conn:
            await conn.execute("DELETE FROM access_list")
            await conn.execute("DELETE FROM group_whitelist")
            if merged_users:
                await conn.executemany(
                    """
                    INSERT INTO access_list (user_id, list_type, created_at, created_by)
                    VALUES (?, ?, ?, ?)
                    """,
                    [(uid, lt.value, now, actor) for uid, lt in merged_users.items()],
                )
            if unique_groups:
                await conn.executemany(
                    """
                    INSERT INTO group_whitelist (chat_id, created_at, created_by)
                    VALUES (?, ?, ?)
                    """,
                    [(gid, now, actor) for gid in unique_groups],
                )
            await conn.execute(
                """
                INSERT INTO system_settings (key, value, updated_at, updated_by)
                VALUES ('seeded_access_lists', '1', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (now, actor),
            )

    # ==========================================================================
    # 4. provider_credentials (CredentialStore Protocol)
    # ==========================================================================

    async def get_credential(self, provider: str) -> ProviderCredentialRecord | None:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                """
                SELECT provider, access_token, refresh_token,
                       account_binding_id, extra_json, updated_at
                FROM provider_credentials
                WHERE provider = ?
                """,
                (provider,),
            ) as cur:
                row = await cur.fetchone()
                if row is None:
                    return None
                return ProviderCredentialRecord(
                    provider=str(row["provider"]),
                    access_token=str(row["access_token"]),
                    refresh_token=str(row["refresh_token"]),
                    account_binding_id=str(row["account_binding_id"]),
                    extra_json=str(row["extra_json"]),
                    updated_at=float(row["updated_at"]),
                )

    async def upsert_credential(self, record: ProviderCredentialRecord) -> None:
        async with self._write_tx() as conn:
            await conn.execute(
                """
                INSERT INTO provider_credentials (
                    provider, access_token, refresh_token,
                    account_binding_id, extra_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider) DO UPDATE SET
                    access_token = excluded.access_token,
                    refresh_token = excluded.refresh_token,
                    account_binding_id = excluded.account_binding_id,
                    extra_json = excluded.extra_json,
                    updated_at = excluded.updated_at
                """,
                (
                    record.provider,
                    record.access_token,
                    record.refresh_token,
                    record.account_binding_id,
                    record.extra_json,
                    float(record.updated_at),
                ),
            )

    async def delete_credential(self, provider: str) -> None:
        async with self._write_tx() as conn:
            await conn.execute("DELETE FROM provider_credentials WHERE provider = ?", (provider,))

    # ==========================================================================
    # 5. pending_inputs CRUD
    # ==========================================================================

    async def get_pending_input(self, chat_id: int, user_id: int) -> PendingInputRecord | None:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                """
                SELECT chat_id, user_id, provider_hint, url, external_id, code,
                       no_subdir, prompt_message_id, updated_at
                FROM pending_inputs
                WHERE chat_id = ? AND user_id = ?
                """,
                (chat_id, user_id),
            ) as cur:
                row = await cur.fetchone()
                if row is None:
                    return None
                return PendingInputRecord(
                    chat_id=int(row["chat_id"]),
                    user_id=int(row["user_id"]),
                    provider_hint=row["provider_hint"],
                    url=row["url"],
                    external_id=row["external_id"],
                    code=row["code"],
                    no_subdir=bool(row["no_subdir"]),
                    prompt_message_id=(
                        int(row["prompt_message_id"])
                        if row["prompt_message_id"] is not None
                        else None
                    ),
                    updated_at=float(row["updated_at"]),
                )

    async def upsert_pending_input(self, record: PendingInputRecord) -> None:
        async with self._write_tx() as conn:
            await conn.execute(
                """
                INSERT INTO pending_inputs (
                    chat_id, user_id, provider_hint, url, external_id, code,
                    no_subdir, prompt_message_id, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(chat_id, user_id) DO UPDATE SET
                    provider_hint = excluded.provider_hint,
                    url = excluded.url,
                    external_id = excluded.external_id,
                    code = excluded.code,
                    no_subdir = excluded.no_subdir,
                    prompt_message_id = excluded.prompt_message_id,
                    updated_at = excluded.updated_at
                """,
                (
                    int(record.chat_id),
                    int(record.user_id),
                    record.provider_hint,
                    record.url,
                    record.external_id,
                    record.code,
                    int(bool(record.no_subdir)),
                    record.prompt_message_id,
                    float(record.updated_at),
                ),
            )

    async def delete_pending_input(self, chat_id: int, user_id: int) -> None:
        async with self._write_tx() as conn:
            await conn.execute(
                "DELETE FROM pending_inputs WHERE chat_id = ? AND user_id = ?",
                (chat_id, user_id),
            )

    async def cleanup_expired_pending_inputs(self, cutoff_ts: float) -> int:
        async with self._write_tx() as conn:
            cur = await conn.execute(
                "DELETE FROM pending_inputs WHERE updated_at <= ?",
                (float(cutoff_ts),),
            )
            return max(cur.rowcount, 0)

    # ==========================================================================
    # 6 & 7. transfer_tasks and transfer_items CRUD + R01 Exclusion
    # ==========================================================================

    async def _get_task_unlocked(
        self, conn: aiosqlite.Connection, task_id: str
    ) -> TaskRecord | None:
        async with conn.execute(
            "SELECT * FROM transfer_tasks WHERE task_id = ?", (task_id,)
        ) as cur:
            row = await cur.fetchone()
            return _row_to_task(row) if row is not None else None

    async def create_task(self, task: TaskRecord) -> None:
        async with self._write_tx() as conn:
            await conn.execute(
                """
                INSERT INTO transfer_tasks (
                    task_id, chat_id, user_id, provider, account_binding_id,
                    openlist_binding_id, share_title, base_save_path, openlist_base_path,
                    no_subdir, task_dir_path, status, delivery_prev_status,
                    transfer_uncertain, remote_task_ref, item_count, tg_send_eligible,
                    openlist_share_id, openlist_share_expires_at, error_code,
                    error_message, panel_message_id, panel_closed, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.task_id,
                    int(task.chat_id),
                    int(task.user_id),
                    task.provider,
                    task.account_binding_id,
                    task.openlist_binding_id,
                    task.share_title,
                    task.base_save_path,
                    task.openlist_base_path,
                    int(bool(task.no_subdir)),
                    task.task_dir_path,
                    task.status.value,
                    task.delivery_prev_status.value if task.delivery_prev_status else None,
                    int(bool(task.transfer_uncertain)),
                    task.remote_task_ref,
                    int(task.item_count),
                    int(bool(task.tg_send_eligible)),
                    task.openlist_share_id,
                    task.openlist_share_expires_at,
                    task.error_code,
                    task.error_message,
                    task.panel_message_id,
                    int(bool(task.panel_closed)),
                    float(task.created_at),
                    float(task.updated_at),
                ),
            )

    async def get_task(self, task_id: str) -> TaskRecord | None:
        async with self._op_lock:
            conn = self._require_conn()
            return await self._get_task_unlocked(conn, task_id)

    async def list_tasks(
        self,
        *,
        user_id: int | None = None,
        status: TaskStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[TaskRecord], int]:
        clauses: list[str] = []
        params: list[Any] = []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(int(user_id))
        if status is not None:
            st = TaskStatus(status)
            clauses.append("status = ?")
            params.append(st.value)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                f"SELECT COUNT(*) FROM transfer_tasks {where_sql}",
                tuple(params),
            ) as cur:
                count_row = await cur.fetchone()
                total = int(count_row[0]) if count_row is not None else 0

            async with conn.execute(
                f"SELECT * FROM transfer_tasks {where_sql} "
                "ORDER BY created_at DESC, task_id ASC LIMIT ? OFFSET ?",
                (*params, int(limit), int(offset)),
            ) as cur:
                rows = await cur.fetchall()
                return [_row_to_task(r) for r in rows], total

    async def update_task_fields(self, task_id: str, **fields: Any) -> TaskRecord | None:
        if not fields:
            return await self.get_task(task_id)

        unknown = set(fields) - _UPDATABLE_TASK_COLUMNS
        if unknown:
            raise ValueError(f"Unsupported transfer_tasks update columns: {sorted(unknown)}")

        updates: dict[str, Any] = {}
        for col, val in fields.items():
            if col in _TASK_BOOLEAN_COLUMNS and val is not None:
                updates[col] = int(bool(val))
            elif isinstance(val, StrEnum):
                updates[col] = val.value
            else:
                updates[col] = val

        if "updated_at" not in updates:
            updates["updated_at"] = time.time()

        set_clause = ", ".join(f"{col} = ?" for col in updates)
        params = (*updates.values(), task_id)

        async with self._write_tx() as conn:
            await conn.execute(
                f"UPDATE transfer_tasks SET {set_clause} WHERE task_id = ?",
                params,
            )
            return await self._get_task_unlocked(conn, task_id)

    async def enter_delivering(self, task_id: str) -> TaskRecord:
        """Atomically transition ready/partial eligible task into delivering (§5.9.1)."""
        now = time.time()
        async with self._write_tx() as conn:
            cur = await conn.execute(
                """
                UPDATE transfer_tasks
                SET delivery_prev_status = status,
                    status = 'delivering',
                    updated_at = ?
                WHERE task_id = ?
                  AND status IN ('ready', 'partial')
                  AND tg_send_eligible = 1
                """,
                (now, task_id),
            )
            if cur.rowcount == 0:
                raise YunBotError(ErrorCode.TASK_BUSY, task_id=task_id)
            task = await self._get_task_unlocked(conn, task_id)
            assert task is not None
            return task

    async def restore_from_delivering(self, task_id: str) -> TaskRecord | None:
        """Atomically restore status from delivery_prev_status when status == 'delivering'."""
        now = time.time()
        async with self._write_tx() as conn:
            await conn.execute(
                """
                UPDATE transfer_tasks
                SET status = CASE
                        WHEN delivery_prev_status IN ('ready', 'partial') THEN delivery_prev_status
                        ELSE 'failed'
                    END,
                    delivery_prev_status = NULL,
                    updated_at = ?
                WHERE task_id = ?
                  AND status = 'delivering'
                """,
                (now, task_id),
            )
            return await self._get_task_unlocked(conn, task_id)

    async def enter_deleting(self, task_id: str) -> TaskRecord:
        """Transition deletable task into deleting and clear tg_send_eligible (§5.10.2)."""
        now = time.time()
        async with self._write_tx() as conn:
            cur = await conn.execute(
                """
                UPDATE transfer_tasks
                SET status = 'deleting',
                    tg_send_eligible = 0,
                    updated_at = ?
                WHERE task_id = ?
                  AND status IN ('ready', 'partial', 'failed', 'delete_failed')
                """,
                (now, task_id),
            )
            if cur.rowcount == 0:
                raise YunBotError(ErrorCode.TASK_BUSY, task_id=task_id)
            task = await self._get_task_unlocked(conn, task_id)
            assert task is not None
            return task

    async def delete_task(self, task_id: str) -> bool:
        async with self._write_tx() as conn:
            await conn.execute("DELETE FROM snapshot_temp_items WHERE task_id = ?", (task_id,))
            cur = await conn.execute("DELETE FROM transfer_tasks WHERE task_id = ?", (task_id,))
            return cur.rowcount > 0

    async def append_transfer_items_batch(
        self,
        task_id: str,
        entries: Sequence[TransferredEntry],
    ) -> list[TransferredEntry]:
        """Enforce R01 cross-task exclusion and persist accepted -n items in a short tx."""
        normalized_candidates: list[TransferredEntry] = []
        seen_batch_ids: set[str] = set()
        for entry in entries:
            norm_path = normalize_posix_path(entry.path, allow_root=False)
            if entry.item_id in seen_batch_ids:
                continue
            seen_batch_ids.add(entry.item_id)
            normalized_candidates.append(
                TransferredEntry(
                    item_id=str(entry.item_id),
                    path=norm_path,
                    name=str(entry.name),
                    is_dir=bool(entry.is_dir),
                )
            )

        now = time.time()
        async with self._write_tx() as conn:
            async with conn.execute(
                """
                SELECT provider, account_binding_id, base_save_path
                FROM transfer_tasks
                WHERE task_id = ?
                """,
                (task_id,),
            ) as cur:
                owner_row = await cur.fetchone()
                if owner_row is None:
                    raise ValueError(f"Unknown task_id: {task_id}")
                provider = str(owner_row["provider"])
                account_binding_id = str(owner_row["account_binding_id"])

            if not normalized_candidates:
                return []

            # (a1) Exclude candidate paths claimed as task_dir_path by other tasks on same account
            claimed_dir_paths: set[str] = set()
            candidate_paths = [c.path for c in normalized_candidates]
            for i in range(0, len(candidate_paths), _SQL_CHUNK_SIZE):
                chunk = candidate_paths[i : i + _SQL_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                async with conn.execute(
                    f"""
                    SELECT task_dir_path
                    FROM transfer_tasks
                    WHERE provider = ?
                      AND account_binding_id = ?
                      AND task_id != ?
                      AND task_dir_path IN ({placeholders})
                    """,
                    (provider, account_binding_id, task_id, *chunk),
                ) as cur:
                    for row in await cur.fetchall():
                        if row["task_dir_path"] is not None:
                            claimed_dir_paths.add(str(row["task_dir_path"]))

            # (a2) Exclude TASK_DIR_REGEX names whose task_id suffix exists in transfer_tasks
            existing_suffix_task_ids: set[str] = set()
            suffix_candidates = list(
                {
                    c.name.split("_", 1)[1]
                    for c in normalized_candidates
                    if TASK_DIR_REGEX.fullmatch(c.name)
                }
            )
            for i in range(0, len(suffix_candidates), _SQL_CHUNK_SIZE):
                chunk = suffix_candidates[i : i + _SQL_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                async with conn.execute(
                    f"SELECT task_id FROM transfer_tasks WHERE task_id IN ({placeholders})",
                    tuple(chunk),
                ) as cur:
                    for row in await cur.fetchall():
                        existing_suffix_task_ids.add(str(row["task_id"]))

            # (b) Exclude item_ids already owned by another task on the same provider & account
            claimed_item_ids: set[str] = set()
            candidate_ids = [c.item_id for c in normalized_candidates]
            for i in range(0, len(candidate_ids), _SQL_CHUNK_SIZE):
                chunk = candidate_ids[i : i + _SQL_CHUNK_SIZE]
                placeholders = ",".join("?" for _ in chunk)
                async with conn.execute(
                    f"""
                    SELECT DISTINCT ti.item_id
                    FROM transfer_items ti
                    JOIN transfer_tasks tt ON tt.task_id = ti.task_id
                    WHERE tt.task_id != ?
                      AND tt.provider = ?
                      AND tt.account_binding_id = ?
                      AND ti.item_id IN ({placeholders})
                    """,
                    (task_id, provider, account_binding_id, *chunk),
                ) as cur:
                    for row in await cur.fetchall():
                        claimed_item_ids.add(str(row["item_id"]))

            accepted: list[TransferredEntry] = []
            for candidate in normalized_candidates:
                if candidate.path in claimed_dir_paths:
                    continue
                if (
                    TASK_DIR_REGEX.fullmatch(candidate.name)
                    and candidate.name.split("_", 1)[1] in existing_suffix_task_ids
                ):
                    continue
                if candidate.item_id in claimed_item_ids:
                    continue
                accepted.append(candidate)

            if accepted:
                await conn.executemany(
                    """
                    INSERT OR IGNORE INTO transfer_items (task_id, item_id, path, name, is_dir)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (task_id, item.item_id, item.path, item.name, int(item.is_dir))
                        for item in accepted
                    ],
                )

            await conn.execute(
                """
                UPDATE transfer_tasks
                SET item_count = (SELECT COUNT(*) FROM transfer_items WHERE task_id = ?),
                    updated_at = ?
                WHERE task_id = ?
                """,
                (task_id, now, task_id),
            )
            return accepted

    async def list_transfer_items(self, task_id: str) -> list[TransferItemRecord]:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                """
                SELECT id, task_id, item_id, path, name, is_dir
                FROM transfer_items
                WHERE task_id = ?
                ORDER BY id ASC
                """,
                (task_id,),
            ) as cur:
                rows = await cur.fetchall()
                return [
                    TransferItemRecord(
                        id=int(r["id"]),
                        task_id=str(r["task_id"]),
                        item_id=str(r["item_id"]),
                        path=str(r["path"]),
                        name=str(r["name"]),
                        is_dir=bool(r["is_dir"]),
                    )
                    for r in rows
                ]

    async def retain_only_failed_transfer_items(
        self,
        task_id: str,
        failed_item_ids: Sequence[str],
    ) -> None:
        keep_set = {str(item_id) for item_id in failed_item_ids}
        now = time.time()
        async with self._write_tx() as conn:
            if not keep_set:
                await conn.execute("DELETE FROM transfer_items WHERE task_id = ?", (task_id,))
            else:
                async with conn.execute(
                    "SELECT id, item_id FROM transfer_items WHERE task_id = ?",
                    (task_id,),
                ) as cur:
                    rows = await cur.fetchall()
                delete_row_ids = [int(r["id"]) for r in rows if str(r["item_id"]) not in keep_set]
                for i in range(0, len(delete_row_ids), _SQL_CHUNK_SIZE):
                    chunk = delete_row_ids[i : i + _SQL_CHUNK_SIZE]
                    placeholders = ",".join("?" for _ in chunk)
                    await conn.execute(
                        f"DELETE FROM transfer_items WHERE id IN ({placeholders})",
                        tuple(chunk),
                    )

            await conn.execute(
                """
                UPDATE transfer_tasks
                SET item_count = (SELECT COUNT(*) FROM transfer_items WHERE task_id = ?),
                    updated_at = ?
                WHERE task_id = ?
                """,
                (task_id, now, task_id),
            )

    async def count_non_inflight_tasks(self) -> int:
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                """
                SELECT COUNT(*)
                FROM transfer_tasks
                WHERE status NOT IN ('queued', 'transferring', 'delivering', 'deleting')
                """
            ) as cur:
                row = await cur.fetchone()
                return int(row[0]) if row is not None else 0

    async def list_prune_candidates(
        self,
        *,
        now: float,
        uncertain_retention_seconds: float = UNCERTAIN_TASK_RETENTION_SECONDS,
        limit: int = 200,
    ) -> list[TaskRecord]:
        """List prunable non-in-flight tasks, protecting young uncertain/delete_failed tasks."""
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                """
                SELECT *
                FROM transfer_tasks
                WHERE status NOT IN ('queued', 'transferring', 'delivering', 'deleting')
                  AND (
                      (status != 'delete_failed' AND transfer_uncertain = 0)
                      OR (? - updated_at >= ?)
                  )
                ORDER BY
                  CASE
                      WHEN (status != 'delete_failed' AND transfer_uncertain = 0) THEN 0
                      ELSE 1
                  END ASC,
                  created_at ASC,
                  task_id ASC
                LIMIT ?
                """,
                (float(now), float(uncertain_retention_seconds), int(limit)),
            ) as cur:
                rows = await cur.fetchall()
                return [_row_to_task(r) for r in rows]

    # ==========================================================================
    # 8. snapshot_temp_items (SnapshotStore Protocol)
    # ==========================================================================

    async def clear_task_snapshots(self, task_id: str) -> None:
        async with self._write_tx() as conn:
            await conn.execute("DELETE FROM snapshot_temp_items WHERE task_id = ?", (task_id,))

    async def insert_snapshot_batch(
        self,
        task_id: str,
        phase: str,
        items: Sequence[SnapshotTempEntry],
        *,
        max_per_phase: int = MAX_SNAPSHOT_ITEMS_PER_PHASE,
    ) -> int:
        """Insert a snapshot page while strictly enforcing max_per_phase before commit."""
        phase_val = SnapshotPhase(phase).value
        if max_per_phase < 0:
            raise ValueError("max_per_phase must be >= 0")

        deduped: list[SnapshotTempEntry] = []
        seen_ids: set[str] = set()
        for entry in items:
            if entry.item_id not in seen_ids:
                seen_ids.add(entry.item_id)
                deduped.append(entry)

        if len(deduped) > max_per_phase:
            raise EnumLimitExceededError(
                f"Snapshot batch size {len(deduped)} exceeds phase limit {max_per_phase}"
            )

        async with self._write_tx() as conn:
            async with conn.execute(
                "SELECT COUNT(*) FROM snapshot_temp_items WHERE task_id = ? AND phase = ?",
                (task_id, phase_val),
            ) as cur:
                row = await cur.fetchone()
                existing_count = int(row[0]) if row is not None else 0

            if existing_count > max_per_phase:
                raise EnumLimitExceededError(
                    f"Snapshot items {existing_count} exceeded phase limit {max_per_phase}"
                )

            if deduped:
                await conn.executemany(
                    """
                    INSERT OR IGNORE INTO snapshot_temp_items (
                        task_id, phase, item_id, name, is_dir
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (task_id, phase_val, str(it.item_id), str(it.name), int(bool(it.is_dir)))
                        for it in deduped
                    ],
                )

            async with conn.execute(
                "SELECT COUNT(*) FROM snapshot_temp_items WHERE task_id = ? AND phase = ?",
                (task_id, phase_val),
            ) as cur:
                row = await cur.fetchone()
                new_total = int(row[0]) if row is not None else 0

            if new_total > max_per_phase:
                raise EnumLimitExceededError(
                    f"Snapshot items {new_total} exceeded phase limit {max_per_phase}"
                )
            return new_total

    async def fetch_added_snapshot_page(
        self,
        task_id: str,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> list[SnapshotTempEntry]:
        """Paginated SQL LEFT JOIN diff returning items present in 'after' but not 'before'."""
        async with self._op_lock:
            conn = self._require_conn()
            async with conn.execute(
                """
                SELECT a.item_id, a.name, a.is_dir
                FROM snapshot_temp_items a
                LEFT JOIN snapshot_temp_items b
                  ON b.task_id = a.task_id
                 AND b.phase = 'before'
                 AND b.item_id = a.item_id
                WHERE a.task_id = ?
                  AND a.phase = 'after'
                  AND b.item_id IS NULL
                ORDER BY a.item_id
                LIMIT ? OFFSET ?
                """,
                (task_id, int(limit), int(offset)),
            ) as cur:
                rows = await cur.fetchall()
                return [
                    SnapshotTempEntry(
                        item_id=str(r["item_id"]),
                        name=str(r["name"]),
                        is_dir=bool(r["is_dir"]),
                    )
                    for r in rows
                ]
