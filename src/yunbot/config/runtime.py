"""Dynamic runtime configuration center, validation, and OpenList binding epochs (§3.3, §5.4).

Strict Dependency Boundary:
Imports only stdlib, ``models``, ``bootstrap_config``, and ``storage``.
Structurally satisfies ``ProviderConfigReader`` without importing ``providers``.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Mapping
from typing import Any

from yunbot.config.bootstrap import (
    parse_bounded_int,
    parse_http_url,
    parse_strict_bool,
    validate_clean_string,
    validate_log_level,
)
from yunbot.models import (
    MAX_DELIVERY_FILES_MAX,
    MAX_DELIVERY_FILES_MIN,
    MAX_RETAINED_TASKS_MAX,
    MAX_RETAINED_TASKS_MIN,
    MAX_TEMP_DISK_MB_MAX,
    MAX_TEMP_DISK_MB_MIN,
    OPENLIST_SHARE_TTL_HOURS_MAX,
    OPENLIST_SHARE_TTL_HOURS_MIN,
    PENDING_INPUT_TTL_SECONDS_MAX,
    PENDING_INPUT_TTL_SECONDS_MIN,
    BootstrapConfigSnapshot,
    RuntimeSettingsSnapshot,
    normalize_posix_path,
    validate_save_path,
)
from yunbot.storage import SQLiteStorage

BUILTIN_PROVIDER_IDS: tuple[str, ...] = ("baidu", "pikpak", "quark")

MUTABLE_SETTING_KEYS: frozenset[str] = frozenset(
    {
        "WHITELIST_ENABLED",
        "OPENLIST_BASE_URL",
        "OPENLIST_PUBLIC_URL",
        "OPENLIST_TOKEN",
        "OPENLIST_USERNAME",
        "OPENLIST_PASSWORD",
        "OPENLIST_BAIDU_PATH",
        "OPENLIST_PIKPAK_PATH",
        "OPENLIST_QUARK_PATH",
        "OPENLIST_SHARE_TTL_HOURS",
        "BAIDU_CLIENT_ID",
        "BAIDU_CLIENT_SECRET",
        "BAIDU_SAVE_PATH",
        "PIKPAK_SAVE_PATH",
        "PIKPAK_DIRECT_EXCLUSIVE_DIR",
        "QUARK_SAVE_PATH",
        "MAX_DELIVERY_FILES",
        "MAX_TEMP_DISK_MB",
        "PENDING_INPUT_TTL_SECONDS",
        "MAX_RETAINED_TASKS",
        "LOG_LEVEL",
    }
)

_INSTANCE_EPOCH_KEY: str = "openlist_instance_epoch"
_MOUNT_EPOCH_PREFIX: str = "openlist_mount_epoch:"
_BOUND_BASE_URL_KEY: str = "_bound_openlist_base_url"
_BOUND_SAVE_PATH_PREFIX: str = "_bound_save_path:"
_BOUND_OPENLIST_PATH_PREFIX: str = "_bound_openlist_path:"


def _new_epoch(previous: str = "") -> str:
    """Generate a 16-hex-character epoch guaranteed to differ from ``previous``."""
    candidate = secrets.token_hex(8)
    while candidate == previous:
        candidate = secrets.token_hex(8)
    return candidate


def _validate_and_serialize_setting(key: str, raw_value: Any) -> tuple[Any, str]:
    """Validate a single mutable runtime setting and return ``(typed_value, db_string)``."""
    if key in ("WHITELIST_ENABLED", "PIKPAK_DIRECT_EXCLUSIVE_DIR"):
        b_val = parse_strict_bool(raw_value, field_name=key)
        return b_val, "true" if b_val else "false"

    if key in ("OPENLIST_BASE_URL", "OPENLIST_PUBLIC_URL"):
        u_val = parse_http_url(raw_value, field_name=key, allow_empty=True)
        return u_val, u_val

    if key in (
        "OPENLIST_TOKEN",
        "OPENLIST_USERNAME",
        "OPENLIST_PASSWORD",
        "BAIDU_CLIENT_ID",
        "BAIDU_CLIENT_SECRET",
    ):
        s_val = validate_clean_string(raw_value, field_name=key)
        return s_val, s_val

    if key in ("OPENLIST_BAIDU_PATH", "OPENLIST_PIKPAK_PATH", "OPENLIST_QUARK_PATH"):
        if not isinstance(raw_value, str):
            raise ValueError(f"{key} must be a string")
        p_val = normalize_posix_path(raw_value, allow_root=False)
        return p_val, p_val

    if key in ("BAIDU_SAVE_PATH", "PIKPAK_SAVE_PATH", "QUARK_SAVE_PATH"):
        if not isinstance(raw_value, str):
            raise ValueError(f"{key} must be a string")
        sp_val = validate_save_path(raw_value)
        return sp_val, sp_val

    if key == "OPENLIST_SHARE_TTL_HOURS":
        i_val = parse_bounded_int(
            raw_value,
            field_name=key,
            min_value=OPENLIST_SHARE_TTL_HOURS_MIN,
            max_value=OPENLIST_SHARE_TTL_HOURS_MAX,
        )
        return i_val, str(i_val)

    if key == "MAX_DELIVERY_FILES":
        i_val = parse_bounded_int(
            raw_value,
            field_name=key,
            min_value=MAX_DELIVERY_FILES_MIN,
            max_value=MAX_DELIVERY_FILES_MAX,
        )
        return i_val, str(i_val)

    if key == "MAX_TEMP_DISK_MB":
        i_val = parse_bounded_int(
            raw_value,
            field_name=key,
            min_value=MAX_TEMP_DISK_MB_MIN,
            max_value=MAX_TEMP_DISK_MB_MAX,
        )
        return i_val, str(i_val)

    if key == "PENDING_INPUT_TTL_SECONDS":
        i_val = parse_bounded_int(
            raw_value,
            field_name=key,
            min_value=PENDING_INPUT_TTL_SECONDS_MIN,
            max_value=PENDING_INPUT_TTL_SECONDS_MAX,
        )
        return i_val, str(i_val)

    if key == "MAX_RETAINED_TASKS":
        i_val = parse_bounded_int(
            raw_value,
            field_name=key,
            min_value=MAX_RETAINED_TASKS_MIN,
            max_value=MAX_RETAINED_TASKS_MAX,
        )
        return i_val, str(i_val)

    if key == "LOG_LEVEL":
        lvl = validate_log_level(raw_value)
        return lvl, lvl

    raise ValueError(f"Unsupported mutable setting key: {key!r}")


def _ordered_mount_epochs(epochs: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    ordered: list[tuple[str, str]] = []
    for pid in BUILTIN_PROVIDER_IDS:
        if pid in epochs:
            ordered.append((pid, epochs[pid]))
    for pid in sorted(epochs):
        if pid not in BUILTIN_PROVIDER_IDS:
            ordered.append((pid, epochs[pid]))
    return tuple(ordered)


class RuntimeConfig:
    """Dynamic configuration manager enforcing SQLite > Env > Default and read-only trust roots."""

    READONLY_TRUST_KEYS: frozenset[str] = frozenset(
        {"TELEGRAM_ADMIN_ID", "WEB_BASE_URL", "WEB_TRUSTED_PROXIES"}
    )

    def __init__(self, bootstrap: BootstrapConfigSnapshot, storage: SQLiteStorage) -> None:
        self._bootstrap = bootstrap
        self._storage = storage
        self._lock = asyncio.Lock()
        initial_mount_epochs = tuple((pid, _new_epoch()) for pid in BUILTIN_PROVIDER_IDS)
        self._snapshot = self._compose_snapshot(
            db_overrides={},
            instance_epoch=_new_epoch(),
            mount_epochs=initial_mount_epochs,
        )

    @property
    def bootstrap(self) -> BootstrapConfigSnapshot:
        return self._bootstrap

    def snapshot(self) -> RuntimeSettingsSnapshot:
        return self._snapshot

    def _compose_snapshot(
        self,
        *,
        db_overrides: Mapping[str, Any],
        instance_epoch: str,
        mount_epochs: tuple[tuple[str, str], ...],
    ) -> RuntimeSettingsSnapshot:
        b = self._bootstrap
        return RuntimeSettingsSnapshot(
            whitelist_enabled=db_overrides.get("WHITELIST_ENABLED", b.initial_whitelist_enabled),
            openlist_base_url=db_overrides.get("OPENLIST_BASE_URL", b.openlist_base_url),
            openlist_public_url=db_overrides.get("OPENLIST_PUBLIC_URL", b.openlist_public_url),
            openlist_token=db_overrides.get("OPENLIST_TOKEN", b.openlist_token),
            openlist_username=db_overrides.get("OPENLIST_USERNAME", b.openlist_username),
            openlist_password=db_overrides.get("OPENLIST_PASSWORD", b.openlist_password),
            openlist_baidu_path=db_overrides.get("OPENLIST_BAIDU_PATH", b.openlist_baidu_path),
            openlist_pikpak_path=db_overrides.get("OPENLIST_PIKPAK_PATH", b.openlist_pikpak_path),
            openlist_quark_path=db_overrides.get("OPENLIST_QUARK_PATH", b.openlist_quark_path),
            openlist_share_ttl_hours=db_overrides.get(
                "OPENLIST_SHARE_TTL_HOURS", b.openlist_share_ttl_hours
            ),
            baidu_client_id=db_overrides.get("BAIDU_CLIENT_ID", b.baidu_client_id),
            baidu_client_secret=db_overrides.get("BAIDU_CLIENT_SECRET", b.baidu_client_secret),
            baidu_save_path=db_overrides.get("BAIDU_SAVE_PATH", b.baidu_save_path),
            pikpak_save_path=db_overrides.get("PIKPAK_SAVE_PATH", b.pikpak_save_path),
            pikpak_direct_exclusive_dir=db_overrides.get(
                "PIKPAK_DIRECT_EXCLUSIVE_DIR", b.pikpak_direct_exclusive_dir
            ),
            quark_save_path=db_overrides.get("QUARK_SAVE_PATH", b.quark_save_path),
            max_delivery_files=db_overrides.get("MAX_DELIVERY_FILES", b.max_delivery_files),
            max_temp_disk_mb=db_overrides.get("MAX_TEMP_DISK_MB", b.max_temp_disk_mb),
            pending_input_ttl_seconds=db_overrides.get(
                "PENDING_INPUT_TTL_SECONDS", b.pending_input_ttl_seconds
            ),
            max_retained_tasks=db_overrides.get("MAX_RETAINED_TASKS", b.max_retained_tasks),
            log_level=db_overrides.get("LOG_LEVEL", b.log_level),
            openlist_instance_epoch=instance_epoch,
            openlist_mount_epochs=mount_epochs,
        )

    @staticmethod
    def _provider_paths_from_snapshot(snap: RuntimeSettingsSnapshot) -> dict[str, tuple[str, str]]:
        return {
            "baidu": (snap.baidu_save_path, snap.openlist_baidu_path),
            "pikpak": (snap.pikpak_save_path, snap.openlist_pikpak_path),
            "quark": (snap.quark_save_path, snap.openlist_quark_path),
        }

    async def initialize(self) -> RuntimeSettingsSnapshot:
        """Seed initial access lists once, resolve SQLite > Env > Default, and sync epochs."""
        async with self._lock:
            raw_db = await self._storage.get_all_settings()

            if raw_db.get("seeded_access_lists") != "1":
                await self._storage.replace_seeded_access_lists(
                    whitelist_ids=self._bootstrap.initial_whitelist_ids,
                    blacklist_ids=self._bootstrap.initial_blacklist_ids,
                    group_ids=self._bootstrap.initial_group_whitelist_ids,
                    admin_id=self._bootstrap.telegram_admin_id,
                    created_by=self._bootstrap.telegram_admin_id,
                )

            # Strictly ignore any SQLite entries matching READONLY_TRUST_KEYS
            parsed_overrides: dict[str, Any] = {}
            for key, raw_val in raw_db.items():
                if key in self.READONLY_TRUST_KEYS or key.upper() in self.READONLY_TRUST_KEYS:
                    continue
                if key in MUTABLE_SETTING_KEYS:
                    typed_val, _ = _validate_and_serialize_setting(key, raw_val)
                    parsed_overrides[key] = typed_val

            temp_snap = self._compose_snapshot(
                db_overrides=parsed_overrides,
                instance_epoch="",
                mount_epochs=(),
            )

            db_writes: dict[str, str] = {}
            existing_inst_epoch = raw_db.get(_INSTANCE_EPOCH_KEY, "").strip()
            bound_base_url = raw_db.get(_BOUND_BASE_URL_KEY)
            if not existing_inst_epoch or (
                bound_base_url is not None and bound_base_url != temp_snap.openlist_base_url
            ):
                inst_epoch = _new_epoch(existing_inst_epoch)
                db_writes[_INSTANCE_EPOCH_KEY] = inst_epoch
            else:
                inst_epoch = existing_inst_epoch

            if bound_base_url != temp_snap.openlist_base_url:
                db_writes[_BOUND_BASE_URL_KEY] = temp_snap.openlist_base_url

            mount_epochs_map: dict[str, str] = {}
            for key, val in raw_db.items():
                if key.startswith(_MOUNT_EPOCH_PREFIX):
                    pid = key[len(_MOUNT_EPOCH_PREFIX) :].strip().lower()
                    if pid and val.strip():
                        mount_epochs_map[pid] = val.strip()

            provider_paths = self._provider_paths_from_snapshot(temp_snap)
            for pid, (eff_save_path, eff_ol_path) in provider_paths.items():
                existing_mount = mount_epochs_map.get(pid, "")
                bound_save = raw_db.get(f"{_BOUND_SAVE_PATH_PREFIX}{pid}")
                bound_ol = raw_db.get(f"{_BOUND_OPENLIST_PATH_PREFIX}{pid}")
                path_changed = (bound_save is not None and bound_save != eff_save_path) or (
                    bound_ol is not None and bound_ol != eff_ol_path
                )
                if not existing_mount or path_changed:
                    new_mount = _new_epoch(existing_mount)
                    mount_epochs_map[pid] = new_mount
                    db_writes[f"{_MOUNT_EPOCH_PREFIX}{pid}"] = new_mount

                if bound_save != eff_save_path:
                    db_writes[f"{_BOUND_SAVE_PATH_PREFIX}{pid}"] = eff_save_path
                if bound_ol != eff_ol_path:
                    db_writes[f"{_BOUND_OPENLIST_PATH_PREFIX}{pid}"] = eff_ol_path

            if db_writes:
                await self._storage.set_settings(
                    db_writes, updated_by=self._bootstrap.telegram_admin_id
                )

            final_snap = self._compose_snapshot(
                db_overrides=parsed_overrides,
                instance_epoch=inst_epoch,
                mount_epochs=_ordered_mount_epochs(mount_epochs_map),
            )
            self._snapshot = final_snap
            logging.getLogger().setLevel(getattr(logging, final_snap.log_level))
            return final_snap

    async def update_settings(
        self,
        updates: Mapping[str, Any],
        *,
        updated_by: int,
    ) -> RuntimeSettingsSnapshot:
        """Validate and persist runtime overrides, rotating OpenList epochs on URL/path changes."""
        validated_typed: dict[str, Any] = {}
        serialized_writes: dict[str, str] = {}
        for key, raw_val in updates.items():
            if not isinstance(key, str):
                raise ValueError("Setting key must be a string")
            if key in self.READONLY_TRUST_KEYS or key.upper() in self.READONLY_TRUST_KEYS:
                raise ValueError(
                    f"Setting {key!r} is a read-only trust root and cannot be modified"
                )
            if key not in MUTABLE_SETTING_KEYS:
                raise ValueError(f"Unknown or non-overridable setting key: {key!r}")
            typed_val, db_str = _validate_and_serialize_setting(key, raw_val)
            validated_typed[key] = typed_val
            serialized_writes[key] = db_str

        async with self._lock:
            prev = self._snapshot
            if not validated_typed:
                return prev

            current_values: dict[str, Any] = {
                "WHITELIST_ENABLED": prev.whitelist_enabled,
                "OPENLIST_BASE_URL": prev.openlist_base_url,
                "OPENLIST_PUBLIC_URL": prev.openlist_public_url,
                "OPENLIST_TOKEN": prev.openlist_token,
                "OPENLIST_USERNAME": prev.openlist_username,
                "OPENLIST_PASSWORD": prev.openlist_password,
                "OPENLIST_BAIDU_PATH": prev.openlist_baidu_path,
                "OPENLIST_PIKPAK_PATH": prev.openlist_pikpak_path,
                "OPENLIST_QUARK_PATH": prev.openlist_quark_path,
                "OPENLIST_SHARE_TTL_HOURS": prev.openlist_share_ttl_hours,
                "BAIDU_CLIENT_ID": prev.baidu_client_id,
                "BAIDU_CLIENT_SECRET": prev.baidu_client_secret,
                "BAIDU_SAVE_PATH": prev.baidu_save_path,
                "PIKPAK_SAVE_PATH": prev.pikpak_save_path,
                "PIKPAK_DIRECT_EXCLUSIVE_DIR": prev.pikpak_direct_exclusive_dir,
                "QUARK_SAVE_PATH": prev.quark_save_path,
                "MAX_DELIVERY_FILES": prev.max_delivery_files,
                "MAX_TEMP_DISK_MB": prev.max_temp_disk_mb,
                "PENDING_INPUT_TTL_SECONDS": prev.pending_input_ttl_seconds,
                "MAX_RETAINED_TASKS": prev.max_retained_tasks,
                "LOG_LEVEL": prev.log_level,
            }
            current_values.update(validated_typed)

            inst_epoch = prev.openlist_instance_epoch
            if current_values["OPENLIST_BASE_URL"] != prev.openlist_base_url:
                inst_epoch = _new_epoch(prev.openlist_instance_epoch)
                serialized_writes[_INSTANCE_EPOCH_KEY] = inst_epoch
                serialized_writes[_BOUND_BASE_URL_KEY] = current_values["OPENLIST_BASE_URL"]

            mount_epochs_map = dict(prev.openlist_mount_epochs)
            next_temp_snap = self._compose_snapshot(
                db_overrides=current_values,
                instance_epoch=inst_epoch,
                mount_epochs=prev.openlist_mount_epochs,
            )
            prev_paths = self._provider_paths_from_snapshot(prev)
            next_paths = self._provider_paths_from_snapshot(next_temp_snap)
            for pid, (next_save, next_ol) in next_paths.items():
                old_save, old_ol = prev_paths[pid]
                if next_save != old_save or next_ol != old_ol:
                    rotated = _new_epoch(mount_epochs_map.get(pid, ""))
                    mount_epochs_map[pid] = rotated
                    serialized_writes[f"{_MOUNT_EPOCH_PREFIX}{pid}"] = rotated
                    serialized_writes[f"{_BOUND_SAVE_PATH_PREFIX}{pid}"] = next_save
                    serialized_writes[f"{_BOUND_OPENLIST_PATH_PREFIX}{pid}"] = next_ol

            await self._storage.set_settings(serialized_writes, updated_by=updated_by)

            updated_snap = self._compose_snapshot(
                db_overrides=current_values,
                instance_epoch=inst_epoch,
                mount_epochs=_ordered_mount_epochs(mount_epochs_map),
            )
            self._snapshot = updated_snap
            if updated_snap.log_level != prev.log_level:
                logging.getLogger().setLevel(getattr(logging, updated_snap.log_level))
            return updated_snap

    async def bump_openlist_mount_epochs(
        self,
        *,
        updated_by: int,
        provider_id: str | None = None,
    ) -> RuntimeSettingsSnapshot:
        """Manually rotate OpenList mount binding epoch(s) via Web 'Refresh Mount Binding'."""
        async with self._lock:
            prev = self._snapshot
            mount_epochs_map = dict(prev.openlist_mount_epochs)
            for pid in BUILTIN_PROVIDER_IDS:
                mount_epochs_map.setdefault(pid, _new_epoch())

            db_writes: dict[str, str] = {}
            if provider_id is not None:
                pid = provider_id.strip().lower()
                if not pid:
                    raise ValueError("provider_id must be non-empty when specified")
                rotated = _new_epoch(mount_epochs_map.get(pid, ""))
                mount_epochs_map[pid] = rotated
                db_writes[f"{_MOUNT_EPOCH_PREFIX}{pid}"] = rotated
            else:
                for pid, old_ep in list(mount_epochs_map.items()):
                    rotated = _new_epoch(old_ep)
                    mount_epochs_map[pid] = rotated
                    db_writes[f"{_MOUNT_EPOCH_PREFIX}{pid}"] = rotated

            await self._storage.set_settings(db_writes, updated_by=updated_by)

            current_values: dict[str, Any] = {
                "WHITELIST_ENABLED": prev.whitelist_enabled,
                "OPENLIST_BASE_URL": prev.openlist_base_url,
                "OPENLIST_PUBLIC_URL": prev.openlist_public_url,
                "OPENLIST_TOKEN": prev.openlist_token,
                "OPENLIST_USERNAME": prev.openlist_username,
                "OPENLIST_PASSWORD": prev.openlist_password,
                "OPENLIST_BAIDU_PATH": prev.openlist_baidu_path,
                "OPENLIST_PIKPAK_PATH": prev.openlist_pikpak_path,
                "OPENLIST_QUARK_PATH": prev.openlist_quark_path,
                "OPENLIST_SHARE_TTL_HOURS": prev.openlist_share_ttl_hours,
                "BAIDU_CLIENT_ID": prev.baidu_client_id,
                "BAIDU_CLIENT_SECRET": prev.baidu_client_secret,
                "BAIDU_SAVE_PATH": prev.baidu_save_path,
                "PIKPAK_SAVE_PATH": prev.pikpak_save_path,
                "PIKPAK_DIRECT_EXCLUSIVE_DIR": prev.pikpak_direct_exclusive_dir,
                "QUARK_SAVE_PATH": prev.quark_save_path,
                "MAX_DELIVERY_FILES": prev.max_delivery_files,
                "MAX_TEMP_DISK_MB": prev.max_temp_disk_mb,
                "PENDING_INPUT_TTL_SECONDS": prev.pending_input_ttl_seconds,
                "MAX_RETAINED_TASKS": prev.max_retained_tasks,
                "LOG_LEVEL": prev.log_level,
            }
            updated_snap = self._compose_snapshot(
                db_overrides=current_values,
                instance_epoch=prev.openlist_instance_epoch,
                mount_epochs=_ordered_mount_epochs(mount_epochs_map),
            )
            self._snapshot = updated_snap
            return updated_snap

    async def reset_access_lists_to_initial(self, *, updated_by: int) -> None:
        """Reset user whitelist/blacklist and group whitelist to initial bootstrap IDs."""
        await self._storage.replace_seeded_access_lists(
            whitelist_ids=self._bootstrap.initial_whitelist_ids,
            blacklist_ids=self._bootstrap.initial_blacklist_ids,
            group_ids=self._bootstrap.initial_group_whitelist_ids,
            admin_id=self._bootstrap.telegram_admin_id,
            created_by=updated_by,
        )

    def build_openlist_binding_id(
        self,
        provider_id: str,
        *,
        storage_signature: str = "",
    ) -> str | None:
        """Compose OpenList instance+mount+storage binding ID or None when OpenList is disabled."""
        snap = self._snapshot
        if snap.openlist_base_url == "":
            return None
        pid = provider_id.strip().lower()
        instance_epoch = snap.openlist_instance_epoch
        mount_epoch = snap.get_mount_epoch(pid)
        sig = storage_signature.strip()
        return f"{instance_epoch}:{mount_epoch}:{sig}".rstrip(":")

    def get_provider_settings(self, provider_id: str) -> Mapping[str, str]:
        """Return read-only provider setting dictionary satisfying ProviderConfigReader."""
        pid = provider_id.strip().lower()
        snap = self._snapshot
        if pid == "baidu":
            return {
                "provider_id": "baidu",
                "client_id": snap.baidu_client_id,
                "client_secret": snap.baidu_client_secret,
                "save_path": snap.baidu_save_path,
                "openlist_path": snap.openlist_baidu_path,
                "direct_exclusive_dir": "true",
                "data_dir": self._bootstrap.data_dir,
            }
        if pid == "pikpak":
            return {
                "provider_id": "pikpak",
                "client_id": "",
                "client_secret": "",
                "save_path": snap.pikpak_save_path,
                "openlist_path": snap.openlist_pikpak_path,
                "direct_exclusive_dir": "true" if snap.pikpak_direct_exclusive_dir else "false",
                "initial_pat": self._bootstrap.pikpak_pat,
                "pat": self._bootstrap.pikpak_pat,
                "data_dir": self._bootstrap.data_dir,
            }
        if pid == "quark":
            return {
                "provider_id": "quark",
                "client_id": "",
                "client_secret": "",
                "save_path": snap.quark_save_path,
                "openlist_path": snap.openlist_quark_path,
                "direct_exclusive_dir": "true",
                "initial_cookie": self._bootstrap.quark_cookie,
                "cookie": self._bootstrap.quark_cookie,
                "data_dir": self._bootstrap.data_dir,
            }
        return {
            "provider_id": pid,
            "client_id": "",
            "client_secret": "",
            "save_path": "",
            "openlist_path": "",
            "direct_exclusive_dir": "true",
            "data_dir": self._bootstrap.data_dir,
        }

    def is_direct_exclusive_dir_confirmed(self, provider_id: str) -> bool:
        """Return PikPak -n exclusive directory gate status (True for non-PikPak providers)."""
        if provider_id.strip().lower() == "pikpak":
            return self._snapshot.pikpak_direct_exclusive_dir
        return True
