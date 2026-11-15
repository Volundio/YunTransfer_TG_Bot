"""Plugin contracts, injected storage/config Protocols, and CloudProvider interface (§4.1, §5.4).

Strict Dependency Boundary:
`providers/` MUST NOT import `storage` or `runtime_config`.
All credential persistence, snapshot temp-table operations, and runtime configuration lookups
are injected via the Protocols defined here.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from yunbot.models import (
    MAX_SNAPSHOT_ITEMS_PER_PHASE,
    AuthMode,
    DeleteItemsOutcome,
    InteractiveAuthPollResult,
    InteractiveAuthStart,
    PasswordPolicy,
    ProviderAccountStatus,
    ProviderCredentialRecord,
    RecognizedShareUrl,
    ShareLinkInfo,
    SnapshotTempEntry,
    TransferItemRecord,
    TransferOutcome,
    TransferredEntry,
)

ItemsBatchCallback = Callable[[Sequence[TransferredEntry]], Awaitable[None]]
RemoteTaskCallback = Callable[[str], Awaitable[None]]
ProgressCallback = Callable[[str, int, int], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class ProviderFieldSpec:
    """Metadata describing a secret or config input field for Web Tab 2 dynamic rendering."""

    key: str
    label: str
    secret: bool = True
    required: bool = True
    placeholder: str = ""
    help_text: str = ""


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Self-describing metadata contract for a cloud storage provider (§5.4)."""

    provider_id: str
    display_name: str
    command: str
    password_policy: PasswordPolicy
    auth_mode: AuthMode
    save_path_key: str
    openlist_path_key: str
    default_save_path: str
    default_openlist_path: str
    extra_auth_modes: tuple[AuthMode, ...] = ()
    secret_fields: tuple[ProviderFieldSpec, ...] = ()
    stream_cookie_allowed_suffixes: tuple[str, ...] = ()
    requires_exclusive_dir_for_direct: bool = False


@runtime_checkable
class ProviderConfigReader(Protocol):
    """Read-only runtime configuration view injected into providers."""

    def get_provider_settings(self, provider_id: str) -> Mapping[str, str]: ...

    def is_direct_exclusive_dir_confirmed(self, provider_id: str) -> bool: ...


@runtime_checkable
class CredentialStore(Protocol):
    """Persistence contract for provider_credentials injected into providers."""

    async def get_credential(self, provider: str) -> ProviderCredentialRecord | None: ...

    async def upsert_credential(self, record: ProviderCredentialRecord) -> None: ...

    async def delete_credential(self, provider: str) -> None: ...


@runtime_checkable
class SnapshotStore(Protocol):
    """Bounded SQLite snapshot_temp_items contract for large directory diffing (§5.6, R08)."""

    async def clear_task_snapshots(self, task_id: str) -> None: ...

    async def insert_snapshot_batch(
        self,
        task_id: str,
        phase: str,
        items: Sequence[SnapshotTempEntry],
        *,
        max_per_phase: int = MAX_SNAPSHOT_ITEMS_PER_PHASE,
    ) -> int: ...

    async def fetch_added_snapshot_page(
        self,
        task_id: str,
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> list[SnapshotTempEntry]: ...


@runtime_checkable
class ShareRecognizer(Protocol):
    """Zero-I/O pure share URL recognizer."""

    @property
    def provider_id(self) -> str: ...

    def recognize(self, url: str) -> RecognizedShareUrl | None: ...


@runtime_checkable
class CloudProvider(Protocol):
    """Unified cloud storage adapter contract (§5.4.4)."""

    @property
    def spec(self) -> ProviderSpec: ...

    @property
    def recognizer(self) -> ShareRecognizer: ...

    def validate_transfer_mode(self, *, no_subdir: bool) -> None:
        """Raise DirectUnsafeDirError if -n mode is disallowed under current settings."""
        ...

    def get_oauth_authorize_url(self) -> str | None:
        """Return optional OAuth authorization page URL for oauth_code providers."""
        ...

    async def get_account_status(self) -> ProviderAccountStatus: ...

    async def get_current_binding_id(self) -> str:
        """Return current verified account_binding_id or raise ProviderAuthInvalidError."""
        ...

    async def save_secret_credentials(self, fields: Mapping[str, str]) -> ProviderAccountStatus: ...

    async def exchange_oauth_code(self, code: str) -> ProviderAccountStatus: ...

    async def start_interactive_auth(self) -> InteractiveAuthStart: ...

    async def poll_interactive_auth(self) -> InteractiveAuthPollResult: ...

    async def cancel_interactive_auth(self) -> None: ...

    async def keepalive(self) -> None: ...

    async def prepare_task_dir(self, task_dir_path: str) -> str: ...

    async def transfer(
        self,
        share: ShareLinkInfo,
        target_dir: str,
        *,
        task_id: str = "",
        collect_items: bool = False,
        on_items_batch: ItemsBatchCallback | None = None,
        on_remote_task: RemoteTaskCallback | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> TransferOutcome: ...

    async def delete_directory(
        self,
        task_dir_path: str,
        *,
        expected_binding_id: str | None = None,
    ) -> None: ...

    async def delete_items(
        self,
        base_save_path: str,
        items: Sequence[TransferItemRecord],
        *,
        expected_binding_id: str | None = None,
        deleted_ids_sink: list[str] | None = None,
    ) -> DeleteItemsOutcome: ...

    async def close(self) -> None: ...
