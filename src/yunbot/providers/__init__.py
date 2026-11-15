"""Cloud storage provider plugin package."""

from yunbot.providers.base import (
    CloudProvider,
    CredentialStore,
    ItemsBatchCallback,
    ProgressCallback,
    ProviderConfigReader,
    ProviderFieldSpec,
    ProviderSpec,
    RemoteTaskCallback,
    ShareRecognizer,
    SnapshotStore,
)
from yunbot.providers.registry import ProviderRegistry

__all__ = [
    "CloudProvider",
    "CredentialStore",
    "ItemsBatchCallback",
    "ProgressCallback",
    "ProviderConfigReader",
    "ProviderFieldSpec",
    "ProviderRegistry",
    "ProviderSpec",
    "RemoteTaskCallback",
    "ShareRecognizer",
    "SnapshotStore",
]
