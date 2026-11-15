"""ProviderRegistry managing registered CloudProvider plugins and ShareRecognizers."""

from __future__ import annotations

from yunbot.providers.base import CloudProvider, ProviderSpec, ShareRecognizer


class ProviderRegistry:
    """In-memory registry mapping provider_id and command to CloudProvider instances."""

    def __init__(self) -> None:
        self._by_id: dict[str, CloudProvider] = {}
        self._by_command: dict[str, CloudProvider] = {}

    def register(self, provider: CloudProvider) -> None:
        pid = provider.spec.provider_id
        cmd = provider.spec.command.lstrip("/").lower()
        if pid in self._by_id:
            raise ValueError(f"Duplicate provider_id registered: {pid}")
        if cmd in self._by_command:
            raise ValueError(f"Duplicate provider command registered: {cmd}")
        self._by_id[pid] = provider
        self._by_command[cmd] = provider

    def get(self, provider_id: str) -> CloudProvider:
        if provider_id not in self._by_id:
            raise KeyError(f"Unknown provider_id: {provider_id}")
        return self._by_id[provider_id]

    def find(self, provider_id: str) -> CloudProvider | None:
        return self._by_id.get(provider_id)

    def get_by_command(self, command: str) -> CloudProvider | None:
        return self._by_command.get(command.lstrip("/").lower())

    def all_providers(self) -> tuple[CloudProvider, ...]:
        return tuple(self._by_id.values())

    def all_specs(self) -> tuple[ProviderSpec, ...]:
        return tuple(p.spec for p in self._by_id.values())

    def all_recognizers(self) -> tuple[ShareRecognizer, ...]:
        return tuple(p.recognizer for p in self._by_id.values())

    async def close_all(self) -> None:
        for provider in self._by_id.values():
            await provider.close()
