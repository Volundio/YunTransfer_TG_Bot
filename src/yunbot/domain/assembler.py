"""Two-message out-of-order private input & group ForceReply share assembler (§5.1).

Strict Dependency Boundary:
Depends ONLY on Python 3.12 standard library, `models`, `parsing`,
`providers.base`, and `providers.registry` (uses Protocol / duck-typed access
to `storage` and `runtime_config`).
"""

from __future__ import annotations

import inspect
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from yunbot.domain.parsing import parse_transfer_text, strip_command_prefix
from yunbot.models import (
    MAX_BATCH_LINKS_PER_MESSAGE,
    PENDING_INPUT_TTL_SECONDS,
    ErrorCode,
    ParsedShareItem,
    PasswordPolicy,
    PendingInputRecord,
    RecognizedShareUrl,
    RuntimeSettingsSnapshot,
    ShareLinkInfo,
)
from yunbot.providers.base import CloudProvider
from yunbot.providers.registry import ProviderRegistry


class AssembleAction(StrEnum):
    """Next action for the Telegram handler after assembling user input."""

    READY = "ready"
    AWAIT_LINK = "await_link"
    NEED_PASSWORD = "need_password"
    ERROR = "error"
    IGNORE = "ignore"


@dataclass(frozen=True, slots=True)
class AssembleResult:
    """Immutable outcome produced by `InputAssembler`."""

    action: AssembleAction
    share: ShareLinkInfo | None = None
    shares: tuple[ShareLinkInfo, ...] = ()
    skipped_need_password: tuple[RecognizedShareUrl, ...] = ()
    pending_share: RecognizedShareUrl | None = None
    error_code: ErrorCode | None = None
    message: str | None = None
    no_subdir: bool = False


@runtime_checkable
class PendingInputStore(Protocol):
    """Persistence contract for the `pending_inputs` SQLite table."""

    async def get_pending_input(self, chat_id: int, user_id: int) -> PendingInputRecord | None: ...

    async def upsert_pending_input(self, record: PendingInputRecord) -> None: ...

    async def delete_pending_input(self, chat_id: int, user_id: int) -> bool: ...


@runtime_checkable
class AssemblerConfigReader(Protocol):
    """Read-only runtime configuration snapshot contract."""

    def snapshot(self) -> RuntimeSettingsSnapshot: ...


class InputAssembler:
    """Stateful input assembler merging private 2-message shares and group ForceReply prompts."""

    def __init__(
        self,
        storage: Any,
        runtime_config: Any,
        registry: ProviderRegistry,
    ) -> None:
        self._storage = storage
        self._runtime_config = runtime_config
        self._registry = registry

    def _get_ttl_seconds(self) -> float:
        snap_fn = getattr(self._runtime_config, "snapshot", None)
        if callable(snap_fn):
            snap = snap_fn()
            return float(snap.pending_input_ttl_seconds)
        return float(
            getattr(self._runtime_config, "pending_input_ttl_seconds", PENDING_INPUT_TTL_SECONDS)
        )

    async def _get_pending(self, chat_id: int, user_id: int) -> PendingInputRecord | None:
        for method_name in ("get_pending_input", "get_pending"):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                return await fn(chat_id, user_id)
        raise AttributeError("Storage does not implement get_pending_input")

    async def _save_pending(self, record: PendingInputRecord) -> None:
        for method_name in (
            "upsert_pending_input",
            "save_pending_input",
            "set_pending_input",
            "save_pending",
        ):
            fn = getattr(self._storage, method_name, None)
            if not callable(fn):
                continue
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
            pos_params = [
                p
                for p in params
                if p.kind
                in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            ]
            if has_varargs or len(pos_params) == 1:
                await fn(record)
                return

            field_map = {
                "chat_id": record.chat_id,
                "user_id": record.user_id,
                "provider_hint": record.provider_hint,
                "url": record.url,
                "external_id": record.external_id,
                "code": record.code,
                "no_subdir": record.no_subdir,
                "prompt_message_id": record.prompt_message_id,
                "updated_at": record.updated_at,
                "now": record.updated_at,
            }
            args: list[Any] = []
            kwargs: dict[str, Any] = {}
            for p in params:
                if p.name in field_map:
                    if p.kind == inspect.Parameter.POSITIONAL_ONLY:
                        args.append(field_map[p.name])
                    else:
                        kwargs[p.name] = field_map[p.name]
            await fn(*args, **kwargs)
            return
        raise AttributeError("Storage does not implement upsert_pending_input")

    async def _delete_pending(self, chat_id: int, user_id: int) -> bool:
        for method_name in ("delete_pending_input", "remove_pending_input", "delete_pending"):
            fn = getattr(self._storage, method_name, None)
            if callable(fn):
                res = await fn(chat_id, user_id)
                return True if res is None else bool(res)
        raise AttributeError("Storage does not implement delete_pending_input")

    async def clear_pending(self, *, chat_id: int, user_id: int) -> bool:
        """Explicitly clear any pending input state for `(chat_id, user_id)`."""
        return await self._delete_pending(chat_id, user_id)

    def _recover_sub_dir_fid(self, provider: CloudProvider | None, url: str) -> str:
        if provider is None:
            return "0"
        recognized = provider.recognizer.recognize(url)
        return recognized.sub_dir_fid if recognized is not None else "0"

    def _resolve_command_provider(
        self, text: str, forced_provider_id: str | None
    ) -> tuple[str | None, str | None, str]:
        """Return `(command_lower, effective_forced_provider_id, stripped_text)`."""
        cmd, stripped = strip_command_prefix(text)
        if forced_provider_id is not None:
            return cmd, forced_provider_id, stripped
        if cmd is not None:
            provider = self._registry.get_by_command(cmd)
            if provider is not None:
                return cmd, provider.spec.provider_id, stripped
        return cmd, None, stripped

    async def handle_private_input(
        self,
        *,
        chat_id: int,
        user_id: int,
        text: str,
        forced_provider_id: str | None = None,
        now: float | None = None,
    ) -> AssembleResult:
        """Assemble single-message or 2-message out-of-order private chat input."""
        ts = time.time() if now is None else float(now)
        ttl = self._get_ttl_seconds()

        existing = await self._get_pending(chat_id, user_id)
        had_expired_pending = False
        if existing is not None and (ts - existing.updated_at > ttl):
            await self._delete_pending(chat_id, user_id)
            had_expired_pending = True
            existing = None

        cmd, effective_forced_id, stripped = self._resolve_command_provider(
            text, forced_provider_id
        )
        # Unknown non-provider slash command in private chat -> ignore cleanly.
        if cmd is not None and effective_forced_id is None:
            return AssembleResult(action=AssembleAction.IGNORE)

        if effective_forced_id is not None and self._registry.find(effective_forced_id) is None:
            return AssembleResult(action=AssembleAction.ERROR, error_code=ErrorCode.INVALID_LINK)

        parsed = parse_transfer_text(
            stripped,
            self._registry.all_recognizers(),
            forced_provider_id=effective_forced_id,
        )

        if parsed.ambiguous:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.AMBIGUOUS_INPUT,
                no_subdir=parsed.no_subdir,
            )

        if parsed.invalid_link_candidate:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.INVALID_LINK,
                no_subdir=parsed.no_subdir,
            )

        # Case A0: Multiple recognized share links (Batch Mode).
        if len(parsed.shares) > 1:
            return await self._assemble_batch_shares(
                chat_id=chat_id,
                user_id=user_id,
                items=parsed.shares,
                no_subdir=parsed.no_subdir,
                existing_pending=existing,
                save_single_missing_pending=True,
                ts=ts,
            )

        # Case A: Current message supplies a single recognized share link.
        if parsed.share is not None:
            share_url = parsed.share
            provider = self._registry.find(share_url.provider_id)
            if provider is None:
                return AssembleResult(
                    action=AssembleAction.ERROR,
                    error_code=ErrorCode.INVALID_LINK,
                    no_subdir=parsed.no_subdir,
                )

            effective_code = parsed.code
            effective_no_subdir = parsed.no_subdir

            if existing is not None:
                if existing.url is None and existing.code is not None:
                    # Out-of-order merge: Code came first, Link came second!
                    if (
                        existing.provider_hint is None
                        or existing.provider_hint == share_url.provider_id
                    ):
                        if effective_code is None:
                            effective_code = existing.code
                            effective_no_subdir = bool(existing.no_subdir or parsed.no_subdir)
                        elif effective_code == existing.code:
                            effective_no_subdir = bool(existing.no_subdir or parsed.no_subdir)
                elif (
                    existing.url is not None
                    and existing.provider_hint == share_url.provider_id
                    and existing.external_id == share_url.external_id
                ):
                    # Re-sent identical pending share link (e.g. adding -n or password).
                    effective_code = effective_code or existing.code
                    effective_no_subdir = bool(existing.no_subdir or parsed.no_subdir)

            policy = provider.spec.password_policy
            if effective_code is not None or policy in (
                PasswordPolicy.OPTIONAL_TRY_FIRST,
                PasswordPolicy.NONE,
            ):
                if existing is not None:
                    await self._delete_pending(chat_id, user_id)
                ready_info = ShareLinkInfo(
                    provider_id=share_url.provider_id,
                    url=share_url.normalized_url,
                    external_id=share_url.external_id,
                    code=effective_code,
                    no_subdir=effective_no_subdir,
                    sub_dir_fid=share_url.sub_dir_fid,
                )
                return AssembleResult(
                    action=AssembleAction.READY,
                    share=ready_info,
                    shares=(ready_info,),
                    no_subdir=effective_no_subdir,
                )

            # PasswordPolicy.REQUIRED without code -> persist pending link and ask for password.
            await self._save_pending(
                PendingInputRecord(
                    chat_id=chat_id,
                    user_id=user_id,
                    provider_hint=share_url.provider_id,
                    url=share_url.normalized_url,
                    external_id=share_url.external_id,
                    code=None,
                    no_subdir=effective_no_subdir,
                    prompt_message_id=None,
                    updated_at=ts,
                )
            )
            return AssembleResult(
                action=AssembleAction.NEED_PASSWORD,
                pending_share=share_url,
                no_subdir=effective_no_subdir,
            )

        # Case B: Current message supplies ONLY an extraction code (no URL).
        if parsed.code is not None:
            if had_expired_pending:
                return AssembleResult(
                    action=AssembleAction.ERROR,
                    error_code=ErrorCode.PENDING_EXPIRED,
                    no_subdir=parsed.no_subdir,
                )

            if (
                existing is not None
                and existing.url is not None
                and existing.external_id is not None
                and existing.provider_hint is not None
            ):
                if (
                    effective_forced_id is not None
                    and effective_forced_id != existing.provider_hint
                ):
                    return AssembleResult(
                        action=AssembleAction.ERROR,
                        error_code=ErrorCode.INVALID_LINK,
                        no_subdir=parsed.no_subdir,
                    )
                merged_no_subdir = bool(existing.no_subdir or parsed.no_subdir)
                provider = self._registry.find(existing.provider_hint)
                sub_dir_fid = self._recover_sub_dir_fid(provider, existing.url)
                await self._delete_pending(chat_id, user_id)
                completed_share = ShareLinkInfo(
                    provider_id=existing.provider_hint,
                    url=existing.url,
                    external_id=existing.external_id,
                    code=parsed.code,
                    no_subdir=merged_no_subdir,
                    sub_dir_fid=sub_dir_fid,
                )
                return AssembleResult(
                    action=AssembleAction.READY,
                    share=completed_share,
                    shares=(completed_share,),
                    no_subdir=merged_no_subdir,
                )

            # Code-first half of a 2-message out-of-order input.
            merged_no_subdir = bool(
                (existing.no_subdir if existing is not None else False) or parsed.no_subdir
            )
            provider_hint = effective_forced_id or (
                existing.provider_hint if existing is not None else None
            )
            await self._save_pending(
                PendingInputRecord(
                    chat_id=chat_id,
                    user_id=user_id,
                    provider_hint=provider_hint,
                    url=None,
                    external_id=None,
                    code=parsed.code,
                    no_subdir=merged_no_subdir,
                    prompt_message_id=None,
                    updated_at=ts,
                )
            )
            return AssembleResult(
                action=AssembleAction.AWAIT_LINK,
                no_subdir=merged_no_subdir,
            )

        # Case C: Neither URL nor extraction code found.
        if had_expired_pending and parsed.no_subdir:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.PENDING_EXPIRED,
                no_subdir=True,
            )
        if effective_forced_id is not None:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.INVALID_LINK,
                no_subdir=parsed.no_subdir,
            )
        return AssembleResult(action=AssembleAction.IGNORE, no_subdir=parsed.no_subdir)

    async def handle_group_command(
        self,
        *,
        chat_id: int,
        user_id: int,
        text: str,
        forced_provider_id: str | None = None,
        now: float | None = None,
    ) -> AssembleResult:
        """Parse explicit group transfer command (`/baidu`, `/pikpak`, `/quark`); ignore prose."""
        ts = time.time() if now is None else float(now)
        _cmd, effective_forced_id, stripped = self._resolve_command_provider(
            text, forced_provider_id
        )
        if effective_forced_id is None:
            return AssembleResult(action=AssembleAction.IGNORE)

        provider = self._registry.find(effective_forced_id)
        if provider is None:
            return AssembleResult(action=AssembleAction.ERROR, error_code=ErrorCode.INVALID_LINK)

        parsed = parse_transfer_text(
            stripped,
            self._registry.all_recognizers(),
            forced_provider_id=effective_forced_id,
        )
        if parsed.ambiguous:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.AMBIGUOUS_INPUT,
                no_subdir=parsed.no_subdir,
            )
        if parsed.invalid_link_candidate or parsed.share is None:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.INVALID_LINK,
                no_subdir=parsed.no_subdir,
            )

        if len(parsed.shares) > 1:
            return await self._assemble_batch_shares(
                chat_id=chat_id,
                user_id=user_id,
                items=parsed.shares,
                no_subdir=parsed.no_subdir,
                existing_pending=None,
                save_single_missing_pending=True,
                ts=ts,
            )

        share_url = parsed.share
        policy = provider.spec.password_policy
        if parsed.code is not None or policy in (
            PasswordPolicy.OPTIONAL_TRY_FIRST,
            PasswordPolicy.NONE,
        ):
            ready_info = ShareLinkInfo(
                provider_id=share_url.provider_id,
                url=share_url.normalized_url,
                external_id=share_url.external_id,
                code=parsed.code,
                no_subdir=parsed.no_subdir,
                sub_dir_fid=share_url.sub_dir_fid,
            )
            return AssembleResult(
                action=AssembleAction.READY,
                share=ready_info,
                shares=(ready_info,),
                no_subdir=parsed.no_subdir,
            )

        # Persist preliminary pending share (prompt_message_id=None until ForceReply is sent)
        # so save_password_prompt works whether caller passes `share` or only `prompt_message_id`.
        await self._save_pending(
            PendingInputRecord(
                chat_id=chat_id,
                user_id=user_id,
                provider_hint=share_url.provider_id,
                url=share_url.normalized_url,
                external_id=share_url.external_id,
                code=None,
                no_subdir=parsed.no_subdir,
                prompt_message_id=None,
                updated_at=ts,
            )
        )
        return AssembleResult(
            action=AssembleAction.NEED_PASSWORD,
            pending_share=share_url,
            no_subdir=parsed.no_subdir,
        )

    async def save_password_prompt(
        self,
        *,
        chat_id: int,
        user_id: int,
        share: ShareLinkInfo | RecognizedShareUrl | None = None,
        pending_share: ShareLinkInfo | RecognizedShareUrl | None = None,
        no_subdir: bool | None = None,
        prompt_message_id: int | None = None,
        now: float | None = None,
    ) -> PendingInputRecord:
        """Persist pending share awaiting password (ForceReply or OPTIONAL_TRY_FIRST retry)."""
        ts = time.time() if now is None else float(now)
        target = share if share is not None else pending_share
        if target is None:
            existing = await self._get_pending(chat_id, user_id)
            if existing is None:
                raise ValueError(
                    "Either `share`/`pending_share` or an existing pending row must exist"
                )
            merged_no_subdir = (
                existing.no_subdir if no_subdir is None else bool(no_subdir or existing.no_subdir)
            )
            updated = PendingInputRecord(
                chat_id=chat_id,
                user_id=user_id,
                provider_hint=existing.provider_hint,
                url=existing.url,
                external_id=existing.external_id,
                code=existing.code,
                no_subdir=merged_no_subdir,
                prompt_message_id=prompt_message_id,
                updated_at=ts,
            )
            await self._save_pending(updated)
            return updated

        if isinstance(target, RecognizedShareUrl):
            url = target.normalized_url
            effective_no_subdir = bool(no_subdir)
        else:
            url = target.url
            if target.provider_id == "quark" and target.sub_dir_fid != "0" and "#" not in url:
                url = f"{url}#/list/share/{target.sub_dir_fid}"
            effective_no_subdir = (
                target.no_subdir if no_subdir is None else bool(no_subdir or target.no_subdir)
            )

        record = PendingInputRecord(
            chat_id=chat_id,
            user_id=user_id,
            provider_hint=target.provider_id,
            url=url,
            external_id=target.external_id,
            code=None,
            no_subdir=effective_no_subdir,
            prompt_message_id=prompt_message_id,
            updated_at=ts,
        )
        await self._save_pending(record)
        return record

    async def handle_group_reply(
        self,
        *,
        chat_id: int,
        user_id: int,
        reply_to_message_id: int,
        text: str,
        now: float | None = None,
    ) -> AssembleResult:
        """Complete a group ForceReply prompt when `(chat_id, user_id, prompt_message_id)` match."""
        row = await self._get_pending(chat_id, user_id)
        if row is None or row.prompt_message_id is None:
            return AssembleResult(action=AssembleAction.IGNORE)
        if row.prompt_message_id != reply_to_message_id:
            return AssembleResult(action=AssembleAction.IGNORE)

        ts = time.time() if now is None else float(now)
        ttl = self._get_ttl_seconds()
        if ts - row.updated_at > ttl:
            await self._delete_pending(chat_id, user_id)
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.PENDING_EXPIRED,
                no_subdir=row.no_subdir,
            )

        parsed = parse_transfer_text(text, self._registry.all_recognizers())
        merged_no_subdir = bool(row.no_subdir or parsed.no_subdir)

        if parsed.ambiguous:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.AMBIGUOUS_INPUT,
                no_subdir=merged_no_subdir,
            )
        if parsed.invalid_link_candidate:
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.INVALID_LINK,
                no_subdir=merged_no_subdir,
            )
        if len(parsed.shares) > 1 or (
            parsed.share is not None
            and (parsed.share.provider_id, parsed.share.external_id)
            != (row.provider_hint, row.external_id)
        ):
            return AssembleResult(
                action=AssembleAction.ERROR,
                error_code=ErrorCode.AMBIGUOUS_INPUT,
                no_subdir=merged_no_subdir,
            )

        if parsed.code is None or not row.url or not row.external_id or not row.provider_hint:
            return AssembleResult(
                action=AssembleAction.NEED_PASSWORD,
                no_subdir=merged_no_subdir,
            )

        provider = self._registry.find(row.provider_hint)
        sub_dir_fid = self._recover_sub_dir_fid(provider, row.url)
        await self._delete_pending(chat_id, user_id)
        completed_share = ShareLinkInfo(
            provider_id=row.provider_hint,
            url=row.url,
            external_id=row.external_id,
            code=parsed.code,
            no_subdir=merged_no_subdir,
            sub_dir_fid=sub_dir_fid,
        )
        return AssembleResult(
            action=AssembleAction.READY,
            share=completed_share,
            shares=(completed_share,),
            no_subdir=merged_no_subdir,
        )

    async def _assemble_batch_shares(
        self,
        *,
        chat_id: int,
        user_id: int,
        items: tuple[ParsedShareItem, ...],
        no_subdir: bool,
        existing_pending: PendingInputRecord | None,
        save_single_missing_pending: bool,
        ts: float,
    ) -> AssembleResult:
        """Validate and partition multi-link batch items into ready shares and missing-pwd items."""
        if len(items) > MAX_BATCH_LINKS_PER_MESSAGE:
            return AssembleResult(
                action=AssembleAction.ERROR,
                message=(
                    f"⚠️ 单次批量转存最多支持 {MAX_BATCH_LINKS_PER_MESSAGE} 个分享链接"
                    f"（本次识别到 {len(items)} 个），请分批发送。"
                ),
                no_subdir=no_subdir,
            )

        ready_shares: list[ShareLinkInfo] = []
        missing_pwd: list[RecognizedShareUrl] = []

        for item in items:
            provider = self._registry.find(item.share.provider_id)
            if provider is None:
                return AssembleResult(
                    action=AssembleAction.ERROR,
                    error_code=ErrorCode.INVALID_LINK,
                    no_subdir=no_subdir,
                )
            policy = provider.spec.password_policy
            if item.code is not None or policy in (
                PasswordPolicy.OPTIONAL_TRY_FIRST,
                PasswordPolicy.NONE,
            ):
                ready_shares.append(
                    ShareLinkInfo(
                        provider_id=item.share.provider_id,
                        url=item.share.normalized_url,
                        external_id=item.share.external_id,
                        code=item.code,
                        no_subdir=no_subdir,
                        sub_dir_fid=item.share.sub_dir_fid,
                    )
                )
            else:
                missing_pwd.append(item.share)

        if existing_pending is not None:
            await self._delete_pending(chat_id, user_id)

        if not ready_shares:
            return AssembleResult(
                action=AssembleAction.ERROR,
                message=(
                    f"🔑 识别到 {len(missing_pwd)} 个加密分享链接均未附带提取码；"
                    "批量发送时请在每条链接后附上对应提取码。"
                ),
                no_subdir=no_subdir,
            )

        pending_single: RecognizedShareUrl | None = None
        if save_single_missing_pending and len(missing_pwd) == 1:
            pending_single = missing_pwd[0]
            await self._save_pending(
                PendingInputRecord(
                    chat_id=chat_id,
                    user_id=user_id,
                    provider_hint=pending_single.provider_id,
                    url=pending_single.normalized_url,
                    external_id=pending_single.external_id,
                    code=None,
                    no_subdir=no_subdir,
                    prompt_message_id=None,
                    updated_at=ts,
                )
            )

        return AssembleResult(
            action=AssembleAction.READY,
            share=ready_shares[0],
            shares=tuple(ready_shares),
            skipped_need_password=tuple(missing_pwd),
            pending_share=pending_single,
            no_subdir=no_subdir,
        )
