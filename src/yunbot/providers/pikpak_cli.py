"""PikPak cloud storage provider backed by the official PikPak CLI v0.6.0 (§5.6).

Strict Dependency Boundary:
MUST NOT import `storage`, `runtime_config`, `pydantic`, `requests`, or `httpx`.
All persistence and runtime settings access go through the Protocols in `providers.base`.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import signal
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlsplit

from yunbot.models import (
    CLI_COMMAND_TIMEOUT_SECONDS,
    CLI_MAX_OUTPUT_BYTES,
    MAX_SHARE_ENUM_ITEMS,
    MAX_SNAPSHOT_ITEMS_PER_PHASE,
    PIKPAK_LS_PAGE_SIZE,
    PIKPAK_SHARE_PAGE_SIZE,
    PIKPAK_TASK_POLL_DELAYS_SECONDS,
    PIKPAK_TASK_POLL_TIMEOUT_SECONDS,
    AuthMode,
    BindingMismatchError,
    DeleteItemsOutcome,
    DirectUnsafeDirError,
    EnumLimitExceededError,
    ErrorCode,
    InteractiveAuthPollResult,
    InteractiveAuthStart,
    PasswordPolicy,
    ProviderAccountStatus,
    ProviderAuthInvalidError,
    ProviderCredentialRecord,
    ProviderInvalidPasswordError,
    ProviderNeedPasswordError,
    ProviderQuotaExceededError,
    ProviderRateLimitedError,
    ProviderShareExpiredError,
    RecognizedShareUrl,
    ShareLinkInfo,
    SnapshotPhase,
    SnapshotTempEntry,
    TransferItemRecord,
    TransferOutcome,
    TransferredEntry,
    YunBotError,
    format_error_message,
    redact_sensitive_text,
    validate_direct_item_path,
    validate_save_path,
)
from yunbot.providers.base import (
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

logger = logging.getLogger(__name__)

PIKPAK_SPEC = ProviderSpec(
    provider_id="pikpak",
    display_name="PikPak",
    command="pikpak",
    password_policy=PasswordPolicy.OPTIONAL_TRY_FIRST,
    auth_mode=AuthMode.INTERACTIVE_FLOW,
    extra_auth_modes=(AuthMode.SECRET_FIELDS,),
    secret_fields=(
        ProviderFieldSpec(
            key="pat",
            label="Personal Access Token (PAT)",
            secret=True,
            required=True,
            placeholder="粘贴 PikPak PAT",
        ),
    ),
    save_path_key="PIKPAK_SAVE_PATH",
    openlist_path_key="OPENLIST_PIKPAK_PATH",
    default_save_path="/My Pack/转存文件",
    default_openlist_path="/pikpak/转存文件",
    requires_exclusive_dir_for_direct=True,
)

_SAFE_PATH_ENV = "/usr/local/bin:/usr/bin:/bin"
_RM_BATCH_SIZE = 100
_SHARE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$")
_HUMAN_CODE_RE = re.compile(r"^\s*Code:\s*([A-Za-z0-9_.-]+)\s*$", re.MULTILINE)
_HUMAN_REASON_RE = re.compile(r"^\s*Reason:\s*(.+?)\s*$", re.MULTILINE)
_HUMAN_ERROR_RE = re.compile(r"^\s*Error:\s*(.+?)\s*$", re.MULTILINE)
_HUMAN_HTTP_STATUS_RE = re.compile(r"(?:HTTP\s+|^|\b)(401|403|404|429)\b", re.IGNORECASE)
_JWT_SUB_RE = re.compile(r"^[A-Za-z0-9_-]{3,128}$")

_AUTH_ERROR_CODES: frozenset[str] = frozenset(
    {
        "UNAUTHENTICATED",
        "UNAUTHORIZED",
        "TOKEN_EXPIRED",
        "TOKEN_REFRESH_FAILED",
        "CREDENTIALS_ERROR",
        "AUTH_REQUIRED",
        "NOT_LOGGED_IN",
    }
)
_QUOTA_ERROR_CODES: frozenset[str] = frozenset(
    {
        "FILE_SPACE_NOT_ENOUGH",
        "SPACE_NOT_ENOUGH",
        "TASK_DAILY_CREATE_LIMIT",
        "DAILY_CREATE_LIMIT_FREE",
        "TRANSFER_QUOTA_EXCEEDED",
        "CONNECTED_APPS_QUOTA_EXCEEDED",
        "QUOTA_EXCEEDED",
    }
)
_RATE_LIMIT_ERROR_CODES: frozenset[str] = frozenset(
    {
        "TOO_MANY_REQUESTS",
        "RATE_LIMITED",
        "RATE_LIMIT_EXCEEDED",
        "ABUSE_DETECTED",
    }
)
_NOT_FOUND_ERROR_CODES: frozenset[str] = frozenset(
    {
        "FILE_NOT_FOUND",
        "INVALID_FILE_ID",
        "NOT_FOUND",
        "SHARE_NOT_FOUND",
    }
)
_SHARE_EXPIRED_CODES: frozenset[str] = frozenset(
    {
        "SHARE_NOT_FOUND",
        "FILE_NOT_FOUND",
        "NOT_FOUND",
        "SHARE_EXPIRED",
        "SHARE_DELETED",
        "SHARE_FORBIDDEN",
        "SHARE_AUDIT_FAILED",
        "SHARE_BANNED",
        "EXPIRED",
        "DELETED",
    }
)
_SHARE_EXPIRED_STATUSES: frozenset[str] = frozenset(
    {
        "DELETED",
        "EXPIRED",
        "FORBIDDEN",
        "BANNED",
        "SHARE_STATUS_DELETED",
        "SHARE_STATUS_EXPIRED",
        "SHARE_STATUS_FORBIDDEN",
    }
)


def _mask_secrets(text: str, secrets_to_mask: Sequence[str] = ()) -> str:
    """Redact explicit runtime secret values as well as standard sensitive patterns."""
    if not text:
        return ""
    masked = text
    for secret in secrets_to_mask:
        if secret and len(secret) >= 2:
            masked = masked.replace(secret, "[REDACTED]")
    return redact_sensitive_text(masked)


def _safe_json_dict(raw_json: str) -> dict[str, Any]:
    if not raw_json:
        return {}
    try:
        parsed = json.loads(raw_json)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _extract_pat_jwt_sub(pat_token: str | None) -> str | None:
    """Extract candidate `sub` user_id from a non-expired JWT PAT (verified via live CLI call)."""
    raw = (pat_token or "").strip()
    if not raw:
        return None
    parts = raw.split(".")
    if len(parts) != 3 or not all(parts):
        return None
    payload_b64 = parts[1]
    padded = payload_b64 + ("=" * ((-len(payload_b64)) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        claims = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and exp > 0 and time.time() >= float(exp):
        return None
    sub = str(claims.get("sub") or "").strip()
    if not _JWT_SUB_RE.fullmatch(sub):
        return None
    return sub


def _is_folder_entry(entry: Mapping[str, Any], *, default_folder: bool = False) -> bool:
    if isinstance(entry.get("is_dir"), bool):
        return bool(entry["is_dir"])
    kind = str(entry.get("kind") or entry.get("type") or "").strip().lower()
    if not kind:
        return default_folder
    return kind in ("folder", "drive#folder", "dir", "directory")


def _parse_optional_task_progress(raw_prog: Any) -> int | None:
    if isinstance(raw_prog, bool):
        return None
    if isinstance(raw_prog, (int, float)):
        return max(0, min(int(raw_prog), 100))
    if isinstance(raw_prog, str):
        cleaned = raw_prog.strip().rstrip("%").strip()
        if cleaned and cleaned != "-":
            try:
                return max(0, min(int(float(cleaned)), 100))
            except ValueError:
                return None
    return None


def _parse_task_progress(raw_prog: Any) -> int:
    parsed = _parse_optional_task_progress(raw_prog)
    return parsed if parsed is not None else 0


def _is_task_complete(status_str: str, phase_str: str) -> bool:
    s = status_str.strip().lower()
    p = phase_str.strip().upper()
    return (
        p == "PHASE_TYPE_COMPLETE"
        or "phase_type_complete" in s
        or s in ("complete", "completed", "success", "succeeded")
        or s.startswith(("complete ", "complete(", "completed ", "completed("))
    )


def _is_task_failed(status_str: str, phase_str: str) -> bool:
    s = status_str.strip().lower()
    p = phase_str.strip().upper()
    return (
        p == "PHASE_TYPE_ERROR"
        or "phase_type_error" in s
        or s in ("error", "failed", "fail")
        or s.startswith(("error ", "error(", "failed ", "failed("))
    )


class _BuiltinPikPakShareRecognizer:
    """Pure-function fallback recognizer for mypikpak.com/s/<share_id> URLs."""

    @property
    def provider_id(self) -> str:
        return "pikpak"

    def recognize(self, url: str) -> RecognizedShareUrl | None:
        raw = (url or "").strip()
        if not raw:
            return None
        try:
            parts = urlsplit(raw)
        except ValueError:
            return None
        if parts.scheme.lower() not in ("http", "https"):
            return None
        host = (parts.hostname or "").lower()
        if host not in ("mypikpak.com", "www.mypikpak.com"):
            return None
        segments = [seg for seg in parts.path.split("/") if seg]
        if len(segments) < 2 or segments[0] != "s":
            return None
        share_id = segments[1].strip()
        if not _SHARE_ID_RE.fullmatch(share_id):
            return None

        query = parse_qs(parts.query)
        embedded_code: str | None = None
        for key in ("pwd", "pass_code", "password", "code"):
            vals = query.get(key)
            if vals and vals[0].strip():
                embedded_code = vals[0].strip()
                break

        return RecognizedShareUrl(
            provider_id="pikpak",
            normalized_url=f"https://mypikpak.com/s/{share_id}",
            external_id=share_id,
            embedded_code=embedded_code,
        )


@dataclass(frozen=True, slots=True)
class _CliExecResult:
    """Raw bounded subprocess execution result."""

    returncode: int
    stdout: str
    stderr: str


class _PikPakCliError(Exception):
    """Structured failure raised by _PikPakCliRunner with redacted diagnostics."""

    def __init__(
        self,
        summary: str,
        *,
        returncode: int = -1,
        service_code: str = "",
        reason: str = "",
        http_status: int | None = None,
        timed_out: bool = False,
        truncated: bool = False,
    ) -> None:
        self.safe_summary = redact_sensitive_text(summary)
        self.returncode = returncode
        self.service_code = service_code.strip().upper()
        self.reason = redact_sensitive_text(reason)
        self.http_status = http_status
        self.timed_out = timed_out
        self.truncated = truncated
        super().__init__(self.safe_summary)

    @property
    def combined_lower(self) -> str:
        return f"{self.service_code} {self.reason} {self.safe_summary}".lower()


@dataclass(frozen=True, slots=True)
class _PendingDeviceAuth:
    """In-memory pending OAuth 2.0 Device Flow state."""

    device_code: str
    verification_uri: str
    user_code: str
    expires_at: float
    interval: int


class _PikPakCliRunner:
    """Hardened subprocess runner for PikPak CLI v0.6.0 (§3.3, §5.6.1, R08).

    Enforces:
    - `create_subprocess_exec` with `stdin=DEVNULL` and `start_new_session=True` (never shell)
    - Strict minimal environment whitelist (never leaks Telegram/Baidu/Quark/OpenList secrets)
    - Concurrent `stdout` & `stderr` draining with `CLI_MAX_OUTPUT_BYTES` truncation-fails rule
    - Process-group `SIGKILL` + `proc.wait()` on truncation, timeout, cancellation, or shutdown
    """

    def __init__(
        self,
        *,
        binary_path: str = "/usr/local/bin/pikpak",
        pikpak_dir: str | Path = "/app/data/pikpak",
        command_timeout: float = CLI_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes: int = CLI_MAX_OUTPUT_BYTES,
    ) -> None:
        self._binary_path = binary_path
        self._pikpak_dir = Path(pikpak_dir)
        self._command_timeout = command_timeout
        self._max_output_bytes = max_output_bytes
        self._active_procs: set[asyncio.subprocess.Process] = set()
        self._closed = False

    @property
    def pikpak_dir(self) -> Path:
        return self._pikpak_dir

    def build_env(self, *, pat_token: str | None = None) -> dict[str, str]:
        """Build isolated child environment from scratch without reading os.environ."""
        dir_str = str(self._pikpak_dir)
        env: dict[str, str] = {
            "PATH": _SAFE_PATH_ENV,
            "HOME": dir_str,
            "PIKPAK_DIR": dir_str,
            "PIKPAK_NO_UPDATE_NOTIFIER": "1",
            "PIKPAK_NO_LOG": "1",
            "LANG": "C.UTF-8",
        }
        if pat_token:
            env["PIKPAK_TOKEN"] = pat_token
        return env

    def _ensure_pikpak_dir_if_mounted(self) -> None:
        parent = self._pikpak_dir.parent
        if parent.exists() and not self._pikpak_dir.exists():
            try:
                self._pikpak_dir.mkdir(mode=0o700, exist_ok=True)
            except OSError:
                pass

    @staticmethod
    def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
        pid = getattr(proc, "pid", None)
        if isinstance(pid, int) and pid > 1 and pid != os.getpid() and pid != os.getpgrp():
            try:
                os.killpg(pid, signal.SIGKILL)
                return
            except ProcessLookupError:
                return
            except (PermissionError, OSError):
                pass
        try:
            proc.kill()
        except (ProcessLookupError, OSError):
            pass

    async def _read_bounded_stream(
        self,
        stream: asyncio.StreamReader | None,
        proc: asyncio.subprocess.Process,
    ) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        buf = bytearray()
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                return bytes(buf), False
            if len(buf) + len(chunk) > self._max_output_bytes:
                keep = self._max_output_bytes - len(buf)
                if keep > 0:
                    buf.extend(chunk[:keep])
                self._kill_process_group(proc)
                return bytes(buf), True
            buf.extend(chunk)

    async def run_raw(
        self,
        args: Sequence[str],
        *,
        pat_token: str | None = None,
        redact_values: Sequence[str] = (),
        timeout: float | None = None,
    ) -> _CliExecResult:
        if self._closed:
            raise _PikPakCliError("PikPak CLI runner is closed")

        self._ensure_pikpak_dir_if_mounted()
        secrets_list: list[str] = [s for s in redact_values if s]
        if pat_token:
            secrets_list.append(pat_token)

        clean_env = self.build_env(pat_token=pat_token)
        effective_timeout = self._command_timeout if timeout is None else timeout

        try:
            proc = await asyncio.create_subprocess_exec(
                self._binary_path,
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
                env=clean_env,
            )
        except OSError as exc:
            safe_err = _mask_secrets(str(exc), secrets_list)
            raise _PikPakCliError(f"Failed to execute pikpak CLI: {safe_err}") from exc

        self._active_procs.add(proc)
        if self._closed:
            self._kill_process_group(proc)
            await proc.wait()
            self._active_procs.discard(proc)
            raise _PikPakCliError("PikPak CLI runner closed during spawn")

        async def _drain_and_wait() -> tuple[bytes, bool, bytes, bool]:
            (out_b, out_trunc), (err_b, err_trunc) = await asyncio.gather(
                self._read_bounded_stream(proc.stdout, proc),
                self._read_bounded_stream(proc.stderr, proc),
            )
            await proc.wait()
            return out_b, out_trunc, err_b, err_trunc

        try:
            out_bytes, out_truncated, err_bytes, err_truncated = await asyncio.wait_for(
                _drain_and_wait(),
                timeout=effective_timeout,
            )
        except TimeoutError as exc:
            self._kill_process_group(proc)
            await proc.wait()
            raise _PikPakCliError(
                f"pikpak command timed out after {effective_timeout}s",
                timed_out=True,
            ) from exc
        except asyncio.CancelledError:
            self._kill_process_group(proc)
            await proc.wait()
            raise
        finally:
            self._active_procs.discard(proc)

        if out_truncated or err_truncated:
            self._kill_process_group(proc)
            await proc.wait()
            which = "stdout" if out_truncated else "stderr"
            raise _PikPakCliError(
                f"pikpak CLI {which} exceeded CLI_MAX_OUTPUT_BYTES ({self._max_output_bytes})",
                returncode=proc.returncode if proc.returncode is not None else -9,
                service_code="OUTPUT_TRUNCATED",
                truncated=True,
            )

        stdout_text = out_bytes.decode("utf-8", errors="replace")
        stderr_text = err_bytes.decode("utf-8", errors="replace")
        rc = proc.returncode if proc.returncode is not None else 0

        if rc != 0:
            raise self._parse_cli_failure(
                rc=rc,
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                secrets_list=secrets_list,
            )

        return _CliExecResult(returncode=rc, stdout=stdout_text, stderr=stderr_text)

    async def run_json(
        self,
        args: Sequence[str],
        *,
        pat_token: str | None = None,
        redact_values: Sequence[str] = (),
        timeout: float | None = None,
        allow_empty: bool = False,
        allow_non_json_text: bool = False,
    ) -> dict[str, Any]:
        secrets_list: list[str] = [s for s in redact_values if s]
        if pat_token:
            secrets_list.append(pat_token)

        res = await self.run_raw(
            args,
            pat_token=pat_token,
            redact_values=redact_values,
            timeout=timeout,
        )
        stripped = res.stdout.strip()
        if not stripped:
            if allow_empty:
                return {}
            raise _PikPakCliError("pikpak CLI returned empty JSON output")

        if allow_non_json_text and not stripped.startswith(("{", "[")):
            return {}

        try:
            parsed = json.loads(stripped)
        except ValueError as exc:
            snippet = _mask_secrets(stripped[:200], secrets_list)
            raise _PikPakCliError(f"pikpak CLI returned invalid JSON: {snippet}") from exc

        if not isinstance(parsed, dict):
            raise _PikPakCliError("pikpak CLI JSON root must be an object")

        err_obj = parsed.get("error")
        if isinstance(err_obj, dict):
            code = str(err_obj.get("code") or "").strip().upper()
            reason = _mask_secrets(
                str(err_obj.get("reason") or err_obj.get("message") or ""),
                secrets_list,
            )
            raw_status = err_obj.get("status")
            status = int(raw_status) if isinstance(raw_status, int) else None
            raise _PikPakCliError(
                f"pikpak error {code}: {reason}".strip(),
                returncode=res.returncode,
                service_code=code,
                reason=reason,
                http_status=status,
            )

        return parsed

    @staticmethod
    def _parse_cli_failure(
        *,
        rc: int,
        stdout_text: str,
        stderr_text: str,
        secrets_list: Sequence[str],
    ) -> _PikPakCliError:
        service_code = ""
        reason = ""
        message = ""
        http_status: int | None = None

        for candidate in (stderr_text.strip(), stdout_text.strip()):
            if not candidate:
                continue
            try:
                payload = json.loads(candidate)
            except ValueError:
                continue
            if isinstance(payload, dict):
                err_node = payload.get("error")
                node = err_node if isinstance(err_node, dict) else payload
                service_code = str(
                    node.get("code") or node.get("error_code") or node.get("error") or ""
                ).strip()
                reason = str(node.get("reason") or node.get("error_description") or "").strip()
                message = str(node.get("message") or "").strip()
                raw_status = node.get("status")
                if isinstance(raw_status, int):
                    http_status = raw_status
                if service_code or reason or message:
                    break

        if not service_code and stderr_text:
            code_match = _HUMAN_CODE_RE.search(stderr_text)
            if code_match:
                service_code = code_match.group(1).strip()
            reason_match = _HUMAN_REASON_RE.search(stderr_text)
            if reason_match:
                reason = reason_match.group(1).strip()
            err_match = _HUMAN_ERROR_RE.search(stderr_text)
            if err_match:
                message = err_match.group(1).strip()

        raw_detail = reason or message or stderr_text.strip() or stdout_text.strip()
        if http_status is None and raw_detail:
            http_match = _HUMAN_HTTP_STATUS_RE.search(raw_detail)
            if http_match:
                http_status = int(http_match.group(1))
        safe_detail = _mask_secrets(raw_detail[:400], secrets_list)
        safe_reason = _mask_secrets(reason or message, secrets_list)
        summary = (
            f"pikpak exited with {rc} ({service_code.upper()}): {safe_detail}"
            if service_code
            else f"pikpak exited with {rc}: {safe_detail}"
        )
        return _PikPakCliError(
            summary,
            returncode=rc,
            service_code=service_code,
            reason=safe_reason or safe_detail,
            http_status=http_status,
        )

    async def close(self) -> None:
        self._closed = True
        procs = list(self._active_procs)
        for proc in procs:
            self._kill_process_group(proc)
        if procs:
            await asyncio.gather(*(proc.wait() for proc in procs), return_exceptions=True)
        self._active_procs.clear()


class PikPakCliProvider:
    """CloudProvider implementation for PikPak via official CLI v0.6.0 (§5.6)."""

    def __init__(
        self,
        credential_store: CredentialStore,
        snapshot_store: SnapshotStore,
        config_reader: ProviderConfigReader,
        *,
        pikpak_dir: str | Path = "/app/data/pikpak",
        binary_path: str = "/usr/local/bin/pikpak",
        recognizer: ShareRecognizer | None = None,
        runner: _PikPakCliRunner | None = None,
        command_timeout: float = CLI_COMMAND_TIMEOUT_SECONDS,
        max_output_bytes: int = CLI_MAX_OUTPUT_BYTES,
        sleep_func: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic_func: Callable[[], float] = time.monotonic,
    ) -> None:
        self._credential_store = credential_store
        self._snapshot_store = snapshot_store
        self._config_reader = config_reader
        self._sleep = sleep_func
        self._monotonic = monotonic_func
        self._auth_lock = asyncio.Lock()
        self._pending_device: _PendingDeviceAuth | None = None

        if runner is not None:
            self._runner = runner
        else:
            self._runner = _PikPakCliRunner(
                binary_path=binary_path,
                pikpak_dir=pikpak_dir,
                command_timeout=command_timeout,
                max_output_bytes=max_output_bytes,
            )

        if recognizer is not None:
            self._recognizer: ShareRecognizer = recognizer
        else:
            try:
                from yunbot.domain.parsing import PikPakShareRecognizer

                self._recognizer = PikPakShareRecognizer()
            except ImportError:
                self._recognizer = _BuiltinPikPakShareRecognizer()

    @property
    def spec(self) -> ProviderSpec:
        return PIKPAK_SPEC

    @property
    def recognizer(self) -> ShareRecognizer:
        return self._recognizer

    def validate_transfer_mode(self, *, no_subdir: bool) -> None:
        if no_subdir and not self._config_reader.is_direct_exclusive_dir_confirmed("pikpak"):
            raise DirectUnsafeDirError()

    def get_oauth_authorize_url(self) -> str | None:
        return None

    async def exchange_oauth_code(self, code: str) -> ProviderAccountStatus:
        raise YunBotError(ErrorCode.INTERNAL_ERROR, "PikPak 不支持 OAuth 授权码模式")

    async def keepalive(self) -> None:
        return None

    # ------------------------------------------------------------------
    # Authentication & Account Binding (pikpak:<user_id>)
    # ------------------------------------------------------------------

    def _get_env_pat(self) -> str:
        settings = self._config_reader.get_provider_settings("pikpak")
        return (settings.get("PIKPAK_PAT") or settings.get("pat") or "").strip()

    async def _fetch_auth_identity(self, *, pat_token: str | None) -> tuple[str, str, str]:
        """Run `pikpak auth status -F json` (or JWT PAT `ls` fallback) and return identity."""
        try:
            data = await self._runner.run_json(
                ["auth", "status", "-F", "json"],
                pat_token=pat_token,
            )
        except _PikPakCliError as auth_exc:
            jwt_sub = _extract_pat_jwt_sub(pat_token) if pat_token else None
            if (
                jwt_sub is not None
                and not auth_exc.timed_out
                and not auth_exc.truncated
                and self._is_auth_cli_error(auth_exc)
            ):
                try:
                    await self._runner.run_json(
                        ["ls", "-l", "1", "-F", "json"],
                        pat_token=pat_token,
                    )
                except _PikPakCliError as ls_exc:
                    raise self._map_general_cli_error(ls_exc) from ls_exc
                short = jwt_sub[:6] if len(jwt_sub) > 6 else jwt_sub
                return jwt_sub, f"PAT ({short})", ""
            raise self._map_general_cli_error(auth_exc) from auth_exc

        logged_in = bool(data.get("logged_in"))
        user_id = str(data.get("user_id") or "").strip()
        if not logged_in or not user_id:
            raise ProviderAuthInvalidError("PikPak", "PikPak 尚未登录或凭证已失效")

        name = str(data.get("name") or "").strip()
        email = str(data.get("email") or "").strip()
        return user_id, name, email

    async def save_secret_credentials(self, fields: Mapping[str, str]) -> ProviderAccountStatus:
        pat = (fields.get("pat") or fields.get("PIKPAK_PAT") or "").strip()
        if not pat:
            raise ProviderAuthInvalidError("PikPak", "Personal Access Token (PAT) 不能为空")

        async with self._auth_lock:
            user_id, name, email = await self._fetch_auth_identity(pat_token=pat)
            binding_id = f"pikpak:{user_id}"
            now = time.time()
            record = ProviderCredentialRecord(
                provider="pikpak",
                access_token=pat,
                refresh_token="",
                account_binding_id=binding_id,
                extra_json=json.dumps(
                    {"mode": "pat", "user_id": user_id, "name": name, "email": email},
                    ensure_ascii=False,
                ),
                updated_at=now,
            )
            await self._credential_store.upsert_credential(record)
            self._pending_device = None
            return ProviderAccountStatus(
                provider_id="pikpak",
                authorized=True,
                account_binding_id=binding_id,
                account_label=name or email or user_id,
                auth_mode_used="pat",
                updated_at=now,
                message="PikPak PAT 授权有效",
            )

    async def seed_initial_pat_if_empty(
        self, pat: str | None = None
    ) -> ProviderAccountStatus | None:
        """Optionally seed initial PIKPAK_PAT only when no stored credential exists."""
        existing = await self._credential_store.get_credential("pikpak")
        if existing is not None and existing.account_binding_id.strip():
            return await self.get_account_status()

        raw_pat = pat if pat is not None else self._get_env_pat()
        if not raw_pat or not raw_pat.strip():
            return None
        return await self.save_secret_credentials({"pat": raw_pat})

    async def start_interactive_auth(self) -> InteractiveAuthStart:
        async with self._auth_lock:
            try:
                data = await self._runner.run_json(
                    ["auth", "login", "-m", "device", "--force", "-F", "json"],
                    pat_token=None,
                )
            except _PikPakCliError as exc:
                raise self._map_general_cli_error(exc) from exc

            device_code = str(data.get("device_code") or "").strip()
            verification_uri = str(
                data.get("verification_uri") or data.get("verification_uri_complete") or ""
            ).strip()
            user_code = str(data.get("user_code") or "").strip()
            expires_in = max(int(data.get("expires_in") or 300), 1)
            interval = max(int(data.get("interval") or 5), 1)

            if not device_code or not verification_uri:
                raise YunBotError(ErrorCode.INTERNAL_ERROR, "PikPak 设备码响应缺少必要字段")

            self._pending_device = _PendingDeviceAuth(
                device_code=device_code,
                verification_uri=verification_uri,
                user_code=user_code,
                expires_at=self._monotonic() + float(expires_in),
                interval=interval,
            )
            return InteractiveAuthStart(
                verification_uri=verification_uri,
                user_code=user_code,
                expires_in=expires_in,
                interval=interval,
            )

    async def poll_interactive_auth(self) -> InteractiveAuthPollResult:
        async with self._auth_lock:
            pending = self._pending_device
            if pending is None:
                return InteractiveAuthPollResult(
                    status="error",
                    message="当前没有进行中的 PikPak 设备码授权流程",
                )
            if self._monotonic() >= pending.expires_at:
                self._pending_device = None
                return InteractiveAuthPollResult(
                    status="expired",
                    message="设备码已过期，请重新发起授权",
                )

            try:
                poll_data = await self._runner.run_json(
                    ["auth", "login", "--continue", pending.device_code, "-F", "json"],
                    pat_token=None,
                    redact_values=(pending.device_code,),
                )
            except _PikPakCliError as exc:
                lower = exc.combined_lower
                if any(
                    tok in lower
                    for tok in ("authorization_pending", "slow_down", "pending", "waiting")
                ):
                    return InteractiveAuthPollResult(
                        status="pending",
                        message="等待用户在浏览器完成授权",
                    )
                self._pending_device = None
                if any(tok in lower for tok in ("expired", "expired_token", "device_code_expired")):
                    return InteractiveAuthPollResult(
                        status="expired",
                        message="设备码已过期，请重新发起授权",
                    )
                return InteractiveAuthPollResult(
                    status="error",
                    message=exc.safe_summary or "PikPak 设备码轮询失败",
                )

            status_raw = str(poll_data.get("status") or "").strip().lower()
            if status_raw in ("pending", "authorization_pending", "slow_down", "waiting"):
                return InteractiveAuthPollResult(
                    status="pending",
                    message="等待用户在浏览器完成授权",
                )
            if status_raw in ("expired", "expired_token"):
                self._pending_device = None
                return InteractiveAuthPollResult(
                    status="expired",
                    message="设备码已过期，请重新发起授权",
                )
            if status_raw in (
                "denied",
                "access_denied",
                "cancelled",
                "canceled",
                "error",
                "failed",
            ):
                self._pending_device = None
                return InteractiveAuthPollResult(
                    status="error",
                    message="PikPak 设备码授权被拒绝或失败",
                )

            try:
                user_id, name, email = await self._fetch_auth_identity(pat_token=None)
            except YunBotError as exc:
                self._pending_device = None
                return InteractiveAuthPollResult(
                    status="error",
                    message=exc.user_message,
                )

            binding_id = f"pikpak:{user_id}"
            now = time.time()
            record = ProviderCredentialRecord(
                provider="pikpak",
                access_token="",
                refresh_token="",
                account_binding_id=binding_id,
                extra_json=json.dumps(
                    {"mode": "device", "user_id": user_id, "name": name, "email": email},
                    ensure_ascii=False,
                ),
                updated_at=now,
            )
            await self._credential_store.upsert_credential(record)
            self._pending_device = None
            account = ProviderAccountStatus(
                provider_id="pikpak",
                authorized=True,
                account_binding_id=binding_id,
                account_label=name or email or user_id,
                auth_mode_used="device",
                updated_at=now,
                message="PikPak 设备码授权成功",
            )
            return InteractiveAuthPollResult(
                status="success",
                account=account,
                message="授权成功",
            )

    async def cancel_interactive_auth(self) -> None:
        async with self._auth_lock:
            self._pending_device = None

    async def get_account_status(self) -> ProviderAccountStatus:
        cred = await self._credential_store.get_credential("pikpak")
        if cred is None:
            return ProviderAccountStatus(
                provider_id="pikpak",
                authorized=False,
                message="尚未配置 PikPak 授权",
            )

        extra = _safe_json_dict(cred.extra_json)
        mode = str(extra.get("mode") or ("pat" if cred.access_token else "device")).lower()
        pat_token = cred.access_token if mode == "pat" else None
        if mode == "pat" and not pat_token:
            return ProviderAccountStatus(
                provider_id="pikpak",
                authorized=False,
                account_binding_id=cred.account_binding_id or None,
                auth_mode_used="pat",
                updated_at=cred.updated_at,
                message="PikPak PAT 为空，请重新配置",
            )

        try:
            user_id, name, email = await self._fetch_auth_identity(pat_token=pat_token)
        except YunBotError as exc:
            return ProviderAccountStatus(
                provider_id="pikpak",
                authorized=False,
                account_binding_id=cred.account_binding_id or None,
                account_label=str(extra.get("name") or extra.get("email") or ""),
                auth_mode_used=mode,
                updated_at=cred.updated_at,
                message=exc.user_message,
            )

        binding_id = cred.account_binding_id or f"pikpak:{user_id}"
        return ProviderAccountStatus(
            provider_id="pikpak",
            authorized=True,
            account_binding_id=binding_id,
            account_label=name or email or user_id,
            auth_mode_used=mode,
            updated_at=cred.updated_at,
            message="PikPak 授权正常",
        )

    async def get_current_binding_id(self) -> str:
        cred = await self._credential_store.get_credential("pikpak")
        if cred is None:
            env_pat = self._get_env_pat()
            if env_pat:
                status = await self.save_secret_credentials({"pat": env_pat})
                if status.account_binding_id:
                    return status.account_binding_id
            raise ProviderAuthInvalidError("PikPak")

        extra = _safe_json_dict(cred.extra_json)
        mode = str(extra.get("mode") or ("pat" if cred.access_token else "device")).lower()
        if mode == "pat" and not cred.access_token:
            raise ProviderAuthInvalidError("PikPak")
        if not cred.account_binding_id:
            status = await self.get_account_status()
            if status.authorized and status.account_binding_id:
                return status.account_binding_id
            raise ProviderAuthInvalidError("PikPak")
        return cred.account_binding_id

    async def _get_cli_pat_token(self) -> str | None:
        """Return PAT token for CLI env if active mode is PAT, or None for Device Flow."""
        pat_token, _ = await self._get_verified_cli_pat_token(None)
        return pat_token

    async def _get_verified_cli_pat_token(
        self,
        expected_binding_id: str | None = None,
    ) -> tuple[str | None, str]:
        """Return `(pat_token, account_binding_id)` verified against `expected_binding_id`."""
        cred = await self._credential_store.get_credential("pikpak")
        if cred is None:
            env_pat = self._get_env_pat()
            if env_pat:
                await self.save_secret_credentials({"pat": env_pat})
                cred = await self._credential_store.get_credential("pikpak")
            if cred is None:
                raise ProviderAuthInvalidError("PikPak")

        extra = _safe_json_dict(cred.extra_json)
        mode = str(extra.get("mode") or ("pat" if cred.access_token else "device")).lower()
        if mode == "pat" and not cred.access_token:
            raise ProviderAuthInvalidError("PikPak")

        binding_id = cred.account_binding_id.strip()
        if not binding_id:
            binding_id = await self.get_current_binding_id()

        if expected_binding_id is not None and binding_id != expected_binding_id:
            raise BindingMismatchError()

        return (cred.access_token if mode == "pat" else None), binding_id

    # ------------------------------------------------------------------
    # Error Mapping Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_auth_cli_error(exc: _PikPakCliError) -> bool:
        if exc.service_code in _AUTH_ERROR_CODES or exc.http_status == 401:
            return True
        lower = exc.combined_lower
        return any(
            tok in lower
            for tok in (
                "authorize failed",
                "unauthorized",
                "unauthenticated",
                "invalid token",
                "token expired",
                "not logged in",
            )
        )

    @classmethod
    def _map_general_cli_error(cls, exc: _PikPakCliError) -> YunBotError:
        code = exc.service_code
        if cls._is_auth_cli_error(exc):
            return ProviderAuthInvalidError("PikPak")
        if code in _QUOTA_ERROR_CODES:
            return ProviderQuotaExceededError("PikPak")
        if code in _RATE_LIMIT_ERROR_CODES or exc.http_status == 429:
            return ProviderRateLimitedError("PikPak")
        return YunBotError(ErrorCode.INTERNAL_ERROR, exc.safe_summary)

    @classmethod
    def _map_share_cli_error(cls, exc: _PikPakCliError, *, share_code: str | None) -> YunBotError:
        code = exc.service_code
        lower = exc.combined_lower

        if cls._is_auth_cli_error(exc):
            return ProviderAuthInvalidError("PikPak")
        if code in _QUOTA_ERROR_CODES:
            return ProviderQuotaExceededError("PikPak")
        if code in _RATE_LIMIT_ERROR_CODES or exc.http_status == 429:
            return ProviderRateLimitedError("PikPak")

        is_password_err = any(kw in code for kw in ("PASS_CODE", "PASSCODE", "PASSWORD")) or any(
            kw in lower
            for kw in (
                "pass_code",
                "passcode",
                "need password",
                "password required",
                "invalid password",
                "wrong password",
                "incorrect password",
                "提取码",
            )
        )
        if is_password_err:
            if not share_code:
                return ProviderNeedPasswordError()
            return ProviderInvalidPasswordError()

        if (
            code in _SHARE_EXPIRED_CODES
            or exc.http_status == 404
            or any(
                kw in lower
                for kw in (
                    "share not found",
                    "share expired",
                    "share deleted",
                    "has expired",
                    "does not exist",
                    "not exist",
                    "no longer available",
                    "violat",
                )
            )
        ):
            return ProviderShareExpiredError()

        return YunBotError(ErrorCode.INTERNAL_ERROR, exc.safe_summary)

    # ------------------------------------------------------------------
    # Folder Resolution & Creation
    # ------------------------------------------------------------------

    @staticmethod
    def _build_ls_args(
        parent_id: str,
        *,
        folders_only: bool = False,
        limit: int = PIKPAK_LS_PAGE_SIZE,
        page_token: str = "",
    ) -> list[str]:
        args: list[str] = ["ls"]
        if parent_id:
            args.extend(["-p", parent_id])
        if folders_only:
            args.extend(["--type", "folder"])
        args.extend(["-l", str(limit)])
        if page_token:
            args.extend(["-t", page_token])
        args.extend(["-F", "json"])
        return args

    async def _find_child_folder_id(
        self,
        parent_id: str,
        segment: str,
        *,
        pat_token: str | None,
    ) -> str | None:
        token = ""
        seen_tokens: set[str] = set()
        while True:
            args = self._build_ls_args(
                parent_id,
                folders_only=True,
                limit=PIKPAK_LS_PAGE_SIZE,
                page_token=token,
            )
            try:
                data = await self._runner.run_json(args, pat_token=pat_token)
            except _PikPakCliError as exc:
                if parent_id and (
                    exc.service_code in _NOT_FOUND_ERROR_CODES or exc.http_status == 404
                ):
                    return None
                raise self._map_general_cli_error(exc) from exc

            files = data.get("files") or []
            if isinstance(files, list):
                for raw in files:
                    if not isinstance(raw, dict):
                        continue
                    if not _is_folder_entry(raw, default_folder=True):
                        continue
                    if str(raw.get("name") or "") == segment:
                        fid = str(raw.get("id") or "").strip()
                        if fid:
                            return fid

            next_token = str(data.get("next_page_token") or "").strip()
            if not next_token or next_token in seen_tokens:
                return None
            seen_tokens.add(next_token)
            token = next_token

    async def _resolve_existing_folder_id(
        self,
        path: str,
        *,
        pat_token: str | None,
    ) -> str | None:
        norm_path = validate_save_path(path)
        segments = [seg for seg in norm_path.split("/") if seg]
        parent_id = ""
        for seg in segments:
            found_id = await self._find_child_folder_id(parent_id, seg, pat_token=pat_token)
            if not found_id:
                return None
            parent_id = found_id
        return parent_id or None

    async def _ensure_folder_id(
        self,
        path: str,
        *,
        pat_token: str | None,
    ) -> str:
        norm_path = validate_save_path(path)
        segments = [seg for seg in norm_path.split("/") if seg]
        parent_id = ""
        for seg in segments:
            found_id = await self._find_child_folder_id(parent_id, seg, pat_token=pat_token)
            if found_id:
                parent_id = found_id
                continue

            mkdir_args: list[str] = ["mkdir", seg]
            if parent_id:
                mkdir_args.extend(["-p", parent_id])
            mkdir_args.extend(["-F", "json"])

            created_id = ""
            try:
                mkdir_data = await self._runner.run_json(
                    mkdir_args,
                    pat_token=pat_token,
                    allow_empty=True,
                )
                file_node = mkdir_data.get("file")
                if isinstance(file_node, dict):
                    created_id = str(file_node.get("id") or "").strip()
                if not created_id:
                    created_id = str(mkdir_data.get("id") or "").strip()
            except _PikPakCliError as exc:
                if (
                    exc.service_code in _AUTH_ERROR_CODES
                    or exc.service_code in _QUOTA_ERROR_CODES
                    or exc.service_code in _RATE_LIMIT_ERROR_CODES
                ):
                    raise self._map_general_cli_error(exc) from exc
                refetched = await self._find_child_folder_id(parent_id, seg, pat_token=pat_token)
                if not refetched:
                    raise self._map_general_cli_error(exc) from exc
                created_id = refetched

            if not created_id:
                refetched = await self._find_child_folder_id(parent_id, seg, pat_token=pat_token)
                if not refetched:
                    raise YunBotError(
                        ErrorCode.INTERNAL_ERROR,
                        f"创建 PikPak 目录段失败: {seg}",
                    )
                created_id = refetched

            parent_id = created_id

        if not parent_id:
            raise YunBotError(ErrorCode.INTERNAL_ERROR, "无法解析空的 PikPak 目标目录")
        return parent_id

    async def prepare_task_dir(self, task_dir_path: str) -> str:
        norm_dir = validate_save_path(task_dir_path)
        pat_token = await self._get_cli_pat_token()
        await self._ensure_folder_id(norm_dir, pat_token=pat_token)
        return norm_dir

    # ------------------------------------------------------------------
    # Share Check, Restore, Polling & Snapshot Diff Transfer
    # ------------------------------------------------------------------

    def _extract_share_id(self, share: ShareLinkInfo) -> str:
        share_id = (share.external_id or "").strip()
        if not share_id and share.url:
            rec = self._recognizer.recognize(share.url)
            if rec is not None:
                share_id = rec.external_id
        if not _SHARE_ID_RE.fullmatch(share_id):
            raise YunBotError(ErrorCode.INVALID_LINK)
        return share_id

    async def _inspect_share(
        self,
        share_id: str,
        share_code: str | None,
        *,
        pat_token: str | None,
    ) -> tuple[str, int, bool, tuple[tuple[str, bool], ...]]:
        """Validate share via `pikpak share get` and return (title, count, exceeded, top_items)."""
        if share_code and share_code.startswith("-"):
            raise ProviderInvalidPasswordError()

        redact_vals = (share_code,) if share_code else ()
        token = ""
        seen_tokens: set[str] = set()
        share_title = ""
        first_item_name = ""
        declared_files = 0
        has_file_list_key = False
        enumerated = 0
        expected_top_items: list[tuple[str, bool]] = []

        while True:
            args: list[str] = ["share", "get", share_id]
            if share_code:
                args.extend(["-p", share_code])
            args.extend(["-l", str(PIKPAK_SHARE_PAGE_SIZE)])
            if token:
                args.extend(["-t", token])
            args.extend(["-F", "json"])

            try:
                data = await self._runner.run_json(
                    args,
                    pat_token=pat_token,
                    redact_values=redact_vals,
                )
            except _PikPakCliError as exc:
                raise self._map_share_cli_error(exc, share_code=share_code) from exc

            share_status = str(data.get("status") or "").strip().upper()
            if share_status in _SHARE_EXPIRED_STATUSES:
                raise ProviderShareExpiredError()

            if not share_title:
                share_title = str(data.get("title") or "").strip()
            raw_files_count = data.get("files")
            parsed_files_count = 0
            if isinstance(raw_files_count, int) and not isinstance(raw_files_count, bool):
                parsed_files_count = raw_files_count
            elif isinstance(raw_files_count, str) and raw_files_count.strip().isdigit():
                parsed_files_count = int(raw_files_count.strip())
            if parsed_files_count > declared_files:
                declared_files = parsed_files_count

            if "file_list" in data:
                has_file_list_key = True
            file_list = data.get("file_list") or []
            if isinstance(file_list, list):
                for item in file_list:
                    if isinstance(item, dict):
                        item_name = str(item.get("name") or "").strip()
                        if item_name and not first_item_name:
                            first_item_name = item_name
                        if item_name:
                            expected_top_items.append(
                                (item_name, _is_folder_entry(item, default_folder=False))
                            )
                enumerated += len(file_list)

            if enumerated > MAX_SHARE_ENUM_ITEMS or declared_files > MAX_SHARE_ENUM_ITEMS:
                title = share_title or first_item_name or share_id
                return title, max(enumerated, declared_files), True, ()

            next_token = str(data.get("next_page_token") or "").strip()
            if not next_token or next_token in seen_tokens:
                break
            seen_tokens.add(next_token)
            token = next_token

        total_count = enumerated or declared_files
        if total_count == 0:
            if has_file_list_key:
                raise ProviderShareExpiredError("分享链接内没有可转存的文件")
            total_count = 1

        final_title = share_title or first_item_name or share_id
        return final_title, total_count, False, tuple(expected_top_items)

    async def _capture_folder_snapshot(
        self,
        task_id: str,
        folder_id: str,
        phase: SnapshotPhase,
        *,
        pat_token: str | None,
    ) -> frozenset[str] | None:
        token = ""
        seen_tokens: set[str] = set()
        total_inserted = 0
        tracked_ids: set[str] | None = set()

        while True:
            args = self._build_ls_args(
                folder_id,
                folders_only=False,
                limit=PIKPAK_LS_PAGE_SIZE,
                page_token=token,
            )
            try:
                data = await self._runner.run_json(args, pat_token=pat_token)
            except _PikPakCliError as exc:
                raise self._map_general_cli_error(exc) from exc

            raw_files = data.get("files") or []
            entries: list[SnapshotTempEntry] = []
            if isinstance(raw_files, list):
                for raw in raw_files:
                    if not isinstance(raw, dict):
                        continue
                    item_id = str(raw.get("id") or "").strip()
                    name = str(raw.get("name") or "").strip()
                    if (
                        not item_id
                        or item_id.startswith("-")
                        or not name
                        or "/" in name
                        or "\\" in name
                        or "\x00" in name
                        or name in (".", "..")
                    ):
                        continue
                    entries.append(
                        SnapshotTempEntry(
                            item_id=item_id,
                            name=name,
                            is_dir=_is_folder_entry(raw, default_folder=False),
                        )
                    )
                    if tracked_ids is not None:
                        if len(tracked_ids) < MAX_SHARE_ENUM_ITEMS:
                            tracked_ids.add(item_id)
                        else:
                            tracked_ids = None

            if entries:
                total_inserted = await self._snapshot_store.insert_snapshot_batch(
                    task_id,
                    phase,
                    entries,
                    max_per_phase=MAX_SNAPSHOT_ITEMS_PER_PHASE,
                )
                if total_inserted > MAX_SNAPSHOT_ITEMS_PER_PHASE:
                    raise EnumLimitExceededError()

            next_token = str(data.get("next_page_token") or "").strip()
            if not next_token or next_token in seen_tokens:
                break
            seen_tokens.add(next_token)
            token = next_token

        return frozenset(tracked_ids) if tracked_ids is not None else None

    async def _list_ready_folder_entries(
        self,
        folder_id: str,
        *,
        pat_token: str | None,
        exclude_ids: frozenset[str] = frozenset(),
        max_pages: int = 5,
    ) -> list[tuple[str, str, bool]] | None:
        """List non-trashed, non-running entries in `folder_id` (bounded to `max_pages`)."""
        token = ""
        seen_tokens: set[str] = set()
        collected: list[tuple[str, str, bool]] = []
        pages = 0

        while pages < max_pages:
            pages += 1
            args = self._build_ls_args(
                folder_id,
                folders_only=False,
                limit=PIKPAK_LS_PAGE_SIZE,
                page_token=token,
            )
            try:
                data = await self._runner.run_json(args, pat_token=pat_token)
            except _PikPakCliError:
                return None

            raw_files = data.get("files") or []
            if isinstance(raw_files, list):
                for raw in raw_files:
                    if not isinstance(raw, dict):
                        continue
                    if bool(raw.get("trashed")):
                        continue
                    raw_phase = str(raw.get("phase") or "").strip().upper()
                    if raw_phase and any(
                        tok in raw_phase for tok in ("RUNNING", "PENDING", "ERROR")
                    ):
                        return None
                    item_id = str(raw.get("id") or "").strip()
                    name = str(raw.get("name") or "").strip()
                    if not item_id or not name or item_id in exclude_ids:
                        continue
                    collected.append((item_id, name, _is_folder_entry(raw, default_folder=False)))

            next_token = str(data.get("next_page_token") or "").strip()
            if not next_token or next_token in seen_tokens:
                return collected
            seen_tokens.add(next_token)
            token = next_token

        return None

    async def _has_expected_items_landed(
        self,
        parent_folder_id: str,
        expected_top_items: tuple[tuple[str, bool], ...],
        *,
        pat_token: str | None,
        exclude_ids: frozenset[str] = frozenset(),
    ) -> bool:
        """Verify whether an instant-saved share has already materialized in `parent_folder_id`.

        PikPak's backend occasionally completes instant file deduplication immediately while
        leaving `pikpak task get` permanently stuck in `Running (PHASE_TYPE_RUNNING)` with
        `progress: "-"`.
        """
        if not expected_top_items:
            return False

        entries = await self._list_ready_folder_entries(
            parent_folder_id,
            pat_token=pat_token,
            exclude_ids=exclude_ids,
        )
        if entries is None or len(entries) < len(expected_top_items):
            return False

        required_counts = Counter(expected_top_items)
        present_counts = Counter((name, is_dir) for _, name, is_dir in entries)
        for key, req_n in required_counts.items():
            if present_counts.get(key, 0) < req_n:
                return False

        matched_dirs = [
            item_id
            for item_id, name, is_dir in entries
            if is_dir and (name, True) in required_counts
        ]
        if not matched_dirs:
            return True

        # For folder shares, require non-empty stabilized child counts across a 2s window
        sampled_dirs = matched_dirs[:5]
        first_counts: dict[str, int] = {}
        top_file_count = sum(1 for _, _, is_dir in entries if not is_dir)
        total_nested = top_file_count
        for dir_id in sampled_dirs:
            children = await self._list_ready_folder_entries(
                dir_id,
                pat_token=pat_token,
                max_pages=2,
            )
            if children is None:
                return False
            first_counts[dir_id] = len(children)
            total_nested += len(children)

        if total_nested <= 0:
            return False

        await self._sleep(2.0)
        for dir_id in sampled_dirs:
            children_after = await self._list_ready_folder_entries(
                dir_id,
                pat_token=pat_token,
                max_pages=2,
            )
            if children_after is None or len(children_after) != first_counts[dir_id]:
                return False

        return True

    async def _emit_restore_progress(
        self,
        on_progress: ProgressCallback | None,
        *,
        share_title: str,
        total_discovered: int,
        prog_pct: int | None,
        completed: bool = False,
    ) -> None:
        if on_progress is None:
            return
        total_items = max(1, total_discovered)
        title_label = share_title or "正在转存"
        if completed:
            await on_progress(title_label, total_items, total_items)
            return
        if prog_pct is not None:
            done_items = total_items if prog_pct >= 100 else (prog_pct * total_items) // 100
            stage_label = title_label if prog_pct >= 100 else f"{title_label} ({prog_pct}%)"
            await on_progress(stage_label, done_items, total_items)
            return
        await on_progress(title_label, 0, total_items)

    async def _poll_restore_task(
        self,
        restore_task_id: str,
        *,
        pat_token: str | None,
        share_title: str = "",
        total_discovered: int = 1,
        has_folder_items: bool = False,
        check_landed: Callable[[], Awaitable[bool]] | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        start_mono = self._monotonic()
        deadline = start_mono + PIKPAK_TASK_POLL_TIMEOUT_SECONDS
        attempt = 0

        while True:
            data = await self._runner.run_json(
                ["task", "get", restore_task_id, "-F", "json"],
                pat_token=pat_token,
            )
            status_str = str(data.get("status") or "").strip().lower()
            phase_str = str(data.get("phase") or "").strip().upper()
            prog_pct = _parse_optional_task_progress(data.get("progress"))

            if _is_task_complete(status_str, phase_str):
                await self._emit_restore_progress(
                    on_progress,
                    share_title=share_title,
                    total_discovered=total_discovered,
                    prog_pct=100,
                    completed=True,
                )
                return

            if _is_task_failed(status_str, phase_str):
                msg = redact_sensitive_text(str(data.get("message") or "PikPak 云端转存任务失败"))
                raise _PikPakCliError(
                    msg,
                    service_code="TASK_ERROR",
                    reason=msg,
                )

            now = self._monotonic()
            if check_landed is not None and prog_pct is None:
                can_probe_now = (not has_folder_items and attempt >= 1) or (
                    has_folder_items and (now - start_mono) >= 12.0
                )
                if can_probe_now and await check_landed():
                    await self._emit_restore_progress(
                        on_progress,
                        share_title=share_title,
                        total_discovered=total_discovered,
                        prog_pct=100,
                        completed=True,
                    )
                    return

            await self._emit_restore_progress(
                on_progress,
                share_title=share_title,
                total_discovered=total_discovered,
                prog_pct=prog_pct,
                completed=False,
            )

            now = self._monotonic()
            remaining = deadline - now
            if remaining <= 0:
                if check_landed is not None and prog_pct is None and await check_landed():
                    await self._emit_restore_progress(
                        on_progress,
                        share_title=share_title,
                        total_discovered=total_discovered,
                        prog_pct=100,
                        completed=True,
                    )
                    return
                raise _PikPakCliError(
                    f"pikpak task {restore_task_id} poll timed out after "
                    f"{PIKPAK_TASK_POLL_TIMEOUT_SECONDS}s",
                    service_code="POLL_TIMEOUT",
                    timed_out=True,
                )

            delay_idx = min(attempt, len(PIKPAK_TASK_POLL_DELAYS_SECONDS) - 1)
            sleep_for = min(PIKPAK_TASK_POLL_DELAYS_SECONDS[delay_idx], remaining)
            attempt += 1
            await self._sleep(sleep_for)

            if self._monotonic() >= deadline:
                # Perform one final check right at deadline before timing out
                final_data = await self._runner.run_json(
                    ["task", "get", restore_task_id, "-F", "json"],
                    pat_token=pat_token,
                )
                f_status = str(final_data.get("status") or "").strip().lower()
                f_phase = str(final_data.get("phase") or "").strip().upper()
                f_prog_pct = _parse_optional_task_progress(final_data.get("progress"))
                if _is_task_complete(f_status, f_phase):
                    await self._emit_restore_progress(
                        on_progress,
                        share_title=share_title,
                        total_discovered=total_discovered,
                        prog_pct=100,
                        completed=True,
                    )
                    return
                if check_landed is not None and f_prog_pct is None and await check_landed():
                    await self._emit_restore_progress(
                        on_progress,
                        share_title=share_title,
                        total_discovered=total_discovered,
                        prog_pct=100,
                        completed=True,
                    )
                    return
                raise _PikPakCliError(
                    f"pikpak task {restore_task_id} poll timed out after "
                    f"{PIKPAK_TASK_POLL_TIMEOUT_SECONDS}s",
                    service_code="POLL_TIMEOUT",
                    timed_out=True,
                )

    async def _execute_restore_and_wait(
        self,
        *,
        share_id: str,
        share_code: str | None,
        parent_folder_id: str,
        pat_token: str | None,
        share_title: str = "",
        total_discovered: int = 1,
        has_folder_items: bool = False,
        check_landed: Callable[[], Awaitable[bool]] | None = None,
        on_remote_task: RemoteTaskCallback | None,
        on_progress: ProgressCallback | None,
    ) -> None:
        redact_vals = (share_code,) if share_code else ()
        restore_args: list[str] = ["share", "restore", share_id]
        if share_code:
            restore_args.extend(["-p", share_code])
        restore_args.extend(["--parent", parent_folder_id, "-F", "json"])

        try:
            restore_data = await self._runner.run_json(
                restore_args,
                pat_token=pat_token,
                redact_values=redact_vals,
            )
        except _PikPakCliError as exc:
            if not exc.timed_out and not exc.truncated:
                mapped = self._map_share_cli_error(exc, share_code=share_code)
                if mapped.code != ErrorCode.INTERNAL_ERROR:
                    raise mapped from exc
            raise

        restore_task_id = str(restore_data.get("restore_task_id") or "").strip()
        if restore_task_id:
            if on_remote_task is not None:
                await on_remote_task(restore_task_id)
            await self._poll_restore_task(
                restore_task_id,
                pat_token=pat_token,
                share_title=share_title,
                total_discovered=total_discovered,
                has_folder_items=has_folder_items,
                check_landed=check_landed,
                on_progress=on_progress,
            )
            return

        restore_status = str(restore_data.get("restore_status") or "").strip().lower()
        if restore_status in ("error", "failed", "fail", "phase_type_error"):
            raise _PikPakCliError(
                f"pikpak share restore failed with status: {restore_status}",
                service_code="RESTORE_ERROR",
            )

    @staticmethod
    def _uncertain_failure_outcome(
        *,
        share_title: str,
        total_discovered: int,
        err: Exception,
        succeeded_count: int = 0,
    ) -> TransferOutcome:
        if isinstance(err, EnumLimitExceededError):
            code = ErrorCode.ENUM_LIMIT_EXCEEDED
            msg = err.user_message
            truncated = True
        elif isinstance(err, YunBotError):
            code = err.code
            msg = err.user_message
            truncated = False
        elif isinstance(err, _PikPakCliError):
            if err.service_code in _QUOTA_ERROR_CODES or "space" in err.combined_lower:
                code = ErrorCode.QUOTA_EXCEEDED
                msg = format_error_message(code, provider_name="PikPak")
            elif err.service_code in _RATE_LIMIT_ERROR_CODES or err.http_status == 429:
                code = ErrorCode.RATE_LIMITED
                msg = format_error_message(code, provider_name="PikPak")
            elif err.service_code in _AUTH_ERROR_CODES or err.http_status == 401:
                code = ErrorCode.PROVIDER_AUTH_INVALID
                msg = format_error_message(code, provider_name="PikPak")
            elif err.service_code == "POLL_TIMEOUT":
                code = ErrorCode.INTERNAL_ERROR
                msg = (
                    f"PikPak 云端任务状态轮询超时（{int(PIKPAK_TASK_POLL_TIMEOUT_SECONDS)}s），"
                    "请稍后检查网盘目录"
                )
            else:
                code = ErrorCode.INTERNAL_ERROR
                msg = err.safe_summary or "PikPak 云端转存状态未确认"
            truncated = False
        else:
            code = ErrorCode.INTERNAL_ERROR
            msg = redact_sensitive_text(str(err)) or "PikPak 云端转存异常中断"
            truncated = False

        failed_count = max(total_discovered - succeeded_count, 1)
        return TransferOutcome(
            share_title=share_title,
            succeeded_count=succeeded_count,
            failed_count=failed_count,
            total_discovered=total_discovered,
            truncated_by_limit=truncated,
            uncertain=True,
            error_code=code,
            error_message=msg,
        )

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
    ) -> TransferOutcome:
        if collect_items or share.no_subdir:
            self.validate_transfer_mode(no_subdir=True)
        if collect_items and not task_id:
            raise ValueError("task_id is required when collect_items=True")

        norm_target = validate_save_path(target_dir)
        share_id = self._extract_share_id(share)
        share_code = (share.code or "").strip() or None
        pat_token = await self._get_cli_pat_token()

        share_title, total_discovered, exceeded, expected_top_items = await self._inspect_share(
            share_id,
            share_code,
            pat_token=pat_token,
        )
        if exceeded:
            return TransferOutcome(
                share_title=share_title,
                succeeded_count=0,
                failed_count=0,
                total_discovered=total_discovered,
                truncated_by_limit=True,
                uncertain=False,
                error_code=ErrorCode.ENUM_LIMIT_EXCEEDED,
                error_message=format_error_message(ErrorCode.ENUM_LIMIT_EXCEEDED),
            )

        folder_id = await self._ensure_folder_id(norm_target, pat_token=pat_token)
        has_folder_items = any(is_dir for _, is_dir in expected_top_items)

        # Branch A: Default mode (isolated task subdirectory, collect_items=False)
        if not collect_items:
            default_landed_probe: Callable[[], Awaitable[bool]] | None = None
            if expected_top_items:

                async def _probe_isolated_dir() -> bool:
                    return await self._has_expected_items_landed(
                        folder_id,
                        expected_top_items,
                        pat_token=pat_token,
                    )

                default_landed_probe = _probe_isolated_dir

            try:
                await self._execute_restore_and_wait(
                    share_id=share_id,
                    share_code=share_code,
                    parent_folder_id=folder_id,
                    pat_token=pat_token,
                    share_title=share_title,
                    total_discovered=total_discovered,
                    has_folder_items=has_folder_items,
                    check_landed=default_landed_probe,
                    on_remote_task=on_remote_task,
                    on_progress=on_progress,
                )
            except _PikPakCliError as exc:
                return self._uncertain_failure_outcome(
                    share_title=share_title,
                    total_discovered=total_discovered,
                    err=exc,
                )

            return TransferOutcome(
                share_title=share_title,
                succeeded_count=total_discovered,
                failed_count=0,
                total_discovered=total_discovered,
                truncated_by_limit=False,
                uncertain=False,
            )

        # Branch B: -n Direct mode (streaming snapshot diff via SQLite snapshot_temp_items)
        await self._snapshot_store.clear_task_snapshots(task_id)
        try:
            # Step 1: BEFORE snapshot (restore has NOT started yet -> uncertain=False on limit)
            try:
                before_ids = await self._capture_folder_snapshot(
                    task_id,
                    folder_id,
                    SnapshotPhase.BEFORE,
                    pat_token=pat_token,
                )
            except EnumLimitExceededError as exc:
                return TransferOutcome(
                    share_title=share_title,
                    succeeded_count=0,
                    failed_count=0,
                    total_discovered=total_discovered,
                    truncated_by_limit=True,
                    uncertain=False,
                    error_code=ErrorCode.ENUM_LIMIT_EXCEEDED,
                    error_message=exc.user_message,
                )

            direct_landed_probe: Callable[[], Awaitable[bool]] | None = None
            if expected_top_items and before_ids is not None:
                known_before = before_ids

                async def _probe_direct_dir() -> bool:
                    return await self._has_expected_items_landed(
                        folder_id,
                        expected_top_items,
                        pat_token=pat_token,
                        exclude_ids=known_before,
                    )

                direct_landed_probe = _probe_direct_dir

            # Step 2: Restore share into baseFolderID and poll restore_task_id (NEVER replay!)
            try:
                await self._execute_restore_and_wait(
                    share_id=share_id,
                    share_code=share_code,
                    parent_folder_id=folder_id,
                    pat_token=pat_token,
                    share_title=share_title,
                    total_discovered=total_discovered,
                    has_folder_items=has_folder_items,
                    check_landed=direct_landed_probe,
                    on_remote_task=on_remote_task,
                    on_progress=on_progress,
                )
            except _PikPakCliError as exc:
                return self._uncertain_failure_outcome(
                    share_title=share_title,
                    total_discovered=total_discovered,
                    err=exc,
                )

            # Step 3: AFTER snapshot & paginated SQL diff -> await on_items_batch per page
            try:
                await self._capture_folder_snapshot(
                    task_id,
                    folder_id,
                    SnapshotPhase.AFTER,
                    pat_token=pat_token,
                )
            except (EnumLimitExceededError, YunBotError, _PikPakCliError) as exc:
                return self._uncertain_failure_outcome(
                    share_title=share_title,
                    total_discovered=total_discovered,
                    err=exc,
                )

            added_total = 0
            offset = 0
            while True:
                added_page = await self._snapshot_store.fetch_added_snapshot_page(
                    task_id,
                    limit=PIKPAK_LS_PAGE_SIZE,
                    offset=offset,
                )
                if not added_page:
                    break

                batch = [
                    TransferredEntry(
                        item_id=entry.item_id,
                        path=f"{norm_target}/{entry.name}",
                        name=entry.name,
                        is_dir=entry.is_dir,
                    )
                    for entry in added_page
                ]
                if on_items_batch is not None:
                    await on_items_batch(batch)
                added_total += len(batch)

                if len(added_page) < PIKPAK_LS_PAGE_SIZE:
                    break
                offset += len(added_page)

            return TransferOutcome(
                share_title=share_title,
                succeeded_count=added_total if added_total > 0 else total_discovered,
                failed_count=0,
                total_discovered=total_discovered,
                truncated_by_limit=False,
                uncertain=False,
            )
        finally:
            try:
                await self._snapshot_store.clear_task_snapshots(task_id)
            except Exception:
                logger.warning("Failed to clear snapshot_temp_items for task %s", task_id)

    # ------------------------------------------------------------------
    # Dual-Mode Verified Deletion
    # ------------------------------------------------------------------

    async def delete_directory(
        self,
        task_dir_path: str,
        *,
        expected_binding_id: str | None = None,
    ) -> None:
        norm_dir = validate_save_path(task_dir_path)
        pat_token, active_binding = await self._get_verified_cli_pat_token(expected_binding_id)
        folder_id = await self._resolve_existing_folder_id(norm_dir, pat_token=pat_token)
        if folder_id is None:
            return

        pat_token, _ = await self._get_verified_cli_pat_token(active_binding)
        try:
            await self._runner.run_json(
                ["rm", folder_id, "-F", "json"],
                pat_token=pat_token,
                allow_empty=True,
                allow_non_json_text=True,
            )
        except _PikPakCliError as exc:
            if exc.service_code in _NOT_FOUND_ERROR_CODES or exc.http_status == 404:
                return
            raise self._map_general_cli_error(exc) from exc

    async def _list_folder_id_to_name(
        self,
        folder_id: str,
        target_ids: frozenset[str],
        *,
        pat_token: str | None,
    ) -> dict[str, str]:
        mapping: dict[str, str] = {}
        if not target_ids:
            return mapping

        token = ""
        seen_tokens: set[str] = set()
        while True:
            args = self._build_ls_args(
                folder_id,
                folders_only=False,
                limit=PIKPAK_LS_PAGE_SIZE,
                page_token=token,
            )
            try:
                data = await self._runner.run_json(args, pat_token=pat_token)
            except _PikPakCliError as exc:
                if exc.service_code in _NOT_FOUND_ERROR_CODES or exc.http_status == 404:
                    return mapping
                raise self._map_general_cli_error(exc) from exc

            raw_files = data.get("files") or []
            if isinstance(raw_files, list):
                for raw in raw_files:
                    if not isinstance(raw, dict):
                        continue
                    fid = str(raw.get("id") or "").strip()
                    fname = str(raw.get("name") or "")
                    if fid:
                        mapping[fid] = fname

            if target_ids.issubset(mapping.keys()):
                break

            next_token = str(data.get("next_page_token") or "").strip()
            if not next_token or next_token in seen_tokens:
                break
            seen_tokens.add(next_token)
            token = next_token

        return mapping

    async def delete_items(
        self,
        base_save_path: str,
        items: Sequence[TransferItemRecord],
        *,
        expected_binding_id: str | None = None,
        deleted_ids_sink: list[str] | None = None,
    ) -> DeleteItemsOutcome:
        norm_base = validate_save_path(base_save_path)
        if not items:
            return DeleteItemsOutcome()

        expected_names: list[tuple[TransferItemRecord, str]] = []
        for item in items:
            norm_item = validate_direct_item_path(item.path, norm_base)
            item_id = (item.item_id or "").strip()
            if not item_id or item_id.startswith("-"):
                raise ValueError(f"Invalid item_id for deletion: {item.item_id!r}")
            p_item = PurePosixPath(norm_item)
            if p_item.parent != PurePosixPath(norm_base):
                raise ValueError("Direct-mode top-level item parent must equal base_save_path")
            expected_name = item.name or p_item.name
            if p_item.name != expected_name:
                raise ValueError("TransferItemRecord.name does not match item.path basename")
            expected_names.append((item, expected_name))

        pat_token, active_binding = await self._get_verified_cli_pat_token(expected_binding_id)
        base_folder_id = await self._resolve_existing_folder_id(norm_base, pat_token=pat_token)

        target_ids = frozenset(item.item_id for item, _ in expected_names)
        present_in_base: dict[str, str] = {}
        if base_folder_id is not None:
            pat_token, _ = await self._get_verified_cli_pat_token(active_binding)
            present_in_base = await self._list_folder_id_to_name(
                base_folder_id,
                target_ids,
                pat_token=pat_token,
            )

        deleted_ids: list[str] = []
        skipped_items: list[TransferItemRecord] = []
        failed_items: list[TransferItemRecord] = []
        to_delete: list[TransferItemRecord] = []
        to_inspect: list[TransferItemRecord] = []

        def _mark_deleted(ids: Sequence[str]) -> None:
            deleted_ids.extend(ids)
            if deleted_ids_sink is not None:
                deleted_ids_sink.extend(ids)

        for item, expected_name in expected_names:
            if item.item_id in present_in_base:
                if present_in_base[item.item_id] == expected_name:
                    to_delete.append(item)
                else:
                    skipped_items.append(item)
            else:
                to_inspect.append(item)

        # Batch delete items confirmed still in baseFolderID with unchanged name
        for start in range(0, len(to_delete), _RM_BATCH_SIZE):
            batch = to_delete[start : start + _RM_BATCH_SIZE]
            pat_token, _ = await self._get_verified_cli_pat_token(active_binding)
            rm_args = ["rm", *(it.item_id for it in batch), "-F", "json"]
            try:
                await self._runner.run_json(
                    rm_args,
                    pat_token=pat_token,
                    allow_empty=True,
                    allow_non_json_text=True,
                )
                _mark_deleted([it.item_id for it in batch])
            except _PikPakCliError as exc:
                if exc.service_code in _AUTH_ERROR_CODES or exc.http_status == 401:
                    raise ProviderAuthInvalidError("PikPak") from exc
                if exc.service_code in _NOT_FOUND_ERROR_CODES or exc.http_status == 404:
                    _mark_deleted([it.item_id for it in batch])
                else:
                    failed_items.extend(batch)

        # Inspect items absent from baseFolderID via `pikpak get <item_id> --raw`
        for item in to_inspect:
            pat_token, _ = await self._get_verified_cli_pat_token(active_binding)
            try:
                raw_info = await self._runner.run_json(
                    ["get", item.item_id, "--raw"],
                    pat_token=pat_token,
                )
            except _PikPakCliError as exc:
                if exc.service_code in _AUTH_ERROR_CODES or exc.http_status == 401:
                    raise ProviderAuthInvalidError("PikPak") from exc
                if (
                    exc.service_code in _NOT_FOUND_ERROR_CODES
                    or exc.http_status == 404
                    or "not found" in exc.combined_lower
                    or "does not exist" in exc.combined_lower
                ):
                    _mark_deleted([item.item_id])
                else:
                    failed_items.append(item)
                continue

            if bool(raw_info.get("trashed")) is True:
                _mark_deleted([item.item_id])
            else:
                skipped_items.append(item)

        return DeleteItemsOutcome(
            deleted_ids=tuple(dict.fromkeys(deleted_ids)),
            skipped_items=tuple(skipped_items),
            failed_items=tuple(failed_items),
        )

    async def close(self) -> None:
        await self.cancel_interactive_auth()
        await self._runner.close()
