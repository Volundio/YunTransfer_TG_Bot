"""Process entrypoint: secret-redacting log setup, signal handling, and event loop (§4.1, §5.1)."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from collections.abc import Sequence

from yunbot.app import Application
from yunbot.config.bootstrap import load_bootstrap_config
from yunbot.models import BootstrapConfigSnapshot, RedactingLogFilter, redact_sensitive_text


class _ExactSecretRedactingFilter(RedactingLogFilter):
    """Extends pattern-based `RedactingLogFilter` with exact bootstrap secret masking."""

    def __init__(self, extra_secrets: Sequence[str] = ()) -> None:
        super().__init__()
        self._secrets: tuple[str, ...] = tuple(
            sorted(
                {s.strip() for s in extra_secrets if isinstance(s, str) and len(s.strip()) >= 4},
                key=len,
                reverse=True,
            )
        )

    def _mask_exact(self, text: str) -> str:
        masked = redact_sensitive_text(text)
        for secret in self._secrets:
            if secret in masked:
                masked = masked.replace(secret, "[REDACTED]")
        return masked

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
            record.msg = self._mask_exact(rendered)
            record.args = ()
            if record.exc_text:
                record.exc_text = self._mask_exact(record.exc_text)
        except Exception:
            record.msg = "[LOG_REDACTION_ERROR]"
            record.args = ()
        return True


def configure_logging(
    level_name: str = "INFO",
    *,
    extra_secrets: Sequence[str] = (),
) -> logging.Filter:
    """Configure root logging with `RedactingLogFilter` attached to all handlers."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)

    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        root.addHandler(handler)

    redactor = _ExactSecretRedactingFilter(extra_secrets=extra_secrets)
    for existing in list(root.filters):
        if isinstance(existing, RedactingLogFilter):
            root.removeFilter(existing)
    root.addFilter(redactor)

    for h in root.handlers:
        for existing in list(h.filters):
            if isinstance(existing, RedactingLogFilter):
                h.removeFilter(existing)
        h.addFilter(redactor)

    return redactor


def _collect_bootstrap_secrets(bootstrap: BootstrapConfigSnapshot) -> tuple[str, ...]:
    candidates = (
        bootstrap.telegram_bot_token,
        bootstrap.openlist_token,
        bootstrap.openlist_password,
        bootstrap.baidu_client_secret,
        bootstrap.pikpak_pat,
        bootstrap.quark_cookie,
    )
    return tuple(s for s in candidates if s and s.strip())


async def run_from_bootstrap(bootstrap: BootstrapConfigSnapshot) -> None:
    """Run `Application` with OS `SIGINT`/`SIGTERM` wired to graceful shutdown."""
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError):
            continue

    app = Application(bootstrap)
    await app.run(stop_event=stop_event)


def main() -> int:
    """Validate bootstrap environment, initialize redacted logging, and run the bot."""
    configure_logging("INFO")
    logger = logging.getLogger(__name__)

    try:
        bootstrap = load_bootstrap_config()
    except Exception as exc:
        logger.critical(
            "Startup configuration validation failed: %s",
            redact_sensitive_text(str(exc)),
        )
        return 1

    configure_logging(
        bootstrap.log_level,
        extra_secrets=_collect_bootstrap_secrets(bootstrap),
    )

    try:
        asyncio.run(run_from_bootstrap(bootstrap))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        logger.critical(
            "Fatal application error: %s",
            redact_sensitive_text(str(exc)),
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
