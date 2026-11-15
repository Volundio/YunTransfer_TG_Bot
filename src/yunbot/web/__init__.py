"""Built-in admin-only Web console package (`web/`)."""

from __future__ import annotations

from yunbot.web.auth import (
    SESSION_COOKIE_NAME,
    ClientIpExtractor,
    LoginRateLimiter,
    OttManager,
    SessionManager,
    WebAuthManager,
    extract_client_ip,
    parse_trusted_networks,
)
from yunbot.web.server import (
    AUTH_MANAGER_APP_KEY,
    AccessService,
    OpenListService,
    RuntimeConfigService,
    TaskDeletionServiceProtocol,
    TaskStorageReader,
    WebServer,
    create_web_app,
)

__all__ = [
    "AUTH_MANAGER_APP_KEY",
    "AccessService",
    "ClientIpExtractor",
    "LoginRateLimiter",
    "OpenListService",
    "OttManager",
    "RuntimeConfigService",
    "SESSION_COOKIE_NAME",
    "SessionManager",
    "TaskDeletionServiceProtocol",
    "TaskStorageReader",
    "WebAuthManager",
    "WebServer",
    "create_web_app",
    "extract_client_ip",
    "parse_trusted_networks",
]
