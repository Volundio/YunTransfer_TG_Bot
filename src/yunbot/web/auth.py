"""Web panel authentication, OTT atomic consumption, bounded sessions, and IP rate limiting.

Implements DEVELOPMENT.md §2.2, §5.2 and R02:
- OttManager: SHA-256 hashed one-time login tokens (TTL=300s, maxsize=3) with single-lock
  atomic `.pop()` consumption so concurrent replays succeed at most once.
- SessionManager: SHA-256 hashed admin sessions (sliding TTL=7200s, maxsize=5 LRU) bound to
  `HttpOnly; SameSite=Strict; Path=/` cookies (`Secure` derived from `WEB_BASE_URL`).
- ClientIpExtractor & LoginRateLimiter: right-to-left `X-Forwarded-For` extraction strictly
  gated on `WEB_TRUSTED_PROXIES`, plus bounded sliding-window brute-force limiter.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from urllib.parse import urlparse

from aiohttp import web

from yunbot.models import (
    WEB_LOGIN_RATE_LIMIT_MAX_FAILS,
    WEB_LOGIN_RATE_LIMIT_MAX_IPS,
    WEB_LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    WEB_OTT_MAXSIZE,
    WEB_OTT_TTL_SECONDS,
    WEB_SESSION_MAXSIZE,
    WEB_SESSION_TTL_SECONDS,
    BootstrapConfigSnapshot,
)

SESSION_COOKIE_NAME: str = "yunbot_admin_session"
_MAX_RAW_TOKEN_LEN: int = 256

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _hash_ascii_token(raw_token: str) -> str | None:
    """Hash a bounded ASCII token with SHA-256, returning None if malformed."""
    if not isinstance(raw_token, str):
        return None
    if not (1 <= len(raw_token) <= _MAX_RAW_TOKEN_LEN) or not raw_token.isascii():
        return None
    return hashlib.sha256(raw_token.encode("ascii")).hexdigest()


def normalize_web_origin(web_origin: str, fallback_base_url: str = "") -> str:
    """Derive canonical `scheme://host[:port]` origin string."""
    candidate = (web_origin or "").strip().rstrip("/")
    if candidate:
        return candidate
    raw_base = (fallback_base_url or "").strip()
    if not raw_base:
        raise ValueError("web_origin or web_base_url must be non-empty")
    parsed = urlparse(raw_base)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid web_base_url for origin derivation: {raw_base!r}")
    return f"{parsed.scheme.lower()}://{parsed.netloc}"


def _parse_ip(raw_ip: str | None) -> IPAddress | None:
    """Parse an IPv4 or IPv6 literal, normalizing IPv4-mapped IPv6 addresses."""
    if not raw_ip or not isinstance(raw_ip, str):
        return None
    token = raw_ip.strip()
    if not token:
        return None
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1].strip()
    if "%" in token:
        token = token.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def parse_trusted_networks(raw_proxies: Sequence[str] | str) -> tuple[IPNetwork, ...]:
    """Parse `WEB_TRUSTED_PROXIES` strings into canonical `ip_network` objects."""
    if isinstance(raw_proxies, str):
        entries = [part.strip() for part in raw_proxies.split(",") if part.strip()]
    else:
        entries = [str(part).strip() for part in raw_proxies if str(part).strip()]

    networks: list[IPNetwork] = []
    for entry in entries:
        net = ipaddress.ip_network(entry, strict=False)
        if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None:
            if net.prefixlen >= 96:
                mapped_prefix = net.prefixlen - 96
                net = ipaddress.ip_network(
                    f"{net.network_address.ipv4_mapped}/{mapped_prefix}", strict=False
                )
        networks.append(net)
    return tuple(networks)


def _ip_in_networks(addr: IPAddress, networks: Sequence[IPNetwork]) -> bool:
    for net in networks:
        if addr.version == net.version and addr in net:
            return True
    return False


def extract_client_ip(
    remote: str | None,
    x_forwarded_for: str | None,
    trusted_networks: Sequence[IPNetwork],
) -> str:
    """Extract authentic client IP respecting `WEB_TRUSTED_PROXIES`.

    Only when `remote` belongs to `trusted_networks`, parses `X-Forwarded-For`
    right-to-left and returns the rightmost valid IP not in `trusted_networks`.
    Otherwise ignores `X-Forwarded-For` completely and returns canonical `remote`.
    """
    peer_ip = _parse_ip(remote)
    if peer_ip is None:
        return "unknown"

    if not trusted_networks or not _ip_in_networks(peer_ip, trusted_networks):
        return str(peer_ip)

    if not x_forwarded_for or not isinstance(x_forwarded_for, str):
        return str(peer_ip)

    parts = x_forwarded_for.split(",")
    for raw_part in reversed(parts):
        candidate = _parse_ip(raw_part)
        if candidate is None:
            continue
        if not _ip_in_networks(candidate, trusted_networks):
            return str(candidate)

    return str(peer_ip)


class ClientIpExtractor:
    """Reusable request client IP extractor bound to parsed trusted proxy networks."""

    def __init__(self, trusted_proxies: Sequence[str] | str = ()) -> None:
        self._trusted_networks: tuple[IPNetwork, ...] = parse_trusted_networks(trusted_proxies)

    @property
    def trusted_networks(self) -> tuple[IPNetwork, ...]:
        return self._trusted_networks

    def extract(self, request: web.BaseRequest) -> str:
        xff = request.headers.get("X-Forwarded-For")
        return extract_client_ip(request.remote, xff, self._trusted_networks)


class OttManager:
    """Bounded SHA-256 One-Time Token pool with single-lock atomic consumption."""

    def __init__(
        self,
        *,
        ttl_seconds: float = WEB_OTT_TTL_SECONDS,
        maxsize: int = WEB_OTT_MAXSIZE,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        self._ttl_seconds = float(ttl_seconds)
        self._maxsize = int(maxsize)
        self._clock = clock
        self._lock = threading.Lock()
        self._tokens: OrderedDict[str, float] = OrderedDict()

    def _purge_expired_locked(self, now: float) -> int:
        expired_keys = [digest for digest, exp in self._tokens.items() if exp <= now]
        for digest in expired_keys:
            self._tokens.pop(digest, None)
        return len(expired_keys)

    def issue_ott(self) -> str:
        """Generate a 256-bit OTT, store only its SHA-256 digest, and evict oldest if full."""
        raw_ott = secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw_ott.encode("ascii")).hexdigest()
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            while len(self._tokens) >= self._maxsize:
                self._tokens.popitem(last=False)
            self._tokens[digest] = now + self._ttl_seconds
        return raw_ott

    def consume_ott(self, raw_ott: str) -> bool:
        """Atomically verify and immediately pop `sha256(raw_ott)` under a single lock."""
        digest = _hash_ascii_token(raw_ott)
        if digest is None:
            return False
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            expires_at = self._tokens.pop(digest, None)
            return expires_at is not None and expires_at > now

    def cleanup_expired(self) -> int:
        now = self._clock()
        with self._lock:
            return self._purge_expired_locked(now)

    @property
    def active_count(self) -> int:
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            return len(self._tokens)


class SessionManager:
    """Bounded SHA-256 admin session store with sliding TTL and LRU eviction."""

    def __init__(
        self,
        *,
        cookie_secure: bool = False,
        cookie_name: str = SESSION_COOKIE_NAME,
        ttl_seconds: float = WEB_SESSION_TTL_SECONDS,
        maxsize: int = WEB_SESSION_MAXSIZE,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if maxsize < 1:
            raise ValueError("maxsize must be >= 1")
        self.cookie_name = cookie_name
        self.cookie_secure = bool(cookie_secure)
        self._ttl_seconds = float(ttl_seconds)
        self._maxsize = int(maxsize)
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: OrderedDict[str, float] = OrderedDict()

    def _purge_expired_locked(self, now: float) -> int:
        expired_keys = [digest for digest, exp in self._sessions.items() if exp <= now]
        for digest in expired_keys:
            self._sessions.pop(digest, None)
        return len(expired_keys)

    def create_session(self) -> str:
        """Issue a new 256-bit admin session token and store its SHA-256 digest."""
        raw_token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            while len(self._sessions) >= self._maxsize:
                self._sessions.popitem(last=False)
            self._sessions[digest] = now + self._ttl_seconds
        return raw_token

    def validate_session(self, raw_token: str | None, *, touch: bool = True) -> bool:
        """Validate session token and optionally slide its idle TTL and LRU position."""
        if not raw_token:
            return False
        digest = _hash_ascii_token(raw_token)
        if digest is None:
            return False
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            if digest not in self._sessions:
                return False
            if touch:
                self._sessions[digest] = now + self._ttl_seconds
                self._sessions.move_to_end(digest)
            return True

    def destroy_session(self, raw_token: str | None) -> bool:
        """Invalidate a session token if present."""
        if not raw_token:
            return False
        digest = _hash_ascii_token(raw_token)
        if digest is None:
            return False
        with self._lock:
            return self._sessions.pop(digest, None) is not None

    def apply_session_cookie(self, response: web.StreamResponse, raw_token: str) -> None:
        """Attach `HttpOnly; SameSite=Strict; Path=/` session cookie to response."""
        response.set_cookie(
            self.cookie_name,
            raw_token,
            max_age=int(self._ttl_seconds),
            path="/",
            httponly=True,
            samesite="Strict",
            secure=self.cookie_secure,
        )

    def clear_session_cookie(self, response: web.StreamResponse) -> None:
        """Overwrite and expire the admin session cookie with matching security flags."""
        response.set_cookie(
            self.cookie_name,
            "",
            max_age=0,
            expires="Thu, 01 Jan 1970 00:00:00 GMT",
            path="/",
            httponly=True,
            samesite="Strict",
            secure=self.cookie_secure,
        )

    def cleanup_expired(self) -> int:
        now = self._clock()
        with self._lock:
            return self._purge_expired_locked(now)

    @property
    def active_count(self) -> int:
        now = self._clock()
        with self._lock:
            self._purge_expired_locked(now)
            return len(self._sessions)


class LoginRateLimiter:
    """Bounded LRU sliding-window failed OTT login rate limiter per client IP."""

    def __init__(
        self,
        *,
        max_ips: int = WEB_LOGIN_RATE_LIMIT_MAX_IPS,
        window_seconds: float = WEB_LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        max_fails: int = WEB_LOGIN_RATE_LIMIT_MAX_FAILS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_ips < 1:
            raise ValueError("max_ips must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_fails < 1:
            raise ValueError("max_fails must be >= 1")
        self._max_ips = int(max_ips)
        self._window_seconds = float(window_seconds)
        self._max_fails = int(max_fails)
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()

    def _prune_ip_locked(self, client_ip: str, cutoff: float) -> deque[float] | None:
        dq = self._buckets.get(client_ip)
        if dq is None:
            return None
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if not dq:
            self._buckets.pop(client_ip, None)
            return None
        return dq

    def _purge_expired_locked(self, cutoff: float) -> int:
        removed = 0
        for ip in list(self._buckets.keys()):
            if self._prune_ip_locked(ip, cutoff) is None:
                removed += 1
        return removed

    def is_limited(self, client_ip: str) -> bool:
        """Return True if `client_ip` has reached `max_fails` within the current window."""
        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            dq = self._prune_ip_locked(client_ip, cutoff)
            if dq is not None and len(dq) >= self._max_fails:
                self._buckets.move_to_end(client_ip)
                return True
            return False

    def record_failure(self, client_ip: str) -> int:
        """Record a failed OTT exchange attempt for `client_ip` and return active fail count."""
        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            dq = self._prune_ip_locked(client_ip, cutoff)
            if dq is None:
                if len(self._buckets) >= self._max_ips:
                    self._purge_expired_locked(cutoff)
                while len(self._buckets) >= self._max_ips:
                    self._buckets.popitem(last=False)
                dq = deque()
                self._buckets[client_ip] = dq
            else:
                self._buckets.move_to_end(client_ip)

            if len(dq) <= self._max_fails:
                dq.append(now)
            else:
                dq.popleft()
                dq.append(now)
            return len(dq)

    def cleanup_expired(self) -> int:
        now = self._clock()
        cutoff = now - self._window_seconds
        with self._lock:
            return self._purge_expired_locked(cutoff)


class WebAuthManager:
    """Unified coordinator for OTTs, admin sessions, origin checks, and IP rate limiting."""

    def __init__(
        self,
        *,
        web_origin: str,
        cookie_secure: bool,
        trusted_proxies: Sequence[str] | str = (),
        ott_manager: OttManager | None = None,
        session_manager: SessionManager | None = None,
        rate_limiter: LoginRateLimiter | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.web_origin = normalize_web_origin(web_origin)
        self.cookie_secure = bool(cookie_secure)
        self.ip_extractor = ClientIpExtractor(trusted_proxies)
        self.ott_manager = ott_manager or OttManager(clock=clock)
        self.session_manager = session_manager or SessionManager(
            cookie_secure=self.cookie_secure, clock=clock
        )
        self.rate_limiter = rate_limiter or LoginRateLimiter(clock=clock)

    @classmethod
    def from_bootstrap(
        cls,
        bootstrap: BootstrapConfigSnapshot,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> WebAuthManager:
        origin = normalize_web_origin(bootstrap.web_origin, bootstrap.web_base_url)
        return cls(
            web_origin=origin,
            cookie_secure=bootstrap.web_cookie_secure,
            trusted_proxies=bootstrap.web_trusted_proxies,
            clock=clock,
        )

    def issue_ott(self) -> str:
        return self.ott_manager.issue_ott()

    def consume_ott(self, raw_ott: str) -> bool:
        return self.ott_manager.consume_ott(raw_ott)

    def extract_request_ip(self, request: web.BaseRequest) -> str:
        return self.ip_extractor.extract(request)

    def is_valid_origin(self, origin_header: str | None) -> bool:
        if not origin_header or not isinstance(origin_header, str):
            return False
        return origin_header.strip() == self.web_origin

    def cleanup_expired(self) -> None:
        """Purge expired OTTs, sessions, and rate-limit buckets (Janitor hook)."""
        self.ott_manager.cleanup_expired()
        self.session_manager.cleanup_expired()
        self.rate_limiter.cleanup_expired()
