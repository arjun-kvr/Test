"""Session-token authentication and role authorisation for AgentOS MCP servers.

VENDORED FILE — byte-identical copies live in ``aos-mcp``, ``databricks-mcp``
and ``rag-mcp``. ``aos-mcp`` holds the canonical copy; edit it there and re-sync
the others. Each repo's ``test_mcp_auth_drift.py`` pins the SHA-256 of this file,
so an unsynchronised edit fails that repo's build instead of silently forking the
security boundary.

WHAT IT ENFORCES
----------------
The platform (agent-builder) mints an RS256 session JWT, stores it in Redis under
an opaque per-session handle, and forwards *only that handle* to MCP servers as the
``login-token`` header. This module turns that handle into a verified identity and
then decides whether the caller may see or call a tool:

1. ``login-token`` is read from the header, the ``Authorization: Bearer`` header, or
   the ``login-token`` cookie. Absent -> deny.
2. The handle is shape-checked before it is ever used as a Redis key, so a caller
   cannot smuggle a glob, a newline, or another keyspace into the lookup.
3. The handle is resolved against the login Redis DB. No session record -> deny.
   Deleting the session hash therefore revokes every in-flight MCP call.
4. The retrieved JWT is verified: asymmetric signature (RS*/PS*/ES* only — HMAC and
   ``none`` are rejected outright, so a leaked public key cannot be used to forge a
   token), ``exp`` required and enforced, ``iss`` required *and* checked, ``aud``
   required *and* checked by default.
5. Binding check: the JWT's ``uid`` claim must equal the presented handle, compared
   in constant time. A missing ``uid`` is a denial, not a skipped check — a token
   cannot be replayed under a different handle.
6. ``role`` must be one of the roles allowed to reach MCP tools (Super Admin, Admin,
   Pro code developer by default). Anything else -> deny.
7. Optionally, a per-tool authorisation callback narrows access further (aos-mcp
   passes its ``mcp_tool_access`` grant table; the leaf MCPs have no such table and
   stop at the role gate).

Every failure path denies. Any unexpected exception denies. If the public key cannot
be loaded the server does not crash — it denies every request and logs CRITICAL,
which is both fail-closed and debuggable.

SCOPE
-----
Gated: ``list_tools``, ``call_tool``, ``list_resources``, ``list_resource_templates``,
``read_resource``, ``list_prompts``, ``get_prompt`` — i.e. every capability that can
disclose or do something.

Not gated: the ``initialize`` handshake and ``ping``. Blocking those would break the
transport before a client can present anything, and they disclose only the server
name and protocol version. Nothing reachable through them returns data or runs code.

This module authenticates the *caller*. It does not authenticate the *server* to the
caller — there is no mTLS on the MCP transport today, so in-cluster placement and
NetworkPolicy remain part of the control set.

CONFIGURATION (all optional; defaults are the secure ones)
----------------------------------------------------------
``MCP_AUTH_ENFORCEMENT``   ``enforce`` (default) | ``monitor``. ``monitor`` logs what
                           *would* have been denied and allows the call — a staged
                           rollout aid only. It is never the default, and it warns on
                           every request it lets through.
``JWT_PUBLIC_KEY_PATH``    default ``conf/keys/kivor_ai.pub``
``JWT_ALG``                default ``RS256``; must be asymmetric
``JWT_ISSUER``             default ``kivor-ai``; always verified
``JWT_AUDIENCE``           default ``agentos-backend``; comma-separated list allowed
``JWT_REQUIRE_AUDIENCE``   default ``true``
``JWT_LEEWAY_SECONDS``     default ``10`` (matches the platform's clock skew budget)
``MCP_ALLOWED_ROLES``      default ``Super Admin,Admin,Pro code developer``
``MCP_ADMIN_ROLES``        default ``Super Admin,Admin``
``MCP_SESSION_REDIS_DB``   default ``3`` (the platform's login DB)
``REDIS_HOST`` / ``REDIS_PORT`` / ``REDIS_USERNAME`` / ``REDIS_PASSWORD``
``MCP_SESSION_REDIS_TIMEOUT_SECONDS`` default ``2``
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import jwt
from fastmcp.exceptions import PromptError, ResourceError, ToolError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware, MiddlewareContext

from src.logging import logger

__all__ = [
    "DEFAULT_ADMIN_ROLES",
    "DEFAULT_ALLOWED_ROLES",
    "AuthContext",
    "AuthError",
    "AuthSettings",
    "McpAuthMiddleware",
    "SessionAuthenticator",
    "build_auth_middleware",
    "normalise_role",
]

# Roles permitted to reach MCP tools at all. Everything else is denied before any
# per-tool grant is consulted.
DEFAULT_ALLOWED_ROLES = ("Super Admin", "Admin", "Pro code developer")

# Roles that are not subject to per-tool grants. They still have to authenticate and
# still have to pass the role gate above; the bypass is logged on every use so it is
# auditable rather than invisible.
DEFAULT_ADMIN_ROLES = ("Super Admin", "Admin")

# Signature algorithms this server will accept. HMAC (``HS*``) and ``none`` are
# excluded deliberately: MCP servers hold only the *public* key, so permitting a
# symmetric algorithm would let anyone holding that public key mint valid tokens.
_ASYMMETRIC_ALGS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
)

# The platform mints handles as ``uuid4().hex`` (32 lowercase hex chars). The check
# is deliberately a little wider than that so a future format change does not lock
# every session out, but narrow enough that the value is safe to use as a Redis key:
# no globs, no whitespace, no CRLF, no separators.
_HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

# Anything outside this set is stripped from caller-supplied values before they are
# written to a log line, so a crafted header cannot forge log entries.
_SAFE_CLIENT_RE = re.compile(r"[^A-Za-z0-9_.:\[\]-]")

_ENFORCE = "enforce"
_MONITOR = "monitor"


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "[mcp-auth] %s=%r is not an integer; using %s", name, raw, default
        )
        return default


def _env_list(name: str, default: Sequence[str]) -> tuple[str, ...]:
    raw = _env(name)
    if not raw:
        return tuple(default)
    values = tuple(part.strip() for part in raw.split(",") if part.strip())
    return values or tuple(default)


def normalise_role(role: Any) -> str:
    """Fold a role name to a comparable form.

    ``Super_Admin``, ``super-admin`` and ``  Super  Admin `` all become
    ``super admin``, so role comparisons do not hinge on how a row was typed.
    """
    if role is None:
        return ""
    if isinstance(role, bytes):
        try:
            role = role.decode()
        except Exception:
            return ""
    text = str(role).replace("_", " ").replace("-", " ")
    return " ".join(text.split()).lower()


def fingerprint(value: str) -> str:
    """Short, non-reversible tag for a session handle, safe to put in a log line."""
    if not value:
        return "-"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


class AuthError(Exception):
    """Raised when a caller cannot be authenticated or is not authorised.

    ``reason`` is the operator-facing detail and is logged. ``client_message`` is what
    the caller is told, and is deliberately coarse so a probe cannot use the error
    text to distinguish "no such session" from "expired" from "wrong role".
    """

    def __init__(self, reason: str, client_message: str = "Access denied"):
        super().__init__(reason)
        self.reason = reason
        self.client_message = client_message


@dataclass(frozen=True)
class AuthContext:
    """The verified identity behind an MCP call."""

    handle: str
    user_id: Any = None
    email: str | None = None
    role: str | None = None
    project_id: int | None = None
    department_id: Any = None
    session_id: str | None = None
    is_admin: bool = False

    @property
    def tag(self) -> str:
        """Identity summary for audit logs. Carries no token material."""
        return (
            f"user={self.user_id} role={self.role!r} project={self.project_id} "
            f"session={fingerprint(self.handle)}"
        )


@dataclass(frozen=True)
class AuthSettings:
    """Effective security configuration, resolved once at import/startup."""

    enforcement: str = _ENFORCE
    public_key_path: str = "conf/keys/kivor_ai.pub"
    algorithm: str = "RS256"
    issuer: str = "kivor-ai"
    # Issuers accepted on inbound tokens. The Kivor -> AOS issuer rename is
    # staged (KIVOR-TO-AOS-RENAME-PLAN.md 7.6): every validator accepts both
    # before the platform flips the value it mints, or validation fails closed.
    accepted_issuers: tuple[str, ...] = ("kivor-ai", "aos-ai")
    audiences: tuple[str, ...] = ("agentos-backend",)
    require_audience: bool = True
    leeway_seconds: int = 10
    allowed_roles: tuple[str, ...] = DEFAULT_ALLOWED_ROLES
    admin_roles: tuple[str, ...] = DEFAULT_ADMIN_ROLES
    redis_db: int = 3
    redis_timeout_seconds: int = 2

    @classmethod
    def from_env(cls) -> AuthSettings:
        enforcement = _env("MCP_AUTH_ENFORCEMENT", _ENFORCE).lower()
        if enforcement not in {_ENFORCE, _MONITOR}:
            logger.warning(
                "[mcp-auth] MCP_AUTH_ENFORCEMENT=%r is not recognised; enforcing.",
                enforcement,
            )
            enforcement = _ENFORCE

        algorithm = _env("JWT_ALG", "RS256").upper()
        if algorithm not in _ASYMMETRIC_ALGS:
            # Refusing to honour the override is the point: a symmetric algorithm
            # here would turn the public key into a signing key.
            logger.error(
                "[mcp-auth] JWT_ALG=%r is not an accepted asymmetric algorithm; "
                "falling back to RS256.",
                algorithm,
            )
            algorithm = "RS256"

        return cls(
            enforcement=enforcement,
            public_key_path=_env("JWT_PUBLIC_KEY_PATH", "conf/keys/kivor_ai.pub"),
            algorithm=algorithm,
            issuer=_env("JWT_ISSUER", "kivor-ai"),
            accepted_issuers=_env_list(
                "JWT_ACCEPTED_ISSUERS", ("kivor-ai", "aos-ai")
            ),
            audiences=_env_list("JWT_AUDIENCE", ("agentos-backend",)),
            require_audience=_env_bool("JWT_REQUIRE_AUDIENCE", True),
            leeway_seconds=_env_int("JWT_LEEWAY_SECONDS", 10),
            allowed_roles=_env_list("MCP_ALLOWED_ROLES", DEFAULT_ALLOWED_ROLES),
            admin_roles=_env_list("MCP_ADMIN_ROLES", DEFAULT_ADMIN_ROLES),
            redis_db=_env_int("MCP_SESSION_REDIS_DB", 3),
            redis_timeout_seconds=_env_int("MCP_SESSION_REDIS_TIMEOUT_SECONDS", 2),
        )

    @property
    def enforcing(self) -> bool:
        return self.enforcement == _ENFORCE

    @property
    def allowed_roles_normalised(self) -> frozenset[str]:
        return frozenset(normalise_role(role) for role in self.allowed_roles)

    @property
    def admin_roles_normalised(self) -> frozenset[str]:
        return frozenset(normalise_role(role) for role in self.admin_roles)

    def describe(self) -> str:
        """One-line, secret-free summary for the startup banner."""
        return (
            f"enforcement={self.enforcement} alg={self.algorithm} issuer={self.issuer!r} "
            f"audience={list(self.audiences)} require_aud={self.require_audience} "
            f"leeway={self.leeway_seconds}s roles={list(self.allowed_roles)} "
            f"admin_roles={list(self.admin_roles)} key={self.public_key_path} "
            f"redis_db={self.redis_db}"
        )


class _PublicKeyCache:
    """Reads the mounted public key, reloading it when the file changes.

    Kubernetes updates a mounted Secret in place, so watching mtime+size lets a key
    rotation take effect without a pod restart, while still avoiding a disk read on
    every request.
    """

    def __init__(self, path: str):
        self._path = path
        self._key: str | None = None
        self._stamp: tuple[float, int] | None = None
        self._lock = threading.Lock()

    @property
    def path(self) -> str:
        return self._path

    def get(self) -> str:
        with self._lock:
            try:
                stat = os.stat(self._path)
                stamp = (stat.st_mtime, stat.st_size)
            except OSError as exc:
                self._key = None
                self._stamp = None
                raise AuthError(
                    f"JWT public key unreadable at {self._path}: {exc}"
                ) from exc

            if self._key is not None and self._stamp == stamp:
                return self._key

            try:
                with open(self._path, encoding="utf-8") as handle:
                    key = handle.read().strip()
            except OSError as exc:
                self._key = None
                self._stamp = None
                raise AuthError(
                    f"JWT public key unreadable at {self._path}: {exc}"
                ) from exc

            if not key:
                self._key = None
                self._stamp = None
                raise AuthError(f"JWT public key at {self._path} is empty")

            self._key = key
            self._stamp = stamp
            return key


class SessionAuthenticator:
    """Turns a ``login-token`` handle into a verified :class:`AuthContext`."""

    def __init__(
        self,
        settings: AuthSettings | None = None,
        redis_client: Any = None,
        key_cache: _PublicKeyCache | None = None,
    ):
        self.settings = settings or AuthSettings.from_env()
        self._key_cache = key_cache or _PublicKeyCache(self.settings.public_key_path)
        self._redis = redis_client
        self._redis_ready = redis_client is not None
        self._redis_lock = threading.Lock()

    # -- session store ----------------------------------------------------- #

    def _get_redis(self) -> Any:
        if self._redis_ready:
            return self._redis
        with self._redis_lock:
            if self._redis_ready:
                return self._redis
            try:
                import redis  # imported lazily so the module loads without the dep
            except ImportError as exc:  # pragma: no cover - dependency is declared
                raise AuthError(f"redis client library unavailable: {exc}") from exc

            settings = self.settings
            timeout = settings.redis_timeout_seconds
            try:
                self._redis = redis.Redis(
                    host=_env("REDIS_HOST", "localhost"),
                    port=_env_int("REDIS_PORT", 6379),
                    username=_env("REDIS_USERNAME") or _env("REDIS_USER") or None,
                    password=_env("REDIS_PASSWORD") or None,
                    db=settings.redis_db,
                    decode_responses=True,
                    # Without these a stalled Redis wedges every MCP request until the
                    # client gives up, which turns an auth dependency into an outage.
                    socket_connect_timeout=timeout,
                    socket_timeout=timeout,
                )
            except Exception as exc:
                raise AuthError(f"failed to build Redis client: {exc}") from exc
            self._redis_ready = True
            return self._redis

    def _lookup_session_jwt(self, handle: str) -> str:
        client = self._get_redis()
        try:
            token = client.hget(handle, "token")
        except Exception as exc:
            # Fail closed. An unreachable session store must not mean "let it through".
            raise AuthError(f"session store lookup failed: {exc}") from exc

        if not token:
            raise AuthError("no session record for the presented handle")
        if isinstance(token, bytes):
            token = token.decode("utf-8", "replace")
        return token

    # -- token verification ------------------------------------------------ #

    def _verify_jwt(self, token: str, handle: str) -> dict:
        settings = self.settings
        public_key = self._key_cache.get()

        required = ["exp", "iss", "uid"]
        if settings.require_audience:
            required.append("aud")

        options = {
            "require": required,
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": settings.require_audience,
        }

        try:
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[settings.algorithm],
                leeway=settings.leeway_seconds,
                # A LIST (PyJWT >= 2.10) so tokens minted either side of the
                # staged issuer rename both validate.
                issuer=list(settings.accepted_issuers),
                # PyJWT raises InvalidAudienceError when a token carries ``aud`` but no
                # expected audience was supplied, so this is passed even when
                # verification is staged off via JWT_REQUIRE_AUDIENCE.
                audience=list(settings.audiences),
                options=options,
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("session token expired") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthError("session token signature is invalid") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("session token issuer mismatch") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("session token audience mismatch") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise AuthError(f"session token missing a required claim: {exc}") from exc
        except jwt.InvalidAlgorithmError as exc:
            # Also the signal that PyJWT has no ``cryptography`` backend for RS256.
            raise AuthError(f"session token algorithm rejected: {exc}") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError(f"session token is invalid: {exc}") from exc

        uid = payload.get("uid")
        if isinstance(uid, bytes):
            uid = uid.decode("utf-8", "replace")
        if not isinstance(uid, str) or not uid:
            raise AuthError("session token has no usable uid binding")
        # Constant-time, and over bytes: the handle is attacker-supplied and this
        # comparison is what stops a token being replayed under a different handle.
        # ``compare_digest`` rejects non-ASCII str operands with TypeError, so both
        # sides are encoded rather than trusting the claim to be ASCII.
        if not hmac.compare_digest(uid.encode("utf-8"), handle.encode("utf-8")):
            raise AuthError("session token is not bound to the presented handle")

        return payload

    # -- entry point ------------------------------------------------------- #

    @staticmethod
    def extract_handle(headers: dict[str, str]) -> str:
        """Pull the session handle out of the request headers.

        ``login-token`` is what the platform sends. ``Authorization: Bearer`` and the
        ``login-token`` cookie are accepted as equivalents so a browser-originated or
        standards-shaped client works without a special case.
        """
        candidate = headers.get("login-token") or ""

        if not candidate:
            authorization = headers.get("authorization") or ""
            scheme, _, value = authorization.partition(" ")
            if scheme.lower() == "bearer":
                candidate = value

        if not candidate:
            cookie_header = headers.get("cookie") or ""
            for part in cookie_header.split(";"):
                name, _, value = part.strip().partition("=")
                if name == "login-token":
                    candidate = value
                    break

        return candidate.strip()

    def authenticate(self, headers: dict[str, str] | None) -> AuthContext:
        """Verify the caller and return their identity, or raise :class:`AuthError`."""
        if not headers:
            # No HTTP request context at all. These servers are deployed over HTTP,
            # so this is either a misconfiguration or a non-HTTP caller; both deny.
            raise AuthError("no request headers available for authentication")

        handle = self.extract_handle(headers)
        if not handle:
            raise AuthError("no login-token presented")
        if not _HANDLE_RE.match(handle):
            # Checked before the value reaches Redis so a malformed handle cannot be
            # used to probe or pattern-match the keyspace.
            raise AuthError("login-token is not a well-formed session handle")

        payload = self._verify_jwt(self._lookup_session_jwt(handle), handle)

        role = payload.get("role")
        role_text = role.decode("utf-8", "replace") if isinstance(role, bytes) else role
        role_norm = normalise_role(role_text)
        if not role_norm:
            raise AuthError("session token carries no role")
        if role_norm not in self.settings.allowed_roles_normalised:
            raise AuthError(f"role {role_text!r} is not permitted to access MCP tools")

        return AuthContext(
            handle=handle,
            user_id=payload.get("user_id"),
            email=payload.get("email"),
            role=role_text,
            project_id=_coerce_project_id(payload.get("project_id")),
            department_id=payload.get("department_id"),
            session_id=payload.get("sid"),
            is_admin=role_norm in self.settings.admin_roles_normalised,
        )


def _coerce_project_id(raw: Any) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode()
        except Exception:
            return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        logger.warning("[mcp-auth] ignoring non-integer project_id in session token")
        return None


# ``(context, tool_name) -> bool``: may this identity call this tool?
ToolAuthorizer = Callable[[AuthContext, str], bool]
# ``(context) -> set[str] | None``: which tool names may this identity see?
# ``None`` means "no per-tool grant model applies — the role gate was enough".
AllowedToolsProvider = Callable[[AuthContext], set[str] | None]


@dataclass
class McpAuthMiddleware(Middleware):
    """FastMCP middleware that authenticates and authorises every capability call.

    Listing and invocation are gated independently, so an ungranted tool is both
    invisible and uncallable — discovering a tool name is never enough to run it.

    ``tool_authorizer`` / ``allowed_tools_provider`` are optional. aos-mcp supplies
    them from its ``mcp_tool_access`` grant table; databricks-mcp and rag-mcp have no
    such table and stop at the role gate, which is what the platform's access model
    grants them anyway.
    """

    server_name: str = "mcp"
    authenticator: SessionAuthenticator = field(default_factory=SessionAuthenticator)
    tool_authorizer: ToolAuthorizer | None = None
    allowed_tools_provider: AllowedToolsProvider | None = None

    def __post_init__(self) -> None:
        # ``Middleware`` has no __init__ of its own in FastMCP, but call it anyway so
        # this keeps working if that changes.
        super().__init__()
        settings = self.settings
        logger.info(
            "[mcp-auth] %s: session-token authentication active (%s)",
            self.server_name,
            settings.describe(),
        )
        if not settings.enforcing:
            logger.warning(
                "[mcp-auth] %s: MCP_AUTH_ENFORCEMENT=monitor — denials are logged but "
                "NOT enforced. This is a rollout aid; unset it to enforce.",
                self.server_name,
            )
        try:
            self.authenticator._key_cache.get()
        except AuthError as exc:
            # Deliberately not fatal: a pod that will not start cannot be inspected,
            # and denying every request is equally fail-closed.
            logger.critical(
                "[mcp-auth] %s: JWT public key is not loadable (%s). Every "
                "authenticated call will be DENIED until this is fixed.",
                self.server_name,
                exc.reason,
            )

    @property
    def settings(self) -> AuthSettings:
        return self.authenticator.settings

    # -- decision helpers -------------------------------------------------- #

    def _client_hint(self, headers: dict[str, str] | None) -> str:
        """Best-effort client address for the audit line.

        These headers are set by the caller, so the value is untrusted twice over:
        it can be spoofed (it is a hint, never an access-control input) and it can
        carry newlines or control characters that would forge extra log lines. It is
        therefore sanitised and truncated before it is logged.
        """
        if not headers:
            return "client=unknown"
        raw = (headers.get("x-forwarded-for") or "").split(",")[0].strip()
        raw = raw or (headers.get("x-real-ip") or "").strip()
        safe = _SAFE_CLIENT_RE.sub("", raw)[:64]
        return f"client={safe or 'unknown'}"

    def _authorise(self, operation: str) -> AuthContext | None:
        """Authenticate the caller for ``operation``.

        Returns the verified context, or ``None`` when authentication failed while
        running in monitor mode (the call is allowed through, unauthenticated).
        Raises :class:`AuthError` when enforcing.
        """
        headers = get_http_headers()
        try:
            context = self.authenticator.authenticate(headers)
        except AuthError as exc:
            self._record_denial(operation, exc, headers)
            if self.settings.enforcing:
                raise
            return None
        except Exception as exc:  # fail closed on anything unexpected
            wrapped = AuthError(f"unexpected authentication failure: {exc}")
            logger.exception(
                "[mcp-auth] %s: unexpected failure authenticating %s",
                self.server_name,
                operation,
            )
            self._record_denial(operation, wrapped, headers)
            if self.settings.enforcing:
                raise wrapped from exc
            return None

        logger.debug(
            "[mcp-auth] %s: %s authenticated for %s",
            self.server_name,
            context.tag,
            operation,
        )
        return context

    def _record_denial(
        self, operation: str, exc: AuthError, headers: dict[str, str] | None
    ) -> None:
        handle = self.authenticator.extract_handle(headers or {})
        verb = "DENY" if self.settings.enforcing else "WOULD-DENY (monitor mode)"
        logger.warning(
            "[mcp-auth] %s: %s %s — %s (session=%s, %s)",
            self.server_name,
            verb,
            operation,
            exc.reason,
            fingerprint(handle),
            self._client_hint(headers),
        )

    def _deny_tool(self, context: AuthContext, tool_name: str, reason: str) -> None:
        """Apply a per-tool grant decision, honouring monitor mode."""
        logger.warning(
            "[mcp-auth] %s: %s call_tool %r — %s (%s)",
            self.server_name,
            "DENY" if self.settings.enforcing else "WOULD-DENY (monitor mode)",
            tool_name,
            reason,
            context.tag,
        )
        if self.settings.enforcing:
            raise AuthError(reason, f"Access denied for tool '{tool_name}'")

    # -- capability hooks -------------------------------------------------- #

    async def on_list_tools(self, context: MiddlewareContext, call_next):
        try:
            auth = self._authorise("list_tools")
        except AuthError as exc:
            raise ToolError(exc.client_message) from exc

        tools = await call_next(context)
        if auth is None:
            return tools

        allowed = self._resolve_allowed_tools(auth)
        if allowed is None:
            return tools

        visible = [tool for tool in tools if getattr(tool, "name", None) in allowed]
        if len(visible) != len(tools):
            logger.info(
                "[mcp-auth] %s: list_tools filtered %d/%d tools (%s)",
                self.server_name,
                len(visible),
                len(tools),
                auth.tag,
            )
        return visible

    def _resolve_allowed_tools(self, auth: AuthContext) -> set[str] | None:
        """Names this identity may see, or ``None`` for "no further narrowing"."""
        if auth.is_admin:
            # Admin visibility is intentional, but it is the privileged path a PAM
            # review cares about, so it is recorded rather than silent.
            logger.info(
                "[mcp-auth] %s: privileged listing — per-tool grants bypassed (%s)",
                self.server_name,
                auth.tag,
            )
            return None
        if self.allowed_tools_provider is None:
            return None
        try:
            return self.allowed_tools_provider(auth)
        except Exception:
            logger.exception(
                "[mcp-auth] %s: tool-grant lookup failed during list_tools; "
                "returning no tools (%s)",
                self.server_name,
                auth.tag,
            )
            # Fail closed: an unreadable grant table must not widen visibility.
            return set()

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool_name = getattr(context.message, "name", None) or "<unknown>"
        try:
            auth = self._authorise(f"call_tool {tool_name!r}")
            if auth is not None:
                self._check_tool_grant(auth, tool_name)
        except AuthError as exc:
            raise ToolError(exc.client_message) from exc
        return await call_next(context)

    def _check_tool_grant(self, auth: AuthContext, tool_name: str) -> None:
        if auth.is_admin:
            logger.info(
                "[mcp-auth] %s: privileged call_tool %r — per-tool grants bypassed (%s)",
                self.server_name,
                tool_name,
                auth.tag,
            )
            return
        if self.tool_authorizer is None:
            return
        try:
            permitted = self.tool_authorizer(auth, tool_name)
        except Exception as exc:
            logger.exception(
                "[mcp-auth] %s: tool-grant lookup failed for %r (%s)",
                self.server_name,
                tool_name,
                auth.tag,
            )
            self._deny_tool(auth, tool_name, f"tool authorisation lookup failed: {exc}")
            return
        if not permitted:
            self._deny_tool(auth, tool_name, "no grant for this role and project")

    async def on_list_resources(self, context: MiddlewareContext, call_next):
        try:
            self._authorise("list_resources")
        except AuthError as exc:
            raise ResourceError(exc.client_message) from exc
        return await call_next(context)

    async def on_list_resource_templates(self, context: MiddlewareContext, call_next):
        try:
            self._authorise("list_resource_templates")
        except AuthError as exc:
            raise ResourceError(exc.client_message) from exc
        return await call_next(context)

    async def on_read_resource(self, context: MiddlewareContext, call_next):
        try:
            self._authorise("read_resource")
        except AuthError as exc:
            raise ResourceError(exc.client_message) from exc
        return await call_next(context)

    async def on_list_prompts(self, context: MiddlewareContext, call_next):
        try:
            self._authorise("list_prompts")
        except AuthError as exc:
            raise PromptError(exc.client_message) from exc
        return await call_next(context)

    async def on_get_prompt(self, context: MiddlewareContext, call_next):
        try:
            self._authorise("get_prompt")
        except AuthError as exc:
            raise PromptError(exc.client_message) from exc
        return await call_next(context)


def build_auth_middleware(
    server_name: str,
    *,
    redis_client: Any = None,
    tool_authorizer: ToolAuthorizer | None = None,
    allowed_tools_provider: AllowedToolsProvider | None = None,
    settings: AuthSettings | None = None,
) -> McpAuthMiddleware:
    """Construct the middleware with environment-derived settings."""
    authenticator = SessionAuthenticator(
        settings=settings or AuthSettings.from_env(), redis_client=redis_client
    )
    return McpAuthMiddleware(
        server_name=server_name,
        authenticator=authenticator,
        tool_authorizer=tool_authorizer,
        allowed_tools_provider=allowed_tools_provider,
    )
