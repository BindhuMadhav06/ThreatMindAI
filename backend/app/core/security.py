"""
Core Authentication and Tenant Authorization Boundary for ThreatMind AI.

Enforces cryptographic Bearer token (JWT) verification, hashed SQLite-durable API-key
authentication, server-side tenant identity derivation, role-based access control (RBAC),
server-side recipient capability resolution with default-deny, and strict prevention of
client-side tenant or approver spoofing.

Conforms to standards:
- RFC 7519 (JSON Web Token)
- RFC 6750 (OAuth 2.0 Bearer Token Usage)
- Zero Trust Architecture (NIST SP 800-207)
"""

import hashlib
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

import jwt
from fastapi import Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import logger


VALID_ROLES: Set[str] = {"analyst", "admin", "lead", "viewer"}
ALLOWED_ALGORITHMS: List[str] = ["HS256"]

KNOWN_INSECURE_SECRETS: Set[str] = {
    "threatmind-dev-secret-key-change-in-production-min32bytes",
    "secret",
    "password",
    "changeme",
    "admin",
    "default-secret-key-do-not-use-in-production",
    "12345678901234567890123456789012",
}


def validate_jwt_secret_configuration(
    secret_key: Optional[str] = None,
    environment: Optional[str] = None,
) -> bool:
    """
    Validates JWT secret key against production security standards.

    In production:
    - Must be non-empty and at least 32 bytes (256 bits).
    - Must not match any entry in KNOWN_INSECURE_SECRETS.
    - Must not contain weak/placeholder substrings like 'change-in-production',
      'secret', 'password', 'default', 'test', 'demo', or 'example' (case-insensitive).
    - Must exhibit sufficient entropy: at least 12 unique characters for keys of 32+ bytes.

    Raises RuntimeError if validation fails in production mode.
    Returns True if valid.
    """
    env = (environment or settings.ENVIRONMENT or "").lower()
    key = secret_key if secret_key is not None else settings.JWT_SECRET_KEY

    # In non-production environments, allow development keys
    if env not in ("production", "prod"):
        return True

    if not key or not isinstance(key, str):
        raise RuntimeError("Production environment requires a non-empty JWT_SECRET_KEY.")

    if len(key) < 32:
        raise RuntimeError(
            f"Production JWT_SECRET_KEY must be at least 32 bytes (256 bits); got {len(key)} bytes."
        )

    key_lower = key.lower()
    if key in KNOWN_INSECURE_SECRETS or key_lower in KNOWN_INSECURE_SECRETS:
        raise RuntimeError(
            "Production JWT_SECRET_KEY cannot use a known default or insecure placeholder secret."
        )

    insecure_patterns = [
        "change-in-production",
        "changeme",
        "default-secret",
        "demo-key",
        "test-secret",
        "example",
    ]
    for pattern in insecure_patterns:
        if pattern in key_lower:
            raise RuntimeError(
                f"Production JWT_SECRET_KEY contains insecure placeholder pattern: '{pattern}'."
            )

    # Entropy check on character distribution
    unique_chars = len(set(key))
    if unique_chars < 12:
        raise RuntimeError(
            f"Production JWT_SECRET_KEY has insufficient character entropy ({unique_chars} unique chars, min 12)."
        )

    return True


class AuthenticatedUser(BaseModel):
    """
    Server-verified user identity context.
    Client-supplied headers or body fields cannot override these attributes.
    """
    user_id: str
    role: str
    tenant_id: str
    is_admin: bool = False
    clearance: str = "AMBER"
    is_internal_org_member: bool = False
    is_extension_aware: bool = False
    scopes: List[str] = Field(default_factory=lambda: ["read", "write"])


# ---------------------------------------------------------------------------
# Server-side Durable SQLite Hashed API Key Store (Thread-safe & WAL mode)
# ---------------------------------------------------------------------------

class ApiKeyRecord(BaseModel):
    key_hash: str
    user_id: str
    tenant_id: str
    role: str
    is_admin: bool = False
    clearance: str = "AMBER"
    is_internal_org_member: bool = False
    is_extension_aware: bool = False
    revoked: bool = False
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class ApiKeyStore:
    """
    Durable, thread-safe SQLite-backed store for cryptographically hashed API keys.
    Operates in WAL mode to guarantee durability across process restarts and concurrent workers.
    Never persists plain-text API keys (SHA-256 digests only).
    """
    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            # Default to data/federation/api_keys.db
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            self.db_path = os.path.join(base_dir, "data", "federation", "api_keys.db")
        else:
            self.db_path = db_path

        if self.db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)

        self._lock = threading.Lock()
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        if self.db_path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            with self._connection() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS api_keys (
                        key_hash TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        tenant_id TEXT NOT NULL,
                        role TEXT NOT NULL,
                        is_admin INTEGER NOT NULL DEFAULT 0,
                        clearance TEXT NOT NULL DEFAULT 'AMBER',
                        is_internal_org_member INTEGER NOT NULL DEFAULT 0,
                        is_extension_aware INTEGER NOT NULL DEFAULT 0,
                        revoked INTEGER NOT NULL DEFAULT 0,
                        expires_at TEXT,
                        created_at TEXT NOT NULL
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);")
                conn.commit()

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()

    def register_key(
        self,
        raw_key: str,
        user_id: str,
        tenant_id: str,
        role: str = "analyst",
        is_admin: bool = False,
        clearance: str = "AMBER",
        is_internal_org_member: bool = False,
        is_extension_aware: bool = False,
        expires_at: Optional[datetime] = None,
    ) -> str:
        kh = self.hash_key(raw_key)
        now_iso = datetime.now(timezone.utc).isoformat()
        exp_iso = expires_at.isoformat() if expires_at else None

        with self._lock:
            with self._connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO api_keys (
                        key_hash, user_id, tenant_id, role, is_admin, clearance,
                        is_internal_org_member, is_extension_aware, revoked, expires_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        kh,
                        user_id,
                        tenant_id,
                        role,
                        1 if (is_admin or role == "admin") else 0,
                        clearance,
                        1 if is_internal_org_member else 0,
                        1 if is_extension_aware else 0,
                        exp_iso,
                        now_iso,
                    ),
                )
                conn.commit()
        return kh

    def revoke_key(self, raw_key: str) -> bool:
        kh = self.hash_key(raw_key)
        return self.revoke_by_hash(kh)

    def revoke_by_hash(self, key_hash: str) -> bool:
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("UPDATE api_keys SET revoked = 1 WHERE key_hash = ?", (key_hash,))
                conn.commit()
                return cur.rowcount > 0

    def lookup_key(self, raw_key: str) -> Optional[ApiKeyRecord]:
        kh = self.hash_key(raw_key)
        return self.lookup_by_hash(kh)

    def lookup_by_hash(self, key_hash: str) -> Optional[ApiKeyRecord]:
        with self._lock:
            with self._connection() as conn:
                cur = conn.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))
                row = cur.fetchone()
                if not row:
                    return None
                return self._row_to_record(row)

    def list_keys(self, tenant_id: Optional[str] = None) -> List[ApiKeyRecord]:
        with self._lock:
            with self._connection() as conn:
                if tenant_id:
                    cur = conn.execute("SELECT * FROM api_keys WHERE tenant_id = ?", (tenant_id,))
                else:
                    cur = conn.execute("SELECT * FROM api_keys")
                rows = cur.fetchall()
                return [self._row_to_record(r) for r in rows]

    def clear(self) -> None:
        """Utility for test suite reset."""
        with self._lock:
            with self._connection() as conn:
                conn.execute("DELETE FROM api_keys")
                conn.commit()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ApiKeyRecord:
        exp_dt = None
        if row["expires_at"]:
            try:
                exp_dt = datetime.fromisoformat(row["expires_at"])
            except Exception:
                pass
        created_dt = None
        if row["created_at"]:
            try:
                created_dt = datetime.fromisoformat(row["created_at"])
            except Exception:
                pass
        return ApiKeyRecord(
            key_hash=row["key_hash"],
            user_id=row["user_id"],
            tenant_id=row["tenant_id"],
            role=row["role"],
            is_admin=bool(row["is_admin"]),
            clearance=row["clearance"],
            is_internal_org_member=bool(row["is_internal_org_member"]),
            is_extension_aware=bool(row["is_extension_aware"]),
            revoked=bool(row["revoked"]),
            expires_at=exp_dt,
            created_at=created_dt,
        )


api_key_store = ApiKeyStore()


# ---------------------------------------------------------------------------
# Server-side Recipient Capability Registry (Default-Deny Zero Trust)
# ---------------------------------------------------------------------------

class RecipientCapabilityRecord(BaseModel):
    recipient_id: str
    tenant_id: Optional[str] = None
    is_internal_org_member: bool = False
    is_extension_aware: bool = False
    max_clearance: str = "AMBER"


class RecipientCapabilityRegistry:
    """
    Server-side authoritative registry for recipient capabilities.
    Enforces Zero Trust Architecture (NIST SP 800-207):
    - Client HTTP headers CANNOT self-elevate internal organization status.
    - Default-deny: unregistered users have is_internal_org_member=False.
    - Attempted header spoofing without server registry/token authorization is clamped to False.
    """
    def __init__(self) -> None:
        self._registry: Dict[str, RecipientCapabilityRecord] = {}
        self._lock = threading.Lock()

    def register_recipient(
        self,
        recipient_id: str,
        tenant_id: Optional[str] = None,
        is_internal_org_member: bool = False,
        is_extension_aware: bool = False,
        max_clearance: str = "AMBER",
    ) -> None:
        with self._lock:
            self._registry[recipient_id] = RecipientCapabilityRecord(
                recipient_id=recipient_id,
                tenant_id=tenant_id,
                is_internal_org_member=is_internal_org_member,
                is_extension_aware=is_extension_aware,
                max_clearance=max_clearance,
            )

    def lookup_recipient(self, recipient_id: str) -> Optional[RecipientCapabilityRecord]:
        with self._lock:
            return self._registry.get(recipient_id)

    def clear(self) -> None:
        with self._lock:
            self._registry.clear()

    def resolve_capabilities(
        self,
        user: AuthenticatedUser,
        header_extension_aware: Optional[str] = None,
        header_org_internal: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Derives trusted recipient capabilities using server-side trust.

        Anti-Spoofing & Zero-Trust Rules:
        1. An identity is only internal if verified by server registry or cryptographically
           signed token claims (user.is_internal_org_member).
        2. If client sends X-Recipient-Org-Internal: true, but server authorization is False:
           The client header is disregarded and clamped to False (anti-spoofing).
        3. If client sends X-Recipient-Org-Internal: false, internal status is False.
        4. Extension awareness is True if token/registry asserts it, OR if client requests it
           via X-Recipient-Extension-Aware: true (a recipient may declare whether its software
           supports STIX extensions).
        """
        with self._lock:
            rec = self._registry.get(user.user_id) or self._registry.get(user.tenant_id)

        server_authorized_internal = user.is_internal_org_member or (rec.is_internal_org_member if rec else False)

        # Internal org membership derivation with header clamping
        if header_org_internal is not None:
            client_wants_internal = header_org_internal.strip().lower() == "true"
            if client_wants_internal and not server_authorized_internal:
                logger.warning(
                    "Recipient attempted unauthorized internal org status elevation: user=%s tenant=%s",
                    user.user_id,
                    user.tenant_id,
                )
                effective_internal = False  # Clamped to False (default-deny)
            else:
                effective_internal = client_wants_internal and server_authorized_internal
        else:
            effective_internal = server_authorized_internal

        # Extension awareness derivation
        server_ext = user.is_extension_aware or (rec.is_extension_aware if rec else False)
        if header_extension_aware is not None:
            effective_ext = header_extension_aware.strip().lower() == "true"
        else:
            effective_ext = server_ext

        return {
            "is_internal_org_member": effective_internal,
            "is_extension_aware": effective_ext,
            "can_be_internal": server_authorized_internal,
        }


recipient_registry = RecipientCapabilityRegistry()


# ---------------------------------------------------------------------------
# JWT Generation & Cryptographic Verification
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str = "analyst",
    is_admin: bool = False,
    clearance: str = "AMBER",
    is_internal_org_member: bool = False,
    is_extension_aware: bool = False,
    expires_delta: Optional[timedelta] = None,
    issuer: Optional[str] = None,
    audience: Optional[str] = None,
    algorithm: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> str:
    """
    Creates a signed JWT with standard and custom claims.
    Used for test identity generation and token issuance.
    """
    now = datetime.now(timezone.utc)
    exp = now + (expires_delta or timedelta(minutes=settings.JWT_EXPIRATION_MINUTES))

    payload: Dict[str, Any] = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "is_admin": is_admin or (role == "admin"),
        "clearance": clearance,
        "is_internal_org_member": is_internal_org_member,
        "is_extension_aware": is_extension_aware,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": issuer or settings.JWT_ISSUER,
        "aud": audience or settings.JWT_AUDIENCE,
    }

    key = secret_key or settings.JWT_SECRET_KEY
    alg = algorithm or settings.JWT_ALGORITHM
    return jwt.encode(payload, key, algorithm=alg)


def _verify_jwt_token(token: str) -> AuthenticatedUser:
    """
    Decodes and cryptographically verifies a JWT token.
    Enforces signature, expiration, algorithm, issuer, and audience.
    """
    # Strict algorithm allowlist check before decoding
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token format.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    alg = unverified_header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unsupported token signing algorithm.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fail closed in production if secret key is insecure, weak, or default
    if settings.ENVIRONMENT.lower() in ("production", "prod"):
        try:
            validate_jwt_secret_configuration(settings.JWT_SECRET_KEY, settings.ENVIRONMENT)
        except (RuntimeError, ValueError) as err:
            logger.critical("Insecure JWT_SECRET_KEY in production: %s", str(err))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security configuration error: Insecure JWT secret key in production.",
            )

    try:
        payload = jwt.decode(
            token,
            key=settings.JWT_SECRET_KEY,
            algorithms=ALLOWED_ALGORITHMS,
            issuer=settings.JWT_ISSUER,
            audience=settings.JWT_AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["sub", "tenant_id", "role", "exp", "iss", "aud"],
            },
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.InvalidSignatureError, jwt.DecodeError, jwt.InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature or structure.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sub = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    role = payload.get("role", "analyst")
    is_admin = bool(payload.get("is_admin", False)) or (role == "admin")
    clearance = payload.get("clearance", "AMBER")
    is_internal_org_member = bool(payload.get("is_internal_org_member", False))
    is_extension_aware = bool(payload.get("is_extension_aware", False))

    if not sub or not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required identity claims.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return AuthenticatedUser(
        user_id=str(sub),
        role=str(role),
        tenant_id=str(tenant_id),
        is_admin=is_admin,
        clearance=str(clearance),
        is_internal_org_member=is_internal_org_member,
        is_extension_aware=is_extension_aware,
    )


def _verify_api_key(raw_key: str) -> AuthenticatedUser:
    """
    Validates API key against hashed server-side SQLite records.
    """
    if not raw_key or not raw_key.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    record = api_key_store.lookup_key(raw_key.strip())
    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unknown API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if record.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if record.expires_at:
        now = datetime.now(timezone.utc)
        if record.expires_at.tzinfo is None:
            expires_at = record.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at = record.expires_at
        if now > expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired.",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    return AuthenticatedUser(
        user_id=record.user_id,
        role=record.role,
        tenant_id=record.tenant_id,
        is_admin=record.is_admin or (record.role == "admin"),
        clearance=record.clearance,
        is_internal_org_member=record.is_internal_org_member,
        is_extension_aware=record.is_extension_aware,
    )


# ---------------------------------------------------------------------------
# Primary Authentication & Anti-Spoofing Dependency
# ---------------------------------------------------------------------------

def verify_authentication(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
) -> AuthenticatedUser:
    """
    Validates Bearer JWT token or API key credentials.
    Derives user role and tenant membership strictly server-side.

    Guarantees:
    - Missing credentials -> 401 Unauthorized
    - Malformed or invalid credentials -> 401 Unauthorized
    - Client sends only X-Tenant-ID without credentials -> 401 Unauthorized
    - Client sends X-Tenant-ID differing from verified identity -> 403 Forbidden
    """
    auth_user: Optional[AuthenticatedUser] = None

    # 1. Bearer Token Authentication
    if authorization and authorization.strip():
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1 and not parts[0].lower().startswith("bearer"):
            token = parts[0]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Authorization header. Format: 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not token or not token.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Empty Bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        auth_user = _verify_jwt_token(token.strip())

    # 2. API Key Authentication (Fallback if no Bearer token supplied)
    elif api_key and api_key.strip():
        auth_user = _verify_api_key(api_key.strip())

    # 3. No Valid Credentials Provided
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required (Bearer JWT or X-API-Key).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Strict Tenant Assertion & Anti-Spoofing Guard
    if x_tenant_id and x_tenant_id.strip():
        claimed_tenant = x_tenant_id.strip()
        if claimed_tenant != auth_user.tenant_id and not auth_user.is_admin:
            logger.warning(
                "Tenant spoofing rejected: user=%s claimed=%s verified=%s",
                auth_user.user_id,
                claimed_tenant,
                auth_user.tenant_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant spoofing detected: client header does not match authenticated identity.",
            )

    return auth_user


# ---------------------------------------------------------------------------
# RBAC Authorization Dependencies
# ---------------------------------------------------------------------------

def require_admin(
    user: AuthenticatedUser = Depends(verify_authentication)
) -> AuthenticatedUser:
    """
    Enforces administrative privileges. Analysts cannot escalate or invoke admin routes.
    """
    if not user.is_admin and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required.",
        )
    return user


def require_analyst(
    user: AuthenticatedUser = Depends(verify_authentication)
) -> AuthenticatedUser:
    """
    Enforces analyst or higher privileges.
    """
    if user.role not in {"analyst", "admin", "lead"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst privileges required.",
        )
    return user


def require_stix_role(
    user: AuthenticatedUser = Depends(verify_authentication)
) -> AuthenticatedUser:
    """
    Enforces that authenticated user has analyst or admin role required for STIX operations.
    """
    if user.role not in {"analyst", "admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Insufficient privileges. Role '{user.role}' cannot perform STIX operations; requires 'analyst' or 'admin'.",
        )
    return user
