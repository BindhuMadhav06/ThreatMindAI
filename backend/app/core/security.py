"""
Core Authentication and Tenant Authorization Boundary for ThreatMind AI.

Enforces cryptographic Bearer token (JWT) verification, hashed server-side API-key
authentication, server-side tenant identity derivation, role-based access control (RBAC),
and strict prevention of client-side tenant or approver spoofing.

Conforms to standards:
- RFC 7519 (JSON Web Token)
- RFC 6750 (OAuth 2.0 Bearer Token Usage)
- Zero Trust Architecture (NIST SP 800-207)
"""

import hashlib
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

import jwt
from fastapi import Header, HTTPException, status, Depends
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import logger


VALID_ROLES: Set[str] = {"analyst", "admin", "lead", "viewer"}
ALLOWED_ALGORITHMS: List[str] = ["HS256"]


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
    scopes: List[str] = Field(default_factory=lambda: ["read", "write"])


# ---------------------------------------------------------------------------
# Server-side In-Memory Hashed API Key Store (Thread-safe)
# ---------------------------------------------------------------------------

class ApiKeyRecord(BaseModel):
    key_hash: str
    user_id: str
    tenant_id: str
    role: str
    is_admin: bool = False
    clearance: str = "AMBER"
    revoked: bool = False
    expires_at: Optional[datetime] = None


class ApiKeyStore:
    """Thread-safe store for cryptographically hashed API keys."""
    def __init__(self) -> None:
        self._keys: Dict[str, ApiKeyRecord] = {}
        self._lock = threading.Lock()

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def register_key(
        self,
        raw_key: str,
        user_id: str,
        tenant_id: str,
        role: str = "analyst",
        is_admin: bool = False,
        clearance: str = "AMBER",
        expires_at: Optional[datetime] = None,
    ) -> str:
        kh = self.hash_key(raw_key)
        record = ApiKeyRecord(
            key_hash=kh,
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            is_admin=is_admin,
            clearance=clearance,
            revoked=False,
            expires_at=expires_at,
        )
        with self._lock:
            self._keys[kh] = record
        return kh

    def revoke_key(self, raw_key: str) -> bool:
        kh = self.hash_key(raw_key)
        with self._lock:
            if kh in self._keys:
                self._keys[kh].revoked = True
                return True
        return False

    def lookup_key(self, raw_key: str) -> Optional[ApiKeyRecord]:
        kh = self.hash_key(raw_key)
        with self._lock:
            return self._keys.get(kh)


api_key_store = ApiKeyStore()


# ---------------------------------------------------------------------------
# JWT Generation & Cryptographic Verification
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: str,
    tenant_id: str,
    role: str = "analyst",
    is_admin: bool = False,
    clearance: str = "AMBER",
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

    # Fail closed in production if secret key is weak or missing
    if settings.ENVIRONMENT == "production":
        if not settings.JWT_SECRET_KEY or len(settings.JWT_SECRET_KEY) < 32:
            logger.critical("Production environment requires strong JWT_SECRET_KEY (min 32 bytes).")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security configuration error.",
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
    )


def _verify_api_key(raw_key: str) -> AuthenticatedUser:
    """
    Validates API key against hashed server-side records.
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
        if claimed_tenant != auth_user.tenant_id:
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
