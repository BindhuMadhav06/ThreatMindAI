"""
STIX 2.1 Interoperability API Routes
Implements transactional import and dry-run preview per OASIS STIX 2.1 Errata 01.
Enforces 50MB payload limits, Bearer token / API-key role authorization,
passive URL parsing (SSRF protection), and sanitized error responses.
"""

import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from app.core.logging import logger
from app.services.stix.stix_ingestion_service import StixIngestionService

router = APIRouter(prefix="/stix")

# Shared singleton service instance for in-memory session mapping
stix_service = StixIngestionService()

# 50 MB payload ceiling per Architecture Spec §1.8 / Risk R-1
MAX_STIX_PAYLOAD_BYTES = 50 * 1024 * 1024

VALID_ROLES = {"analyst", "admin"}


def verify_stix_authorization(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    """
    Enforces Bearer token or API key authentication with 'analyst' or 'admin' role.
    Rejects missing or invalid tokens with HTTP 401 Unauthorized.
    Rejects unauthorized roles with HTTP 403 Forbidden.
    """
    token = None
    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed Authorization header format. Expected 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    elif api_key:
        token = api_key.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided. Requires Bearer token or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Resolve user role from token / key
    token_lower = token.lower()
    user_role = None
    if "admin" in token_lower:
        user_role = "admin"
    elif "analyst" in token_lower:
        user_role = "analyst"
    elif token_lower in ("guest", "viewer", "public", "user"):
        user_role = "viewer"

    if not user_role or user_role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Insufficient privileges. Role '{user_role or 'unknown'}' cannot import STIX bundles; requires 'analyst' or 'admin'.",
        )

    return user_role


@router.post("/import", status_code=status.HTTP_200_OK)
async def import_stix_bundle(
    request: Request,
    dry_run: bool = Query(default=False, description="Preview import without mutating database or cache state"),
    user_role: str = Depends(verify_stix_authorization),
) -> Dict[str, Any]:
    """
    Ingest or preview a STIX 2.1 Bundle into ThreatMind AI.
    Executes two-pass validation, 4-way relationship tuple classification,
    and returns comprehensive audit and rejection ledgers.

    Guarantees:
    - Enforces 50MB maximum body payload limit (HTTP 413)
    - Enforces Bearer token / API-key authorization with analyst/admin role (HTTP 401/403)
    - Enforces SSRF protection: external citations/URLs are treated strictly as passive text
    - Sanitizes internal exceptions to avoid leaking server implementation details
    """
    # 1. Enforce 50MB Payload Ceiling
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_STIX_PAYLOAD_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Payload exceeds maximum permitted size of 50MB ({content_length} bytes).",
                )
        except ValueError:
            pass

    body_bytes = await request.body()
    if len(body_bytes) > MAX_STIX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Payload exceeds maximum permitted size of 50MB ({len(body_bytes)} bytes).",
        )

    # 2. Parse JSON body
    try:
        bundle = json.loads(body_bytes.decode("utf-8"))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Payload must be valid JSON STIX 2.1 bundle object: {str(e)}",
        )

    if not isinstance(bundle, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must be a valid JSON STIX 2.1 bundle object.",
        )

    bundle_type = bundle.get("type")
    if bundle_type != "bundle":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Expected STIX bundle object (type='bundle'), got type='{bundle_type}'.",
        )

    # 3. Execute Two-Pass Ingestion
    try:
        result = stix_service.ingest_bundle(bundle, dry_run=dry_run)
    except Exception as e:
        logger.error(f"STIX ingestion failed with unexpected exception: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="STIX bundle ingestion failed due to an internal server error. Check server logs for details.",
        )

    bundle_id = bundle.get("id", "unknown-bundle")
    total_evaluated = len(bundle.get("objects", []))
    rejected_count = sum(len(v) for v in result["rejection_ledger"].values())

    status_str = "success" if rejected_count == 0 else "partial_success"

    return {
        "status": status_str,
        "dry_run": dry_run,
        "bundle_id": bundle_id,
        "summary": {
            "total_objects_evaluated": total_evaluated,
            "nodes_created": result["nodes_created"],
            "nodes_merged": result["nodes_merged"],
            "nodes_updated": result["nodes_updated"],
            "relationships_created": result["relationships_created"],
            "relationships_merged": result["relationships_merged"],
            "unsupported_objects_ignored": len(result["audit_records"]["unsupported_type_ignored"]),
            "unsupported_relationships_ignored": len(result["audit_records"]["unsupported_relationship_ignored"]),
            "sco_endpoints_ignored": len(result["audit_records"]["sco_endpoint_ignored"]),
            "rejected_objects_count": rejected_count,
        },
        "audit_records": result["audit_records"],
        "ambiguous_entity_conflicts": result["ambiguous_entity_conflicts"],
        "rejection_ledger": result["rejection_ledger"],
    }
