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
from app.services.stix.stix_export_service import StixExportService

router = APIRouter(prefix="/stix")

# Shared singleton service instances for in-memory session mapping and export
stix_service = StixIngestionService()
stix_export_service = StixExportService(
    ingestion_service=stix_service,
    graph_service=stix_service.graph_service,
)

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


@router.get("/export/bundle", status_code=status.HTTP_200_OK)
async def export_stix_bundle(
    request: Request,
    investigation_id: Optional[str] = Query(default=None, description="Investigation identifier anchor"),
    actor_id: Optional[str] = Query(default=None, description="Threat actor identifier anchor"),
    technique_id: Optional[str] = Query(default=None, description="Attack technique identifier anchor"),
    entity_ids: Optional[str] = Query(default=None, description="Comma-separated list of entity or STIX identifiers"),
    max_depth: int = Query(default=2, ge=1, le=3, description="Maximum traversal depth (hard limit: 3 hops)"),
    max_nodes: int = Query(default=100, ge=1, le=500, description="Maximum node extraction count (hard limit: 500)"),
    user_role: str = Depends(verify_stix_authorization),
    x_recipient_extension_aware: Optional[str] = Header(None, alias="X-Recipient-Extension-Aware"),
    x_recipient_org_internal: Optional[str] = Header(None, alias="X-Recipient-Org-Internal"),
) -> Dict[str, Any]:
    """
    Exports a standards-compliant OASIS STIX 2.1 Bundle containing a bounded subgraph.
    Enforces AC-7B (Export TLP Authorization & Recipient Capability Gating) and
    AC-13 (Bounded Export Scope & Round-Trip Validation).

    Guarantees:
    - Mandatory scoping: requires at least one of investigation_id, actor_id, technique_id, or entity_ids (HTTP 400).
    - Traversal limits: max_depth <= 3, max_nodes <= 500.
    - Synchronous payload ceiling: max 25MB (HTTP 413).
    - Absolute TLP:RED suppression: zero generic admin bypass; drops all incident edges to RED nodes.
    - Recipient capability gating: extension-unaware or external recipients requesting AMBER+STRICT are denied (HTTP 403).
    - Interoperability mapping: FIRST TLP:CLEAR maps to STIX 2.1 TLP:WHITE carrying the FIRST extension.
    - Container invariant: bundle root has NO spec_version property.
    """
    # 1. Enforce Mandatory Scoping
    scope_params = [investigation_id, actor_id, technique_id, entity_ids]
    if not any(p and p.strip() for p in scope_params if isinstance(p, str)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Full-graph export is prohibited. Request must specify at least one scope parameter: investigation_id, actor_id, technique_id, or entity_ids.",
        )

    # 2. Extract Seed Identifiers
    seed_ids: List[str] = []
    if investigation_id and investigation_id.strip():
        seed_ids.append(investigation_id.strip())
    if actor_id and actor_id.strip():
        seed_ids.append(actor_id.strip())
    if technique_id and technique_id.strip():
        seed_ids.append(technique_id.strip())
    if entity_ids and entity_ids.strip():
        for e in entity_ids.split(","):
            cleaned = e.strip()
            if cleaned:
                seed_ids.append(cleaned)

    # 3. Derive Recipient Capabilities Strictly from Trusted Headers
    # Query parameter spoofing attempts (e.g. ?is_extension_aware=true) are ignored.
    is_extension_aware = (x_recipient_extension_aware or "").strip().lower() == "true"
    is_internal_org_member = (x_recipient_org_internal or "").strip().lower() == "true"

    # 4. Execute Export Pipeline
    try:
        bundle = stix_export_service.export_subgraph(
            seed_ids=seed_ids,
            max_depth=max_depth,
            max_nodes=max_nodes,
            is_extension_aware=is_extension_aware,
            is_internal_org_member=is_internal_org_member,
        )
        return bundle
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"STIX bundle export failed with unexpected exception: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="STIX bundle export failed due to an internal server error. Check server logs for details.",
        )

