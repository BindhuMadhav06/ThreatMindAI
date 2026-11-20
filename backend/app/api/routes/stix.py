"""
STIX 2.1 Interoperability API Routes
Implements transactional import and dry-run preview per OASIS STIX 2.1 Errata 01.
Enforces 50MB payload limits, centralized Bearer token / API-key role authorization,
passive URL parsing (SSRF protection), and sanitized error responses.
"""

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app.core.logging import logger
from app.core.security import AuthenticatedUser, recipient_registry, require_stix_role
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


class StixUserContext(BaseModel):
    """
    Authenticated user context for STIX operations, establishing a formal
    trust boundary for tenant isolation and recipient capability enforcement.
    """
    user_id: str = Field(default="user-analyst")
    user_role: str = Field(default="analyst")
    tenant_id: Optional[str] = Field(default=None)
    is_internal_org_member: bool = Field(default=False)
    is_extension_aware: bool = Field(default=False)
    clearance: str = Field(default="AMBER")
    can_be_internal: bool = Field(default=False)


def get_stix_user_context(
    current_user: AuthenticatedUser = Depends(require_stix_role),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_recipient_extension_aware: Optional[str] = Header(None, alias="X-Recipient-Extension-Aware"),
    x_recipient_org_internal: Optional[str] = Header(None, alias="X-Recipient-Org-Internal"),
) -> StixUserContext:
    """
    Derives trusted user context strictly from server-validated credentials.
    Enforces header entitlement clamping: client headers requesting internal org status
    are denied/clamped to False if the server registry or signed credentials indicate external identity.
    """
    # Cross-tenant anti-spoofing guard
    if x_tenant_id and x_tenant_id.strip():
        claimed_tenant = x_tenant_id.strip()
        if claimed_tenant != current_user.tenant_id and not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant spoofing detected: client header does not match authenticated identity.",
            )

    caps = recipient_registry.resolve_capabilities(
        user=current_user,
        header_extension_aware=x_recipient_extension_aware,
        header_org_internal=x_recipient_org_internal,
    )

    clearance = "RED" if (current_user.is_admin or current_user.role == "admin" or current_user.clearance == "RED") else current_user.clearance

    return StixUserContext(
        user_id=current_user.user_id,
        user_role=current_user.role,
        tenant_id=current_user.tenant_id,
        is_internal_org_member=caps["is_internal_org_member"],
        is_extension_aware=caps["is_extension_aware"],
        clearance=clearance,
        can_be_internal=caps["can_be_internal"],
    )


@router.post("/import", status_code=status.HTTP_200_OK)
async def import_stix_bundle(
    request: Request,
    dry_run: bool = Query(default=False, description="Preview import without mutating database or cache state"),
    current_user: AuthenticatedUser = Depends(require_stix_role),
) -> Dict[str, Any]:
    """
    Ingest or preview a STIX 2.1 Bundle into ThreatMind AI.
    Executes two-pass validation, 4-way relationship tuple classification,
    and returns comprehensive audit and rejection ledgers.

    Guarantees:
    - Enforces 50MB maximum body payload limit (HTTP 413)
    - Enforces cryptographic Bearer token / API-key authorization with analyst/admin role (HTTP 401/403)
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
    user_context: StixUserContext = Depends(get_stix_user_context),
) -> Dict[str, Any]:
    """
    Exports a standards-compliant OASIS STIX 2.1 Bundle containing a bounded subgraph.
    Enforces AC-7B (Export TLP Authorization & Recipient Capability Gating),
    AC-13 (Bounded Export Scope & Round-Trip Validation),
    and Part A Security Hardening (Tenant Isolation, Fail-Closed Behavior, Transitive Scrubbing).

    Guarantees:
    - Mandatory scoping: requires at least one of investigation_id, actor_id, technique_id, or entity_ids (HTTP 400).
    - Traversal limits: max_depth <= 3, max_nodes <= 500.
    - Synchronous payload ceiling: max 25MB (HTTP 413).
    - Absolute TLP:RED suppression: zero generic admin bypass; drops all incident edges to RED nodes; scrubs references.
    - Recipient capability gating: extension-unaware or external recipients requesting AMBER+STRICT are denied (HTTP 403).
    - Interoperability mapping: FIRST TLP:CLEAR maps to STIX 2.1 TLP:WHITE carrying the FIRST extension.
    - Container invariant: bundle root has NO spec_version property.
    - Cross-tenant isolation: bounded extraction strictly filters by tenant boundary.
    - Production fail-closed: returns HTTP 503 if Neo4j is offline in production mode.
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

    # 3. Derive Capabilities from Authenticated User Context (Protected from Header Spoofing)
    is_extension_aware = user_context.is_extension_aware
    is_internal_org_member = user_context.is_internal_org_member
    tenant_id = user_context.tenant_id

    # 4. Execute Export Pipeline
    try:
        bundle = stix_export_service.export_subgraph(
            seed_ids=seed_ids,
            max_depth=max_depth,
            max_nodes=max_nodes,
            is_extension_aware=is_extension_aware,
            is_internal_org_member=is_internal_org_member,
            tenant_id=tenant_id,
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
