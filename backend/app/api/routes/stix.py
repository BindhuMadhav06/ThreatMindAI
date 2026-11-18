"""
STIX 2.1 Interoperability API Routes
Implements transactional import and dry-run preview per OASIS STIX 2.1 Errata 01.
"""

from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Query, status

from app.services.stix.stix_ingestion_service import StixIngestionService

router = APIRouter(prefix="/stix")

# Shared singleton service instance for in-memory session mapping
stix_service = StixIngestionService()


@router.post("/import", status_code=status.HTTP_200_OK)
async def import_stix_bundle(
    bundle: Dict[str, Any],
    dry_run: bool = Query(default=False, description="Preview import without mutating database or cache state"),
) -> Dict[str, Any]:
    """
    Ingest or preview a STIX 2.1 Bundle into ThreatMind AI.
    Executes two-pass validation, 4-way relationship tuple classification,
    and returns comprehensive audit and rejection ledgers.
    """
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

    try:
        result = stix_service.ingest_bundle(bundle, dry_run=dry_run)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"STIX ingestion failed with unhandled exception: {str(e)}",
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
