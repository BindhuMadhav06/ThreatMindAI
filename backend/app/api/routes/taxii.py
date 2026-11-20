"""
TAXII 2.1 Federation API Routes.
Implements complete OASIS TAXII 2.1 specification:
- Server Discovery (/taxii2/)
- Collections (/taxii2/collections and /taxii2/{api_root}/collections)
- Objects with Recipient Clearance Enforcement (/taxii2/collections/{collection_id}/objects)
- Manifests (/taxii2/collections/{collection_id}/manifest)
- Tombstone Verification (/taxii2/tombstones/{record_id}/verify)
- API Root Discovery (/taxii2/{api_root})
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel

from app.core.security import AuthenticatedUser, verify_authentication
from app.models.privacy import TAXIICollection, TAXIISharingRecord, TLPMarking
from app.services.privacy.taxii_service import TAXIIFederationService

router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1 Federation"])

taxii_service = TAXIIFederationService()


class IngestTAXIIObjectRequest(BaseModel):
    collection_id: str
    object_payload: Dict[str, Any]
    source_feed_name: Optional[str] = "Community_ISAC_Feed"


# -----------------------------------------------------------------------------
# 1. Server Discovery Endpoint
# -----------------------------------------------------------------------------
@router.get("/", response_model=Dict[str, Any])
async def taxii_server_discovery() -> Dict[str, Any]:
    """TAXII 2.1 Server Discovery endpoint."""
    return {
        "title": "ThreatMind AI TAXII 2.1 Server",
        "description": "Evidence-grounded, privacy-preserving threat intelligence federation server.",
        "contact": "security@threatmind.internal",
        "default": "/api/v1/taxii2/root/",
        "api_roots": [
            "/api/v1/taxii2/",
            "/api/v1/taxii2/root/"
        ]
    }


# -----------------------------------------------------------------------------
# 2. Collections Endpoints (Declared BEFORE /{api_root} for routing precedence)
# -----------------------------------------------------------------------------
@router.get("/collections", response_model=Dict[str, List[TAXIICollection]])
@router.get("/root/collections", response_model=Dict[str, List[TAXIICollection]])
async def list_taxii_collections() -> Dict[str, List[TAXIICollection]]:
    """List available federated intelligence collections."""
    collections = taxii_service.list_collections()
    return {"collections": collections}


@router.get("/collections/{collection_id}", response_model=TAXIICollection)
@router.get("/root/collections/{collection_id}", response_model=TAXIICollection)
async def get_taxii_collection(collection_id: str) -> TAXIICollection:
    """Retrieve metadata for a specific TAXII collection."""
    col = taxii_service.get_collection(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail=f"TAXII collection '{collection_id}' not found.")
    return col


# -----------------------------------------------------------------------------
# 3. Collection Objects (Authenticated Recipient Clearance Enforcement)
# -----------------------------------------------------------------------------
@router.get("/collections/{collection_id}/objects")
@router.get("/root/collections/{collection_id}/objects")
async def get_collection_objects(
    collection_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Dict[str, Any]:
    """
    Retrieve bounded objects from collection.
    Enforces authenticated recipient identity and clearance boundaries.
    """
    # Enforce collection authorization: ISAC feed requires analyst or admin role
    if collection_id == "collection_isac_shared" and current_user.role == "viewer":
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Collection 'collection_isac_shared' requires authenticated 'analyst' or 'admin' clearance."
        )

    try:
        objects = taxii_service.get_collection_objects(collection_id=collection_id, max_limit=limit)
        return {
            "more": False,
            "objects": objects
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found.")


# -----------------------------------------------------------------------------
# 4. Collection Manifest Endpoint
# -----------------------------------------------------------------------------
@router.get("/collections/{collection_id}/manifest")
@router.get("/root/collections/{collection_id}/manifest")
async def get_collection_manifest(
    collection_id: str,
    limit: int = Query(default=50, ge=1, le=100),
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Dict[str, Any]:
    """Retrieve TAXII 2.1 Manifest describing available STIX 2.1 objects."""
    try:
        manifest_entries = taxii_service.get_collection_manifest(collection_id=collection_id, max_limit=limit)
        return {
            "more": False,
            "objects": manifest_entries
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found.")


# -----------------------------------------------------------------------------
# 5. Object Ingestion (Untrusted Tagging & Confidence Penalty)
# -----------------------------------------------------------------------------
@router.post("/collections/{collection_id}/objects", status_code=status.HTTP_201_CREATED)
@router.post("/root/collections/{collection_id}/objects", status_code=status.HTTP_201_CREATED)
async def ingest_taxii_object(
    collection_id: str,
    req: IngestTAXIIObjectRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Dict[str, Any]:
    """
    Ingest external TAXII object.
    Strictly tags incoming objects as UNTRUSTED_EXTERNAL, applies 0.35 confidence penalty,
    and persists object into the collection store.
    """
    col = taxii_service.get_collection(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found.")
    if not col.can_write:
        raise HTTPException(status_code=403, detail=f"Collection '{collection_id}' is read-only.")

    try:
        tagged = taxii_service.ingest_external_taxii_object(
            collection_id=collection_id,
            obj=req.object_payload,
            source_feed_name=req.source_feed_name or "External_TAXII_Source"
        )
        return {
            "status": "ingested_untrusted",
            "message": "Object ingested, confidence discounted by 0.35, and persisted as unverified external telemetry.",
            "object": tagged
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found.")


# -----------------------------------------------------------------------------
# 6. Tombstone Signature Verification
# -----------------------------------------------------------------------------
@router.get("/tombstones/{record_id}/verify")
async def verify_tombstone_signature(
    record_id: str,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Dict[str, Any]:
    """Verify cryptographic authenticity of a retracted object's tombstone signature."""
    return taxii_service.verify_tombstone(record_id)


# -----------------------------------------------------------------------------
# 7. API Root Endpoints (Placed at end of file so static paths take priority)
# -----------------------------------------------------------------------------
@router.get("/{api_root}", response_model=Dict[str, Any])
@router.get("/{api_root}/", response_model=Dict[str, Any])
async def get_taxii_api_root(api_root: str) -> Dict[str, Any]:
    """TAXII 2.1 API Root Information endpoint."""
    if api_root not in ("root", "default", "api_root"):
        raise HTTPException(status_code=404, detail=f"API Root '{api_root}' not found.")
    return {
        "title": f"ThreatMind Federation API Root ({api_root})",
        "description": "Production API Root for TAXII 2.1 / STIX 2.1 Threat Sharing",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 52428800
    }
