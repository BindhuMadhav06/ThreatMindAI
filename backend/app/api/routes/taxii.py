"""
TAXII 2.1 Federation API Routes.
Implements standard server discovery, collections browsing,
bounded object retrieval, and untrusted external ingestion tagging.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, Response, status
from pydantic import BaseModel

from app.models.privacy import TAXIICollection, TAXIISharingRecord, TLPMarking
from app.api.routes.privacy import taxii_service, get_verified_tenant

router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1 Federation"])


class IngestTAXIIObjectRequest(BaseModel):
    collection_id: str
    object_payload: Dict[str, Any]
    source_feed_name: Optional[str] = "Community_ISAC_Feed"


@router.get("/", response_model=Dict[str, Any])
async def taxii_server_discovery() -> Dict[str, Any]:
    """TAXII 2.1 Server Discovery endpoint."""
    return {
        "title": "ThreatMind AI TAXII 2.1 Server",
        "description": "Evidence-grounded, privacy-preserving threat intelligence federation server.",
        "contact": "security@threatmind.internal",
        "default": "/api/v1/taxii2/",
        "api_roots": ["/api/v1/taxii2/"]
    }


@router.get("/collections", response_model=Dict[str, List[TAXIICollection]])
async def list_taxii_collections() -> Dict[str, List[TAXIICollection]]:
    """List available federated intelligence collections."""
    collections = taxii_service.list_collections()
    return {"collections": collections}


@router.get("/collections/{collection_id}", response_model=TAXIICollection)
async def get_taxii_collection(collection_id: str) -> TAXIICollection:
    """Retrieve metadata for a specific TAXII collection."""
    col = taxii_service.get_collection(collection_id)
    if not col:
        raise HTTPException(status_code=404, detail=f"TAXII collection '{collection_id}' not found.")
    return col


@router.get("/collections/{collection_id}/objects")
async def get_collection_objects(
    collection_id: str,
    limit: int = Query(default=20, ge=1, le=100)
) -> Dict[str, Any]:
    """Retrieve bounded objects from collection with TAXII 2.1 media type negotiation."""
    try:
        objects = taxii_service.get_collection_objects(collection_id=collection_id, max_limit=limit)
        return {
            "more": False,
            "objects": objects
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found.")


@router.post("/collections/{collection_id}/objects", status_code=status.HTTP_201_CREATED)
async def ingest_taxii_object(
    collection_id: str,
    req: IngestTAXIIObjectRequest
) -> Dict[str, Any]:
    """
    Ingest external TAXII object.
    Strictly tags incoming objects as UNTRUSTED_EXTERNAL to prevent unauthorized claim injection.
    """
    try:
        tagged = taxii_service.ingest_external_taxii_object(
            collection_id=collection_id,
            obj=req.object_payload,
            source_feed_name=req.source_feed_name or "External_TAXII_Source"
        )
        return {
            "status": "ingested_untrusted",
            "message": "Object ingested and tagged as unverified external telemetry.",
            "object": tagged
        }
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Collection '{collection_id}' not found.")
