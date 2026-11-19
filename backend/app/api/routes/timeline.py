"""
Attack Timeline Reconstruction API Routes
Phase 12C Implementation

Exposes REST endpoints for:
- Reconstructing multi-source chronological attack timelines
- Querying Allen's Interval Algebra contradictions and timestamp disparities
- Preserving parallel intelligence tracks with visual dispute indicators
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.models.timeline import (
    TimelineConflict,
    TimelineEvent,
    TimelineReconstructionResponse,
)
from app.services.timeline.timeline_service import TimelineService
from app.api.routes.stix import stix_service

router = APIRouter(prefix="/timeline", tags=["Attack Timeline Reconstruction"])

# Singleton timeline service instance
timeline_service = TimelineService(
    graph_service=stix_service.graph_service,
    ingestion_service=stix_service,
)


@router.get("/events", response_model=TimelineReconstructionResponse, status_code=status.HTTP_200_OK)
def get_timeline_events(
    investigation_id: Optional[str] = Query(default=None, description="Scope by investigation anchor"),
    actor_id: Optional[str] = Query(default=None, description="Scope by threat actor ID"),
    technique_id: Optional[str] = Query(default=None, description="Scope by ATT&CK technique ID"),
) -> TimelineReconstructionResponse:
    """
    Reconstructs attack timeline grouped into parallel multi-source tracks.
    Identifies contradictions and timestamp disparities without lossy averaging.
    """
    return timeline_service.reconstruct_timeline(
        investigation_id=investigation_id,
        actor_id=actor_id,
        technique_id=technique_id,
    )


@router.get("/conflicts", response_model=List[TimelineConflict], status_code=status.HTTP_200_OK)
def get_timeline_conflicts(
    investigation_id: Optional[str] = Query(default=None),
) -> List[TimelineConflict]:
    """
    Fetches all temporal contradictions and multi-source timestamp disparities.
    """
    timeline = timeline_service.reconstruct_timeline(investigation_id=investigation_id)
    return timeline.conflicts


@router.post("/events", response_model=TimelineEvent, status_code=status.HTTP_201_CREATED)
def record_timeline_event(event: TimelineEvent) -> TimelineEvent:
    """
    Injects a temporal event into the active timeline reconstruction engine.
    """
    return timeline_service.record_event(event)
