"""
Temporal Event and Allen Interval Algebra Models
Phase 12C Attack Timeline Reconstruction Implementation

Defines temporal event abstractions distinguishing occurrence, observation,
publication, and ingestion timestamps, along with Allen's 13 interval relations
and multi-source conflict structures.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class AllenRelation(str, Enum):
    """
    James Allen's 13 qualitative interval relations (1983).
    """
    BEFORE = "before"
    AFTER = "after"
    MEETS = "meets"
    MET_BY = "met_by"
    OVERLAPS = "overlaps"
    OVERLAPPED_BY = "overlapped_by"
    STARTS = "starts"
    STARTED_BY = "started_by"
    DURING = "during"
    CONTAINS = "contains"
    FINISHES = "finishes"
    FINISHED_BY = "finished_by"
    EQUALS = "equals"


class TimelineEvent(BaseModel):
    """
    Temporal event with distinct lifecycle timestamps, preserving multi-source
    provenance and observation latency.
    """
    id: str
    title: str
    description: Optional[str] = None
    source_id: str
    source_name: str
    track_id: str = "track-default"
    entity_ids: List[str] = Field(default_factory=list)
    technique_id: Optional[str] = None
    occurrence_start: str  # Authoritative ISO 8601 UTC
    occurrence_end: Optional[str] = None  # Authoritative ISO 8601 UTC
    observation_time: Optional[str] = None
    publication_time: Optional[str] = None
    ingestion_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    is_inferred: bool = False
    uncertainty_seconds: int = 0


class TimelineConflict(BaseModel):
    """
    Represents a detected temporal contradiction or multi-source timestamp disparity.
    Parallel tracks are maintained without silent deletion or averaging.
    """
    conflict_id: str
    conflict_type: Literal[
        "TEMPORAL_ORDER_INVERSION",
        "TIMESTAMP_DISPARITY",
        "CAUSALITY_VIOLATION",
    ]
    event_a_id: str
    event_b_id: str
    source_a: str
    source_b: str
    timestamp_a: str
    timestamp_b: str
    relation_a_to_b: str
    disparity_delta_seconds: Optional[float] = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    explanation: str


class TimelineTrack(BaseModel):
    """
    Parallel timeline track representing events reported by a specific intelligence source.
    """
    track_id: str
    source_name: str
    events: List[TimelineEvent] = Field(default_factory=list)


class TimelineReconstructionResponse(BaseModel):
    tracks: List[TimelineTrack]
    total_events: int
    conflicts: List[TimelineConflict]
    has_disputes: bool
