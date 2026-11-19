"""
Multi-Source Attack Timeline Reconstruction Service
Phase 12C Implementation

Orchestrates multi-source timeline reconstruction, parallel track assembly,
and contradiction detection using Allen's Interval Algebra.
Preserves conflicting intelligence on parallel tracks without lossy averaging.
"""

from typing import Dict, List, Optional
from app.models.timeline import (
    TimelineConflict,
    TimelineEvent,
    TimelineReconstructionResponse,
    TimelineTrack,
)
from app.services.timeline.allen_algebra import AllenIntervalAlgebra
from app.services.stix.stix_graph_service import StixGraphService
from app.services.stix.stix_ingestion_service import StixIngestionService


class TimelineService:
    """
    Assembles chronological attack event timelines across multiple intelligence sources.
    """

    def __init__(
        self,
        graph_service: Optional[StixGraphService] = None,
        ingestion_service: Optional[StixIngestionService] = None,
    ):
        self.graph_service = graph_service or StixGraphService()
        self.ingestion_service = ingestion_service
        self._manual_events: List[TimelineEvent] = []

    def record_event(self, event: TimelineEvent) -> TimelineEvent:
        """
        Registers an explicit timeline event into the in-memory timeline store.
        """
        self._manual_events.append(event)
        return event

    def reconstruct_timeline(
        self,
        investigation_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        technique_id: Optional[str] = None,
    ) -> TimelineReconstructionResponse:
        """
        Reconstructs multi-source timeline tracks and executes contradiction detection.
        """
        all_events: List[TimelineEvent] = list(self._manual_events)

        # 1. Harvest timestamped entities from in-memory ingestion mapper if available
        if self.ingestion_service and hasattr(self.ingestion_service, "mapper"):
            entities = self.ingestion_service.mapper.entities_by_stix_id
            for eid, edata in entities.items():
                props = edata.get("properties", {})
                created_ts = props.get("created")
                if not created_ts:
                    continue

                # Filter by actor_id or technique_id if requested
                if actor_id and props.get("id") != actor_id and props.get("stix_id") != actor_id:
                    continue
                if technique_id and props.get("technique_id") != technique_id and technique_id not in str(props.get("name")):
                    continue

                source_name = props.get("source") or props.get("created_by_ref") or "ThreatMind Intelligence"
                ev = TimelineEvent(
                    id=f"ev-{eid}",
                    title=props.get("name") or eid,
                    description=props.get("description"),
                    source_id=str(props.get("created_by_ref") or "source-internal"),
                    source_name=source_name,
                    track_id=f"track-{source_name.lower().replace(' ', '-')}",
                    entity_ids=[eid],
                    technique_id=props.get("technique_id"),
                    occurrence_start=created_ts,
                    occurrence_end=props.get("modified"),
                    confidence=float(props.get("confidence", 90)) / 100.0,
                )
                all_events.append(ev)

        # 2. Group into parallel tracks by source
        tracks_by_id: Dict[str, TimelineTrack] = {}
        for ev in all_events:
            tid = ev.track_id or "track-default"
            if tid not in tracks_by_id:
                tracks_by_id[tid] = TimelineTrack(
                    track_id=tid,
                    source_name=ev.source_name,
                    events=[],
                )
            tracks_by_id[tid].events.append(ev)

        # Sort events inside each track chronologically
        tracks = list(tracks_by_id.values())
        for track in tracks:
            track.events.sort(key=lambda x: x.occurrence_start)

        # 3. Detect temporal conflicts and multi-source timestamp disparities
        conflicts = AllenIntervalAlgebra.detect_conflicts(all_events)

        return TimelineReconstructionResponse(
            tracks=tracks,
            total_events=len(all_events),
            conflicts=conflicts,
            has_disputes=len(conflicts) > 0,
        )
