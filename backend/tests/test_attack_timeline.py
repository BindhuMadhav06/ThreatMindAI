"""
Unit and Integration Tests for Attack Timeline Reconstruction
Phase 12C Implementation Verification Suite

Validates:
- Requirement C1: Allen's Interval Algebra 13 qualitative relations
- Requirement C2: Multi-source temporal conflict & timestamp disparity detection
- Requirement C3: Parallel track preservation without lossy averaging or silent deletion
- Requirement C4: REST API endpoints for attack timeline reconstruction
"""

from fastapi.testclient import TestClient

from app.main import app
from app.models.timeline import AllenRelation, TimelineEvent
from app.services.timeline.allen_algebra import AllenIntervalAlgebra
from app.services.timeline.timeline_service import TimelineService

client = TestClient(app)


# ---------------------------------------------------------------------------
# REQUIREMENT C1: ALLEN INTERVAL ALGEBRA (13 RELATIONS)
# ---------------------------------------------------------------------------

def test_c1_allen_interval_algebra_13_relations():
    """
    Validates James Allen's 13 qualitative temporal interval relations.
    """
    def make_event(start: str, end: str) -> TimelineEvent:
        return TimelineEvent(
            id="ev-test",
            title="Test Event",
            source_id="src-1",
            source_name="Test Source",
            occurrence_start=start,
            occurrence_end=end,
        )

    # 1. Before: [10:00, 10:30] before [11:00, 11:30]
    e_a = make_event("2026-02-15T10:00:00Z", "2026-02-15T10:30:00Z")
    e_b = make_event("2026-02-15T11:00:00Z", "2026-02-15T11:30:00Z")
    assert AllenIntervalAlgebra.determine_relation(e_a, e_b) == AllenRelation.BEFORE
    assert AllenIntervalAlgebra.determine_relation(e_b, e_a) == AllenRelation.AFTER

    # 2. Meets: [10:00, 10:30] meets [10:30, 11:00]
    e_m1 = make_event("2026-02-15T10:00:00Z", "2026-02-15T10:30:00Z")
    e_m2 = make_event("2026-02-15T10:30:00Z", "2026-02-15T11:00:00Z")
    assert AllenIntervalAlgebra.determine_relation(e_m1, e_m2) == AllenRelation.MEETS
    assert AllenIntervalAlgebra.determine_relation(e_m2, e_m1) == AllenRelation.MET_BY

    # 3. Overlaps: [10:00, 10:45] overlaps [10:30, 11:15]
    e_o1 = make_event("2026-02-15T10:00:00Z", "2026-02-15T10:45:00Z")
    e_o2 = make_event("2026-02-15T10:30:00Z", "2026-02-15T11:15:00Z")
    assert AllenIntervalAlgebra.determine_relation(e_o1, e_o2) == AllenRelation.OVERLAPS
    assert AllenIntervalAlgebra.determine_relation(e_o2, e_o1) == AllenRelation.OVERLAPPED_BY

    # 4. Starts: [10:00, 10:30] starts [10:00, 11:00]
    e_s1 = make_event("2026-02-15T10:00:00Z", "2026-02-15T10:30:00Z")
    e_s2 = make_event("2026-02-15T10:00:00Z", "2026-02-15T11:00:00Z")
    assert AllenIntervalAlgebra.determine_relation(e_s1, e_s2) == AllenRelation.STARTS
    assert AllenIntervalAlgebra.determine_relation(e_s2, e_s1) == AllenRelation.STARTED_BY

    # 5. During: [10:15, 10:45] during [10:00, 11:00]
    e_d1 = make_event("2026-02-15T10:15:00Z", "2026-02-15T10:45:00Z")
    e_d2 = make_event("2026-02-15T10:00:00Z", "2026-02-15T11:00:00Z")
    assert AllenIntervalAlgebra.determine_relation(e_d1, e_d2) == AllenRelation.DURING
    assert AllenIntervalAlgebra.determine_relation(e_d2, e_d1) == AllenRelation.CONTAINS

    # 6. Finishes: [10:30, 11:00] finishes [10:00, 11:00]
    e_f1 = make_event("2026-02-15T10:30:00Z", "2026-02-15T11:00:00Z")
    e_f2 = make_event("2026-02-15T10:00:00Z", "2026-02-15T11:00:00Z")
    assert AllenIntervalAlgebra.determine_relation(e_f1, e_f2) == AllenRelation.FINISHES
    assert AllenIntervalAlgebra.determine_relation(e_f2, e_f1) == AllenRelation.FINISHED_BY

    # 7. Equals: [10:00, 11:00] equals [10:00, 11:00]
    e_eq1 = make_event("2026-02-15T10:00:00Z", "2026-02-15T11:00:00Z")
    e_eq2 = make_event("2026-02-15T10:00:00Z", "2026-02-15T11:00:00Z")
    assert AllenIntervalAlgebra.determine_relation(e_eq1, e_eq2) == AllenRelation.EQUALS


# ---------------------------------------------------------------------------
# REQUIREMENT C2: MULTI-SOURCE CONFLICT & DISPARITY DETECTION
# ---------------------------------------------------------------------------

def test_c2_detect_timestamp_disparity_between_sources():
    """
    Source A (CrowdStrike) asserts Technique T1059.001 occurred at 02:00 UTC.
    Source B (CISA) asserts Technique T1059.001 occurred at 08:00 UTC (6 hours later).
    The engine must flag this as a TIMESTAMP_DISPARITY conflict without discarding either.
    """
    ev_a = TimelineEvent(
        id="ev-cs-01",
        title="PowerShell Execution",
        source_id="src-crowdstrike",
        source_name="CrowdStrike Intelligence",
        technique_id="T1059.001",
        occurrence_start="2026-02-15T02:00:00Z",
    )
    ev_b = TimelineEvent(
        id="ev-cisa-01",
        title="PowerShell Execution",
        source_id="src-cisa",
        source_name="CISA Alert AA26-045A",
        technique_id="T1059.001",
        occurrence_start="2026-02-15T08:00:00Z",
    )

    conflicts = AllenIntervalAlgebra.detect_conflicts([ev_a, ev_b], disparity_threshold_seconds=3600.0)

    assert len(conflicts) == 1
    c = conflicts[0]
    assert c.conflict_type == "TIMESTAMP_DISPARITY"
    assert c.disparity_delta_seconds == 6 * 3600.0
    assert "Discrepancy: 6.0 hours" in c.explanation
    assert c.source_a == "CrowdStrike Intelligence"
    assert c.source_b == "CISA Alert AA26-045A"


# ---------------------------------------------------------------------------
# REQUIREMENT C3: PARALLEL TRACK PRESERVATION (NO SILENT MERGING)
# ---------------------------------------------------------------------------

def test_c3_parallel_track_reconstruction_without_silent_merging():
    """
    Verifies that conflicting reports are placed on separate parallel tracks
    and the response flags has_disputes=True.
    """
    service = TimelineService()

    # Source 1: Internal Telemetry
    service.record_event(
        TimelineEvent(
            id="ev-int-01",
            title="Initial Ingress",
            source_id="src-edr",
            source_name="Internal EDR",
            track_id="track-edr",
            technique_id="T1190",
            occurrence_start="2026-02-15T01:00:00Z",
        )
    )
    service.record_event(
        TimelineEvent(
            id="ev-int-02",
            title="Credential Access",
            source_id="src-edr",
            source_name="Internal EDR",
            track_id="track-edr",
            technique_id="T1003",
            occurrence_start="2026-02-15T02:30:00Z",
        )
    )

    # Source 2: External OSINT Report with conflicting timestamp for T1003
    service.record_event(
        TimelineEvent(
            id="ev-ext-01",
            title="Credential Access (OSINT)",
            source_id="src-osint",
            source_name="OSINT Report",
            track_id="track-osint",
            technique_id="T1003",
            occurrence_start="2026-02-15T12:00:00Z",  # 9.5 hours difference!
        )
    )

    res = service.reconstruct_timeline()

    assert res.total_events == 3
    assert len(res.tracks) == 2
    track_names = [t.source_name for t in res.tracks]
    assert "Internal EDR" in track_names
    assert "OSINT Report" in track_names

    # Neither event was deleted or averaged
    edr_track = next(t for t in res.tracks if t.source_name == "Internal EDR")
    osint_track = next(t for t in res.tracks if t.source_name == "OSINT Report")
    assert len(edr_track.events) == 2
    assert len(osint_track.events) == 1

    # Conflict was flagged
    assert res.has_disputes is True
    assert len(res.conflicts) == 1
    assert res.conflicts[0].conflict_type == "TIMESTAMP_DISPARITY"


# ---------------------------------------------------------------------------
# REQUIREMENT C4: REST API ENDPOINTS
# ---------------------------------------------------------------------------

def test_c4_timeline_api_routes():
    """
    Tests REST API endpoints:
    - POST /api/v1/timeline/events
    - GET /api/v1/timeline/events
    - GET /api/v1/timeline/conflicts
    """
    # 1. Post Event
    ev_payload = {
        "id": "ev-api-01",
        "title": "Phishing Delivery",
        "source_id": "src-email-gateway",
        "source_name": "Email Gateway",
        "track_id": "track-email",
        "technique_id": "T1566.001",
        "occurrence_start": "2026-02-15T04:15:00Z",
        "confidence": 0.95,
    }
    post_res = client.post("/api/v1/timeline/events", json=ev_payload)
    assert post_res.status_code == 201
    assert post_res.json()["id"] == "ev-api-01"

    # 2. Get Timeline Events
    get_res = client.get("/api/v1/timeline/events")
    assert get_res.status_code == 200
    timeline = get_res.json()
    assert "tracks" in timeline
    assert "total_events" in timeline
    assert timeline["total_events"] >= 1

    # 3. Get Timeline Conflicts
    conflict_res = client.get("/api/v1/timeline/conflicts")
    assert conflict_res.status_code == 200
    assert isinstance(conflict_res.json(), list)
