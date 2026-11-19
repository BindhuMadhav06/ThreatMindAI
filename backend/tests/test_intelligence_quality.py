"""
Phase 13: ThreatMind Intelligence Quality Engine — Verification Test Suite
Covers:
- Evidence span and cryptographic hash integrity
- Dispute ledger persistence without evidence deletion
- Temporal freshness decay and frozen-clock audit boundaries
- Source reliability and circular corroboration suppression
- Feed poisoning and prompt injection quarantine
- Bayesian Beta-Binomial confidence calibration & Brier score
- Multi-tier deduplication (SimHash & Jaccard)
- Reproducible decision envelopes (RFC 8785 canonical serialization)
- Quality Engine REST API routes
"""

import hashlib
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.quality import (
    ClaimType,
    DisputeResolutionStatus,
    DuplicateType,
    SourceType,
    ValidationState,
)
from app.services.quality import (
    BayesianConfidenceService,
    ClaimEngine,
    DeduplicationService,
    DisputeLedger,
    FreshnessEngine,
    ReproducibilityService,
    SourceReliabilityService,
    canonical_json_bytes,
    canonical_sha256,
)

client = TestClient(app)


# ============================================================================
# Test Group 1: Evidence Span & Hash Integrity (13.1)
# ============================================================================

def test_evidence_span_verification_success():
    engine = ClaimEngine()
    doc_text = "Analysis reveals that APT29 deployed Cobalt Strike beacons via malicious ISO containers."
    # "APT29 deployed Cobalt Strike" starts at 22 and ends at 51
    quote = "APT29 deployed Cobalt Strike"
    offset_start = doc_text.index(quote)
    offset_end = offset_start + len(quote)

    claim = engine.validate_and_anchor_claim(
        claim_id="claim_001",
        claim_type=ClaimType.RELATIONSHIP,
        subject="APT29",
        predicate="USES",
        obj="Cobalt Strike",
        source_doc_id="doc_mnd_001",
        source_identity="Mandiant",
        raw_document_text=doc_text,
        offset_start=offset_start,
        offset_end=offset_end,
        quoted_evidence=quote,
        observation_time="2026-11-19T10:00:00Z"
    )

    assert claim.validation_state == ValidationState.VERIFIED
    assert claim.document_sha256 == hashlib.sha256(doc_text.encode("utf-8")).hexdigest()
    assert claim.quoted_evidence == doc_text[offset_start:offset_end]


def test_evidence_span_hash_mismatch_fails_closed():
    engine = ClaimEngine()
    doc_text = "Analysis reveals that APT29 deployed Cobalt Strike."
    quote = "APT29 deployed Cobalt Strike"
    offset_start = doc_text.index(quote)
    offset_end = offset_start + len(quote)

    tampered_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    claim = engine.validate_and_anchor_claim(
        claim_id="claim_tampered",
        claim_type=ClaimType.RELATIONSHIP,
        subject="APT29",
        predicate="USES",
        obj="Cobalt Strike",
        source_doc_id="doc_mnd_001",
        source_identity="Mandiant",
        raw_document_text=doc_text,
        offset_start=offset_start,
        offset_end=offset_end,
        quoted_evidence=quote,
        observation_time="2026-11-19T10:00:00Z",
        expected_sha256=tampered_hash
    )

    # Fail closed: state must be REJECTED, never VERIFIED
    assert claim.validation_state == ValidationState.REJECTED


def test_evidence_coordinate_boundary_mismatch_fails_closed():
    engine = ClaimEngine()
    doc_text = "Analysis reveals that APT29 deployed Cobalt Strike."
    quote = "APT29 deployed Cobalt Strike"

    # Erroneous offsets that don't match the quote
    claim = engine.validate_and_anchor_claim(
        claim_id="claim_offset_err",
        claim_type=ClaimType.RELATIONSHIP,
        subject="APT29",
        predicate="USES",
        obj="Cobalt Strike",
        source_doc_id="doc_mnd_001",
        source_identity="Mandiant",
        raw_document_text=doc_text,
        offset_start=0,
        offset_end=10,
        quoted_evidence=quote,
        observation_time="2026-11-19T10:00:00Z"
    )

    assert claim.validation_state == ValidationState.REJECTED


# ============================================================================
# Test Group 2: Dispute Ledger Persistence Without Deletion (13.2)
# ============================================================================

def test_dispute_ledger_registration_and_resolution():
    engine = ClaimEngine()
    ledger = DisputeLedger(claim_engine=engine)

    doc_a = "Mandiant attributes Campaign SolarWorm directly to threat actor APT29."
    quote_a = "attributes Campaign SolarWorm directly to threat actor APT29"
    claim_a = engine.validate_and_anchor_claim(
        claim_id="claim_vendor_a",
        claim_type=ClaimType.ATTRIBUTION,
        subject="Campaign SolarWorm",
        predicate="ATTRIBUTED_TO",
        obj="APT29",
        source_doc_id="doc_a",
        source_identity="Mandiant",
        raw_document_text=doc_a,
        offset_start=doc_a.index(quote_a),
        offset_end=doc_a.index(quote_a) + len(quote_a),
        quoted_evidence=quote_a,
        observation_time="2026-11-18T10:00:00Z"
    )

    doc_b = "CrowdStrike report argues Campaign SolarWorm was executed by FIN7."
    quote_b = "Campaign SolarWorm was executed by FIN7"
    claim_b = engine.validate_and_anchor_claim(
        claim_id="claim_vendor_b",
        claim_type=ClaimType.ATTRIBUTION,
        subject="Campaign SolarWorm",
        predicate="ATTRIBUTED_TO",
        obj="FIN7",
        source_doc_id="doc_b",
        source_identity="CrowdStrike",
        raw_document_text=doc_b,
        offset_start=doc_b.index(quote_b),
        offset_end=doc_b.index(quote_b) + len(quote_b),
        quoted_evidence=quote_b,
        observation_time="2026-11-19T11:00:00Z"
    )

    dispute = ledger.register_dispute(
        claim_a=claim_a,
        claim_b=claim_b,
        dispute_type="ATTRIBUTION_DISPUTE"
    )

    assert dispute.resolution_status == DisputeResolutionStatus.OPEN
    assert "claim_vendor_b" in claim_a.contradicting_evidence_ids
    assert "claim_vendor_a" in claim_b.contradicting_evidence_ids

    # Analyst resolves in favor of Claim A
    resolved = ledger.resolve_dispute(
        dispute_id=dispute.dispute_id,
        favored_claim_id="claim_vendor_a",
        analyst_id="analyst_sec_01",
        rationale="Corroborated by telemetry and DNS registration artifacts.",
        claims_store=engine.store
    )

    assert resolved.resolution_status == DisputeResolutionStatus.ANALYST_RESOLVED
    assert resolved.resolved_by == "analyst_sec_01"

    # CRITICAL INVARIANT: Claim B must NOT be deleted!
    assert engine.get_claim("claim_vendor_b") is not None
    assert engine.get_claim("claim_vendor_b").validation_state == ValidationState.DISPUTED
    assert engine.get_claim("claim_vendor_a").validation_state == ValidationState.VERIFIED


# ============================================================================
# Test Group 3: Temporal Freshness Decay & Frozen-Clock Audits (13.3)
# ============================================================================

def test_temporal_freshness_decay_curve():
    freshness = FreshnessEngine()

    # IPv4 indicator: half-life = 14 days
    policy_0d = freshness.calculate_freshness(
        entity_type="ipv4",
        observation_time="2026-11-19T00:00:00Z",
        as_of_time="2026-11-19T00:00:00Z"
    )
    assert policy_0d.freshness_score == 1.0
    assert not policy_0d.is_stale

    # Exactly 14 days later: score must be exactly 0.5 (2^-1)
    policy_14d = freshness.calculate_freshness(
        entity_type="ipv4",
        observation_time="2026-11-05T00:00:00Z",
        as_of_time="2026-11-19T00:00:00Z"
    )
    assert abs(policy_14d.freshness_score - 0.5) < 0.01

    # 28 days later: score must be 0.25 (2^-2), flagged as stale
    policy_28d = freshness.calculate_freshness(
        entity_type="ipv4",
        observation_time="2026-10-22T00:00:00Z",
        as_of_time="2026-11-19T00:00:00Z"
    )
    assert abs(policy_28d.freshness_score - 0.25) < 0.01
    assert policy_28d.is_stale
    assert "exceeds entity half-life" in policy_28d.stale_warning


def test_frozen_clock_deterministic_evaluation():
    freshness = FreshnessEngine()
    as_of = "2026-06-01T12:00:00Z"
    obs = "2026-05-18T12:00:00Z"

    # Evaluated at frozen historical time
    res = freshness.calculate_freshness("domain", obs, as_of_time=as_of)
    assert res.half_life_days == 60.0
    assert abs(res.current_age_days - 14.0) < 0.1


# ============================================================================
# Test Group 4: Source Reliability & Circular Corroboration (13.4)
# ============================================================================

def test_source_reliability_and_circular_suppression():
    rel_service = SourceReliabilityService()

    # Independent government CERT source
    cert_score = rel_service.evaluate_source(
        source_id="cert_us_cisa",
        source_name="CISA Alerts",
        source_type=SourceType.GOVERNMENT_CERT,
        historical_accuracy=0.98,
        independent_corroboration_rate=0.95,
        correction_rate=0.01,
        recency_factor=1.0,
        circular_penalty=0.0
    )
    assert cert_score.overall_reliability >= 0.90

    # Syndicated wire source penalized for circular copy-paste
    syndicate_score = rel_service.evaluate_source(
        source_id="syndicate_wire_01",
        source_name="Aggregator Wire",
        source_type=SourceType.OPEN_SOURCE,
        historical_accuracy=0.85,
        independent_corroboration_rate=0.40,
        correction_rate=0.08,
        recency_factor=0.9,
        circular_penalty=0.45
    )
    assert syndicate_score.overall_reliability < cert_score.overall_reliability
    assert syndicate_score.circular_corroboration_penalty == 0.45


# ============================================================================
# Test Group 5: Feed Poisoning & Prompt Injection Quarantine (13.4)
# ============================================================================

def test_feed_poisoning_quarantine_alert():
    rel_service = SourceReliabilityService()

    # Flag volume burst anomaly
    alert = rel_service.register_poisoning_alert(
        source_id="feed_anomaly_99",
        source_name="Rogue Community Feed",
        anomaly_type="VOLUME_BURST",
        anomaly_score=0.92,
        details="Received 2,400 synthetic indicators within 90 seconds."
    )

    assert alert.quarantined is True
    assert alert.anomaly_type == "VOLUME_BURST"

    # Ensure source is now quarantined
    src = rel_service.get_score("feed_anomaly_99")
    assert src.quarantine_status is True


# ============================================================================
# Test Group 6 & 7: Bayesian Confidence Calibration & Brier Score (13.5)
# ============================================================================

def test_bayesian_confidence_updating_and_credible_interval():
    bayes = BayesianConfidenceService(default_alpha=2.0, default_beta=2.0)

    # Prior: Beta(2, 2), Expected confidence = 0.5
    prior_est = bayes.calibrate("claim_prior_only")
    assert prior_est.expected_confidence == 0.5
    assert prior_est.is_insufficient_evidence is True

    # 4 strong positive independent reports, 0 negative
    evidences_pos = [
        {"weight": 1.0, "reliability": 0.95, "is_syndicated": False},
        {"weight": 1.0, "reliability": 0.90, "is_syndicated": False},
        {"weight": 1.0, "reliability": 0.85, "is_syndicated": False},
        {"weight": 1.0, "reliability": 0.90, "is_syndicated": False},
    ]
    post_est = bayes.calibrate("claim_post", positive_evidences=evidences_pos)
    assert post_est.expected_confidence > 0.70
    assert post_est.credible_interval_high > post_est.credible_interval_low
    assert not post_est.is_insufficient_evidence

    # Syndicated report discounting
    ev_syndicated = [{"weight": 1.0, "reliability": 1.0, "is_syndicated": True}]
    post_synd = bayes.calibrate("claim_synd", positive_evidences=ev_syndicated)
    assert post_synd.positive_evidence_weight == 0.20  # Discounted to 0.2


def test_brier_score_tracking():
    bayes = BayesianConfidenceService()
    # Predictions: [0.90, 0.80, 0.20], True ground truths: [1, 1, 0]
    preds = [0.90, 0.80, 0.20]
    outcomes = [1, 1, 0]
    # Errors: (0.10)^2 + (0.20)^2 + (0.20)^2 = 0.01 + 0.04 + 0.04 = 0.09 / 3 = 0.03
    brier = bayes.compute_brier_score(preds, outcomes)
    assert abs(brier - 0.03) < 0.001


# ============================================================================
# Test Group 8: Multi-Tier Deduplication (13.6)
# ============================================================================

def test_deduplication_exact_and_near_duplicate():
    dedup = DeduplicationService()

    text_a = "Threat actor APT29 used malicious ISO files to deliver Cobalt Strike beacons."
    text_exact = "Threat actor APT29 used malicious ISO files to deliver Cobalt Strike beacons."
    text_near = "Mandiant observed threat actor APT29 utilizing spearphishing emails containing malicious ISO container attachments to compromise victims and deploy Cobalt Strike beacon payloads across targeted domain controller infrastructure in corporate networks."
    text_near_variant = "Mandiant observed threat actor APT29 utilizing spearphishing emails containing malicious ISO container attachments to compromise victims and deploy Cobalt Strike beacon payloads across targeted domain controller infrastructure in corporate systems."
    text_diff = "Zero-day vulnerability CVE-2024-21413 allows NTLM credential disclosure in Microsoft Outlook."

    # Tier 1: Exact
    res_exact = dedup.analyze_pair("doc_1", text_a, "doc_2", text_exact)
    assert res_exact.duplicate_type == DuplicateType.EXACT_DUPLICATE
    assert res_exact.exact_hash_match is True
    assert res_exact.suppression_recommended is True

    # Tier 2 & 3: Near duplicate / syndicated copy
    res_near = dedup.analyze_pair("doc_1", text_near, "doc_3", text_near_variant)
    assert res_near.duplicate_type in (DuplicateType.NEAR_DUPLICATE, DuplicateType.SYNDICATED_COPY)
    assert res_near.suppression_recommended is True

    # Independent
    res_diff = dedup.analyze_pair("doc_1", text_a, "doc_4", text_diff)
    assert res_diff.duplicate_type == DuplicateType.INDEPENDENT_REPORT
    assert res_diff.suppression_recommended is False


# ============================================================================
# Test Group 9: Reproducible Decision Envelopes (13.7)
# ============================================================================

def test_reproducible_decision_envelope_rfc8785():
    service = ReproducibilityService()

    record = service.create_record(
        decision_id="dec_path_001",
        decision_type="attack_path_remediation",
        graph_snapshot={"nodes": ["asset_1", "asset_2"], "edges": [("asset_1", "asset_2")]},
        evidence_document_hashes=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        model_version="threatmind-v2.1",
        prompt_template_version="pt-v1.0.4",
        parameters={"alpha": 2.0, "max_depth": 6},
        decision_inputs={"target": "asset_2"},
        decision_outputs={"recommended_cut_set": ["d3f:MultiFactorAuthentication"]}
    )

    assert record.reproducibility_digest is not None
    assert len(record.reproducibility_digest) == 64

    # Verify digest matches canonical serialization
    valid, msg = service.verify_record(record)
    assert valid is True

    # Tampering with payload fails verification
    record.decision_outputs["recommended_cut_set"].append("d3f:NetworkIsolation")
    tampered_valid, tampered_msg = service.verify_record(record)
    assert tampered_valid is False
    assert "Digest mismatch" in tampered_msg


# ============================================================================
# Test Group 10: Quality Engine API Endpoints
# ============================================================================

def test_quality_api_claim_and_freshness():
    # Submit claim endpoint
    doc = "APT28 utilized spearphishing emails with RTF attachments."
    quote = "spearphishing emails with RTF attachments"
    start = doc.index(quote)
    end = start + len(quote)

    resp = client.post(
        "/api/v1/quality/claims",
        json={
            "claim_id": "claim_api_test_01",
            "claim_type": "technique_execution",
            "subject": "APT28",
            "predicate": "USES",
            "object": "T1566.001",
            "source_doc_id": "doc_osint_01",
            "source_identity": "CISA",
            "raw_document_text": doc,
            "offset_start": start,
            "offset_end": end,
            "quoted_evidence": quote,
            "observation_time": "2026-11-19T00:00:00Z",
            "extraction_method": "deterministic_heuristic"
        }
    )
    assert resp.status_code == 201
    assert resp.json()["validation_state"] == "verified"

    # Freshness endpoint
    f_resp = client.get(
        "/api/v1/quality/freshness",
        params={"entity_type": "ipv4", "observation_time": "2026-11-01T00:00:00Z"}
    )
    assert f_resp.status_code == 200
    assert "freshness_score" in f_resp.json()
