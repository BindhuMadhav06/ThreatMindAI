"""
Phase 13: ThreatMind Intelligence Quality Engine — Data Models
Implements structured claims, dispute ledgers, temporal freshness policies,
source reliability, Bayesian confidence, multi-tier deduplication, and
cryptographic reproducibility envelopes.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class ValidationState(str, Enum):
    VERIFIED = "verified"
    SUPPORTED_UNVERIFIED = "supported_unverified"
    INFERRED = "inferred"
    DISPUTED = "disputed"
    REJECTED = "rejected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ClaimType(str, Enum):
    RELATIONSHIP = "relationship"
    ATTRIBUTION = "attribution"
    INDICATOR_USAGE = "indicator_usage"
    TECHNIQUE_EXECUTION = "technique_execution"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"
    INFRASTRUCTURE_LINK = "infrastructure_link"


class StructuredClaim(BaseModel):
    """
    Structured intelligence claim with character-coordinate evidence anchors,
    cryptographic source binding, and traceable provenance history.
    """
    claim_id: str
    claim_type: ClaimType
    subject: str
    predicate: str
    object: str
    source_doc_id: str
    source_identity: str
    document_sha256: str
    # Exact character coordinate system (0-indexed start and end character offsets)
    offset_start: int = Field(ge=0)
    offset_end: int = Field(gt=0)
    quoted_evidence: str
    observation_time: str
    publication_time: Optional[str] = None
    extraction_method: Literal["deterministic_heuristic", "llm_structured_extraction", "analyst_curated"]
    confidence: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(default=0.1, ge=0.0, le=1.0)
    validation_state: ValidationState = ValidationState.SUPPORTED_UNVERIFIED
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)
    provenance_history: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DisputeResolutionStatus(str, Enum):
    OPEN = "open"
    UNDER_REVIEW = "under_review"
    ANALYST_RESOLVED = "analyst_resolved"


class DisputeLedgerEntry(BaseModel):
    """
    Persistent dispute record for conflicting vendor claims and attribution debates.
    Immutable: Resolution updates status and rationale, but preserves original evidence.
    """
    dispute_id: str
    claim_a_id: str
    claim_b_id: str
    dispute_type: Literal["ATTRIBUTION_DISPUTE", "TEMPORAL_CONTRADICTION", "VENDOR_OBSERVATION_CONFLICT"]
    subject: str
    predicate: str
    competing_values: Dict[str, str]  # e.g. {"claim_a": "APT29", "claim_b": "FIN7"}
    sources: List[str]
    evidence_refs: List[str]
    source_reliabilities: Dict[str, float]
    resolution_status: DisputeResolutionStatus = DisputeResolutionStatus.OPEN
    resolution_rationale: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class FreshnessPolicy(BaseModel):
    """
    Entity-aware freshness decay model based on half-life half_life_days.
    Formula: freshness(t) = 2^(-age / half_life)
    """
    entity_type: str
    half_life_days: float
    current_age_days: float
    freshness_score: float = Field(ge=0.0, le=1.0)
    is_stale: bool
    stale_warning: Optional[str] = None
    expiration_days: Optional[float] = None
    is_expired: bool = False


class SourceType(str, Enum):
    GOVERNMENT_CERT = "government_cert"
    COMMERCIAL_TI = "commercial_ti"
    ISAC_FEED = "isac_feed"
    OPEN_SOURCE = "open_source"
    UNVERIFIED_FORUM = "unverified_forum"


class SourceReliabilityScore(BaseModel):
    """
    Multi-factor source reliability evaluation discounting circular corroboration.
    """
    source_id: str
    source_name: str
    source_type: SourceType
    historical_accuracy: float = Field(ge=0.0, le=1.0)
    independent_corroboration_rate: float = Field(ge=0.0, le=1.0)
    correction_rate: float = Field(ge=0.0, le=1.0)
    recency_factor: float = Field(ge=0.0, le=1.0)
    circular_corroboration_penalty: float = Field(default=0.0, ge=0.0, le=1.0)
    overall_reliability: float = Field(ge=0.0, le=1.0)
    total_claims_evaluated: int = 0
    quarantine_status: bool = False


class PoisoningAlert(BaseModel):
    """
    Feed poisoning alert flagging volume bursts, synthetic indicators, or prompt injection.
    """
    alert_id: str
    source_id: str
    source_name: str
    anomaly_type: Literal["VOLUME_BURST", "FABRICATED_INDICATORS", "PROMPT_INJECTION_ATTEMPT", "SUSPICIOUS_CONTENT"]
    anomaly_score: float = Field(ge=0.0, le=1.0)
    quarantined: bool = True
    details: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BayesianConfidenceEstimate(BaseModel):
    """
    Bayesian Beta-Binomial confidence model with transparent priors,
    corroboration updating, credible interval, and Brier score tracking.
    """
    claim_id: str
    prior_alpha: float = 2.0
    prior_beta: float = 2.0
    positive_evidence_weight: float = 0.0
    negative_evidence_weight: float = 0.0
    posterior_alpha: float
    posterior_beta: float
    expected_confidence: float
    credible_interval_low: float
    credible_interval_high: float
    variance: float
    total_evidence_count: int
    is_insufficient_evidence: bool = False
    brier_score_sample: Optional[float] = None


class DuplicateType(str, Enum):
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    NEAR_DUPLICATE = "NEAR_DUPLICATE"
    SYNDICATED_COPY = "SYNDICATED_COPY"
    INDEPENDENT_REPORT = "INDEPENDENT_REPORT"
    RECYCLED_INDICATOR = "RECYCLED_INDICATOR"
    VERSION_UPDATE = "VERSION_UPDATE"


class DuplicateDetectionResult(BaseModel):
    """
    Multi-tier deduplication result using exact digest, 64-bit SimHash, and Jaccard similarity.
    """
    doc_a_id: str
    doc_b_id: str
    duplicate_type: DuplicateType
    exact_hash_match: bool
    simhash_distance: int  # Hamming distance in 0..64
    jaccard_similarity: float  # Token overlap 0.0..1.0
    suppression_recommended: bool
    explanation: str


class ReproducibleDecisionRecord(BaseModel):
    """
    Cryptographic decision record enabling independent verification and audit fidelity.
    """
    decision_id: str
    decision_type: str
    graph_snapshot_hash: str
    evidence_document_hashes: List[str]
    model_version: str
    prompt_template_version: str
    parameters: Dict[str, Any]
    decision_inputs: Dict[str, Any]
    decision_outputs: Dict[str, Any]
    analyst_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    reproducibility_digest: str  # RFC 8785 canonical JSON digest
