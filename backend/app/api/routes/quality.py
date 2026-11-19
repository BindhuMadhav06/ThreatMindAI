"""
API routes for Phase 13 ThreatMind Intelligence Quality Engine.
Provides endpoints for claim anchoring, dispute management, temporal freshness,
source reliability, Bayesian confidence calibration, deduplication, and
decision envelope verification.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.models.quality import (
    ClaimType,
    DisputeLedgerEntry,
    DisputeResolutionStatus,
    DuplicateDetectionResult,
    FreshnessPolicy,
    PoisoningAlert,
    ReproducibleDecisionRecord,
    SourceReliabilityScore,
    StructuredClaim,
    ValidationState,
    BayesianConfidenceEstimate,
)
from app.services.quality import (
    BayesianConfidenceService,
    ClaimEngine,
    DeduplicationService,
    DisputeLedger,
    FreshnessEngine,
    ReproducibilityService,
    SourceReliabilityService,
)

router = APIRouter(prefix="/quality", tags=["Intelligence Quality Engine"])

# Singleton in-memory service instances for fast access and testing
claim_engine = ClaimEngine()
dispute_ledger = DisputeLedger()
freshness_engine = FreshnessEngine()
reliability_service = SourceReliabilityService()
bayesian_service = BayesianConfidenceService()
dedup_service = DeduplicationService()
reproducibility_service = ReproducibilityService()


class ClaimSubmissionRequest(BaseModel):
    claim_id: str
    claim_type: ClaimType
    subject: str
    predicate: str
    object: str
    source_doc_id: str
    source_identity: str
    raw_document_text: str
    offset_start: int
    offset_end: int
    quoted_evidence: str
    observation_time: str
    publication_time: Optional[str] = None
    extraction_method: str = "llm_structured_extraction"
    confidence: float = 0.8
    tenant_id: Optional[str] = None


class DisputeResolutionRequest(BaseModel):
    favored_claim_id: str
    analyst_id: str
    rationale: str


class DeduplicationRequest(BaseModel):
    doc_a_id: str
    text_a: str
    doc_b_id: str
    text_b: str
    simhash_threshold: int = 3
    jaccard_threshold: float = 0.80


class BayesianCalibrateRequest(BaseModel):
    claim_id: str
    positive_evidences: List[Dict[str, Any]] = Field(default_factory=list)
    negative_evidences: List[Dict[str, Any]] = Field(default_factory=list)
    prior_alpha: float = 2.0
    prior_beta: float = 2.0
    ground_truth_outcome: Optional[int] = None


@router.post("/claims", response_model=StructuredClaim, status_code=status.HTTP_201_CREATED)
async def submit_claim(request: ClaimSubmissionRequest) -> StructuredClaim:
    """
    Submit and anchor an intelligence claim against raw document text.
    Strictly validates character offsets and SHA-256 document digest.
    """
    claim = claim_engine.validate_and_anchor_claim(
        claim_id=request.claim_id,
        claim_type=request.claim_type,
        subject=request.subject,
        predicate=request.predicate,
        obj=request.object,
        source_doc_id=request.source_doc_id,
        source_identity=request.source_identity,
        raw_document_text=request.raw_document_text,
        offset_start=request.offset_start,
        offset_end=request.offset_end,
        quoted_evidence=request.quoted_evidence,
        observation_time=request.observation_time,
        publication_time=request.publication_time,
        extraction_method=request.extraction_method,  # type: ignore
        confidence=request.confidence,
    )
    return claim


@router.get("/claims", response_model=List[StructuredClaim])
async def list_claims(
    subject: Optional[str] = Query(None, description="Filter by subject entity"),
    validation_state: Optional[ValidationState] = Query(None, description="Filter by validation state")
) -> List[StructuredClaim]:
    """Retrieve indexed structured claims."""
    claims = claim_engine.get_all_claims()
    if subject:
        claims = [c for c in claims if c.subject.lower() == subject.lower()]
    if validation_state:
        claims = [c for c in claims if c.validation_state == validation_state]
    return claims


@router.get("/claims/{claim_id}", response_model=StructuredClaim)
async def get_claim(claim_id: str) -> StructuredClaim:
    """Retrieve a single claim by its unique ID."""
    claim = claim_engine.get_claim(claim_id)
    if not claim:
        raise HTTPException(status_code=404, detail=f"Claim {claim_id} not found.")
    return claim


@router.post("/disputes", response_model=DisputeLedgerEntry, status_code=status.HTTP_201_CREATED)
async def create_dispute(
    dispute_id: str,
    claim_a_id: str,
    claim_b_id: str,
    dispute_type: str = "ATTRIBUTION_DISPUTE"
) -> DisputeLedgerEntry:
    """Register an attribution or observation conflict in the persistent dispute ledger."""
    claim_a = claim_engine.get_claim(claim_a_id)
    claim_b = claim_engine.get_claim(claim_b_id)
    if not claim_a or not claim_b:
        raise HTTPException(status_code=404, detail="One or both conflicting claims not found.")

    entry = dispute_ledger.register_dispute(claim_a, claim_b, dispute_type=dispute_type)  # type: ignore
    return entry


@router.get("/disputes", response_model=List[DisputeLedgerEntry])
async def list_disputes(
    status_filter: Optional[DisputeResolutionStatus] = Query(None, description="Filter by status")
) -> List[DisputeLedgerEntry]:
    """List disputes from the persistent ledger."""
    entries = dispute_ledger.get_all_disputes()
    if status_filter:
        entries = [e for e in entries if e.resolution_status == status_filter]
    return entries


@router.post("/disputes/{dispute_id}/resolve", response_model=DisputeLedgerEntry)
async def resolve_dispute(dispute_id: str, req: DisputeResolutionRequest) -> DisputeLedgerEntry:
    """
    Resolve a dispute in favor of a specific claim.
    Updates the ledger and claims without deleting or overwriting any historical evidence.
    """
    try:
        resolved = dispute_ledger.resolve_dispute(
            dispute_id=dispute_id,
            favored_claim_id=req.favored_claim_id,
            analyst_id=req.analyst_id,
            rationale=req.rationale,
            claims_store=claim_engine.store
        )
        return resolved
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Dispute {dispute_id} not found.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/freshness", response_model=FreshnessPolicy)
async def calculate_freshness(
    entity_type: str = Query(..., description="Indicator or entity type: ipv4, domain, url, file_hash, vulnerability"),
    observation_time: str = Query(..., description="ISO 8601 timestamp of observation or publication"),
    as_of_time: Optional[str] = Query(None, description="Optional frozen reference time for audit")
) -> FreshnessPolicy:
    """Calculate temporal freshness decay score using entity-specific half-life policies."""
    try:
        return freshness_engine.calculate_freshness(
            entity_type=entity_type,
            observation_time=observation_time,
            as_of_time=as_of_time
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Freshness calculation error: {str(e)}")


@router.get("/sources/reliability", response_model=List[SourceReliabilityScore])
async def get_source_reliabilities() -> List[SourceReliabilityScore]:
    """Retrieve source reliability scores with circular corroboration discounting."""
    return reliability_service.get_all_scores()


@router.get("/sources/poisoning-alerts", response_model=List[PoisoningAlert])
async def get_poisoning_alerts() -> List[PoisoningAlert]:
    """Retrieve feed poisoning, prompt injection, and volume burst alerts."""
    return reliability_service.get_poisoning_alerts()


@router.post("/deduplicate", response_model=DuplicateDetectionResult)
async def test_deduplication(req: DeduplicationRequest) -> DuplicateDetectionResult:
    """Multi-tier deduplication check (SHA-256, 64-bit SimHash, token Jaccard similarity)."""
    return dedup_service.analyze_pair(
        doc_a_id=req.doc_a_id,
        text_a=req.text_a,
        doc_b_id=req.doc_b_id,
        text_b=req.text_b,
        simhash_threshold=req.simhash_threshold,
        jaccard_threshold=req.jaccard_threshold
    )


@router.post("/bayesian/calibrate", response_model=BayesianConfidenceEstimate)
async def calibrate_confidence(req: BayesianCalibrateRequest) -> BayesianConfidenceEstimate:
    """Calibrate confidence on an intelligence claim via Bayesian Beta-Binomial updating."""
    return bayesian_service.calibrate(
        claim_id=req.claim_id,
        positive_evidences=req.positive_evidences,
        negative_evidences=req.negative_evidences,
        prior_alpha=req.prior_alpha,
        prior_beta=req.prior_beta,
        ground_truth_outcome=req.ground_truth_outcome
    )


@router.post("/reproducibility/verify")
async def verify_envelope(record: ReproducibleDecisionRecord) -> Dict[str, Any]:
    """Verify cryptographic reproducibility envelope against canonical JSON serialization."""
    valid, message = reproducibility_service.verify_record(record)
    return {
        "decision_id": record.decision_id,
        "is_valid": valid,
        "message": message,
        "stored_digest": record.reproducibility_digest
    }
