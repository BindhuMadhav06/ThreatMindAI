import hashlib
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.models.reasoning import EvidenceBackedPath

def compute_evidence_id(source_id: str, relationship: str, evidence_text: str) -> str:
    """
    Computes a stable, deterministic evidence identifier independent of transient database IDs.
    """
    raw_key = f"{source_id.strip()}|{relationship.strip()}|{evidence_text.strip()}"
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
    return f"ev_{digest}"

class AnswerRequest(BaseModel):
    question: str = Field(..., min_length=1, description="Natural-language cyber threat question")
    entity_hints: Optional[List[str]] = Field(default=None, description="Optional entity hints provided by analyst")
    max_depth: int = Field(default=3, ge=1, le=3, description="Maximum traversal depth (hard cap: 3)")
    max_paths: int = Field(default=10, ge=1, le=20, description="Maximum accepted paths to consider")
    min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Optional minimum confidence threshold")

class AnswerClaim(BaseModel):
    claim_text: str = Field(..., description="Specific factual proposition made in the answer")
    evidence_references: List[str] = Field(default_factory=list, description="Referenced citation IDs, e.g. ['CIT-1']")
    claim_type: str = Field(
        default="relationship",
        description="relationship, actor_behavior, vulnerability_impact, technique_usage, observational"
    )
    verification_status: str = Field(
        default="unverified",
        description="verified or unverified"
    )
    validation_reasons: List[str] = Field(
        default_factory=list,
        description="Reasons explaining verification status, metadata checks, or failure reasons"
    )

class AnswerCitation(BaseModel):
    citation_id: str = Field(..., description="Stable query citation identifier, e.g. CIT-1")
    evidence_id: str = Field(..., description="Deterministic unique evidence identifier")
    source_id: str = Field(..., description="Source document or advisory ID")
    source_title: Optional[str] = Field(default=None, description="Source publication title")
    source_url: Optional[str] = Field(default=None, description="URL or reference link")
    publisher: Optional[str] = Field(default=None, description="Publishing organization")
    published_date: Optional[str] = Field(default=None, description="Publication date")
    evidence_text: str = Field(..., description="Verbatim text passage extracted from source")
    supported_relationship: str = Field(..., description="Canonical graph edge, e.g. (APT29)-[USES]->(Cobalt Strike)")
    confidence: Optional[float] = Field(default=None, description="Extraction confidence or None if unknown")
    is_synthetic: bool = Field(default=False, description="Flag indicating if evidence originates from synthetic demo data")

class GroundedAnswer(BaseModel):
    summary: str = Field(..., description="High-level synthesis of findings")
    direct_answer: str = Field(..., description="Comprehensive narrative answering the question with inline citations [CIT-X]")
    claims: List[AnswerClaim] = Field(default_factory=list, description="List of granular claims made in the answer")
    citations: List[AnswerCitation] = Field(default_factory=list, description="List of citations backing the claims")
    referenced_paths: List[str] = Field(default_factory=list, description="IDs of graph paths referenced")
    caveats: List[str] = Field(default_factory=list, description="Analytical caveats and non-causality notes")
    sufficiency_status: str = Field(..., description="sufficient, partial, or insufficient")
    is_synthetic: bool = Field(default=False, description="Flag indicating if any cited evidence is synthetic")

class AnswerValidationResult(BaseModel):
    is_valid: bool = Field(..., description="True if answer satisfies required grounding criteria")
    grounding_status: str = Field(
        ...,
        description="fully_grounded, partially_grounded, insufficient_evidence, or unsupported"
    )
    verified_claims: List[AnswerClaim] = Field(default_factory=list)
    unverified_claims: List[AnswerClaim] = Field(default_factory=list)
    rejected_reasons: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class AnswerResponse(BaseModel):
    original_question: str = Field(..., description="Original user question")
    answer: GroundedAnswer = Field(..., description="Evidence-grounded answer object")
    claims: List[AnswerClaim] = Field(default_factory=list, description="All evaluated claims with verification statuses")
    citations: List[AnswerCitation] = Field(default_factory=list, description="All citations in the response citation pool")
    graph_paths: List[EvidenceBackedPath] = Field(default_factory=list, description="Validated multi-hop reasoning paths")
    resolved_entities: List[str] = Field(default_factory=list, description="Resolved entity names")
    unresolved_entities: List[str] = Field(default_factory=list, description="Unresolved entities from question")
    warnings: List[str] = Field(default_factory=list, description="Aggregated operational and grounding warnings")
    grounding_status: str = Field(
        ...,
        description="fully_grounded, partially_grounded, insufficient_evidence, or unsupported"
    )
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Performance and validation metrics")
