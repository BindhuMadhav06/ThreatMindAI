from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.models.query import ResolvedEntity, EvidenceRecord

class ReasoningRequest(BaseModel):
    question: str = Field(..., min_length=1, description="Natural-language cyber threat investigation question")
    entity_hints: Optional[List[str]] = Field(default=None, description="Optional starting entity hints")
    target_entity: Optional[str] = Field(default=None, description="Optional target entity for targeted path finding")
    template_name: Optional[str] = Field(default=None, description="Optional explicit path template identifier")
    max_depth: int = Field(default=3, ge=1, le=3, description="Maximum traversal hops (hard cap: 3)")
    max_paths: int = Field(default=10, ge=1, le=20, description="Maximum accepted paths to return")
    min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Optional minimum confidence")

class ReasoningStep(BaseModel):
    step_number: int = Field(..., description="1-based step index in the path")
    source_id: str
    source_label: str
    source_name: str
    rel_type: str
    target_id: str
    target_label: str
    target_name: str
    evidence_records: List[EvidenceRecord] = Field(default_factory=list)
    sources: List[Dict[str, Any]] = Field(default_factory=list)
    is_valid: bool = True
    validation_notes: List[str] = Field(default_factory=list)

class EvidenceBackedPath(BaseModel):
    path_id: str
    steps: List[ReasoningStep]
    length: int
    is_complete: bool = True
    is_valid: bool = True
    relevance_score: float = 0.0
    template_applied: Optional[str] = None
    semantic_caveats: List[str] = Field(default_factory=list)

class PathValidationResult(BaseModel):
    is_valid: bool
    validation_status: str = Field(..., description="accepted, rejected, or partial")
    reasons: List[str] = Field(default_factory=list)
    steps_evaluated: int = 0
    valid_steps_count: int = 0

class ReasoningResult(BaseModel):
    original_question: str
    resolved_entities: List[ResolvedEntity]
    candidate_paths_considered: int
    accepted_paths: List[EvidenceBackedPath]
    rejected_paths: List[Dict[str, Any]]
    partial_paths: List[EvidenceBackedPath]
    referenced_sources: List[Dict[str, Any]]
    warnings: List[str]
    statistics: Dict[str, Any]
