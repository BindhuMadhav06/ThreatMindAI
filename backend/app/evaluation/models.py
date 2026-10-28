from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class MetricScore(BaseModel):
    numerator: int = Field(..., description="Count of correct / matching instances")
    denominator: int = Field(..., description="Total opportunities or instances")
    value: Optional[float] = Field(None, description="Computed metric value between 0.0 and 1.0, or None if undefined")
    formatted: str = Field(..., description="Human-readable fraction and percentage, e.g. '12/15 (80.0%)' or '0/0 (N/A)'")

class EntityExtractionEvaluation(BaseModel):
    overall_precision: MetricScore
    overall_recall: MetricScore
    overall_f1: float
    by_label: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

class RelationExtractionEvaluation(BaseModel):
    precision: MetricScore
    recall: MetricScore
    f1: float

class RetrievalEvaluation(BaseModel):
    k: int = Field(default=5)
    precision_at_k: MetricScore
    recall_at_k: MetricScore
    unresolvable_entity_count: int = Field(default=0)
    unresolvable_query_rate: Optional[MetricScore] = None
    zero_resolved_seed_rate: Optional[MetricScore] = None
    entity_mention_resolution_rate: Optional[MetricScore] = None

class ReasoningPathEvaluation(BaseModel):
    path_validity_rate: MetricScore
    path_continuity_rate: MetricScore
    cycle_rejection_rate: MetricScore
    total_evaluated_paths: int = 0
    accepted_paths: int = 0
    rejected_paths: int = 0

class GroundingEvaluation(BaseModel):
    citation_correctness_rate: MetricScore
    citation_completeness_rate: MetricScore
    unsupported_claim_rate: MetricScore
    total_claims: int = 0
    verified_claims: int = 0
    unverified_claims: int = 0
    total_citations: int = 0
    valid_citations: int = 0

class AbstentionEvaluation(BaseModel):
    precision: MetricScore
    recall: MetricScore
    false_abstention_rate: MetricScore
    tp_abstain: int = 0
    fp_abstain: int = 0
    tn_answer: int = 0
    fn_answer: int = 0

class QueryEvaluationRecord(BaseModel):
    query_id: str
    category: str
    question: str
    must_abstain: bool
    predicted_abstain: bool
    is_abstention_correct: bool
    retrieved_facts_count: int
    active_paths_count: int
    claims_count: int
    verified_claims_count: int
    citations_count: int
    grounding_status: str
    unresolved_entities: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

class BenchmarkSummary(BaseModel):
    benchmark_name: str = "ThreatMind Research Evaluation"
    version: str = "1.0.0"
    execution_mode: str = Field(..., description="OFFLINE_DETERMINISTIC, OFFLINE_MOCK, or LIVE_LLM")
    timestamp: str
    total_queries: int
    entity_extraction: Optional[EntityExtractionEvaluation] = None
    relation_extraction: Optional[RelationExtractionEvaluation] = None
    retrieval: RetrievalEvaluation
    reasoning: ReasoningPathEvaluation
    grounding: GroundingEvaluation
    abstention: AbstentionEvaluation
    baseline_comparisons: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    query_records: List[QueryEvaluationRecord] = Field(default_factory=list)
