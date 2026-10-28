from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class RetrievalConfig(BaseModel):
    max_depth: int = Field(default=1, ge=1, le=3, description="Maximum graph traversal depth (hard max: 3)")
    max_entities: int = Field(default=20, ge=1, le=50, description="Maximum returned entity nodes (hard max: 50)")
    max_relationships: int = Field(default=30, ge=1, le=50, description="Maximum returned relationships (hard max: 50)")
    max_evidence: int = Field(default=30, ge=1, le=50, description="Maximum evidence records (hard max: 50)")
    min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Optional minimum confidence threshold")

class ThreatQuery(BaseModel):
    question: str = Field(..., min_length=1, description="Natural-language cyber threat question")
    entity_hints: Optional[List[str]] = Field(default=None, description="Optional entity hints provided by analyst")
    config: RetrievalConfig = Field(default_factory=RetrievalConfig, description="Bounded retrieval configuration")

class ResolvedEntity(BaseModel):
    id: str = Field(..., description="Unique graph entity ID, e.g. actor_apt29")
    label: str = Field(..., description="Graph entity node label, e.g. ThreatActor")
    name: str = Field(..., description="Canonical entity name")
    match_method: str = Field(..., description="Method used: canonical_name, alias_lookup, cve_identifier, mitre_identifier, entity_hint")
    confidence_score: float = Field(default=1.0, description="Confidence in entity resolution match")

class UnresolvedEntity(BaseModel):
    candidate_text: str = Field(..., description="Candidate entity phrase from question")
    reason: str = Field(..., description="Reason resolution failed: not_found_in_graph, ambiguous_multiple_matches")

class RetrievedEntity(BaseModel):
    id: str
    label: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)

class RetrievedRelationship(BaseModel):
    source_id: str
    source_name: str
    source_label: str
    rel_type: str
    target_id: str
    target_name: str
    target_label: str
    provenance: Dict[str, Any] = Field(default_factory=dict)

class EvidenceRecord(BaseModel):
    source_id: str
    source_title: Optional[str] = None
    source_url: Optional[str] = None
    publisher: Optional[str] = None
    published_date: Optional[str] = None
    evidence_text: str
    extraction_method: Optional[str] = None
    confidence: Optional[float] = None
    relationship: str

class GraphPath(BaseModel):
    path_id: str
    nodes: List[RetrievedEntity]
    relationships: List[RetrievedRelationship]
    length: int

class RetrievalStatistics(BaseModel):
    execution_time_ms: float
    entities_resolved_count: int
    nodes_retrieved_count: int
    edges_retrieved_count: int
    evidence_records_count: int
    paths_count: int

class RetrievalResult(BaseModel):
    original_question: str
    resolved_entities: List[ResolvedEntity]
    unresolved_entities: List[UnresolvedEntity]
    retrieved_entities: List[RetrievedEntity]
    retrieved_relationships: List[RetrievedRelationship]
    graph_paths: List[GraphPath]
    evidence_records: List[EvidenceRecord]
    sources: List[Dict[str, Any]]
    warnings: List[str]
    statistics: RetrievalStatistics
