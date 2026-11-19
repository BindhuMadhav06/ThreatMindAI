"""
SigmaHQ Detection Rule Models
Phase 12B Detection Engineering Implementation

Complies with SigmaHQ v2.1.0 specification and defines
sidecar provenance structures ensuring zero schema pollution
in the detection condition block.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class SigmaRuleLogSource(BaseModel):
    category: Optional[str] = None
    product: Optional[str] = None
    service: Optional[str] = None
    definition: Optional[str] = None


class ThreatMindProvenance(BaseModel):
    """
    Evidence lineage sidecar preserved outside the detection condition
    to strictly prevent schema pollution per Phase 12B specification.
    """
    rule_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_entity_id: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactics: List[str] = Field(default_factory=list)
    d3fend_countermeasures: List[str] = Field(default_factory=list)
    evidence_text_snippets: List[str] = Field(default_factory=list)
    graph_node_ids: List[str] = Field(default_factory=list)
    confidence_score: float = 0.90
    generator: str = "ThreatMind Detection Engineering Engine v1.0"
    review_status: Literal["draft", "under_review", "approved", "rejected"] = "draft"
    review_notes: List[str] = Field(default_factory=list)
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None


class SigmaRule(BaseModel):
    """
    OASIS / SigmaHQ v2.1.0 Rule Container with ThreatMind sidecar provenance.
    """
    title: str
    id: str
    status: Literal["experimental", "test", "stable", "deprecated", "unsupported"] = "experimental"
    description: str
    references: List[str] = Field(default_factory=list)
    author: str = "ThreatMind AI"
    date: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y/%m/%d"))
    modified: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    logsource: SigmaRuleLogSource
    detection: Dict[str, Any]
    fields: Optional[List[str]] = None
    falsepositives: List[str] = Field(default_factory=list)
    level: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    threatmind_provenance: Optional[ThreatMindProvenance] = None
    raw_yaml: Optional[str] = None


class SigmaRuleGenerateRequest(BaseModel):
    technique_id: str  # e.g., "T1059.001"
    technique_name: Optional[str] = None
    evidence_text: Optional[str] = None
    graph_node_ids: Optional[List[str]] = Field(default_factory=list)
    d3fend_countermeasures: Optional[List[str]] = Field(default_factory=list)
    level: Optional[Literal["informational", "low", "medium", "high", "critical"]] = "high"
    logsource_category: Optional[str] = "process_creation"
    logsource_product: Optional[str] = "windows"


class SigmaRuleValidateRequest(BaseModel):
    yaml_content: str


class SigmaRuleReviewRequest(BaseModel):
    review_status: Literal["draft", "under_review", "approved", "rejected"]
    reviewer: str
    notes: Optional[str] = None
