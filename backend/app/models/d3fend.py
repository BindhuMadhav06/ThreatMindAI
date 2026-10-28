from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class D3fendTactic(str, Enum):
    MODEL = "Model"
    HARDEN = "Harden"
    DETECT = "Detect"
    ISOLATE = "Isolate"
    DECEIVE = "Deceive"
    EVICT = "Evict"
    RESTORE = "Restore"

class ApplicabilityClassification(str, Enum):
    OFFICIALLY_MAPPED = "officially_mapped"
    POTENTIALLY_RELEVANT = "potentially_relevant"
    REQUIRES_ENVIRONMENT_REVIEW = "requires_environment_review"

class D3fendCountermeasure(BaseModel):
    id: str = Field(..., description="Canonical D3FEND technique identifier, e.g. d3f:ProcessSpawnAnalysis")
    name: str = Field(..., description="Countermeasure title, e.g. Process Spawn Analysis")
    tactic: D3fendTactic = Field(..., description="Defensive tactic classification")
    definition: str = Field(..., description="Formal technical definition from MITRE D3FEND")
    official_url: Optional[str] = Field(default="", description="Canonical MITRE D3FEND reference URI, or empty string for application-defined countermeasures")

class DefensiveRecommendation(BaseModel):
    original_framework_id: str = Field(..., description="Source framework and identifier, e.g. ATT&CK:T1059.001")
    attack_technique_id: str = Field(..., description="Observed offensive MITRE ATT&CK ID, e.g. T1059.001")
    attack_technique_name: str = Field(..., description="Offensive technique title, e.g. PowerShell")
    mitigation_id: Optional[str] = Field(None, description="ATT&CK mitigation intermediary, e.g. M1047")
    mitigation_name: Optional[str] = Field(None, description="ATT&CK mitigation title, e.g. Audit")
    mapping_relationship: str = Field(default="mitigates_and_maps_to", description="Relationship connecting offensive to defensive framework")
    mapping_direction: str = Field(default="offensive_to_defensive", description="Defensive alignment direction")
    countermeasure: D3fendCountermeasure = Field(..., description="Mapped D3FEND defensive technique")
    applicability: ApplicabilityClassification = Field(..., description="Classification: officially_mapped, potentially_relevant, requires_environment_review")
    mapping_provenance: str = Field(..., description="Authoritative mapping provenance reference")
    source_version: str = Field(default="d3fend-v0.14.0-attack-v14.1", description="Catalog release/snapshot version")
    retrieval_date: str = Field(default="2024-04-15", description="Retrieval snapshot date")
    rationale: str = Field(..., description="Technical rationale connecting the attack behavior to defense")
    environment_limitations: str = Field(..., description="Operational boundaries and prerequisites for deployment")

class DefensiveResponse(BaseModel):
    target_techniques: List[str] = Field(default_factory=list, description="Requested ATT&CK technique IDs")
    recommendations: List[DefensiveRecommendation] = Field(default_factory=list)
    summary_by_tactic: Dict[str, int] = Field(default_factory=dict)
    summary_by_applicability: Dict[str, int] = Field(default_factory=dict)
    catalog_version: str
    snapshot_date: str
    catalog_sha256: str
    disclaimer: str = Field(
        default="MITRE D3FEND is a defensive knowledge base; mappings do not guarantee effectiveness, "
                "prescribe controls, or establish environmental sufficiency without analyst verification."
    )
