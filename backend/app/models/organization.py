"""
Phase 14: Organization-Aware Threat Intelligence & Attack Simulation — Data Models
Implements internal asset inventories, SBOM adapters, semantic version matching,
explainable risk prioritization, graph attack-path traversal, and D3FEND minimum cut-sets.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class AssetType(str, Enum):
    ENDPOINT = "endpoint"
    SERVER = "server"
    CLOUD_RESOURCE = "cloud_resource"
    APPLICATION = "application"
    CONTAINER = "container"
    IDENTITY = "identity"
    NETWORK_SERVICE = "network_service"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MISSION_CRITICAL = "mission_critical"


class SoftwarePackage(BaseModel):
    name: str
    version: str
    vendor: Optional[str] = None
    cpe23: Optional[str] = None
    license: Optional[str] = None


class CloudResourceDetails(BaseModel):
    provider: Literal["aws", "azure", "gcp", "generic_cloud"]
    account_id: str
    region: str
    resource_arn: Optional[str] = None
    public_exposure: bool = False


class Asset(BaseModel):
    """
    Internal enterprise asset representation with SBOM package bindings,
    network footprint, and tenant ownership.
    """
    asset_id: str
    name: str
    tenant_id: str
    asset_type: AssetType
    ip_addresses: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)
    os: Optional[str] = None
    os_version: Optional[str] = None
    installed_software: List[SoftwarePackage] = Field(default_factory=list)
    cloud_details: Optional[CloudResourceDetails] = None
    external_exposure: bool = False
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    business_services: List[str] = Field(default_factory=list)
    owner: Optional[str] = None
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"
    security_controls: List[str] = Field(default_factory=list)  # e.g. ["EDR", "MFA", "WAF", "Segmentation"]
    import_provenance: str = "Manual_Inventory"
    last_observed: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SBOMFormat(str, Enum):
    CYCLONEDX_JSON = "cyclonedx_json"
    SPDX_JSON = "spdx_json"


class SBOMImportRequest(BaseModel):
    tenant_id: str
    target_asset_id: str
    sbom_format: SBOMFormat
    sbom_content: str  # Raw JSON or string content


class SBOMImportResponse(BaseModel):
    asset_id: str
    tenant_id: str
    packages_imported: int
    components: List[SoftwarePackage]
    import_status: Literal["success", "partial_success", "failed"]
    warnings: List[str] = Field(default_factory=list)


class AssetThreatMatch(BaseModel):
    """
    Semantic match between external threat intelligence and internal asset software/configuration.
    """
    match_id: str
    asset_id: str
    asset_name: str
    tenant_id: str
    threat_entity_id: str
    threat_type: Literal["vulnerability", "technique", "threat_actor", "malware"]
    cve_id: Optional[str] = None
    technique_id: Optional[str] = None
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    vulnerable_range: Optional[str] = None
    affected_version_matched: bool = True
    matching_confidence: float = Field(ge=0.0, le=1.0)
    evidence_rationale: str


class PrioritizedAssetRisk(BaseModel):
    """
    Transparent, decomposed organization risk prioritization score (0 to 100).
    """
    asset_id: str
    asset_name: str
    tenant_id: str
    composite_score: float = Field(ge=0.0, le=100.0)
    priority_tier: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    score_breakdown: Dict[str, float]  # CVSS, EPSS, Exposure, Criticality, ThreatRelevance, ControlDeduction
    uncertainty_bounds: Dict[str, float]  # low, high
    matches: List[AssetThreatMatch]
    recommendations_summary: List[str]


class AttackPathNode(BaseModel):
    id: str
    label: str
    name: str
    asset_id: Optional[str] = None
    threat_id: Optional[str] = None
    is_entry_point: bool = False
    is_critical_asset: bool = False


class AttackPathEdge(BaseModel):
    source: str
    target: str
    relationship_type: str
    technique_id: Optional[str] = None


class AttackPath(BaseModel):
    path_id: str
    tenant_id: str
    entry_asset_id: str
    target_asset_id: str
    steps: List[AttackPathNode]
    edges: List[AttackPathEdge]
    path_length: int
    estimated_exploitability: float = Field(ge=0.0, le=1.0)


class D3fendCutSetRecommendation(BaseModel):
    """
    Mathematically grounded Minimum D3FEND Cut-Set interrupting identified attack paths.
    """
    cut_set_id: str
    tenant_id: str
    defensive_techniques: List[str]  # e.g. ["d3f:ProcessSegmentExecutionPrevention", "d3f:MultiFactorAuthentication"]
    target_assets: List[str]
    interrupted_path_ids: List[str]
    total_paths_blocked: int
    estimated_impact: float = Field(ge=0.0, le=1.0)
    operational_cost: float = Field(ge=0.0, le=1.0)
    alternative_mitigations: List[str]
    uncertainty_disclaimer: str = (
        "Simulated remediation represents graph-theoretic path disruption based on current model assertions. "
        "It does not guarantee real-world risk elimination."
    )
