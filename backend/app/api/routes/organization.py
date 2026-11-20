"""
API routes for Phase 14 ThreatMind Organization-Aware Threat Intelligence & Attack Simulation.
Provides endpoints for asset inventory management, SBOM parsing, SemVer threat matching,
transparent risk prioritization, graph attack path discovery, and minimum D3FEND cut-set calculation.
Enforces authenticated tenant derivation and anti-spoofing boundaries on every endpoint.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.core.security import AuthenticatedUser, verify_authentication
from app.models.organization import (
    Asset,
    AssetCriticality,
    AssetThreatMatch,
    AssetType,
    AttackPath,
    D3fendCutSetRecommendation,
    PrioritizedAssetRisk,
    SBOMFormat,
    SBOMImportRequest,
    SBOMImportResponse,
)
from app.services.organization import (
    AssetInventoryService,
    AssetThreatMatcher,
    AttackPathService,
    RemediationCutSetService,
    RiskPrioritizationEngine,
)

router = APIRouter(prefix="/organization", tags=["Organization-Aware Intelligence"])

# In-memory singleton service instances
inventory_service = AssetInventoryService()
matcher = AssetThreatMatcher()
prioritization_engine = RiskPrioritizationEngine()
attack_path_service = AttackPathService()
cutset_service = RemediationCutSetService()


class ThreatAdvisoryItem(BaseModel):
    cve_id: str
    package_name: str
    vulnerable_range: str
    threat_entity_id: Optional[str] = None


class AdvisoryMatchRequest(BaseModel):
    advisories: List[ThreatAdvisoryItem]


class AttackPathRequest(BaseModel):
    lateral_connections: List[List[str]] = Field(default_factory=list)  # [[src, tgt, rel]]
    threat_mappings: List[Dict[str, str]] = Field(default_factory=list)
    custom_entry_ids: Optional[List[str]] = None
    custom_target_ids: Optional[List[str]] = None


class CutSetRequest(BaseModel):
    attack_paths: List[AttackPath]


@router.post("/assets", response_model=Asset, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset: Asset,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Asset:
    """Register or update an enterprise asset under strict tenant ownership."""
    effective_tenant = current_user.tenant_id
    if asset.tenant_id and asset.tenant_id != effective_tenant and not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Cannot create asset for tenant '{asset.tenant_id}' with authenticated tenant '{effective_tenant}'.",
        )
    asset.tenant_id = effective_tenant
    return inventory_service.register_asset(asset)


@router.get("/assets", response_model=List[Asset])
async def list_assets(
    asset_type: Optional[AssetType] = Query(None),
    criticality: Optional[str] = Query(None),
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> List[Asset]:
    """List assets strictly isolated to the requesting authenticated tenant."""
    return inventory_service.list_assets(
        tenant_id=current_user.tenant_id,
        asset_type=asset_type,
        criticality=criticality,
    )


@router.get("/assets/{asset_id}", response_model=Asset)
async def get_asset(
    asset_id: str,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Asset:
    """Retrieve an asset by ID with tenant isolation verification."""
    asset = inventory_service.get_asset(asset_id, tenant_id=current_user.tenant_id)
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"Asset {asset_id} not found in tenant {current_user.tenant_id}.",
        )
    return asset


@router.post("/assets/sbom", response_model=SBOMImportResponse)
async def import_sbom(
    request: SBOMImportRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> SBOMImportResponse:
    """
    Import CycloneDX or SPDX SBOM components into an asset's installed software inventory.
    """
    if request.tenant_id != current_user.tenant_id and not current_user.is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"SBOM import tenant '{request.tenant_id}' violates auth tenant '{current_user.tenant_id}'.",
        )
    response = inventory_service.import_sbom(request)
    if response.import_status == "failed":
        raise HTTPException(status_code=400, detail="; ".join(response.warnings))
    return response


@router.post("/match", response_model=List[AssetThreatMatch])
async def match_threats(
    request: AdvisoryMatchRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> List[AssetThreatMatch]:
    """
    Evaluate tenant assets against vulnerability advisories using SemVer range logic.
    Rejects naive substring matching.
    """
    assets = inventory_service.list_assets(tenant_id=current_user.tenant_id)

    advisories_dict = [a.model_dump() for a in request.advisories]
    all_matches: List[AssetThreatMatch] = []
    for asset in assets:
        matches = matcher.scan_asset_against_advisories(asset, advisories_dict)
        all_matches.extend(matches)
    return all_matches


@router.get("/prioritization", response_model=List[PrioritizedAssetRisk])
async def get_prioritized_risks(
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> List[PrioritizedAssetRisk]:
    """
    Compute decomposed organization-specific risk scores for all assets in tenant scope.
    """
    assets = inventory_service.list_assets(tenant_id=current_user.tenant_id)

    risks: List[PrioritizedAssetRisk] = []
    for asset in assets:
        risk = prioritization_engine.calculate_asset_risk(
            asset=asset,
            matches=[],
            cvss_base=7.0 if asset.external_exposure else 4.0,
            epss_probability=0.4 if asset.external_exposure else 0.1,
            threat_actor_relevance=60.0,
        )
        risks.append(risk)

    risks.sort(key=lambda r: r.composite_score, reverse=True)
    return risks


@router.post("/attack-paths", response_model=List[AttackPath])
async def discover_attack_paths(
    req: AttackPathRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> List[AttackPath]:
    """
    Discover bounded, cycle-free attack paths traversing from entry assets to critical targets.
    """
    assets = inventory_service.list_assets(tenant_id=current_user.tenant_id)

    lateral = [tuple(conn) for conn in req.lateral_connections]  # type: ignore
    graph = attack_path_service.build_network_graph(
        tenant_id=current_user.tenant_id,
        assets=assets,
        lateral_connections=lateral,  # type: ignore
        threat_mappings=req.threat_mappings,
    )

    paths = attack_path_service.find_attack_paths(
        tenant_id=current_user.tenant_id,
        graph=graph,
        custom_entry_ids=req.custom_entry_ids,
        custom_target_ids=req.custom_target_ids,
    )
    return paths


@router.post("/remediation/cut-set", response_model=D3fendCutSetRecommendation)
async def compute_minimum_cut_set(
    req: CutSetRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> D3fendCutSetRecommendation:
    """
    Compute the Minimum D3FEND Cut-Set disrupting all provided attack paths.
    Validates recommendations against the frozen MITRE D3FEND catalog.
    """
    return cutset_service.calculate_minimum_cut_set(
        tenant_id=current_user.tenant_id,
        attack_paths=req.attack_paths,
    )
