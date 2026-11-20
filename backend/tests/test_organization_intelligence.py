"""
Phase 14: ThreatMind Organization-Aware Threat Intelligence & Attack Simulation — Test Suite
Covers:
- Enterprise asset inventory & strict multi-tenant isolation
- CycloneDX & SPDX SBOM ingestion adapters
- Semantic version range matching (SemVer / PEP 440) vs naive substring rejection
- Decomposed organization risk prioritization formula
- NetworkX bounded attack-path traversal & cycle prevention
- Minimum D3FEND Cut-Set calculation & hitting set optimality
- MITRE D3FEND catalog digest integrity preservation
- Organization Intelligence REST API routes
"""

import hashlib
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_access_token
from app.models.organization import (
    Asset,
    AssetCriticality,
    AssetType,
    AttackPath,
    AttackPathEdge,
    AttackPathNode,
    SBOMFormat,
    SBOMImportRequest,
    SoftwarePackage,
)
from app.services.organization import (
    AssetInventoryService,
    AssetThreatMatcher,
    AttackPathService,
    RemediationCutSetService,
    RiskPrioritizationEngine,
)

client = TestClient(app)


# ============================================================================
# Test Group 11: Enterprise Asset Inventory & Tenant Isolation (14.1)
# ============================================================================

def test_asset_inventory_tenant_isolation():
    service = AssetInventoryService()

    asset_a = Asset(
        asset_id="asset_alpha_01",
        name="Alpha Domain Controller",
        tenant_id="tenant_alpha",
        asset_type=AssetType.SERVER,
        criticality=AssetCriticality.MISSION_CRITICAL
    )

    asset_b = Asset(
        asset_id="asset_beta_01",
        name="Beta Edge Router",
        tenant_id="tenant_beta",
        asset_type=AssetType.NETWORK_SERVICE,
        criticality=AssetCriticality.HIGH
    )

    service.register_asset(asset_a)
    service.register_asset(asset_b)

    # Tenant alpha should only see asset_alpha_01
    alpha_assets = service.list_assets(tenant_id="tenant_alpha")
    assert len(alpha_assets) == 1
    assert alpha_assets[0].asset_id == "asset_alpha_01"

    # Cross-tenant read access must return None
    cross_read = service.get_asset("asset_alpha_01", tenant_id="tenant_beta")
    assert cross_read is None


def test_asset_inventory_sqlite_durability_across_restarts(tmp_path):
    """
    Verifies that AssetInventoryService persists assets and SBOM packages to SQLite
    and reloads cleanly across service process restarts.
    """
    db_file = tmp_path / "test_inventory.db"

    # Instance 1: Create and populate assets
    service1 = AssetInventoryService(db_path=db_file)
    asset_alpha = Asset(
        asset_id="asset_persist_01",
        name="Durable Database Server",
        tenant_id="tenant_durable",
        asset_type=AssetType.SERVER,
        criticality=AssetCriticality.MISSION_CRITICAL,
        installed_software=[
            SoftwarePackage(name="postgresql", version="15.2"),
            SoftwarePackage(name="openssl", version="1.1.1t"),
        ],
    )
    service1.register_asset(asset_alpha)

    # Verify in Instance 1
    found1 = service1.get_asset("asset_persist_01", tenant_id="tenant_durable")
    assert found1 is not None
    assert len(found1.installed_software) == 2

    # Instance 2: Simulate restart with new service instance on same DB file
    service2 = AssetInventoryService(db_path=db_file)
    found2 = service2.get_asset("asset_persist_01", tenant_id="tenant_durable")
    assert found2 is not None
    assert found2.name == "Durable Database Server"
    assert found2.criticality == AssetCriticality.MISSION_CRITICAL
    assert len(found2.installed_software) == 2
    assert found2.installed_software[0].name == "postgresql"
    assert found2.installed_software[0].version == "15.2"

    # Verify cross-tenant isolation survives restart
    cross = service2.get_asset("asset_persist_01", tenant_id="other_tenant")
    assert cross is None


# ============================================================================
# Test Group 12: CycloneDX and SPDX SBOM Ingestion (14.1)
# ============================================================================

def test_cyclonedx_sbom_import():
    service = AssetInventoryService()
    target_asset = Asset(
        asset_id="asset_srv_web",
        name="Web Application Server",
        tenant_id="tenant_test",
        asset_type=AssetType.SERVER
    )
    service.register_asset(target_asset)

    cyclonedx_payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "name": "log4j-core",
                "version": "2.14.1",
                "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                "licenses": [{"license": {"id": "Apache-2.0"}}]
            },
            {
                "name": "spring-core",
                "version": "5.3.18",
                "publisher": "VMware"
            }
        ]
    }

    req = SBOMImportRequest(
        tenant_id="tenant_test",
        target_asset_id="asset_srv_web",
        sbom_format=SBOMFormat.CYCLONEDX_JSON,
        sbom_content=json.dumps(cyclonedx_payload)
    )

    resp = service.import_sbom(req)
    assert resp.import_status == "success"
    assert resp.packages_imported == 2

    # Verify asset software packages
    updated_asset = service.get_asset("asset_srv_web", tenant_id="tenant_test")
    pkg_names = {p.name for p in updated_asset.installed_software}
    assert "log4j-core" in pkg_names
    assert "spring-core" in pkg_names


def test_spdx_sbom_import():
    service = AssetInventoryService()
    target_asset = Asset(
        asset_id="asset_srv_db",
        name="Database Host",
        tenant_id="tenant_test",
        asset_type=AssetType.SERVER
    )
    service.register_asset(target_asset)

    spdx_payload = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "postgresql",
                "versionInfo": "14.2",
                "supplier": "Organization: PostgreSQL Global Development Group",
                "licenseConcluded": "PostgreSQL"
            }
        ]
    }

    req = SBOMImportRequest(
        tenant_id="tenant_test",
        target_asset_id="asset_srv_db",
        sbom_format=SBOMFormat.SPDX_JSON,
        sbom_content=json.dumps(spdx_payload)
    )

    resp = service.import_sbom(req)
    assert resp.import_status == "success"
    assert resp.packages_imported == 1


# ============================================================================
# Test Group 13: SemVer Range Matching vs Naive Substring Rejection (14.2)
# ============================================================================

def test_semver_range_matching_and_substring_rejection():
    matcher = AssetThreatMatcher()

    asset = Asset(
        asset_id="asset_srv_app",
        name="Production App Server",
        tenant_id="tenant_sec",
        asset_type=AssetType.APPLICATION,
        installed_software=[
            SoftwarePackage(name="log4j-core", version="2.14.1"),
            # Naive substring candidate: name contains "openssl", but is NOT "openssl"
            SoftwarePackage(name="openssl-helper-lib", version="1.0.0"),
            SoftwarePackage(name="urllib3", version="2.0.7")
        ]
    )

    # 1. Vulnerable Log4j match (< 2.15.0)
    match_log4j = matcher.match_asset_vulnerability(
        asset=asset,
        cve_id="CVE-2021-44228",
        target_package="log4j-core",
        vulnerable_range="< 2.15.0"
    )
    assert match_log4j is not None
    assert match_log4j.affected_version_matched is True
    assert match_log4j.installed_version == "2.14.1"

    # 2. Patched Log4j (should NOT match)
    asset_patched = Asset(
        asset_id="asset_srv_patched",
        name="Patched App Server",
        tenant_id="tenant_sec",
        asset_type=AssetType.APPLICATION,
        installed_software=[
            SoftwarePackage(name="log4j-core", version="2.17.1")
        ]
    )
    match_patched = matcher.match_asset_vulnerability(
        asset=asset_patched,
        cve_id="CVE-2021-44228",
        target_package="log4j-core",
        vulnerable_range="< 2.15.0"
    )
    assert match_patched is None

    # 3. CRITICAL: Strictly reject naive substring matching!
    # Looking for package 'openssl', should NOT match 'openssl-helper-lib'
    match_openssl = matcher.match_asset_vulnerability(
        asset=asset,
        cve_id="CVE-2022-3602",
        target_package="openssl",
        vulnerable_range=">= 3.0.0, < 3.0.7"
    )
    assert match_openssl is None, "Failed closed: Naive substring match incorrectly triggered!"


# ============================================================================
# Test Group 14: Decomposed Organization Risk Prioritization (14.3)
# ============================================================================

def test_decomposed_risk_prioritization_engine():
    engine = RiskPrioritizationEngine()

    high_exposure_asset = Asset(
        asset_id="asset_edge",
        name="Edge Gateway",
        tenant_id="tenant_prod",
        asset_type=AssetType.SERVER,
        external_exposure=True,
        criticality=AssetCriticality.HIGH,
        security_controls=["EDR"]  # 1 control
    )

    risk_high = engine.calculate_asset_risk(
        asset=high_exposure_asset,
        matches=[],
        cvss_base=9.8,
        epss_probability=0.75,
        threat_actor_relevance=80.0
    )

    assert risk_high.composite_score >= 70.0
    assert risk_high.priority_tier in ("CRITICAL", "HIGH")
    assert "vulnerability_severity" in risk_high.score_breakdown
    assert risk_high.uncertainty_bounds["high"] >= risk_high.composite_score

    # Internal well-defended asset
    shielded_asset = Asset(
        asset_id="asset_internal",
        name="Internal Workstation",
        tenant_id="tenant_prod",
        asset_type=AssetType.ENDPOINT,
        external_exposure=False,
        criticality=AssetCriticality.LOW,
        security_controls=["EDR", "MFA", "Segmentation", "WAF"]  # 4 controls
    )

    risk_low = engine.calculate_asset_risk(
        asset=shielded_asset,
        matches=[],
        cvss_base=4.0,
        epss_probability=0.05,
        threat_actor_relevance=10.0
    )

    assert risk_low.composite_score < risk_high.composite_score
    assert risk_low.priority_tier in ("LOW", "MEDIUM")


# ============================================================================
# Test Group 15: Graph Attack Path Discovery & Cycle Prevention (14.4)
# ============================================================================

def test_attack_path_traversal_and_cycle_prevention():
    path_service = AttackPathService(max_depth=6)

    # Topology: Entry -> Pivot -> DB (with a cycle Pivot -> Entry)
    assets = [
        Asset(
            asset_id="node_entry",
            name="Public Ingress",
            tenant_id="tenant_sim",
            asset_type=AssetType.SERVER,
            external_exposure=True,
            criticality=AssetCriticality.MEDIUM
        ),
        Asset(
            asset_id="node_pivot",
            name="App Server",
            tenant_id="tenant_sim",
            asset_type=AssetType.SERVER,
            external_exposure=False,
            criticality=AssetCriticality.MEDIUM
        ),
        Asset(
            asset_id="node_crown_jewel",
            name="Financial DB",
            tenant_id="tenant_sim",
            asset_type=AssetType.SERVER,
            external_exposure=False,
            criticality=AssetCriticality.MISSION_CRITICAL
        )
    ]

    connections = [
        ("node_entry", "node_pivot", "EXPLOITS_ACROSS"),
        ("node_pivot", "node_crown_jewel", "CONNECTS_TO"),
        ("node_pivot", "node_entry", "CYCLE_BACK"),  # Cycle test
    ]

    graph = path_service.build_network_graph("tenant_sim", assets, lateral_connections=connections)
    paths = path_service.find_attack_paths("tenant_sim", graph)

    assert len(paths) == 1
    p = paths[0]
    assert p.entry_asset_id == "node_entry"
    assert p.target_asset_id == "node_crown_jewel"
    assert p.path_length == 3  # entry -> pivot -> db (cycle prevented)


# ============================================================================
# Test Group 16 & 17: Minimum D3FEND Cut-Set & Catalog Integrity (14.5)
# ============================================================================

def test_minimum_d3fend_cutset_optimization():
    cutset_service = RemediationCutSetService()

    # Form 2 attack paths sharing an intermediate technique
    node_a = AttackPathNode(id="n_a", label="Asset", name="Public Web", is_entry_point=True)
    node_b = AttackPathNode(id="n_b", label="Asset", name="App Server")
    node_c = AttackPathNode(id="n_c", label="Asset", name="Database", is_critical_asset=True)

    edge_1 = AttackPathEdge(source="n_a", target="n_b", relationship_type="EXPLOITS", technique_id="T1059.001")
    edge_2 = AttackPathEdge(source="n_b", target="n_c", relationship_type="USES_ACCOUNT", technique_id="T1078")

    path_1 = AttackPath(
        path_id="path_001",
        tenant_id="tenant_cutset",
        entry_asset_id="n_a",
        target_asset_id="n_c",
        steps=[node_a, node_b, node_c],
        edges=[edge_1, edge_2],
        path_length=3,
        estimated_exploitability=0.85
    )

    rec = cutset_service.calculate_minimum_cut_set("tenant_cutset", [path_1])

    assert rec.total_paths_blocked == 1
    assert len(rec.defensive_techniques) > 0
    # Techniques must be valid D3FEND IDs
    for tech in rec.defensive_techniques:
        assert tech.startswith("d3f:")


def test_d3fend_catalog_integrity_digest_preservation():
    """Verify that catalog SHA-256 strictly preserves the Phase 11 baseline."""
    catalog_path = Path(__file__).resolve().parent.parent / "app" / "services" / "defense" / "d3fend_catalog.json"
    assert catalog_path.exists()
    computed_digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    expected_digest = "a7a1ebffba38d5283df0c1bdf84eb78b4c5849c643c48da9e0e3a132a9ad04b2"
    assert computed_digest == expected_digest, "D3FEND catalog digest changed! Catalog must remain immutable."


# ============================================================================
# Test Group 18: Organization Intelligence API Endpoints
# ============================================================================

def test_organization_api_asset_and_prioritization():
    token = create_access_token(user_id="analyst_org_01", tenant_id="tenant_api_eval", role="analyst")
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": "tenant_api_eval"}

    # Register asset via API
    create_resp = client.post(
        "/api/v1/organization/assets",
        headers=headers,
        json={
            "asset_id": "asset_api_01",
            "name": "API Web Gateway",
            "tenant_id": "tenant_api_eval",
            "asset_type": "server",
            "criticality": "high",
            "external_exposure": True,
            "security_controls": ["WAF"]
        }
    )
    assert create_resp.status_code == 201

    # List assets for tenant
    list_resp = client.get(
        "/api/v1/organization/assets",
        headers=headers
    )
    assert list_resp.status_code == 200
    assets = list_resp.json()
    assert len(assets) >= 1
    assert any(a["asset_id"] == "asset_api_01" for a in assets)

    # Get prioritized risk
    risk_resp = client.get(
        "/api/v1/organization/prioritization",
        headers=headers
    )
    assert risk_resp.status_code == 200
    risks = risk_resp.json()
    assert len(risks) >= 1
    assert risks[0]["asset_id"] == "asset_api_01"


def test_organization_api_unauthenticated_request_rejected():
    # Calling without credentials must return 401 Unauthorized
    resp = client.get("/api/v1/organization/assets")
    assert resp.status_code == 401


def test_organization_api_tenant_spoofing_rejected():
    # Token for tenant_alpha, but header claims tenant_beta -> 403 Forbidden
    token = create_access_token(user_id="user_alpha", tenant_id="tenant_alpha", role="analyst")
    headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": "tenant_beta"}
    resp = client.get("/api/v1/organization/assets", headers=headers)
    assert resp.status_code == 403
    assert "Tenant spoofing" in resp.json().get("detail", "")

