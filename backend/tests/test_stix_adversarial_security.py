"""
Adversarial Security Test Suite for STIX 2.1 Export & Interoperability
Phase 12A Milestone 2 Hardening (Gates A1 through A7)

Verifies:
- Gate A1: Recipient trust boundary & header spoofing denial (entitlement clamping)
- Gate A2: Cross-tenant bounded export isolation
- Gate A3: Transitive TLP:RED scrubbing (zero leakage of RED UUIDs or incident edges)
- Gate A4: 25MB synchronous response ceiling (HTTP 413)
- Gate A5: Production fail-closed behavior (HTTP 503 on database disruption, no fallback)
- Gate A6: Independent stix2-validator (v3.3.2) conformance verification
- Gate A7: Cypher injection resistance and input sanitization
"""

import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.core.security import create_access_token
from app.services.stix.stix_validator_service import StixValidatorService
from app.services.stix.stix_export_service import (
    STANDARD_STIX_TLP_RED_ID,
    STANDARD_STIX_TLP_WHITE_ID,
    TLP_EXTENSION_DEFINITION_ID,
    StixExportService,
)
from app.services.stix.stix_ingestion_service import StixIngestionService

client = TestClient(app)


# ---------------------------------------------------------------------------
# GATE A1: RECIPIENT TRUST BOUNDARY & HEADER SPOOFING DENIAL
# ---------------------------------------------------------------------------

def test_a1_external_user_spoofing_internal_header_denied_amber_strict():
    """
    Gate A1: An external party (e.g. client/partner analyst) attempts to spoof
    the 'X-Recipient-Org-Internal: true' header to access AMBER+STRICT intelligence.
    The server trust boundary must clamp the capability to external and DENY with HTTP 403.
    """
    from app.api.routes.stix import stix_service

    amber_strict_def_id = "marking-definition--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
    actor_id = "threat-actor--77770000-0000-0000-0000-000000000001"

    seed_bundle = {
        "type": "bundle",
        "id": "bundle--77770000-0000-0000-0000-000000000002",
        "objects": [
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": amber_strict_def_id,
                "created": "2026-02-15T00:00:00.000Z",
                "name": "FIRST TLP:AMBER+STRICT Definition",
                "definition_type": "statement",
                "definition": {"statement": "Internal only"},
                "extensions": {
                    TLP_EXTENSION_DEFINITION_ID: {
                        "extension_type": "property-extension",
                        "first_tlp_label": "AMBER",
                        "strict_restriction": True,
                        "sharing_scope": "organization_only",
                    }
                },
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": "2026-02-15T00:00:00.000Z",
                "modified": "2026-02-15T00:00:00.000Z",
                "name": "Proprietary Threat Actor",
                "object_marking_refs": [amber_strict_def_id],
            },
        ],
    }
    stix_service.ingest_bundle(seed_bundle)

    # External analyst credential with spoofed internal header
    external_token = create_access_token(
        user_id="external-partner-analyst",
        tenant_id="tenant-external",
        role="analyst",
        is_internal_org_member=False,
        is_extension_aware=True,
    )
    headers = {
        "Authorization": f"Bearer {external_token}",
        "X-Recipient-Extension-Aware": "true",
        "X-Recipient-Org-Internal": "true",  # Attempted spoofing!
    }
    response = client.get(f"/api/v1/stix/export/bundle?actor_id={actor_id}", headers=headers)
    assert response.status_code == 403
    assert "TLP:AMBER+STRICT" in response.json().get("detail", "")


# ---------------------------------------------------------------------------
# GATE A2: CROSS-TENANT BOUNDED EXPORT ISOLATION
# ---------------------------------------------------------------------------

def test_a2_cross_tenant_isolation_in_export():
    """
    Gate A2: Multi-tenant boundary verification.
    Tenant A exports a subgraph seeded by their own asset.
    Tenant B's private nodes and relationships must NEVER be included.
    """
    from app.api.routes.stix import stix_service, stix_export_service

    tenant_a_actor = "threat-actor--aaaa0000-0000-0000-0000-000000000001"
    tenant_b_malware = "malware--bbbb0000-0000-0000-0000-000000000002"

    # Populate in-memory mapper directly with tenant tags
    stix_service.mapper.entities_by_stix_id[tenant_a_actor] = {
        "labels": ["ThreatActor"],
        "properties": {
            "id": tenant_a_actor,
            "stix_id": tenant_a_actor,
            "name": "Tenant A Actor",
            "stix_type": "threat-actor",
            "tenant_id": "tenant-alpha",
        },
    }
    stix_service.mapper.entities_by_stix_id[tenant_b_malware] = {
        "labels": ["Malware"],
        "properties": {
            "id": tenant_b_malware,
            "stix_id": tenant_b_malware,
            "name": "Tenant B Proprietary Malware",
            "stix_type": "malware",
            "tenant_id": "tenant-beta",
        },
    }
    # Add relationship attempting to bridge tenants
    rel_id = "relationship--aaaa-bbbb-0000-0000-000000000001"
    stix_service.stored_relationships = [
        {
            "id": rel_id,
            "relationship_type": "uses",
            "source_ref": tenant_a_actor,
            "target_ref": tenant_b_malware,
            "tenant_id": "tenant-beta",  # Private to tenant-beta
        }
    ]

    # Export for tenant-alpha
    bundle = stix_export_service.export_subgraph(
        seed_ids=[tenant_a_actor],
        max_depth=2,
        max_nodes=100,
        tenant_id="tenant-alpha",
    )

    exported_ids = [o["id"] for o in bundle["objects"]]
    assert tenant_a_actor in exported_ids
    assert tenant_b_malware not in exported_ids
    assert rel_id not in exported_ids


# ---------------------------------------------------------------------------
# GATE A3: TRANSITIVE TLP:RED SCRUBBING
# ---------------------------------------------------------------------------

def test_a3_transitive_tlp_red_scrubbing_removes_marking_refs():
    """
    Gate A3: Transitive TLP:RED Scrubbing.
    When a graph contains a GREEN surviving node connected to a RED node,
    the RED node and all incident edges must be pruned.
    Furthermore, any residual references in surviving nodes (e.g. granular markings)
    or edges to RED marking definitions or RED entities must be scrubbed so zero RED UUIDs leak.
    """
    from app.api.routes.stix import stix_service, stix_export_service

    red_marking_id = STANDARD_STIX_TLP_RED_ID
    green_marking_id = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    surviving_actor_id = "threat-actor--66660000-0000-0000-0000-000000000001"
    suppressed_red_tool = "tool--66660000-0000-0000-0000-000000000002"

    stix_service.mapper.entities_by_stix_id[surviving_actor_id] = {
        "labels": ["ThreatActor"],
        "properties": {
            "id": surviving_actor_id,
            "stix_id": surviving_actor_id,
            "name": "Surviving Actor",
            "stix_type": "threat-actor",
            "object_marking_refs": [green_marking_id],
            "granular_markings": [
                {"marking_ref": green_marking_id, "selectors": ["name"]},
                {"marking_ref": red_marking_id, "selectors": ["description"]},
            ],
        },
    }
    stix_service.mapper.entities_by_stix_id[suppressed_red_tool] = {
        "labels": ["Tool"],
        "properties": {
            "id": suppressed_red_tool,
            "stix_id": suppressed_red_tool,
            "name": "Secret Tool",
            "stix_type": "tool",
            "tlp": "RED",
            "object_marking_refs": [red_marking_id],
        },
    }
    rel_id = "relationship--6666-0000-0000-0000-000000000003"
    stix_service.stored_relationships = [
        {
            "id": rel_id,
            "relationship_type": "uses",
            "source_ref": surviving_actor_id,
            "target_ref": suppressed_red_tool,
        }
    ]

    bundle = stix_export_service.export_subgraph(
        seed_ids=[surviving_actor_id],
        max_depth=2,
    )

    exported_ids = [o["id"] for o in bundle["objects"]]
    assert surviving_actor_id in exported_ids
    assert suppressed_red_tool not in exported_ids
    assert rel_id not in exported_ids

    # Find the surviving actor object in the bundle
    surviving_obj = next(o for o in bundle["objects"] if o["id"] == surviving_actor_id)
    marking_refs = surviving_obj.get("object_marking_refs", [])
    assert red_marking_id not in marking_refs

    # Granular markings referencing RED must be scrubbed
    gm_refs = [gm["marking_ref"] for gm in surviving_obj.get("granular_markings", [])]
    assert red_marking_id not in gm_refs


# ---------------------------------------------------------------------------
# GATE A4: 25MB SYNCHRONOUS RESPONSE CEILING
# ---------------------------------------------------------------------------

def test_a4_export_payload_exceeding_25mb_raises_413():
    """
    Gate A4: Payload ceiling enforcement.
    If the serialized STIX bundle exceeds 25MB, the service must raise HTTP 413.
    """
    from app.services.stix.stix_export_service import StixExportService
    from fastapi import HTTPException

    service = StixExportService()
    # Create large dummy node list that exceeds 25MB
    large_description = "A" * (1024 * 1024)  # 1 MB string
    large_nodes = [
        {
            "labels": ["ThreatActor"],
            "properties": {
                "id": f"threat-actor--{i:08d}-0000-0000-0000-000000000000",
                "name": f"Actor {i}",
                "description": large_description,
                "stix_type": "threat-actor",
            },
        }
        for i in range(26)  # 26 MB
    ]

    with pytest.raises(HTTPException) as exc_info:
        service.serialize_bundle(nodes=large_nodes, relationships=[], marking_defs={})

    assert exc_info.value.status_code == 413
    assert "25MB" in exc_info.value.detail


# ---------------------------------------------------------------------------
# GATE A5: PRODUCTION FAIL-CLOSED BEHAVIOR
# ---------------------------------------------------------------------------

def test_a5_production_mode_fails_closed_on_database_disruption(monkeypatch):
    """
    Gate A5: In production environment, Neo4j disconnection must raise HTTP 503
    rather than silently falling back to in-memory store.
    """
    from app.services.stix.stix_export_service import StixExportService
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    # Mock graph_service that reports disconnected
    class MockDisconnectedGraphService:
        def is_connected(self):
            return False

    service = StixExportService(graph_service=MockDisconnectedGraphService())

    with pytest.raises(HTTPException) as exc_info:
        service.extract_bounded_subgraph(seed_ids=["threat-actor--1234-0000-0000-0000"])

    assert exc_info.value.status_code == 503
    assert "Database service unavailable" in exc_info.value.detail
    assert "In-memory fallback is disabled in production mode" in exc_info.value.detail


# ---------------------------------------------------------------------------
# GATE A6: INDEPENDENT STIX2-VALIDATOR (v3.3.2) CONFORMANCE
# ---------------------------------------------------------------------------

def test_a6_exported_bundle_passes_oasis_stix2validator():
    """
    Gate A6: Validates that bundles exported by ThreatMind AI pass OASIS stix2-validator.
    """
    from app.api.routes.stix import stix_service, stix_export_service

    actor_id = "threat-actor--5b5978a2-2591-4475-bf51-c0a6b7d5bf2a"
    stix_service.mapper.entities_by_stix_id[actor_id] = {
        "labels": ["ThreatActor"],
        "properties": {
            "id": actor_id,
            "stix_id": actor_id,
            "name": "Validated Threat Actor",
            "stix_type": "threat-actor",
            "created": "2026-02-15T00:00:00.000Z",
            "modified": "2026-02-15T00:00:00.000Z",
        },
    }

    bundle = stix_export_service.export_subgraph(seed_ids=[actor_id])

    validator = StixValidatorService(strict=False)
    val_res = validator.validate_bundle_dict(bundle)

    assert val_res["is_valid"] is True, f"Validation errors: {val_res['errors']}"
    assert len(val_res["errors"]) == 0


# ---------------------------------------------------------------------------
# GATE A7: ADVERSARIAL ATTACKS & CYPHER INJECTION RESISTANCE
# ---------------------------------------------------------------------------

def test_a7_cypher_injection_in_seeds_denied_or_safely_parameterized():
    """
    Gate A7: Parameter tampering / injection attempts in seed IDs or query parameters
    must be safely handled without SQL/Cypher injection.
    """
    malicious_seeds = [
        "threat-actor--1234' OR '1'='1",
        "'; MATCH (n) DETACH DELETE n; //",
        "threat-actor--1234' UNION MATCH (s) RETURN s //",
    ]

    analyst_token = create_access_token(user_id="analyst-user", tenant_id="tenant-default", role="analyst")
    for seed in malicious_seeds:
        response = client.get(
            f"/api/v1/stix/export/bundle?actor_id={seed}",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        # Should either return empty bundle (status 200) or safe 400/404, never 500 error from syntax crash
        assert response.status_code in (200, 400, 404)
        if response.status_code == 200:
            bundle = response.json()
            assert bundle.get("type") == "bundle"
            # Injected query did not dump all nodes
            assert len(bundle.get("objects", [])) <= 1
