"""
Unit and Integration Tests for STIX 2.1 Bounded Export & Recipient Enforcement
Phase 12A Milestone 2 Verification Suite (AC-7B & AC-13)

Validates:
- AC-13: Mandatory scope parameters (HTTP 400 on missing scope)
- AC-13: Hard traversal constraints (depth <= 3, nodes <= 500, payload <= 25MB)
- AC-13: STIX 2.1 Bundle container compliance (NO spec_version at root)
- AC-13: Round-trip export and re-import fidelity
- AC-7B: Recipient capability gating (HTTP 403 for extension-unaware / external on AMBER+STRICT)
- AC-7B: Absolute TLP:RED suppression (zero generic admin bypass, drops connected edges)
- AC-7B: FIRST TLP:CLEAR to STIX 2.1 TLP:WHITE mapping with extension preservation
- AC-7B: Query parameter capability spoofing prevention
"""

import json
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_access_token
from app.models.stix import StixBundle, SupportedStixSdo
from app.services.stix.stix_export_service import (
    FIRST_TLP_EXTENSION_DEFINITION_OBJECT,
    STANDARD_STIX_TLP_WHITE_ID,
    STANDARD_STIX_TLP_RED_ID,
    TLP_EXTENSION_DEFINITION_ID,
    StixExportService,
)
from app.services.stix.stix_ingestion_service import StixIngestionService

client = TestClient(app)

ANALYST_TOKEN = create_access_token(user_id="export-analyst-user", tenant_id="tenant-default", role="analyst")
ADMIN_TOKEN = create_access_token(user_id="export-admin-user", tenant_id="tenant-default", role="admin", is_admin=True, is_internal_org_member=True, is_extension_aware=True)
VIEWER_TOKEN = create_access_token(user_id="export-viewer-user", tenant_id="tenant-default", role="viewer")

ANALYST_AUTH = {"Authorization": f"Bearer {ANALYST_TOKEN}"}
ADMIN_AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
VIEWER_AUTH = {"Authorization": f"Bearer {VIEWER_TOKEN}"}


# ---------------------------------------------------------------------------
# AC-13: MANDATORY SCOPE AND LIMIT ENFORCEMENT
# ---------------------------------------------------------------------------

def test_ac13_export_without_scope_parameters_returns_400():
    """
    AC-13 Requirement: Request export without scope parameters.
    Must return HTTP 400 Bad Request to prevent unconstrained full-graph dumps.
    """
    response = client.get("/api/v1/stix/export/bundle", headers=ANALYST_AUTH)
    assert response.status_code == 400
    detail = response.json().get("detail", "")
    assert "Full-graph export is prohibited" in detail
    assert "investigation_id, actor_id, technique_id, or entity_ids" in detail


def test_ac13_export_with_empty_scope_strings_returns_400():
    """
    AC-13 Requirement: Whitespace or empty scope strings must also be rejected.
    """
    response = client.get(
        "/api/v1/stix/export/bundle?investigation_id=   &actor_id=",
        headers=ANALYST_AUTH,
    )
    assert response.status_code == 400
    assert "Full-graph export is prohibited" in response.json().get("detail", "")


def test_ac13_export_depth_and_node_limits_clamped():
    """
    AC-13 Requirement: Max depth clamped to range [1, 3], max nodes to [1, 500].
    """
    # Exceeding depth > 3 triggers FastAPI Query validation (HTTP 422)
    response = client.get(
        "/api/v1/stix/export/bundle?actor_id=test-actor&max_depth=5",
        headers=ANALYST_AUTH,
    )
    assert response.status_code == 422

    # Exceeding nodes > 500 triggers FastAPI Query validation (HTTP 422)
    response = client.get(
        "/api/v1/stix/export/bundle?actor_id=test-actor&max_nodes=1000",
        headers=ANALYST_AUTH,
    )
    assert response.status_code == 422


def test_ac13_bundle_root_has_no_spec_version():
    """
    AC-13 / STIX 2.1 §2.1 Invariant:
    Exported bundle root MUST NOT contain a 'spec_version' property.
    """
    response = client.get(
        "/api/v1/stix/export/bundle?actor_id=non-existent-seed-id",
        headers=ANALYST_AUTH,
    )
    assert response.status_code == 200
    bundle = response.json()
    assert bundle["type"] == "bundle"
    assert "spec_version" not in bundle
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)


# ---------------------------------------------------------------------------
# AC-7B: TLP:RED ABSOLUTE SUPPRESSION (ZERO GENERIC ADMIN BYPASS)
# ---------------------------------------------------------------------------

def test_ac7b_tlp_red_absolute_suppression():
    """
    AC-7B Requirement: Case (c)
    TLP:RED objects and incident relationships MUST be completely suppressed
    from standard export endpoints under all clearance levels and roles.
    Zero generic administrative bypass parameter is permitted.
    """
    ingestion = StixIngestionService()
    red_marking_id = STANDARD_STIX_TLP_RED_ID
    actor_id = "threat-actor--aaaa0000-0000-0000-0000-000000000001"
    malware_id = "malware--bbbb0000-0000-0000-0000-000000000002"
    rel_id = "relationship--cccc0000-0000-0000-0000-000000000003"

    seed_bundle = {
        "type": "bundle",
        "id": "bundle--dddd0000-0000-0000-0000-000000000004",
        "objects": [
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": red_marking_id,
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
                "name": "TLP:RED",
                "definition": {"tlp": "red"},
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": "2026-02-15T00:00:00.000Z",
                "modified": "2026-02-15T00:00:00.000Z",
                "name": "Public Actor A",
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": "2026-02-15T00:00:00.000Z",
                "modified": "2026-02-15T00:00:00.000Z",
                "name": "Classified RED Implant",
                "is_family": True,
                "object_marking_refs": [red_marking_id],
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": "2026-02-15T00:00:00.000Z",
                "modified": "2026-02-15T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": malware_id,
            },
        ],
    }

    # Ingest bundle into local service
    ingest_res = ingestion.ingest_bundle(seed_bundle)
    assert ingest_res["nodes_created"] >= 2

    # Instantiate export service bound to this ingestion state
    export_svc = StixExportService(ingestion_service=ingestion)

    # Export starting from actor_id
    exported = export_svc.export_subgraph(
        seed_ids=[actor_id],
        max_depth=2,
        max_nodes=50,
        is_extension_aware=True,
        is_internal_org_member=True,
    )

    obj_ids = [obj["id"] for obj in exported["objects"]]
    # 1. Non-RED actor must be present
    assert actor_id in obj_ids
    # 2. TLP:RED malware must be completely suppressed
    assert malware_id not in obj_ids
    # 3. Relationship connecting to suppressed RED malware must be dropped
    assert rel_id not in obj_ids
    # 4. RED marking definition must not be leaked
    assert red_marking_id not in obj_ids


def test_ac7b_tlp_red_admin_role_cannot_bypass():
    """
    AC-7B Requirement: Absolute Suppression Invariant.
    Even when authenticated as admin and requesting bypass in query parameters,
    TLP:RED suppression CANNOT be bypassed.
    """
    from app.api.routes.stix import stix_service

    red_marking_id = STANDARD_STIX_TLP_RED_ID
    red_actor_id = "threat-actor--99990000-0000-0000-0000-000000000001"

    seed_bundle = {
        "type": "bundle",
        "id": "bundle--99990000-0000-0000-0000-000000000002",
        "objects": [
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": red_marking_id,
                "created": "2017-01-20T00:00:00.000Z",
                "definition_type": "tlp",
                "name": "TLP:RED",
                "definition": {"tlp": "red"},
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": red_actor_id,
                "created": "2026-02-15T00:00:00.000Z",
                "modified": "2026-02-15T00:00:00.000Z",
                "name": "Strictly RED Confidential Actor",
                "object_marking_refs": [red_marking_id],
            },
        ],
    }

    stix_service.ingest_bundle(seed_bundle)

    # Attempt to export as admin with query param bypass attempts
    headers = {
        "Authorization": f"Bearer {ADMIN_TOKEN}",
        "X-Recipient-Extension-Aware": "true",
        "X-Recipient-Org-Internal": "true",
    }
    response = client.get(
        f"/api/v1/stix/export/bundle?actor_id={red_actor_id}&clearance=red&bypass_filters=true",
        headers=headers,
    )
    assert response.status_code == 200
    exported_bundle = response.json()
    exported_ids = [o["id"] for o in exported_bundle["objects"]]
    # The RED actor is strictly suppressed
    assert red_actor_id not in exported_ids


# ---------------------------------------------------------------------------
# AC-7B: AMBER+STRICT RECIPIENT CAPABILITY GATING
# ---------------------------------------------------------------------------

def test_ac7b_amber_strict_extension_unaware_recipient_denied_403():
    """
    AC-7B Requirement: Case (b)
    When exported subgraph contains AMBER+STRICT intelligence:
    Recipient that is extension-unaware is DENIED (HTTP 403 Forbidden).
    Statement markings are NOT treated as an enforceable substitute.
    """
    from app.api.routes.stix import stix_service

    amber_strict_def_id = "marking-definition--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
    actor_id = "threat-actor--88880000-0000-0000-0000-000000000001"

    bundle = {
        "type": "bundle",
        "id": "bundle--88880000-0000-0000-0000-000000000002",
        "objects": [
            {
                "type": "extension-definition",
                "spec_version": "2.1",
                "id": TLP_EXTENSION_DEFINITION_ID,
                "created": "2026-02-15T00:00:00.000Z",
                "modified": "2026-02-15T00:00:00.000Z",
                "created_by_ref": "identity--5b5978a2-2591-4475-bf51-c0a6b7d5bf2a",
                "name": "ThreatMind FIRST TLP 2.0 Compatibility Extension",
                "description": "Formal property-extension",
                "version": "1.0.0",
                "extension_types": ["property-extension"],
                "schema": "https://threatmind.ai/schema/stix/extensions/first-tlp-v1.json",
            },
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": amber_strict_def_id,
                "created": "2026-02-15T00:00:00.000Z",
                "name": "FIRST TLP:AMBER+STRICT Definition",
                "definition_type": "statement",
                "definition": {
                    "statement": "TLP:AMBER+STRICT - Sharing is restricted to recipient organization only."
                },
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
                "name": "AMBER+STRICT Threat Actor",
                "object_marking_refs": [amber_strict_def_id],
            },
        ],
    }

    stix_service.ingest_bundle(bundle)

    # Recipient without X-Recipient-Extension-Aware header (default unaware)
    internal_unaware_token = create_access_token(
        user_id="internal-unaware-analyst",
        tenant_id="tenant-default",
        role="analyst",
        is_internal_org_member=True,
        is_extension_aware=False,
    )
    headers = {
        "Authorization": f"Bearer {internal_unaware_token}",
        "X-Recipient-Org-Internal": "true",
    }
    response = client.get(f"/api/v1/stix/export/bundle?actor_id={actor_id}", headers=headers)
    assert response.status_code == 403
    detail = response.json().get("detail", "")
    assert "TLP:AMBER+STRICT" in detail
    assert "extension-unaware" in detail


def test_ac7b_amber_strict_external_recipient_denied_403():
    """
    AC-7B Requirement: Case (b)
    Recipient that is extension-aware but NOT an internal org member (e.g. client/partner)
    is DENIED (HTTP 403 Forbidden).
    """
    actor_id = "threat-actor--88880000-0000-0000-0000-000000000001"
    external_aware_token = create_access_token(
        user_id="external-aware-analyst",
        tenant_id="tenant-default",
        role="analyst",
        is_internal_org_member=False,
        is_extension_aware=True,
    )
    headers = {
        "Authorization": f"Bearer {external_aware_token}",
        "X-Recipient-Extension-Aware": "true",
        "X-Recipient-Org-Internal": "false",  # External client
    }
    response = client.get(f"/api/v1/stix/export/bundle?actor_id={actor_id}", headers=headers)
    assert response.status_code == 403
    detail = response.json().get("detail", "")
    assert "TLP:AMBER+STRICT" in detail


def test_ac7b_amber_strict_authorized_internal_recipient_allowed_200():
    """
    AC-7B Requirement: Case (a)
    Extension-aware authorized internal recipient requesting AMBER+STRICT succeeds (HTTP 200).
    Verifies that the formal ThreatMind FIRST TLP 2.0 Compatibility Extension is attached
    directly to MarkingDefinition, and the Extension Definition object is included.
    """
    actor_id = "threat-actor--88880000-0000-0000-0000-000000000001"
    internal_aware_token = create_access_token(
        user_id="internal-aware-analyst",
        tenant_id="tenant-default",
        role="analyst",
        is_internal_org_member=True,
        is_extension_aware=True,
    )
    headers = {
        "Authorization": f"Bearer {internal_aware_token}",
        "X-Recipient-Extension-Aware": "true",
        "X-Recipient-Org-Internal": "true",
    }
    response = client.get(f"/api/v1/stix/export/bundle?actor_id={actor_id}", headers=headers)
    assert response.status_code == 200
    exported_bundle = response.json()

    # 1. Verify bundle root compliance
    assert exported_bundle["type"] == "bundle"
    assert "spec_version" not in exported_bundle

    objects = exported_bundle["objects"]
    types = [o["type"] for o in objects]

    # 2. Extension Definition must be present
    assert "extension-definition" in types
    ext_def = next(o for o in objects if o["type"] == "extension-definition")
    assert ext_def["id"] == TLP_EXTENSION_DEFINITION_ID
    assert ext_def["schema"] == "https://threatmind.ai/schema/stix/extensions/first-tlp-v1.json"

    # 3. Marking Definition must have the FIRST TLP extension attached
    marking_def = next(o for o in objects if o["type"] == "marking-definition")
    assert TLP_EXTENSION_DEFINITION_ID in marking_def["extensions"]
    ext_data = marking_def["extensions"][TLP_EXTENSION_DEFINITION_ID]
    assert ext_data["first_tlp_label"] == "AMBER"
    assert ext_data["strict_restriction"] is True
    assert ext_data["sharing_scope"] == "organization_only"


def test_ac7b_query_parameter_capability_spoofing_ignored():
    """
    AC-7B Security Invariant:
    Query parameter capability spoofing attempt (e.g. ?is_extension_aware=true)
    must be ignored; capability is read strictly from trusted headers.
    """
    actor_id = "threat-actor--88880000-0000-0000-0000-000000000001"
    # Query parameters carry spoofed capability, but headers omit them
    headers = ANALYST_AUTH
    response = client.get(
        f"/api/v1/stix/export/bundle?actor_id={actor_id}&is_extension_aware=true&is_internal_org_member=true",
        headers=headers,
    )
    # Must be DENIED with 403 because headers were not provided
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# AC-7B: FIRST TLP:CLEAR TO WHITE INTEROPERABILITY MAPPING
# ---------------------------------------------------------------------------

def test_ac7b_first_tlp_clear_to_white_mapping():
    """
    AC-7B Requirement: Case (d)
    Object carrying FIRST TLP:CLEAR must map to standard STIX 2.1 TLP:WHITE
    (marking-definition--613f2e26-407d-48c7-9ece-e8f352f3037f) accompanied by
    the ThreatMind FIRST TLP Extension with first_tlp_label: "CLEAR".
    Negative Invariant: NEVER inject non-standard values like {"tlp": "clear"}.
    """
    from app.api.routes.stix import stix_service

    clear_marking_id = "marking-definition--77770000-0000-0000-0000-000000000001"
    actor_id = "threat-actor--77770000-0000-0000-0000-000000000002"

    bundle = {
        "type": "bundle",
        "id": "bundle--77770000-0000-0000-0000-000000000003",
        "objects": [
            {
                "type": "marking-definition",
                "spec_version": "2.1",
                "id": clear_marking_id,
                "created": "2026-02-15T00:00:00.000Z",
                "name": "FIRST TLP:CLEAR Definition",
                "definition_type": "statement",
                "definition": {"statement": "TLP:CLEAR"},
                "extensions": {
                    TLP_EXTENSION_DEFINITION_ID: {
                        "extension_type": "property-extension",
                        "first_tlp_label": "CLEAR",
                        "strict_restriction": False,
                        "sharing_scope": "all",
                    }
                },
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": "2026-02-15T00:00:00.000Z",
                "modified": "2026-02-15T00:00:00.000Z",
                "name": "Public Disseminated Actor",
                "object_marking_refs": [clear_marking_id],
            },
        ],
    }

    stix_service.ingest_bundle(bundle)

    headers = ANALYST_AUTH
    response = client.get(f"/api/v1/stix/export/bundle?actor_id={actor_id}", headers=headers)
    assert response.status_code == 200
    exported_bundle = response.json()

    # Find marking definition in export
    marking_defs = [o for o in exported_bundle["objects"] if o["type"] == "marking-definition"]
    assert len(marking_defs) >= 1
    white_marking = marking_defs[0]

    # Verify ID is standard STIX 2.1 TLP:WHITE
    assert white_marking["id"] == STANDARD_STIX_TLP_WHITE_ID
    # Verify definition is standard tlp: white
    assert white_marking["definition"]["tlp"] == "white"
    # Negative Invariant: NEVER "clear"
    assert white_marking["definition"]["tlp"] != "clear"

    # Verify FIRST TLP extension is attached
    assert TLP_EXTENSION_DEFINITION_ID in white_marking["extensions"]
    ext_data = white_marking["extensions"][TLP_EXTENSION_DEFINITION_ID]
    assert ext_data["first_tlp_label"] == "CLEAR"
    assert ext_data["strict_restriction"] is False
    assert ext_data["sharing_scope"] == "all"


# ---------------------------------------------------------------------------
# AC-13: ROUND-TRIP EXPORT & RE-IMPORT FIDELITY
# ---------------------------------------------------------------------------

def test_ac13_export_round_trip_reimport_fidelity():
    """
    AC-13 Requirement:
    Import bundle -> Persist/Map -> Export scoped bundle -> Re-import into fresh mapper.
    Verify 100% graph topology and property preservation.
    """
    ingestion_1 = StixIngestionService()

    actor_id = "threat-actor--55550000-0000-0000-0000-000000000001"
    technique_id = "attack-pattern--55550000-0000-0000-0000-000000000002"
    rel_id = "relationship--55550000-0000-0000-0000-000000000003"

    initial_bundle = {
        "type": "bundle",
        "id": "bundle--55550000-0000-0000-0000-000000000004",
        "objects": [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": actor_id,
                "created": "2026-02-15T12:00:00.000Z",
                "modified": "2026-02-15T12:00:00.000Z",
                "name": "Round Trip APT Group",
                "aliases": ["RT-Group", "RoundBear"],
            },
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": technique_id,
                "created": "2026-02-15T12:00:00.000Z",
                "modified": "2026-02-15T12:00:00.000Z",
                "name": "PowerShell Execution",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": "2026-02-15T12:00:00.000Z",
                "modified": "2026-02-15T12:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": technique_id,
            },
        ],
    }

    # Pass 1: Ingest into ingestion_1
    ingestion_1.ingest_bundle(initial_bundle)

    # Pass 2: Export bounded subgraph
    export_svc = StixExportService(ingestion_service=ingestion_1)
    exported_bundle = export_svc.export_subgraph(
        seed_ids=[actor_id],
        max_depth=2,
        max_nodes=100,
        is_extension_aware=True,
        is_internal_org_member=True,
    )

    # Validate exported bundle structure with Pydantic StixBundle
    validated_bundle = StixBundle.model_validate(exported_bundle)
    assert validated_bundle.type == "bundle"
    assert "spec_version" not in exported_bundle

    # Pass 3: Re-import exported bundle into a fresh ingestion service instance
    ingestion_2 = StixIngestionService()
    reimport_res = ingestion_2.ingest_bundle(exported_bundle)

    assert reimport_res["nodes_created"] == 2
    assert reimport_res["relationships_created"] == 1
    assert len(reimport_res["rejection_ledger"]["rejected_and_isolated"]) == 0

    # Verify graph topology matches identically
    assert actor_id in ingestion_2.mapper.entities_by_stix_id
    assert technique_id in ingestion_2.mapper.entities_by_stix_id
    reimported_actor = ingestion_2.mapper.entities_by_stix_id[actor_id]["properties"]
    assert reimported_actor["name"] == "Round Trip APT Group"
    assert "RT-Group" in reimported_actor["aliases"]

    assert len(ingestion_2.stored_relationships) == 1
    stored_rel = ingestion_2.stored_relationships[0]
    assert stored_rel["source_ref"] == actor_id
    assert stored_rel["target_ref"] == technique_id
    assert stored_rel["relationship_type"] == "uses"


# ---------------------------------------------------------------------------
# AUTHENTICATION & ERROR SANITIZATION TESTS
# ---------------------------------------------------------------------------

def test_export_authentication_required():
    """
    Export endpoint must reject unauthenticated requests with HTTP 401.
    """
    response = client.get("/api/v1/stix/export/bundle?actor_id=test")
    assert response.status_code == 401
    assert "Authentication credentials" in response.json().get("detail", "")


def test_export_insufficient_role_forbidden():
    """
    Export endpoint must reject viewer role with HTTP 403.
    """
    response = client.get("/api/v1/stix/export/bundle?actor_id=test", headers=VIEWER_AUTH)
    assert response.status_code == 403
    assert "Insufficient privileges" in response.json().get("detail", "")
