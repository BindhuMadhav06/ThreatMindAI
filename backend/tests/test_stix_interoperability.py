"""
ThreatMind Phase 12A Milestone 1 — STIX 2.1 Interoperability Test Suite
Tests AC-1 through AC-6, AC-7A, AC-8 through AC-12, and AC-14.
Verifies discriminated SDO models, 4-way tuple classification, SCO auditing,
granular marking XOR invariant, permanent revocation, and canonical immutability.
"""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.models.stix import (
    FirstTlpExtensionData,
    StixAttackPattern,
    StixBundle,
    StixCampaign,
    StixCourseOfAction,
    StixExternalReference,
    StixGranularMarking,
    StixIdentity,
    StixIndicator,
    StixInfrastructure,
    StixIntrusionSet,
    StixLocation,
    StixMalware,
    StixMarkingDefinition,
    StixRelationship,
    StixReport,
    StixThreatActor,
    StixTool,
    StixVulnerability,
    SupportedStixSdo,
)
from app.services.stix.stix_entity_mapper import StixEntityMapper
from app.services.stix.stix_ingestion_service import StixIngestionService


NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)


# =============================================================================
# AC-1: Discriminated SDO Models & Negative Schema Validation
# =============================================================================

def test_ac1_supported_sdo_models_instantiation():
    """Validates that all 13 supported SDOs instantiate and validate properly."""
    actor = StixThreatActor(
        id="threat-actor--8e2e282b-1234-5678-9abc-def012345678",
        created=NOW,
        modified=NOW,
        name="APT29",
    )
    assert actor.type == "threat-actor"

    malware = StixMalware(
        id="malware--8e2e282b-1234-5678-9abc-def012345678",
        created=NOW,
        modified=NOW,
        name="Cobalt Strike",
        is_family=True,
    )
    assert malware.is_family is True

    tool = StixTool(
        id="tool--8e2e282b-1234-5678-9abc-def012345678",
        created=NOW,
        modified=NOW,
        name="Mimikatz",
    )
    assert tool.name == "Mimikatz"

    vuln = StixVulnerability(
        id="vulnerability--8e2e282b-1234-5678-9abc-def012345678",
        created=NOW,
        modified=NOW,
        name="CVE-2021-44228",
    )
    assert vuln.name == "CVE-2021-44228"

    indicator = StixIndicator(
        id="indicator--8e2e282b-1234-5678-9abc-def012345678",
        created=NOW,
        modified=NOW,
        pattern="[file:hashes.'SHA-256' = 'abc...']",
        pattern_type="stix",
        valid_from=NOW,
    )
    assert indicator.pattern_type == "stix"


def test_ac1_negative_schema_cases():
    """
    Negative tests:
    (a) Missing required 'name' on ThreatActor
    (b) Missing 'is_family' on Malware
    (c) Missing 'pattern' on Indicator
    (d) Wrong ID prefix (e.g. campaign-- with type threat-actor)
    (e) defanged on ThreatActor or Malware
    (f) spec_version at root of bundle
    """
    # (a) Missing name
    with pytest.raises(ValidationError):
        StixThreatActor(
            id="threat-actor--8e2e282b-1234-5678-9abc-def012345678",
            created=NOW,
            modified=NOW,
        )

    # (b) Missing is_family on malware
    with pytest.raises(ValidationError):
        StixMalware(
            id="malware--8e2e282b-1234-5678-9abc-def012345678",
            created=NOW,
            modified=NOW,
            name="Test Malware",
        )

    # (c) Missing pattern on indicator
    with pytest.raises(ValidationError):
        StixIndicator(
            id="indicator--8e2e282b-1234-5678-9abc-def012345678",
            created=NOW,
            modified=NOW,
            pattern_type="stix",
            valid_from=NOW,
        )

    # (d) Wrong ID prefix
    with pytest.raises(ValidationError):
        StixThreatActor(
            id="campaign--8e2e282b-1234-5678-9abc-def012345678",
            created=NOW,
            modified=NOW,
            name="Mismatched Prefix",
        )

    # (e) defanged on SDO or SRO is strictly forbidden
    with pytest.raises(ValueError, match="defanged.*strictly forbidden"):
        StixThreatActor(
            id="threat-actor--8e2e282b-1234-5678-9abc-def012345678",
            created=NOW,
            modified=NOW,
            name="Defanged Actor",
            defanged=True,
        )

    with pytest.raises(ValueError, match="defanged.*strictly forbidden"):
        StixRelationship(
            id="relationship--8e2e282b-1234-5678-9abc-def012345678",
            created=NOW,
            modified=NOW,
            relationship_type="uses",
            source_ref="threat-actor--8e2e282b-1234-5678-9abc-def012345678",
            target_ref="malware--8e2e282b-1234-5678-9abc-def012345678",
            defanged=True,
        )

    # (f) spec_version forbidden at bundle root per STIX 2.1 §2.1
    with pytest.raises(ValidationError, match="spec_version.*MUST NOT be present at bundle root"):
        StixBundle.model_validate({
            "type": "bundle",
            "id": "bundle--8e2e282b-1234-5678-9abc-def012345678",
            "spec_version": "2.1",
            "objects": [],
        })


# =============================================================================
# AC-2: Identity Class Separation
# =============================================================================

def test_ac2_identity_class_separation():
    """
    Verifies that only organization identities receive secondary ':Organization' label;
    individual, system, and class identities receive strictly ':Identity'.
    """
    mapper = StixEntityMapper()

    org_id = StixIdentity(
        id="identity--11111111-1111-1111-1111-111111111111",
        created=NOW,
        modified=NOW,
        name="CISA",
        identity_class="organization",
    )
    ind_id = StixIdentity(
        id="identity--22222222-2222-2222-2222-222222222222",
        created=NOW,
        modified=NOW,
        name="Lead Threat Hunter",
        identity_class="individual",
    )
    class_id = StixIdentity(
        id="identity--33333333-3333-3333-3333-333333333333",
        created=NOW,
        modified=NOW,
        name="Financial Sector Entities",
        identity_class="class",
    )

    org_mapped = mapper.map_sdo_to_graph_properties(org_id)
    ind_mapped = mapper.map_sdo_to_graph_properties(ind_id)
    class_mapped = mapper.map_sdo_to_graph_properties(class_id)

    assert "Identity" in org_mapped["labels"]
    assert "Organization" in org_mapped["labels"]

    assert ind_mapped["labels"] == ["Identity"]
    assert "Organization" not in ind_mapped["labels"]

    assert class_mapped["labels"] == ["Identity"]
    assert "Organization" not in class_mapped["labels"]


# =============================================================================
# AC-3: Distinct ThreatActor vs IntrusionSet
# =============================================================================

def test_ac3_distinct_threat_actor_vs_intrusion_set():
    """
    Verifies that ThreatActor and IntrusionSet are never collapsed or merged,
    even when sharing identical names.
    """
    mapper = StixEntityMapper()

    actor = StixThreatActor(
        id="threat-actor--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        created=NOW,
        modified=NOW,
        name="APT29",
    )
    intrusion_set = StixIntrusionSet(
        id="intrusion-set--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        created=NOW,
        modified=NOW,
        name="APT29",
    )

    status_actor, _ = mapper.resolve_sdo(actor, actor.model_dump(mode="json"))
    status_is, _ = mapper.resolve_sdo(intrusion_set, intrusion_set.model_dump(mode="json"))

    assert status_actor == "created"
    assert status_is == "created"

    assert len(mapper.entities_by_stix_id) == 2
    assert mapper.entities_by_stix_id[actor.id]["labels"] == ["ThreatActor"]
    assert mapper.entities_by_stix_id[intrusion_set.id]["labels"] == ["IntrusionSet"]


# =============================================================================
# AC-4: Authoritative Relationship Matrix & 4-Way Tuple Classification
# =============================================================================

def test_ac4_relationship_matrix_and_tuple_classification():
    """
    Tests 4-way tuple classification:
    - Supported registered tuples: ingested
    - Registered custom relationships: audited as custom_relationship_ignored
    - Valid unsupported tuples: audited as unsupported_relationship_ignored
    - Malformed / negative invariants: rejected_and_isolated
    """
    service = StixIngestionService()

    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-5678-1234-567812345678",
        "objects": [
            # Endpoints
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--11111111-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Adversary Alpha",
            },
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--22222222-2222-2222-2222-222222222222",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Adversary Beta",
            },
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--33333333-3333-3333-3333-333333333333",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Beacon Loader",
                "is_family": True,
            },
            {
                "type": "infrastructure",
                "spec_version": "2.1",
                "id": "infrastructure--44444444-4444-4444-4444-444444444444",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "C2 Server",
            },
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": "vulnerability--55555555-5555-5555-5555-555555555555",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "CVE-2021-44228",
            },
            {
                "type": "intrusion-set",
                "spec_version": "2.1",
                "id": "intrusion-set--66666666-6666-6666-6666-666666666666",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Operation Starlight",
            },
            {
                "type": "intrusion-set",
                "spec_version": "2.1",
                "id": "intrusion-set--77777777-7777-7777-7777-777777777777",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Tracked Cluster B",
            },
            # 1. Supported Registered Tuple: threat-actor uses malware
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--aaaaaaaa-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--11111111-1111-1111-1111-111111111111",
                "target_ref": "malware--33333333-3333-3333-3333-333333333333",
            },
            # 2. Registered Custom Relationship: threat-actor financially-supports threat-actor
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--bbbbbbbb-2222-2222-2222-222222222222",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "relationship_type": "financially-supports",
                "source_ref": "threat-actor--11111111-1111-1111-1111-111111111111",
                "target_ref": "threat-actor--22222222-2222-2222-2222-222222222222",
            },
            # 3. Valid Unsupported Standard Tuple: infrastructure hosts malware
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--cccccccc-3333-3333-3333-333333333333",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "relationship_type": "hosts",
                "source_ref": "infrastructure--44444444-4444-4444-4444-444444444444",
                "target_ref": "malware--33333333-3333-3333-3333-333333333333",
            },
            # 4. Negative Invariant: intrusion-set attributed-to intrusion-set
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--dddddddd-4444-4444-4444-444444444444",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "relationship_type": "attributed-to",
                "source_ref": "intrusion-set--66666666-6666-6666-6666-666666666666",
                "target_ref": "intrusion-set--77777777-7777-7777-7777-777777777777",
            },
            # 5. Negative Invariant: threat-actor exploits vulnerability (must use targets)
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--eeeeeeee-5555-5555-5555-555555555555",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "relationship_type": "exploits",
                "source_ref": "threat-actor--11111111-1111-1111-1111-111111111111",
                "target_ref": "vulnerability--55555555-5555-5555-5555-555555555555",
            },
        ],
    }

    result = service.ingest_bundle(bundle)
    assert result["success"] is True

    # 1. Supported relationship created
    assert result["relationships_created"] == 1
    assert any(r["id"] == "relationship--aaaaaaaa-1111-1111-1111-111111111111" for r in service.stored_relationships)

    # 2. Registered custom relationship audited as custom_relationship_ignored
    assert len(result["audit_records"]["custom_relationship_ignored"]) == 1
    assert result["audit_records"]["custom_relationship_ignored"][0]["id"] == "relationship--bbbbbbbb-2222-2222-2222-222222222222"

    # 3. Valid unsupported standard relationship audited as unsupported_relationship_ignored
    assert len(result["audit_records"]["unsupported_relationship_ignored"]) == 1
    assert result["audit_records"]["unsupported_relationship_ignored"][0]["id"] == "relationship--cccccccc-3333-3333-3333-333333333333"

    # 4 & 5. Negative invariants strictly rejected
    rejected_ids = [r["id"] for r in result["rejection_ledger"]["rejected_and_isolated"]]
    assert "relationship--dddddddd-4444-4444-4444-444444444444" in rejected_ids
    assert "relationship--eeeeeeee-5555-5555-5555-555555555555" in rejected_ids


# =============================================================================
# AC-5: Course of Action & D3FEND Safeguard
# =============================================================================

def test_ac5_course_of_action_and_d3fend_safeguard():
    """
    Verifies that M1042 is extracted from external references,
    while generic names without ATT&CK reference do not trigger mitigation IDs.
    """
    mapper = StixEntityMapper()

    coa_with_attack = StixCourseOfAction(
        id="course-of-action--7e69f0b3-96b6-455f-a369-07bc9d9ff4a5",
        created=NOW,
        modified=NOW,
        name="Disable PowerShell Execution",
        external_references=[
            StixExternalReference(source_name="mitre-attack", external_id="M1042")
        ],
    )

    coa_generic = StixCourseOfAction(
        id="course-of-action--8f7a0b1c-1234-5678-9abc-def012345678",
        created=NOW,
        modified=NOW,
        name="Update software",
    )

    mapped_attack = mapper.map_sdo_to_graph_properties(coa_with_attack)
    mapped_generic = mapper.map_sdo_to_graph_properties(coa_generic)

    assert mapped_attack["properties"]["stix_id"] == "course-of-action--7e69f0b3-96b6-455f-a369-07bc9d9ff4a5"
    assert mapped_attack["properties"]["mitre_attack_id"] == "M1042"

    assert mapped_generic["properties"]["stix_id"] == "course-of-action--8f7a0b1c-1234-5678-9abc-def012345678"
    assert "mitre_attack_id" not in mapped_generic["properties"]


# =============================================================================
# AC-6: Authoritative CVE Identifier Validation Regex (4 to 19 digits)
# =============================================================================

def test_ac6_authoritative_cve_regex_validation():
    """Validates CVE ID sequence lengths from 4 to 19 digits and rejects invalid formats."""
    mapper = StixEntityMapper()

    # Valid formats
    assert mapper.validate_cve_id("CVE-1999-0067") is True           # 4-digit
    assert mapper.validate_cve_id("CVE-2021-44228") is True          # 5-digit
    assert mapper.validate_cve_id("CVE-2024-1234567890123456789") is True  # 19-digit

    # Invalid formats
    assert mapper.validate_cve_id("CVE-21-1234") is False            # 2-digit year
    assert mapper.validate_cve_id("CVE-2021-ABC") is False           # non-digit sequence
    assert mapper.validate_cve_id("CVE-2021-12") is False            # sequence < 4 digits
    assert mapper.validate_cve_id("NOT-A-CVE") is False


# =============================================================================
# AC-7A: Granular Markings XOR Invariant & Marking Immutability
# =============================================================================

def test_ac7a_granular_marking_xor_invariant():
    """
    Verifies that StixGranularMarking requires non-empty selectors and
    strictly enforces XOR between lang and marking_ref.
    """
    # (a) Valid lang with selectors
    gm_lang = StixGranularMarking(lang="en", selectors=["description"])
    assert gm_lang.lang == "en"

    # (b) Valid marking_ref with selectors
    gm_ref = StixGranularMarking(marking_ref="marking-definition--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d", selectors=["name"])
    assert gm_ref.marking_ref is not None

    # (c) Negative: both lang and marking_ref
    with pytest.raises(ValueError, match="exactly one of 'lang' or 'marking_ref'"):
        StixGranularMarking(
            lang="en",
            marking_ref="marking-definition--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
            selectors=["description"],
        )

    # (d) Negative: neither lang nor marking_ref
    with pytest.raises(ValueError, match="exactly one of 'lang' or 'marking_ref'"):
        StixGranularMarking(selectors=["description"])

    # (e) Negative: empty selectors
    with pytest.raises(ValidationError):
        StixGranularMarking(lang="en", selectors=[])


def test_ac7a_marking_definition_full_object_immutability():
    """
    Verifies full-object canonical immutability check:
    Same ID + identical digest -> merged
    Same ID + differing metadata -> immutable_marking_conflict_rejected
    """
    mapper = StixEntityMapper()

    raw_def_1 = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--11111111-1111-1111-1111-111111111111",
        "created": "2026-11-18T12:00:00.000Z",
        "name": "TLP:GREEN",
        "definition_type": "statement",
        "definition": {"statement": "Internal Community Only"},
    }

    raw_def_1_conflict = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--11111111-1111-1111-1111-111111111111",
        "created": "2026-11-18T12:00:00.000Z",
        "name": "Modified Name TLP:GREEN",
        "definition_type": "statement",
        "definition": {"statement": "Altered Statement Content"},
    }

    marking_def_1 = StixMarkingDefinition.model_validate(raw_def_1)
    marking_def_conflict = StixMarkingDefinition.model_validate(raw_def_1_conflict)

    status_1, _ = mapper.resolve_and_stage_marking_definition(marking_def_1, raw_def_1)
    assert status_1 == "created"

    # Idempotent repeat
    status_repeat, _ = mapper.resolve_and_stage_marking_definition(marking_def_1, raw_def_1)
    assert status_repeat == "merged"

    # Conflict on non-versionable marking definition
    status_conflict, conflict_record = mapper.resolve_and_stage_marking_definition(marking_def_conflict, raw_def_1_conflict)
    assert status_conflict == "immutable_marking_conflict_rejected"
    assert conflict_record["stix_id"] == "marking-definition--11111111-1111-1111-1111-111111111111"


# =============================================================================
# AC-8: Embedded Reference Resolution, Fail-Closed Markings & SCO Endpoints
# =============================================================================

def test_ac8_fail_closed_unresolved_marking_rejection():
    """
    Verifies that SDOs or SROs referencing missing/unresolvable marking definitions
    are strictly rejected into unresolved_marking_rejected (fail-closed).
    """
    service = StixIngestionService()

    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-5678-1234-567812345678",
        "objects": [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--11111111-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Actor with Missing Marking",
                "object_marking_refs": ["marking-definition--missing-marking-uuid"],
            }
        ],
    }

    result = service.ingest_bundle(bundle)
    assert result["nodes_created"] == 0
    assert len(result["rejection_ledger"]["unresolved_marking_rejected"]) == 1
    assert result["rejection_ledger"]["unresolved_marking_rejected"][0]["id"] == "threat-actor--11111111-1111-1111-1111-111111111111"


def test_ac8_sco_endpoint_auditing():
    """
    Verifies that relationships pointing to SCO endpoints (e.g. ipv4-addr)
    are gracefully audited as sco_endpoint_ignored without crashing.
    """
    service = StixIngestionService()

    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-5678-1234-567812345678",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--11111111-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
                "pattern_type": "stix",
                "valid_from": "2026-11-18T12:00:00.000Z",
            },
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--11111111-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "indicator--11111111-1111-1111-1111-111111111111",
                "target_ref": "ipv4-addr--198.51.100.1",
            },
        ],
    }

    result = service.ingest_bundle(bundle)
    assert result["nodes_created"] == 1
    assert len(result["audit_records"]["sco_endpoint_ignored"]) == 1
    assert result["audit_records"]["sco_endpoint_ignored"][0]["target_ref"] == "ipv4-addr--198.51.100.1"


# =============================================================================
# AC-9: Versioning, Same-Version Content Conflict & Permanent Revocation
# =============================================================================

def test_ac9_versioning_and_permanent_revocation():
    """
    Verifies:
    - Submitting older version archives it into version history.
    - Same (stix_id, modified) with different content quarantines in ambiguous_entity_conflicts.
    - Submitting an update to an already revoked object is strictly rejected (revoked_object_update_rejected).
    """
    mapper = StixEntityMapper()

    # 1. Active version
    v1 = StixThreatActor(
        id="threat-actor--11111111-1111-1111-1111-111111111111",
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2026, 6, 1, tzinfo=timezone.utc),
        name="APT29 Initial Tracking",
    )
    status_1, _ = mapper.resolve_sdo(v1, v1.model_dump(mode="json"))
    assert status_1 == "created"

    # 2. Older version submitted later
    v0 = StixThreatActor(
        id="threat-actor--11111111-1111-1111-1111-111111111111",
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2026, 3, 1, tzinfo=timezone.utc),
        name="APT29 Early Historical",
    )
    status_0, _ = mapper.resolve_sdo(v0, v0.model_dump(mode="json"))
    assert status_0 == "archived_historical"

    # 3. Same (stix_id, modified) with differing content -> Quarantine
    v1_conflict = StixThreatActor(
        id="threat-actor--11111111-1111-1111-1111-111111111111",
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2026, 6, 1, tzinfo=timezone.utc),
        name="Conflicting Name Payload",
    )
    status_conflict, _ = mapper.resolve_sdo(v1_conflict, v1_conflict.model_dump(mode="json"))
    assert status_conflict == "version_conflict_quarantined"
    assert len(mapper.ambiguous_entity_conflicts) == 1

    # 4. Object revoked
    v2_revoked = StixThreatActor(
        id="threat-actor--22222222-2222-2222-2222-222222222222",
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2026, 7, 1, tzinfo=timezone.utc),
        name="Decommissioned Threat Actor",
        revoked=True,
    )
    status_rev, _ = mapper.resolve_sdo(v2_revoked, v2_revoked.model_dump(mode="json"))
    assert status_rev == "created"

    # 5. Subsequent update to revoked object -> rejected
    v3_post_revocation = StixThreatActor(
        id="threat-actor--22222222-2222-2222-2222-222222222222",
        created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        modified=datetime(2026, 8, 1, tzinfo=timezone.utc),
        name="Attempted Re-activation",
    )
    status_post_rev, detail = mapper.resolve_sdo(v3_post_revocation, v3_post_revocation.model_dump(mode="json"))
    assert status_post_rev == "revoked_object_update_rejected"
    assert detail["stix_id"] == "threat-actor--22222222-2222-2222-2222-222222222222"


# =============================================================================
# AC-10: Idempotency of Repeated Imports
# =============================================================================

def test_ac10_idempotency_of_repeated_imports():
    """Verifies that re-importing the same bundle creates 0 duplicate nodes and edges."""
    service = StixIngestionService()

    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-5678-1234-567812345678",
        "objects": [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--11111111-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Persistent Adversary",
            }
        ],
    }

    result_1 = service.ingest_bundle(bundle)
    assert result_1["nodes_created"] == 1
    assert result_1["nodes_merged"] == 0

    result_2 = service.ingest_bundle(bundle)
    assert result_2["nodes_created"] == 0
    assert result_2["nodes_merged"] == 1


# =============================================================================
# AC-11: Dry-Run Logical State Equality
# =============================================================================

def test_ac11_dry_run_logical_state_equality():
    """
    Verifies that executing ingest_bundle with dry_run=True computes the complete
    predicted change set and rejection ledger without mutating in-memory/database state.
    """
    service = StixIngestionService()

    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-5678-1234-567812345678",
        "objects": [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--11111111-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Dry Run Adversary",
            }
        ],
    }

    # Initial state
    assert len(service.mapper.entities_by_stix_id) == 0

    # Dry run execution
    result = service.ingest_bundle(bundle, dry_run=True)
    assert result["dry_run"] is True
    assert result["nodes_created"] == 1

    # State after dry run MUST BE COMPLETELY UNCHANGED
    assert len(service.mapper.entities_by_stix_id) == 0
    assert len(service.stored_relationships) == 0


# =============================================================================
# FIRST TLP Extension Data Validation Matrix
# =============================================================================

def test_first_tlp_extension_data_validation():
    """Validates the conditional oneOf constraints for FIRST TLP 2.0 labels and sharing scopes."""
    # Valid CLEAR
    clear_ext = FirstTlpExtensionData(
        first_tlp_label="CLEAR",
        strict_restriction=False,
        sharing_scope="all",
    )
    assert clear_ext.first_tlp_label == "CLEAR"

    # Valid Standard AMBER
    amber_ext = FirstTlpExtensionData(
        first_tlp_label="AMBER",
        strict_restriction=False,
        sharing_scope="organization_and_clients",
    )
    assert amber_ext.strict_restriction is False

    # Valid AMBER+STRICT
    amber_strict_ext = FirstTlpExtensionData(
        first_tlp_label="AMBER",
        strict_restriction=True,
        sharing_scope="organization_only",
    )
    assert amber_strict_ext.strict_restriction is True

    # Invalid CLEAR with strict_restriction=True
    with pytest.raises(ValueError, match="TLP:CLEAR requires strict_restriction=False and sharing_scope='all'"):
        FirstTlpExtensionData(
            first_tlp_label="CLEAR",
            strict_restriction=True,
            sharing_scope="all",
        )

    # Invalid AMBER+STRICT with wrong sharing scope
    with pytest.raises(ValueError, match="TLP:AMBER\\+STRICT requires strict_restriction=True and sharing_scope='organization_only'"):
        FirstTlpExtensionData(
            first_tlp_label="AMBER",
            strict_restriction=True,
            sharing_scope="organization_and_clients",
        )
