import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from app.services.defense.d3fend_service import (
    d3fend_service,
    EXPECTED_CATALOG_SHA256,
    RECOGNIZED_ATTACK_TECHNIQUES,
)
from app.models.d3fend import ApplicabilityClassification, D3fendTactic

def test_catalog_integrity():
    assert d3fend_service._catalog_sha256 == EXPECTED_CATALOG_SHA256
    assert d3fend_service._catalog_metadata["catalog_version"] == "d3fend-v0.15.0-attack-v14.1"
    assert len(d3fend_service._mappings_by_technique) >= 7

def test_technique_id_normalization():
    assert d3fend_service.normalize_technique_id("T1059.001") == "T1059.001"
    assert d3fend_service.normalize_technique_id("t1059.001") == "T1059.001"
    assert d3fend_service.normalize_technique_id("tech_t1059_001") == "T1059.001"
    assert d3fend_service.normalize_technique_id("T1078") == "T1078"
    assert d3fend_service.normalize_technique_id("invalid-tech-id") is None
    assert d3fend_service.normalize_technique_id("") is None

def test_official_mapping_powershell():
    recs = d3fend_service.get_recommendations_for_technique("T1059.001")
    assert len(recs) == 4

    # M1038 -> Executable Allowlisting
    eal = next((r for r in recs if r.countermeasure.id == "d3f:ExecutableAllowlisting"), None)
    assert eal is not None
    assert eal.mitigation_id == "M1038"
    assert eal.mitigation_name == "Execution Prevention"
    assert eal.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED
    assert eal.countermeasure.tactic == D3fendTactic.HARDEN

    # M1038 -> Process Segment Execution Prevention
    psep = next((r for r in recs if r.countermeasure.id == "d3f:ProcessSegmentExecutionPrevention"), None)
    assert psep is not None
    assert psep.mitigation_id == "M1038"

    # M1042 -> Application Configuration Hardening (Disable or Remove Feature or Program)
    ach = next((r for r in recs if r.countermeasure.id == "d3f:ApplicationConfigurationHardening"), None)
    assert ach is not None
    assert ach.mitigation_id == "M1042"
    assert ach.mitigation_name == "Disable or Remove Feature or Program"
    assert ach.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED

    # M1026 -> Local Account Monitoring
    lam = next((r for r in recs if r.countermeasure.id == "d3f:LocalAccountMonitoring"), None)
    assert lam is not None
    assert lam.mitigation_id == "M1026"

    # Verify M1047 (Audit) is NOT directly on T1059.001, but belongs on parent T1059
    assert all(r.mitigation_id != "M1047" for r in recs)

def test_parent_mapping_command_and_scripting():
    recs = d3fend_service.get_recommendations_for_technique("T1059")
    assert len(recs) == 2
    sfa = next((r for r in recs if r.countermeasure.id == "d3f:SystemFileAnalysis"), None)
    assert sfa is not None
    assert sfa.mitigation_id == "M1047"
    assert sfa.mitigation_name == "Audit"
    assert sfa.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED
    assert sfa.countermeasure.tactic == D3fendTactic.DETECT

def test_official_mapping_web_shell():
    # T1505.003 via M1042 -> Application Configuration Hardening
    recs = d3fend_service.get_recommendations_for_technique("T1505.003")
    assert len(recs) == 1
    ach = recs[0]
    assert ach.countermeasure.id == "d3f:ApplicationConfigurationHardening"
    assert ach.mitigation_id == "M1042"
    assert ach.mitigation_name == "Disable or Remove Feature or Program"
    assert ach.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED
    assert ach.countermeasure.tactic == D3fendTactic.HARDEN

def test_inferred_mapping_process_injection():
    # T1055 has both an official mapping (M1040 -> D3-AZET) and an app-defined inferred recommendation
    recs = d3fend_service.get_recommendations_for_technique("T1055")
    assert len(recs) == 2
    inferred = next((r for r in recs if r.countermeasure.id == "app:inferred_memory_protection"), None)
    assert inferred is not None
    assert inferred.applicability == ApplicabilityClassification.POTENTIALLY_RELEVANT
    assert inferred.countermeasure.official_url == ""
    assert inferred.countermeasure.name == "Inferred Memory Protection"
    assert inferred.mapping_relationship == "inferred_conceptual_defense"

def test_official_mapping_valid_accounts():
    recs = d3fend_service.get_recommendations_for_technique("T1078")
    assert len(recs) >= 3

    # M1032 -> Multi-factor Authentication
    mfa = next((r for r in recs if r.countermeasure.id == "d3f:MultiFactorAuthentication"), None)
    assert mfa is not None
    assert mfa.mitigation_id == "M1032"
    assert mfa.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED

    # M1015 -> User Account Permissions (NOT M1018)
    uap = next((r for r in recs if r.countermeasure.id == "d3f:UserAccountPermissions"), None)
    assert uap is not None
    assert uap.mitigation_id == "M1015"
    assert uap.mitigation_name == "Active Directory Configuration"
    assert uap.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED

    # M1018 -> Local File Permissions
    lfp = next((r for r in recs if r.countermeasure.id == "d3f:LocalFilePermissions"), None)
    assert lfp is not None
    assert lfp.mitigation_id == "M1018"
    assert lfp.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED

def test_official_mapping_credential_dumping():
    # T1003 via M1043 -> Hardware-based Process Isolation (NOT OS Credential Hardening)
    recs = d3fend_service.get_recommendations_for_technique("T1003")
    assert len(recs) >= 1
    hbpi = next((r for r in recs if r.countermeasure.id == "d3f:Hardware-basedProcessIsolation"), None)
    assert hbpi is not None
    assert hbpi.mitigation_id == "M1043"
    assert hbpi.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED
    assert hbpi.countermeasure.tactic == D3fendTactic.ISOLATE

def test_official_mapping_dos():
    # T1498 via M1037 -> Network Isolation (NOT Network Traffic Filtering)
    recs = d3fend_service.get_recommendations_for_technique("T1498")
    assert len(recs) >= 1
    ni = next((r for r in recs if r.countermeasure.id == "d3f:NetworkIsolation"), None)
    assert ni is not None
    assert ni.mitigation_id == "M1037"
    assert ni.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED

def test_step5_nonexistent_identifier_rejected():
    # Nonexistent identifier T1059.999 must NOT inherit parent T1059 recommendations
    assert "T1059.999" not in RECOGNIZED_ATTACK_TECHNIQUES
    recs = d3fend_service.get_recommendations_for_technique("T1059.999")
    assert recs == []

def test_step5_legitimate_subtechnique_parent_fallback():
    # T1059.003 (Windows Command Shell) is a verified ATT&CK sub-technique
    # It has no direct mapping, so it must inherit parent T1059 recommendations as requires_environment_review
    assert "T1059.003" in RECOGNIZED_ATTACK_TECHNIQUES
    recs = d3fend_service.get_recommendations_for_technique("T1059.003")
    assert len(recs) > 0
    for r in recs:
        assert r.applicability == ApplicabilityClassification.REQUIRES_ENVIRONMENT_REVIEW
        assert "Inferred from parent technique T1059" in r.rationale

def test_unknown_technique_abstains():
    # Unknown technique T9999 must abstain
    recs = d3fend_service.get_recommendations_for_technique("T9999")
    assert recs == []

def test_catalog_relationship_authenticity():
    # Verify all 18 records in catalog meet relationship direction and provenance constraints
    total_records = 0
    for tech_id, recs in d3fend_service._mappings_by_technique.items():
        for r in recs:
            total_records += 1
            assert r.attack_technique_id == tech_id
            assert r.original_framework_id.startswith("ATT&CK:")
            assert r.mapping_direction == "offensive_to_defensive"
            if r.applicability == ApplicabilityClassification.OFFICIALLY_MAPPED:
                assert r.mitigation_id is not None
                assert "https://d3fend.mitre.org" in r.countermeasure.official_url
                assert r.countermeasure.id.startswith("d3f:")
                assert "Official MITRE ATT&CK Mitigation" in r.mapping_provenance
            elif r.applicability == ApplicabilityClassification.POTENTIALLY_RELEVANT:
                assert r.countermeasure.id.startswith("app:")
                assert r.countermeasure.official_url == ""
                assert "Application-defined" in r.mapping_provenance
    assert total_records == 18
