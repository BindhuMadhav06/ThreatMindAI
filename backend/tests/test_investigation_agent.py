"""
Phase 15: Trusted AI Investigation Agents — Verification Test Suite
Covers:
- Orchestrator finite state machine transitions
- Read-only tool sandboxing & forbidden operation blocking
- Cross-tenant isolation boundaries
- Evidence-grounded claim synthesis
- Inconclusive handling on fabricated/unknown entities
- Human-in-the-Loop (HITL) action approval queue without autonomous execution
- RFC 8785 canonical reproducibility digest validation
- Investigation Agent benchmark evaluation harness
- Investigation REST API endpoints
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.investigation import (
    ActionApprovalStatus,
    ActionRiskLevel,
    InvestigationRequest,
    InvestigationState,
    ToolPermission,
)
from app.services.investigation import (
    HITLApprovalService,
    InvestigationEvaluator,
    InvestigationOrchestrator,
    InvestigationToolsService,
)

client = TestClient(app)


# ============================================================================
# Test Group 1 & 2: Tool Sandboxing & Permission Boundaries
# ============================================================================

def test_tool_sandbox_read_only_tools_success():
    tools = InvestigationToolsService()

    # Valid read-only graph lookup
    res_graph = tools.execute_tool(
        permission=ToolPermission.READ_GRAPH_ENTITY,
        parameters={"entity_id": "APT29"},
        tenant_id="tenant_alpha"
    )
    assert res_graph.status == "success"
    assert res_graph.permitted is True
    assert "APT29" in res_graph.result_summary

    # Valid vulnerability lookup
    res_vuln = tools.execute_tool(
        permission=ToolPermission.LOOKUP_VULNERABILITY,
        parameters={"cve_id": "CVE-2021-44228"},
        tenant_id="tenant_alpha"
    )
    assert res_vuln.status == "success"
    assert res_vuln.permitted is True


def test_tool_sandbox_strictly_blocks_forbidden_operations():
    tools = InvestigationToolsService()

    # Attempt cross-tenant parameter injection
    res_cross = tools.execute_tool(
        permission=ToolPermission.READ_GRAPH_ENTITY,
        parameters={"entity_id": "APT29", "tenant_id": "victim_tenant_beta"},
        tenant_id="tenant_alpha"
    )
    assert res_cross.status == "blocked_permission"
    assert res_cross.permitted is False
    assert "Access denied" in (res_cross.error_message or "")


# ============================================================================
# Test Group 3 & 4: Multi-Step Investigation Workflow & Grounded Claims
# ============================================================================

def test_investigation_orchestrator_execution_and_grounding():
    orchestrator = InvestigationOrchestrator()

    req = InvestigationRequest(
        tenant_id="tenant_soc_prod",
        analyst_id="analyst_01",
        objective="Assess APT29 toolchain and detection coverage.",
        target_entity="APT29",
        max_steps=6,
        max_tool_calls=10
    )

    report = orchestrator.run_investigation(req)

    # 1. State machine steps executed
    assert len(report.execution_steps) >= 4
    step_states = [s.state for s in report.execution_steps]
    assert InvestigationState.VALIDATING in step_states
    assert InvestigationState.RETRIEVING in step_states
    assert InvestigationState.PIVOTING in step_states
    assert InvestigationState.EVALUATING in step_states

    # 2. Grounded claims formulated
    assert len(report.grounded_claims) >= 1
    claim = report.grounded_claims[0]
    assert claim.subject == "APT29"
    assert len(claim.supporting_evidence_refs) > 0
    assert claim.confidence >= 0.80

    # 3. Analytical question sections populated
    assert len(report.what_is_known) > 0
    assert len(report.what_is_unknown) > 0
    assert len(report.what_contradicts) > 0
    assert len(report.stale_evidence_warnings) > 0

    # 4. Reproducibility digest present
    assert report.reproducibility_digest is not None
    assert len(report.reproducibility_digest) == 64


def test_investigation_inconclusive_on_nonexistent_entity():
    orchestrator = InvestigationOrchestrator()

    req = InvestigationRequest(
        tenant_id="tenant_soc_prod",
        analyst_id="analyst_01",
        objective="Investigate fabricated entity.",
        target_entity="UNKNOWN_FABRICATED_GHOST_ACTOR"
    )

    report = orchestrator.run_investigation(req)

    # Inconclusive invariant: Zero hallucinations
    assert report.is_inconclusive is True
    assert len(report.grounded_claims) == 0
    assert "inconclusive" in report.executive_summary.lower()


# ============================================================================
# Test Group 5: Human-in-the-Loop (HITL) Action Approval Workflow
# ============================================================================

def test_hitl_approval_lifecycle_no_autonomous_execution():
    approval = HITLApprovalService()

    action = approval.propose_action(
        tenant_id="tenant_corp",
        action_type="DEPLOY_SIGMA_DETECTION",
        proposed_action="Deploy Sigma rule for PowerShell cradles.",
        rationale="Corroborated by grounded evidence.",
        supporting_evidence=["ev_doc_01"],
        risk_level=ActionRiskLevel.LOW
    )

    # Invariant 1: Action starts strictly in PENDING state
    assert action.approval_status == ActionApprovalStatus.PENDING
    assert action.approver is None

    # Invariant 2: Tenant isolation
    cross_lookup = approval.get_action(action.action_id, tenant_id="other_tenant")
    assert cross_lookup is None

    # Invariant 3: Analyst review transitions status with audit logging
    reviewed = approval.review_action(
        action_id=action.action_id,
        approver="senior_analyst_jane",
        decision=ActionApprovalStatus.APPROVED,
        notes="Validated against test endpoint before deployment."
    )

    assert reviewed.approval_status == ActionApprovalStatus.APPROVED
    assert reviewed.approver == "senior_analyst_jane"
    assert len(reviewed.audit_history) >= 2


# ============================================================================
# Test Group 6: Agent Benchmark Evaluation Harness
# ============================================================================

def test_investigation_evaluation_benchmark():
    evaluator = InvestigationEvaluator()
    metrics = evaluator.run_benchmark()

    assert metrics["evidence_retrieval_precision"] == 1.0
    assert metrics["evidence_retrieval_recall"] == 1.0
    assert metrics["claim_grounding_rate"] == 1.0
    assert metrics["unsupported_claim_rate"] == 0.0  # Zero unsupported claims!
    assert metrics["tool_permission_enforcement_rate"] == 1.0
    assert metrics["tenant_isolation_enforcement_rate"] == 1.0
    assert metrics["abstention_accuracy"] == 1.0
    assert metrics["zero_autonomous_execution_guarantee"] is True


# ============================================================================
# Test Group 7: Investigation REST API Routes
# ============================================================================

def test_investigation_api_run_and_actions():
    # 1. Run investigation endpoint
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"X-Tenant-ID": "tenant_api_test"},
        json={
            "tenant_id": "tenant_api_test",
            "analyst_id": "api_analyst",
            "objective": "API Investigation test",
            "target_entity": "APT29"
        }
    )
    assert resp.status_code == 200
    report_data = resp.json()
    assert "report_id" in report_data
    assert len(report_data["grounded_claims"]) >= 1

    report_id = report_data["report_id"]

    # 2. Get report endpoint
    get_resp = client.get(
        f"/api/v1/investigation-agent/reports/{report_id}",
        headers={"X-Tenant-ID": "tenant_api_test"}
    )
    assert get_resp.status_code == 200

    # 3. List actions endpoint
    act_resp = client.get(
        "/api/v1/investigation-agent/actions",
        headers={"X-Tenant-ID": "tenant_api_test"}
    )
    assert act_resp.status_code == 200
    actions = act_resp.json()
    assert len(actions) >= 1

    # 4. Review action endpoint
    act_id = actions[0]["action_id"]
    rev_resp = client.post(
        f"/api/v1/investigation-agent/actions/{act_id}/review",
        headers={"X-Tenant-ID": "tenant_api_test"},
        json={
            "decision": "APPROVED",
            "approver": "api_analyst_lead",
            "notes": "Approved via API integration test."
        }
    )
    assert rev_resp.status_code == 200
    assert rev_resp.json()["approval_status"] == "APPROVED"

    # 5. Evaluate benchmark endpoint
    eval_resp = client.post("/api/v1/investigation-agent/evaluate")
    assert eval_resp.status_code == 200
    assert eval_resp.json()["unsupported_claim_rate"] == 0.0
