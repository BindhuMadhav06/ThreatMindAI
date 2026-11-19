"""
API routes for Phase 15 ThreatMind Trusted AI Investigation Agents.
Provides endpoints for executing bounded investigation plans, querying reports,
reviewing Human-in-the-Loop defensive actions, and running evaluation benchmarks.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel

from app.models.investigation import (
    ActionApprovalStatus,
    HITLProposedAction,
    InvestigationReport,
    InvestigationRequest,
)
from app.services.investigation import (
    HITLApprovalService,
    InvestigationEvaluator,
    InvestigationOrchestrator,
    InvestigationToolsService,
)

router = APIRouter(prefix="/investigation-agent", tags=["Trusted AI Investigation Agents"])

tools_service = InvestigationToolsService()
approval_service = HITLApprovalService()
orchestrator = InvestigationOrchestrator(
    tools_service=tools_service,
    approval_service=approval_service
)
evaluator = InvestigationEvaluator()


class ActionReviewRequest(BaseModel):
    decision: ActionApprovalStatus
    approver: str
    notes: Optional[str] = ""


def get_verified_tenant(x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")) -> str:
    if not x_tenant_id or not x_tenant_id.strip():
        return "default_tenant"
    return x_tenant_id.strip()


@router.post("/run", response_model=InvestigationReport, status_code=status.HTTP_200_OK)
async def run_investigation(
    request: InvestigationRequest,
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")
) -> InvestigationReport:
    """
    Execute a bounded multi-step investigation against a target entity or alert.
    Dispatches only permitted read-only tools and records full execution traces.
    """
    tenant = get_verified_tenant(x_tenant_id)
    request.tenant_id = tenant
    report = orchestrator.run_investigation(request)
    return report


@router.get("/reports/{report_id}", response_model=InvestigationReport)
async def get_investigation_report(
    report_id: str,
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")
) -> InvestigationReport:
    """Retrieve an investigation report with strict tenant isolation."""
    tenant = get_verified_tenant(x_tenant_id)
    report = orchestrator.get_report(report_id, tenant_id=tenant)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found for tenant '{tenant}'."
        )
    return report


@router.get("/actions", response_model=List[HITLProposedAction])
async def list_proposed_actions(
    status_filter: Optional[ActionApprovalStatus] = Query(None),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")
) -> List[HITLProposedAction]:
    """List pending or reviewed defensive actions awaiting human approval."""
    tenant = get_verified_tenant(x_tenant_id)
    return approval_service.list_actions(tenant_id=tenant, status_filter=status_filter)


@router.post("/actions/{action_id}/review", response_model=HITLProposedAction)
async def review_action(
    action_id: str,
    req: ActionReviewRequest,
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID")
) -> HITLProposedAction:
    """
    Approve or reject a proposed defensive action.
    Maintains complete audit history and enforces human decision authority.
    """
    tenant = get_verified_tenant(x_tenant_id)
    action = approval_service.get_action(action_id, tenant_id=tenant)
    if not action:
        raise HTTPException(
            status_code=404,
            detail=f"Proposed action '{action_id}' not found for tenant '{tenant}'."
        )

    try:
        updated = approval_service.review_action(
            action_id=action_id,
            approver=req.approver,
            decision=req.decision,
            notes=req.notes or ""
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/evaluate", response_model=Dict[str, Any])
async def evaluate_agent_benchmark() -> Dict[str, Any]:
    """Run automated investigation evaluation benchmark suite."""
    return evaluator.run_benchmark()
