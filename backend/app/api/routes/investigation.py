"""
API routes for Phase 15 ThreatMind Trusted AI Investigation Agents.
Provides endpoints for executing bounded investigation plans, querying reports,
reviewing Human-in-the-Loop defensive actions, and running evaluation benchmarks.
Enforces cryptographic authentication, server-side tenant derivation,
and strict anti-spoofing boundaries on every endpoint.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel

from app.core.security import AuthenticatedUser, verify_authentication
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
    notes: Optional[str] = ""
    # Optional client-suggested approver name; server always binds to verified user identity
    approver: Optional[str] = None


@router.post("/run", response_model=InvestigationReport, status_code=status.HTTP_200_OK)
async def run_investigation(
    request: InvestigationRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> InvestigationReport:
    """
    Execute a bounded multi-step investigation against a target entity or alert.
    Derives trusted tenant identity server-side from verified credentials.
    """
    # Overwrite/bind tenant to verified server-side identity
    if not current_user.is_admin or not request.tenant_id:
        request.tenant_id = current_user.tenant_id
    if not request.analyst_id:
        request.analyst_id = current_user.user_id

    report = orchestrator.run_investigation(request)
    return report


@router.get("/reports/{report_id}", response_model=InvestigationReport)
async def get_investigation_report(
    report_id: str,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> InvestigationReport:
    """Retrieve an investigation report with strict server-side tenant isolation."""
    report = orchestrator.get_report(report_id, tenant_id=current_user.tenant_id)
    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Report '{report_id}' not found for tenant '{current_user.tenant_id}'."
        )
    return report


@router.get("/actions", response_model=List[HITLProposedAction])
async def list_proposed_actions(
    status_filter: Optional[ActionApprovalStatus] = Query(None),
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> List[HITLProposedAction]:
    """List pending or reviewed defensive actions awaiting human approval."""
    return approval_service.list_actions(
        tenant_id=current_user.tenant_id,
        status_filter=status_filter
    )


@router.post("/actions/{action_id}/review", response_model=HITLProposedAction)
async def review_action(
    action_id: str,
    req: ActionReviewRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> HITLProposedAction:
    """
    Approve or reject a proposed defensive action.
    Derives approver identity server-side from verified user identity.
    Enforces tenant boundary check so tenant A cannot review tenant B's actions.
    """
    # Verify authorized role for action review
    if current_user.role not in {"analyst", "admin", "lead"}:
        raise HTTPException(
            status_code=403,
            detail=f"Role '{current_user.role}' is not authorized to review defensive actions.",
        )

    action = approval_service.get_action(action_id, tenant_id=current_user.tenant_id)
    if not action:
        raise HTTPException(
            status_code=404,
            detail=f"Proposed action '{action_id}' not found for tenant '{current_user.tenant_id}'."
        )

    # Server derives approver from verified user identity (preventing spoofing)
    verified_approver = current_user.user_id

    try:
        updated = approval_service.review_action(
            action_id=action_id,
            approver=verified_approver,
            decision=req.decision,
            tenant_id=current_user.tenant_id,
            notes=req.notes or ""
        )
        return updated
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/evaluate", response_model=Dict[str, Any])
async def run_evaluation_benchmark(
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Dict[str, Any]:
    """
    Run the Phase 15 Automated Evaluation Benchmark.
    Computes precision, recall, grounding rates, and safety enforcement metrics.
    """
    metrics = evaluator.run_benchmark()
    return metrics
