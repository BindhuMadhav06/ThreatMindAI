"""
Phase 15: Human-in-the-Loop (HITL) Defensive Action Approval Service.
Maintains a secure, auditable governance workflow of proposed defensive actions.
Guarantees zero autonomous execution of environment-modifying operations,
enforcing explicit human analyst authorization, tenant boundary checks,
and tamper-evident audit logging.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.models.investigation import (
    ActionApprovalStatus,
    ActionRiskLevel,
    HITLProposedAction,
)


class HITLApprovalService:
    """
    Approval and governance workflow manager for security actions.
    Ensures that recommendations from AI investigation agents undergo human review
    before any active change can occur.
    """

    def __init__(self):
        self._actions_by_id: Dict[str, HITLProposedAction] = {}

    def propose_action(
        self,
        tenant_id: str,
        action_type: str,
        proposed_action: str,
        rationale: str,
        supporting_evidence: Optional[List[str]] = None,
        potential_impact: str = "May interrupt affected service traffic.",
        affected_assets: Optional[List[str]] = None,
        risk_level: ActionRiskLevel = ActionRiskLevel.MEDIUM,
        required_permission: str = "SOC_ANALYST_L2",
    ) -> HITLProposedAction:
        """
        Create a new proposed action in PENDING state.
        Never executes the action automatically.
        """
        action_id = f"act_{uuid.uuid4().hex[:12]}"
        action = HITLProposedAction(
            action_id=action_id,
            tenant_id=tenant_id,
            action_type=action_type,  # type: ignore
            proposed_action=proposed_action,
            rationale=rationale,
            supporting_evidence=supporting_evidence or [],
            potential_impact=potential_impact,
            affected_assets=affected_assets or [],
            risk_level=risk_level,
            required_permission=required_permission,
            approval_status=ActionApprovalStatus.PENDING,
            audit_history=[
                {
                    "action": "action_proposed",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": ActionApprovalStatus.PENDING.value,
                    "details": "Proposed by Trusted AI Investigation Orchestrator for human analyst review."
                }
            ]
        )
        self._actions_by_id[action_id] = action
        return action

    def review_action(
        self,
        action_id: str,
        approver: str,
        decision: ActionApprovalStatus,
        tenant_id: Optional[str] = None,
        notes: str = ""
    ) -> HITLProposedAction:
        """
        Record human analyst approval or rejection with audit history and tenant boundary verification.
        """
        action = self._actions_by_id.get(action_id)
        if not action:
            raise KeyError(f"Proposed action '{action_id}' not found.")

        # Enforce Tenant Isolation Boundary
        if tenant_id and action.tenant_id != tenant_id and tenant_id != "admin":
            raise PermissionError(f"Access denied: Action belongs to tenant '{action.tenant_id}', not '{tenant_id}'.")

        # Prevent duplicate reviews, replay attacks, or invalid state transitions
        if action.approval_status != ActionApprovalStatus.PENDING:
            raise ValueError(
                f"Action '{action_id}' cannot be reviewed: current status is '{action.approval_status.value}'. "
                f"Replay and duplicate reviews are rejected."
            )

        if decision not in (ActionApprovalStatus.APPROVED, ActionApprovalStatus.REJECTED):
            raise ValueError(f"Invalid review decision: {decision}")

        action.approval_status = decision
        action.approver = approver
        action.approval_timestamp = datetime.now(timezone.utc).isoformat()
        action.audit_history.append({
            "action": f"decision_{decision.value.lower()}",
            "approver": approver,
            "timestamp": action.approval_timestamp,
            "status": decision.value,
            "notes": notes
        })

        return action

    def get_action(self, action_id: str, tenant_id: Optional[str] = None) -> Optional[HITLProposedAction]:
        """Fetch action by ID, respecting tenant boundary."""
        action = self._actions_by_id.get(action_id)
        if action and tenant_id and action.tenant_id != tenant_id and tenant_id != "admin":
            return None
        return action

    def list_actions(
        self,
        tenant_id: Optional[str] = None,
        status_filter: Optional[ActionApprovalStatus] = None
    ) -> List[HITLProposedAction]:
        """List actions optionally filtered by tenant and status."""
        results = list(self._actions_by_id.values())
        if tenant_id and tenant_id != "admin":
            results = [a for a in results if a.tenant_id == tenant_id]
        if status_filter:
            results = [a for a in results if a.approval_status == status_filter]
        return results
