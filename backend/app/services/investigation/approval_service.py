"""
Phase 15: Human-in-the-Loop (HITL) Defensive Action Approval Service.
Maintains a secure, auditable queue of proposed defensive actions.
Guarantees zero autonomous execution of environment-modifying operations,
enforcing explicit analyst authorization and complete audit logging.
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
    Approval workflow manager for security actions.
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
                    "details": "Proposed by Trusted AI Investigation Orchestrator."
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
        notes: str = ""
    ) -> HITLProposedAction:
        """
        Record human analyst approval or rejection with audit history.
        """
        action = self._actions_by_id.get(action_id)
        if not action:
            raise KeyError(f"Proposed action '{action_id}' not found.")

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
        action = self._actions_by_id.get(action_id)
        if not action:
            return None
        if tenant_id and action.tenant_id != tenant_id:
            return None
        return action

    def list_actions(
        self,
        tenant_id: str,
        status_filter: Optional[ActionApprovalStatus] = None
    ) -> List[HITLProposedAction]:
        """List proposed actions strictly scoped to the requesting tenant."""
        actions = [a for a in self._actions_by_id.values() if a.tenant_id == tenant_id]
        if status_filter:
            actions = [a for a in actions if a.approval_status == status_filter]
        return actions
