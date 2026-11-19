"""
Claim Provenance & Contradiction Dispute Ledger
Phase 13 Implementation (Requirement 13.2)

Maintains persistent records of attribution disputes, vendor contradictions,
and analyst resolutions without ever overwriting or deleting historical evidence.
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status

from app.models.quality import (
    DisputeLedgerEntry,
    DisputeResolutionStatus,
    StructuredClaim,
    ValidationState,
)
from app.services.quality.claim_engine import ClaimEngine


class DisputeLedger:
    """
    Manages persistent contradiction tracking and human resolution workflows.
    """

    def __init__(self, claim_engine: Optional[ClaimEngine] = None):
        self.claim_engine = claim_engine or ClaimEngine()
        self._disputes_by_id: Dict[str, DisputeLedgerEntry] = {}
        # Directed contradiction graph: (claim_a, claim_b) -> relation
        self._claim_relationships: List[Dict[str, str]] = []

    def register_dispute(
        self,
        claim_a: StructuredClaim,
        claim_b: StructuredClaim,
        dispute_type: str = "ATTRIBUTION_DISPUTE",
    ) -> DisputeLedgerEntry:
        """
        Creates a persistent dispute between two conflicting claims.
        Updates validation_state of both claims to DISPUTED.
        Establishes mutual CONTRADICTS relationships.
        """
        dispute_id = f"dispute-{uuid.uuid4()}"

        # Record CONTRADICTS relationship
        self._claim_relationships.append({
            "source_claim": claim_a.claim_id,
            "target_claim": claim_b.claim_id,
            "relationship": "CONTRADICTS",
        })
        self._claim_relationships.append({
            "source_claim": claim_b.claim_id,
            "target_claim": claim_a.claim_id,
            "relationship": "CONTRADICTS",
        })

        # Update claims in ClaimEngine without deleting evidence
        claim_a.validation_state = ValidationState.DISPUTED
        if claim_b.claim_id not in claim_a.contradicting_evidence_ids:
            claim_a.contradicting_evidence_ids.append(claim_b.claim_id)
        claim_a.provenance_history.append({
            "action": "dispute_registered",
            "dispute_id": dispute_id,
            "conflicting_claim": claim_b.claim_id,
            "competing_source": claim_b.source_identity,
        })

        claim_b.validation_state = ValidationState.DISPUTED
        if claim_a.claim_id not in claim_b.contradicting_evidence_ids:
            claim_b.contradicting_evidence_ids.append(claim_a.claim_id)
        claim_b.provenance_history.append({
            "action": "dispute_registered",
            "dispute_id": dispute_id,
            "conflicting_claim": claim_a.claim_id,
            "competing_source": claim_a.source_identity,
        })

        self.claim_engine.verify_and_store_claim(claim_a)
        self.claim_engine.verify_and_store_claim(claim_b)

        entry = DisputeLedgerEntry(
            dispute_id=dispute_id,
            claim_a_id=claim_a.claim_id,
            claim_b_id=claim_b.claim_id,
            dispute_type=dispute_type,  # type: ignore
            subject=claim_a.subject,
            predicate=claim_a.predicate,
            competing_values={
                "claim_a": claim_a.object,
                "claim_b": claim_b.object,
            },
            sources=[claim_a.source_identity, claim_b.source_identity],
            evidence_refs=[claim_a.source_doc_id, claim_b.source_doc_id],
            source_reliabilities={
                claim_a.source_identity: claim_a.confidence,
                claim_b.source_identity: claim_b.confidence,
            },
            resolution_status=DisputeResolutionStatus.OPEN,
        )

        self._disputes_by_id[dispute_id] = entry
        return entry

    def resolve_dispute(
        self,
        dispute_id: str,
        favored_claim_id: Optional[str] = None,
        analyst_id: Optional[str] = None,
        rationale: Optional[str] = None,
        resolution_rationale: Optional[str] = None,
        resolved_by: Optional[str] = None,
        claims_store: Optional[Any] = None,
    ) -> DisputeLedgerEntry:
        """
        Executes an analyst resolution of a dispute.
        INVARIANT: Original conflicting evidence is NEVER deleted.
        If a claim is favored, it transitions to VERIFIED; the other claim remains preserved as DISPUTED.
        """
        dispute = self._disputes_by_id.get(dispute_id)
        if not dispute:
            raise KeyError(f"Dispute with ID '{dispute_id}' not found.")

        final_rationale = rationale or resolution_rationale or "Resolved by analyst review."
        final_analyst = analyst_id or resolved_by or "analyst"

        dispute.resolution_status = DisputeResolutionStatus.ANALYST_RESOLVED
        dispute.resolution_rationale = final_rationale
        dispute.resolved_by = final_analyst
        dispute.resolved_at = datetime.now(timezone.utc).isoformat()

        # Update claim states if favored claim specified
        if favored_claim_id:
            other_claim_id = dispute.claim_b_id if favored_claim_id == dispute.claim_a_id else dispute.claim_a_id

            favored_claim = self.claim_engine.get_claim(favored_claim_id)
            if not favored_claim and claims_store and favored_claim_id in claims_store:
                favored_claim = claims_store[favored_claim_id]

            if favored_claim:
                favored_claim.validation_state = ValidationState.VERIFIED
                favored_claim.provenance_history.append({
                    "action": "dispute_resolved_favored",
                    "dispute_id": dispute_id,
                    "resolved_by": final_analyst,
                    "rationale": final_rationale,
                })

            other_claim = self.claim_engine.get_claim(other_claim_id)
            if not other_claim and claims_store and other_claim_id in claims_store:
                other_claim = claims_store[other_claim_id]

            if other_claim:
                # Do NOT delete; preserve historical record with dispute note
                other_claim.validation_state = ValidationState.DISPUTED
                other_claim.provenance_history.append({
                    "action": "dispute_resolved_unfavored",
                    "dispute_id": dispute_id,
                    "resolved_by": final_analyst,
                    "rationale": final_rationale,
                })

        return dispute

    def get_dispute(self, dispute_id: str) -> Optional[DisputeLedgerEntry]:
        return self._disputes_by_id.get(dispute_id)

    def get_all_disputes(self) -> List[DisputeLedgerEntry]:
        return list(self._disputes_by_id.values())

    def list_disputes(
        self,
        status_filter: Optional[DisputeResolutionStatus] = None,
        subject: Optional[str] = None,
    ) -> List[DisputeLedgerEntry]:
        disputes = list(self._disputes_by_id.values())
        if status_filter:
            disputes = [d for d in disputes if d.resolution_status == status_filter]
        if subject:
            disputes = [d for d in disputes if d.subject.lower() == subject.lower()]
        return disputes
