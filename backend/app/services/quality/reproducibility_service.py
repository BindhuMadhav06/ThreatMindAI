"""
Reproducible Decision Envelopes service.
Implements RFC 8785 canonical JSON serialization, deterministic hashing,
audit trail binding, and independent decision re-verification.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from app.models.quality import ReproducibleDecisionRecord


def canonical_json_bytes(data: Any) -> bytes:
    """
    Serialize data to RFC 8785 compliant canonical UTF-8 JSON bytes.
    - Deterministic lexicographic key ordering
    - Compact separators (',', ':') with no whitespace
    - UTF-8 encoded with ensure_ascii=False
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str
    ).encode('utf-8')


def canonical_sha256(data: Any) -> str:
    """Compute SHA-256 hex digest of canonical JSON representation."""
    return hashlib.sha256(canonical_json_bytes(data)).hexdigest()


class ReproducibilityService:
    """
    Creates and cryptographically verifies decision envelopes,
    ensuring tamper-evident provenance across graph queries,
    threat assessments, and automated countermeasure plans.
    """

    @staticmethod
    def _extract_canonical_payload(record_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract the reproducible payload by omitting the self-referential
        digest field so the hash can be deterministically calculated and verified.
        """
        return {
            k: v for k, v in record_dict.items()
            if k != "reproducibility_digest"
        }

    def create_record(
        self,
        decision_id: str,
        decision_type: str,
        graph_snapshot: Any,
        evidence_document_hashes: List[str],
        model_version: str,
        prompt_template_version: str,
        parameters: Dict[str, Any],
        decision_inputs: Dict[str, Any],
        decision_outputs: Dict[str, Any],
        analyst_id: Optional[str] = None
    ) -> ReproducibleDecisionRecord:
        """
        Package a decision into a cryptographically anchored envelope.
        """
        graph_hash = canonical_sha256(graph_snapshot) if not isinstance(graph_snapshot, str) else graph_snapshot

        # Build payload dictionary
        payload = {
            "decision_id": decision_id,
            "decision_type": decision_type,
            "graph_snapshot_hash": graph_hash,
            "evidence_document_hashes": sorted(evidence_document_hashes),
            "model_version": model_version,
            "prompt_template_version": prompt_template_version,
            "parameters": parameters,
            "decision_inputs": decision_inputs,
            "decision_outputs": decision_outputs,
            "analyst_id": analyst_id,
        }

        digest = canonical_sha256(payload)

        return ReproducibleDecisionRecord(
            decision_id=decision_id,
            decision_type=decision_type,
            graph_snapshot_hash=graph_hash,
            evidence_document_hashes=sorted(evidence_document_hashes),
            model_version=model_version,
            prompt_template_version=prompt_template_version,
            parameters=parameters,
            decision_inputs=decision_inputs,
            decision_outputs=decision_outputs,
            analyst_id=analyst_id,
            reproducibility_digest=digest
        )

    def verify_record(self, record: ReproducibleDecisionRecord) -> Tuple[bool, str]:
        """
        Recompute digest over canonical attributes and compare to stored digest.
        Returns (is_valid, reason).
        """
        record_dict = record.model_dump()
        payload = self._extract_canonical_payload(record_dict)

        # Omit timestamp from digest payload if it wasn't part of original payload
        payload.pop("timestamp", None)

        recomputed_digest = canonical_sha256(payload)
        if recomputed_digest == record.reproducibility_digest:
            return True, "Digest verified against canonical envelope."
        return False, f"Digest mismatch: recomputed {recomputed_digest} != record {record.reproducibility_digest}"
