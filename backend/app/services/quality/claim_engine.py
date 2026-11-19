"""
Evidence-First Intelligence Claim Engine
Phase 13 Implementation (Requirement 13.1)

Validates structured claims with character-coordinate evidence bounds,
recovers evidence verbatim from source documents, and prevents model-generated
hallucinations from being promoted to verified intelligence claims.
"""

import hashlib
from typing import Dict, List, Optional
from fastapi import HTTPException, status

from app.models.quality import ClaimType, StructuredClaim, ValidationState
from app.core.logging import logger


class ClaimEngine:
    """
    Manages structured intelligence claims with strict cryptographic and
    character-offset evidence grounding.
    """

    def __init__(self):
        self._claims_by_id: Dict[str, StructuredClaim] = {}
        self._documents_by_id: Dict[str, str] = {}  # doc_id -> raw_text

    @property
    def store(self) -> Dict[str, StructuredClaim]:
        return self._claims_by_id

    def register_source_document(self, doc_id: str, content: str) -> str:
        """Stores raw document text and returns its authoritative SHA-256 digest."""
        self._documents_by_id[doc_id] = content
        doc_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return doc_hash

    def get_source_document(self, doc_id: str) -> Optional[str]:
        return self._documents_by_id.get(doc_id)

    def verify_and_store_claim(
        self,
        claim: StructuredClaim,
        document_text: Optional[str] = None,
    ) -> StructuredClaim:
        """
        Verifies evidence grounding against raw source document:
        1. Verifies document SHA-256 matches actual document content.
        2. Verifies document substring at [offset_start : offset_end] exactly matches quoted_evidence.
        3. Fails closed if offsets or digests are mismatched.
        """
        doc = document_text or self._documents_by_id.get(claim.source_doc_id)
        if not doc:
            claim.validation_state = ValidationState.INSUFFICIENT_EVIDENCE
            claim.provenance_history.append({
                "action": "validation_evaluated",
                "result": "insufficient_evidence",
                "reason": f"Source document '{claim.source_doc_id}' not available for offset verification.",
            })
            self._claims_by_id[claim.claim_id] = claim
            return claim

        # 1. Verify Document Digest
        actual_doc_hash = hashlib.sha256(doc.encode("utf-8")).hexdigest()
        if actual_doc_hash.lower() != claim.document_sha256.lower():
            claim.validation_state = ValidationState.REJECTED
            claim.confidence = 0.0
            claim.provenance_history.append({
                "action": "digest_verification_failed",
                "result": "rejected",
                "expected_hash": claim.document_sha256,
                "actual_hash": actual_doc_hash,
            })
            self._claims_by_id[claim.claim_id] = claim
            return claim

        # 2. Verify Character Coordinate Bounds
        if claim.offset_start < 0 or claim.offset_end > len(doc) or claim.offset_start >= claim.offset_end:
            claim.validation_state = ValidationState.REJECTED
            claim.confidence = 0.0
            claim.provenance_history.append({
                "action": "offset_bound_check_failed",
                "result": "rejected",
                "reason": f"Offsets [{claim.offset_start}:{claim.offset_end}] out of range for doc length {len(doc)}.",
            })
            self._claims_by_id[claim.claim_id] = claim
            return claim

        # 3. Exact Substring Verification (Character coordinate system)
        extracted_span = doc[claim.offset_start:claim.offset_end]
        if extracted_span.strip() != claim.quoted_evidence.strip():
            claim.validation_state = ValidationState.REJECTED
            claim.confidence = 0.0
            claim.provenance_history.append({
                "action": "evidence_mismatch",
                "result": "rejected",
                "expected": claim.quoted_evidence,
                "extracted": extracted_span,
            })
            self._claims_by_id[claim.claim_id] = claim
            return claim

        # 4. Evidence Verified Successfully
        if claim.extraction_method in ("analyst_curated", "deterministic_heuristic"):
            claim.validation_state = ValidationState.VERIFIED
        else:
            claim.validation_state = ValidationState.SUPPORTED_UNVERIFIED

        claim.provenance_history.append({
            "action": "evidence_grounding_verified",
            "result": claim.validation_state.value,
            "matched_offsets": [claim.offset_start, claim.offset_end],
            "document_digest": actual_doc_hash,
        })

        self._claims_by_id[claim.claim_id] = claim
        return claim

    def validate_and_anchor_claim(
        self,
        claim_id: str,
        claim_type: ClaimType,
        subject: str,
        predicate: str,
        obj: str,
        source_doc_id: str,
        source_identity: str,
        raw_document_text: str,
        offset_start: int,
        offset_end: int,
        quoted_evidence: str,
        observation_time: str,
        publication_time: Optional[str] = None,
        extraction_method: str = "deterministic_heuristic",
        confidence: float = 0.8,
        expected_sha256: Optional[str] = None,
    ) -> StructuredClaim:
        """
        Anchor and validate a structured intelligence claim directly against raw document text.
        """
        doc_hash = expected_sha256 or hashlib.sha256(raw_document_text.encode("utf-8")).hexdigest()
        self.register_source_document(source_doc_id, raw_document_text)

        claim = StructuredClaim(
            claim_id=claim_id,
            claim_type=claim_type,
            subject=subject,
            predicate=predicate,
            object=obj,
            source_doc_id=source_doc_id,
            source_identity=source_identity,
            document_sha256=doc_hash,
            offset_start=offset_start,
            offset_end=offset_end,
            quoted_evidence=quoted_evidence,
            observation_time=observation_time,
            publication_time=publication_time,
            extraction_method=extraction_method,  # type: ignore
            confidence=confidence,
        )
        return self.verify_and_store_claim(claim, document_text=raw_document_text)

    def get_claim(self, claim_id: str) -> Optional[StructuredClaim]:
        return self._claims_by_id.get(claim_id)

    def get_all_claims(self) -> List[StructuredClaim]:
        return list(self._claims_by_id.values())

    def list_claims(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        validation_state: Optional[ValidationState] = None,
    ) -> List[StructuredClaim]:
        claims = list(self._claims_by_id.values())
        if subject:
            claims = [c for c in claims if c.subject.lower() == subject.lower()]
        if predicate:
            claims = [c for c in claims if c.predicate.lower() == predicate.lower()]
        if validation_state:
            claims = [c for c in claims if c.validation_state == validation_state]
        return claims
