import re
from typing import List, Dict, Any, Tuple, Set, Optional
from app.models.answering import (
    AnswerClaim,
    AnswerCitation,
    GroundedAnswer,
    AnswerValidationResult
)
from app.core.logging import logger

STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "and", "or", "in", "on", "at",
    "to", "for", "with", "by", "from", "of", "it", "that", "this", "which", "as",
    "be", "has", "have", "had", "using", "uses", "used", "during", "been"
}

COMPROMISE_PATTERNS = [
    r"\bsuccessfully\s+compromised?\b",
    r"\bsuccessfully\s+breached?\b",
    r"\bbreached\s+the\s+network\b",
    r"\bcomplete\s+takeover\b",
    r"\bdestroyed\b",
    r"\bcatastrophic\s+damage\b",
    r"\binfiltrated\s+successfully\b",
    r"\bconfirmed\s+breach\b",
    r"\bcompromised\s+the\s+system\b",
    r"\bcaused\s+the\s+outage\b"
]

class AnswerValidator:
    """
    Multi-stage verification engine enforcing evidence grounding.
    Separates structural citation integrity from semantic grounding.
    """

    @classmethod
    def _tokenize(cls, text: str) -> Set[str]:
        words = re.findall(r"[A-Za-z0-9_-]+", text.lower())
        return {w for w in words if w not in STOPWORDS and len(w) > 2}

    @classmethod
    def validate_citation_integrity(
        cls,
        claim: AnswerClaim,
        citation_pool: Dict[str, AnswerCitation]
    ) -> Tuple[bool, List[str]]:
        """
        Deterministic Check 1: Verifies that cited citation IDs exist in the active citation pool.
        """
        reasons = []
        if not claim.evidence_references:
            reasons.append("Claim has empty evidence references.")
            return False, reasons

        all_exist = True
        for ref in claim.evidence_references:
            if ref not in citation_pool:
                reasons.append(f"Citation ID '{ref}' does not exist in citation pool.")
                all_exist = False

        return all_exist, reasons

    @classmethod
    def validate_metadata_integrity(
        cls,
        claim: AnswerClaim,
        citation_pool: Dict[str, AnswerCitation]
    ) -> Tuple[bool, List[str]]:
        """
        Deterministic Check 2: Verifies that citation records have valid source IDs and evidence IDs.
        """
        reasons = []
        for ref in claim.evidence_references:
            cit = citation_pool.get(ref)
            if not cit:
                continue
            if not cit.evidence_id or not cit.evidence_id.startswith("ev_"):
                reasons.append(f"Citation '{ref}' lacks a valid deterministic evidence identifier.")
            if not cit.source_id or cit.source_id == "unknown_source":
                reasons.append(f"Citation '{ref}' lacks a verified source identifier.")

        return len(reasons) == 0, reasons

    @classmethod
    def validate_unsupported_extrapolation(
        cls,
        claim: AnswerClaim,
        citation_pool: Dict[str, AnswerCitation]
    ) -> Tuple[bool, List[str]]:
        """
        Deterministic Check 3: Detects assertions of attack success, confirmed compromise,
        or extreme causality not explicitly substantiated in the cited passage text.
        """
        reasons = []
        claim_text_lower = claim.claim_text.lower()

        # Check if claim asserts aggressive attack success
        has_compromise_assertion = any(
            re.search(pat, claim_text_lower) for pat in COMPROMISE_PATTERNS
        )

        if has_compromise_assertion:
            # Check if any cited citation explicitly supports this assertion
            supported_by_passage = False
            for ref in claim.evidence_references:
                cit = citation_pool.get(ref)
                if not cit:
                    continue
                ev_lower = cit.evidence_text.lower()
                if any(re.search(pat, ev_lower) for pat in COMPROMISE_PATTERNS):
                    supported_by_passage = True
                    break

            if not supported_by_passage:
                reasons.append(
                    "Claim asserts unproven attack success, confirmed compromise, or severe causality "
                    "not explicitly documented in the cited passage text."
                )

        return len(reasons) == 0, reasons

    @classmethod
    def validate_semantic_and_passage_alignment(
        cls,
        claim: AnswerClaim,
        citation_pool: Dict[str, AnswerCitation]
    ) -> Tuple[bool, List[str]]:
        """
        Deterministic Check 4: Checks token and entity overlap between claim and cited passages.
        Ensures the claim accurately represents the passage rather than misattributing it.
        """
        reasons = []
        claim_tokens = cls._tokenize(claim.claim_text)
        if not claim_tokens:
            reasons.append("Claim text contains no substantive tokens.")
            return False, reasons

        has_aligned_citation = False
        for ref in claim.evidence_references:
            cit = citation_pool.get(ref)
            if not cit:
                continue

            passage_tokens = cls._tokenize(cit.evidence_text)
            rel_tokens = cls._tokenize(cit.supported_relationship)
            combined_ref_tokens = passage_tokens | rel_tokens

            overlap = claim_tokens & combined_ref_tokens
            # Must share at least 2 substantive tokens or >25% of claim tokens
            overlap_ratio = len(overlap) / len(claim_tokens) if claim_tokens else 0.0

            if len(overlap) >= 2 or overlap_ratio >= 0.25:
                has_aligned_citation = True
                break

        if not has_aligned_citation:
            reasons.append(
                f"Claim exhibits insufficient lexical/entity alignment with cited evidence passages "
                f"({list(claim.evidence_references)})."
            )

        return has_aligned_citation, reasons

    @classmethod
    def validate_claim(
        cls,
        claim: AnswerClaim,
        citation_pool: Dict[str, AnswerCitation]
    ) -> AnswerClaim:
        """
        Executes all validation checks for a single claim.
        """
        all_reasons = []

        # Check 1: Citation pool existence
        cit_ok, cit_reasons = cls.validate_citation_integrity(claim, citation_pool)
        all_reasons.extend(cit_reasons)

        if cit_ok:
            # Check 2: Metadata integrity
            meta_ok, meta_reasons = cls.validate_metadata_integrity(claim, citation_pool)
            all_reasons.extend(meta_reasons)

            # Check 3: Unsupported extrapolation
            extrap_ok, extrap_reasons = cls.validate_unsupported_extrapolation(claim, citation_pool)
            all_reasons.extend(extrap_reasons)

            # Check 4: Passage alignment
            align_ok, align_reasons = cls.validate_semantic_and_passage_alignment(claim, citation_pool)
            all_reasons.extend(align_reasons)

            is_verified = meta_ok and extrap_ok and align_ok
        else:
            is_verified = False

        status = "verified" if is_verified else "unverified"
        if is_verified:
            all_reasons.append("Claim verified: Supported by cited evidence passage and relationship.")

        return AnswerClaim(
            claim_text=claim.claim_text,
            evidence_references=claim.evidence_references,
            claim_type=claim.claim_type,
            verification_status=status,
            validation_reasons=all_reasons
        )

    @classmethod
    def validate_answer(
        cls,
        answer: GroundedAnswer,
        citation_pool: Dict[str, AnswerCitation]
    ) -> Tuple[GroundedAnswer, AnswerValidationResult]:
        """
        Validates all claims in the answer, separates verified from unverified claims,
        and computes overall grounding status and warnings.
        """
        evaluated_claims: List[AnswerClaim] = []
        verified_claims: List[AnswerClaim] = []
        unverified_claims: List[AnswerClaim] = []
        rejected_reasons: List[str] = []
        warnings: List[str] = []

        # Check for synthetic evidence
        has_synthetic = any(cit.is_synthetic for cit in answer.citations) or answer.is_synthetic
        if has_synthetic:
            warnings.append(
                "SYNTHETIC DATA NOTICE: Response is grounded in synthetic demonstration data, "
                "not verified real-world threat intelligence."
            )

        # Abstention check
        if answer.sufficiency_status == "insufficient" or not answer.claims:
            val_res = AnswerValidationResult(
                is_valid=True,
                grounding_status="insufficient_evidence",
                verified_claims=[],
                unverified_claims=[],
                rejected_reasons=[],
                warnings=warnings
            )
            return answer, val_res

        # Validate each individual claim
        for claim in answer.claims:
            eval_claim = cls.validate_claim(claim, citation_pool)
            evaluated_claims.append(eval_claim)

            if eval_claim.verification_status == "verified":
                verified_claims.append(eval_claim)
            else:
                unverified_claims.append(eval_claim)
                rejected_reasons.extend(eval_claim.validation_reasons)
                warnings.append(
                    f"UNVERIFIED CLAIM: '{eval_claim.claim_text[:80]}...' - {'; '.join(eval_claim.validation_reasons)}"
                )

        # Determine overall grounding status
        if len(verified_claims) > 0 and len(unverified_claims) == 0:
            grounding_status = "fully_grounded"
            is_valid = True
        elif len(verified_claims) > 0 and len(unverified_claims) > 0:
            grounding_status = "partially_grounded"
            is_valid = True
        else:
            grounding_status = "unsupported"
            is_valid = False

        updated_answer = GroundedAnswer(
            summary=answer.summary,
            direct_answer=answer.direct_answer,
            claims=evaluated_claims,
            citations=list(citation_pool.values()),
            referenced_paths=answer.referenced_paths,
            caveats=answer.caveats,
            sufficiency_status=answer.sufficiency_status,
            is_synthetic=has_synthetic
        )

        val_result = AnswerValidationResult(
            is_valid=is_valid,
            grounding_status=grounding_status,
            verified_claims=verified_claims,
            unverified_claims=unverified_claims,
            rejected_reasons=rejected_reasons,
            warnings=warnings
        )

        logger.info(
            f"Answer validation completed: status={grounding_status}, "
            f"verified={len(verified_claims)}, unverified={len(unverified_claims)}"
        )

        return updated_answer, val_result

answer_validator = AnswerValidator()
