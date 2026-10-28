import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.answering import AnswerClaim, AnswerCitation, GroundedAnswer
from app.services.answering.answer_validator import answer_validator, AnswerValidator

@pytest.fixture
def sample_citation_pool():
    return {
        "CIT-1": AnswerCitation(
            citation_id="CIT-1",
            evidence_id="ev_abc123456789",
            source_id="src_synthetic_01",
            source_title="Synthetic CTI Report",
            evidence_text="[Synthetic Evidence] APT29 deployed Cobalt Strike Beacon payloads during lateral movement operations.",
            supported_relationship="(APT29)-[USES]->(Cobalt Strike)",
            confidence=None,
            is_synthetic=True
        ),
        "CIT-2": AnswerCitation(
            citation_id="CIT-2",
            evidence_id="ev_def987654321",
            source_id="src_synthetic_01",
            source_title="Synthetic CTI Report",
            evidence_text="[Synthetic Evidence] CVE-2021-44228 affects Apache Log4j versions 2.0-beta9 through 2.14.1.",
            supported_relationship="(CVE-2021-44228)-[AFFECTS]->(Apache Log4j)",
            confidence=None,
            is_synthetic=True
        )
    }

def test_validator_supported_claim(sample_citation_pool):
    claim = AnswerClaim(
        claim_text="APT29 deployed Cobalt Strike Beacon during lateral movement operations.",
        evidence_references=["CIT-1"],
        claim_type="relationship"
    )
    validated = answer_validator.validate_claim(claim, sample_citation_pool)
    assert validated.verification_status == "verified"
    assert any("Claim verified" in r for r in validated.validation_reasons)

def test_validator_fabricated_citation_id(sample_citation_pool):
    claim = AnswerClaim(
        claim_text="APT29 used Mimikatz to dump credentials.",
        evidence_references=["CIT-999"],  # Non-existent citation
        claim_type="relationship"
    )
    validated = answer_validator.validate_claim(claim, sample_citation_pool)
    assert validated.verification_status == "unverified"
    assert any("does not exist in citation pool" in r for r in validated.validation_reasons)

def test_validator_unsupported_attack_success_extrapolation(sample_citation_pool):
    # Citation 1 only documents deploying Cobalt Strike, NOT a confirmed breach or network destruction
    claim = AnswerClaim(
        claim_text="APT29 successfully breached the network using Cobalt Strike.",
        evidence_references=["CIT-1"],
        claim_type="relationship"
    )
    validated = answer_validator.validate_claim(claim, sample_citation_pool)
    assert validated.verification_status == "unverified"
    assert any("asserts unproven attack success" in r for r in validated.validation_reasons)

def test_validator_semantic_misalignment(sample_citation_pool):
    # Claim references CIT-1, but talks about quantum encryption which has zero overlap with Cobalt Strike
    claim = AnswerClaim(
        claim_text="Quantum encryption protocols were compromised across satellite uplinks.",
        evidence_references=["CIT-1"],
        claim_type="relationship"
    )
    validated = answer_validator.validate_claim(claim, sample_citation_pool)
    assert validated.verification_status == "unverified"
    assert any("insufficient lexical/entity alignment" in r for r in validated.validation_reasons)

def test_validator_metadata_integrity_failure():
    bad_pool = {
        "CIT-1": AnswerCitation(
            citation_id="CIT-1",
            evidence_id="transient_neo4j_123",  # Invalid ID format (must be ev_...)
            source_id="unknown_source",         # Unverified source
            evidence_text="Sample text",
            supported_relationship="(A)-[USES]->(B)"
        )
    }
    claim = AnswerClaim(
        claim_text="A uses B for operations.",
        evidence_references=["CIT-1"]
    )
    validated = answer_validator.validate_claim(claim, bad_pool)
    assert validated.verification_status == "unverified"
    assert any("deterministic evidence identifier" in r for r in validated.validation_reasons)

def test_validator_overall_answer_statuses(sample_citation_pool):
    # Fully grounded answer
    good_answer = GroundedAnswer(
        summary="APT29 tools and vulnerabilities summary.",
        direct_answer="APT29 deployed Cobalt Strike Beacon [CIT-1]. CVE-2021-44228 affects Apache Log4j [CIT-2].",
        claims=[
            AnswerClaim(
                claim_text="APT29 deployed Cobalt Strike Beacon.",
                evidence_references=["CIT-1"]
            ),
            AnswerClaim(
                claim_text="CVE-2021-44228 affects Apache Log4j.",
                evidence_references=["CIT-2"]
            )
        ],
        citations=list(sample_citation_pool.values()),
        referenced_paths=["path_0"],
        caveats=[],
        sufficiency_status="sufficient",
        is_synthetic=True
    )
    _, res_good = answer_validator.validate_answer(good_answer, sample_citation_pool)
    assert res_good.grounding_status == "fully_grounded"
    assert res_good.is_valid is True
    assert len(res_good.verified_claims) == 2
    assert any("SYNTHETIC DATA NOTICE" in w for w in res_good.warnings)

    # Partially grounded answer
    partial_answer = GroundedAnswer(
        summary="Summary",
        direct_answer="Answer",
        claims=[
            AnswerClaim(
                claim_text="APT29 deployed Cobalt Strike Beacon.",
                evidence_references=["CIT-1"]
            ),
            AnswerClaim(
                claim_text="APT29 successfully breached the network [CIT-1].",
                evidence_references=["CIT-1"]  # Unsupported attack success
            )
        ],
        citations=list(sample_citation_pool.values()),
        referenced_paths=["path_0"],
        caveats=[],
        sufficiency_status="sufficient",
        is_synthetic=True
    )
    _, res_partial = answer_validator.validate_answer(partial_answer, sample_citation_pool)
    assert res_partial.grounding_status == "partially_grounded"
    assert len(res_partial.verified_claims) == 1
    assert len(res_partial.unverified_claims) == 1

    # Insufficient evidence answer
    insufficient_answer = GroundedAnswer(
        summary="No evidence",
        direct_answer="ThreatMind could not establish a sufficiently supported relationship from the currently available sources.",
        claims=[],
        citations=[],
        referenced_paths=[],
        caveats=[],
        sufficiency_status="insufficient"
    )
    _, res_insufficient = answer_validator.validate_answer(insufficient_answer, {})
    assert res_insufficient.grounding_status == "insufficient_evidence"
    assert res_insufficient.is_valid is True
