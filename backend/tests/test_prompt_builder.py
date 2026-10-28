import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.query import EvidenceRecord
from app.models.reasoning import ReasoningStep, EvidenceBackedPath
from app.services.answering.prompt_builder import PromptBuilder, ABSTENTION_PHRASE

def test_prompt_builder_citation_pool_construction():
    ev1 = EvidenceRecord(
        source_id="src_synthetic_01",
        source_title="Synthetic Report",
        evidence_text="[Synthetic Evidence] APT29 deployed Cobalt Strike Beacon payloads.",
        relationship="(APT29)-[USES]->(Cobalt Strike)",
        confidence=None
    )
    step1 = ReasoningStep(
        step_number=1,
        source_id="actor_apt29",
        source_label="ThreatActor",
        source_name="APT29",
        rel_type="USES",
        target_id="malware_cobaltstrike",
        target_label="Malware",
        target_name="Cobalt Strike",
        evidence_records=[ev1]
    )
    path = EvidenceBackedPath(
        path_id="path_0",
        steps=[step1],
        length=1,
        semantic_caveats=["Correlation does not imply causality."]
    )

    sources = [
        {
            "id": "src_synthetic_01",
            "title": "Synthetic Report",
            "url": "https://example.test",
            "publisher": "Test Labs",
            "is_synthetic": True
        }
    ]

    citation_pool = PromptBuilder.build_citation_pool([path], sources)

    assert len(citation_pool) == 1
    assert "CIT-1" in citation_pool
    cit = citation_pool["CIT-1"]
    assert cit.citation_id == "CIT-1"
    assert cit.evidence_id.startswith("ev_")
    assert cit.source_id == "src_synthetic_01"
    assert cit.is_synthetic is True
    assert cit.confidence is None
    assert cit.supported_relationship == "(APT29)-[USES]->(Cobalt Strike)"

def test_prompt_builder_grounding_prompt():
    ev1 = EvidenceRecord(
        source_id="src_synthetic_01",
        evidence_text="[Synthetic Evidence] APT29 targeted Apache Log4j.",
        relationship="(APT29)-[EXPLOITS]->(Log4j)"
    )
    step1 = ReasoningStep(
        step_number=1,
        source_id="actor_apt29",
        source_label="ThreatActor",
        source_name="APT29",
        rel_type="EXPLOITS",
        target_id="vuln_log4j",
        target_label="Vulnerability",
        target_name="Log4j",
        evidence_records=[ev1]
    )
    path = EvidenceBackedPath(
        path_id="path_0",
        steps=[step1],
        length=1,
        semantic_caveats=["Observational correlation only."]
    )

    sources = [{"id": "src_synthetic_01", "is_synthetic": True}]
    citation_pool = PromptBuilder.build_citation_pool([path], sources)

    sys_instruction, user_prompt = PromptBuilder.build_grounding_prompt(
        question="How does APT29 exploit Log4j?",
        citation_pool=citation_pool,
        paths=[path],
        caveats=["Observational correlation only."]
    )

    assert "NO GUESSING" in sys_instruction
    assert "NO UNSUPPORTED ATTACK SUCCESS" in sys_instruction
    assert ABSTENTION_PHRASE in sys_instruction
    assert "[CIT-1]" in user_prompt
    assert "SYNTHETIC" in user_prompt
    assert "Observational correlation only." in user_prompt

def test_prompt_builder_structured_schema():
    schema = PromptBuilder.get_structured_output_schema()
    assert schema["type"] == "object"
    assert "summary" in schema["properties"]
    assert "direct_answer" in schema["properties"]
    assert "claims" in schema["properties"]
    assert "sufficiency_status" in schema["properties"]
