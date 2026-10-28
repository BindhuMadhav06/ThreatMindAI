import pytest
import sys
import os
from typing import Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.answering import AnswerRequest
from app.services.answering.answer_generator import AnswerGenerator
from app.services.answering.prompt_builder import ABSTENTION_PHRASE
from app.services.llm.base_provider import BaseLLMProvider

class MockAnsweringLLM(BaseLLMProvider):
    def get_provider_name(self) -> str:
        return "mock_answering_llm"

    def is_available(self) -> bool:
        return True

    def generate_response(self, prompt: str, system_instruction=None, temperature=0.2) -> str:
        return "Mock direct answer"

    def generate_structured_output(self, prompt: str, schema: Any, system_instruction=None) -> dict:
        return {
            "summary": "APT29 utilizes Cobalt Strike and PowerShell in documented execution chains.",
            "direct_answer": "APT29 has deployed Cobalt Strike Beacon payloads [CIT-1], and Cobalt Strike invokes PowerShell scripts for stager execution [CIT-2].",
            "claims": [
                {
                    "claim_text": "APT29 deployed Cobalt Strike Beacon payloads.",
                    "evidence_references": ["CIT-1"],
                    "claim_type": "relationship"
                },
                {
                    "claim_text": "Cobalt Strike invokes PowerShell scripts for execution.",
                    "evidence_references": ["CIT-2"],
                    "claim_type": "relationship"
                }
            ],
            "referenced_paths": ["reason_path_0"],
            "caveats": ["Observed association does not imply attack success."],
            "sufficiency_status": "sufficient"
        }

class MockOfflineLLM(BaseLLMProvider):
    def get_provider_name(self) -> str:
        return "mock_offline_llm"

    def is_available(self) -> bool:
        return False

    def generate_response(self, prompt: str, system_instruction=None, temperature=0.2) -> str:
        return ""

    def generate_structured_output(self, prompt: str, schema: Any, system_instruction=None) -> dict:
        return {}

def test_answer_generator_with_mock_llm():
    generator = AnswerGenerator(llm_provider=MockAnsweringLLM())
    req = AnswerRequest(
        question="How does APT29 attack systems?",
        max_depth=3,
        max_paths=5
    )
    response = generator.generate_answer(req)

    assert response.original_question == req.question
    assert response.grounding_status in ["fully_grounded", "partially_grounded"]
    assert response.answer.sufficiency_status == "sufficient"
    assert len(response.claims) >= 1
    assert any(c.verification_status == "verified" for c in response.claims)
    assert len(response.citations) >= 1
    # Check synthetic notice
    assert response.answer.is_synthetic is True
    assert any("SYNTHETIC DATA NOTICE" in w for w in response.warnings)
    assert "statistics" in response.model_dump()
    assert response.statistics["provider"] == "mock_answering_llm"

def test_answer_generator_deterministic_offline_fallback():
    # LLM is unavailable; generator must produce a valid, validated fallback answer directly from graph evidence
    generator = AnswerGenerator(llm_provider=MockOfflineLLM())
    req = AnswerRequest(
        question="What vulnerabilities are exploited by APT29?",
        max_depth=2,
        max_paths=5
    )
    response = generator.generate_answer(req)

    assert response.original_question == req.question
    assert response.grounding_status in ["fully_grounded", "partially_grounded"]
    assert len(response.claims) >= 1
    assert any(c.verification_status == "verified" for c in response.claims)
    assert len(response.citations) >= 1
    assert any("CVE-2021-44228" in c.claim_text for c in response.claims)
    assert response.answer.is_synthetic is True

def test_answer_generator_unknown_entity_abstention():
    generator = AnswerGenerator(llm_provider=MockAnsweringLLM())
    req = AnswerRequest(
        question="What techniques are used by CompletelyUnknownGroup999?"
    )
    response = generator.generate_answer(req)

    assert response.grounding_status == "insufficient_evidence"
    assert response.answer.direct_answer == ABSTENTION_PHRASE
    assert response.answer.sufficiency_status == "insufficient"
    assert len(response.claims) == 0
    assert len(response.citations) == 0
    assert any("Abstention triggered" in w for w in response.warnings)

def test_answer_generator_adversarial_unsupported_success():
    class MockAdversarialLLM(BaseLLMProvider):
        def get_provider_name(self) -> str:
            return "mock_adversarial_llm"
        def is_available(self) -> bool:
            return True
        def generate_response(self, prompt, system_instruction=None, temperature=0.2):
            return ""
        def generate_structured_output(self, prompt, schema, system_instruction=None):
            return {
                "summary": "APT29 compromise analysis.",
                "direct_answer": "APT29 successfully breached the network [CIT-1].",
                "claims": [
                    {
                        "claim_text": "APT29 successfully breached the network.",
                        "evidence_references": ["CIT-1"],
                        "claim_type": "relationship"
                    }
                ],
                "referenced_paths": ["reason_path_0"],
                "caveats": [],
                "sufficiency_status": "sufficient"
            }

    generator = AnswerGenerator(llm_provider=MockAdversarialLLM())
    req = AnswerRequest(question="How does APT29 attack systems?")
    response = generator.generate_answer(req)

    # Claim asserts 'successfully breached', which is not in evidence
    assert any(c.verification_status == "unverified" for c in response.claims)
    assert response.grounding_status in ["unsupported", "partially_grounded"]
    assert any("asserts unproven attack success" in "; ".join(c.validation_reasons) for c in response.claims)
