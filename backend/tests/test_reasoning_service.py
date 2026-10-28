import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.reasoning import ReasoningRequest
from app.services.reasoning.reasoning_service import reasoning_service

def test_reasoning_service_valid_multihop():
    req = ReasoningRequest(
        question="How does APT29 attack systems?",
        max_depth=3,
        max_paths=10
    )
    result = reasoning_service.reason(req)

    assert result.original_question == req.question
    assert len(result.resolved_entities) >= 1
    assert any(e.name == "APT29" for e in result.resolved_entities)
    assert len(result.accepted_paths) >= 1

    # Check multi-hop path
    multi_hop = next((p for p in result.accepted_paths if p.length >= 2), None)
    assert multi_hop is not None
    assert multi_hop.is_complete is True
    assert multi_hop.is_valid is True

    # Check that every step has evidence records
    for step in multi_hop.steps:
        assert step.is_valid is True
        assert len(step.evidence_records) >= 1
        assert step.evidence_records[0].evidence_text != ""

    # Check semantic caveats attached
    assert len(multi_hop.semantic_caveats) >= 1

    # Check statistics
    assert "execution_time_ms" in result.statistics
    assert result.statistics["accepted_paths"] >= 1

def test_reasoning_service_unknown_entity():
    req = ReasoningRequest(
        question="What techniques are used by CompletelyUnknownGroup999?"
    )
    result = reasoning_service.reason(req)
    assert len(result.resolved_entities) == 0
    assert len(result.accepted_paths) == 0
    assert any("No starting cybersecurity entities could be resolved" in w for w in result.warnings)
