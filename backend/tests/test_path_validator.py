import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.query import EvidenceRecord
from app.models.reasoning import ReasoningStep
from app.services.reasoning.path_validator import path_validator

def create_mock_step(
    step_num: int,
    src_id: str,
    src_label: str,
    rel: str,
    tgt_id: str,
    tgt_label: str,
    evidence_text: str = "Valid evidence text quote."
) -> ReasoningStep:
    ev_list = []
    if evidence_text:
        ev_list.append(EvidenceRecord(
            source_id="src_001",
            source_title="Advisory 1",
            evidence_text=evidence_text,
            relationship=f"({src_id})-[{rel}]->({tgt_id})"
        ))
    return ReasoningStep(
        step_number=step_num,
        source_id=src_id,
        source_label=src_label,
        source_name=src_id,
        rel_type=rel,
        target_id=tgt_id,
        target_label=tgt_label,
        target_name=tgt_id,
        evidence_records=ev_list
    )

def test_validate_step_valid():
    step = create_mock_step(1, "actor_apt29", "ThreatActor", "USES", "malware_cobalt", "Malware")
    is_valid, notes = path_validator.validate_step(step)
    assert is_valid is True
    assert len(notes) == 0

def test_validate_step_missing_evidence():
    step = create_mock_step(1, "actor_apt29", "ThreatActor", "USES", "malware_cobalt", "Malware", evidence_text="")
    is_valid, notes = path_validator.validate_step(step)
    assert is_valid is False
    assert any("No evidence records" in n for n in notes)

def test_validate_step_disallowed_relationship():
    step = create_mock_step(1, "actor_apt29", "ThreatActor", "DISALLOWED_REL", "malware_cobalt", "Malware")
    is_valid, notes = path_validator.validate_step(step)
    assert is_valid is False
    assert any("Disallowed relationship" in n for n in notes)

def test_validate_path_valid_two_hop():
    s1 = create_mock_step(1, "actor_apt29", "ThreatActor", "USES", "malware_cobalt", "Malware")
    s2 = create_mock_step(2, "malware_cobalt", "Malware", "USES_TECHNIQUE", "tech_ps", "Technique")
    
    val_res = path_validator.validate_path([s1, s2])
    assert val_res.is_valid is True
    assert val_res.validation_status == "accepted"
    assert val_res.valid_steps_count == 2

def test_validate_path_cycle_detection():
    # A -> B -> A (Cycle)
    s1 = create_mock_step(1, "actor_apt29", "ThreatActor", "USES", "malware_cobalt", "Malware")
    s2 = create_mock_step(2, "malware_cobalt", "Malware", "TARGETS", "actor_apt29", "ThreatActor")

    val_res = path_validator.validate_path([s1, s2])
    assert val_res.is_valid is False
    assert any("Cycle detected" in r for r in val_res.reasons)

def test_validate_path_disconnected_steps():
    # Step 1 ends at malware_cobalt, but Step 2 starts at tool_mimikatz
    s1 = create_mock_step(1, "actor_apt29", "ThreatActor", "USES", "malware_cobalt", "Malware")
    s2 = create_mock_step(2, "tool_mimikatz", "Tool", "USES_TECHNIQUE", "tech_ps", "Technique")

    val_res = path_validator.validate_path([s1, s2])
    assert val_res.is_valid is False
    assert any("does not connect" in r for r in val_res.reasons)
