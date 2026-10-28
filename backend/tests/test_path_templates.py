import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.reasoning.path_templates import (
    PATH_TEMPLATES,
    detect_template_for_query,
    ACTOR_ATTACK_PATTERN,
    ACTOR_VULNERABILITY_EXPLOITATION
)

def test_template_registry():
    assert "actor_attack_pattern" in PATH_TEMPLATES
    assert "actor_vulnerability_exploitation" in PATH_TEMPLATES
    assert "actor_targeting" in PATH_TEMPLATES
    assert "malware_capabilities" in PATH_TEMPLATES
    assert "vulnerability_impact" in PATH_TEMPLATES

def test_detect_template_for_query():
    assert detect_template_for_query("How does APT29 attack systems?") == "actor_attack_pattern"
    assert detect_template_for_query("What vulnerabilities are exploited by APT29?") == "actor_vulnerability_exploitation"
    assert detect_template_for_query("Which industries does this actor target?") == "actor_targeting"
    assert detect_template_for_query("What products are affected by this CVE?") == "vulnerability_impact"
    assert detect_template_for_query("A generic query with no intent") is None

def test_template_sequence_matching():
    # Valid Actor Attack Pattern
    valid_rels = ["USES", "USES_TECHNIQUE"]
    valid_labels = ["ThreatActor", "Malware", "Technique"]
    assert ACTOR_ATTACK_PATTERN.matches_sequence(valid_rels, valid_labels) is True

    # Invalid relationship in sequence
    invalid_rels = ["EXPLOITS", "USES_TECHNIQUE"]
    assert ACTOR_ATTACK_PATTERN.matches_sequence(invalid_rels, valid_labels) is False
