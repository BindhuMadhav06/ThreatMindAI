import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.retrieval.entity_resolver import entity_resolver
from app.services.graph.repository import graph_repository

def test_resolve_exact_canonical_name():
    resolved, unresolved = entity_resolver.resolve("How does APT29 attack systems?")
    assert len(resolved) >= 1
    actor = next((e for e in resolved if e.name == "APT29"), None)
    assert actor is not None
    assert actor.id == "actor_apt29"
    assert actor.match_method in ["canonical_name", "alias_lookup"]

def test_resolve_threat_actor_alias():
    resolved, unresolved = entity_resolver.resolve("What campaigns are attributed to Cozy Bear?")
    assert len(resolved) >= 1
    actor = next((e for e in resolved if e.id == "actor_apt29"), None)
    assert actor is not None
    assert actor.name == "APT29"

def test_resolve_cve_identifier():
    resolved, unresolved = entity_resolver.resolve("What products are affected by CVE-2021-44228?")
    assert len(resolved) >= 1
    vuln = next((e for e in resolved if "cve_2021_44228" in e.id), None)
    assert vuln is not None
    assert vuln.match_method == "cve_identifier"

def test_resolve_mitre_technique_identifier():
    resolved, unresolved = entity_resolver.resolve("Which threat actors use T1059.001?")
    assert len(resolved) >= 1
    tech = next((e for e in resolved if "t1059_001" in e.id), None)
    assert tech is not None
    assert tech.match_method == "mitre_identifier"

def test_resolve_unknown_entity():
    resolved, unresolved = entity_resolver.resolve("Tell me about UnknownAdversaryXYZ123.")
    # Unknown entity should not be resolved into graph
    assert not any(e.name == "UnknownAdversaryXYZ123" for e in resolved)
    assert any(u.candidate_text == "UnknownAdversaryXYZ123" for u in unresolved)
    assert any(u.reason == "not_found_in_graph" for u in unresolved)

def test_resolve_with_entity_hints():
    resolved, unresolved = entity_resolver.resolve(
        question="What tools are used in this operation?",
        entity_hints=["Cobalt Strike"]
    )
    assert len(resolved) >= 1
    cs = next((e for e in resolved if e.name == "Cobalt Strike"), None)
    assert cs is not None
