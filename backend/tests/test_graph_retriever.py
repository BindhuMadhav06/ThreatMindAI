import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.query import ThreatQuery, RetrievalConfig, ResolvedEntity
from app.services.retrieval.graph_retriever import graph_retriever
from app.services.retrieval.graphrag_retriever import graphrag_retriever
from app.services.graph.repository import graph_repository

def test_controlled_graph_retrieval_one_hop():
    # APT29 starting entity
    resolved = [ResolvedEntity(
        id="actor_apt29",
        label="ThreatActor",
        name="APT29",
        match_method="canonical_name",
        confidence_score=1.0
    )]
    config = RetrievalConfig(max_depth=1, max_entities=10, max_relationships=10)

    entities, rels, paths, evidence, sources, warnings = graph_retriever.retrieve(resolved, config)

    assert len(entities) >= 1
    assert any(e.id == "actor_apt29" for e in entities)
    assert len(rels) >= 1
    assert all(r.provenance.get("evidence_text") for r in rels)  # Every returned relationship has evidence
    assert len(evidence) >= 1
    assert any(ev.source_id.startswith("source_") for ev in evidence)

def test_controlled_graph_retrieval_multi_hop_depth_limit():
    resolved = [ResolvedEntity(
        id="actor_apt29",
        label="ThreatActor",
        name="APT29",
        match_method="canonical_name",
        confidence_score=1.0
    )]

    # Depth 1 vs Depth 2
    config_d1 = RetrievalConfig(max_depth=1, max_entities=20, max_relationships=20)
    ents_d1, rels_d1, paths_d1, _, _, _ = graph_retriever.retrieve(resolved, config_d1)

    config_d2 = RetrievalConfig(max_depth=2, max_entities=20, max_relationships=20)
    ents_d2, rels_d2, paths_d2, _, _, _ = graph_retriever.retrieve(resolved, config_d2)

    # Depth 2 can traverse deeper paths (e.g. APT29 -> Cobalt Strike -> Technique)
    assert len(ents_d2) >= len(ents_d1)
    if paths_d2:
        max_path_len = max(p.length for p in paths_d2)
        assert max_path_len <= 2  # Hard bounded by max_depth=2

def test_evidence_exclusion_when_missing_evidence():
    # Insert a temporary unevidenced relationship in Neo4j to test exclusion filter
    graph_repository.create_or_update_entity("ThreatActor", {"id": "actor_fake_test", "name": "FakeActor"})
    graph_repository.create_or_update_entity("Malware", {"id": "malware_fake_test", "name": "FakeMalware"})
    
    # Create relationship with EMPTY evidence_text
    graph_repository.create_relationship(
        source_id="actor_fake_test",
        source_label="ThreatActor",
        rel_type="USES",
        target_id="malware_fake_test",
        target_label="Malware",
        provenance={"source_id": "source_fake", "evidence_text": ""}  # Empty evidence
    )

    resolved = [ResolvedEntity(
        id="actor_fake_test",
        label="ThreatActor",
        name="FakeActor",
        match_method="canonical_name",
        confidence_score=1.0
    )]
    config = RetrievalConfig(max_depth=1)

    entities, rels, paths, evidence, sources, warnings = graph_retriever.retrieve(resolved, config)

    # The relationship with empty evidence must be EXCLUDED
    fake_rel = next((r for r in rels if r.source_id == "actor_fake_test" and r.target_id == "malware_fake_test"), None)
    assert fake_rel is None
    assert any("EXCLUDED RELATIONSHIP" in w and "actor_fake_test" in w for w in warnings)

def test_graphrag_retriever_empty_for_unknown():
    query = ThreatQuery(question="Tell me about completely_unknown_adversary_xyz")
    result = graphrag_retriever.retrieve(query)
    assert result.original_question == query.question
    assert len(result.resolved_entities) == 0
    assert len(result.retrieved_entities) == 0
    assert len(result.retrieved_relationships) == 0
    assert len(result.evidence_records) == 0
    assert any("No known cybersecurity entities could be resolved" in w for w in result.warnings)
