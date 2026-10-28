import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.query import RetrievedRelationship, EvidenceRecord, ResolvedEntity
from app.services.reasoning.path_builder import PathBuilder

def test_compute_relevance():
    rel = RetrievedRelationship(
        source_id="actor_apt29",
        source_name="APT29",
        source_label="ThreatActor",
        rel_type="USES",
        target_id="malware_cobalt",
        target_name="Cobalt Strike",
        target_label="Malware",
        provenance={"evidence_text": "text", "source_id": "src_1"}
    )
    step = PathBuilder.assemble_step(1, rel, [], [])
    
    # Query mentions target "Cobalt Strike"
    score_high = PathBuilder.compute_relevance([step], "Does APT29 use Cobalt Strike?", "actor_attack_pattern")
    score_low = PathBuilder.compute_relevance([step], "A completely unrelated query about another topic")
    
    assert score_high > score_low

def test_semantic_caveats_attached():
    r1 = RetrievedRelationship(
        source_id="actor_apt29",
        source_name="APT29",
        source_label="ThreatActor",
        rel_type="USES",
        target_id="malware_cobalt",
        target_name="Cobalt Strike",
        target_label="Malware",
        provenance={"evidence_text": "Evidence text 1", "source_id": "src_1"}
    )
    r2 = RetrievedRelationship(
        source_id="malware_cobalt",
        source_name="Cobalt Strike",
        source_label="Malware",
        rel_type="USES_TECHNIQUE",
        target_id="tech_ps",
        target_name="PowerShell",
        target_label="Technique",
        provenance={"evidence_text": "Evidence text 2", "source_id": "src_1"}
    )

    ev_records = [
        EvidenceRecord(source_id="src_1", evidence_text="Evidence text 1", relationship="(APT29)-[USES]->(Cobalt Strike)"),
        EvidenceRecord(source_id="src_1", evidence_text="Evidence text 2", relationship="(Cobalt Strike)-[USES_TECHNIQUE]->(PowerShell)")
    ]

    resolved = [ResolvedEntity(
        id="actor_apt29",
        label="ThreatActor",
        name="APT29",
        match_method="canonical_name",
        confidence_score=1.0
    )]

    accepted, partial, rejected, count = PathBuilder.build_paths_from_graph(
        question="How does APT29 attack systems?",
        resolved_entities=resolved,
        retrieved_relationships=[r1, r2],
        evidence_records=ev_records,
        sources=[{"id": "src_1", "title": "Report"}]
    )

    assert len(accepted) >= 1
    two_hop_path = next((p for p in accepted if p.length == 2), None)
    assert two_hop_path is not None
    assert len(two_hop_path.semantic_caveats) >= 1
    assert any("causality" in c.lower() for c in two_hop_path.semantic_caveats)
