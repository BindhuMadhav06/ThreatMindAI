import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.graph.schema_manager import schema_manager
from app.services.graph.repository import graph_repository
from app.services.graph.connection import neo4j_conn

@pytest.fixture(scope="module", autouse=True)
def setup_test_environment():
    schema_manager.initialize_schema()
    yield

def test_entity_creation_and_retrieval():
    test_actor = {
        "id": "actor_test_001",
        "name": "APT-TestGroup",
        "aliases": ["TestBear", "GroupTest"],
        "description": "Test threat actor for unit verification."
    }
    created = graph_repository.create_or_update_entity("ThreatActor", test_actor)
    assert created["id"] == "actor_test_001"
    assert created["name"] == "APT-TestGroup"

    retrieved = graph_repository.get_entity_by_id("ThreatActor", "actor_test_001")
    assert retrieved is not None
    assert retrieved["id"] == "actor_test_001"
    assert retrieved["name"] == "APT-TestGroup"

def test_entity_find_by_name():
    results = graph_repository.find_entity_by_name("ThreatActor", "testgroup")
    assert len(results) >= 1
    assert results[0]["id"] == "actor_test_001"

def test_entity_idempotency():
    test_malware = {
        "id": "malware_test_001",
        "name": "TestTrojan",
        "description": "Initial description."
    }
    # First insert
    graph_repository.create_or_update_entity("Malware", test_malware)
    
    # Second insert with updated description
    updated_malware = {
        "id": "malware_test_001",
        "name": "TestTrojan",
        "description": "Updated description."
    }
    graph_repository.create_or_update_entity("Malware", updated_malware)

    # Verify no duplicate nodes created
    cypher = "MATCH (m:Malware {id: 'malware_test_001'}) RETURN count(m) AS total, m.description AS desc"
    res = neo4j_conn.query(cypher)
    assert res[0]["total"] == 1
    assert res[0]["desc"] == "Updated description."

def test_relationship_creation_and_provenance():
    source_node = {
        "id": "source_test_001",
        "title": "Test CTI Advisory",
        "url": "https://test.threatmind.io/adv001",
        "publisher": "Test Security Inc",
        "published_date": "2026-02-01"
    }
    graph_repository.create_or_update_entity("Source", source_node)

    provenance = {
        "source_id": "source_test_001",
        "source_url": "https://test.threatmind.io/adv001",
        "evidence_text": "APT-TestGroup executed TestTrojan during targeted operations.",
        "published_date": "2026-02-01",
        "extraction_method": "unit_test_extraction",
        "confidence": None
    }

    rel = graph_repository.create_relationship(
        source_id="actor_test_001",
        source_label="ThreatActor",
        rel_type="USES",
        target_id="malware_test_001",
        target_label="Malware",
        provenance=provenance
    )

    assert rel["source"] == "actor_test_001"
    assert rel["rel"] == "USES"
    assert rel["target"] == "malware_test_001"
    assert rel["provenance"]["evidence_text"] == "APT-TestGroup executed TestTrojan during targeted operations."

def test_relationship_idempotency():
    provenance = {
        "source_id": "source_test_001",
        "evidence_text": "APT-TestGroup executed TestTrojan."
    }
    # Duplicate edge insertion
    graph_repository.create_relationship(
        source_id="actor_test_001",
        source_label="ThreatActor",
        rel_type="USES",
        target_id="malware_test_001",
        target_label="Malware",
        provenance=provenance
    )

    cypher = """
    MATCH (a:ThreatActor {id: 'actor_test_001'})-[r:USES]->(m:Malware {id: 'malware_test_001'})
    RETURN count(r) AS total
    """
    res = neo4j_conn.query(cypher)
    assert res[0]["total"] == 1

def test_evidence_retrieval():
    evidence_records = graph_repository.get_relationship_evidence("actor_test_001", "malware_test_001", "USES")
    assert len(evidence_records) >= 1
    ev = evidence_records[0]
    assert ev["source_id"] == "actor_test_001"
    assert ev["target_id"] == "malware_test_001"
    assert ev["relationship"] == "USES"
    assert "provenance" in ev
    assert ev["provenance"]["evidence_text"] == "APT-TestGroup executed TestTrojan."

def test_parameterized_query_security():
    # Attempt Cypher injection via label and ID
    with pytest.raises(ValueError):
        graph_repository.get_entity_by_id("ThreatActor'; DROP TABLE x; --", "actor_test_001")
