import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.ingestion.loaders import DocumentLoader
from app.services.ingestion.pipeline import IngestionPipeline
from app.services.graph.repository import graph_repository
from tests.test_extraction import MockLLMProvider

def test_full_ingestion_pipeline_into_neo4j():
    mock_llm = MockLLMProvider()
    pipeline = IngestionPipeline(llm_provider=mock_llm)

    text_content = "APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations."
    doc = DocumentLoader.load_txt(
        text_content=text_content,
        filename="pipeline_test.txt",
        metadata={
            "title": "Pipeline Integration Test Advisory",
            "publisher": "ThreatMind Integration Suite",
            "url": "https://test.threatmind.io/pipeline_001"
        }
    )

    response = pipeline.process_document(doc)
    assert response.status == "success"
    assert response.source_id == doc.source_id
    assert response.chunks_count >= 1
    assert response.entities_extracted == 2
    assert response.relationships_accepted == 1

    # Verify Source Node in Neo4j
    source_node = graph_repository.get_entity_by_id("Source", doc.source_id)
    assert source_node is not None
    assert source_node["title"] == "Pipeline Integration Test Advisory"

    # Verify Entity Nodes in Neo4j
    actor_node = graph_repository.get_entity_by_id("ThreatActor", "actor_apt29")
    assert actor_node is not None
    assert actor_node["name"] == "APT29"

    malware_node = graph_repository.get_entity_by_id("Malware", "malware_cobalt_strike")
    assert malware_node is not None
    assert malware_node["name"] == "Cobalt Strike"

    # Verify Relationship & Edge Provenance in Neo4j
    evidence = graph_repository.get_relationship_evidence("actor_apt29", "malware_cobalt_strike", "USES")
    assert len(evidence) >= 1
    ev_record = evidence[0]
    assert ev_record["source_id"] == "actor_apt29"
    assert ev_record["target_id"] == "malware_cobalt_strike"
    assert ev_record["relationship"] == "USES"
    assert "provenance" in ev_record
    assert ev_record["provenance"]["source_id"] == doc.source_id
    assert "Cobalt Strike" in ev_record["provenance"]["evidence_text"]

def test_duplicate_ingestion_idempotency():
    mock_llm = MockLLMProvider()
    pipeline = IngestionPipeline(llm_provider=mock_llm)

    text_content = "APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations."
    doc = DocumentLoader.load_txt(text_content, filename="idempotency_test.txt")

    # Ingest once
    res1 = pipeline.process_document(doc)
    
    # Ingest duplicate
    res2 = pipeline.process_document(doc)

    assert res1.source_id == res2.source_id

    # Verify count of relationships remains exactly 1
    evidence = graph_repository.get_relationship_evidence("actor_apt29", "malware_cobalt_strike", "USES")
    assert len(evidence) == 1
