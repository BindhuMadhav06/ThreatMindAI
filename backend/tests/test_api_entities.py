import pytest
import sys
import os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app

client = TestClient(app)

def test_get_graph_stats():
    response = client.get("/api/v1/graph/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_nodes" in data
    assert "total_relationships" in data
    assert "total_sources" in data
    assert "node_counts_by_label" in data
    assert data["total_nodes"] >= 1
    assert data["total_relationships"] >= 1

def test_list_entities_unfiltered():
    response = client.get("/api/v1/entities?limit=10")
    assert response.status_code == 200
    entities = response.json()
    assert isinstance(entities, list)
    assert len(entities) >= 1
    first = entities[0]
    assert "id" in first
    assert "label" in first
    assert "name" in first
    assert "is_synthetic" in first

def test_list_entities_filtered_valid_label():
    response = client.get("/api/v1/entities?label=ThreatActor&limit=5")
    assert response.status_code == 200
    actors = response.json()
    assert isinstance(actors, list)
    assert any(a["name"] == "APT29" for a in actors)
    for a in actors:
        assert a["label"] == "ThreatActor"

def test_list_entities_invalid_label():
    response = client.get("/api/v1/entities?label=InvalidLabelNonExistent")
    assert response.status_code == 400
    assert "Invalid label" in response.json()["detail"]

def test_get_entity_details_existing():
    response = client.get("/api/v1/entities/actor_apt29")
    assert response.status_code == 200
    data = response.json()
    assert "entity" in data
    assert data["entity"]["id"] == "actor_apt29"
    assert data["entity"]["name"] == "APT29"
    assert "neighbors" in data
    assert "relationships" in data
    assert len(data["neighbors"]) >= 1
    assert len(data["relationships"]) >= 1
    # Check edge provenance structure
    first_rel = data["relationships"][0]
    assert "source_id" in first_rel
    assert "rel_type" in first_rel
    assert "target_id" in first_rel
    assert "provenance" in first_rel
    assert "is_synthetic" in first_rel

def test_get_entity_details_not_found():
    response = client.get("/api/v1/entities/nonexistent_id_99999")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]
