import pytest
import sys
import os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app

client = TestClient(app)

def test_api_query_retrieve_success():
    payload = {
        "question": "How does APT29 attack systems?",
        "config": {
            "max_depth": 1,
            "max_entities": 15,
            "max_relationships": 15
        }
    }
    response = client.post("/api/v1/query/retrieve", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    assert data["original_question"] == "How does APT29 attack systems?"
    assert len(data["resolved_entities"]) >= 1
    assert any(e["id"] == "actor_apt29" for e in data["resolved_entities"])
    assert len(data["retrieved_entities"]) >= 1
    assert len(data["retrieved_relationships"]) >= 1
    assert len(data["evidence_records"]) >= 1
    assert "statistics" in data
    assert data["statistics"]["entities_resolved_count"] >= 1
    assert "answer" not in data  # Mandatory: No final LLM answer in Phase 5

def test_api_query_retrieve_empty_question():
    payload = {"question": "   "}
    response = client.post("/api/v1/query/retrieve", json=payload)
    assert response.status_code == 400
    assert "Query question cannot be empty" in response.json()["detail"]

def test_api_query_retrieve_invalid_limits():
    # max_depth must be <= 3 (hard limit)
    payload = {
        "question": "What is APT29?",
        "config": {
            "max_depth": 10  # Exceeds max 3
        }
    }
    response = client.post("/api/v1/query/retrieve", json=payload)
    assert response.status_code == 422  # Unprocessable Entity from Pydantic
