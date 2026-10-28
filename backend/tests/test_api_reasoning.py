import pytest
import sys
import os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app

client = TestClient(app)

def test_api_query_reason_success():
    payload = {
        "question": "How does APT29 attack systems?",
        "max_depth": 3,
        "max_paths": 10
    }
    response = client.post("/api/v1/query/reason", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["original_question"] == "How does APT29 attack systems?"
    assert len(data["resolved_entities"]) >= 1
    assert any(e["name"] == "APT29" for e in data["resolved_entities"])
    assert len(data["accepted_paths"]) >= 1
    assert "statistics" in data
    assert "answer" not in data  # Mandatory: No final LLM answer in Phase 6

def test_api_query_reason_empty_question():
    payload = {"question": "   "}
    response = client.post("/api/v1/query/reason", json=payload)
    assert response.status_code == 400
    assert "Query question cannot be empty" in response.json()["detail"]

def test_api_query_reason_invalid_depth():
    payload = {
        "question": "How does APT29 attack systems?",
        "max_depth": 10  # Exceeds hard cap 3
    }
    response = client.post("/api/v1/query/reason", json=payload)
    assert response.status_code == 422  # Pydantic validation error
