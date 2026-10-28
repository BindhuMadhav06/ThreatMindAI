import pytest
import sys
import os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.services.answering.prompt_builder import ABSTENTION_PHRASE

client = TestClient(app)

def test_api_query_answer_success():
    payload = {
        "question": "How does APT29 attack systems?",
        "max_depth": 3,
        "max_paths": 5
    }
    response = client.post("/api/v1/query/answer", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["original_question"] == payload["question"]
    assert "answer" in data
    assert "direct_answer" in data["answer"]
    assert len(data["answer"]["direct_answer"]) > 0
    assert "claims" in data
    assert "citations" in data
    assert len(data["citations"]) >= 1
    assert "grounding_status" in data
    assert data["grounding_status"] in ["fully_grounded", "partially_grounded"]
    assert "statistics" in data
    assert data["answer"]["is_synthetic"] is True

def test_api_query_answer_empty_question():
    payload = {"question": "   "}
    response = client.post("/api/v1/query/answer", json=payload)
    assert response.status_code == 400
    assert "Query question cannot be empty" in response.json()["detail"]

def test_api_query_answer_invalid_depth():
    payload = {
        "question": "How does APT29 attack systems?",
        "max_depth": 10  # Exceeds limit 3
    }
    response = client.post("/api/v1/query/answer", json=payload)
    assert response.status_code == 422

def test_api_query_answer_abstention():
    payload = {
        "question": "What tools are used by NonExistentActor12345?"
    }
    response = client.post("/api/v1/query/answer", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["grounding_status"] == "insufficient_evidence"
    assert data["answer"]["direct_answer"] == ABSTENTION_PHRASE
    assert data["answer"]["sufficiency_status"] == "insufficient"
    assert len(data["claims"]) == 0
    assert len(data["citations"]) == 0
