import pytest
import sys
import os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app

client = TestClient(app)

def test_api_ingestion_text_payload():
    payload = {
        "text_content": "APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations.",
        "title": "API Test Ingestion Advisory",
        "publisher": "Test Cyber Agency",
        "source_type": "txt"
    }

    response = client.post("/api/v1/ingestion", data=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["source_id"].startswith("source_")
    assert data["title"] == "API Test Ingestion Advisory"
    assert data["chunks_count"] >= 1

def test_api_ingestion_empty_rejection():
    response = client.post("/api/v1/ingestion", data={})
    assert response.status_code == 400
    assert "Either a file upload or text_content must be provided" in response.json()["detail"]
