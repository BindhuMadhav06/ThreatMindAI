import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_technique_defense_valid():
    response = client.get("/api/v1/defense/techniques/T1059.001")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2
    item = data[0]
    assert "attack_technique_id" in item
    assert "countermeasure" in item
    assert "applicability" in item
    assert "mapping_provenance" in item
    assert "original_framework_id" in item

def test_get_technique_defense_invalid_format():
    response = client.get("/api/v1/defense/techniques/invalid-format")
    assert response.status_code == 400
    assert "Invalid ATT&CK technique identifier" in response.json()["detail"]

def test_post_defense_recommend_batch():
    payload = {"technique_ids": ["T1059.001", "T1078"]}
    response = client.post("/api/v1/defense/recommend", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "target_techniques" in data
    assert "recommendations" in data
    assert "summary_by_tactic" in data
    assert "catalog_version" in data
    assert "catalog_sha256" in data

def test_post_defense_recommend_empty():
    response = client.post("/api/v1/defense/recommend", json={"technique_ids": []})
    assert response.status_code in [400, 422]
