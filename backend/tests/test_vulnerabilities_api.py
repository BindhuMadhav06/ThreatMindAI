import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_vulnerability_intel_valid_cve():
    response = client.get("/api/v1/vulnerabilities/CVE-2021-44228/intel")
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2021-44228"
    assert data["provenance"] in ["offline_fixture", "cached", "live", "mixed"]
    assert data["freshness"] in ["fresh", "stale", "partial"]
    assert "cvss" in data["provenance_by_source"]
    assert "epss" in data["freshness_by_source"]
    assert data["cvss"]["base_score"] == 10.0
    assert data["cvss"]["severity"] == "Critical"
    assert data["cvss"]["provenance"] == "offline_fixture"
    assert "in the wild over the next 30 days" in data["epss"]["definition"]
    assert data["epss"]["model_version"] == "v2023.03.01"
    assert data["cisa_kev"]["status"] == "Listed"

def test_get_vulnerability_intel_invalid_format():
    response = client.get("/api/v1/vulnerabilities/invalid-cve/intel")
    assert response.status_code == 400
    assert "Invalid CVE identifier format" in response.json()["detail"]

def test_get_vulnerability_intel_unknown_cve():
    response = client.get("/api/v1/vulnerabilities/CVE-2099-0001/intel")
    assert response.status_code == 200
    data = response.json()
    assert data["freshness"] == "unavailable"
    assert data["provenance"] == "unavailable"
    assert data["cvss"]["severity"] == "Unavailable"
    # KEV must be Unable to verify, never Not listed
    assert data["cisa_kev"]["status"] == "Unable to verify"

def test_get_vulnerability_intel_cisa_not_listed():
    response = client.get("/api/v1/vulnerabilities/CVE-2019-14287/intel")
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2019-14287"
    assert data["cisa_kev"]["status"] == "Not listed"
    assert data["cisa_kev"]["is_stale_assertion"] is True
    assert "Not listed in historical snapshot" in data["cisa_kev"]["notes"]
    assert data["cvss"]["base_score"] == 8.8
    assert data["epss"]["score_date"] == "2024-04-15"
    assert "in the wild over the next 30 days" in data["epss"]["definition"]
