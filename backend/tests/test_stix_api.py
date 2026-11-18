"""
Tests for STIX 2.1 Import API Endpoint: POST /api/v1/stix/import
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_api_stix_import_valid_bundle():
    bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-5678-1234-567812345678",
        "objects": [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--11111111-1111-1111-1111-111111111111",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "API Imported Threat Actor",
            }
        ],
    }

    response = client.post("/api/v1/stix/import", json=bundle)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["dry_run"] is False
    assert data["bundle_id"] == "bundle--12345678-1234-5678-1234-567812345678"
    assert data["summary"]["nodes_created"] == 1
    assert data["summary"]["rejected_objects_count"] == 0


def test_api_stix_import_dry_run():
    bundle = {
        "type": "bundle",
        "id": "bundle--22222222-2222-2222-2222-222222222222",
        "objects": [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--22222222-2222-2222-2222-222222222222",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Dry Run Malware",
                "is_family": True,
            }
        ],
    }

    response = client.post("/api/v1/stix/import?dry_run=true", json=bundle)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["dry_run"] is True
    assert data["summary"]["nodes_created"] == 1


def test_api_stix_import_invalid_payload_not_bundle():
    response = client.post("/api/v1/stix/import", json={"type": "threat-actor", "name": "Not a bundle"})
    assert response.status_code == 400
    assert "Expected STIX bundle object" in response.json()["detail"]


def test_api_stix_import_partial_success_with_rejections():
    bundle = {
        "type": "bundle",
        "id": "bundle--33333333-3333-3333-3333-333333333333",
        "objects": [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--33333333-3333-3333-3333-333333333333",
                "created": "2026-11-18T12:00:00.000Z",
                "modified": "2026-11-18T12:00:00.000Z",
                "name": "Actor With Bad Marking",
                "object_marking_refs": ["marking-definition--missing-marking-uuid"],
            }
        ],
    }

    response = client.post("/api/v1/stix/import", json=bundle)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "partial_success"
    assert data["summary"]["rejected_objects_count"] == 1
    assert len(data["rejection_ledger"]["unresolved_marking_rejected"]) == 1
