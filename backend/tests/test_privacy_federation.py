"""
Phase 16: Privacy-Preserving Collaborative Intelligence & TAXII 2.1 — Test Suite
Covers:
- Salted HMAC pseudonymization vs unsalted hash enumeration rejection
- Private RFC 1918 address transformation & public C2 indicator preservation
- Internal hostname anonymization & credential/PII redaction
- TLP export policy gating & TLP:RED suppression
- TAXII 2.1 collection discovery & bounded object querying
- Untrusted external TAXII ingestion provenance tagging
- Collaborative retraction & superseding without history erasure
- Privacy and TAXII REST API routes
"""

import hashlib
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.privacy import (
    CollaborationRetractionRequest,
    SharingPolicy,
    SharingScope,
    TLPMarking,
)
from app.services.privacy import AnonymizationService, SharingPolicyService, TAXIIFederationService

client = TestClient(app)


# ============================================================================
# Test Group 1: Salted HMAC vs Unsalted Enumeration Rejection (16.2)
# ============================================================================

def test_salted_hmac_resists_enumeration_and_isolates_tenants():
    anonymizer = AnonymizationService()
    internal_ip = "192.168.1.100"

    # Tenant A transformation
    trans_a, rec_a = anonymizer.transform_internal_ip(internal_ip, tenant_id="tenant_a")
    assert rec_a is not None
    assert trans_a.startswith("pseudonym-ip-")

    # Tenant B transformation on identical internal IP
    trans_b, rec_b = anonymizer.transform_internal_ip(internal_ip, tenant_id="tenant_b")
    assert rec_b is not None

    # CRITICAL INVARIANT: Tenant isolation prevents cross-tenant linkage
    assert trans_a != trans_b, "Cryptographic failure: Cross-tenant pseudonym collision!"

    # Unsalted hash vulnerability demonstration:
    # An unsalted SHA-256 of 192.168.1.100 is identical across all systems,
    # enabling rainbow table enumeration.
    unsalted_hash = hashlib.sha256(internal_ip.encode()).hexdigest()[:12]
    assert unsalted_hash not in trans_a
    assert unsalted_hash not in trans_b


# ============================================================================
# Test Group 2: Private RFC 1918 Pseudonymization & Public Indicator Preservation
# ============================================================================

def test_private_vs_public_ip_handling():
    anonymizer = AnonymizationService()

    # 1. Private RFC 1918 IPs must be anonymized
    assert anonymizer.is_private_ip("10.0.0.1") is True
    assert anonymizer.is_private_ip("172.16.5.20") is True
    assert anonymizer.is_private_ip("192.168.0.1") is True
    assert anonymizer.is_private_ip("127.0.0.1") is True

    anon_ip, rec = anonymizer.transform_internal_ip("10.0.0.1", "tenant_prod")
    assert anon_ip != "10.0.0.1"
    assert rec is not None

    # 2. Public threat indicators (malicious C2) must be preserved for threat sharing
    public_c2 = "198.51.100.42"
    assert anonymizer.is_private_ip(public_c2) is False
    pres_ip, rec_pub = anonymizer.transform_internal_ip(public_c2, "tenant_prod")
    assert pres_ip == public_c2
    assert rec_pub is None


# ============================================================================
# Test Group 3 & 4: Hostname Transformation & Credential Redaction
# ============================================================================

def test_internal_hostname_and_credential_sanitization():
    anonymizer = AnonymizationService()

    # Hostname transformation
    host, rec = anonymizer.transform_internal_hostname("dc01.corp.internal", "tenant_prod")
    assert "dc01.corp" not in host
    assert host.startswith("pseudonym-host-")
    assert host.endswith(".internal")

    # Credential & PII scrubbing
    raw_text = (
        "Adversary staged credentials: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... "
        "and password=SuperSecretPassword123! from admin@company.corp"
    )
    scrubbed = anonymizer.redact_pii_and_credentials(raw_text)
    assert "SuperSecretPassword123!" not in scrubbed
    assert "admin@company.corp" not in scrubbed
    assert "[REDACTED_CREDENTIAL]" in scrubbed
    assert "[REDACTED_EMAIL]" in scrubbed


# ============================================================================
# Test Group 5: TLP Export Policy Governance (16.3)
# ============================================================================

def test_tlp_export_policy_enforcement():
    policy_service = SharingPolicyService()

    # Rule 1: TLP:RED can NEVER be exported to community/ISAC scopes
    auth_red, reason_red = policy_service.evaluate_export_authorization(
        tenant_id="tenant_bank",
        object_tlp=TLPMarking.TLP_RED,
        requested_scope=SharingScope.COMMUNITY_ISAC,
        recipient_id="isac_member_verified"
    )
    assert auth_red is False
    assert "TLP:RED" in reason_red

    # Rule 2: TLP:AMBER to unauthorized recipient fails closed
    auth_amber_bad, reason_amber = policy_service.evaluate_export_authorization(
        tenant_id="tenant_bank",
        object_tlp=TLPMarking.TLP_AMBER,
        requested_scope=SharingScope.COMMUNITY_ISAC,
        recipient_id="unauthorized_third_party"
    )
    assert auth_amber_bad is False
    assert "not authorized" in reason_amber

    # Rule 3: TLP:AMBER to authorized recipient succeeds
    auth_amber_ok, _ = policy_service.evaluate_export_authorization(
        tenant_id="tenant_bank",
        object_tlp=TLPMarking.TLP_AMBER,
        requested_scope=SharingScope.COMMUNITY_ISAC,
        recipient_id="isac_member_verified"
    )
    assert auth_amber_ok is True


# ============================================================================
# Test Group 6 & 7: TAXII 2.1 Collections & Untrusted Ingestion Tagging (16.4)
# ============================================================================

def test_taxii_collections_and_untrusted_tagging():
    taxii = TAXIIFederationService()

    collections = taxii.list_collections()
    assert len(collections) >= 2
    col_ids = [c.id for c in collections]
    assert "collection_isac_shared" in col_ids

    # Ingestion tagging invariant: external objects tagged as UNTRUSTED_EXTERNAL
    raw_external_obj = {
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '198.51.100.99']"
    }

    tagged = taxii.ingest_external_taxii_object(
        collection_id="collection_isac_shared",
        obj=raw_external_obj,
        source_feed_name="FS_ISAC_Feed"
    )

    assert "threatmind_provenance" in tagged
    assert tagged["threatmind_provenance"]["source_type"] == "UNTRUSTED_EXTERNAL_TAXII"
    assert tagged["threatmind_provenance"]["validation_status"] == "unverified_external"


# ============================================================================
# Test Group 8: Collaborative Retraction & Superseding (16.5)
# ============================================================================

def test_collaborative_retraction_without_history_erasure():
    taxii = TAXIIFederationService()

    # Publish an object
    record = taxii.publish_object_to_collection(
        collection_id="collection_isac_shared",
        tenant_id="tenant_hospital",
        obj={"id": "indicator--test-01", "name": "Erroneous False Positive IP", "ip": "10.0.1.20"},
        tlp_marking=TLPMarking.TLP_GREEN
    )

    assert record.status == "ACTIVE"

    # Retract intelligence
    req = CollaborationRetractionRequest(
        record_id=record.record_id,
        tenant_id="tenant_hospital",
        reason="False positive indicator identified in internal QA.",
        analyst_id="analyst_lead"
    )
    retracted = taxii.retract_intelligence(req)

    # Invariant: Record is marked RETRACTED with tombstone metadata; never erased!
    assert retracted.status == "RETRACTED"
    assert retracted.retraction_reason == "False positive indicator identified in internal QA."
    assert retracted.retracted_at is not None


# ============================================================================
# Test Group 9: Privacy & TAXII REST API Routes
# ============================================================================

def test_privacy_and_taxii_api_endpoints():
    # 1. Anonymize endpoint
    anon_resp = client.post(
        "/api/v1/privacy/anonymize",
        headers={"X-Tenant-ID": "tenant_api_sec"},
        json={"value": "192.168.1.50", "identifier_type": "INTERNAL_IP"}
    )
    assert anon_resp.status_code == 200
    assert anon_resp.json()["transformed"].startswith("pseudonym-ip-")

    # 2. Sharing evaluation endpoint
    eval_resp = client.post(
        "/api/v1/privacy/sharing/evaluate",
        headers={"X-Tenant-ID": "tenant_api_sec"},
        json={
            "object_tlp": "TLP:RED",
            "requested_scope": "COMMUNITY_ISAC"
        }
    )
    assert eval_resp.status_code == 200
    assert eval_resp.json()["is_authorized"] is False

    # 3. TAXII 2.1 Server Discovery
    taxii_disc = client.get("/api/v1/taxii2/")
    assert taxii_disc.status_code == 200
    assert "/api/v1/taxii2/" in taxii_disc.json()["api_roots"]

    # 4. TAXII 2.1 Collections List
    taxii_cols = client.get("/api/v1/taxii2/collections")
    assert taxii_cols.status_code == 200
    assert len(taxii_cols.json()["collections"]) >= 2
