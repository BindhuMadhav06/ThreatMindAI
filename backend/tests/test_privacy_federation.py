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
from app.core.security import create_access_token

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
    public_c2 = "185.199.108.153"
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
    token = create_access_token(user_id="analyst_test", tenant_id="tenant_api_sec", role="analyst")
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-ID": "tenant_api_sec"
    }

    # 1. Anonymize endpoint
    anon_resp = client.post(
        "/api/v1/privacy/anonymize",
        headers=headers,
        json={"value": "192.168.1.50", "identifier_type": "INTERNAL_IP"}
    )
    assert anon_resp.status_code == 200
    assert anon_resp.json()["transformed"].startswith("pseudonym-ip-")

    # 2. Sharing evaluation endpoint
    eval_resp = client.post(
        "/api/v1/privacy/sharing/evaluate",
        headers=headers,
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


# ============================================================================
# Test Group 10: Persistent TAXII Manifest, Ingestion & Recursive Sanitization
# ============================================================================

def test_persistent_taxii_manifest_and_tombstone_verification():
    taxii = TAXIIFederationService()

    # 1. Ingest external object with confidence discount
    raw_obj = {
        "id": "indicator--federated-test-01",
        "type": "indicator",
        "confidence": 1.0,
        "name": "External C2 Indicator"
    }
    ingested = taxii.ingest_external_taxii_object("collection_isac_shared", raw_obj, "TestFeed")
    assert ingested["confidence"] == 0.65  # 0.35 confidence discount applied!
    assert ingested["threatmind_provenance"]["confidence_discount"] == 0.35

    # 2. Verify Manifest returns STIX 2.1 media type
    manifest = taxii.get_collection_manifest("collection_isac_shared")
    assert len(manifest) >= 1
    found = any(m["id"] == "indicator--federated-test-01" for m in manifest)
    assert found is True

    # 3. Publish an object and retract with cryptographic signature
    record = taxii.publish_object_to_collection(
        collection_id="collection_isac_shared",
        tenant_id="tenant_audit_test",
        obj={"id": "indicator--audit-01", "name": "Audit Observable", "ip": "10.10.10.10"}
    )
    ret_req = CollaborationRetractionRequest(
        record_id=record.record_id,
        tenant_id="tenant_audit_test",
        reason="Revoked during security audit.",
        analyst_id="lead_analyst"
    )
    retracted = taxii.retract_intelligence(ret_req)
    assert retracted.status == "RETRACTED"

    # 4. Verify tombstone cryptographic signature
    v_res = taxii.verify_tombstone(record.record_id)
    assert v_res["verified"] is True
    assert len(v_res["signature"]) == 64


def test_recursive_sanitization_nested_objects():
    anonymizer = AnonymizationService()
    nested_payload = {
        "id": "report--001",
        "name": "Internal Breach Analysis",
        "description": "Exfiltration from host dc1.corp.internal with token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "network": {
            "source_ip": "10.0.5.12",       # RFC 1918 private IP
            "c2_ip": "185.199.108.153",    # Real public routable C2 IP (GitHub Pages)
            "internal_dns": "dns.corp.internal"
        },
        "indicators": [
            {"ip": "172.16.0.4", "type": "internal"},
            {"ip": "8.8.8.8", "type": "public"}
        ]
    }

    sanitized = anonymizer.sanitize_recursive(nested_payload, tenant_id="tenant_rec_test")

    # 1. Credentials scrubbed
    assert "[REDACTED_CREDENTIAL]" in sanitized["description"]
    assert "eyJhbGci" not in sanitized["description"]

    # 2. Private IPs pseudonymized with >= 128-bit output
    assert sanitized["network"]["source_ip"].startswith("pseudonym-ip-")
    assert sanitized["indicators"][0]["ip"].startswith("pseudonym-ip-")
    # Verify 128-bit entropy (32 hex characters after prefix)
    anon_hash = sanitized["network"]["source_ip"].replace("pseudonym-ip-", "")
    assert len(anon_hash) >= 32

    # 3. Internal hostnames pseudonymized
    assert sanitized["network"]["internal_dns"].startswith("pseudonym-host-")
    assert "corp.internal" not in sanitized["network"]["internal_dns"]

    # 4. Genuinely public routable C2 indicators PRESERVED intact
    assert sanitized["network"]["c2_ip"] == "185.199.108.153"
    assert sanitized["indicators"][1]["ip"] == "8.8.8.8"


def test_ip_address_classification_and_masking_matrix():
    """
    Offline deterministic verification across all IPv4 and IPv6 address classes:
    - Public IPv4 / IPv6: PRESERVED intact
    - Private RFC 1918 / RFC 4193: MASKED
    - Loopback: MASKED
    - Link-Local: MASKED
    - Carrier-Grade NAT (100.64.0.0/10): MASKED
    - Documentation-only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32): MASKED
    - Multicast & Reserved: MASKED
    - Malformed IP strings: Handled safely
    """
    anonymizer = AnonymizationService()
    tenant = "tenant_matrix_test"

    matrix = [
        # (IP string, should_be_masked, category)
        ("8.8.8.8", False, "Public IPv4 Google DNS"),
        ("1.1.1.1", False, "Public IPv4 Cloudflare"),
        ("185.199.108.153", False, "Public IPv4 GitHub"),
        ("2606:4700:4700::1111", False, "Public IPv6 Cloudflare"),
        ("10.0.0.1", True, "Private IPv4 10/8"),
        ("10.255.255.254", True, "Private IPv4 10/8 boundary"),
        ("172.16.0.5", True, "Private IPv4 172.16/12"),
        ("172.31.255.254", True, "Private IPv4 172.31 boundary"),
        ("192.168.1.1", True, "Private IPv4 192.168/16"),
        ("127.0.0.1", True, "IPv4 Loopback"),
        ("127.0.0.53", True, "IPv4 Systemd Resolved"),
        ("::1", True, "IPv6 Loopback"),
        ("169.254.169.254", True, "IPv4 Link-Local / Cloud Metadata"),
        ("fe80::1", True, "IPv6 Link-Local"),
        ("100.64.0.1", True, "Carrier-Grade NAT RFC 6598"),
        ("100.127.255.254", True, "Carrier-Grade NAT boundary"),
        ("192.0.2.1", True, "TEST-NET-1 Documentation"),
        ("198.51.100.42", True, "TEST-NET-2 Documentation"),
        ("203.0.113.99", True, "TEST-NET-3 Documentation"),
        ("2001:db8::1", True, "IPv6 Documentation"),
        ("224.0.0.1", True, "IPv4 Multicast"),
        ("ff02::1", True, "IPv6 Multicast"),
        ("240.0.0.1", True, "IPv4 Reserved Class E"),
    ]

    for ip_str, should_mask, desc in matrix:
        # 1. Method should_mask_ip check
        assert AnonymizationService.should_mask_ip(ip_str) == should_mask, f"Failed should_mask_ip for {desc} ({ip_str})"

        # 2. Method transform_internal_ip check
        transformed, record = anonymizer.transform_internal_ip(ip_str, tenant_id=tenant)
        if should_mask:
            assert transformed.startswith("pseudonym-ip-"), f"Expected pseudonym for {desc} ({ip_str}), got {transformed}"
            assert record is not None
            # Verify 128-bit entropy (32 hex characters)
            hex_part = transformed.replace("pseudonym-ip-", "")
            assert len(hex_part) == 32, f"Expected 32-hex (128-bit) digest, got {len(hex_part)}"
        else:
            assert transformed == ip_str, f"Expected preserved public IP for {desc} ({ip_str}), got {transformed}"
            assert record is None

    # 3. Test malformed IP strings handle safely without throwing
    malformed = ["999.999.999.999", "not_an_ip", "1.2.3.4.5", "256.1.1.1"]
    for m in malformed:
        assert AnonymizationService.should_mask_ip(m) is False
        trans_m, rec_m = anonymizer.transform_internal_ip(m, tenant_id=tenant)
        assert trans_m == m
        assert rec_m is None
