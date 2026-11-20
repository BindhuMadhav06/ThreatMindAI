"""
ThreatMind AI — Adversarial Security, Authentication & Tenant Isolation Test Suite.

Comprehensive adversarial test suite verifying:
- Cryptographic JWT signature verification and claim enforcement (RFC 7519)
- Protection against algorithm confusion ('none', unlisted algs)
- Issuer and audience claim validation
- Token expiration (exp) and not-before (nbf) enforcement
- Strict prevention of client-controlled identity or tenant spoofing via X-Tenant-ID
- Hashed server-side API key authentication, revocation, and expiration
- Role-based access control (RBAC) and prevention of analyst self-promotion
- Cross-tenant read, write, and approval isolation
- Prevention of unauthenticated and replay/duplicate action approvals
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
import jwt

from app.main import app
from app.core.config import settings
from app.core.security import (
    ApiKeyStore,
    AuthenticatedUser,
    api_key_store,
    create_access_token,
    recipient_registry,
    validate_jwt_secret_configuration,
    verify_authentication,
)
from app.models.investigation import (
    ActionApprovalStatus,
    ActionRiskLevel,
)
from app.api.routes.investigation import approval_service

client = TestClient(app)


# ---------------------------------------------------------------------------
# FIXTURES & HELPERS
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_api_keys_and_actions():
    """Ensure clean state for API keys and approval actions between tests."""
    api_key_store.clear()
    approval_service._actions_by_id.clear()
    yield


# ---------------------------------------------------------------------------
# 1. JWT CRYPTOGRAPHIC VERIFICATION & ATTACK SCENARIOS
# ---------------------------------------------------------------------------

def test_missing_credentials_returns_401():
    """Verify that requests with no credentials return HTTP 401 Unauthorized."""
    resp = client.post("/api/v1/investigation-agent/run", json={
        "tenant_id": "tenant_1",
        "analyst_id": "analyst_1",
        "objective": "Test",
        "target_entity": "APT29"
    })
    assert resp.status_code == 401
    assert "Authentication credentials required" in resp.json()["detail"]


def test_empty_bearer_token_returns_401():
    """Verify that an empty Bearer header returns HTTP 401 Unauthorized."""
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"Authorization": "Bearer "},
        json={"tenant_id": "t1", "analyst_id": "a1", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401


def test_malformed_token_returns_401():
    """Verify that a malformed non-JWT token returns HTTP 401 Unauthorized."""
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"Authorization": "Bearer not.a.valid.jwt.token"},
        json={"tenant_id": "t1", "analyst_id": "a1", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401
    assert "Invalid" in resp.json()["detail"]


def test_forged_jwt_signature_returns_401():
    """Verify that a JWT signed with an attacker key returns HTTP 401 Unauthorized."""
    attacker_secret = "attacker-controlled-secret-key-that-does-not-match"
    forged_token = create_access_token(
        user_id="attacker",
        tenant_id="tenant_target",
        role="admin",
        secret_key=attacker_secret
    )
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"Authorization": f"Bearer {forged_token}"},
        json={"tenant_id": "tenant_target", "analyst_id": "attacker", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401


def test_expired_jwt_returns_401():
    """Verify that an expired JWT token returns HTTP 401 Unauthorized."""
    expired_token = create_access_token(
        user_id="analyst_1",
        tenant_id="tenant_1",
        role="analyst",
        expires_delta=timedelta(seconds=-60)  # Expired 60s ago
    )
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"Authorization": f"Bearer {expired_token}"},
        json={"tenant_id": "tenant_1", "analyst_id": "analyst_1", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_wrong_issuer_returns_401():
    """Verify that a JWT with an untrusted issuer returns HTTP 401 Unauthorized."""
    wrong_iss_token = create_access_token(
        user_id="analyst_1",
        tenant_id="tenant_1",
        issuer="untrusted-identity-provider"
    )
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"Authorization": f"Bearer {wrong_iss_token}"},
        json={"tenant_id": "tenant_1", "analyst_id": "analyst_1", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401
    assert "issuer" in resp.json()["detail"].lower()


def test_wrong_audience_returns_401():
    """Verify that a JWT with an unintended audience returns HTTP 401 Unauthorized."""
    wrong_aud_token = create_access_token(
        user_id="analyst_1",
        tenant_id="tenant_1",
        audience="wrong-api-audience"
    )
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"Authorization": f"Bearer {wrong_aud_token}"},
        json={"tenant_id": "tenant_1", "analyst_id": "analyst_1", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401
    assert "audience" in resp.json()["detail"].lower()


def test_unsupported_algorithm_returns_401():
    """Verify that tokens using 'none' algorithm or unapproved algs are rejected with 401."""
    # Construct an unsigned token using 'none' algorithm
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "sub": "attacker",
        "tenant_id": "tenant_1",
        "role": "admin",
        "exp": now + 3600,
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE
    }
    # Direct encode without signature simulation
    unsigned_token = jwt.encode(payload, key="", algorithm="none")
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"Authorization": f"Bearer {unsigned_token}"},
        json={"tenant_id": "tenant_1", "analyst_id": "attacker", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 2. TENANT ISOLATION & ANTI-SPOOFING
# ---------------------------------------------------------------------------

def test_client_sends_only_x_tenant_id_returns_401():
    """Verify that sending only X-Tenant-ID without credentials returns HTTP 401."""
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"X-Tenant-ID": "tenant_victim"},
        json={"tenant_id": "tenant_victim", "analyst_id": "anon", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401


def test_authenticated_user_supplying_different_tenant_header_returns_403():
    """Verify that an authenticated user supplying a different X-Tenant-ID returns 403."""
    token_tenant_a = create_access_token(user_id="user_a", tenant_id="tenant_a", role="analyst")
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={
            "Authorization": f"Bearer {token_tenant_a}",
            "X-Tenant-ID": "tenant_b"  # Spoofing attempt
        },
        json={"tenant_id": "tenant_b", "analyst_id": "user_a", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 403
    assert "Tenant spoofing detected" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 3. SECURE API KEY AUTHENTICATION & REVOCATION
# ---------------------------------------------------------------------------

def test_unknown_api_key_returns_401():
    """Verify that an unregistered API key returns HTTP 401 Unauthorized."""
    resp = client.post(
        "/api/v1/investigation-agent/run",
        headers={"X-API-Key": "tm_live_unknown_unregistered_key_12345"},
        json={"tenant_id": "tenant_1", "analyst_id": "user_1", "objective": "Test", "target_entity": "APT29"}
    )
    assert resp.status_code == 401
    assert "Invalid or unknown API key" in resp.json()["detail"]


def test_valid_api_key_authenticates_successfully():
    """Verify that a registered API key authenticates and resolves tenant."""
    test_key = "tm_live_valid_test_key_8888"
    api_key_store.register_key(
        raw_key=test_key,
        user_id="key_analyst",
        tenant_id="tenant_corp",
        role="analyst"
    )

    resp = client.get(
        "/api/v1/investigation-agent/actions",
        headers={"X-API-Key": test_key}
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_revoked_api_key_returns_401():
    """Verify that a revoked API key is rejected with HTTP 401 Unauthorized."""
    test_key = "tm_live_to_be_revoked_key_9999"
    api_key_store.register_key(
        raw_key=test_key,
        user_id="compromised_user",
        tenant_id="tenant_corp",
        role="analyst"
    )
    # Revoke the key
    api_key_store.revoke_key(test_key)

    resp = client.get(
        "/api/v1/investigation-agent/actions",
        headers={"X-API-Key": test_key}
    )
    assert resp.status_code == 401
    assert "revoked" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 4. RBAC & HUMAN-IN-THE-LOOP (HITL) GOVERNANCE
# ---------------------------------------------------------------------------

def test_viewer_role_cannot_review_action_returns_403():
    """Verify that a user with 'viewer' role is rejected from reviewing defensive actions."""
    viewer_token = create_access_token(user_id="viewer_1", tenant_id="tenant_sec", role="viewer")
    
    # Propose action under tenant_sec
    act = approval_service.propose_action(
        tenant_id="tenant_sec",
        action_type="ISOLATE_NETWORK_SEGMENT",
        proposed_action="Isolate infected machine segment.",
        rationale="Active C2 beacon detected."
    )

    resp = client.post(
        f"/api/v1/investigation-agent/actions/{act.action_id}/review",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"decision": "APPROVED", "notes": "Viewer attempt"}
    )
    assert resp.status_code == 403
    assert "not authorized" in resp.json()["detail"]


def test_tenant_a_cannot_approve_tenant_b_action_denied():
    """Verify that an analyst from Tenant A cannot approve an action belonging to Tenant B."""
    token_tenant_a = create_access_token(user_id="analyst_a", tenant_id="tenant_alpha", role="analyst")

    # Propose action under tenant_beta
    act = approval_service.propose_action(
        tenant_id="tenant_beta",
        action_type="BLOCK_IP_FIREWALL",
        proposed_action="Block IP 198.51.100.10",
        rationale="Host exfiltration"
    )

    resp = client.post(
        f"/api/v1/investigation-agent/actions/{act.action_id}/review",
        headers={"Authorization": f"Bearer {token_tenant_a}"},
        json={"decision": "APPROVED", "notes": "Cross tenant review attempt"}
    )
    # Returns 404 to avoid leaking existence of Tenant B's action ID
    assert resp.status_code == 404


def test_replay_duplicate_approval_rejected_400():
    """Verify that reviewing an already approved action triggers duplicate review rejection."""
    token = create_access_token(user_id="analyst_lead", tenant_id="tenant_omega", role="analyst")

    act = approval_service.propose_action(
        tenant_id="tenant_omega",
        action_type="BLOCK_IP_FIREWALL",
        proposed_action="Block C2 IP.",
        rationale="Confirmed malicious."
    )

    # First review: APPROVED
    resp1 = client.post(
        f"/api/v1/investigation-agent/actions/{act.action_id}/review",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "APPROVED", "notes": "First approval"}
    )
    assert resp1.status_code == 200
    assert resp1.json()["approval_status"] == "APPROVED"

    # Second review: Replay attempt
    resp2 = client.post(
        f"/api/v1/investigation-agent/actions/{act.action_id}/review",
        headers={"Authorization": f"Bearer {token}"},
        json={"decision": "REJECTED", "notes": "Replay attempt"}
    )
    assert resp2.status_code == 400
    assert "Replay and duplicate reviews are rejected" in resp2.json()["detail"]


def test_valid_analyst_and_admin_operations_succeed():
    """Verify that legitimate analyst and admin operations succeed."""
    analyst_token = create_access_token(user_id="analyst_good", tenant_id="tenant_prime", role="analyst")
    admin_token = create_access_token(user_id="admin_good", tenant_id="tenant_prime", role="admin", is_admin=True)

    # Analyst can propose and list actions
    act = approval_service.propose_action(
        tenant_id="tenant_prime",
        action_type="BLOCK_IP_FIREWALL",
        proposed_action="Block malicious C2 domain.",
        rationale="Confirmed via CTI."
    )

    resp_list = client.get(
        "/api/v1/investigation-agent/actions",
        headers={"Authorization": f"Bearer {analyst_token}"}
    )
    assert resp_list.status_code == 200
    assert len(resp_list.json()) >= 1

    # Admin can review and approve
    resp_rev = client.post(
        f"/api/v1/investigation-agent/actions/{act.action_id}/review",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"decision": "APPROVED", "notes": "Admin verified"}
    )
    assert resp_rev.status_code == 200
    assert resp_rev.json()["approval_status"] == "APPROVED"
    assert resp_rev.json()["approver"] == "admin_good"


# ---------------------------------------------------------------------------
# 5. SQLITE DURABLE API KEY STORE PERSISTENCE
# ---------------------------------------------------------------------------

def test_sqlite_api_key_store_durability_across_instances():
    """
    Verify that ApiKeyStore persists keys and revocations to SQLite across
    process restarts or distinct store instances.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_file = os.path.join(tmp_dir, "test_api_keys.db")

        # Instance 1: Register key
        store1 = ApiKeyStore(db_path=db_file)
        raw_key = "threatmind-persistent-test-api-key-9999"
        store1.register_key(
            raw_key=raw_key,
            user_id="user_persistent",
            tenant_id="tenant_durable",
            role="analyst",
            is_internal_org_member=True,
        )

        # Instance 2: Lookup from newly instantiated store
        store2 = ApiKeyStore(db_path=db_file)
        rec = store2.lookup_key(raw_key)
        assert rec is not None
        assert rec.user_id == "user_persistent"
        assert rec.tenant_id == "tenant_durable"
        assert rec.role == "analyst"
        assert rec.is_internal_org_member is True
        assert rec.revoked is False

        # Instance 1: Revoke the key
        revoked = store1.revoke_key(raw_key)
        assert revoked is True

        # Instance 3: Verify revocation persists
        store3 = ApiKeyStore(db_path=db_file)
        rec_after_rev = store3.lookup_key(raw_key)
        assert rec_after_rev is not None
        assert rec_after_rev.revoked is True


# ---------------------------------------------------------------------------
# 6. PRODUCTION JWT SECRET ENFORCEMENT & FAIL-CLOSED VALIDATION
# ---------------------------------------------------------------------------

def test_production_jwt_secret_validation_rejects_insecure_keys():
    """
    Verifies that validate_jwt_secret_configuration rejects known development keys,
    short keys, low-entropy keys, and placeholder strings in production mode.
    """
    # 1. Dev key in production must fail
    with pytest.raises(RuntimeError, match="known default or insecure placeholder"):
        validate_jwt_secret_configuration(
            secret_key="threatmind-dev-secret-key-change-in-production-min32bytes",
            environment="production",
        )

    # 2. Key containing 'change-in-production' must fail
    with pytest.raises(RuntimeError, match="insecure placeholder pattern"):
        validate_jwt_secret_configuration(
            secret_key="some-custom-key-change-in-production-long-enough-32bytes",
            environment="production",
        )

    # 3. Short key (< 32 bytes) must fail
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        validate_jwt_secret_configuration(
            secret_key="short-insecure-key",
            environment="production",
        )

    # 4. Low-entropy key must fail
    with pytest.raises(RuntimeError, match="insufficient character entropy"):
        validate_jwt_secret_configuration(
            secret_key="11111111111111111111111111111111",
            environment="production",
        )

    # 5. Strong high-entropy key must pass
    valid_key = "a8F!9zQ#2vL$5mK*7xP&0wR^3yT@1bN%"
    assert validate_jwt_secret_configuration(secret_key=valid_key, environment="production") is True

    # 6. In development mode, development keys are tolerated
    assert validate_jwt_secret_configuration(
        secret_key="threatmind-dev-secret-key-change-in-production-min32bytes",
        environment="development",
    ) is True


def test_production_mode_fails_closed_on_insecure_jwt_secret():
    """
    Verifies that when ENVIRONMENT is production and the secret is insecure,
    incoming requests fail closed with HTTP 500 Internal Server Error.
    """
    original_env = settings.ENVIRONMENT
    original_key = settings.JWT_SECRET_KEY
    try:
        settings.ENVIRONMENT = "production"
        settings.JWT_SECRET_KEY = "threatmind-dev-secret-key-change-in-production-min32bytes"
        token = create_access_token(user_id="user_prod", tenant_id="tenant_prod", role="analyst")
        resp = client.get(
            "/api/v1/investigation-agent/actions",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 500
        assert "Security configuration error" in resp.json()["detail"]
    finally:
        settings.ENVIRONMENT = original_env
        settings.JWT_SECRET_KEY = original_key


# ---------------------------------------------------------------------------
# 7. UNIFIED STIX AUTHENTICATION & SUBSTRING TOKEN REJECTION
# ---------------------------------------------------------------------------

def test_stix_endpoints_reject_substring_tokens_401():
    """
    Guarantees that unverified tokens containing 'analyst' or 'admin' strings
    are strictly rejected with HTTP 401 across STIX routes.
    """
    forgery_headers = [
        {"Authorization": "Bearer fakeanalyst"},
        {"Authorization": "Bearer analyst"},
        {"Authorization": "Bearer not-a-real-analyst-token"},
        {"Authorization": "Bearer admin"},
        {"Authorization": "Bearer admin_super_user"},
    ]

    for h in forgery_headers:
        # Import route
        resp_import = client.post("/api/v1/stix/import", json={"type": "bundle", "id": "bundle--1"}, headers=h)
        assert resp_import.status_code == 401, f"Failed on {h}"

        # Export route
        resp_export = client.get("/api/v1/stix/export/bundle?investigation_id=inv-1", headers=h)
        assert resp_export.status_code == 401, f"Failed on {h}"


# ---------------------------------------------------------------------------
# 8. SERVER-SIDE RECIPIENT CAPABILITY REGISTRY & ZERO-TRUST GATING
# ---------------------------------------------------------------------------

def test_recipient_registry_default_deny_and_anti_spoofing():
    """
    Verifies that client header 'X-Recipient-Org-Internal: true' cannot elevate
    unregistered external recipients to internal status (Zero Trust / default-deny).
    """
    recipient_registry.clear()

    # User whose token claims internal=False and who is not in registry
    ext_user = AuthenticatedUser(
        user_id="user_ext_01",
        role="analyst",
        tenant_id="tenant_partner",
        is_internal_org_member=False,
    )

    # Attempt to spoof internal org header
    caps_spoofed = recipient_registry.resolve_capabilities(
        user=ext_user,
        header_org_internal="true",
        header_extension_aware="true",
    )
    # Server clamps to False
    assert caps_spoofed["is_internal_org_member"] is False
    assert caps_spoofed["can_be_internal"] is False
    assert caps_spoofed["is_extension_aware"] is True

    # Register an internal entity in server registry
    recipient_registry.register_recipient(
        recipient_id="user_internal_01",
        tenant_id="tenant_corp",
        is_internal_org_member=True,
        is_extension_aware=True,
    )

    int_user = AuthenticatedUser(
        user_id="user_internal_01",
        role="analyst",
        tenant_id="tenant_corp",
        is_internal_org_member=False,  # Not in token, but in registry
    )
    caps_registered = recipient_registry.resolve_capabilities(
        user=int_user,
        header_org_internal="true",
    )
    assert caps_registered["is_internal_org_member"] is True
    assert caps_registered["can_be_internal"] is True


# ---------------------------------------------------------------------------
# 9. ORGANIZATION API UNIFIED AUTHENTICATION & ANTI-SPOOFING
# ---------------------------------------------------------------------------

def test_organization_endpoints_require_authentication():
    """
    Verifies that all Phase 14 Organization-Aware endpoints strictly require
    authentication and derive tenant membership server-side.
    """
    # 1. Unauthenticated asset list -> 401
    resp_unauth = client.get("/api/v1/organization/assets")
    assert resp_unauth.status_code == 401

    # 2. Unauthenticated prioritization -> 401
    resp_prio_unauth = client.get("/api/v1/organization/prioritization")
    assert resp_prio_unauth.status_code == 401

    # 3. Authenticated asset list -> 200
    token_tenant_a = create_access_token(user_id="analyst_org_a", tenant_id="tenant_org_a", role="analyst")
    resp_auth = client.get(
        "/api/v1/organization/assets",
        headers={"Authorization": f"Bearer {token_tenant_a}"},
    )
    assert resp_auth.status_code == 200

    # 4. Tenant spoofing attempt -> 403 Forbidden
    resp_spoof = client.get(
        "/api/v1/organization/assets",
        headers={"Authorization": f"Bearer {token_tenant_a}", "X-Tenant-ID": "tenant_org_b"},
    )
    assert resp_spoof.status_code == 403
    assert "Tenant spoofing detected" in resp_spoof.json()["detail"]

