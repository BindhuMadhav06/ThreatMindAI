"""
API routes for Phase 16 ThreatMind Privacy-Preserving Collaborative Intelligence.
Provides endpoints for privacy policy governance, salted HMAC anonymization,
sharing evaluation, and non-destructive intelligence retractions.
Enforces authenticated tenant derivation and anti-spoofing guarantees.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from app.core.security import AuthenticatedUser, verify_authentication
from app.models.privacy import (
    CollaborationRetractionRequest,
    SharingPolicy,
    SharingScope,
    TAXIISharingRecord,
    TLPMarking,
)
from app.services.privacy import AnonymizationService, SharingPolicyService, TAXIIFederationService

router = APIRouter(prefix="/privacy", tags=["Privacy-Preserving Collaborative Intelligence"])

anonymizer = AnonymizationService()
policy_service = SharingPolicyService()
taxii_service = TAXIIFederationService(policy_service=policy_service, anonymization_service=anonymizer)


class AnonymizationTestRequest(BaseModel):
    value: str
    identifier_type: str = "INTERNAL_IP"  # "INTERNAL_IP" or "INTERNAL_HOSTNAME"


class SharingEvaluationRequest(BaseModel):
    object_tlp: TLPMarking
    requested_scope: SharingScope
    recipient_id: Optional[str] = None
    contains_internal_identifiers: bool = False


@router.get("/policy", response_model=SharingPolicy)
async def get_tenant_policy(
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> SharingPolicy:
    """Retrieve the active sharing and privacy policy for requesting tenant."""
    return policy_service.get_or_create_policy(current_user.tenant_id)


@router.put("/policy", response_model=SharingPolicy)
async def update_tenant_policy(
    policy: SharingPolicy,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> SharingPolicy:
    """Update tenant sharing policy."""
    policy.tenant_id = current_user.tenant_id
    return policy_service.update_policy(policy)


@router.post("/anonymize")
async def test_anonymization(
    req: AnonymizationTestRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Dict[str, Any]:
    """Test salted HMAC pseudonymization on an internal identifier."""
    tenant = current_user.tenant_id
    if req.identifier_type.upper() == "INTERNAL_IP":
        trans, rec = anonymizer.transform_internal_ip(req.value, tenant)
        return {
            "original": req.value,
            "transformed": trans,
            "is_private": anonymizer.is_private_ip(req.value),
            "record": rec.model_dump() if rec else None
        }
    else:
        trans, rec = anonymizer.transform_internal_hostname(req.value, tenant)
        return {
            "original": req.value,
            "transformed": trans,
            "record": rec.model_dump()
        }


@router.post("/sharing/evaluate")
async def evaluate_sharing_request(
    req: SharingEvaluationRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> Dict[str, Any]:
    """Evaluate whether an intelligence export is authorized under TLP and recipient rules."""
    tenant = current_user.tenant_id
    is_auth, rationale = policy_service.evaluate_export_authorization(
        tenant_id=tenant,
        object_tlp=req.object_tlp,
        requested_scope=req.requested_scope,
        recipient_id=req.recipient_id,
        contains_internal_identifiers=req.contains_internal_identifiers
    )
    return {
        "is_authorized": is_auth,
        "rationale": rationale,
        "tenant_id": tenant,
        "requested_scope": req.requested_scope.value,
        "object_tlp": req.object_tlp.value
    }


@router.post("/sharing/retract", response_model=TAXIISharingRecord)
async def retract_intelligence_record(
    req: CollaborationRetractionRequest,
    current_user: AuthenticatedUser = Depends(verify_authentication),
) -> TAXIISharingRecord:
    """Retract previously shared intelligence with cryptographic tombstone signing."""
    req.tenant_id = current_user.tenant_id
    try:
        return taxii_service.retract_intelligence(req)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
