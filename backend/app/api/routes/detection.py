"""
SigmaHQ Detection Engineering API Routes
Phase 12B Implementation

Provides REST endpoints for:
- Listing and filtering Sigma detection rules
- Grounded Sigma rule generation from ATT&CK techniques, D3FEND, and evidence
- pySigma v2.1.0 rule validation
- Human review and approval workflow (draft -> under_review -> approved / rejected)
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.models.sigma import (
    SigmaRule,
    SigmaRuleGenerateRequest,
    SigmaRuleReviewRequest,
    SigmaRuleValidateRequest,
)
from app.services.detection.sigma_generation_service import SigmaGenerationService
from app.services.detection.sigma_repository import SigmaRepository
from app.services.detection.sigma_validation_service import SigmaValidationService

router = APIRouter(prefix="/detection", tags=["detection"])

# Singletons for service and repository
sigma_repository = SigmaRepository()
sigma_generation_service = SigmaGenerationService()
sigma_validation_service = SigmaValidationService()


@router.get("/rules", status_code=status.HTTP_200_OK)
def list_rules(
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by Sigma status"),
    technique_id: Optional[str] = Query(default=None, description="Filter by ATT&CK technique ID"),
    level: Optional[str] = Query(default=None, description="Filter by severity level"),
    review_status: Optional[str] = Query(default=None, description="Filter by review status (draft, under_review, approved, rejected)"),
) -> List[Dict[str, Any]]:
    """
    Lists all indexed SigmaHQ rules matching query filters.
    """
    rules = sigma_repository.list_rules(
        status_filter=status_filter,
        technique_id=technique_id,
        level=level,
        review_status=review_status,
    )
    return [r.model_dump(exclude_none=True) for r in rules]


@router.get("/rules/{rule_id}", status_code=status.HTTP_200_OK)
def get_rule(rule_id: str) -> Dict[str, Any]:
    """
    Fetches a specific SigmaHQ detection rule by UUID.
    """
    rule = sigma_repository.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sigma rule with ID '{rule_id}' not found.",
        )
    return rule.model_dump(exclude_none=True)


@router.post("/rules/generate", status_code=status.HTTP_201_CREATED)
def generate_rule(req: SigmaRuleGenerateRequest) -> Dict[str, Any]:
    """
    Generates an evidence-grounded Sigma v2.1.0 rule from MITRE ATT&CK technique,
    D3FEND countermeasures, and evidence text, complete with sidecar provenance.
    """
    rule = sigma_generation_service.generate_rule(req)
    # Validate generated rule using pySigma
    if rule.raw_yaml:
        val_res = sigma_validation_service.validate_yaml(rule.raw_yaml)
        if not val_res["is_valid"]:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Rule generation produced invalid Sigma: {val_res['errors']}",
            )

    sigma_repository.save_rule(rule)
    return rule.model_dump(exclude_none=True)


@router.post("/rules/validate", status_code=status.HTTP_200_OK)
def validate_rule(req: SigmaRuleValidateRequest) -> Dict[str, Any]:
    """
    Validates a raw Sigma rule YAML string against SigmaHQ v2.1.0 specifications
    using the pySigma engine and ThreatMind sidecar integrity checks.
    """
    result = sigma_validation_service.validate_yaml(req.yaml_content)
    return result


@router.post("/rules/{rule_id}/review", status_code=status.HTTP_200_OK)
def review_rule(rule_id: str, req: SigmaRuleReviewRequest) -> Dict[str, Any]:
    """
    Executes an analyst review state transition ('draft' -> 'under_review' -> 'approved' / 'rejected')
    with audit notes.
    """
    updated_rule = sigma_repository.update_review_status(
        rule_id=rule_id,
        new_status=req.review_status,
        reviewer=req.reviewer,
        notes=req.notes,
    )
    return updated_rule.model_dump(exclude_none=True)
