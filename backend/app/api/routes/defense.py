from typing import List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.models.d3fend import DefensiveResponse, DefensiveRecommendation
from app.services.defense.d3fend_service import d3fend_service
from app.core.logging import logger

router = APIRouter()

class DefenseRecommendationRequest(BaseModel):
    technique_ids: List[str] = Field(..., min_length=1, description="List of ATT&CK technique IDs (e.g. ['T1059.001', 'T1078'])")

@router.get(
    "/defense/techniques/{external_id}",
    response_model=List[DefensiveRecommendation],
    summary="Get MITRE D3FEND defensive countermeasures for an ATT&CK technique"
)
def get_defenses_for_technique(external_id: str):
    """
    Resolves authoritative MITRE D3FEND defensive recommendations for a specific
    MITRE ATT&CK technique ID (e.g. T1059.001 or T1078).
    Traces through: ATT&CK technique -> ATT&CK mitigation -> D3FEND technique.
    """
    normalized = d3fend_service.normalize_technique_id(external_id)
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid ATT&CK technique identifier format: '{external_id}'. Expected format like 'T1059.001' or 'T1078'."
        )

    recommendations = d3fend_service.get_recommendations_for_technique(normalized)
    return recommendations

@router.post(
    "/defense/recommend",
    response_model=DefensiveResponse,
    summary="Batch resolve defensive recommendations for multiple techniques"
)
def get_recommendations_batch(request: DefenseRecommendationRequest):
    """
    Aggregates defensive recommendations across multiple ATT&CK technique IDs,
    providing deduplicated countermeasures, provenance, and summary metrics.
    """
    if not request.technique_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Technique ID list cannot be empty."
        )

    try:
        response = d3fend_service.get_recommendations(request.technique_ids)
        return response
    except Exception as e:
        logger.error(f"Error computing defensive recommendations: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Defensive reasoning engine failed: {str(e)}"
        )
