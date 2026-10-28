from fastapi import APIRouter, HTTPException, status, Query

from app.models.vulnerability_intel import VulnerabilityIntelResponse
from app.services.vulnerability.enrichment_service import vulnerability_service
from app.core.logging import logger

router = APIRouter()

@router.get(
    "/vulnerabilities/{cve_id}/intel",
    response_model=VulnerabilityIntelResponse,
    summary="Get enriched vulnerability intelligence (CVSS, EPSS, CISA KEV)"
)
def get_vulnerability_intelligence(
    cve_id: str,
    force_live: bool = Query(
        default=False,
        description="Whether to attempt live network retrieval rather than local cache."
    )
):
    """
    Returns enriched vulnerability intelligence for a CVE identifier,
    including CVSS v3.1 severity, EPSS 30-day wild exploitation probability,
    and official CISA Known Exploited Vulnerabilities (KEV) catalog status.
    """
    normalized = vulnerability_service.normalize_cve_id(cve_id)
    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid CVE identifier format: '{cve_id}'. Expected format like 'CVE-2021-44228'."
        )

    try:
        intel = vulnerability_service.get_vulnerability_intel(normalized, force_live=force_live)
        return intel
    except Exception as e:
        logger.error(f"Error retrieving vulnerability intelligence for {cve_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Vulnerability intelligence lookup failed: {str(e)}"
        )
