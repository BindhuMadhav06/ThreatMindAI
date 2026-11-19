"""
Phase 14: Decomposed Organization Risk Prioritization Engine.
Calculates transparent, explainable organization risk scores (0 to 100)
using CVSS severity, EPSS probability, asset exposure, criticality,
threat actor relevance, and compensative defensive controls.
"""

from typing import Any, Dict, List, Optional
from app.models.organization import (
    Asset,
    AssetCriticality,
    AssetThreatMatch,
    PrioritizedAssetRisk,
)


class RiskPrioritizationEngine:
    """
    Decomposed organization risk prioritization engine.
    Formula:
      S_org = w_v * S_vuln + w_e * P_exploit + w_x * E_exposure + w_c * C_asset + w_t * T_rel - w_m * M_controls
    Normalized strictly to range [0.0, 100.0].
    """

    CRITICALITY_MAP = {
        AssetCriticality.MISSION_CRITICAL: 100.0,
        AssetCriticality.HIGH: 75.0,
        AssetCriticality.MEDIUM: 50.0,
        AssetCriticality.LOW: 25.0,
    }

    def __init__(
        self,
        weight_vuln: float = 0.25,
        weight_exploit: float = 0.20,
        weight_exposure: float = 0.20,
        weight_criticality: float = 0.20,
        weight_threat_rel: float = 0.15,
        weight_controls: float = 0.15,
    ):
        self.w_v = weight_vuln
        self.w_e = weight_exploit
        self.w_x = weight_exposure
        self.w_c = weight_criticality
        self.w_t = weight_threat_rel
        self.w_m = weight_controls

    def calculate_asset_risk(
        self,
        asset: Asset,
        matches: List[AssetThreatMatch],
        cvss_base: float = 7.5,
        epss_probability: float = 0.35,
        threat_actor_relevance: float = 60.0
    ) -> PrioritizedAssetRisk:
        """
        Compute transparent prioritized risk for an asset given threat matches.
        """
        # S_vuln: CVSS scaled 0..10 -> 0..100
        s_vuln = min(100.0, max(0.0, cvss_base * 10.0))

        # P_exploit: EPSS probability scaled 0..1 -> 0..100
        p_exploit = min(100.0, max(0.0, epss_probability * 100.0))

        # E_exposure: External reachability (100 if external, 30 if internal)
        e_exposure = 100.0 if asset.external_exposure else 30.0

        # C_asset: Business criticality
        c_asset = self.CRITICALITY_MAP.get(asset.criticality, 50.0)

        # T_rel: Threat actor relevance 0..100
        t_rel = min(100.0, max(0.0, threat_actor_relevance))

        # M_controls: 20 points per effective control up to 80 max
        active_controls = len(asset.security_controls)
        m_controls = min(80.0, active_controls * 20.0)

        raw_score = (
            self.w_v * s_vuln
            + self.w_e * p_exploit
            + self.w_x * e_exposure
            + self.w_c * c_asset
            + self.w_t * t_rel
            - self.w_m * m_controls
        )

        composite_score = round(max(0.0, min(100.0, raw_score)), 2)

        if composite_score >= 80.0:
            priority_tier = "CRITICAL"
        elif composite_score >= 60.0:
            priority_tier = "HIGH"
        elif composite_score >= 40.0:
            priority_tier = "MEDIUM"
        else:
            priority_tier = "LOW"

        # Uncertainty bounds based on match count and confidence
        avg_confidence = (
            sum(m.matching_confidence for m in matches) / len(matches)
            if matches else 0.85
        )
        margin = round((1.0 - avg_confidence) * 15.0 + 3.0, 2)
        uncertainty_low = round(max(0.0, composite_score - margin), 2)
        uncertainty_high = round(min(100.0, composite_score + margin), 2)

        recommendations: List[str] = []
        if asset.external_exposure:
            recommendations.append("Restrict public ingress or place behind WAF/Zero-Trust proxy.")
        if not asset.security_controls:
            recommendations.append("Deploy EDR telemetry and MFA to reduce exposure penalty.")
        for match in matches:
            if match.cve_id:
                recommendations.append(
                    f"Patch package '{match.package_name}' beyond vulnerable range '{match.vulnerable_range}' ({match.cve_id})."
                )

        return PrioritizedAssetRisk(
            asset_id=asset.asset_id,
            asset_name=asset.name,
            tenant_id=asset.tenant_id,
            composite_score=composite_score,
            priority_tier=priority_tier,
            score_breakdown={
                "vulnerability_severity": round(s_vuln, 2),
                "exploit_probability": round(p_exploit, 2),
                "asset_exposure": round(e_exposure, 2),
                "asset_criticality": round(c_asset, 2),
                "threat_relevance": round(t_rel, 2),
                "control_mitigation": round(m_controls, 2),
            },
            uncertainty_bounds={
                "low": uncertainty_low,
                "high": uncertainty_high,
            },
            matches=matches,
            recommendations_summary=recommendations
        )
