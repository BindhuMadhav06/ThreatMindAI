"""
Source Reliability & Feed Poisoning Detection Service
Phase 13 Implementation (Requirement 13.4)

Evaluates multi-factor source reliability, suppresses circular corroboration
from syndicated feeds, and quarantines adversarial poisoning bursts and injection attempts.
"""

from datetime import datetime, timezone
import re
import uuid
from typing import Dict, List, Optional, Set

from app.models.quality import PoisoningAlert, SourceReliabilityScore, SourceType

SOURCE_TYPE_PRIORS: Dict[SourceType, float] = {
    SourceType.GOVERNMENT_CERT: 0.95,
    SourceType.COMMERCIAL_TI: 0.85,
    SourceType.ISAC_FEED: 0.80,
    SourceType.OPEN_SOURCE: 0.60,
    SourceType.UNVERIFIED_FORUM: 0.35,
}

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+|the\s+)?(previous|prior)\s+instructions",
    r"disregard\s+(previous|prior)\s+(system\s+)?instructions",
    r"you\s+are\s+now\s+a\s+(new\s+)?assistant",
    r"system\s*:\s*override",
    r"<\s*system\s*>",
    r"bypass\s+all\s+guardrails",
    r"assistant\s*:\s*i\s+confirm\s+this\s+claim",
]


class SourceReliabilityService:
    """
    Evaluates feed trustworthiness and protects the ingestion pipeline from data poisoning.
    """

    def __init__(self):
        self._scores_by_source: Dict[str, SourceReliabilityScore] = {}
        self._alerts: List[PoisoningAlert] = []
        self._syndication_clusters: Dict[str, str] = {}  # doc_hash -> root_source_id

    def register_source(
        self,
        source_id: str,
        source_name: str,
        source_type: SourceType = SourceType.COMMERCIAL_TI,
        historical_accuracy: float = 0.85,
        independent_corroboration_rate: float = 0.80,
        correction_rate: float = 0.05,
        recency_factor: float = 0.90,
        circular_penalty: float = 0.0,
    ) -> SourceReliabilityScore:
        type_prior = SOURCE_TYPE_PRIORS.get(source_type, 0.70)
        overall = (
            0.35 * historical_accuracy
            + 0.25 * independent_corroboration_rate
            + 0.15 * (1.0 - correction_rate)
            + 0.15 * recency_factor
            + 0.10 * type_prior
            - 0.20 * circular_penalty
        )
        overall = max(0.0, min(1.0, round(overall, 3)))

        score = SourceReliabilityScore(
            source_id=source_id,
            source_name=source_name,
            source_type=source_type,
            historical_accuracy=round(historical_accuracy, 3),
            independent_corroboration_rate=round(independent_corroboration_rate, 3),
            correction_rate=round(correction_rate, 3),
            recency_factor=round(recency_factor, 3),
            circular_corroboration_penalty=round(circular_penalty, 3),
            overall_reliability=overall,
            quarantine_status=False,
        )
        self._scores_by_source[source_id] = score
        return score

    evaluate_source = register_source

    def get_source_score(self, source_id: str) -> SourceReliabilityScore:
        if source_id in self._scores_by_source:
            return self._scores_by_source[source_id]
        return self.register_source(source_id, source_id, SourceType.OPEN_SOURCE)

    get_score = get_source_score

    def get_all_scores(self) -> List[SourceReliabilityScore]:
        return list(self._scores_by_source.values())

    def get_poisoning_alerts(self) -> List[PoisoningAlert]:
        return list(self._alerts)

    def register_poisoning_alert(
        self,
        source_id: str,
        source_name: str,
        anomaly_type: str,
        anomaly_score: float,
        details: str,
        quarantined: bool = True
    ) -> PoisoningAlert:
        alert = PoisoningAlert(
            alert_id=f"alert-{uuid.uuid4()}",
            source_id=source_id,
            source_name=source_name,
            anomaly_type=anomaly_type,  # type: ignore
            anomaly_score=anomaly_score,
            quarantined=quarantined,
            details=details,
        )
        self._alerts.append(alert)

        # Update source quarantine status
        if source_id in self._scores_by_source:
            self._scores_by_source[source_id].quarantine_status = quarantined
        else:
            score = self.register_source(source_id, source_name)
            score.quarantine_status = quarantined

        return alert

    def register_syndication(self, doc_hash: str, original_source_id: str):
        if doc_hash not in self._syndication_clusters:
            self._syndication_clusters[doc_hash] = original_source_id

    def check_circular_corroboration(self, doc_hash: str, current_source_id: str) -> bool:
        original_source = self._syndication_clusters.get(doc_hash)
        if original_source and original_source != current_source_id:
            return True
        return False

    def inspect_content_for_poisoning(
        self,
        source_id: str,
        source_name: str,
        content: str,
        indicator_count: int = 1,
        time_window_count: int = 1,
    ) -> Optional[PoisoningAlert]:
        for pat in PROMPT_INJECTION_PATTERNS:
            if re.search(pat, content, re.IGNORECASE):
                return self.register_poisoning_alert(
                    source_id=source_id,
                    source_name=source_name,
                    anomaly_type="PROMPT_INJECTION_ATTEMPT",
                    anomaly_score=0.98,
                    details=f"Adversarial prompt injection pattern detected: '{pat}'. Content quarantined.",
                    quarantined=True
                )

        if time_window_count > 100:
            return self.register_poisoning_alert(
                source_id=source_id,
                source_name=source_name,
                anomaly_type="VOLUME_BURST",
                anomaly_score=0.88,
                details=f"Anomalous claim volume spike ({time_window_count} items in current window). Quarantined for review.",
                quarantined=True
            )

        return None

    def list_alerts(self, quarantined_only: bool = True) -> List[PoisoningAlert]:
        if quarantined_only:
            return [a for a in self._alerts if a.quarantined]
        return list(self._alerts)
