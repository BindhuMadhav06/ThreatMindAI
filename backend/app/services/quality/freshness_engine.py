"""
Temporal Intelligence & Freshness Decay Engine
Phase 13 Implementation (Requirement 13.3)

Implements entity-aware freshness models: freshness(t) = 2^(-age / half_life).
Distinguishes freshness from truth/confidence, generates stale warnings,
supports as-of-time historical queries, and strictly preserves historical evidence.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models.quality import FreshnessPolicy

DEFAULT_HALF_LIFE_DAYS: Dict[str, float] = {
    "ipv4": 14.0,
    "ipv6": 14.0,
    "ip_address": 14.0,
    "ipv4-addr": 14.0,
    "ipv6-addr": 14.0,
    "domain": 60.0,
    "domain-name": 60.0,
    "url": 7.0,
    "file_hash": 365.0,
    "file": 365.0,
    "vulnerability": 730.0,
    "threat_actor_claim": 365.0,
    "threat-actor": 365.0,
    "campaign": 90.0,
    "malware_family": 180.0,
    "malware": 180.0,
    "detection_rule": 180.0,
    "default": 90.0,
}


def parse_timestamp(ts_val: Any) -> datetime:
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val
    if isinstance(ts_val, str):
        clean = ts_val.strip()
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        elif "+" not in clean and len(clean) >= 19:
            clean = clean + "+00:00"
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return datetime.now(timezone.utc)


class FreshnessEngine:
    """
    Computes mathematical freshness decay and evaluates temporal policy guardrails.
    """

    def __init__(self, half_life_config: Optional[Dict[str, float]] = None):
        self.half_life_config = dict(DEFAULT_HALF_LIFE_DAYS)
        if half_life_config:
            self.half_life_config.update(half_life_config)

    def get_half_life(self, entity_type: str) -> float:
        return self.half_life_config.get(entity_type.lower(), self.half_life_config["default"])

    def evaluate_freshness(
        self,
        entity_type: str,
        observation_time: Any,
        as_of_time: Optional[Any] = None,
    ) -> FreshnessPolicy:
        """
        Calculates freshness score:
        freshness = 2 ^ (-age_days / half_life_days)
        Supports frozen-clock evaluation via `as_of_time`.
        """
        obs_dt = parse_timestamp(observation_time)
        eval_dt = parse_timestamp(as_of_time) if as_of_time else datetime.now(timezone.utc)

        age_seconds = max(0.0, (eval_dt - obs_dt).total_seconds())
        age_days = age_seconds / 86400.0

        half_life = self.get_half_life(entity_type)
        freshness_score = 2.0 ** (-age_days / half_life)
        # Clamp to range [0.0, 1.0]
        freshness_score = max(0.0, min(1.0, round(freshness_score, 6)))

        is_stale = (age_days > half_life) or (freshness_score < 0.50)
        stale_warning = None
        if is_stale:
            stale_warning = (
                f"Stale indicator warning for {entity_type}: observation is {age_days:.1f} days old "
                f"which exceeds entity half-life of {half_life} days (freshness score {freshness_score:.3f}). "
                f"Confidence must be calibrated for historical decay."
            )

        expiration_days = 5.0 * half_life
        is_expired = age_days >= expiration_days

        return FreshnessPolicy(
            entity_type=entity_type,
            half_life_days=half_life,
            current_age_days=round(age_days, 3),
            freshness_score=freshness_score,
            is_stale=is_stale,
            stale_warning=stale_warning,
            expiration_days=expiration_days,
            is_expired=is_expired,
        )

    # Alias for API compatibility
    calculate_freshness = evaluate_freshness
