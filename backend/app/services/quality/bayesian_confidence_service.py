"""
Bayesian Beta-Binomial confidence calibration service.
Implements mathematically rigorous Bayesian updating with transparent priors,
independent evidence weighting, syndicated report discounting,
95% credible intervals, and Brier score tracking.
"""

from typing import Any, Dict, List, Optional
from scipy.stats import beta
from app.models.quality import BayesianConfidenceEstimate


class BayesianConfidenceService:
    """
    Bayesian confidence calibration using Beta-Binomial conjugate update.
    Prior: Beta(alpha_0, beta_0), default (2.0, 2.0)
    Posterior: Beta(alpha_0 + w_pos, beta_0 + w_neg)
    """

    def __init__(self, default_alpha: float = 2.0, default_beta: float = 2.0):
        self.default_alpha = default_alpha
        self.default_beta = default_beta

    def calibrate(
        self,
        claim_id: str,
        positive_evidences: Optional[List[Dict[str, Any]]] = None,
        negative_evidences: Optional[List[Dict[str, Any]]] = None,
        prior_alpha: Optional[float] = None,
        prior_beta: Optional[float] = None,
        ground_truth_outcome: Optional[int] = None
    ) -> BayesianConfidenceEstimate:
        """
        Calibrate confidence on an intelligence claim given supporting and contradicting evidence.
        Each evidence item may specify:
          - 'weight': base confidence or weight (default 1.0)
          - 'reliability': source reliability factor (default 1.0)
          - 'is_correlated' or 'is_syndicated': bool indicating feed duplication (discount factor 0.2)
        """
        alpha_0 = prior_alpha if prior_alpha is not None else self.default_alpha
        beta_0 = prior_beta if prior_beta is not None else self.default_beta

        pos_list = positive_evidences or []
        neg_list = negative_evidences or []

        def calculate_weight(item: Dict[str, Any]) -> float:
            base_w = float(item.get("weight", 1.0))
            rel = float(item.get("reliability", 1.0))
            is_syndicated = bool(item.get("is_correlated", False) or item.get("is_syndicated", False))
            discount = 0.2 if is_syndicated else 1.0
            return max(0.0, base_w * rel * discount)

        w_pos = sum(calculate_weight(e) for e in pos_list)
        w_neg = sum(calculate_weight(e) for e in neg_list)

        post_alpha = alpha_0 + w_pos
        post_beta = beta_0 + w_neg

        # Expected value
        expected_confidence = post_alpha / (post_alpha + post_beta)

        # Variance
        total_param = post_alpha + post_beta
        variance = (post_alpha * post_beta) / ((total_param ** 2) * (total_param + 1))

        # 95% Credible Interval using scipy.stats.beta
        ci_low, ci_high = beta.ppf([0.025, 0.975], post_alpha, post_beta)

        total_count = len(pos_list) + len(neg_list)
        is_insufficient = total_count < 2

        brier_sample: Optional[float] = None
        if ground_truth_outcome is not None:
            # outcome must be 0 or 1
            gt = 1.0 if ground_truth_outcome > 0 else 0.0
            brier_sample = float((expected_confidence - gt) ** 2)

        return BayesianConfidenceEstimate(
            claim_id=claim_id,
            prior_alpha=round(alpha_0, 4),
            prior_beta=round(beta_0, 4),
            positive_evidence_weight=round(w_pos, 4),
            negative_evidence_weight=round(w_neg, 4),
            posterior_alpha=round(post_alpha, 4),
            posterior_beta=round(post_beta, 4),
            expected_confidence=round(expected_confidence, 4),
            credible_interval_low=round(float(ci_low), 4),
            credible_interval_high=round(float(ci_high), 4),
            variance=round(variance, 6),
            total_evidence_count=total_count,
            is_insufficient_evidence=is_insufficient,
            brier_score_sample=round(brier_sample, 6) if brier_sample is not None else None
        )

    def compute_brier_score(self, predictions: List[float], outcomes: List[int]) -> float:
        """
        Compute mean squared error across predictions and true outcomes (0 or 1).
        Formula: Brier = (1/N) * sum((p_i - o_i)^2)
        """
        if not predictions or len(predictions) != len(outcomes):
            return 0.0
        n = len(predictions)
        total_sq_err = sum((float(p) - (1.0 if o > 0 else 0.0)) ** 2 for p, o in zip(predictions, outcomes))
        return round(total_sq_err / n, 6)
