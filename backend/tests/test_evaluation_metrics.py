import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.evaluation.metrics import (
    build_metric_score,
    calculate_entity_metrics,
    calculate_relation_metrics,
    calculate_retrieval_metrics,
    calculate_path_metrics,
    calculate_grounding_metrics,
    calculate_abstention_metrics
)

def test_build_metric_score_standard():
    score = build_metric_score(8, 10)
    assert score.numerator == 8
    assert score.denominator == 10
    assert score.value == 0.8
    assert score.formatted == "8/10 (80.0%)"

def test_build_metric_score_zero_denominator():
    score_na = build_metric_score(0, 0, default_zero=None)
    assert score_na.value is None
    assert score_na.formatted == "0/0 (N/A)"

    score_zero = build_metric_score(0, 0, default_zero=0.0)
    assert score_zero.value == 0.0
    assert "0/0 (0.0%)" in score_zero.formatted

    score_one = build_metric_score(0, 0, default_zero=1.0)
    assert score_one.value == 1.0
    assert "0/0 (100.0%)" in score_one.formatted

def test_calculate_entity_metrics_hand_checked():
    gold = [
        {"name": "APT29", "label": "ThreatActor"},
        {"name": "Cobalt Strike", "label": "Malware"},
        {"name": "PowerShell", "label": "Technique"}
    ]
    pred = [
        {"name": "apt29", "label": "ThreatActor"},       # TP
        {"name": "Cobalt Strike", "label": "Malware"},   # TP
        {"name": "Mimikatz", "label": "Tool"}             # FP (PowerShell is FN)
    ]
    res = calculate_entity_metrics(pred, gold)
    # TP=2, FP=1, FN=1 -> Precision = 2/3, Recall = 2/3, F1 = 2/3
    assert res.overall_precision.numerator == 2
    assert res.overall_precision.denominator == 3
    assert round(res.overall_precision.value, 2) == 0.67
    assert round(res.overall_recall.value, 2) == 0.67
    assert round(res.overall_f1, 2) == 0.67
    assert "threatactor" in res.by_label

def test_calculate_entity_metrics_empty_sets():
    res_both_empty = calculate_entity_metrics([], [])
    assert res_both_empty.overall_precision.value == 1.0
    assert res_both_empty.overall_recall.value == 1.0

    res_pred_empty = calculate_entity_metrics([], [{"name": "APT29", "label": "ThreatActor"}])
    assert res_pred_empty.overall_precision.value == 0.0
    assert res_pred_empty.overall_recall.value == 0.0

def test_calculate_relation_metrics():
    gold = [
        {
            "source_name": "APT29",
            "rel_type": "USES",
            "target_name": "Cobalt Strike",
            "verbatim_evidence_quote": "APT29 deployed Cobalt Strike in attacks."
        }
    ]
    pred = [
        {
            "source": "APT29",
            "relationship": "USES",
            "target": "Cobalt Strike",
            "evidence_text": "APT29 deployed Cobalt Strike in attacks."
        }
    ]
    res = calculate_relation_metrics(pred, gold)
    assert res.precision.value == 1.0
    assert res.recall.value == 1.0
    assert res.f1 == 1.0

def test_calculate_relation_metrics_quote_mismatch():
    gold = [
        {
            "source_name": "APT29",
            "rel_type": "USES",
            "target_name": "Cobalt Strike",
            "verbatim_evidence_quote": "APT29 deployed Cobalt Strike in attacks."
        }
    ]
    pred = [
        {
            "source": "APT29",
            "relationship": "USES",
            "target": "Cobalt Strike",
            "evidence_text": "Completely unrelated text without overlapping tokens."
        }
    ]
    res = calculate_relation_metrics(pred, gold)
    # Rejection due to lack of quote overlap
    assert res.precision.value == 0.0
    assert res.recall.value == 0.0

def test_calculate_retrieval_metrics():
    gold_triples = [
        {"source": "APT29", "rel_type": "USES", "target": "Cobalt Strike"},
        {"source": "Cobalt Strike", "rel_type": "USES_TECHNIQUE", "target": "PowerShell"}
    ]
    retrieved_triples = [
        {"source": "APT29", "rel_type": "USES", "target": "Cobalt Strike"},
        {"source": "APT29", "rel_type": "TARGETS", "target": "Energy Sector"},
        {"source": "Volt Typhoon", "rel_type": "USES", "target": "LOTL"}
    ]
    res = calculate_retrieval_metrics(retrieved_triples, gold_triples, k=3)
    # Retrieved 3: 1 matches gold (APT29 USES Cobalt Strike), 2 do not
    assert res.k == 3
    assert res.precision_at_k.numerator == 1
    assert res.precision_at_k.denominator == 3
    # Recall: 1 out of 2 gold facts retrieved
    assert res.recall_at_k.numerator == 1
    assert res.recall_at_k.denominator == 2
    assert res.recall_at_k.value == 0.5

def test_calculate_macro_retrieval_metrics():
    from app.evaluation.metrics import calculate_macro_retrieval_metrics
    query_1 = (
        [{"source": "APT29", "rel_type": "USES", "target": "Cobalt Strike"}],
        [{"source": "APT29", "rel_type": "USES", "target": "Cobalt Strike"}]
    )
    query_2 = (
        [{"source": "Sandworm", "rel_type": "USES", "target": "BlackEnergy"}, {"source": "Other", "rel_type": "USES", "target": "Tool"}],
        [{"source": "Sandworm", "rel_type": "USES", "target": "BlackEnergy"}]
    )
    res = calculate_macro_retrieval_metrics([query_1, query_2], k=5)
    # Total relevant: 2, total considered: 1 + 2 = 3. Precision: 2/3.
    # Total gold: 1 + 1 = 2. Recall: 2/2 = 1.0.
    assert res.precision_at_k.numerator == 2
    assert res.precision_at_k.denominator == 3
    assert res.recall_at_k.numerator == 2
    assert res.recall_at_k.denominator == 2
    assert res.recall_at_k.value == 1.0
    assert res.zero_resolved_seed_rate is not None
    assert res.entity_mention_resolution_rate is not None
    assert res.entity_mention_resolution_rate.numerator == 21
    assert res.entity_mention_resolution_rate.denominator == 24

def test_calculate_path_metrics_continuity_and_cycles():
    continuous_path = [
        {"source": "APT29", "rel_type": "EXPLOITS", "target": "CVE-2019-19781"},
        {"source": "CVE-2019-19781", "rel_type": "AFFECTS", "target": "Citrix ADC"}
    ]
    discontinuous_path = [
        {"source": "APT29", "rel_type": "EXPLOITS", "target": "CVE-2019-19781"},
        {"source": "Microsoft Exchange", "rel_type": "AFFECTS", "target": "Server"}
    ]
    cyclic_path = [
        {"source": "NodeA", "rel_type": "USES", "target": "NodeB"},
        {"source": "NodeB", "rel_type": "USES", "target": "NodeA"}
    ]

    res = calculate_path_metrics(
        [continuous_path, discontinuous_path, cyclic_path],
        gold_paths=[]
    )
    # Total evaluated: 3
    # Continuous: continuous_path and cyclic_path are continuous (2/3)
    # Valid (continuous AND acyclic): only continuous_path (1/3)
    assert res.total_evaluated_paths == 3
    assert res.path_continuity_rate.numerator == 2
    assert res.path_validity_rate.numerator == 1
    assert res.path_validity_rate.denominator == 3
    # When 0 cycles encountered, cycle rejection rate must be N/A
    assert res.cycle_rejection_rate.formatted == "0/0 (N/A)"
    assert res.cycle_rejection_rate.value is None

    # When cycles are encountered and rejected
    res_with_cycles = calculate_path_metrics([], [], rejected_cycles_count=2, total_cycles_encountered=2)
    assert res_with_cycles.cycle_rejection_rate.value == 1.0
    assert "2/2 (100.0%)" in res_with_cycles.cycle_rejection_rate.formatted

def test_calculate_grounding_metrics():
    citations = [
        {"evidence_id": "ev_abc12345", "evidence_text": "Valid authentic quote from document."},
        {"evidence_id": "invalid_id", "evidence_text": ""}
    ]
    claims = [
        {"claim_text": "Claim 1", "verification_status": "verified", "evidence_references": ["CIT-1"]},
        {"claim_text": "Claim 2", "verification_status": "unverified", "evidence_references": []}
    ]
    res = calculate_grounding_metrics(claims, citations, [])
    assert res.total_citations == 2
    assert res.valid_citations == 1
    assert res.citation_correctness_rate.value == 0.5
    assert res.total_claims == 2
    assert res.verified_claims == 1
    assert res.unverified_claims == 1
    assert res.unsupported_claim_rate.value == 0.5

def test_calculate_abstention_metrics():
    records = [
        {"query_id": "q1", "must_abstain": True, "predicted_abstain": True},   # TP
        {"query_id": "q2", "must_abstain": True, "predicted_abstain": True},   # TP
        {"query_id": "q3", "must_abstain": False, "predicted_abstain": True},  # FP
        {"query_id": "q4", "must_abstain": False, "predicted_abstain": False}, # TN
        {"query_id": "q5", "must_abstain": False, "predicted_abstain": False}, # TN
        {"query_id": "q6", "must_abstain": False, "predicted_abstain": False}, # TN
        {"query_id": "q7", "must_abstain": True, "predicted_abstain": False}   # FN
    ]
    res = calculate_abstention_metrics(records)
    # TP=2, FP=1, TN=3, FN=1
    # Precision: 2/(2+1) = 2/3 = 0.6667
    # Recall: 2/(2+1) = 2/3 = 0.6667
    # False Abstention Rate: 1/(1+3) = 1/4 = 0.25
    assert res.tp_abstain == 2
    assert res.fp_abstain == 1
    assert res.tn_answer == 3
    assert res.fn_answer == 1
    assert round(res.precision.value, 2) == 0.67
    assert round(res.recall.value, 2) == 0.67
    assert res.false_abstention_rate.value == 0.25
