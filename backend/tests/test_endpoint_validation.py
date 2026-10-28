import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.query import ResolvedEntity
from app.models.reasoning import ReasoningStep, ReasoningRequest
from app.services.reasoning.path_builder import PathBuilder
from app.services.answering.answer_generator import AnswerGenerator
from app.services.answering.prompt_builder import ABSTENTION_PHRASE
from app.evaluation.isolation import seed_evaluation_graph, cleanup_evaluation_graph

@pytest.fixture(scope="module", autouse=True)
def setup_eval_graph():
    """Ensure evaluation graph is seeded for endpoint validation tests, and demo data restored afterwards."""
    seed_evaluation_graph()
    yield
    cleanup_evaluation_graph()
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts")))
    from seed_demo_data import seed_demo_data
    seed_demo_data()

def test_validate_path_endpoints_single_entity():
    """Exploratory single-entity query accepts any valid path."""
    e1 = ResolvedEntity(id="eval_actor_apt29", label="ThreatActor", name="APT29", match_method="canonical", confidence_score=1.0)
    step = ReasoningStep(
        step_number=1,
        source_id="eval_actor_apt29",
        source_label="ThreatActor",
        source_name="APT29",
        rel_type="USES",
        target_id="eval_malware_wellmess",
        target_label="Malware",
        target_name="WellMess",
        evidence_records=[],
        sources=[]
    )
    ok, err = PathBuilder.validate_path_endpoints([step], [e1])
    assert ok is True
    assert err is None

def test_validate_path_endpoints_two_entities_bridged():
    """Query with two entities accepts path connecting both."""
    e1 = ResolvedEntity(id="eval_actor_sandworm", label="ThreatActor", name="Sandworm Team", match_method="canonical", confidence_score=1.0)
    e2 = ResolvedEntity(id="eval_malware_blackenergy", label="Malware", name="BlackEnergy", match_method="canonical", confidence_score=1.0)
    step = ReasoningStep(
        step_number=1,
        source_id="eval_actor_sandworm",
        source_label="ThreatActor",
        source_name="Sandworm Team",
        rel_type="USES",
        target_id="eval_malware_blackenergy",
        target_label="Malware",
        target_name="BlackEnergy",
        evidence_records=[],
        sources=[]
    )
    ok, err = PathBuilder.validate_path_endpoints([step], [e1, e2])
    assert ok is True
    assert err is None

def test_validate_path_endpoints_two_entities_disconnected():
    """Query with two entities rejects path covering only one entity."""
    e1 = ResolvedEntity(id="eval_actor_volt_typhoon", label="ThreatActor", name="Volt Typhoon", match_method="canonical", confidence_score=1.0)
    e2 = ResolvedEntity(id="eval_malware_blackenergy", label="Malware", name="BlackEnergy", match_method="canonical", confidence_score=1.0)
    step = ReasoningStep(
        step_number=1,
        source_id="eval_actor_volt_typhoon",
        source_label="ThreatActor",
        source_name="Volt Typhoon",
        rel_type="USES_TECHNIQUE",
        target_id="eval_tech_valid_accounts",
        target_label="Technique",
        target_name="Valid Accounts",
        evidence_records=[],
        sources=[]
    )
    ok, err = PathBuilder.validate_path_endpoints([step], [e1, e2])
    assert ok is False
    assert "unsupported_endpoint_relationship" in err
    assert "BlackEnergy" in err

def test_validate_path_endpoints_three_entities_fully_bridged():
    """Query with three entities accepts multi-hop chain connecting all three."""
    e1 = ResolvedEntity(id="eval_actor_apt29", label="ThreatActor", name="APT29", match_method="canonical", confidence_score=1.0)
    e2 = ResolvedEntity(id="eval_vuln_cve_2019_19781", label="Vulnerability", name="CVE-2019-19781", match_method="cve", confidence_score=1.0)
    e3 = ResolvedEntity(id="eval_prod_citrix_adc", label="Product", name="Citrix ADC", match_method="canonical", confidence_score=1.0)

    s1 = ReasoningStep(
        step_number=1,
        source_id="eval_actor_apt29",
        source_label="ThreatActor",
        source_name="APT29",
        rel_type="EXPLOITS",
        target_id="eval_vuln_cve_2019_19781",
        target_label="Vulnerability",
        target_name="CVE-2019-19781",
        evidence_records=[],
        sources=[]
    )
    s2 = ReasoningStep(
        step_number=2,
        source_id="eval_vuln_cve_2019_19781",
        source_label="Vulnerability",
        source_name="CVE-2019-19781",
        rel_type="AFFECTS",
        target_id="eval_prod_citrix_adc",
        target_label="Product",
        target_name="Citrix ADC",
        evidence_records=[],
        sources=[]
    )
    ok, err = PathBuilder.validate_path_endpoints([s1, s2], [e1, e2, e3])
    assert ok is True
    assert err is None

def test_validate_path_endpoints_three_entities_disconnected_target_subgraph():
    """Rejects isolated subpath between e2 and e3 that omits primary subject e1."""
    e1 = ResolvedEntity(id="eval_actor_sandworm", label="ThreatActor", name="Sandworm Team", match_method="canonical", confidence_score=1.0)
    e2 = ResolvedEntity(id="eval_vuln_cve_2021_44228", label="Vulnerability", name="CVE-2021-44228", match_method="cve", confidence_score=1.0)
    e3 = ResolvedEntity(id="eval_prod_apache_log4j", label="Product", name="Apache Log4j", match_method="canonical", confidence_score=1.0)

    s1 = ReasoningStep(
        step_number=1,
        source_id="eval_vuln_cve_2021_44228",
        source_label="Vulnerability",
        source_name="CVE-2021-44228",
        rel_type="AFFECTS",
        target_id="eval_prod_apache_log4j",
        target_label="Product",
        target_name="Apache Log4j",
        evidence_records=[],
        sources=[]
    )
    ok, err = PathBuilder.validate_path_endpoints([s1], [e1, e2, e3])
    assert ok is False
    assert "omits the primary subject entity" in err

# =========================================================================
# Regression Tests for Known Unsupported Queries (q_13, q_14, q_15)
# =========================================================================

def test_regression_q13_volt_typhoon_blackenergy_abstains():
    """q_13: Must abstain because Volt Typhoon is not documented using BlackEnergy."""
    generator = AnswerGenerator()
    from app.models.answering import AnswerRequest
    req = AnswerRequest(question="Did Volt Typhoon deploy BlackEnergy malware?")
    res = generator.generate_answer(req)
    assert res.grounding_status == "insufficient_evidence"
    assert res.answer.direct_answer.strip() == ABSTENTION_PHRASE.strip()
    assert len(res.graph_paths) == 0

def test_regression_q14_sandworm_log4j_abstains():
    """q_14: Must abstain because Sandworm Team is not documented exploiting CVE-2021-44228 in Log4j."""
    generator = AnswerGenerator()
    from app.models.answering import AnswerRequest
    req = AnswerRequest(question="Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?")
    res = generator.generate_answer(req)
    assert res.grounding_status == "insufficient_evidence"
    assert res.answer.direct_answer.strip() == ABSTENTION_PHRASE.strip()
    assert len(res.graph_paths) == 0

def test_regression_q15_apt29_olympic_destroyer_abstains():
    """q_15: Must abstain because APT29 is not documented using Olympic Destroyer."""
    generator = AnswerGenerator()
    from app.models.answering import AnswerRequest
    req = AnswerRequest(question="How did APT29 use Olympic Destroyer to attack the Ukrainian power grid?")
    res = generator.generate_answer(req)
    assert res.grounding_status == "insufficient_evidence"
    assert res.answer.direct_answer.strip() == ABSTENTION_PHRASE.strip()
    assert len(res.graph_paths) == 0

# =========================================================================
# Positive Tests for Supported Queries
# =========================================================================

def test_positive_two_entity_direct_supported():
    """Positive 1-hop: Sandworm Team uses BlackEnergy should return a supported answer."""
    generator = AnswerGenerator()
    from app.models.answering import AnswerRequest
    req = AnswerRequest(question="Does Sandworm Team use BlackEnergy?")
    res = generator.generate_answer(req)
    assert res.grounding_status in ["fully_grounded", "partially_grounded"]
    assert res.answer.direct_answer != ABSTENTION_PHRASE
    assert len(res.graph_paths) > 0
    # Verify the path connects Sandworm Team and BlackEnergy
    path = res.graph_paths[0]
    names = [step.source_name for step in path.steps] + [step.target_name for step in path.steps]
    assert "Sandworm Team" in names
    assert "BlackEnergy" in names

def test_positive_three_entity_multihop_supported():
    """Positive 2-hop: APT29 exploiting CVE-2019-19781 affecting Citrix ADC should return a supported answer."""
    generator = AnswerGenerator()
    from app.models.answering import AnswerRequest
    req = AnswerRequest(question="Does APT29 exploit CVE-2019-19781 affecting Citrix ADC?")
    res = generator.generate_answer(req)
    assert res.grounding_status in ["fully_grounded", "partially_grounded"]
    assert res.answer.direct_answer != ABSTENTION_PHRASE
    assert len(res.graph_paths) > 0
    # Verify all three entities are present in the multi-hop reasoning path
    path = res.graph_paths[0]
    names = [step.source_name for step in path.steps] + [step.target_name for step in path.steps]
    assert "APT29" in names
    assert "CVE-2019-19781" in names
    assert "Citrix ADC" in names
