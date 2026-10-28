import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.ingestion.loaders import DocumentLoader
from app.services.ingestion.validator import EvidenceValidator
from app.services.ingestion.models import ExtractedRelationship

def test_evidence_validator_acceptance():
    doc_text = "APT29 has extensively used Cobalt Strike Beacon payloads during targeted cyber operations."
    doc = DocumentLoader.load_txt(doc_text, filename="apt29.txt")

    valid_rel = ExtractedRelationship(
        source_name="APT29",
        source_label="ThreatActor",
        rel_type="USES",
        target_name="Cobalt Strike",
        target_label="Malware",
        evidence_text="APT29 has extensively used Cobalt Strike Beacon payloads during targeted cyber operations."
    )

    result = EvidenceValidator.validate_relationships(doc, [valid_rel])
    assert len(result.accepted_relationships) == 1
    assert len(result.rejected_relationships) == 0

def test_evidence_validator_rejection_missing_evidence_quote():
    doc_text = "Lazarus Group conducted attacks against financial institutions in 2025."
    doc = DocumentLoader.load_txt(doc_text, filename="lazarus.txt")

    # Fabricated relationship not present in source text
    hallucinated_rel = ExtractedRelationship(
        source_name="Lazarus Group",
        source_label="ThreatActor",
        rel_type="USES",
        target_name="WannaCry",
        target_label="Malware",
        evidence_text="Lazarus Group deployed WannaCry ransomware across healthcare servers."
    )

    result = EvidenceValidator.validate_relationships(doc, [hallucinated_rel])
    assert len(result.accepted_relationships) == 0
    assert len(result.rejected_relationships) == 1
    assert "not found in source document" in result.rejected_relationships[0]["reason"]

def test_evidence_validator_rejection_empty_evidence():
    doc_text = "APT29 exploits CVE-2021-44228."
    doc = DocumentLoader.load_txt(doc_text, filename="apt29_cve.txt")

    empty_evidence_rel = ExtractedRelationship(
        source_name="APT29",
        source_label="ThreatActor",
        rel_type="EXPLOITS",
        target_name="CVE-2021-44228",
        target_label="Vulnerability",
        evidence_text=""  # Empty evidence
    )

    result = EvidenceValidator.validate_relationships(doc, [empty_evidence_rel])
    assert len(result.accepted_relationships) == 0
    assert len(result.rejected_relationships) == 1
    assert "empty or missing" in result.rejected_relationships[0]["reason"]

def test_evidence_validator_rejection_disallowed_rel_type():
    doc_text = "APT29 exploits CVE-2021-44228."
    doc = DocumentLoader.load_txt(doc_text, filename="apt29_cve.txt")

    disallowed_rel = ExtractedRelationship(
        source_name="APT29",
        source_label="ThreatActor",
        rel_type="INVALID_RELATION_TYPE",
        target_name="CVE-2021-44228",
        target_label="Vulnerability",
        evidence_text="APT29 exploits CVE-2021-44228."
    )

    result = EvidenceValidator.validate_relationships(doc, [disallowed_rel])
    assert len(result.accepted_relationships) == 0
    assert len(result.rejected_relationships) == 1
    assert "Disallowed relationship type" in result.rejected_relationships[0]["reason"]
