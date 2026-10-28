import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.normalization.normalizer import EntityNormalizer
from app.services.ingestion.models import ExtractedEntity, ExtractedRelationship

def test_normalize_cve():
    assert EntityNormalizer.normalize_cve_id("cve_2021_44228") == "CVE-2021-44228"
    assert EntityNormalizer.normalize_cve_id("CVE-2023-1234") == "CVE-2023-1234"

def test_normalize_mitre_technique():
    assert EntityNormalizer.normalize_mitre_technique_id("t1059.001") == "T1059.001"
    assert EntityNormalizer.normalize_mitre_technique_id("t1059") == "T1059"

def test_normalize_threat_actor_aliases():
    e1 = ExtractedEntity(id="e1", label="ThreatActor", name="Cozy Bear")
    n1 = EntityNormalizer.normalize_entity(e1)
    assert n1.name == "APT29"
    assert n1.id == "actor_apt29"

    e2 = ExtractedEntity(id="e2", label="Malware", name="Beacon")
    n2 = EntityNormalizer.normalize_entity(e2)
    assert n2.name == "Cobalt Strike"
    assert n2.id == "malware_cobalt_strike"

def test_normalize_relationship():
    rel = ExtractedRelationship(
        source_name="Cozy Bear",
        source_label="ThreatActor",
        rel_type="USES",
        target_name="Beacon",
        target_label="Malware",
        evidence_text="Cozy Bear deployed Beacon."
    )
    norm_rel = EntityNormalizer.normalize_relationship(rel)
    assert norm_rel.source_name == "APT29"
    assert norm_rel.target_name == "Cobalt Strike"
