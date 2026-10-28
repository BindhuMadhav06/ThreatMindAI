"""
ThreatMind Phase 11D — Release Verification Script
Automated release-gate execution verifying backend APIs, D3FEND mappings,
vulnerability intelligence, edge-case contracts, and dataset integrity.
"""

import sys
import hashlib
import json
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from fastapi.testclient import TestClient
from app.main import app
from app.services.defense.d3fend_service import D3fendService
from app.services.vulnerability.enrichment_service import VulnerabilityEnrichmentService

def test_section(name: str):
    print(f"\n{'='*70}\n[RUNNING CHECK] {name}\n{'='*70}")

def assert_check(condition: bool, msg: str):
    if not condition:
        print(f"  [FAIL] {msg}")
        raise AssertionError(f"Check failed: {msg}")
    print(f"  [PASS] {msg}")

def main():
    print("Initiating ThreatMind Phase 11D Release Verification Suite...")
    client = TestClient(app)
    d3fend_service = D3fendService()
    vuln_service = VulnerabilityEnrichmentService()

    # -------------------------------------------------------------------------
    # Gate 1: Catalog & Mapping Integrity
    # -------------------------------------------------------------------------
    test_section("Gate 1: MITRE D3FEND Catalog & Mapping Integrity")
    catalog_path = ROOT / "backend" / "app" / "services" / "defense" / "d3fend_catalog.json"
    assert_check(catalog_path.exists(), "d3fend_catalog.json exists")

    with open(catalog_path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    assert_check(actual_hash == d3fend_service.catalog_sha256, f"Catalog SHA-256 integrity matches ({actual_hash[:16]}...)")

    with open(catalog_path, "r", encoding="utf-8") as f:
        catalog_data = json.load(f)

    # Verify no app: identifiers have official URLs
    for rec in catalog_data.get("mappings", []):
        cm = rec.get("countermeasure", {})
        d_id = cm.get("id", "")
        off_url = cm.get("official_url")
        if d_id.startswith("app:"):
            assert_check(not off_url, f"App-inferred {d_id} strictly has no official URL (empty or None)")
            assert_check(rec.get("mapping_provenance") == "Application-defined heuristic inference (no direct MITRE D3FEND ontology countermeasure or M1040 table mapping)", f"{d_id} has provenance=Application-defined heuristic inference")
            assert_check(rec.get("applicability") == "potentially_relevant", f"{d_id} has applicability=potentially_relevant")
        else:
            assert_check(d_id.startswith("d3f:") or d_id.startswith("D3-"), f"Official D3FEND technique {d_id} starts with d3f: or D3-")
            assert_check(off_url is not None and "d3fend.mitre.org" in off_url, f"{d_id} has valid canonical MITRE URL: {off_url}")

    # -------------------------------------------------------------------------
    # Gate 2: Defensive Recommendations API & Edge Cases
    # -------------------------------------------------------------------------
    test_section("Gate 2: Defensive Recommendations API & Edge Cases")

    # Positive batch request
    resp = client.post("/api/v1/defense/recommend", json={"technique_ids": ["T1059.001", "T1055"]})
    assert_check(resp.status_code == 200, "POST /api/v1/defense/recommend returns 200 for valid techniques")
    data = resp.json()
    assert_check(len(data["recommendations"]) >= 2, "Returns at least 2 recommendations for T1059.001 and T1055")
    assert_check("Harden" in data["summary_by_tactic"], "Summary contains Harden tactic")

    # Duplicate technique IDs handling
    resp_single = client.get("/api/v1/defense/techniques/T1059.001")
    single_count = len(resp_single.json())
    resp_dup = client.post("/api/v1/defense/recommend", json={"technique_ids": ["T1059.001", "T1059.001", "t1059.001"]})
    assert_check(resp_dup.status_code == 200, "POST /api/v1/defense/recommend handles duplicate technique IDs")
    assert_check(len(resp_dup.json()["recommendations"]) == single_count, f"Duplicate IDs are deduplicated ({single_count} unique recommendations)")

    # Invalid technique format handling
    resp_invalid = client.get("/api/v1/defense/techniques/NOT-A-TECHNIQUE")
    assert_check(resp_invalid.status_code == 400, "GET /api/v1/defense/techniques/NOT-A-TECHNIQUE returns 400 Bad Request")

    # Unknown technique handling (valid format, e.g. T9999)
    resp_unknown = client.get("/api/v1/defense/techniques/T9999")
    assert_check(resp_unknown.status_code == 200, "GET /api/v1/defense/techniques/T9999 returns 200 with empty recommendations")
    assert_check(len(resp_unknown.json()) == 0, "Unknown technique returns 0 recommendations without crashing")

    # Empty batch handling
    resp_empty = client.post("/api/v1/defense/recommend", json={"technique_ids": []})
    assert_check(resp_empty.status_code == 422, "POST /api/v1/defense/recommend with empty list returns 422 Unprocessable Entity")

    # -------------------------------------------------------------------------
    # Gate 3: Vulnerability Intelligence API & Freshness Guardrails
    # -------------------------------------------------------------------------
    test_section("Gate 3: Vulnerability Intelligence API & Freshness Guardrails")

    # Critical Log4Shell CVE
    resp_log4j = client.get("/api/v1/vulnerabilities/CVE-2021-44228/intel")
    assert_check(resp_log4j.status_code == 200, "GET /api/v1/vulnerabilities/CVE-2021-44228/intel returns 200")
    v_log4j = resp_log4j.json()
    assert_check(v_log4j["cvss"]["base_score"] == 10.0, "CVSS base score is 10.0")
    assert_check(v_log4j["cvss"]["severity"] == "Critical", "CVSS severity is Critical")
    assert_check(v_log4j["epss"]["probability"] > 0.90, "EPSS wild exploit probability > 90%")
    assert_check(v_log4j["cisa_kev"]["status"] == "Listed", "CISA KEV status is Listed")
    assert_check(v_log4j["cisa_kev"]["is_stale_assertion"] is False, "Log4Shell KEV is not marked as stale assertion")

    # Sudo CVE with historical snapshot KEV Not Listed
    resp_sudo = client.get("/api/v1/vulnerabilities/CVE-2019-14287/intel")
    assert_check(resp_sudo.status_code == 200, "GET /api/v1/vulnerabilities/CVE-2019-14287/intel returns 200")
    v_sudo = resp_sudo.json()
    assert_check(v_sudo["cisa_kev"]["status"] == "Not listed", "Sudo CVE KEV status is 'Not listed' in snapshot")
    assert_check(v_sudo["cisa_kev"]["is_stale_assertion"] is True, "Stale snapshot of 'Not listed' triggers is_stale_assertion=True")
    assert_check(v_sudo["freshness"] == "stale", "Aggregate freshness is marked 'stale'")
    assert_check("status unverified" in v_sudo["cisa_kev"]["notes"], "Notes clearly state status unverified")

    # EPSS API Version vs Model Version verification
    assert_check(v_log4j["epss"]["model_version"] != "1.0", "FIRST API version '1.0' is NEVER misassigned to model_version")
    assert_check("api_version" in v_log4j["epss"], "EPSS schema contains dedicated api_version field")

    # Malformed CVE ID input
    resp_bad_cve = client.get("/api/v1/vulnerabilities/INVALID-CVE/intel")
    assert_check(resp_bad_cve.status_code == 400, "Invalid CVE format returns 400 Bad Request")

    # Unknown CVE ID input (valid syntax, e.g. CVE-2099-99999)
    resp_unk_cve = client.get("/api/v1/vulnerabilities/CVE-2099-99999/intel")
    assert_check(resp_unk_cve.status_code == 200, "Unknown CVE returns 200 with safe unavailable state")
    v_unk = resp_unk_cve.json()
    assert_check(v_unk["cisa_kev"]["status"] == "Unable to verify", "Network/upstream miss sets KEV to 'Unable to verify', NEVER 'Not listed'")
    assert_check(v_unk["freshness"] == "unavailable", "Freshness for unknown CVE is 'unavailable'")

    # -------------------------------------------------------------------------
    # Gate 4: Evaluation Dataset Preservation
    # -------------------------------------------------------------------------
    test_section("Gate 4: Evaluation Dataset Preservation")
    from scripts.validate_dataset import validate_dataset
    dataset_valid = validate_dataset()
    assert_check(dataset_valid, "Evaluation dataset v1.1.0 passes 100% integrity validation")

    print("\n" + "="*70)
    print("ALL RELEASE VERIFICATION GATES PASSED (100% SUCCESS)")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
