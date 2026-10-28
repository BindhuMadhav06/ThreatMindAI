import json
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Any, Set
from app.models.d3fend import (
    DefensiveRecommendation,
    DefensiveResponse,
    D3fendCountermeasure,
    ApplicabilityClassification,
    D3fendTactic,
)
from app.core.logging import logger

CATALOG_PATH = Path(__file__).parent / "d3fend_catalog.json"
EXPECTED_CATALOG_SHA256 = "a7a1ebffba38d5283df0c1bdf84eb78b4c5849c643c48da9e0e3a132a9ad04b2"

TECHNIQUE_ID_REGEX = re.compile(r"^(T\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# Pinned registry of recognized MITRE ATT&CK Enterprise techniques and sub-techniques
# Used to prevent fabricated or nonexistent IDs (e.g. T1059.999) from triggering parent fallback.
RECOGNIZED_ATTACK_TECHNIQUES: Set[str] = {
    # T1059 family (Command and Scripting Interpreter)
    "T1059",
    "T1059.001",  # PowerShell
    "T1059.002",  # AppleScript
    "T1059.003",  # Windows Command Shell
    "T1059.004",  # Unix Shell
    "T1059.005",  # Visual Basic
    "T1059.006",  # Python
    "T1059.007",  # JavaScript
    "T1059.008",  # Network Device CLI
    # T1078 family (Valid Accounts)
    "T1078",
    "T1078.001",  # Default Accounts
    "T1078.002",  # Domain Accounts
    "T1078.003",  # Local Accounts
    "T1078.004",  # Cloud Accounts
    # T1055 family (Process Injection)
    "T1055",
    "T1055.001",  # DLL Injection
    "T1055.002",  # PE Injection
    "T1055.003",  # Thread Execution Hijacking
    "T1055.004",  # APC Injection
    "T1055.005",  # Thread Local Storage
    "T1055.008",  # Ptrace System Calls
    "T1055.009",  # Proc Memory
    "T1055.011",  # Extra Window Memory Injection
    "T1055.012",  # Process Hollowing
    "T1055.013",  # Process Doppelganging
    "T1055.014",  # VDSO Hijacking
    # T1505 family (Server Software Component)
    "T1505",
    "T1505.001",  # Exchange Transport Agent
    "T1505.002",  # Office Application Startup
    "T1505.003",  # Web Shell
    "T1505.004",  # IIS Components
    "T1505.005",  # Terminal Services DLL
    # T1003 family (OS Credential Dumping)
    "T1003",
    "T1003.001",  # LSASS Memory
    "T1003.002",  # SAM
    "T1003.003",  # NTDS
    "T1003.004",  # LSA Secrets
    "T1003.005",  # Cached Domain Credentials
    "T1003.006",  # DCSync
    "T1003.007",  # Proc Filesystem
    "T1003.008",  # /etc/passwd and /etc/shadow
    # T1566 family (Phishing)
    "T1566",
    "T1566.001",  # Spearphishing Attachment
    "T1566.002",  # Spearphishing Link
    "T1566.003",  # Spearphishing via Service
    # T1560 family (Archive Collected Data)
    "T1560",
    "T1560.001",  # Archive via Utility
    "T1560.002",  # Archive via Library
    "T1560.003",  # Archive via Custom Software
    # T1498 family (Network Denial of Service)
    "T1498",
    "T1498.001",  # Direct Network Flood
    "T1498.002",  # Reflection Amplification
    # Single techniques present in ThreatMind CTI dataset
    "T1190",  # Exploit Public-Facing Application
    "T1485",  # Data Destruction
    "T1047",  # Windows Management Instrumentation
    "T1027",  # Obfuscated Files or Information
    "T1110",  # Brute Force
    "T1021",  # Remote Services
    "T1071",  # Application Layer Protocol
    "T1082",  # System Information Discovery
    "T1083",  # File and Directory Discovery
}

class D3fendService:
    def __init__(self, catalog_path: Path = CATALOG_PATH):
        self.catalog_path = catalog_path
        self._catalog_metadata: Dict[str, Any] = {}
        self._mappings_by_technique: Dict[str, List[DefensiveRecommendation]] = {}
        self._catalog_sha256: str = ""
        self._load_catalog()

    def _load_catalog(self) -> None:
        if not self.catalog_path.exists():
            logger.warning(f"D3FEND catalog file not found at {self.catalog_path}")
            return

        raw_bytes = self.catalog_path.read_bytes()
        self._catalog_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        if self._catalog_sha256 != EXPECTED_CATALOG_SHA256:
            logger.warning(
                f"D3FEND catalog integrity digest mismatch! Expected {EXPECTED_CATALOG_SHA256}, got {self._catalog_sha256}"
            )

        data = json.loads(raw_bytes.decode("utf-8"))
        self._catalog_metadata = data.get("metadata", {})

        raw_mappings = data.get("mappings", [])
        self._mappings_by_technique.clear()

        for item in raw_mappings:
            tech_id = item["attack_technique_id"].upper()
            countermeasure = D3fendCountermeasure(
                id=item["countermeasure"]["id"],
                name=item["countermeasure"]["name"],
                tactic=D3fendTactic(item["countermeasure"]["tactic"]),
                definition=item["countermeasure"]["definition"],
                official_url=item["countermeasure"]["official_url"],
            )

            rec = DefensiveRecommendation(
                original_framework_id=item.get("original_framework_id", f"ATT&CK:{tech_id}"),
                attack_technique_id=tech_id,
                attack_technique_name=item["attack_technique_name"],
                mitigation_id=item.get("mitigation_id"),
                mitigation_name=item.get("mitigation_name"),
                mapping_relationship=item.get("mapping_relationship", "mitigates_and_maps_to"),
                mapping_direction=item.get("mapping_direction", "offensive_to_defensive"),
                countermeasure=countermeasure,
                applicability=ApplicabilityClassification(item["applicability"]),
                mapping_provenance=item.get("mapping_provenance", "Official MITRE D3FEND Matrix"),
                source_version=item.get("source_version", self._catalog_metadata.get("catalog_version", "unknown")),
                retrieval_date=item.get("retrieval_date", self._catalog_metadata.get("snapshot_date", "unknown")),
                rationale=item["rationale"],
                environment_limitations=item["environment_limitations"],
            )

            if tech_id not in self._mappings_by_technique:
                self._mappings_by_technique[tech_id] = []
            self._mappings_by_technique[tech_id].append(rec)

        logger.info(
            f"Loaded {len(raw_mappings)} MITRE D3FEND mappings across {len(self._mappings_by_technique)} techniques. "
            f"Catalog SHA-256: {self._catalog_sha256[:12]}..."
        )

    @property
    def catalog_sha256(self) -> str:
        return self._catalog_sha256

    @property
    def catalog_metadata(self) -> Dict[str, Any]:
        return self._catalog_metadata

    def normalize_technique_id(self, raw_id: str) -> Optional[str]:
        """
        Normalizes candidate strings (e.g. 'tech_t1059_001' or 't1059.001') to canonical 'T1059.001'.
        Returns None if invalid syntax.
        """
        if not raw_id:
            return None
        cleaned = raw_id.strip()
        if cleaned.lower().startswith("tech_t"):
            cleaned = cleaned[5:]
            cleaned = cleaned.replace("_", ".")

        cleaned = cleaned.upper()
        if TECHNIQUE_ID_REGEX.match(cleaned):
            return cleaned
        return None

    def get_recommendations_for_technique(self, technique_id: str) -> List[DefensiveRecommendation]:
        """
        Retrieves defensive recommendations for a single ATT&CK technique.
        Never fabricates mappings:
        1. Validates technique against RECOGNIZED_ATTACK_TECHNIQUES.
        2. Returns direct mappings if available.
        3. Only performs parent fallback if the sub-technique is a genuine, recognized ATT&CK identifier.
        """
        normalized = self.normalize_technique_id(technique_id)
        if not normalized:
            return []

        # Step 5 safeguard: Nonexistent identifiers (e.g. T1059.999) must not inherit recommendations
        if normalized not in RECOGNIZED_ATTACK_TECHNIQUES:
            logger.debug(
                f"Technique {normalized} is not in recognized ATT&CK dataset. Abstaining from recommendation."
            )
            return []

        # Direct match in catalog
        if normalized in self._mappings_by_technique:
            return list(self._mappings_by_technique[normalized])

        # Sub-technique fallback to parent ONLY if the sub-technique is a verified ATT&CK technique
        if "." in normalized:
            parent_id = normalized.split(".")[0]
            if parent_id in RECOGNIZED_ATTACK_TECHNIQUES and parent_id in self._mappings_by_technique:
                parent_recs = self._mappings_by_technique[parent_id]
                calibrated = []
                for r in parent_recs:
                    copy_dict = r.model_dump()
                    copy_dict["attack_technique_id"] = normalized
                    copy_dict["original_framework_id"] = f"ATT&CK:{normalized}"
                    copy_dict["applicability"] = ApplicabilityClassification.REQUIRES_ENVIRONMENT_REVIEW
                    copy_dict["rationale"] = (
                        f"Inferred from parent technique {parent_id}. " + copy_dict["rationale"]
                    )
                    calibrated.append(DefensiveRecommendation(**copy_dict))
                return calibrated

        return []

    def get_recommendations(self, technique_ids: List[str]) -> DefensiveResponse:
        """
        Aggregates recommendations across multiple technique IDs with deduplication
        and structured summary statistics.
        """
        normalized_targets = []
        all_recs: List[DefensiveRecommendation] = []
        seen_keys = set()

        for raw_id in technique_ids:
            norm = self.normalize_technique_id(raw_id)
            if norm and norm in RECOGNIZED_ATTACK_TECHNIQUES:
                normalized_targets.append(norm)
                recs = self.get_recommendations_for_technique(norm)
                for rec in recs:
                    key = (rec.attack_technique_id, rec.countermeasure.id)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        all_recs.append(rec)

        summary_by_tactic: Dict[str, int] = {}
        summary_by_applicability: Dict[str, int] = {}

        for r in all_recs:
            tactic_name = r.countermeasure.tactic.value
            summary_by_tactic[tactic_name] = summary_by_tactic.get(tactic_name, 0) + 1

            app_label = r.applicability.value
            summary_by_applicability[app_label] = summary_by_applicability.get(app_label, 0) + 1

        return DefensiveResponse(
            target_techniques=sorted(list(set(normalized_targets))),
            recommendations=all_recs,
            summary_by_tactic=summary_by_tactic,
            summary_by_applicability=summary_by_applicability,
            catalog_version=self._catalog_metadata.get("catalog_version", "unknown"),
            snapshot_date=self._catalog_metadata.get("snapshot_date", "unknown"),
            catalog_sha256=self._catalog_sha256,
        )

d3fend_service = D3fendService()
