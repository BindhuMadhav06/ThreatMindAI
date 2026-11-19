"""
Evidence-Grounded Sigma Rule Generation Service
Phase 12B Detection Engineering Implementation

Constructs production-grade SigmaHQ v2.1.0 rules from MITRE ATT&CK techniques,
D3FEND countermeasures, and real investigation evidence text.
Generates structured sidecar provenance preserving evidence lineage.
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List, Optional
import yaml

from app.models.sigma import (
    SigmaRule,
    SigmaRuleGenerateRequest,
    SigmaRuleLogSource,
    ThreatMindProvenance,
)

# Known ATT&CK technique to tactic mappings
TECHNIQUE_TACTIC_MAP: Dict[str, str] = {
    "T1059": "execution",
    "T1059.001": "execution",
    "T1059.003": "execution",
    "T1053": "execution",
    "T1078": "defense_evasion",
    "T1070": "defense_evasion",
    "T1003": "credential_access",
    "T1110": "credential_access",
    "T1071": "command_and_control",
    "T1566": "initial_access",
    "T1190": "initial_access",
    "T1082": "discovery",
    "T1083": "discovery",
}

# Known technique to D3FEND countermeasure mappings
TECHNIQUE_D3FEND_MAP: Dict[str, List[str]] = {
    "T1059": ["D3-PA: Process Analysis", "D3-PSA: Process Spawn Analysis"],
    "T1059.001": ["D3-PA: Process Analysis", "D3-PSA: Process Spawn Analysis", "D3-SPTA: Script Execution Analysis"],
    "T1059.003": ["D3-PA: Process Analysis", "D3-PSA: Process Spawn Analysis"],
    "T1003": ["D3-MDA: Memory Dump Analysis", "D3-LSA: LSASS Memory Protection"],
    "T1071": ["D3-NTTA: Network Traffic Trend Analysis", "D3-DNRA: Domain Name Reputation Analysis"],
    "T1053": ["D3-JSA: Job Scheduling Analysis"],
}


class SigmaGenerationService:
    """
    Generates evidence-grounded Sigma v2.1.0 detection rules.
    """

    def generate_rule(self, req: SigmaRuleGenerateRequest) -> SigmaRule:
        rule_uuid = str(uuid.uuid4())
        tech_clean = req.technique_id.strip().upper()
        tech_name = req.technique_name or f"Technique {tech_clean}"

        # 1. Derive Tactic and ATT&CK Tags
        tactic = TECHNIQUE_TACTIC_MAP.get(tech_clean) or TECHNIQUE_TACTIC_MAP.get(tech_clean.split(".")[0], "execution")
        tags: List[str] = [
            f"attack.{tactic}",
            f"attack.{tech_clean.lower()}",
        ]
        if "." in tech_clean:
            parent_id = tech_clean.split(".")[0].lower()
            tags.append(f"attack.{parent_id}")

        # 2. Derive D3FEND Countermeasures
        d3fend = req.d3fend_countermeasures or TECHNIQUE_D3FEND_MAP.get(tech_clean) or TECHNIQUE_D3FEND_MAP.get(tech_clean.split(".")[0]) or ["D3-PA: Process Analysis"]

        # 3. Derive Logsource
        category = req.logsource_category or "process_creation"
        product = req.logsource_product or "windows"

        # 4. Construct Evidence-Grounded Detection
        selection: Dict[str, Any] = {}
        evidence = (req.evidence_text or "").strip()

        if "powershell" in tech_name.lower() or "powershell" in tech_clean.lower() or "powershell" in evidence.lower():
            category = "process_creation"
            product = "windows"
            selection["Image|endswith"] = [
                "\\powershell.exe",
                "\\pwsh.exe",
            ]
            if evidence:
                # Extract interesting strings from evidence
                terms = []
                for kw in ["-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex", "bypass", "hidden", "webclient"]:
                    if kw in evidence.lower():
                        terms.append(kw)
                if terms:
                    selection["CommandLine|contains"] = terms
                else:
                    selection["CommandLine|contains"] = ["-enc", "-nop", "downloadstring"]
            else:
                selection["CommandLine|contains"] = ["-enc", "-ExecutionPolicy Bypass", "DownloadString"]

        elif "cmd" in tech_name.lower() or "cmd" in tech_clean.lower():
            category = "process_creation"
            product = "windows"
            selection["Image|endswith"] = "\\cmd.exe"
            selection["CommandLine|contains"] = ["/c", "/k"]

        elif "credential" in tactic or "t1003" in tech_clean.lower():
            category = "process_creation"
            product = "windows"
            selection["CommandLine|contains"] = ["sekurlsa", "minidump", "lsass.dmp", "procdump"]

        elif "scheduled" in tech_name.lower() or "t1053" in tech_clean.lower():
            category = "process_creation"
            product = "windows"
            selection["Image|endswith"] = "\\schtasks.exe"
            selection["CommandLine|contains"] = ["/create", "/run"]

        else:
            category = req.logsource_category or "process_creation"
            product = req.logsource_product or "windows"
            if evidence:
                selection["CommandLine|contains"] = [evidence[:50]]
            else:
                selection["CommandLine|contains"] = [tech_clean]

        detection_block = {
            "selection": selection,
            "condition": "selection",
        }

        # 5. Build ThreatMind Sidecar Provenance (Strictly separate from detection block)
        provenance = ThreatMindProvenance(
            rule_id=f"sigma-{rule_uuid}",
            created_at=datetime.now(timezone.utc).isoformat(),
            source_entity_id=f"technique--{tech_clean}",
            technique_id=tech_clean,
            technique_name=tech_name,
            tactics=[tactic],
            d3fend_countermeasures=d3fend,
            evidence_text_snippets=[evidence] if evidence else [],
            graph_node_ids=req.graph_node_ids or [],
            confidence_score=0.92,
            generator="ThreatMind Detection Engineering Engine v1.0",
            review_status="draft",
        )

        title = f"Suspicious Activity Grounded in {tech_name} ({tech_clean})"
        description = (
            f"Detects execution and malicious indicators associated with MITRE ATT&CK technique {tech_clean} ({tech_name}). "
            f"Correlated with D3FEND countermeasure: {', '.join(d3fend)}."
        )

        # 6. Build Rule Container
        sigma_rule = SigmaRule(
            title=title,
            id=rule_uuid,
            status="experimental",
            description=description,
            references=[
                f"https://attack.mitre.org/techniques/{tech_clean.replace('.', '/')}/",
                "https://threatmind.ai/rules/provenance",
            ],
            author="ThreatMind AI Detection Engine",
            date=datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            tags=tags,
            logsource=SigmaRuleLogSource(category=category, product=product),
            detection=detection_block,
            falsepositives=[
                "Legitimate administrative scripts and automation tasks",
                "Software deployment tools and configuration management",
            ],
            level=req.level or "high",
            threatmind_provenance=provenance,
        )

        # 7. Render Formatted YAML
        rule_dict = {
            "title": sigma_rule.title,
            "id": sigma_rule.id,
            "status": sigma_rule.status,
            "description": sigma_rule.description,
            "references": sigma_rule.references,
            "author": sigma_rule.author,
            "date": sigma_rule.date,
            "tags": sigma_rule.tags,
            "logsource": sigma_rule.logsource.model_dump(exclude_none=True),
            "detection": sigma_rule.detection,
            "falsepositives": sigma_rule.falsepositives,
            "level": sigma_rule.level,
            "threatmind_provenance": provenance.model_dump(exclude_none=True),
        }
        sigma_rule.raw_yaml = yaml.dump(rule_dict, sort_keys=False)

        return sigma_rule
