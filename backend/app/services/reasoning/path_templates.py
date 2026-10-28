import re
from typing import Dict, List, Optional, Any
from app.services.graph.schema_manager import SUPPORTED_RELATIONSHIPS

class PathTemplate:
    def __init__(
        self,
        template_id: str,
        name: str,
        description: str,
        rel_sequence: List[List[str]],
        label_sequence: List[List[str]],
        default_caveats: List[str]
    ):
        self.template_id = template_id
        self.name = name
        self.description = description
        self.rel_sequence = rel_sequence
        self.label_sequence = label_sequence
        self.default_caveats = default_caveats

    def matches_sequence(self, steps_rels: List[str], nodes_labels: List[str]) -> bool:
        if len(steps_rels) != len(self.rel_sequence):
            return False
        for i, allowed_rels in enumerate(self.rel_sequence):
            if steps_rels[i].upper() not in allowed_rels:
                return False
        for i, allowed_labels in enumerate(self.label_sequence):
            if i < len(nodes_labels) and nodes_labels[i] not in allowed_labels:
                return False
        return True

# 1. Actor Attack Pattern: ThreatActor -> USES -> Malware|Tool -> USES_TECHNIQUE -> Technique
ACTOR_ATTACK_PATTERN = PathTemplate(
    template_id="actor_attack_pattern",
    name="Threat Actor Attack Pattern",
    description="Maps a threat actor through utilized software/malware to executed MITRE ATT&CK techniques.",
    rel_sequence=[["USES"], ["USES_TECHNIQUE"]],
    label_sequence=[["ThreatActor"], ["Malware", "Tool"], ["Technique"]],
    default_caveats=[
        "Graph association documents software capability/usage; it does not prove specific attack campaign attribution without dedicated campaign evidence.",
        "Documented technique usage does not guarantee success against all defended environments.",
        "No chronological sequence of execution is implied solely by graph node connectivity."
    ]
)

# 2. Actor Vulnerability Exploitation: ThreatActor -> EXPLOITS -> Vulnerability -> AFFECTS -> Product|OperatingSystem
ACTOR_VULNERABILITY_EXPLOITATION = PathTemplate(
    template_id="actor_vulnerability_exploitation",
    name="Threat Actor Vulnerability Exploitation",
    description="Traces a threat actor exploiting a CVE vulnerability affecting target products or operating systems.",
    rel_sequence=[["EXPLOITS"], ["AFFECTS"]],
    label_sequence=[["ThreatActor"], ["Vulnerability"], ["Product", "OperatingSystem"]],
    default_caveats=[
        "Graph facts document exploitation capability; they do not establish that all affected products were compromised in a single incident.",
        "Compromise is contingent on vulnerability unpatched status and network reachability."
    ]
)

# 3. Actor Targeting: ThreatActor -> TARGETS -> Organization
ACTOR_TARGETING = PathTemplate(
    template_id="actor_targeting",
    name="Threat Actor Sector Targeting",
    description="Connects a threat actor directly to targeted organizations or industry sectors.",
    rel_sequence=[["TARGETS"]],
    label_sequence=[["ThreatActor"], ["Organization"]],
    default_caveats=[
        "Historical targeting indicates adversary interest, not exhaustive or current victimology."
    ]
)

# 4. Malware Capabilities: Malware|Tool -> USES_TECHNIQUE -> Technique -> PART_OF -> Tactic
MALWARE_CAPABILITIES = PathTemplate(
    template_id="malware_capabilities",
    name="Malware Technique Capabilities",
    description="Maps malware or tool post-exploitation techniques to MITRE ATT&CK tactics.",
    rel_sequence=[["USES_TECHNIQUE"], ["PART_OF"]],
    label_sequence=[["Malware", "Tool"], ["Technique"], ["Tactic"]],
    default_caveats=[
        "Technique capability indicates potential execution vectors supported by the malware binary/script."
    ]
)

# 5. Vulnerability Impact: Vulnerability -> AFFECTS -> Product|OperatingSystem
VULNERABILITY_IMPACT = PathTemplate(
    template_id="vulnerability_impact",
    name="Vulnerability Product Impact",
    description="Maps a CVE vulnerability to affected software products or host operating systems.",
    rel_sequence=[["AFFECTS"]],
    label_sequence=[["Vulnerability"], ["Product", "OperatingSystem"]],
    default_caveats=[
        "Vulnerability impact is version-specific and subject to vendor patching advisories."
    ]
)

PATH_TEMPLATES: Dict[str, PathTemplate] = {
    "actor_attack_pattern": ACTOR_ATTACK_PATTERN,
    "actor_vulnerability_exploitation": ACTOR_VULNERABILITY_EXPLOITATION,
    "actor_targeting": ACTOR_TARGETING,
    "malware_capabilities": MALWARE_CAPABILITIES,
    "vulnerability_impact": VULNERABILITY_IMPACT
}

def detect_template_for_query(question: str) -> Optional[str]:
    """
    Heuristically matches analyst question intent to a known path template.
    """
    q_lower = question.lower()
    
    if any(k in q_lower for k in ["affect", "affected", "product", "software affected"]):
        return "vulnerability_impact"
    elif any(k in q_lower for k in ["attack", "how does", "operate", "behavior", "kill chain"]):
        return "actor_attack_pattern"
    elif any(k in q_lower for k in ["exploit", "exploited", "cve", "vulnerability"]):
        return "actor_vulnerability_exploitation"
    elif any(k in q_lower for k in ["target", "victim", "sector", "industry"]):
        return "actor_targeting"
    elif any(k in q_lower for k in ["malware", "technique", "capability", "tactic"]):
        return "malware_capabilities"
    elif any(k in q_lower for k in ["affect", "product", "software affected"]):
        return "vulnerability_impact"
    
    return None
