import re
from typing import Dict, Any, List
from app.services.ingestion.models import ExtractedEntity, ExtractedRelationship

# Known Threat Actor Alias Mapping (Deterministic)
KNOWN_THREAT_ACTOR_ALIASES = {
    "cozy bear": "APT29",
    "the dukes": "APT29",
    "nobelium": "APT29",
    "midnight blizzard": "APT29",
    "fancy bear": "APT28",
    "apt 28": "APT28",
    "strontium": "APT28",
    "lazarus group": "Lazarus Group",
    "hidden cobra": "Lazarus Group"
}

# Known Malware / Tool Aliases
KNOWN_SOFTWARE_ALIASES = {
    "cobalt strike beacon": "Cobalt Strike",
    "cs beacon": "Cobalt Strike",
    "beacon": "Cobalt Strike"
}

class EntityNormalizer:
    """
    Deterministic CTI entity and identifier normalizer.
    Normalizes casing, CVE formats, MITRE ATT&CK IDs, and canonical aliases.
    """

    @classmethod
    def normalize_cve_id(cls, text: str) -> str:
        """
        Formats CVE identifiers to standard uppercase format (e.g., CVE-2021-44228).
        """
        match = re.search(r'cve[-_]?(\d{4})[-_]?(\d{4,7})', text, re.IGNORECASE)
        if match:
            return f"CVE-{match.group(1)}-{match.group(2)}"
        return text.strip()

    @classmethod
    def normalize_mitre_technique_id(cls, text: str) -> str:
        """
        Formats MITRE ATT&CK technique IDs to standard uppercase (e.g., T1059.001).
        """
        match = re.search(r't(\d{4})(?:\.(\d{3}))?', text, re.IGNORECASE)
        if match:
            tech_num = match.group(1)
            sub_num = match.group(2)
            return f"T{tech_num}.{sub_num}" if sub_num else f"T{tech_num}"
        return text.strip()

    @classmethod
    def normalize_name_and_label(cls, name: str, label: str) -> tuple[str, str]:
        """
        Returns (canonical_name, canonical_id_suffix).
        """
        clean_name = name.strip().strip('"\'')
        name_lower = clean_name.lower()

        # 1. Threat Actor Aliases
        if label.lower() == "threatactor" and name_lower in KNOWN_THREAT_ACTOR_ALIASES:
            canonical_name = KNOWN_THREAT_ACTOR_ALIASES[name_lower]
            return canonical_name, canonical_name

        # 2. Software Aliases
        if label.lower() in ["malware", "tool"] and name_lower in KNOWN_SOFTWARE_ALIASES:
            canonical_name = KNOWN_SOFTWARE_ALIASES[name_lower]
            return canonical_name, canonical_name

        # 3. CVE Vulnerabilities
        if label.lower() == "vulnerability" or "cve" in name_lower:
            norm_cve = cls.normalize_cve_id(clean_name)
            return norm_cve, norm_cve

        # 4. MITRE Techniques
        if label.lower() == "technique" or re.search(r'\bt\d{4}\b', name_lower):
            norm_tech = cls.normalize_mitre_technique_id(clean_name)
            return norm_tech, norm_tech

        return clean_name, clean_name

    @classmethod
    def normalize_entity(cls, entity: ExtractedEntity) -> ExtractedEntity:
        canonical_name, suffix = cls.normalize_name_and_label(entity.name, entity.label)
        
        # Recalculate ID based on canonical name
        clean_suffix = re.sub(r'[^a-zA-Z0-9_]', '_', suffix.lower())
        clean_suffix = re.sub(r'_+', '_', clean_suffix).strip('_')
        
        prefix_map = {
            "threatactor": "actor",
            "malware": "malware",
            "tool": "tool",
            "vulnerability": "vuln",
            "technique": "tech",
            "tactic": "tactic",
            "campaign": "camp",
            "software": "sw",
            "operatingsystem": "os",
            "product": "prod",
            "organization": "org",
            "indicator": "ioc"
        }
        prefix = prefix_map.get(entity.label.lower(), entity.label.lower())
        new_id = f"{prefix}_{clean_suffix}"

        return ExtractedEntity(
            id=new_id,
            label=entity.label,
            name=canonical_name,
            aliases=entity.aliases,
            description=entity.description,
            properties=entity.properties
        )

    @classmethod
    def normalize_relationship(cls, rel: ExtractedRelationship) -> ExtractedRelationship:
        norm_src_name, _ = cls.normalize_name_and_label(rel.source_name, rel.source_label)
        norm_tgt_name, _ = cls.normalize_name_and_label(rel.target_name, rel.target_label)

        return ExtractedRelationship(
            source_name=norm_src_name,
            source_label=rel.source_label,
            rel_type=rel.rel_type,
            target_name=norm_tgt_name,
            target_label=rel.target_label,
            evidence_text=rel.evidence_text,
            confidence=rel.confidence
        )
