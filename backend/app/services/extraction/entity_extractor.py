import json
import re
from typing import List, Dict, Any, Optional
from app.services.ingestion.models import TextChunk, ExtractedEntity
from app.services.graph.schema_manager import PRIMARY_NODE_LABELS
from app.services.llm.llm_factory import get_llm_provider
from app.core.logging import logger

ENTITY_EXTRACTION_SYSTEM_PROMPT = """
You are an expert Cyber Threat Intelligence (CTI) entity extraction engine.
Your job is to identify cybersecurity entities from the provided CTI text.

You MUST ONLY extract entities belonging to these allowed primary labels:
- ThreatActor
- Malware
- Tool
- Vulnerability
- Technique
- Tactic
- Campaign
- Software
- OperatingSystem
- Product
- Organization
- Indicator

Guidelines:
1. 'ThreatActor': State-sponsored groups or threat actors (e.g., APT29, Cozy Bear).
2. 'Malware': Malicious software, C2, trojans (e.g., Cobalt Strike, Beacon).
3. 'Tool': Dual-use utilities (e.g., Mimikatz, PowerShell, PsExec).
4. 'Vulnerability': Security flaws with CVE IDs (e.g., CVE-2021-44228).
5. 'Technique': MITRE ATT&CK techniques (e.g., PowerShell, T1059.001).
6. 'Tactic': MITRE ATT&CK tactics (e.g., Execution, TA0002).
7. 'Product': Software applications or libraries (e.g., Apache Log4j).
8. 'OperatingSystem': Target OS platforms (e.g., Windows 10, Linux).
9. 'Organization': Target enterprise or government sectors (e.g., Government Sector).

Output JSON Format:
{
  "entities": [
    {
      "label": "ThreatActor",
      "name": "APT29",
      "aliases": ["Cozy Bear", "The Dukes"],
      "description": "Russian cyber espionage group"
    }
  ]
}
"""

class EntityExtractor:
    def __init__(self, llm_provider=None):
        self.llm = llm_provider or get_llm_provider()

    @staticmethod
    def generate_entity_id(label: str, name: str) -> str:
        """
        Generates a canonical ID for an entity based on its label and normalized name.
        """
        clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name.lower().strip())
        clean_name = re.sub(r'_+', '_', clean_name).strip('_')
        
        # Handle special ID patterns
        if label.lower() == "vulnerability" and "cve" in clean_name:
            return f"vuln_{clean_name}"
        if label.lower() == "technique" and re.match(r't\d{4}', clean_name):
            return f"tech_{clean_name}"

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
            "indicator": "ioc",
            "source": "source"
        }
        prefix = prefix_map.get(label.lower(), label.lower())
        return f"{prefix}_{clean_name}"

    def extract_entities_from_chunk(self, chunk: TextChunk) -> List[ExtractedEntity]:
        prompt = f"Extract CTI entities from the following text chunk:\n\n{chunk.text}"
        
        schema = {
            "type": "object",
            "properties": {
                "entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string"},
                            "name": {"type": "string"},
                            "aliases": {"type": "array", "items": {"type": "string"}},
                            "description": {"type": "string"}
                        },
                        "required": ["label", "name"]
                    }
                }
            },
            "required": ["entities"]
        }

        try:
            res_json = self.llm.generate_structured_output(
                prompt=prompt,
                schema=schema,
                system_instruction=ENTITY_EXTRACTION_SYSTEM_PROMPT
            )
            
            raw_entities = res_json.get("entities", [])
            extracted = []
            allowed_labels_lower = {l.lower(): l for l in PRIMARY_NODE_LABELS}

            for item in raw_entities:
                label_raw = item.get("label", "").strip()
                name_raw = item.get("name", "").strip()
                if not label_raw or not name_raw:
                    continue

                if label_raw.lower() not in allowed_labels_lower:
                    logger.warning(f"Ignoring entity with disallowed label '{label_raw}'")
                    continue

                canonical_label = allowed_labels_lower[label_raw.lower()]
                entity_id = self.generate_entity_id(canonical_label, name_raw)
                
                extracted.append(ExtractedEntity(
                    id=entity_id,
                    label=canonical_label,
                    name=name_raw,
                    aliases=item.get("aliases") or [],
                    description=item.get("description"),
                    properties={"extracted_from_chunk": chunk.chunk_id}
                ))

            return extracted
        except Exception as e:
            logger.error(f"Error during entity extraction on chunk {chunk.chunk_id}: {e}")
            return []
