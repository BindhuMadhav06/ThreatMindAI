import json
from typing import List, Dict, Any, Optional
from app.services.ingestion.models import TextChunk, ExtractedRelationship
from app.services.graph.schema_manager import SUPPORTED_RELATIONSHIPS, PRIMARY_NODE_LABELS
from app.services.llm.llm_factory import get_llm_provider
from app.core.logging import logger

RELATION_EXTRACTION_SYSTEM_PROMPT = """
You are an expert Cyber Threat Intelligence (CTI) relationship extraction engine.
Your objective is to extract evidence-backed relationships between cybersecurity entities in the text chunk.

MANDATORY RULES:
1. Every relationship MUST include the EXACT supporting text quote ('evidence_text') verbatim from the chunk.
2. DO NOT invent or infer relationships that are not explicitly stated in the chunk text.
3. Only use these whitelisted relationship types:
   - USES (e.g. ThreatActor USES Malware, ThreatActor USES Tool)
   - USES_TECHNIQUE (e.g. ThreatActor USES_TECHNIQUE Technique, Malware USES_TECHNIQUE Technique)
   - EXPLOITS (e.g. ThreatActor EXPLOITS Vulnerability)
   - TARGETS (e.g. ThreatActor TARGETS Organization, Malware TARGETS Product)
   - CONDUCTS (e.g. ThreatActor CONDUCTS Campaign)
   - PART_OF (e.g. Technique PART_OF Tactic)
   - AFFECTS (e.g. Vulnerability AFFECTS Product, Vulnerability AFFECTS OperatingSystem)
   - ASSOCIATED_WITH (e.g. Indicator ASSOCIATED_WITH ThreatActor)

Output JSON Format:
{
  "relationships": [
    {
      "source_name": "APT29",
      "source_label": "ThreatActor",
      "rel_type": "USES",
      "target_name": "Cobalt Strike",
      "target_label": "Malware",
      "evidence_text": "APT29 deployed Cobalt Strike Beacon payloads during lateral movement.",
      "confidence": null
    }
  ]
}
"""

class RelationExtractor:
    def __init__(self, llm_provider=None):
        self.llm = llm_provider or get_llm_provider()

    def extract_relationships_from_chunk(
        self,
        chunk: TextChunk,
        known_entities: Optional[List[Dict[str, Any]]] = None
    ) -> List[ExtractedRelationship]:
        prompt = f"Extract CTI relationships with exact supporting evidence quotes from this text:\n\n{chunk.text}"
        if known_entities:
            entity_str = ", ".join([f"{e['name']} ({e['label']})" for e in known_entities])
            prompt += f"\n\nContext Entities identified in this document: {entity_str}"

        schema = {
            "type": "object",
            "properties": {
                "relationships": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source_name": {"type": "string"},
                            "source_label": {"type": "string"},
                            "rel_type": {"type": "string"},
                            "target_name": {"type": "string"},
                            "target_label": {"type": "string"},
                            "evidence_text": {"type": "string"},
                            "confidence": {"type": ["number", "null"]}
                        },
                        "required": ["source_name", "source_label", "rel_type", "target_name", "target_label", "evidence_text"]
                    }
                }
            },
            "required": ["relationships"]
        }

        try:
            res_json = self.llm.generate_structured_output(
                prompt=prompt,
                schema=schema,
                system_instruction=RELATION_EXTRACTION_SYSTEM_PROMPT
            )

            raw_rels = res_json.get("relationships", [])
            extracted = []

            allowed_rels_lower = {r.lower(): r for r in SUPPORTED_RELATIONSHIPS}
            allowed_labels_lower = {l.lower(): l for l in PRIMARY_NODE_LABELS}

            for r in raw_rels:
                src_name = r.get("source_name", "").strip()
                src_label = r.get("source_label", "").strip()
                rel_type_raw = r.get("rel_type", "").strip()
                tgt_name = r.get("target_name", "").strip()
                tgt_label = r.get("target_label", "").strip()
                evidence = r.get("evidence_text", "").strip()

                if not src_name or not tgt_name or not evidence:
                    logger.warning("Skipping relationship with missing source_name, target_name, or evidence_text.")
                    continue

                if rel_type_raw.lower() not in allowed_rels_lower:
                    logger.warning(f"Rejecting relationship with disallowed rel_type '{rel_type_raw}'")
                    continue

                if src_label.lower() not in allowed_labels_lower or tgt_label.lower() not in allowed_labels_lower:
                    logger.warning(f"Rejecting relationship with invalid entity labels: {src_label} -> {tgt_label}")
                    continue

                extracted.append(ExtractedRelationship(
                    source_name=src_name,
                    source_label=allowed_labels_lower[src_label.lower()],
                    rel_type=allowed_rels_lower[rel_type_raw.lower()],
                    target_name=tgt_name,
                    target_label=allowed_labels_lower[tgt_label.lower()],
                    evidence_text=evidence,
                    confidence=r.get("confidence")
                ))

            return extracted
        except Exception as e:
            logger.error(f"Error extracting relationships from chunk {chunk.chunk_id}: {e}")
            return []
