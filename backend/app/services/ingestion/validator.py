import re
from typing import List, Dict, Any
from app.services.ingestion.models import ParsedDocument, ExtractedRelationship, ValidationResult
from app.services.graph.schema_manager import PRIMARY_NODE_LABELS, SUPPORTED_RELATIONSHIPS
from app.core.logging import logger

class EvidenceValidator:
    """
    Evidence and Schema Validation Layer for ThreatMind CTI Ingestion.
    
    ENFORCES MANDATORY RULE:
    If a relationship cannot be verified against supporting source evidence in the document,
    it MUST BE REJECTED and excluded from Neo4j graph insertion.
    """

    @staticmethod
    def _normalize_for_match(text: str) -> str:
        """
        Normalizes text for substring search by removing extra whitespace and punctuation.
        """
        cleaned = re.sub(r'[^\w\s]', '', text.lower())
        return re.sub(r'\s+', ' ', cleaned).strip()

    @classmethod
    def validate_relationships(
        cls,
        doc: ParsedDocument,
        relationships: List[ExtractedRelationship]
    ) -> ValidationResult:
        result = ValidationResult()
        doc_normalized = cls._normalize_for_match(doc.raw_text)

        allowed_labels_lower = {l.lower() for l in PRIMARY_NODE_LABELS}
        allowed_rels_lower = {r.lower() for r in SUPPORTED_RELATIONSHIPS}

        for rel in relationships:
            # 1. Source Evidence Check
            if not rel.evidence_text or not rel.evidence_text.strip():
                rejection = {
                    "relationship": f"({rel.source_name})-[{rel.rel_type}]->({rel.target_name})",
                    "reason": "REJECTED: Mandatory evidence_text is empty or missing."
                }
                result.rejected_relationships.append(rejection)
                logger.warning(rejection["reason"])
                continue

            # 2. Text Grounding Verification (Evidence text must exist in document)
            evidence_norm = cls._normalize_for_match(rel.evidence_text)
            
            # Allow partial fuzzy/substring match (at least 60% of words or 15 char sequence matched)
            matched = False
            if evidence_norm in doc_normalized:
                matched = True
            else:
                # Check for word snippet match if LLM slightly paraphrased whitespace
                words = [w for w in evidence_norm.split() if len(w) > 3]
                if len(words) >= 3:
                    matched_count = sum(1 for w in words if w in doc_normalized)
                    if matched_count / len(words) >= 0.7:
                        matched = True

            if not matched:
                rejection = {
                    "relationship": f"({rel.source_name})-[{rel.rel_type}]->({rel.target_name})",
                    "reason": f"REJECTED: Evidence text '{rel.evidence_text[:60]}...' was not found in source document text.",
                    "evidence_text": rel.evidence_text
                }
                result.rejected_relationships.append(rejection)
                logger.warning(rejection["reason"])
                continue

            # 3. Label Whitelist Verification
            if rel.source_label.lower() not in allowed_labels_lower or rel.target_label.lower() not in allowed_labels_lower:
                rejection = {
                    "relationship": f"({rel.source_name}: {rel.source_label})-[{rel.rel_type}]->({rel.target_name}: {rel.target_label})",
                    "reason": f"REJECTED: Disallowed entity labels. Allowed: {PRIMARY_NODE_LABELS}"
                }
                result.rejected_relationships.append(rejection)
                logger.warning(rejection["reason"])
                continue

            # 4. Relationship Type Whitelist Verification
            if rel.rel_type.lower() not in allowed_rels_lower:
                rejection = {
                    "relationship": f"({rel.source_name})-[{rel.rel_type}]->({rel.target_name})",
                    "reason": f"REJECTED: Disallowed relationship type '{rel.rel_type}'. Allowed: {SUPPORTED_RELATIONSHIPS}"
                }
                result.rejected_relationships.append(rejection)
                logger.warning(rejection["reason"])
                continue

            # Accepted relationship
            result.accepted_relationships.append(rel)

        logger.info(f"Validation finished: {len(result.accepted_relationships)} accepted, {len(result.rejected_relationships)} rejected.")
        return result
