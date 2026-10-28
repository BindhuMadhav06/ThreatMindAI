import re
from typing import List, Tuple, Dict, Any, Optional
from app.services.graph.connection import neo4j_conn
from app.services.normalization.normalizer import (
    EntityNormalizer,
    KNOWN_THREAT_ACTOR_ALIASES,
    KNOWN_SOFTWARE_ALIASES
)
from app.models.query import ResolvedEntity, UnresolvedEntity
from app.core.logging import logger

class QueryEntityResolver:
    """
    Deterministic Cybersecurity Entity Resolver.
    Extracts candidate entity phrases, CVE IDs, and MITRE ATT&CK codes from
    the analyst's query and resolves them against authoritative Neo4j graph nodes.
    """

    def __init__(self, conn=neo4j_conn):
        self.conn = conn

    def extract_candidate_tokens(self, question: str, entity_hints: Optional[List[str]] = None) -> List[str]:
        candidates = []
        
        # 1. Add analyst hints first
        if entity_hints:
            for hint in entity_hints:
                if hint and hint.strip():
                    candidates.append(hint.strip())

        # 2. Extract CVE IDs
        cve_matches = re.findall(r'cve[-_]?\d{4}[-_]?\d{4,7}', question, re.IGNORECASE)
        for cve in cve_matches:
            candidates.append(EntityNormalizer.normalize_cve_id(cve))

        # 3. Extract MITRE ATT&CK Technique & Tactic IDs
        mitre_matches = re.findall(r'\b[tT]\d{4}(?:\.\d{3})?\b|\b[tT][aA]\d{4}\b', question)
        for m in mitre_matches:
            candidates.append(m.upper())

        # 4. Check known threat actor & software alias dictionaries
        q_lower = question.lower()
        for alias, canonical in KNOWN_THREAT_ACTOR_ALIASES.items():
            if re.search(rf'\b{re.escape(alias)}\b', q_lower):
                candidates.append(canonical)

        for alias, canonical in KNOWN_SOFTWARE_ALIASES.items():
            if re.search(rf'\b{re.escape(alias)}\b', q_lower):
                candidates.append(canonical)

        # 5. Extract capitalized n-grams / potential proper nouns (e.g. "APT29", "Cobalt Strike", "Log4j")
        # Matches patterns like "APT29", "Cobalt Strike", "Apache Log4j", "Mimikatz"
        leading_question_words = {
            "how", "what", "which", "why", "when", "where", "who",
            "is", "are", "was", "were", "does", "did", "do",
            "can", "could", "would", "should", "has", "have", "had",
            "the", "a", "an"
        }
        proper_nouns = re.findall(r'\b[A-Z][a-zA-Z0-9]*(?:\s+[A-Z][a-zA-Z0-9]*)*\b', question)
        has_specific_cve = any(c.upper().startswith("CVE-") for c in candidates)

        for pn in proper_nouns:
            words = pn.split()
            # If the candidate phrase starts with a leading question word or stopword, strip it
            if words and words[0].lower() in leading_question_words:
                remainder = " ".join(words[1:]).strip()
                if remainder and remainder.lower() not in leading_question_words:
                    candidates.append(remainder)
            elif pn.lower() not in leading_question_words:
                # Omit bare 'CVE' token if a specific CVE ID was already captured
                if pn.upper() == "CVE" and has_specific_cve:
                    continue
                candidates.append(pn)

        # Remove duplicate candidate strings preserving order
        seen = set()
        unique_candidates = []
        for c in candidates:
            c_clean = c.strip()
            if c_clean and c_clean.lower() not in seen:
                seen.add(c_clean.lower())
                unique_candidates.append(c_clean)

        return unique_candidates

    def resolve_entity_in_graph(self, candidate: str) -> Tuple[Optional[ResolvedEntity], Optional[str]]:
        """
        Queries Neo4j using parameterized Cypher to find an exact or alias match.
        Returns (ResolvedEntity, error_reason_if_any).
        """
        # A. Check for CVE ID match
        if candidate.upper().startswith("CVE-"):
            norm_cve = EntityNormalizer.normalize_cve_id(candidate)
            cypher = """
            MATCH (n:Vulnerability)
            WHERE n.name = $name OR n.id = $id OR toLower(n.name) = toLower($name)
            RETURN n.id AS id, labels(n)[0] AS label, n.name AS name
            """
            res = self.conn.query(cypher, {"name": norm_cve, "id": f"vuln_{norm_cve.lower().replace('-', '_')}"})
            if res:
                return ResolvedEntity(
                    id=res[0]["id"],
                    label=res[0]["label"],
                    name=res[0]["name"],
                    match_method="cve_identifier",
                    confidence_score=1.0
                ), None

        # B. Check for MITRE ATT&CK ID match
        if re.match(r'^[tT]\d{4}(?:\.\d{3})?$', candidate) or re.match(r'^[tT][aA]\d{4}$', candidate):
            norm_mitre = candidate.upper()
            cypher = """
            MATCH (n)
            WHERE (n:Technique OR n:Tactic) AND (n.external_id = $ext_id OR n.name = $ext_id OR n.id = $id)
            RETURN n.id AS id, labels(n)[0] AS label, n.name AS name
            """
            res = self.conn.query(cypher, {"ext_id": norm_mitre, "id": f"tech_{norm_mitre.lower().replace('.', '_')}"})
            if res:
                return ResolvedEntity(
                    id=res[0]["id"],
                    label=res[0]["label"],
                    name=res[0]["name"],
                    match_method="mitre_identifier",
                    confidence_score=1.0
                ), None

        # C. Check exact canonical name match across all primary entity labels
        cypher_exact = """
        MATCH (n)
        WHERE NOT n:Source AND (toLower(n.name) = toLower($candidate) OR toLower(n.id) = toLower($candidate))
        RETURN n.id AS id, labels(n)[0] AS label, n.name AS name
        """
        res_exact = self.conn.query(cypher_exact, {"candidate": candidate})
        if res_exact:
            unique_names = {r["name"].lower() for r in res_exact}
            unique_labels = {r["label"] for r in res_exact}
            if len(unique_names) == 1 and len(unique_labels) == 1:
                return ResolvedEntity(
                    id=res_exact[0]["id"],
                    label=res_exact[0]["label"],
                    name=res_exact[0]["name"],
                    match_method="canonical_name",
                    confidence_score=1.0
                ), None
            elif len(unique_labels) > 1 or len(unique_names) > 1:
                logger.warning(f"Ambiguous matches for candidate '{candidate}': {res_exact}")
                return None, f"ambiguous_multiple_matches ({len(res_exact)} conflicting nodes matched)"

        # D. Check graph node aliases property
        cypher_alias = """
        MATCH (n)
        WHERE NOT n:Source AND n.aliases IS NOT NULL AND any(alias IN n.aliases WHERE toLower(alias) = toLower($candidate))
        RETURN n.id AS id, labels(n)[0] AS label, n.name AS name
        """
        res_alias = self.conn.query(cypher_alias, {"candidate": candidate})
        if res_alias:
            unique_names = {r["name"].lower() for r in res_alias}
            unique_labels = {r["label"] for r in res_alias}
            if len(unique_names) == 1 and len(unique_labels) == 1:
                return ResolvedEntity(
                    id=res_alias[0]["id"],
                    label=res_alias[0]["label"],
                    name=res_alias[0]["name"],
                    match_method="graph_alias",
                    confidence_score=0.95
                ), None
            elif len(unique_labels) > 1 or len(unique_names) > 1:
                logger.warning(f"Ambiguous alias matches for '{candidate}': {res_alias}")
                return None, f"ambiguous_multiple_matches ({len(res_alias)} conflicting aliases matched)"

        # Not resolved in graph
        return None, "not_found_in_graph"

    def resolve(self, question: str, entity_hints: Optional[List[str]] = None) -> Tuple[List[ResolvedEntity], List[UnresolvedEntity]]:
        candidates = self.extract_candidate_tokens(question, entity_hints)
        logger.info(f"Query entity candidates extracted: {candidates}")

        resolved: List[ResolvedEntity] = []
        unresolved: List[UnresolvedEntity] = []
        seen_resolved_ids = set()

        for cand in candidates:
            entity, err = self.resolve_entity_in_graph(cand)
            if entity:
                if entity.id not in seen_resolved_ids:
                    seen_resolved_ids.add(entity.id)
                    resolved.append(entity)
            else:
                unresolved.append(UnresolvedEntity(candidate_text=cand, reason=err or "not_found_in_graph"))

        # Sort resolved entities deterministically by appearance order in the question text
        q_lower = question.lower()
        def _pos(e: ResolvedEntity) -> int:
            idx = q_lower.find(e.name.lower())
            return idx if idx != -1 else 999
        resolved.sort(key=_pos)

        logger.info(f"Resolution complete: {len(resolved)} resolved, {len(unresolved)} unresolved.")
        return resolved, unresolved

entity_resolver = QueryEntityResolver()
