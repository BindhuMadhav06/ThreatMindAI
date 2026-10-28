import hashlib
from typing import List, Dict, Any, Tuple, Optional
from app.models.reasoning import EvidenceBackedPath
from app.models.answering import AnswerCitation, compute_evidence_id

ABSTENTION_PHRASE = "ThreatMind could not establish a sufficiently supported relationship from the currently available sources."

class PromptBuilder:
    """
    Constructs strict, citation-indexed grounding prompts and system instructions
    for LLM-based answer generation.
    """

    @classmethod
    def build_citation_pool(
        cls,
        paths: List[EvidenceBackedPath],
        sources: List[Dict[str, Any]]
    ) -> Dict[str, AnswerCitation]:
        """
        Extracts, deduplicates, and assigns stable citation identifiers (CIT-1, CIT-2, ...)
        to evidence records from reasoning paths and source records.
        """
        citations_by_id: Dict[str, AnswerCitation] = {}
        seen_evidence_keys = set()
        sources_map = {s.get("id"): s for s in sources if s.get("id")}

        cit_counter = 1

        for path in paths:
            for step in path.steps:
                for ev in step.evidence_records:
                    ev_text = ev.evidence_text.strip()
                    rel_repr = ev.relationship or f"({step.source_name})-[{step.rel_type}]->({step.target_name})"
                    src_id = ev.source_id or "unknown_source"

                    ev_id = compute_evidence_id(src_id, rel_repr, ev_text)
                    if ev_id in seen_evidence_keys:
                        continue
                    seen_evidence_keys.add(ev_id)

                    src_meta = sources_map.get(src_id, {})
                    is_synthetic = bool(src_meta.get("is_synthetic", False))

                    citation_tag = f"CIT-{cit_counter}"
                    cit_counter += 1

                    citations_by_id[citation_tag] = AnswerCitation(
                        citation_id=citation_tag,
                        evidence_id=ev_id,
                        source_id=src_id,
                        source_title=ev.source_title or src_meta.get("title"),
                        source_url=ev.source_url or src_meta.get("url"),
                        publisher=ev.publisher or src_meta.get("publisher"),
                        published_date=ev.published_date or src_meta.get("published_date"),
                        evidence_text=ev_text,
                        supported_relationship=rel_repr,
                        confidence=ev.confidence,
                        is_synthetic=is_synthetic
                    )

        return citations_by_id

    @classmethod
    def build_grounding_prompt(
        cls,
        question: str,
        citation_pool: Dict[str, AnswerCitation],
        paths: List[EvidenceBackedPath],
        caveats: List[str]
    ) -> Tuple[str, str]:
        """
        Builds the system instruction and user prompt enforcing zero-unsupported claims.
        Returns (system_instruction, user_prompt).
        """
        system_instruction = (
            "You are ThreatMind's Evidence-Grounded Cyber Threat Intelligence Analyst.\n"
            "Your task is to answer the cybersecurity investigation question using ONLY the provided "
            "knowledge graph paths and verbatim evidence citations.\n\n"
            "STRICT RULES:\n"
            "1. NO GUESSING & NO EXTRAPOLATION: Every factual statement must be directly backed by the provided citations.\n"
            "2. CITATION TAGGING: You must cite the exact citation tag (e.g. [CIT-1], [CIT-2]) for every substantive assertion.\n"
            "3. NO INVENTED CITATIONS: Never reference a citation tag that is not explicitly defined in the context.\n"
            "4. NO UNSUPPORTED ATTACK SUCCESS OR CAUSALITY: Do NOT assert that an attack succeeded, a system was compromised, "
            "or an entity caused an outcome unless the cited evidence passage explicitly uses words stating that outcome.\n"
            "5. SYNTHETIC DATA DISCLOSURE: If any cited evidence is marked as synthetic, you must explicitly state that the answer "
            "is based on synthetic demonstration data and not verified real-world threat intelligence.\n"
            "6. ABSTENTION: If the retrieved citations do not support answering the question or key relationships are missing, "
            f"you must state: '{ABSTENTION_PHRASE}'\n"
            "7. CONFLICTS & CAVEATS: If sources conflict or caveats apply, explicitly highlight the caveats."
        )

        # Build Citations Context
        citations_lines = []
        has_synthetic = False
        for cit_id, cit in citation_pool.items():
            if cit.is_synthetic:
                has_synthetic = True
            conf_str = f"{cit.confidence:.2f}" if cit.confidence is not None else "unknown"
            synth_str = "SYNTHETIC" if cit.is_synthetic else "REAL-WORLD"
            citations_lines.append(
                f"[{cit_id}] (Type: {synth_str}, Confidence: {conf_str})\n"
                f"  Relationship: {cit.supported_relationship}\n"
                f"  Source: {cit.source_title or cit.source_id} ({cit.published_date or 'date unknown'})\n"
                f"  Evidence: \"{cit.evidence_text}\""
            )

        citations_block = "\n".join(citations_lines) if citations_lines else "No citations available."

        # Build Paths Context
        paths_lines = []
        for path in paths:
            step_strs = [
                f"({s.source_name}) -[{s.rel_type}]-> ({s.target_name})"
                for s in path.steps
            ]
            path_repr = " -> ".join(step_strs)
            paths_lines.append(f"- Path ID {path.path_id} (Score: {path.relevance_score}): {path_repr}")

        paths_block = "\n".join(paths_lines) if paths_lines else "No complete graph paths available."

        caveats_block = "\n".join([f"- {c}" for c in caveats]) if caveats else "None provided."

        user_prompt = (
            f"INVESTIGATION QUESTION: {question}\n\n"
            f"--- VERIFIED GRAPH PATHS ---\n{paths_block}\n\n"
            f"--- EVIDENCE CITATIONS ---\n{citations_block}\n\n"
            f"--- ANALYTICAL CAVEATS ---\n{caveats_block}\n\n"
            "Generate a structured, evidence-grounded response answering the question. "
            "Deconstruct your answer into granular claims, each mapped to its supporting citation IDs."
        )

        return system_instruction, user_prompt

    @classmethod
    def get_structured_output_schema(cls) -> Dict[str, Any]:
        """
        Defines the JSON schema for structured LLM generation.
        """
        return {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "High-level summary of findings"
                },
                "direct_answer": {
                    "type": "string",
                    "description": "Detailed answer directly answering the question with inline [CIT-X] citations"
                },
                "claims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "claim_text": {
                                "type": "string",
                                "description": "Specific factual assertion made"
                            },
                            "evidence_references": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of citation tags backing this assertion, e.g. ['CIT-1']"
                            },
                            "claim_type": {
                                "type": "string",
                                "enum": ["relationship", "actor_behavior", "vulnerability_impact", "technique_usage", "observational"],
                                "description": "Category of cybersecurity claim"
                            }
                        },
                        "required": ["claim_text", "evidence_references", "claim_type"]
                    }
                },
                "referenced_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IDs of graph paths referenced in the answer"
                },
                "caveats": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Caveats, limitations, or conflict notes"
                },
                "sufficiency_status": {
                    "type": "string",
                    "enum": ["sufficient", "partial", "insufficient"],
                    "description": "Whether the provided context was sufficient to answer the question"
                }
            },
            "required": ["summary", "direct_answer", "claims", "referenced_paths", "caveats", "sufficiency_status"]
        }
