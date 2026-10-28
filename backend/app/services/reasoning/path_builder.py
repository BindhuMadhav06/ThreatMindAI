from typing import List, Dict, Any, Tuple, Optional
from app.models.query import (
    ResolvedEntity,
    RetrievedEntity,
    RetrievedRelationship,
    EvidenceRecord
)
from app.models.reasoning import (
    ReasoningStep,
    EvidenceBackedPath,
    PathValidationResult
)
from app.services.reasoning.path_templates import (
    PATH_TEMPLATES,
    PathTemplate,
    detect_template_for_query
)
from app.services.reasoning.path_validator import path_validator
from app.services.graph.schema_manager import SUPPORTED_RELATIONSHIPS
from app.core.logging import logger

class PathBuilder:
    """
    Constructs, enriches, validates, and ranks multi-hop reasoning paths.
    """

    @classmethod
    def assemble_step(
        cls,
        step_number: int,
        rel: RetrievedRelationship,
        evidence_records: List[EvidenceRecord],
        sources: List[Dict[str, Any]]
    ) -> ReasoningStep:
        # Match evidence records for this specific edge
        step_evidence = [
            ev for ev in evidence_records
            if ev.source_id == rel.provenance.get("source_id") or
               f"({rel.source_name})-[{rel.rel_type}]->({rel.target_name})" in ev.relationship
        ]

        # If no pre-matched record, build from rel.provenance
        if not step_evidence and rel.provenance.get("evidence_text"):
            source_id = rel.provenance.get("source_id")
            src_info = next((s for s in sources if s.get("id") == source_id), {})
            step_evidence.append(EvidenceRecord(
                source_id=source_id or "unknown",
                source_title=src_info.get("title"),
                source_url=rel.provenance.get("source_url") or src_info.get("url"),
                publisher=src_info.get("publisher"),
                published_date=rel.provenance.get("published_date") or src_info.get("published_date"),
                evidence_text=rel.provenance.get("evidence_text", ""),
                extraction_method=rel.provenance.get("extraction_method"),
                confidence=rel.provenance.get("confidence"),
                relationship=f"({rel.source_name})-[{rel.rel_type}]->({rel.target_name})"
            ))

        # Match relevant sources
        step_sources = [
            s for s in sources
            if s.get("id") in [ev.source_id for ev in step_evidence]
        ]

        return ReasoningStep(
            step_number=step_number,
            source_id=rel.source_id,
            source_label=rel.source_label,
            source_name=rel.source_name,
            rel_type=rel.rel_type,
            target_id=rel.target_id,
            target_label=rel.target_label,
            target_name=rel.target_name,
            evidence_records=step_evidence,
            sources=step_sources,
            is_valid=True,
            validation_notes=[]
        )

    @classmethod
    def compute_relevance(
        cls,
        path_steps: List[ReasoningStep],
        question: str,
        template_id: Optional[str] = None
    ) -> float:
        score = 0.5
        q_lower = question.lower()

        # Check if question keywords match target nodes
        for step in path_steps:
            if step.target_name.lower() in q_lower:
                score += 0.2
            if step.source_name.lower() in q_lower:
                score += 0.1

        # Template match bonus
        if template_id:
            score += 0.15

        # Penalty for excessive hops if question is simple
        if len(path_steps) > 2 and "how" not in q_lower:
            score -= 0.05

        return round(min(score, 1.0), 3)

    @classmethod
    def validate_path_endpoints(
        cls,
        path_steps: List[ReasoningStep],
        resolved_entities: List[ResolvedEntity]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates whether candidate path steps connect the required query entities.
        - If len(resolved_entities) <= 1: exploratory single-entity query, path is accepted.
        - If len(resolved_entities) == 2: path must connect both resolved entities.
        - If len(resolved_entities) >= 3: path must connect the primary queried entity
          (the first resolved entity) and span the required entities without using disconnected subgraphs.
        """
        if len(resolved_entities) <= 1:
            return True, None

        # Collect all node IDs and normalized names in the path
        path_node_ids = set()
        path_node_names = set()
        for step in path_steps:
            path_node_ids.add(step.source_id)
            path_node_ids.add(step.target_id)
            path_node_names.add(step.source_name.lower())
            path_node_names.add(step.target_name.lower())

        # Determine which resolved entities are present in this path
        matched_entities = []
        for ent in resolved_entities:
            if ent.id in path_node_ids or ent.name.lower() in path_node_names:
                matched_entities.append(ent)

        matched_count = len(matched_entities)

        if len(resolved_entities) == 2:
            if matched_count < 2:
                unmatched = [e.name for e in resolved_entities if e not in matched_entities]
                return False, f"unsupported_endpoint_relationship: path does not connect both queried entities (missing: {', '.join(unmatched)})"
            return True, None

        # len(resolved_entities) >= 3:
        # 1. Primary subject entity (first entity mentioned in query) MUST be present in the path
        primary_entity = resolved_entities[0]
        is_primary_matched = (primary_entity.id in path_node_ids or primary_entity.name.lower() in path_node_names)
        if not is_primary_matched:
            return False, f"unsupported_endpoint_relationship: path omits the primary subject entity '{primary_entity.name}'"

        # 2. When a query inquires about multiple entities (>= 3), disconnected or partial subgraphs
        # (e.g. only connecting 2 of the 3 entities while leaving the primary subject or target disconnected)
        # cannot provide a supported answer. All required entities in the query chain must be connected.
        if matched_count < len(resolved_entities):
            unmatched = [e.name for e in resolved_entities if e not in matched_entities]
            return False, f"unsupported_endpoint_relationship: path does not connect all required query entities (missing: {', '.join(unmatched)})"

        return True, None

    @classmethod
    def build_paths_from_graph(
        cls,
        question: str,
        resolved_entities: List[ResolvedEntity],
        retrieved_relationships: List[RetrievedRelationship],
        evidence_records: List[EvidenceRecord],
        sources: List[Dict[str, Any]],
        max_depth: int = 3,
        max_paths: int = 10,
        preferred_template: Optional[str] = None
    ) -> Tuple[List[EvidenceBackedPath], List[EvidenceBackedPath], List[Dict[str, Any]], int]:
        """
        Builds, validates, and ranks multi-hop paths starting from resolved entities.
        Returns (accepted_paths, partial_paths, rejected_paths, candidate_paths_count).
        """
        start_ids = {e.id for e in resolved_entities}
        detected_template = preferred_template or detect_template_for_query(question)

        # Build adjacency mapping for forward traversal
        adj: Dict[str, List[RetrievedRelationship]] = {}
        for r in retrieved_relationships:
            adj.setdefault(r.source_id, []).append(r)

        candidate_step_chains: List[List[RetrievedRelationship]] = []

        def dfs_traverse(curr_id: str, current_path: List[RetrievedRelationship], visited_nodes: set):
            if len(current_path) >= max_depth:
                return

            for edge in adj.get(curr_id, []):
                if edge.target_id in visited_nodes:
                    continue  # Avoid cycles

                new_path = current_path + [edge]
                candidate_step_chains.append(new_path)

                new_visited = visited_nodes | {edge.target_id}
                dfs_traverse(edge.target_id, new_path, new_visited)

        for s_id in start_ids:
            dfs_traverse(s_id, [], {s_id})

        # Also consider direct 1-hop incoming edges to starting entities (e.g. Vulnerability AFFECTS Product)
        for edge in retrieved_relationships:
            if edge.target_id in start_ids and edge.source_id not in start_ids:
                candidate_step_chains.append([edge])

        candidate_count = len(candidate_step_chains)
        logger.info(f"Generated {candidate_count} raw candidate reasoning path chains.")

        accepted_paths: List[EvidenceBackedPath] = []
        partial_paths: List[EvidenceBackedPath] = []
        rejected_paths: List[Dict[str, Any]] = []

        seen_path_signatures = set()

        for idx, chain in enumerate(candidate_step_chains):
            # Signature check for deduplication
            signature = "->".join([f"{e.source_id}:{e.rel_type}:{e.target_id}" for e in chain])
            if signature in seen_path_signatures:
                continue
            seen_path_signatures.add(signature)

            # Assemble ReasoningSteps with evidence
            steps = []
            for step_num, edge in enumerate(chain, start=1):
                step = cls.assemble_step(step_num, edge, evidence_records, sources)
                steps.append(step)

            # Validate the complete path
            val_res: PathValidationResult = path_validator.validate_path(steps)

            # Check template matching
            matched_template_id = None
            caveats = [
                "Graph traversal documents observed association; it does not infer causality, attack success, or chronology without explicit temporal evidence."
            ]

            if detected_template and detected_template in PATH_TEMPLATES:
                tmpl = PATH_TEMPLATES[detected_template]
                rels = [s.rel_type for s in steps]
                labels = [steps[0].source_label] + [s.target_label for s in steps]
                if tmpl.matches_sequence(rels, labels):
                    matched_template_id = detected_template
                    caveats.extend(tmpl.default_caveats)

            rel_score = cls.compute_relevance(steps, question, matched_template_id)

            path_obj = EvidenceBackedPath(
                path_id=f"reason_path_{idx}",
                steps=steps,
                length=len(steps),
                is_complete=(val_res.validation_status == "accepted"),
                is_valid=val_res.is_valid,
                relevance_score=rel_score,
                template_applied=matched_template_id,
                semantic_caveats=caveats
            )

            if val_res.validation_status == "accepted":
                endpoint_ok, endpoint_err = cls.validate_path_endpoints(steps, resolved_entities)
                if endpoint_ok:
                    accepted_paths.append(path_obj)
                else:
                    path_obj.is_complete = False
                    path_obj.is_valid = False
                    rejected_paths.append({
                        "path_id": f"rejected_{idx}",
                        "reasons": [endpoint_err],
                        "attempted_path": signature
                    })
            elif val_res.validation_status == "partial":
                if len(resolved_entities) <= 1:
                    partial_paths.append(path_obj)
                else:
                    endpoint_ok, _ = cls.validate_path_endpoints(steps, resolved_entities)
                    if endpoint_ok:
                        partial_paths.append(path_obj)
            else:
                rejected_paths.append({
                    "path_id": f"rejected_{idx}",
                    "reasons": val_res.reasons,
                    "attempted_path": signature
                })

        # Sort accepted paths deterministically by relevance_score descending, then length
        accepted_paths.sort(key=lambda p: (p.relevance_score, -p.length), reverse=True)
        accepted_paths = accepted_paths[:max_paths]

        return accepted_paths, partial_paths[:max_paths], rejected_paths[:max_paths], candidate_count
