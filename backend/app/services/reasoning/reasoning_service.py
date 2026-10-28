import time
from typing import Optional, Dict, Any, List
from app.models.query import ThreatQuery, RetrievalConfig
from app.models.reasoning import ReasoningRequest, ReasoningResult, EvidenceBackedPath
from app.services.retrieval.graphrag_retriever import graphrag_retriever, GraphKnowledgeRetriever
from app.services.reasoning.path_builder import PathBuilder
from app.core.logging import logger

class ThreatReasoningService:
    """
    Multi-Hop Threat Reasoning Engine for ThreatMind.
    Integrates GraphRAG retrieval to construct, validate, and rank
    transparent, evidence-grounded cybersecurity threat paths.
    """

    def __init__(self, retriever: Optional[GraphKnowledgeRetriever] = None):
        self.retriever = retriever or graphrag_retriever

    def reason(self, request: ReasoningRequest) -> ReasoningResult:
        start_time = time.perf_counter()
        logger.info(f"Initiating multi-hop threat reasoning for question: '{request.question}'")

        # 1. Execute GraphRAG Retrieval via Phase 5 Retriever
        threat_query = ThreatQuery(
            question=request.question,
            entity_hints=request.entity_hints,
            config=RetrievalConfig(
                max_depth=request.max_depth,
                max_entities=30,
                max_relationships=40,
                max_evidence=40,
                min_confidence=request.min_confidence
            )
        )
        retrieval_res = self.retriever.retrieve(threat_query)

        warnings: List[str] = list(retrieval_res.warnings)

        if not retrieval_res.resolved_entities:
            warnings.append("Reasoning stopped: No starting cybersecurity entities could be resolved.")
            exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return ReasoningResult(
                original_question=request.question,
                resolved_entities=[],
                candidate_paths_considered=0,
                accepted_paths=[],
                rejected_paths=[],
                partial_paths=[],
                referenced_sources=[],
                warnings=warnings,
                statistics={
                    "execution_time_ms": exec_time_ms,
                    "candidate_paths": 0,
                    "accepted_paths": 0,
                    "partial_paths": 0,
                    "rejected_paths": 0
                }
            )

        # 2. Bounded Multi-Hop Path Construction & Validation
        accepted_paths, partial_paths, rejected_paths, candidate_count = PathBuilder.build_paths_from_graph(
            question=request.question,
            resolved_entities=retrieval_res.resolved_entities,
            retrieved_relationships=retrieval_res.retrieved_relationships,
            evidence_records=retrieval_res.evidence_records,
            sources=retrieval_res.sources,
            max_depth=request.max_depth,
            max_paths=request.max_paths,
            preferred_template=request.template_name
        )

        if not accepted_paths:
            warnings.append("No fully validated, evidence-backed multi-hop path found connecting all query concepts.")
            if partial_paths:
                warnings.append(f"Found {len(partial_paths)} partial path(s) documenting incomplete graph chains.")

        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        stats = {
            "execution_time_ms": exec_time_ms,
            "candidate_paths": candidate_count,
            "accepted_paths": len(accepted_paths),
            "partial_paths": len(partial_paths),
            "rejected_paths": len(rejected_paths),
            "sources_count": len(retrieval_res.sources)
        }

        logger.info(
            f"Multi-hop reasoning completed in {exec_time_ms}ms: "
            f"{len(accepted_paths)} accepted paths, {len(partial_paths)} partial paths, "
            f"{len(rejected_paths)} rejected paths."
        )

        return ReasoningResult(
            original_question=request.question,
            resolved_entities=retrieval_res.resolved_entities,
            candidate_paths_considered=candidate_count,
            accepted_paths=accepted_paths,
            rejected_paths=rejected_paths,
            partial_paths=partial_paths,
            referenced_sources=retrieval_res.sources,
            warnings=warnings,
            statistics=stats
        )

reasoning_service = ThreatReasoningService()
