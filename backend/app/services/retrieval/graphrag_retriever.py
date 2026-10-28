import time
from typing import List, Dict, Any, Optional
from app.services.retrieval.base import BaseGraphRetriever
from app.services.retrieval.entity_resolver import entity_resolver, QueryEntityResolver
from app.services.retrieval.graph_retriever import graph_retriever, ControlledGraphRetriever
from app.models.query import (
    ThreatQuery,
    RetrievalResult,
    RetrievalStatistics,
    ResolvedEntity,
    UnresolvedEntity
)
from app.core.logging import logger

class GraphKnowledgeRetriever(BaseGraphRetriever):
    """
    Primary GraphRAG Retrieval Engine for ThreatMind.
    Coordinates entity resolution, bounded graph traversal, evidence collection,
    and strict provenance verification.
    """

    def __init__(
        self,
        resolver: Optional[QueryEntityResolver] = None,
        retriever: Optional[ControlledGraphRetriever] = None
    ):
        self.resolver = resolver or entity_resolver
        self.retriever = retriever or graph_retriever

    def retrieve(self, query: ThreatQuery) -> RetrievalResult:
        start_time = time.perf_counter()
        logger.info(f"Processing GraphRAG retrieval for query: '{query.question}'")

        # 1. Resolve Entities from Question
        resolved_entities, unresolved_entities = self.resolver.resolve(
            question=query.question,
            entity_hints=query.entity_hints
        )

        all_warnings: List[str] = []

        if unresolved_entities:
            for unres in unresolved_entities:
                all_warnings.append(f"Unresolved entity candidate '{unres.candidate_text}': {unres.reason}")

        if not resolved_entities:
            all_warnings.append("No known cybersecurity entities could be resolved from the question or hints.")
            exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return RetrievalResult(
                original_question=query.question,
                resolved_entities=[],
                unresolved_entities=unresolved_entities,
                retrieved_entities=[],
                retrieved_relationships=[],
                graph_paths=[],
                evidence_records=[],
                sources=[],
                warnings=all_warnings,
                statistics=RetrievalStatistics(
                    execution_time_ms=exec_time_ms,
                    entities_resolved_count=0,
                    nodes_retrieved_count=0,
                    edges_retrieved_count=0,
                    evidence_records_count=0,
                    paths_count=0
                )
            )

        # 2. Execute Controlled Bounded Graph Traversal
        retrieved_entities, retrieved_relationships, paths, evidence, sources, retrieval_warnings = self.retriever.retrieve(
            resolved_entities=resolved_entities,
            config=query.config
        )

        all_warnings.extend(retrieval_warnings)

        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        stats = RetrievalStatistics(
            execution_time_ms=exec_time_ms,
            entities_resolved_count=len(resolved_entities),
            nodes_retrieved_count=len(retrieved_entities),
            edges_retrieved_count=len(retrieved_relationships),
            evidence_records_count=len(evidence),
            paths_count=len(paths)
        )

        logger.info(
            f"GraphRAG retrieval completed in {exec_time_ms}ms: "
            f"{stats.entities_resolved_count} entities resolved, "
            f"{stats.nodes_retrieved_count} nodes retrieved, "
            f"{stats.edges_retrieved_count} edges, {stats.evidence_records_count} evidence records."
        )

        return RetrievalResult(
            original_question=query.question,
            resolved_entities=resolved_entities,
            unresolved_entities=unresolved_entities,
            retrieved_entities=retrieved_entities,
            retrieved_relationships=retrieved_relationships,
            graph_paths=paths,
            evidence_records=evidence,
            sources=sources,
            warnings=all_warnings,
            statistics=stats
        )

graphrag_retriever = GraphKnowledgeRetriever()
