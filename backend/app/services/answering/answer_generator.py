import time
from typing import Optional, List, Dict, Any
from app.models.answering import (
    AnswerRequest,
    AnswerResponse,
    GroundedAnswer,
    AnswerClaim,
    AnswerCitation
)
from app.models.reasoning import ReasoningRequest, ReasoningResult, EvidenceBackedPath
from app.services.reasoning.reasoning_service import reasoning_service, ThreatReasoningService
from app.services.reasoning.path_builder import PathBuilder
from app.services.llm.llm_factory import get_llm_provider
from app.services.llm.base_provider import BaseLLMProvider
from app.services.answering.prompt_builder import PromptBuilder, ABSTENTION_PHRASE
from app.services.answering.answer_validator import answer_validator, AnswerValidator
from app.core.logging import logger

class AnswerGenerator:
    """
    Coordinates end-to-end question answering with multi-hop reasoning,
    GraphRAG retrieval, strict provenance verification, and deterministic fallback.
    """

    def __init__(
        self,
        reasoner: Optional[ThreatReasoningService] = None,
        llm_provider: Optional[BaseLLMProvider] = None,
        validator: Optional[AnswerValidator] = None
    ):
        self.reasoner = reasoner or reasoning_service
        self.llm = llm_provider or get_llm_provider()
        self.validator = validator or answer_validator

    def generate_answer(self, request: AnswerRequest) -> AnswerResponse:
        start_time = time.perf_counter()
        logger.info(f"Generating evidence-grounded answer for query: '{request.question}'")

        # 1. Execute Multi-Hop Reasoning
        reasoning_req = ReasoningRequest(
            question=request.question,
            entity_hints=request.entity_hints,
            max_depth=request.max_depth,
            max_paths=request.max_paths,
            min_confidence=request.min_confidence
        )
        reasoning_res: ReasoningResult = self.reasoner.reason(reasoning_req)

        warnings: List[str] = list(reasoning_res.warnings)
        unresolved_texts = [
            w.split("'")[1] for w in warnings if "Unresolved entity candidate" in w
        ]

        active_paths = reasoning_res.accepted_paths or reasoning_res.partial_paths

        # If query has multiple resolved entities, verify active paths connect the required endpoints
        if len(reasoning_res.resolved_entities) >= 2:
            bridging_paths = []
            for p in active_paths:
                ok, _ = PathBuilder.validate_path_endpoints(p.steps, reasoning_res.resolved_entities)
                if ok:
                    bridging_paths.append(p)
            active_paths = bridging_paths

        # 2. Strict Abstention Check
        if not reasoning_res.resolved_entities or not active_paths:
            logger.info("Abstention triggered: insufficient graph entities or verified paths.")
            warnings.append("Abstention triggered: Insufficient evidence in knowledge graph.")
            exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

            abstention_answer = GroundedAnswer(
                summary="Insufficient knowledge graph evidence to answer the query.",
                direct_answer=ABSTENTION_PHRASE,
                claims=[],
                citations=[],
                referenced_paths=[],
                caveats=["No supported cybersecurity relationships were found in the knowledge graph for the specified query concepts."],
                sufficiency_status="insufficient",
                is_synthetic=False
            )

            return AnswerResponse(
                original_question=request.question,
                answer=abstention_answer,
                claims=[],
                citations=[],
                graph_paths=[],
                resolved_entities=[e.name for e in reasoning_res.resolved_entities],
                unresolved_entities=unresolved_texts,
                warnings=warnings,
                grounding_status="insufficient_evidence",
                statistics={
                    "execution_time_ms": exec_time_ms,
                    "paths_considered": reasoning_res.candidate_paths_considered,
                    "paths_used": 0,
                    "claims_count": 0,
                    "verified_claims_count": 0,
                    "provider": self.llm.get_provider_name()
                }
            )

        # 3. Construct Citation Pool & Aggregated Caveats
        citation_pool = PromptBuilder.build_citation_pool(
            active_paths,
            reasoning_res.referenced_sources
        )

        all_caveats = []
        for p in active_paths:
            all_caveats.extend(p.semantic_caveats)
        # Deduplicate caveats preserving order
        dedup_caveats = list(dict.fromkeys(all_caveats))

        # Check if citations contain synthetic demonstration data
        is_synthetic = any(cit.is_synthetic for cit in citation_pool.values())

        # 4. Attempt LLM Generation
        system_instruction, user_prompt = PromptBuilder.build_grounding_prompt(
            request.question,
            citation_pool,
            active_paths,
            dedup_caveats
        )
        schema = PromptBuilder.get_structured_output_schema()

        raw_llm_output = {}
        if self.llm.is_available():
            try:
                raw_llm_output = self.llm.generate_structured_output(
                    prompt=user_prompt,
                    schema=schema,
                    system_instruction=system_instruction
                )
            except Exception as e:
                logger.warning(f"LLM structured generation error: {e}. Falling back to deterministic synthesis.")
                warnings.append(f"LLM provider error: {str(e)}; utilized deterministic fallback.")

        # 5. Fallback or Structured Conversion
        if raw_llm_output and "direct_answer" in raw_llm_output and raw_llm_output.get("claims"):
            candidate_claims = [
                AnswerClaim(
                    claim_text=c.get("claim_text", ""),
                    evidence_references=c.get("evidence_references", []),
                    claim_type=c.get("claim_type", "relationship"),
                    verification_status="unverified",
                    validation_reasons=[]
                )
                for c in raw_llm_output.get("claims", [])
            ]
            candidate_answer = GroundedAnswer(
                summary=raw_llm_output.get("summary", ""),
                direct_answer=raw_llm_output.get("direct_answer", ""),
                claims=candidate_claims,
                citations=list(citation_pool.values()),
                referenced_paths=raw_llm_output.get("referenced_paths", [p.path_id for p in active_paths]),
                caveats=raw_llm_output.get("caveats", dedup_caveats),
                sufficiency_status=raw_llm_output.get("sufficiency_status", "sufficient"),
                is_synthetic=is_synthetic
            )
        else:
            # Deterministic, evidence-grounded offline fallback
            candidate_answer = self._generate_deterministic_fallback(
                request.question,
                active_paths,
                citation_pool,
                dedup_caveats,
                is_synthetic
            )

        # 6. Strict Multi-Stage Answer Validation
        validated_answer, val_result = self.validator.validate_answer(candidate_answer, citation_pool)

        warnings.extend(val_result.warnings)

        exec_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        stats = {
            "execution_time_ms": exec_time_ms,
            "paths_considered": reasoning_res.candidate_paths_considered,
            "paths_used": len(active_paths),
            "claims_count": len(validated_answer.claims),
            "verified_claims_count": len(val_result.verified_claims),
            "unverified_claims_count": len(val_result.unverified_claims),
            "citations_count": len(citation_pool),
            "provider": self.llm.get_provider_name()
        }

        logger.info(
            f"Answer generation completed in {exec_time_ms}ms with status: {val_result.grounding_status}"
        )

        return AnswerResponse(
            original_question=request.question,
            answer=validated_answer,
            claims=validated_answer.claims,
            citations=validated_answer.citations,
            graph_paths=active_paths,
            resolved_entities=[e.name for e in reasoning_res.resolved_entities],
            unresolved_entities=unresolved_texts,
            warnings=warnings,
            grounding_status=val_result.grounding_status,
            statistics=stats
        )

    def _generate_deterministic_fallback(
        self,
        question: str,
        paths: List[EvidenceBackedPath],
        citation_pool: Dict[str, AnswerCitation],
        caveats: List[str],
        is_synthetic: bool
    ) -> GroundedAnswer:
        """
        Synthesizes a deterministic, evidence-grounded answer directly from graph path steps.
        Subject to the exact same validation rules as LLM outputs.
        """
        # Map relationship representations to citation tags
        rel_to_cit: Dict[str, str] = {}
        for cit_id, cit in citation_pool.items():
            rel_to_cit[cit.supported_relationship] = cit_id

        sentences = []
        claims = []
        referenced_path_ids = []

        prefix = "Based on synthetic demonstration data, " if is_synthetic else "Based on retrieved threat intelligence sources, "

        for path in paths:
            referenced_path_ids.append(path.path_id)
            for step in path.steps:
                rel_repr = f"({step.source_name})-[{step.rel_type}]->({step.target_name})"
                cit_id = rel_to_cit.get(rel_repr)
                cit_tag = f"[{cit_id}]" if cit_id else ""

                human_rel = step.rel_type.lower().replace("_", " ")
                sent = f"{step.source_name} {human_rel} {step.target_name} {cit_tag}".strip()
                sentences.append(sent)

                claims.append(AnswerClaim(
                    claim_text=f"{step.source_name} {human_rel} {step.target_name}.",
                    evidence_references=[cit_id] if cit_id else [],
                    claim_type="relationship",
                    verification_status="unverified",
                    validation_reasons=[]
                ))

        direct_narrative = prefix + "; ".join(sentences) + "."
        summary = f"Identified {len(paths)} validated multi-hop threat intelligence reasoning path(s)."

        return GroundedAnswer(
            summary=summary,
            direct_answer=direct_narrative,
            claims=claims,
            citations=list(citation_pool.values()),
            referenced_paths=referenced_path_ids,
            caveats=caveats,
            sufficiency_status="sufficient",
            is_synthetic=is_synthetic
        )

answer_generator = AnswerGenerator()
