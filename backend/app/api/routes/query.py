from fastapi import APIRouter, HTTPException, status
from app.models.query import ThreatQuery, RetrievalResult
from app.models.reasoning import ReasoningRequest, ReasoningResult
from app.models.answering import AnswerRequest, AnswerResponse
from app.services.retrieval.graphrag_retriever import graphrag_retriever
from app.services.reasoning.reasoning_service import reasoning_service
from app.services.answering.answer_generator import answer_generator
from app.services.graph.connection import neo4j_conn
from app.core.logging import logger

router = APIRouter()

@router.post("/query/retrieve", response_model=RetrievalResult, summary="Retrieve evidence-backed graph context for a query")
def retrieve_graph_context(query: ThreatQuery):
    """
    Accepts a natural-language cyber threat intelligence question,
    resolves mentioned entities, and traverses the knowledge graph to retrieve
    bounded graph context, supporting evidence records, and exact provenance.
    
    NOTE: Performs retrieval only. Does NOT generate final LLM narrative answers.
    """
    if not query.question or not query.question.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query question cannot be empty."
        )

    if not neo4j_conn.verify_connectivity():
        logger.error("Neo4j database connection unavailable during query retrieval.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge graph database is currently unavailable."
        )

    try:
        result = graphrag_retriever.retrieve(query)
        return result
    except Exception as e:
        logger.error(f"Error during graph context retrieval: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Retrieval engine failed: {str(e)}"
        )

@router.post("/query/reason", response_model=ReasoningResult, summary="Execute multi-hop graph reasoning and path verification")
def execute_multi_hop_reasoning(request: ReasoningRequest):
    """
    Assembles, validates, and ranks multi-hop cyber threat reasoning paths
    connecting query entities, verifying edge provenance and preventing unsupported
    causal conclusions.
    
    NOTE: Returns structured reasoning results, NOT a final LLM narrative answer.
    """
    if not request.question or not request.question.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query question cannot be empty."
        )

    if not neo4j_conn.verify_connectivity():
        logger.error("Neo4j database connection unavailable during reasoning.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge graph database is currently unavailable."
        )

    try:
        result = reasoning_service.reason(request)
        return result
    except Exception as e:
        logger.error(f"Error during multi-hop threat reasoning: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reasoning engine failed: {str(e)}"
        )

@router.post("/query/answer", response_model=AnswerResponse, summary="Generate evidence-grounded threat intelligence answer")
def generate_grounded_answer(request: AnswerRequest):
    """
    Synthesizes multi-hop reasoning paths and verified graph evidence into a
    transparent, citation-backed natural-language answer with multi-stage
    validation, claim verification, and strict abstention.
    """
    if not request.question or not request.question.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query question cannot be empty."
        )

    if not neo4j_conn.verify_connectivity():
        logger.error("Neo4j database connection unavailable during answer generation.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge graph database is currently unavailable."
        )

    try:
        result = answer_generator.generate_answer(request)
        return result
    except Exception as e:
        logger.error(f"Error during grounded answer generation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Answer generation engine failed: {str(e)}"
        )
