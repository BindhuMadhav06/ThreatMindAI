from fastapi import APIRouter, HTTPException, Query, status
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.services.graph.repository import graph_repository
from app.services.graph.connection import neo4j_conn
from app.services.graph.schema_manager import PRIMARY_NODE_LABELS
from app.core.logging import logger

router = APIRouter()

class GraphStats(BaseModel):
    total_nodes: int
    total_relationships: int
    total_sources: int
    node_counts_by_label: Dict[str, int]

class EntitySummary(BaseModel):
    id: str
    label: str
    name: str
    description: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    is_synthetic: bool = False
    properties: Dict[str, Any] = Field(default_factory=dict)

class NeighborEdge(BaseModel):
    source_id: str
    source_name: str
    source_label: str
    rel_type: str
    target_id: str
    target_name: str
    target_label: str
    provenance: Dict[str, Any] = Field(default_factory=dict)
    is_synthetic: bool = False

class EntityDetail(BaseModel):
    entity: EntitySummary
    neighbors: List[EntitySummary] = Field(default_factory=list)
    relationships: List[NeighborEdge] = Field(default_factory=list)

@router.get("/graph/stats", response_model=GraphStats, summary="Get genuine knowledge graph node and relationship counts")
def get_graph_stats():
    """
    Returns authentic graph statistics from Neo4j (counts by primary label, total relationships, total sources).
    """
    if not neo4j_conn.verify_connectivity():
        logger.error("Neo4j database connection unavailable during graph stats lookup.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge graph database is currently unavailable."
        )

    try:
        stats = graph_repository.get_graph_stats()
        return stats
    except Exception as e:
        logger.error(f"Error fetching graph stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query graph statistics: {str(e)}"
        )

@router.get("/entities", response_model=List[EntitySummary], summary="Query knowledge graph entities")
def list_entities(
    label: Optional[str] = Query(None, description="Optional label filter restricted to approved primary labels"),
    search: Optional[str] = Query(None, description="Optional search term matching entity name or id"),
    limit: int = Query(50, ge=1, le=100, description="Max entities to return (hard limit 100)")
):
    """
    Lists genuine knowledge graph entities with optional approved label filter and search term.
    Uses parameterized Cypher and enforces a hard limit.
    """
    if not neo4j_conn.verify_connectivity():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge graph database is currently unavailable."
        )

    if label:
        allowed = [l.lower() for l in PRIMARY_NODE_LABELS]
        if label.lower() not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid label '{label}'. Allowed labels: {PRIMARY_NODE_LABELS}"
            )

    try:
        entities = graph_repository.get_entities(label=label, search=search, limit=limit)
        return entities
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        logger.error(f"Error querying graph entities: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Entity query failed: {str(e)}"
        )

@router.get("/entities/{entity_id}", response_model=EntityDetail, summary="Get entity details and 1-hop neighbors")
def get_entity_details(entity_id: str):
    """
    Retrieves full properties and 1-hop evidence-backed connections for a specific entity ID.
    """
    if not entity_id or not entity_id.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Entity ID cannot be empty.")

    if not neo4j_conn.verify_connectivity():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Knowledge graph database is currently unavailable."
        )

    try:
        res = graph_repository.get_entity_with_neighbors(entity_id=entity_id.strip())
        if not res:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Entity '{entity_id}' not found in knowledge graph."
            )
        return res
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error querying entity details for '{entity_id}': {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Entity lookup failed: {str(e)}"
        )
