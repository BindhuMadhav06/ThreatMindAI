from fastapi import APIRouter
from app.core.config import settings
from app.services.graph.connection import neo4j_conn
from app.services.llm.llm_factory import get_llm_provider

router = APIRouter()

@router.get("/health", summary="Get system health status")
def get_health_status():
    neo4j_connected = neo4j_conn.verify_connectivity()
    llm = get_llm_provider()
    
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "neo4j_connected": neo4j_connected,
        "llm_provider": llm.get_provider_name(),
        "llm_available": llm.is_available()
    }
