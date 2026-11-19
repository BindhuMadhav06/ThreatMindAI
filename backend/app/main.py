from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import logger
from app.api.routes import health, ingestion, query, entities, defense, vulnerabilities, stix, detection, timeline
from app.services.graph.connection import neo4j_conn

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.PROJECT_NAME} backend service...")
    neo4j_conn.verify_connectivity()
    yield
    logger.info(f"Shutting down {settings.PROJECT_NAME} backend service...")
    neo4j_conn.close()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    lifespan=lifespan
)

# CORS middleware for React frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(health.router, prefix=settings.API_V1_STR, tags=["Health"])
app.include_router(health.router, prefix="/api", tags=["Health"], include_in_schema=False)
app.include_router(health.router, tags=["Health"], include_in_schema=False)
app.include_router(ingestion.router, prefix=settings.API_V1_STR, tags=["Ingestion"])
app.include_router(query.router, prefix=settings.API_V1_STR, tags=["Query & Retrieval"])
app.include_router(entities.router, prefix=settings.API_V1_STR, tags=["Entities & Graph"])
app.include_router(defense.router, prefix=settings.API_V1_STR, tags=["MITRE D3FEND Defensive Recommendations"])
app.include_router(vulnerabilities.router, prefix=settings.API_V1_STR, tags=["Vulnerability Intelligence"])
app.include_router(stix.router, prefix=settings.API_V1_STR, tags=["STIX 2.1 Interoperability"])
app.include_router(detection.router, prefix=settings.API_V1_STR, tags=["SigmaHQ Detection Engineering"])
app.include_router(timeline.router, prefix=settings.API_V1_STR, tags=["Attack Timeline Reconstruction"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
