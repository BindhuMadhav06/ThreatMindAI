import sys
import os
import pytest

# Ensure backend root and project root are on sys.path for test discovery
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
project_root = os.path.abspath(os.path.join(backend_dir, ".."))
for path in [backend_dir, project_root]:
    if path not in sys.path:
        sys.path.insert(0, path)

from app.services.graph.connection import neo4j_conn

@pytest.fixture(scope="session", autouse=True)
def setup_neo4j_session():
    """Ensure Neo4j schema and demo synthetic dataset are seeded if database is available."""
    if neo4j_conn.verify_connectivity():
        try:
            from scripts.seed_demo_data import seed_demo_data
            seed_demo_data()
        except Exception as e:
            pass
