import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.graph.connection import neo4j_conn
from app.services.graph.schema_manager import schema_manager

def test_neo4j_connectivity():
    assert neo4j_conn.verify_connectivity() is True

def test_schema_initialization():
    result = schema_manager.initialize_schema()
    assert result["status"] == "success"
    assert len(result["primary_labels"]) == 13
    assert len(result["constraints"]) == 13
    assert len(result["indexes"]) >= 8

def test_schema_verification():
    verification = schema_manager.verify_schema()
    assert "constraints_count" in verification
    assert verification["constraints_count"] >= 13
    assert "indexes_count" in verification
    assert verification["indexes_count"] >= 8
