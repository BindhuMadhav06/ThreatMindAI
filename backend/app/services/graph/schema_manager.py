from typing import Dict, List, Any
from app.services.graph.connection import neo4j_conn
from app.core.logging import logger

# 13 Primary Node Labels
PRIMARY_NODE_LABELS = [
    "ThreatActor",
    "Malware",
    "Tool",
    "Vulnerability",
    "Technique",
    "Tactic",
    "Campaign",
    "Software",
    "OperatingSystem",
    "Product",
    "Organization",
    "Indicator",
    "Source"
]

# Supported Relationship Vocabulary
SUPPORTED_RELATIONSHIPS = [
    "USES",
    "USES_TECHNIQUE",
    "EXPLOITS",
    "TARGETS",
    "CONDUCTS",
    "PART_OF",
    "AFFECTS",
    "ASSOCIATED_WITH",
    "SUPPORTED_BY"
]

class SchemaManager:
    def __init__(self, conn=neo4j_conn):
        self.conn = conn

    def initialize_schema(self) -> Dict[str, Any]:
        """
        Creates all uniqueness constraints and secondary indexes in Neo4j.
        Safe to execute repeatedly (idempotent).
        """
        if not self.conn.verify_connectivity():
            raise RuntimeError("Cannot initialize schema: Neo4j database is unreachable.")

        constraints_created = []
        constraints_existed = []
        indexes_created = []
        indexes_existed = []

        # 1. Create Uniqueness Constraints for all primary node labels
        for label in PRIMARY_NODE_LABELS:
            constraint_name = f"constraint_{label.lower()}_id"
            cypher = f"""
            CREATE CONSTRAINT {constraint_name} IF NOT EXISTS
            FOR (n:{label}) REQUIRE n.id IS UNIQUE
            """
            try:
                self.conn.query(cypher)
                constraints_created.append(constraint_name)
            except Exception as e:
                logger.warning(f"Note on constraint {constraint_name}: {e}")
                constraints_existed.append(constraint_name)

        # 2. Create Secondary Indexes for key lookup fields
        index_definitions = [
            ("ThreatActor", "name", "idx_threatactor_name"),
            ("Malware", "name", "idx_malware_name"),
            ("Tool", "name", "idx_tool_name"),
            ("Technique", "name", "idx_technique_name"),
            ("Technique", "external_id", "idx_technique_external_id"),
            ("Tactic", "external_id", "idx_tactic_external_id"),
            ("Vulnerability", "name", "idx_vulnerability_name"),
            ("Source", "url", "idx_source_url"),
            ("Indicator", "value", "idx_indicator_value")
        ]

        for label, property_name, index_name in index_definitions:
            cypher = f"""
            CREATE INDEX {index_name} IF NOT EXISTS
            FOR (n:{label}) ON (n.{property_name})
            """
            try:
                self.conn.query(cypher)
                indexes_created.append(index_name)
            except Exception as e:
                logger.warning(f"Note on index {index_name}: {e}")
                indexes_existed.append(index_name)

        logger.info(f"Schema initialization complete: {len(constraints_created)} constraints, {len(indexes_created)} indexes processed.")
        return {
            "status": "success",
            "primary_labels": PRIMARY_NODE_LABELS,
            "relationships": SUPPORTED_RELATIONSHIPS,
            "constraints": constraints_created,
            "indexes": indexes_created
        }

    def verify_schema(self) -> Dict[str, Any]:
        """
        Queries Neo4j system metadata to verify existing constraints and indexes.
        """
        try:
            constraints_raw = self.conn.query("SHOW CONSTRAINTS")
            indexes_raw = self.conn.query("SHOW INDEXES")
            return {
                "constraints_count": len(constraints_raw),
                "indexes_count": len(indexes_raw),
                "constraints": [c.get("name") for c in constraints_raw],
                "indexes": [i.get("name") for i in indexes_raw]
            }
        except Exception as e:
            logger.error(f"Failed to verify Neo4j schema: {e}")
            return {"error": str(e)}

schema_manager = SchemaManager()
