"""
Neo4j Graph Persistence and ACID Transaction Manager for STIX 2.1 Objects
Handles atomic database mutations, parameterized Cypher generation,
and isolated dry-run graph verification.
"""

from typing import Any, Dict, List, Optional, Set
from app.services.graph.connection import neo4j_conn
from app.services.graph.schema_manager import (
    PRIMARY_NODE_LABELS,
    STIX_NODE_LABELS,
    SUPPORTED_RELATIONSHIPS,
    STIX_SUPPORTED_RELATIONSHIPS,
)
from app.core.logging import logger

VALID_LABELS_LOWER: Dict[str, str] = {lbl.lower(): lbl for lbl in STIX_NODE_LABELS}
VALID_RELS_LOWER: Dict[str, str] = {rel.lower(): rel for rel in STIX_SUPPORTED_RELATIONSHIPS}


class StixGraphService:
    """
    Manages persistent Neo4j transactions for STIX SDOs, SROs, and Marking Definitions.
    """

    def __init__(self, conn=neo4j_conn):
        self.conn = conn

    def validate_label(self, label: str) -> str:
        canonical = VALID_LABELS_LOWER.get(label.lower())
        if not canonical:
            raise ValueError(f"Invalid entity label '{label}'. Allowed: {PRIMARY_NODE_LABELS}")
        return canonical

    def validate_rel_type(self, rel_type: str) -> str:
        canonical = VALID_RELS_LOWER.get(rel_type.lower())
        if not canonical:
            raise ValueError(f"Invalid relationship type '{rel_type}'. Allowed: {SUPPORTED_RELATIONSHIPS}")
        return canonical

    def is_connected(self) -> bool:
        return self.conn.verify_connectivity()

    def get_graph_snapshot(self) -> Dict[str, Any]:
        """
        Retrieves a canonical snapshot of the active graph state:
        - Sorted node records (id, labels, properties)
        - Sorted edge records (id, type, source, target, properties)
        Used for strict AC-11 dry-run state equality and AC-12 rollback assertions.
        """
        if not self.is_connected():
            return {"nodes": [], "relationships": []}

        nodes_query = """
        MATCH (n)
        RETURN n.id AS id, labels(n) AS labels, properties(n) AS props
        ORDER BY n.id
        """
        edges_query = """
        MATCH (a)-[r]->(b)
        RETURN coalesce(r.id, a.id + '->' + type(r) + '->' + b.id) AS id,
               type(r) AS type, a.id AS source, b.id AS target, properties(r) AS props
        ORDER BY id
        """
        nodes = self.conn.query(nodes_query)
        edges = self.conn.query(edges_query)
        return {
            "nodes": nodes,
            "relationships": edges,
        }

    def persist_bundle_transaction(
        self,
        nodes: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        """
        Executes a real atomic ACID transaction in Neo4j:
        - Idempotently merges all staged SDO nodes, labels, and properties.
        - Idempotently merges all staged SRO relationship edges with embedded STIX provenance.
        - On any constraint violation or unexpected exception, automatically rolls back.
        """
        if not self.is_connected():
            raise RuntimeError("Cannot persist STIX bundle: Neo4j database is unreachable.")

        nodes_written = 0
        edges_written = 0

        with self.conn.transaction() as tx:
            # Step 1: Persist Nodes
            for node_data in nodes:
                labels = node_data.get("labels", ["Entity"])
                primary_label = self.validate_label(labels[0])
                properties = dict(node_data.get("properties", {}))
                node_id = properties.get("id") or properties.get("stix_id")
                if not node_id:
                    raise ValueError("Node must have an 'id' or 'stix_id' property.")

                # Base MERGE query on primary label
                cypher_node = f"""
                MERGE (n:{primary_label} {{id: $id}})
                SET n += $props
                """
                tx.run(cypher_node, {"id": node_id, "props": properties})

                # Apply secondary labels if any (e.g. :Organization on :Identity)
                for secondary in labels[1:]:
                    sec_label = self.validate_label(secondary)
                    tx.run(f"MATCH (n:{primary_label} {{id: $id}}) SET n:{sec_label}", {"id": node_id})

                nodes_written += 1

            # Step 2: Persist Relationship Edges
            for edge_data in relationships:
                rel_id = edge_data.get("id")
                rel_type = self.validate_rel_type(edge_data.get("relationship_type"))
                source_ref = edge_data.get("source_ref")
                target_ref = edge_data.get("target_ref")

                edge_props = {
                    "id": rel_id,
                    "stix_id": rel_id,
                    "created": edge_data.get("created"),
                    "modified": edge_data.get("modified"),
                    "confidence": edge_data.get("confidence"),
                }
                if edge_data.get("object_marking_refs"):
                    edge_props["object_marking_refs"] = edge_data["object_marking_refs"]

                cypher_edge = f"""
                MATCH (a {{id: $source_ref}})
                MATCH (b {{id: $target_ref}})
                MERGE (a)-[r:{rel_type} {{id: $rel_id}}]->(b)
                SET r += $props
                """
                tx.run(cypher_edge, {
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "rel_id": rel_id,
                    "props": edge_props,
                })
                edges_written += 1

        logger.info(f"Committed STIX ACID transaction: {nodes_written} nodes, {edges_written} relationships.")
        return {
            "nodes_written": nodes_written,
            "relationships_written": edges_written,
        }
