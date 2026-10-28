from typing import Dict, List, Any, Optional
from app.services.graph.connection import neo4j_conn
from app.services.graph.schema_manager import PRIMARY_NODE_LABELS, SUPPORTED_RELATIONSHIPS
from app.core.logging import logger

class GraphRepository:
    def __init__(self, conn=neo4j_conn):
        self.conn = conn

    def _validate_label(self, label: str) -> str:
        # Match case-insensitively to primary node labels
        for valid in PRIMARY_NODE_LABELS:
            if valid.lower() == label.lower():
                return valid
        raise ValueError(f"Invalid entity label '{label}'. Allowed labels: {PRIMARY_NODE_LABELS}")

    def _validate_rel_type(self, rel_type: str) -> str:
        for valid in SUPPORTED_RELATIONSHIPS:
            if valid.lower() == rel_type.lower():
                return valid
        raise ValueError(f"Invalid relationship type '{rel_type}'. Allowed types: {SUPPORTED_RELATIONSHIPS}")

    def create_or_update_entity(self, label: str, properties: Dict[str, Any]) -> Dict[str, Any]:
        """
        Idempotently creates or updates an entity node in Neo4j matching on `id`.
        Uses 100% parameterized Cypher.
        """
        valid_label = self._validate_label(label)
        if "id" not in properties or not properties["id"]:
            raise ValueError("Entity properties must include a non-empty 'id'.")

        cypher = f"""
        MERGE (n:{valid_label} {{id: $id}})
        SET n += $props
        RETURN n, labels(n) as node_labels
        """
        result = self.conn.query(cypher, {"id": properties["id"], "props": properties})
        if not result:
            raise RuntimeError(f"Failed to create/update entity {valid_label} with ID {properties['id']}")
        
        node_data = result[0]["n"]
        return node_data

    def get_entity_by_id(self, label: str, entity_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves an entity node by its label and unique ID.
        """
        valid_label = self._validate_label(label)
        cypher = f"MATCH (n:{valid_label} {{id: $id}}) RETURN n"
        result = self.conn.query(cypher, {"id": entity_id})
        return result[0]["n"] if result else None

    def find_entity_by_name(self, label: str, name: str) -> List[Dict[str, Any]]:
        """
        Searches for entities by name (case-insensitive substring).
        """
        valid_label = self._validate_label(label)
        cypher = f"MATCH (n:{valid_label}) WHERE toLower(n.name) CONTAINS toLower($name) RETURN n"
        result = self.conn.query(cypher, {"name": name})
        return [record["n"] for record in result]

    def create_relationship(
        self,
        source_id: str,
        source_label: str,
        rel_type: str,
        target_id: str,
        target_label: str,
        provenance: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Idempotently creates a typed relationship between source and target entities
        with mandatory provenance metadata embedded on the edge.
        """
        v_source_label = self._validate_label(source_label)
        v_target_label = self._validate_label(target_label)
        v_rel_type = self._validate_rel_type(rel_type)

        provenance_data = {
            "source_id": provenance.get("source_id") if provenance else None,
            "source_url": provenance.get("source_url") if provenance else None,
            "evidence_text": provenance.get("evidence_text") if provenance else None,
            "published_date": provenance.get("published_date") if provenance else None,
            "extraction_method": provenance.get("extraction_method") if provenance else "manual_extraction",
            "confidence": provenance.get("confidence") if provenance and provenance.get("confidence") is not None else None
        }

        cypher = f"""
        MATCH (a:{v_source_label} {{id: $source_id}})
        MATCH (b:{v_target_label} {{id: $target_id}})
        MERGE (a)-[r:{v_rel_type}]->(b)
        SET r += $prov
        RETURN a.id AS source, type(r) AS rel, b.id AS target, properties(r) AS provenance
        """
        result = self.conn.query(cypher, {
            "source_id": source_id,
            "target_id": target_id,
            "prov": provenance_data
        })

        if not result:
            raise RuntimeError(f"Could not create relationship ({source_id})-[{v_rel_type}]->({target_id}). Ensure both nodes exist.")

        # Link entity nodes to Source node via SUPPORTED_BY if source_id is present
        if provenance_data["source_id"]:
            supp_cypher = f"""
            MATCH (e) WHERE e.id IN [$source_id, $target_id]
            MATCH (s:Source {{id: $s_id}})
            MERGE (e)-[:SUPPORTED_BY]->(s)
            """
            try:
                self.conn.query(supp_cypher, {
                    "source_id": source_id,
                    "target_id": target_id,
                    "s_id": provenance_data["source_id"]
                })
            except Exception as e:
                logger.warning(f"Note linking entity to Source: {e}")

        return result[0]

    def get_relationship_evidence(self, source_id: str, target_id: str, rel_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Answers 'Why does ThreatMind believe this relationship exists?'
        Returns exact edge properties, evidence text, source URL, and Source details.
        """
        rel_clause = f"[r:{rel_type}]" if rel_type else "[r]"
        cypher = f"""
        MATCH (a {{id: $source_id}})-{rel_clause}->(b {{id: $target_id}})
        OPTIONAL MATCH (s:Source {{id: r.source_id}})
        RETURN a.id AS source_id, labels(a) AS source_labels,
               type(r) AS relationship,
               b.id AS target_id, labels(b) AS target_labels,
               properties(r) AS provenance,
               s.title AS source_title, s.url AS source_url, s.publisher AS publisher
        """
        result = self.conn.query(cypher, {"source_id": source_id, "target_id": target_id})
        return result

    def get_neighbors(self, entity_id: str, max_hops: int = 1) -> List[Dict[str, Any]]:
        """
        Retrieves 1 to max_hops neighborhood graph centered at entity_id.
        """
        cypher = f"""
        MATCH path = (a {{id: $entity_id}})-[r*1..{max_hops}]-(b)
        RETURN path
        """
        result = self.conn.query(cypher, {"entity_id": entity_id})
        return result

    def get_graph_stats(self) -> Dict[str, Any]:
        """
        Returns genuine counts of nodes by label, relationships, and sources.
        """
        label_counts_cypher = """
        MATCH (n)
        RETURN labels(n)[0] AS label, count(n) AS cnt
        """
        label_res = self.conn.query(label_counts_cypher)
        counts_by_label: Dict[str, int] = {}
        total_nodes = 0
        total_sources = 0

        for row in label_res:
            lbl = row.get("label") or "Unknown"
            cnt = row.get("cnt") or 0
            counts_by_label[lbl] = cnt
            total_nodes += cnt
            if lbl == "Source":
                total_sources = cnt

        rel_count_cypher = "MATCH ()-[r]->() RETURN count(r) AS cnt"
        rel_res = self.conn.query(rel_count_cypher)
        total_relationships = rel_res[0].get("cnt", 0) if rel_res else 0

        return {
            "total_nodes": total_nodes,
            "total_relationships": total_relationships,
            "total_sources": total_sources,
            "node_counts_by_label": counts_by_label
        }

    def get_entities(
        self,
        label: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Returns bounded, deterministic list of graph entities.
        Restricts label to PRIMARY_NODE_LABELS and enforces hard limit max 100.
        """
        bounded_limit = max(1, min(limit, 100))
        params: Dict[str, Any] = {"limit": bounded_limit, "search": search}

        if label:
            valid_label = self._validate_label(label)
            cypher = f"""
            MATCH (n:{valid_label})
            WHERE ($search IS NULL OR toLower(n.name) CONTAINS toLower($search) OR toLower(n.id) CONTAINS toLower($search))
            RETURN n.id AS id, labels(n)[0] AS label, n.name AS name,
                   n.description AS description, properties(n) AS properties
            ORDER BY n.name ASC
            LIMIT $limit
            """
        else:
            cypher = """
            MATCH (n)
            WHERE NOT n:Source AND ($search IS NULL OR toLower(n.name) CONTAINS toLower($search) OR toLower(n.id) CONTAINS toLower($search))
            RETURN n.id AS id, labels(n)[0] AS label, n.name AS name,
                   n.description AS description, properties(n) AS properties
            ORDER BY n.name ASC
            LIMIT $limit
            """

        records = self.conn.query(cypher, params)
        entities = []
        for r in records:
            props = r.get("properties") or {}
            entities.append({
                "id": r["id"],
                "label": r["label"] or "Entity",
                "name": r["name"] or r["id"],
                "description": r.get("description"),
                "aliases": props.get("aliases", []),
                "is_synthetic": bool(props.get("is_synthetic", False)),
                "properties": props
            })
        return entities

    def get_entity_with_neighbors(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """
        Returns an entity's properties and bounded 1-hop neighbors with edge provenance.
        """
        cypher_entity = """
        MATCH (n {id: $entity_id})
        RETURN n.id AS id, labels(n)[0] AS label, n.name AS name,
               n.description AS description, properties(n) AS properties
        """
        res_entity = self.conn.query(cypher_entity, {"entity_id": entity_id})
        if not res_entity:
            return None

        e_row = res_entity[0]
        e_props = e_row.get("properties") or {}

        cypher_neighbors = """
        MATCH (n {id: $entity_id})-[r]-(m)
        WHERE NOT m:Source
        RETURN
          startNode(r).id AS src_id,
          startNode(r).name AS src_name,
          labels(startNode(r))[0] AS src_label,
          type(r) AS rel_type,
          endNode(r).id AS tgt_id,
          endNode(r).name AS tgt_name,
          labels(endNode(r))[0] AS tgt_label,
          properties(r) AS provenance,
          m.id AS neighbor_id,
          m.name AS neighbor_name,
          labels(m)[0] AS neighbor_label,
          properties(m) AS neighbor_props
        LIMIT 50
        """
        records = self.conn.query(cypher_neighbors, {"entity_id": entity_id})

        neighbors = []
        relationships = []
        seen_neighbors = set()

        for row in records:
            nbr_id = row["neighbor_id"]
            if nbr_id and nbr_id not in seen_neighbors:
                seen_neighbors.add(nbr_id)
                nbr_props = row.get("neighbor_props") or {}
                neighbors.append({
                    "id": nbr_id,
                    "label": row["neighbor_label"] or "Entity",
                    "name": row["neighbor_name"] or nbr_id,
                    "is_synthetic": bool(nbr_props.get("is_synthetic", False)),
                    "properties": nbr_props
                })

            prov = row.get("provenance") or {}
            relationships.append({
                "source_id": row["src_id"],
                "source_name": row["src_name"] or row["src_id"],
                "source_label": row["src_label"] or "Entity",
                "rel_type": row["rel_type"],
                "target_id": row["tgt_id"],
                "target_name": row["tgt_name"] or row["tgt_id"],
                "target_label": row["tgt_label"] or "Entity",
                "provenance": prov,
                "is_synthetic": bool(prov.get("is_synthetic", False) or e_props.get("is_synthetic", False))
            })

        return {
            "entity": {
                "id": e_row["id"],
                "label": e_row["label"] or "Entity",
                "name": e_row["name"] or e_row["id"],
                "description": e_row.get("description"),
                "aliases": e_props.get("aliases", []),
                "is_synthetic": bool(e_props.get("is_synthetic", False)),
                "properties": e_props
            },
            "neighbors": neighbors,
            "relationships": relationships
        }

    def delete_all_data(self) -> Dict[str, Any]:
        """
        Deletes all nodes and relationships in the Neo4j database (for testing/resets).
        """
        self.conn.query("MATCH (n) DETACH DELETE n")
        logger.info("Cleared all nodes and relationships from Neo4j graph.")
        return {"status": "cleared"}

graph_repository = GraphRepository()
