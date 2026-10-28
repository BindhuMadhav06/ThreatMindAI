from typing import List, Dict, Any, Tuple, Optional
from app.services.graph.connection import neo4j_conn
from app.services.graph.schema_manager import SUPPORTED_RELATIONSHIPS
from app.models.query import (
    ResolvedEntity,
    RetrievalConfig,
    RetrievedEntity,
    RetrievedRelationship,
    EvidenceRecord,
    GraphPath
)
from app.core.logging import logger

class ControlledGraphRetriever:
    """
    Controlled Cyber Threat Knowledge Graph Retriever.
    Executes bounded, parameterized Cypher traversals centered at resolved entities,
    enforcing relationship whitelists, strict provenance validation, and hard retrieval limits.
    """

    def __init__(self, conn=neo4j_conn):
        self.conn = conn

    def retrieve(
        self,
        resolved_entities: List[ResolvedEntity],
        config: RetrievalConfig
    ) -> Tuple[List[RetrievedEntity], List[RetrievedRelationship], List[GraphPath], List[EvidenceRecord], List[Dict[str, Any]], List[str]]:
        if not resolved_entities:
            return [], [], [], [], [], ["No resolved starting entities found for graph traversal."]

        entity_ids = [e.id for e in resolved_entities]
        warnings: List[str] = []

        retrieved_entities_map: Dict[str, RetrievedEntity] = {}
        retrieved_relationships_map: Dict[Tuple[str, str, str], RetrievedRelationship] = {}
        evidence_records_list: List[EvidenceRecord] = []
        sources_map: Dict[str, Dict[str, Any]] = {}
        graph_paths: List[GraphPath] = []

        # 1. Fetch details of all starting resolved entities
        cypher_start_nodes = """
        MATCH (n)
        WHERE n.id IN $entity_ids
        RETURN n.id AS id, labels(n)[0] AS label, n.name AS name,
               n.aliases AS aliases, n.description AS description, properties(n) AS properties
        """
        start_nodes = self.conn.query(cypher_start_nodes, {"entity_ids": entity_ids})
        for node in start_nodes:
            r_ent = RetrievedEntity(
                id=node["id"],
                label=node["label"] or "Entity",
                name=node["name"] or node["id"],
                aliases=node["aliases"] or [],
                description=node["description"],
                properties=node["properties"] or {}
            )
            retrieved_entities_map[r_ent.id] = r_ent

        # 2. Traverse paths from starting entities
        max_depth = min(config.max_depth, 3)  # Hard cap at 3
        max_limit = config.max_relationships * 2

        cypher_paths = f"""
        MATCH (start)
        WHERE start.id IN $entity_ids
        MATCH path = (start)-[r*1..{max_depth}]-(neighbor)
        WHERE NOT neighbor:Source AND all(n IN nodes(path) WHERE NOT n:Source)
          AND all(rel IN relationships(path) WHERE type(rel) IN $allowed_rels)
        WITH path, length(path) AS hop_length, nodes(path) AS p_nodes, relationships(path) AS p_rels
        LIMIT $max_limit
        RETURN 
            hop_length,
            [n IN p_nodes | {{
                id: n.id,
                name: n.name,
                label: labels(n)[0],
                aliases: n.aliases,
                description: n.description,
                properties: properties(n)
            }}] AS path_nodes,
            [rel IN p_rels | {{
                src_id: startNode(rel).id,
                src_name: startNode(rel).name,
                src_label: labels(startNode(rel))[0],
                rel_type: type(rel),
                rel_props: properties(rel),
                tgt_id: endNode(rel).id,
                tgt_name: endNode(rel).name,
                tgt_label: labels(endNode(rel))[0]
            }}] AS path_edges
        """

        try:
            records = self.conn.query(cypher_paths, {
                "entity_ids": entity_ids,
                "allowed_rels": SUPPORTED_RELATIONSHIPS,
                "max_limit": max_limit
            })
        except Exception as e:
            logger.error(f"Error executing graph traversal Cypher: {e}")
            warnings.append(f"Graph traversal error: {str(e)}")
            return list(retrieved_entities_map.values()), [], [], [], [], warnings

        # 3. Process paths, edges, evidence, and provenance
        path_idx = 0
        for row in records:
            hop_length = row["hop_length"]
            raw_nodes = row["path_nodes"] or []
            raw_edges = row["path_edges"] or []

            current_path_nodes: List[RetrievedEntity] = []
            current_path_edges: List[RetrievedRelationship] = []
            path_valid = True

            for edge in raw_edges:
                src_id = edge["src_id"]
                tgt_id = edge["tgt_id"]
                rel_type = edge["rel_type"]
                rel_props = edge["rel_props"] or {}

                # EVIDENCE-FIRST REQUIREMENT: Check for mandatory evidence text
                evidence_text = rel_props.get("evidence_text")
                source_id = rel_props.get("source_id")

                if not evidence_text or not evidence_text.strip():
                    warnings.append(
                        f"EXCLUDED RELATIONSHIP: ({src_id})-[{rel_type}]->({tgt_id}) lacked required evidence_text."
                    )
                    path_valid = False
                    continue

                if not source_id or not source_id.strip():
                    warnings.append(
                        f"EXCLUDED RELATIONSHIP: ({src_id})-[{rel_type}]->({tgt_id}) lacked required source_id."
                    )
                    path_valid = False
                    continue

                # Confidence threshold check
                confidence = rel_props.get("confidence")
                if config.min_confidence is not None and confidence is not None:
                    if confidence < config.min_confidence:
                        warnings.append(
                            f"EXCLUDED RELATIONSHIP: ({src_id})-[{rel_type}]->({tgt_id}) confidence {confidence} < threshold {config.min_confidence}."
                        )
                        path_valid = False
                        continue

                rel_key = (src_id, rel_type, tgt_id)
                if rel_key not in retrieved_relationships_map and len(retrieved_relationships_map) < config.max_relationships:
                    ret_rel = RetrievedRelationship(
                        source_id=src_id,
                        source_name=edge["src_name"] or src_id,
                        source_label=edge["src_label"] or "Entity",
                        rel_type=rel_type,
                        target_id=tgt_id,
                        target_name=edge["tgt_name"] or tgt_id,
                        target_label=edge["tgt_label"] or "Entity",
                        provenance=rel_props
                    )
                    retrieved_relationships_map[rel_key] = ret_rel
                else:
                    ret_rel = retrieved_relationships_map.get(rel_key)

                if ret_rel:
                    current_path_edges.append(ret_rel)

                # Fetch Source node details if not yet cached
                if source_id not in sources_map:
                    cypher_src = "MATCH (s:Source {id: $sid}) RETURN s"
                    src_res = self.conn.query(cypher_src, {"sid": source_id})
                    if src_res:
                        sources_map[source_id] = src_res[0]["s"]

                source_data = sources_map.get(source_id, {})

                # Build EvidenceRecord
                if len(evidence_records_list) < config.max_evidence:
                    ev_rec = EvidenceRecord(
                        source_id=source_id,
                        source_title=source_data.get("title"),
                        source_url=rel_props.get("source_url") or source_data.get("url"),
                        publisher=source_data.get("publisher"),
                        published_date=rel_props.get("published_date") or source_data.get("published_date"),
                        evidence_text=evidence_text,
                        extraction_method=rel_props.get("extraction_method"),
                        confidence=confidence,
                        relationship=f"({edge['src_name']})-[{rel_type}]->({edge['tgt_name']})"
                    )
                    if not any(e.evidence_text == ev_rec.evidence_text and e.relationship == ev_rec.relationship for e in evidence_records_list):
                        evidence_records_list.append(ev_rec)

            if not path_valid:
                continue

            for node in raw_nodes:
                n_id = node["id"]
                if not n_id:
                    continue
                if n_id not in retrieved_entities_map and len(retrieved_entities_map) < config.max_entities:
                    retrieved_entities_map[n_id] = RetrievedEntity(
                        id=n_id,
                        label=node["label"] or "Entity",
                        name=node["name"] or n_id,
                        aliases=node["aliases"] or [],
                        description=node["description"],
                        properties=node["properties"] or {}
                    )
                if n_id in retrieved_entities_map:
                    current_path_nodes.append(retrieved_entities_map[n_id])

            if current_path_edges and len(graph_paths) < 20:
                graph_paths.append(GraphPath(
                    path_id=f"path_{path_idx}",
                    nodes=current_path_nodes,
                    relationships=current_path_edges,
                    length=hop_length
                ))
                path_idx += 1

        logger.info(
            f"Retrieval complete: {len(retrieved_entities_map)} entities, "
            f"{len(retrieved_relationships_map)} relationships, "
            f"{len(evidence_records_list)} evidence records, {len(graph_paths)} paths."
        )

        return (
            list(retrieved_entities_map.values()),
            list(retrieved_relationships_map.values()),
            graph_paths,
            evidence_records_list,
            list(sources_map.values()),
            warnings
        )

graph_retriever = ControlledGraphRetriever()
