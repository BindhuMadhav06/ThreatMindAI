import os
import json
from typing import Dict, Any, List
from app.services.graph.repository import graph_repository
from app.services.graph.schema_manager import schema_manager
from app.core.logging import logger

def seed_evaluation_graph(dataset_dir: str = None) -> Dict[str, int]:
    """
    Seeds the Neo4j knowledge graph with the authentic CTI evaluation dataset.
    All seeded nodes and edges have is_synthetic = False and eval prefixes.
    """
    if not dataset_dir:
        dataset_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "evaluation"))

    logger.info(f"Seeding evaluation graph from {dataset_dir}")
    schema_manager.initialize_schema()

    # Clear existing graph to enforce evaluation isolation
    graph_repository.conn.query("MATCH (n) DETACH DELETE n")

    # 1. Ingest Sources
    docs_dir = os.path.join(dataset_dir, "documents")
    docs_seeded = 0
    docs_map = {}
    for f in sorted(os.listdir(docs_dir)):
        if f.endswith(".json"):
            with open(os.path.join(docs_dir, f), "r", encoding="utf-8") as fp:
                doc = json.load(fp)
            docs_map[doc["source_id"]] = doc
            src_props = {
                "id": doc["source_id"],
                "title": doc["title"],
                "url": doc["url"],
                "publisher": doc["publisher"],
                "published_date": doc["published_date"],
                "source_type": "official_cti_advisory",
                "is_synthetic": False
            }
            graph_repository.create_or_update_entity("Source", src_props)
            docs_seeded += 1

    # 2. Ingest Entities
    entities_path = os.path.join(dataset_dir, "annotations", "entities.json")
    with open(entities_path, "r", encoding="utf-8") as fp:
        entities_data = json.load(fp).get("entities", [])

    entities_seeded = 0
    for ent in entities_data:
        props = {
            "id": ent["id"],
            "name": ent["name"],
            "aliases": ent.get("aliases", []),
            "description": f"Real CTI entity documented in {ent['source_id']}",
            "is_synthetic": False
        }
        graph_repository.create_or_update_entity(ent["label"], props)
        entities_seeded += 1

    # 3. Ingest Relationships with Provenance
    rels_path = os.path.join(dataset_dir, "annotations", "relationships.json")
    with open(rels_path, "r", encoding="utf-8") as fp:
        rels_data = json.load(fp).get("relationships", [])

    rels_seeded = 0
    for rel in rels_data:
        doc_src = docs_map.get(rel["document_source_id"], {})
        provenance = {
            "source_id": rel["document_source_id"],
            "source_url": doc_src.get("url", ""),
            "evidence_text": rel["verbatim_evidence_quote"],
            "published_date": doc_src.get("published_date", ""),
            "confidence": rel.get("confidence", 1.0),
            "is_synthetic": False
        }
        graph_repository.create_relationship(
            source_id=rel["source_id"],
            source_label=rel["source_label"],
            rel_type=rel["rel_type"],
            target_id=rel["target_id"],
            target_label=rel["target_label"],
            provenance=provenance
        )
        rels_seeded += 1

    logger.info(f"Evaluation graph seeded: {docs_seeded} sources, {entities_seeded} entities, {rels_seeded} relationships.")
    return {
        "sources_seeded": docs_seeded,
        "entities_seeded": entities_seeded,
        "relationships_seeded": rels_seeded
    }

def cleanup_evaluation_graph() -> int:
    """
    Selectively removes all evaluation nodes and relationships without modifying schema constraints.
    Targets nodes starting with 'eval_' or 'cisa_' or 'mitre_' or having is_synthetic = False.
    """
    logger.info("Cleaning up evaluation nodes and edges from Neo4j...")
    query = """
    MATCH (n)
    WHERE n.id STARTS WITH 'eval_' 
       OR n.id STARTS WITH 'cisa_' 
       OR n.id STARTS WITH 'mitre_'
       OR n.is_synthetic = false
    OPTIONAL MATCH (n)-[r]-()
    DELETE r, n
    RETURN count(n) AS deleted_nodes
    """
    records = graph_repository.conn.query(query)
    deleted = records[0]["deleted_nodes"] if records else 0

    logger.info(f"Cleaned up {deleted} evaluation nodes and their connected edges.")
    return deleted
