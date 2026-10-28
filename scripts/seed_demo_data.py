import json
import os
import sys

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.services.graph.schema_manager import schema_manager
from app.services.graph.repository import graph_repository

def seed_demo_data():
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample", "demo_synthetic_cti.json")
    if not os.path.exists(dataset_path):
        print(f"Error: Demo dataset file not found at {dataset_path}")
        sys.exit(1)

    print("Step 1: Initializing Neo4j Schema...")
    schema_manager.initialize_schema()

    print(f"\nStep 2: Loading Synthetic Demo CTI Dataset from {dataset_path}...")
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    meta = data.get("metadata", {})
    print(f"Dataset: {meta.get('dataset_name')}")
    print(f"Disclaimer: {meta.get('disclaimer')}")

    # 1. Seed Source Nodes
    sources = data.get("sources", [])
    for src in sources:
        graph_repository.create_or_update_entity("Source", src)
    print(f"Seeded {len(sources)} Source nodes.")

    # 2. Seed Primary Entity Nodes
    nodes = data.get("nodes", [])
    for node in nodes:
        label = node["label"]
        props = node["properties"]
        graph_repository.create_or_update_entity(label, props)
    print(f"Seeded {len(nodes)} Entity nodes.")

    # 3. Seed Relationships with Provenance
    relationships = data.get("relationships", [])
    for rel in relationships:
        graph_repository.create_relationship(
            source_id=rel["source_id"],
            source_label=rel["source_label"],
            rel_type=rel["rel_type"],
            target_id=rel["target_id"],
            target_label=rel["target_label"],
            provenance=rel.get("provenance")
        )
    print(f"Seeded {len(relationships)} Relationships with edge provenance metadata.")

    print("\nSynthetic Demo Data Seeding Complete!")

if __name__ == "__main__":
    seed_demo_data()
