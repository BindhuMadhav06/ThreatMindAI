import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.services.graph.schema_manager import schema_manager

def main():
    print("Initializing ThreatMind Neo4j Knowledge Graph Schema...")
    try:
        result = schema_manager.initialize_schema()
        print("Schema Initialization Result:")
        print(f"  Status: {result['status']}")
        print(f"  Primary Node Labels ({len(result['primary_labels'])}): {', '.join(result['primary_labels'])}")
        print(f"  Constraints Configured: {len(result['constraints'])}")
        print(f"  Indexes Configured: {len(result['indexes'])}")
        
        verification = schema_manager.verify_schema()
        print(f"Verified Active Constraints in Neo4j: {verification.get('constraints_count', 0)}")
        print(f"Verified Active Indexes in Neo4j: {verification.get('indexes_count', 0)}")
    except Exception as e:
        print(f"ERROR initializing schema: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
