import os
import sys
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from app.evaluation.isolation import cleanup_evaluation_graph

def main():
    parser = argparse.ArgumentParser(description="Clean up ThreatMind evaluation data from Neo4j.")
    parser.add_argument("--restore-demo", action="store_true", help="Restore synthetic demo fixture after cleanup.")
    args = parser.parse_args()

    print("Executing ThreatMind Evaluation Graph Cleanup...")
    deleted = cleanup_evaluation_graph()
    print(f"Successfully deleted {deleted} evaluation nodes and their connected edges.")

    if args.restore_demo:
        print("Restoring synthetic demo fixture...")
        from seed_demo_data import seed_demo_data
        seed_demo_data()
        print("Synthetic demo fixture restored.")

if __name__ == "__main__":
    main()
