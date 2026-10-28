import os
import sys
import json
import hashlib
from typing import Dict, Any, List

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from app.services.graph.schema_manager import PRIMARY_NODE_LABELS, SUPPORTED_RELATIONSHIPS

def validate_dataset(dataset_dir: str = None) -> bool:
    if not dataset_dir:
        dataset_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "evaluation"))

    print(f"==================================================")
    print(f"ThreatMind CTI Evaluation Dataset Validation")
    print(f"Target Directory: {dataset_dir}")
    print(f"==================================================")

    errors: List[str] = []
    warnings: List[str] = []

    # 1. Validate Manifest
    manifest_path = os.path.join(dataset_dir, "dataset_manifest.json")
    if not os.path.isfile(manifest_path):
        errors.append(f"Missing manifest file: {manifest_path}")
        print("\n".join(f"[ERROR] {e}" for e in errors))
        return False

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    if manifest.get("is_synthetic") is not False:
        errors.append("Dataset manifest must declare 'is_synthetic: false'.")

    docs_dir = os.path.join(dataset_dir, "documents")
    if not os.path.isdir(docs_dir):
        errors.append(f"Missing documents directory: {docs_dir}")
        print("\n".join(f"[ERROR] {e}" for e in errors))
        return False

    loaded_docs: Dict[str, Dict[str, Any]] = {}
    for doc_meta in manifest.get("documents", []):
        filename = doc_meta["filename"]
        doc_path = os.path.join(docs_dir, filename)
        if not os.path.isfile(doc_path):
            errors.append(f"Document file missing: {doc_path}")
            continue

        with open(doc_path, "rb") as fp:
            file_bytes = fp.read()
            computed_hash = hashlib.sha256(file_bytes).hexdigest()

        if computed_hash != doc_meta["sha256_hash"]:
            errors.append(f"SHA-256 hash mismatch for {filename}: expected {doc_meta['sha256_hash']}, got {computed_hash}")

        with open(doc_path, "r", encoding="utf-8") as fp:
            doc_data = json.load(fp)

        if doc_data.get("is_synthetic") is not False:
            errors.append(f"Document {doc_meta['source_id']} must have is_synthetic=false")

        if not doc_data.get("raw_text") or len(doc_data["raw_text"]) == 0:
            errors.append(f"Document {doc_meta['source_id']} has empty raw_text")

        loaded_docs[doc_meta["source_id"]] = doc_data

    print(f"[*] Verified {len(loaded_docs)} source documents and SHA-256 integrity hashes.")

    # 2. Validate Entity Annotations
    entities_path = os.path.join(dataset_dir, "annotations", "entities.json")
    if not os.path.isfile(entities_path):
        errors.append(f"Missing entities annotations: {entities_path}")
    else:
        with open(entities_path, "r", encoding="utf-8") as fp:
            entities_blob = json.load(fp)

        entity_ids = set()
        for idx, ent in enumerate(entities_blob.get("entities", [])):
            e_id = ent.get("id")
            if not e_id:
                errors.append(f"Entity at index {idx} has missing 'id'")
            elif e_id in entity_ids:
                errors.append(f"Duplicate entity ID found: {e_id}")
            entity_ids.add(e_id)

            label = ent.get("label")
            if label not in PRIMARY_NODE_LABELS:
                errors.append(f"Entity {e_id} has invalid label '{label}' not in PRIMARY_NODE_LABELS")

            src_id = ent.get("source_id")
            if src_id not in loaded_docs:
                errors.append(f"Entity {e_id} references unknown source_id '{src_id}'")
                continue

            raw = loaded_docs[src_id]["raw_text"]
            mention = ent.get("mention_text", "")
            s_char = ent.get("start_char", -1)
            e_char = ent.get("end_char", -1)

            if s_char < 0 or e_char <= s_char or e_char > len(raw):
                errors.append(f"Entity {e_id} character bounds invalid: [{s_char}, {e_char}] (doc len {len(raw)})")
            elif raw[s_char:e_char] != mention:
                errors.append(
                    f"Entity {e_id} mention mismatch at [{s_char}:{e_char}]: "
                    f"expected '{mention}', found '{raw[s_char:e_char]}'"
                )

        print(f"[*] Verified {len(entities_blob.get('entities', []))} entity annotations and text spans.")

    # 3. Validate Relationship Annotations
    rels_path = os.path.join(dataset_dir, "annotations", "relationships.json")
    if not os.path.isfile(rels_path):
        errors.append(f"Missing relationships annotations: {rels_path}")
    else:
        with open(rels_path, "r", encoding="utf-8") as fp:
            rels_blob = json.load(fp)

        rel_ids = set()
        for idx, rel in enumerate(rels_blob.get("relationships", [])):
            r_id = rel.get("id")
            if not r_id:
                errors.append(f"Relationship at index {idx} has missing 'id'")
            elif r_id in rel_ids:
                errors.append(f"Duplicate relationship ID: {r_id}")
            rel_ids.add(r_id)

            rel_type = rel.get("rel_type")
            if rel_type not in SUPPORTED_RELATIONSHIPS:
                errors.append(f"Relationship {r_id} has unsupported type '{rel_type}'")

            src_doc_id = rel.get("document_source_id")
            if src_doc_id not in loaded_docs:
                errors.append(f"Relationship {r_id} references unknown document_source_id '{src_doc_id}'")
                continue

            raw = loaded_docs[src_doc_id]["raw_text"]
            quote = rel.get("verbatim_evidence_quote", "")
            c_start = rel.get("char_start", -1)
            c_end = rel.get("char_end", -1)

            if not quote:
                errors.append(f"Relationship {r_id} has empty verbatim_evidence_quote")
            elif c_start < 0 or c_end <= c_start or c_end > len(raw):
                errors.append(f"Relationship {r_id} quote bounds invalid: [{c_start}, {c_end}]")
            elif raw[c_start:c_end] != quote:
                errors.append(
                    f"Relationship {r_id} quote mismatch at [{c_start}:{c_end}]: "
                    f"expected '{quote[:30]}...', found '{raw[c_start:c_end][:30]}...'"
                )

        print(f"[*] Verified {len(rels_blob.get('relationships', []))} relationship annotations with verbatim quotes.")

    # 4. Validate Queries & Ground Truth Alignment
    queries_path = os.path.join(dataset_dir, "queries.json")
    gt_path = os.path.join(dataset_dir, "ground_truth.json")

    if not os.path.isfile(queries_path):
        errors.append(f"Missing queries.json: {queries_path}")
    if not os.path.isfile(gt_path):
        errors.append(f"Missing ground_truth.json: {gt_path}")

    if os.path.isfile(queries_path) and os.path.isfile(gt_path):
        with open(queries_path, "r", encoding="utf-8") as fp:
            queries_blob = json.load(fp)
        with open(gt_path, "r", encoding="utf-8") as fp:
            gt_blob = json.load(fp)

        query_ids = {q["query_id"] for q in queries_blob.get("queries", [])}
        gt_ids = set(gt_blob.get("ground_truth", {}).keys())

        if query_ids != gt_ids:
            diff_q = query_ids - gt_ids
            diff_gt = gt_ids - query_ids
            if diff_q:
                errors.append(f"Queries missing from ground_truth: {diff_q}")
            if diff_gt:
                errors.append(f"Ground truth has unreferenced query IDs: {diff_gt}")

        print(f"[*] Verified {len(query_ids)} queries with 1-to-1 ground truth alignment.")

    # 5. Check Contamination with Synthetic Demo Fixture
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sample", "demo_synthetic_cti.json"))
    if os.path.isfile(demo_path):
        with open(demo_path, "r", encoding="utf-8") as fp:
            demo_blob = json.load(fp)
        demo_src_ids = {s["id"] for s in demo_blob.get("sources", [])}
        demo_node_ids = {n["properties"]["id"] for n in demo_blob.get("nodes", [])}

        eval_src_ids = set(loaded_docs.keys())
        eval_node_ids = {e["id"] for e in entities_blob.get("entities", [])} if os.path.isfile(entities_path) else set()

        overlap_src = demo_src_ids.intersection(eval_src_ids)
        overlap_nodes = demo_node_ids.intersection(eval_node_ids)

        if overlap_src:
            errors.append(f"Contamination detected! Overlapping source IDs with demo synthetic data: {overlap_src}")
        if overlap_nodes:
            errors.append(f"Contamination detected! Overlapping node IDs with demo synthetic data: {overlap_nodes}")

        print(f"[*] Verified zero ID contamination with demo synthetic fixture.")

    # Report Summary
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  [WARN] {w}")

    if errors:
        print(f"\nValidation FAILED with {len(errors)} error(s):")
        for e in errors:
            print(f"  [FAIL] {e}")
        return False

    print("\nDataset Validation PASSED: All integrity constraints satisfied!")
    return True

if __name__ == "__main__":
    success = validate_dataset()
    sys.exit(0 if success else 1)
