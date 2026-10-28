import os
import sys
import json
import pytest
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from scripts.validate_dataset import validate_dataset

EVAL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "evaluation"))

def test_evaluation_dataset_passes_validation():
    """Verify that the official real CTI evaluation dataset passes all validation constraints."""
    assert os.path.isdir(EVAL_DIR), f"Evaluation directory missing: {EVAL_DIR}"
    assert validate_dataset(EVAL_DIR) is True

def test_validation_detects_synthetic_contamination():
    """Verify that setting is_synthetic=True on an evaluation document triggers validation failure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Copy eval dir to tmpdir
        shutil.copytree(EVAL_DIR, os.path.join(tmpdir, "evaluation"))
        test_dir = os.path.join(tmpdir, "evaluation")

        # Corrupt one document to declare is_synthetic = True
        doc_path = os.path.join(test_dir, "documents", "cisa_aa21_356a.json")
        with open(doc_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["is_synthetic"] = True
        with open(doc_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Update manifest hash so hash check passes but synthetic check catches it
        import hashlib
        h = hashlib.sha256(open(doc_path, "rb").read()).hexdigest()
        manifest_path = os.path.join(test_dir, "dataset_manifest.json")
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        for d in manifest["documents"]:
            if d["filename"] == "cisa_aa21_356a.json":
                d["sha256_hash"] = h
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f)

        assert validate_dataset(test_dir) is False

def test_validation_detects_quote_mismatch():
    """Verify that altering an evidence quote triggers a validation error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        shutil.copytree(EVAL_DIR, os.path.join(tmpdir, "evaluation"))
        test_dir = os.path.join(tmpdir, "evaluation")

        rels_path = os.path.join(test_dir, "annotations", "relationships.json")
        with open(rels_path, "r", encoding="utf-8") as f:
            rels_blob = json.load(f)

        # Corrupt first quote
        rels_blob["relationships"][0]["verbatim_evidence_quote"] = "Non-existent fabricated quote text here."
        with open(rels_path, "w", encoding="utf-8") as f:
            json.dump(rels_blob, f)

        assert validate_dataset(test_dir) is False

def test_validation_detects_unsupported_relationship_type():
    """Verify that an unsupported relationship type triggers a validation failure."""
    with tempfile.TemporaryDirectory() as tmpdir:
        shutil.copytree(EVAL_DIR, os.path.join(tmpdir, "evaluation"))
        test_dir = os.path.join(tmpdir, "evaluation")

        rels_path = os.path.join(test_dir, "annotations", "relationships.json")
        with open(rels_path, "r", encoding="utf-8") as f:
            rels_blob = json.load(f)

        rels_blob["relationships"][0]["rel_type"] = "INVALID_FABRICATED_RELATION"
        with open(rels_path, "w", encoding="utf-8") as f:
            json.dump(rels_blob, f)

        assert validate_dataset(test_dir) is False
