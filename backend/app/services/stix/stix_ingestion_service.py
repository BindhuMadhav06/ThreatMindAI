"""
Two-Pass STIX 2.1 Ingestion and Transactional Resolution Service
Enforces strict OASIS STIX 2.1 schema validation, 4-way tuple classification,
SCO auditing, fail-closed marking resolution, and full provenance tracking.
"""

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import ValidationError, TypeAdapter

from app.models.stix import (
    FirstTlpExtensionData,
    StixBundle,
    StixExtensionDefinition,
    StixMarkingDefinition,
    StixRelationship,
    SupportedStixSdo,
)
from app.services.stix.stix_entity_mapper import StixEntityMapper
from app.services.stix.stix_graph_service import StixGraphService

# Set of standard STIX 2.1 Cyber-observable Object (SCO) prefixes
STANDARD_SCO_TYPES: Set[str] = {
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
}

# Standard unsupported SDO types
STANDARD_UNSUPPORTED_SDOS: Set[str] = {
    "opinion",
    "note",
    "sighting",
    "grouping",
    "observed-data",
    "malware-analysis",
    "language-content",
}


class StixIngestionService:
    """
    Two-Pass Transactional Ingestion Pipeline for STIX 2.1 Bundles.
    """

    def __init__(
        self,
        registry_path: Optional[Path] = None,
        graph_service: Optional[StixGraphService] = None,
    ):
        if registry_path is None:
            registry_path = Path(__file__).resolve().parent / "relationship_registry.json"

        with open(registry_path, "r", encoding="utf-8") as f:
            registry_data = json.load(f)

        # Parse supported relationships: set of (source_type, rel_type, target_type)
        self.supported_tuples: Set[Tuple[str, str, str]] = set()
        for rel_type, pair_list in registry_data.get("supported_relationships", {}).items():
            for src, tgt in pair_list:
                self.supported_tuples.add((src, rel_type, tgt))

        # Parse standard unsupported tuples: set of (source_type, rel_type, target_type)
        self.standard_unsupported_tuples: Set[Tuple[str, str, str]] = set()
        for src, rel_type, tgt in registry_data.get("standard_unsupported_tuples", []):
            self.standard_unsupported_tuples.add((src, rel_type, tgt))

        # Parse registered custom relationships: set of (source_type, rel_type, target_type)
        self.registered_custom_tuples: Set[Tuple[str, str, str]] = set()
        for src, rel_type, tgt in registry_data.get("registered_custom_relationships", []):
            self.registered_custom_tuples.add((src, rel_type, tgt))

        # Entity mapper and storage
        self.mapper = StixEntityMapper()
        # Stored relationships: list of {edge dict}
        self.stored_relationships: List[Dict[str, Any]] = []
        # Keyed relationships for deduplication: (src, rel_type, tgt) -> edge dict
        self.relationships_by_key: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        # Graph persistence engine
        self.graph_service = graph_service or StixGraphService()

        # Pydantic TypeAdapter for discriminating SupportedStixSdo
        self.sdo_adapter = TypeAdapter(SupportedStixSdo)

    def _get_type_from_stix_id(self, stix_id: str) -> str:
        """Extracts the type prefix from a STIX identifier (e.g. malware--uuid -> malware)."""
        if "--" in stix_id:
            return stix_id.split("--", 1)[0]
        return ""

    def ingest_bundle(self, bundle_dict: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
        """
        Executes Two-Pass Ingestion on a STIX 2.1 bundle:
        Pass 1: Process and stage MarkingDefinitions, ExtensionDefinitions, and SDOs.
        Pass 2: Classify and resolve SRO relationships via 4-way tuple framework.
        Supports dry_run=True (pure preview without state mutations) and transactional rollback on error.
        """
        # Snapshot state for rollback and dry-run isolation
        snapshot_entities = copy.deepcopy(self.mapper.entities_by_stix_id)
        snapshot_revoked = set(self.mapper.revoked_stix_ids)
        snapshot_markings = dict(self.mapper.marking_definition_digests)
        snapshot_cve = dict(self.mapper.cve_index)
        snapshot_name = {k: set(v) for k, v in self.mapper.name_index.items()}
        snapshot_conflicts = list(self.mapper.ambiguous_entity_conflicts)
        snapshot_relationships = copy.deepcopy(self.stored_relationships)
        snapshot_relationships_by_key = copy.deepcopy(self.relationships_by_key)

        audit_records: Dict[str, List[Dict[str, Any]]] = {
            "unsupported_type_ignored": [],
            "unsupported_relationship_ignored": [],
            "sco_endpoint_ignored": [],
            "custom_relationship_ignored": [],
        }

        rejection_ledger: Dict[str, List[Dict[str, Any]]] = {
            "rejected_and_isolated": [],
            "unresolved_reference_rejected": [],
            "unresolved_marking_rejected": [],
            "revoked_object_update_rejected": [],
            "immutable_marking_conflict_rejected": [],
        }

        nodes_created = 0
        nodes_merged = 0
        nodes_updated = 0
        relationships_created = 0
        relationships_merged = 0

        # Staging queues for atomic Neo4j transactional persistence
        staged_nodes_for_bundle: List[Dict[str, Any]] = []
        staged_edges_for_bundle: List[Dict[str, Any]] = []

        # Step 0: Validate Bundle root structure (forbidding spec_version at root)
        try:
            bundle = StixBundle.model_validate(bundle_dict)
        except ValidationError as e:
            rejection_ledger["rejected_and_isolated"].append({
                "id": bundle_dict.get("id", "unknown-bundle"),
                "reason": f"Bundle validation failure: {str(e)}",
            })
            return {
                "success": False,
                "dry_run": dry_run,
                "nodes_created": 0,
                "nodes_merged": 0,
                "nodes_updated": 0,
                "relationships_created": 0,
                "relationships_merged": 0,
                "audit_records": audit_records,
                "rejection_ledger": rejection_ledger,
                "ambiguous_entity_conflicts": self.mapper.ambiguous_entity_conflicts,
            }

        raw_objects = bundle.objects
        # Set of marking definition IDs accepted in this bundle (created or merged)
        accepted_marking_ids: Set[str] = set()
        sdo_candidates: List[Dict[str, Any]] = []
        sro_candidates: List[Dict[str, Any]] = []

        # =========================================================================
        # PASS 1A: Process Marking Definitions and Extension Definitions
        # =========================================================================
        for raw_obj in raw_objects:
            obj_type = raw_obj.get("type")

            if obj_type == "marking-definition":
                try:
                    marking_def = StixMarkingDefinition.model_validate(raw_obj)
                    status, conflict = self.mapper.resolve_and_stage_marking_definition(marking_def, raw_obj)
                    if status == "created":
                        accepted_marking_ids.add(marking_def.id)
                        staged_nodes_for_bundle.append(self.mapper.entities_by_stix_id[marking_def.id])
                        nodes_created += 1
                    elif status == "merged":
                        accepted_marking_ids.add(marking_def.id)
                        nodes_merged += 1
                    elif status == "immutable_marking_conflict_rejected":
                        rejection_ledger["immutable_marking_conflict_rejected"].append(conflict)
                except ValidationError as e:
                    rejection_ledger["rejected_and_isolated"].append({
                        "id": raw_obj.get("id", "unknown-marking"),
                        "reason": f"Invalid marking-definition: {str(e)}",
                    })

            elif obj_type == "extension-definition":
                try:
                    ext_def = StixExtensionDefinition.model_validate(raw_obj)
                    # Stage extension definition
                    ext_entry = {
                        "labels": ["ExtensionDefinition"],
                        "properties": ext_def.model_dump(),
                        "raw_payload": raw_obj,
                    }
                    self.mapper.entities_by_stix_id[ext_def.id] = ext_entry
                    staged_nodes_for_bundle.append(ext_entry)
                    nodes_created += 1
                except ValidationError as e:
                    rejection_ledger["rejected_and_isolated"].append({
                        "id": raw_obj.get("id", "unknown-extension"),
                        "reason": f"Invalid extension-definition: {str(e)}",
                    })

            elif obj_type == "relationship":
                sro_candidates.append(raw_obj)

            elif obj_type in STANDARD_UNSUPPORTED_SDOS:
                audit_records["unsupported_type_ignored"].append({
                    "id": raw_obj.get("id", "unknown-unsupported-sdo"),
                    "type": obj_type,
                    "reason": "Valid STIX 2.1 SDO outside ThreatMind core graph ontology.",
                })

            elif obj_type in STANDARD_SCO_TYPES:
                audit_records["sco_endpoint_ignored"].append({
                    "id": raw_obj.get("id", "unknown-sco"),
                    "type": obj_type,
                    "reason": "Cyber-observable object outside ThreatMind graph scope.",
                })

            else:
                sdo_candidates.append(raw_obj)

        # =========================================================================
        # PASS 1B: Validate and Resolve SDOs
        # =========================================================================
        for raw_obj in sdo_candidates:
            stix_id = raw_obj.get("id", "unknown-sdo")

            # 1. Schema Validation via discriminated model
            try:
                sdo = self.sdo_adapter.validate_python(raw_obj)
            except ValidationError as e:
                rejection_ledger["rejected_and_isolated"].append({
                    "id": stix_id,
                    "reason": f"SDO validation failure: {str(e)}",
                })
                continue

            # 2. Marking Reference Verification (Fail-Closed)
            # Only markings present in persistent storage or successfully accepted in this bundle are valid
            unresolved_markings: List[str] = []
            if sdo.object_marking_refs:
                for m_ref in sdo.object_marking_refs:
                    if m_ref not in self.mapper.marking_definition_digests and m_ref not in accepted_marking_ids:
                        unresolved_markings.append(m_ref)

            if sdo.granular_markings:
                for gm in sdo.granular_markings:
                    if gm.marking_ref:
                        if (
                            gm.marking_ref not in self.mapper.marking_definition_digests
                            and gm.marking_ref not in accepted_marking_ids
                        ):
                            unresolved_markings.append(gm.marking_ref)

            if unresolved_markings:
                rejection_ledger["unresolved_marking_rejected"].append({
                    "id": stix_id,
                    "unresolved_marking_refs": unresolved_markings,
                    "reason": "SDO references unresolvable object_marking_refs; fail-closed isolation enforced.",
                })
                continue

            # 3. Resolve and Stage in Entity Mapper
            status, detail = self.mapper.resolve_sdo(sdo, raw_obj)
            if status == "created":
                staged_nodes_for_bundle.append(self.mapper.entities_by_stix_id[stix_id])
                nodes_created += 1
            elif status == "merged":
                nodes_merged += 1
            elif status == "updated":
                staged_nodes_for_bundle.append(self.mapper.entities_by_stix_id[stix_id])
                nodes_updated += 1
            elif status == "revoked_object_update_rejected":
                rejection_ledger["revoked_object_update_rejected"].append(detail)
            elif status in ("version_conflict_quarantined", "ambiguity_quarantined"):
                pass  # Already staged in mapper.ambiguous_entity_conflicts
                pass  # Already staged in mapper.ambiguous_entity_conflicts

        # =========================================================================
        # PASS 2: SRO Relationship Validation and 4-Way Tuple Classification
        # =========================================================================
        for raw_obj in sro_candidates:
            sro_id = raw_obj.get("id", "unknown-relationship")

            # 1. Basic SRO Syntax Validation
            try:
                sro = StixRelationship.model_validate(raw_obj)
            except ValidationError as e:
                rejection_ledger["rejected_and_isolated"].append({
                    "id": sro_id,
                    "reason": f"SRO validation failure: {str(e)}",
                })
                continue

            src_type = self._get_type_from_stix_id(sro.source_ref)
            tgt_type = self._get_type_from_stix_id(sro.target_ref)
            rel_type = sro.relationship_type
            rel_tuple = (src_type, rel_type, tgt_type)

            # 2. Check for SCO endpoints (Audited, NOT malformed)
            if src_type in STANDARD_SCO_TYPES or tgt_type in STANDARD_SCO_TYPES:
                audit_records["sco_endpoint_ignored"].append({
                    "id": sro_id,
                    "tuple": rel_tuple,
                    "source_ref": sro.source_ref,
                    "target_ref": sro.target_ref,
                    "reason": "Relationship references a valid SCO endpoint outside active graph scope.",
                })
                continue

            # 3. Fail-Closed Marking Reference Check on SRO
            unresolved_sro_markings: List[str] = []
            if sro.object_marking_refs:
                for m_ref in sro.object_marking_refs:
                    if m_ref not in self.mapper.marking_definition_digests and m_ref not in accepted_marking_ids:
                        unresolved_sro_markings.append(m_ref)

            if sro.granular_markings:
                for gm in sro.granular_markings:
                    if gm.marking_ref:
                        if (
                            gm.marking_ref not in self.mapper.marking_definition_digests
                            and gm.marking_ref not in accepted_marking_ids
                        ):
                            unresolved_sro_markings.append(gm.marking_ref)

            if unresolved_sro_markings:
                rejection_ledger["unresolved_marking_rejected"].append({
                    "id": sro_id,
                    "unresolved_marking_refs": unresolved_sro_markings,
                    "reason": "SRO references unresolvable object_marking_refs; fail-closed isolation enforced.",
                })
                continue

            # 4. Check negative ontological invariants
            # Strict Invariant: IntrusionSet -> IntrusionSet via attributed-to is strictly rejected
            if rel_type == "attributed-to" and src_type == "intrusion-set" and tgt_type == "intrusion-set":
                rejection_ledger["rejected_and_isolated"].append({
                    "id": sro_id,
                    "tuple": rel_tuple,
                    "reason": "OASIS STIX 2.1 §5.1 Violation: IntrusionSet attributed-to IntrusionSet is strictly prohibited.",
                })
                continue

            # Strict Invariant: ThreatActor and Campaign directly exploiting vulnerability is invalid (must use targets)
            if rel_type == "exploits" and src_type in ("threat-actor", "campaign"):
                rejection_ledger["rejected_and_isolated"].append({
                    "id": sro_id,
                    "tuple": rel_tuple,
                    "reason": f"OASIS STIX 2.1 §5.1 Violation: {src_type} cannot directly exploit vulnerability; must use targets.",
                })
                continue

            # 5. 4-Way Tuple Classification
            # Category A: Supported Registered Tuple
            if rel_tuple in self.supported_tuples:
                # Endpoint Resolution Check
                src_exists = sro.source_ref in self.mapper.entities_by_stix_id
                tgt_exists = sro.target_ref in self.mapper.entities_by_stix_id

                if not src_exists or not tgt_exists:
                    missing = []
                    if not src_exists:
                        missing.append(sro.source_ref)
                    if not tgt_exists:
                        missing.append(sro.target_ref)
                    rejection_ledger["unresolved_reference_rejected"].append({
                        "id": sro_id,
                        "unresolved_endpoints": missing,
                        "reason": "Relationship references missing/unresolvable SDO endpoints.",
                    })
                    continue

                # Deduplication and staging
                edge_key = (sro.source_ref, rel_type, sro.target_ref)
                if edge_key in self.relationships_by_key or any(r["id"] == sro.id for r in self.stored_relationships):
                    relationships_merged += 1
                else:
                    edge_dict = {
                        "id": sro.id,
                        "relationship_type": rel_type,
                        "source_ref": sro.source_ref,
                        "target_ref": sro.target_ref,
                        "created": sro.created.isoformat(),
                        "modified": sro.modified.isoformat(),
                        "object_marking_refs": sro.object_marking_refs,
                        "confidence": sro.confidence,
                    }
                    self.relationships_by_key[edge_key] = edge_dict
                    self.stored_relationships.append(edge_dict)
                    staged_edges_for_bundle.append(edge_dict)
                    relationships_created += 1

            # Category B: Valid Unsupported Standard Tuple
            elif rel_tuple in self.standard_unsupported_tuples:
                audit_records["unsupported_relationship_ignored"].append({
                    "id": sro_id,
                    "tuple": rel_tuple,
                    "reason": "Valid OASIS STIX 2.1 relationship tuple outside ThreatMind active graph ontology.",
                })

            # Category C: Registered Custom Relationship Tuple (open vocabulary or x_)
            elif rel_tuple in self.registered_custom_tuples or rel_type.startswith("x_"):
                audit_records["custom_relationship_ignored"].append({
                    "id": sro_id,
                    "tuple": rel_tuple,
                    "reason": "User-defined custom relationship acknowledged and preserved in audit records.",
                })

            # Category D: Malformed / Unrecognized Tuple
            else:
                rejection_ledger["rejected_and_isolated"].append({
                    "id": sro_id,
                    "tuple": rel_tuple,
                    "reason": f"Unrecognized relationship tuple ({src_type}, {rel_type}, {tgt_type}) outside STIX 2.1 specification.",
                })

        # Dry-run handling vs atomic transactional database persistence
        if dry_run:
            self.mapper.entities_by_stix_id = snapshot_entities
            self.mapper.revoked_stix_ids = snapshot_revoked
            self.mapper.marking_definition_digests = snapshot_markings
            self.mapper.cve_index = snapshot_cve
            self.mapper.name_index = snapshot_name
            self.mapper.ambiguous_entity_conflicts = snapshot_conflicts
            self.stored_relationships = snapshot_relationships
            self.relationships_by_key = snapshot_relationships_by_key
        else:
            if self.graph_service.is_connected() and (staged_nodes_for_bundle or staged_edges_for_bundle):
                try:
                    self.graph_service.persist_bundle_transaction(staged_nodes_for_bundle, staged_edges_for_bundle)
                except Exception as e:
                    # Roll back in-memory mutations on database transaction failure
                    self.mapper.entities_by_stix_id = snapshot_entities
                    self.mapper.revoked_stix_ids = snapshot_revoked
                    self.mapper.marking_definition_digests = snapshot_markings
                    self.mapper.cve_index = snapshot_cve
                    self.mapper.name_index = snapshot_name
                    self.mapper.ambiguous_entity_conflicts = snapshot_conflicts
                    self.stored_relationships = snapshot_relationships
                    self.relationships_by_key = snapshot_relationships_by_key
                    raise RuntimeError(f"Database transaction failed; full rollback executed: {str(e)}") from e

        return {
            "success": True,
            "dry_run": dry_run,
            "nodes_created": nodes_created,
            "nodes_merged": nodes_merged,
            "nodes_updated": nodes_updated,
            "relationships_created": relationships_created,
            "relationships_merged": relationships_merged,
            "audit_records": audit_records,
            "rejection_ledger": rejection_ledger,
            "ambiguous_entity_conflicts": self.mapper.ambiguous_entity_conflicts,
        }
