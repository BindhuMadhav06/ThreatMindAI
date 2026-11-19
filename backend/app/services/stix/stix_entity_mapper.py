"""
STIX 2.1 Entity Mapper and Deduplication Engine
Enforces 4-tier conservative resolution hierarchy, permanent revocation,
and strict ontological invariants per OASIS STIX 2.1 Specification.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from app.models.stix import (
    StixCommonSdoMetadata,
    StixCourseOfAction,
    StixIdentity,
    StixIntrusionSet,
    StixMalware,
    StixMarkingDefinition,
    StixThreatActor,
    StixTool,
    StixVulnerability,
    SupportedStixSdo,
)
from app.services.stix.canonical_json import compute_canonical_digest

# Authoritative CVE regex: sequence supports 4 to 19 digits per CVE Record Format
CVE_REGEX = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")

# MITRE ATT&CK Mitigation ID regex (e.g., M1042)
MITRE_MITIGATION_REGEX = re.compile(r"^M\d{4}$")

# Mapping of STIX 2.1 SDO types to primary Neo4j labels
STIX_TO_GRAPH_LABEL: Dict[str, str] = {
    "threat-actor": "ThreatActor",
    "intrusion-set": "IntrusionSet",
    "campaign": "Campaign",
    "malware": "Malware",
    "tool": "Tool",
    "vulnerability": "Vulnerability",
    "attack-pattern": "Technique",
    "course-of-action": "Mitigation",
    "identity": "Identity",
    "indicator": "Indicator",
    "infrastructure": "Infrastructure",
    "location": "Location",
    "report": "Source",
    "marking-definition": "MarkingDefinition",
}


class StixEntityMapper:
    """
    Manages in-memory / graph-backed entity resolution, versioning,
    and deduplication for STIX 2.1 objects.
    """

    def __init__(self):
        # In-memory store for staged/persisted entities
        # key: stix_id -> {node dict}
        self.entities_by_stix_id: Dict[str, Dict[str, Any]] = {}

        # Canonical lookup tables
        # key: cve_id -> stix_id
        self.cve_index: Dict[str, str] = {}
        # key: attack_id -> stix_id
        self.attack_pattern_index: Dict[str, str] = {}
        # key: (entity_type, normalized_name) -> Set[stix_id]
        self.name_index: Dict[Tuple[str, str], Set[str]] = {}

        # Tracking for revoked STIX IDs (Permanent Revocation Invariant)
        self.revoked_stix_ids: Set[str] = set()

        # Tracking for marking definitions and their full-object digests
        # key: stix_id -> canonical_digest
        self.marking_definition_digests: Dict[str, str] = {}

        # Ledger for ambiguous entity conflicts requiring analyst review
        self.ambiguous_entity_conflicts: List[Dict[str, Any]] = []

    def validate_cve_id(self, cve_id: str) -> bool:
        """
        Validates CVE identifier against authoritative 4-to-19 digit regex.
        """
        return bool(CVE_REGEX.match(cve_id.strip().upper()))

    def extract_mitre_attack_id(self, external_refs: Optional[List[Any]]) -> Optional[str]:
        """
        Extracts authoritative MITRE ATT&CK mitigation ID (M####) from external references.
        """
        if not external_refs:
            return None
        for ref in external_refs:
            # ref can be StixExternalReference or dict
            source_name = getattr(ref, "source_name", None) or (ref.get("source_name") if isinstance(ref, dict) else None)
            external_id = getattr(ref, "external_id", None) or (ref.get("external_id") if isinstance(ref, dict) else None)
            if source_name == "mitre-attack" and external_id:
                if MITRE_MITIGATION_REGEX.match(external_id.strip()):
                    return external_id.strip()
        return None

    def map_sdo_to_graph_properties(self, sdo: SupportedStixSdo) -> Dict[str, Any]:
        """
        Maps a typed Pydantic STIX SDO model into Neo4j node properties and labels.
        Enforces distinct ThreatActor vs IntrusionSet, generic Identity,
        and authoritative CourseOfAction properties.
        """
        raw_dict = sdo.model_dump(exclude_none=True)
        primary_label = STIX_TO_GRAPH_LABEL.get(sdo.type, "Entity")
        labels = [primary_label]

        node_props: Dict[str, Any] = {
            "id": sdo.id,
            "stix_id": sdo.id,
            "stix_type": sdo.type,
            "spec_version": sdo.spec_version,
            "created": sdo.created.isoformat(),
            "modified": sdo.modified.isoformat(),
            "name": getattr(sdo, "name", sdo.id),
        }

        # Common metadata properties
        if sdo.description:
            node_props["description"] = sdo.description
        if sdo.created_by_ref:
            node_props["stix_created_by_ref"] = sdo.created_by_ref
        if sdo.revoked is not None:
            node_props["revoked"] = sdo.revoked
        if sdo.labels:
            node_props["labels"] = sdo.labels
        if sdo.confidence is not None:
            node_props["confidence"] = sdo.confidence
        if sdo.object_marking_refs:
            node_props["object_marking_refs"] = sdo.object_marking_refs

        # Type-specific property mappings & invariants
        if isinstance(sdo, StixThreatActor):
            # Strict Invariant: ThreatActor must NOT have IntrusionSet label
            if sdo.threat_actor_types:
                node_props["threat_actor_types"] = sdo.threat_actor_types
            if sdo.aliases:
                node_props["aliases"] = sdo.aliases
            if sdo.sophistication:
                node_props["sophistication"] = sdo.sophistication

        elif isinstance(sdo, StixIntrusionSet):
            # Strict Invariant: IntrusionSet must NOT be merged with ThreatActor
            if sdo.aliases:
                node_props["aliases"] = sdo.aliases
            if sdo.first_seen:
                node_props["first_seen"] = sdo.first_seen.isoformat()
            if sdo.last_seen:
                node_props["last_seen"] = sdo.last_seen.isoformat()

        elif isinstance(sdo, StixIdentity):
            node_props["identity_class"] = sdo.identity_class
            if sdo.sectors:
                node_props["sectors"] = sdo.sectors
            if sdo.contact_information:
                node_props["contact_information"] = sdo.contact_information
            # Backward-compatible Organization labeling
            if sdo.identity_class == "organization":
                labels.append("Organization")

        elif isinstance(sdo, StixVulnerability):
            node_props["cve_id"] = sdo.name
            # Validate CVE ID
            if self.validate_cve_id(sdo.name):
                node_props["is_valid_cve"] = True
            else:
                node_props["is_valid_cve"] = False

        elif isinstance(sdo, StixCourseOfAction):
            attack_mitigation_id = self.extract_mitre_attack_id(sdo.external_references)
            if attack_mitigation_id:
                node_props["mitre_attack_id"] = attack_mitigation_id

        elif isinstance(sdo, StixMalware):
            node_props["is_family"] = sdo.is_family
            if sdo.aliases:
                node_props["aliases"] = sdo.aliases
            if sdo.malware_types:
                node_props["malware_types"] = sdo.malware_types

        elif isinstance(sdo, StixTool):
            if sdo.aliases:
                node_props["aliases"] = sdo.aliases
            if sdo.tool_types:
                node_props["tool_types"] = sdo.tool_types

        return {
            "labels": labels,
            "properties": node_props,
            "raw_payload": raw_dict,
        }

    def resolve_and_stage_marking_definition(
        self,
        marking_def: StixMarkingDefinition,
        raw_obj: Dict[str, Any],
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Enforces non-versionable full-object immutability per STIX 2.1 §7.2:
        - Same id + identical canonical digest: idempotent no-op (returns "merged").
        - Same id + different canonical digest: rejects with "immutable_marking_conflict_rejected".
        - New id: stores and returns "created".
        """
        stix_id = marking_def.id
        marking_payload = marking_def.model_dump(mode="python", exclude_none=True)
        current_digest = compute_canonical_digest(marking_payload)

        if stix_id in self.marking_definition_digests:
            existing_digest = self.marking_definition_digests[stix_id]
            if existing_digest == current_digest:
                return "merged", None
            else:
                # Full-object content mismatch on non-versionable object
                conflict_record = {
                    "stix_id": stix_id,
                    "existing_digest": existing_digest,
                    "incoming_digest": current_digest,
                    "reason": "Marking definitions are non-versionable; content conflict detected.",
                }
                return "immutable_marking_conflict_rejected", conflict_record

        # Store new definition
        self.marking_definition_digests[stix_id] = current_digest
        self.entities_by_stix_id[stix_id] = {
            "labels": ["MarkingDefinition"],
            "properties": {
                "id": stix_id,
                "stix_id": stix_id,
                "created": marking_def.created.isoformat(),
                "name": marking_def.name,
                "canonical_digest": current_digest,
            },
            "raw_payload": marking_payload,
        }
        return "created", None

    def resolve_sdo(
        self,
        sdo: SupportedStixSdo,
        raw_obj: Dict[str, Any],
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Executes the 4-Tier Conservative Resolution Hierarchy:
        - Checks permanent revocation
        - Tier 1: Canonical Identifier Match
        - Tier 2: Persistent STIX ID Match (versioning rules)
        - Tier 3: Unique Exact Normalized Name & Alias Match
        - Tier 4: Ambiguity Detected -> Quarantine in ambiguous_entity_conflicts
        """
        stix_id = sdo.id

        model_payload = sdo.model_dump(mode="python", exclude_none=True)
        graph_entity = self.map_sdo_to_graph_properties(sdo)
        graph_entity["raw_payload"] = model_payload
        incoming_digest = compute_canonical_digest(model_payload)
        graph_entity["canonical_digest"] = incoming_digest

        # Permanent Revocation Invariant (§3.2)
        if stix_id in self.revoked_stix_ids:
            # Check if this is an idempotent re-import of the identical revoked object
            if stix_id in self.entities_by_stix_id:
                existing_entity = self.entities_by_stix_id[stix_id]
                existing_digest = existing_entity.get("canonical_digest") or compute_canonical_digest(existing_entity.get("raw_payload", {}))
                if incoming_digest == existing_digest:
                    return "merged", None
            return "revoked_object_update_rejected", {
                "stix_id": stix_id,
                "reason": "Object is permanently revoked; no subsequent updates permitted.",
            }

        # If incoming object is marked revoked, record it for permanent revocation
        if sdo.revoked is True:
            self.revoked_stix_ids.add(stix_id)

        # Tier 2 Check: Existing STIX ID match
        if stix_id in self.entities_by_stix_id:
            existing_entity = self.entities_by_stix_id[stix_id]
            existing_modified_str = existing_entity["properties"]["modified"]
            existing_modified = datetime.fromisoformat(existing_modified_str)
            existing_digest = existing_entity.get("canonical_digest") or compute_canonical_digest(existing_entity["raw_payload"])

            # Case A: Same (stix_id, modified)
            if sdo.modified == existing_modified:
                if incoming_digest == existing_digest:
                    return "merged", None
                else:
                    # Same-version content conflict
                    conflict_record = {
                        "stix_id": stix_id,
                        "modified": sdo.modified.isoformat(),
                        "existing_digest": existing_digest,
                        "incoming_digest": incoming_digest,
                        "reason": "Same-version content conflict: identical (stix_id, modified) with differing content.",
                    }
                    self.ambiguous_entity_conflicts.append(conflict_record)
                    return "version_conflict_quarantined", conflict_record

            # Case B: Newer modified timestamp -> Update
            elif sdo.modified > existing_modified:
                # Archive existing into version history
                if "stix_version_history" not in existing_entity:
                    existing_entity["stix_version_history"] = []
                existing_entity["stix_version_history"].append({
                    "modified": existing_modified_str,
                    "payload": existing_entity["raw_payload"],
                })
                # Update entity properties
                existing_entity["properties"].update(graph_entity["properties"])
                existing_entity["raw_payload"] = model_payload
                existing_entity["canonical_digest"] = incoming_digest
                return "updated", None

            # Case C: Older modified timestamp -> Archive historical observation
            else:
                if "stix_version_history" not in existing_entity:
                    existing_entity["stix_version_history"] = []
                existing_entity["stix_version_history"].append({
                    "modified": sdo.modified.isoformat(),
                    "payload": model_payload,
                })
                return "archived_historical", None

        # Tier 1 Check: Canonical Identifier Match (CVE or ATT&CK ID)
        if isinstance(sdo, StixVulnerability) and sdo.name:
            cve_key = sdo.name.strip().upper()
            if cve_key in self.cve_index:
                resolved_id = self.cve_index[cve_key]
                existing_entity = self.entities_by_stix_id[resolved_id]
                # Update aliases table
                if "stix_id_aliases" not in existing_entity["properties"]:
                    existing_entity["properties"]["stix_id_aliases"] = []
                existing_entity["properties"]["stix_id_aliases"].append(stix_id)
                return "merged", None
            elif self.validate_cve_id(cve_key):
                self.cve_index[cve_key] = stix_id

        # Tier 3 & Tier 4 Check: Name and Alias Match
        name_key = (sdo.type, (getattr(sdo, "name", "") or "").strip().lower())
        if name_key[1] and name_key in self.name_index:
            candidates = self.name_index[name_key]
            # Ontological Invariant: ThreatActor and IntrusionSet never share candidates
            filtered_candidates = {
                c_id for c_id in candidates
                if self.entities_by_stix_id.get(c_id, {}).get("properties", {}).get("stix_type") == sdo.type
            }

            if len(filtered_candidates) == 1:
                # Exactly 1 match -> Merge
                resolved_id = next(iter(filtered_candidates))
                existing_entity = self.entities_by_stix_id[resolved_id]
                # Merge aliases
                incoming_aliases = getattr(sdo, "aliases", None) or []
                existing_aliases = existing_entity["properties"].get("aliases", [])
                merged_aliases = list(set(existing_aliases + incoming_aliases))
                if merged_aliases:
                    existing_entity["properties"]["aliases"] = merged_aliases
                return "merged", None
            elif len(filtered_candidates) > 1:
                # Tier 4: Ambiguity detected -> Quarantine
                conflict_record = {
                    "stix_id": stix_id,
                    "name": getattr(sdo, "name", ""),
                    "candidates": list(filtered_candidates),
                    "reason": "Multiple graph candidates match name/aliases; automated merge blocked.",
                }
                self.ambiguous_entity_conflicts.append(conflict_record)
                return "ambiguity_quarantined", conflict_record

        # Default: Create new entity
        self.entities_by_stix_id[stix_id] = graph_entity
        if name_key[1]:
            self.name_index.setdefault(name_key, set()).add(stix_id)

        # Index aliases
        for alias in getattr(sdo, "aliases", None) or []:
            alias_key = (sdo.type, alias.strip().lower())
            if alias_key[1]:
                self.name_index.setdefault(alias_key, set()).add(stix_id)

        return "created", None
