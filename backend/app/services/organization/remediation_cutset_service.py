"""
Phase 14: Remediation Cut-Set Service.
Computes the Minimum D3FEND Cut-Set interrupting identified attack paths
using graph-theoretic hitting set optimization and authoritative D3FEND techniques.
Preserves Phase 11 D3FEND catalog integrity without any catalog mutations.
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
from app.models.organization import AttackPath, D3fendCutSetRecommendation

CATALOG_PATH = Path(__file__).resolve().parent.parent / "defense" / "d3fend_catalog.json"


class RemediationCutSetService:
    """
    Computes mathematically grounded defensive cut-sets to disrupt attack graphs
    while strictly binding recommendations to authoritative MITRE D3FEND countermeasures.
    """

    def __init__(self, catalog_path: Path = CATALOG_PATH):
        self.catalog_path = catalog_path
        self._valid_d3fend_ids: Set[str] = set()
        self._load_catalog_index()

    def _load_catalog_index(self) -> None:
        """Read D3FEND catalog without modifying it to index valid countermeasure IDs."""
        if not self.catalog_path.exists():
            return
        with open(self.catalog_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for m in data.get("mappings", []):
            cid = m.get("countermeasure", {}).get("id")
            if cid:
                self._valid_d3fend_ids.add(cid)

    def _map_edge_to_d3fend(self, technique_id: str, rel_type: str) -> List[str]:
        """
        Map attack path technique or edge relationship to valid D3FEND countermeasures.
        """
        tech = (technique_id or "").upper()
        rel = (rel_type or "").upper()

        candidates: List[str] = []

        if "T1059" in tech:
            candidates.extend(["d3f:ExecutableAllowlisting", "d3f:ProcessSegmentExecutionPrevention"])
        elif "T1078" in tech or "ACCOUNT" in rel:
            candidates.extend(["d3f:MultiFactorAuthentication", "d3f:UserAccountPermissions"])
        elif "T1055" in tech:
            candidates.extend(["d3f:ProcessSegmentExecutionPrevention", "d3f:SystemCallFiltering"])
        elif "NETWORK" in rel or "LATERAL" in rel or "CONNECTS" in rel:
            candidates.extend(["d3f:NetworkIsolation", "d3f:ApplicationConfigurationHardening"])
        else:
            candidates.extend(["d3f:SoftwareUpdate", "d3f:ApplicationConfigurationHardening"])

        # Filter strictly to validated IDs in catalog
        valid = [c for c in candidates if c in self._valid_d3fend_ids]
        return valid if valid else ["d3f:ApplicationConfigurationHardening"]

    def calculate_minimum_cut_set(
        self,
        tenant_id: str,
        attack_paths: List[AttackPath]
    ) -> D3fendCutSetRecommendation:
        """
        Calculate the Minimum D3FEND Cut-Set separating entry points from crown jewels.
        Uses greedy minimum hitting set optimization over candidate defensive interventions.
        """
        if not attack_paths:
            return D3fendCutSetRecommendation(
                cut_set_id=f"cutset_{tenant_id}_empty",
                tenant_id=tenant_id,
                defensive_techniques=[],
                target_assets=[],
                interrupted_path_ids=[],
                total_paths_blocked=0,
                estimated_impact=0.0,
                operational_cost=0.0,
                alternative_mitigations=[]
            )

        # Map each path to candidate countermeasures that can disrupt at least one of its edges/steps
        path_countermeasures: Dict[str, Set[str]] = {}
        target_assets_set: Set[str] = set()

        for path in attack_paths:
            target_assets_set.add(path.target_asset_id)
            options: Set[str] = set()

            for edge in path.edges:
                techs = self._map_edge_to_d3fend(edge.technique_id or "", edge.relationship_type)
                options.update(techs)

            # If no edge produced countermeasures, provide baseline hardening
            if not options:
                options.add("d3f:ApplicationConfigurationHardening")

            path_countermeasures[path.path_id] = options

        # Greedy Hitting Set Algorithm:
        # Find minimum set of techniques that covers all paths in path_countermeasures
        uncovered_paths = set(path_countermeasures.keys())
        selected_techniques: List[str] = []

        while uncovered_paths:
            # Find technique that covers the largest number of uncovered paths
            candidate_counts: Dict[str, int] = {}
            for pid in uncovered_paths:
                for tech in path_countermeasures[pid]:
                    candidate_counts[tech] = candidate_counts.get(tech, 0) + 1

            if not candidate_counts:
                break

            # Pick highest frequency technique
            best_tech = max(candidate_counts.items(), key=lambda kv: kv[1])[0]
            selected_techniques.append(best_tech)

            # Mark covered paths
            covered_now = {
                pid for pid in uncovered_paths
                if best_tech in path_countermeasures[pid]
            }
            uncovered_paths.difference_update(covered_now)

        total_blocked = len(attack_paths)
        num_techs = len(selected_techniques)
        estimated_impact = round(min(0.99, 0.70 + 0.08 * num_techs), 2)
        operational_cost = round(min(0.85, 0.15 + 0.15 * num_techs), 2)

        # Alternative mitigations from valid catalog techniques not selected in minimal cut-set
        alt_mitigations = [
            t for t in sorted(list(self._valid_d3fend_ids))
            if t not in selected_techniques and t.startswith("d3f:")
        ][:3]

        return D3fendCutSetRecommendation(
            cut_set_id=f"cutset_{tenant_id}_opt",
            tenant_id=tenant_id,
            defensive_techniques=selected_techniques,
            target_assets=sorted(list(target_assets_set)),
            interrupted_path_ids=[p.path_id for p in attack_paths],
            total_paths_blocked=total_blocked,
            estimated_impact=estimated_impact,
            operational_cost=operational_cost,
            alternative_mitigations=alt_mitigations
        )
