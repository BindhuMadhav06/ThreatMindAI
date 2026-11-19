"""
Phase 14: Graph Attack-Path Traversal Service.
Implements bounded, cycle-free directed graph path traversal
from external entry points to mission-critical crown jewels using NetworkX.
"""

from typing import Dict, List, Optional, Set, Tuple
import networkx as nx

from app.models.organization import (
    Asset,
    AssetCriticality,
    AttackPath,
    AttackPathEdge,
    AttackPathNode,
)


class AttackPathService:
    """
    Constructs tenant-isolated hybrid graphs of enterprise assets and threat capabilities,
    computing bounded attack paths from public entry points to critical targets.
    """

    def __init__(self, max_depth: int = 6, max_paths_limit: int = 25):
        self.max_depth = max_depth
        self.max_paths_limit = max_paths_limit

    def build_network_graph(
        self,
        tenant_id: str,
        assets: List[Asset],
        lateral_connections: Optional[List[Tuple[str, str, str]]] = None,
        threat_mappings: Optional[List[Dict[str, str]]] = None
    ) -> nx.DiGraph:
        """
        Build directed NetworkX graph of enterprise topology and threat relationships.
        lateral_connections: list of (source_asset_id, target_asset_id, relation_type)
        threat_mappings: list of dicts {'asset_id': ..., 'technique_id': ..., 'target_asset_id': ...}
        """
        G = nx.DiGraph()

        # Add asset nodes
        for asset in assets:
            if asset.tenant_id != tenant_id:
                continue
            is_entry = asset.external_exposure
            is_critical = asset.criticality in (AssetCriticality.MISSION_CRITICAL, AssetCriticality.HIGH)
            G.add_node(
                asset.asset_id,
                label="Asset",
                name=asset.name,
                asset_id=asset.asset_id,
                is_entry_point=is_entry,
                is_critical_asset=is_critical,
                asset_type=asset.asset_type.value
            )

        # Add connections
        if lateral_connections:
            for src, tgt, rel in lateral_connections:
                if G.has_node(src) and G.has_node(tgt):
                    G.add_edge(src, tgt, relationship_type=rel, technique_id=None)

        if threat_mappings:
            for tm in threat_mappings:
                src = tm.get("asset_id")
                tgt = tm.get("target_asset_id")
                tech = tm.get("technique_id")
                rel = tm.get("relationship_type", "EXPLOITS_TOWARD")
                if src and tgt and G.has_node(src) and G.has_node(tgt):
                    G.add_edge(src, tgt, relationship_type=rel, technique_id=tech)

        return G

    def find_attack_paths(
        self,
        tenant_id: str,
        graph: nx.DiGraph,
        custom_entry_ids: Optional[List[str]] = None,
        custom_target_ids: Optional[List[str]] = None
    ) -> List[AttackPath]:
        """
        Traverse graph to find all cycle-free attack paths from entry points to critical targets.
        Enforces max depth and max paths limits to guarantee bounded computation.
        """
        # Determine entry nodes
        if custom_entry_ids:
            entry_nodes = [n for n in custom_entry_ids if graph.has_node(n)]
        else:
            entry_nodes = [
                n for n, d in graph.nodes(data=True)
                if d.get("is_entry_point") is True
            ]

        # Determine target nodes
        if custom_target_ids:
            target_nodes = [n for n in custom_target_ids if graph.has_node(n)]
        else:
            target_nodes = [
                n for n, d in graph.nodes(data=True)
                if d.get("is_critical_asset") is True
            ]

        paths: List[AttackPath] = []
        path_counter = 1

        for src in entry_nodes:
            for dst in target_nodes:
                if src == dst:
                    continue

                try:
                    # all_simple_paths prevents cycles and respects cutoff depth
                    simple_paths = nx.all_simple_paths(
                        graph,
                        source=src,
                        target=dst,
                        cutoff=self.max_depth
                    )
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

                for p in simple_paths:
                    # Assemble path nodes
                    nodes: List[AttackPathNode] = []
                    for nid in p:
                        data = graph.nodes[nid]
                        nodes.append(AttackPathNode(
                            id=nid,
                            label=data.get("label", "Asset"),
                            name=data.get("name", nid),
                            asset_id=data.get("asset_id"),
                            threat_id=data.get("threat_id"),
                            is_entry_point=data.get("is_entry_point", False),
                            is_critical_asset=data.get("is_critical_asset", False)
                        ))

                    # Assemble path edges
                    edges: List[AttackPathEdge] = []
                    for i in range(len(p) - 1):
                        u, v = p[i], p[i + 1]
                        edge_data = graph.get_edge_data(u, v, default={})
                        edges.append(AttackPathEdge(
                            source=u,
                            target=v,
                            relationship_type=edge_data.get("relationship_type", "CONNECTS_TO"),
                            technique_id=edge_data.get("technique_id")
                        ))

                    # Approximate exploitability based on path length (shorter paths = higher exploitability)
                    exploitability = round(max(0.2, 1.0 - (len(p) - 2) * 0.15), 2)

                    attack_path = AttackPath(
                        path_id=f"path_{tenant_id}_{path_counter:03d}",
                        tenant_id=tenant_id,
                        entry_asset_id=src,
                        target_asset_id=dst,
                        steps=nodes,
                        edges=edges,
                        path_length=len(p),
                        estimated_exploitability=exploitability
                    )
                    paths.append(attack_path)
                    path_counter += 1

                    if len(paths) >= self.max_paths_limit:
                        return paths

        return paths
