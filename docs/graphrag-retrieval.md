# ThreatMind GraphRAG & Controlled Graph Retrieval

## 1. Executive Summary

Phase 5 implements the **Controlled Graph Retrieval & GraphRAG Foundation** for ThreatMind. Given a natural-language cyber threat question from an analyst, the retrieval engine:
1. Resolves candidate cyber entities and identifiers (ThreatActors, Malware, CVEs, MITRE ATT&CK IDs) against authoritative Neo4j knowledge graph nodes.
2. Performs bounded, parameterized Cypher graph traversal constrained by depth, node, and relationship caps.
3. Enforces strict **Evidence-First Filtering**: relationships lacking provenance metadata or supporting evidence text are strictly excluded from the answer context.
4. Generates structured graph context (`RetrievedEntity`, `RetrievedRelationship`, `EvidenceRecord`, `GraphPath`) without generating final speculative LLM narrative answers.

---

## 2. Architecture & Data Flow

```
                           THREATMIND RETRIEVAL FLOW
                                       │
                 Analyst Question: "How does APT29 attack systems?"
                                       │
                                       ▼
                       1. Query Entity Resolver
                     (Regex IDs + Alias Dictionaries + Cypher)
                                       │
                         Resolved: [actor_apt29 (APT29)]
                         Unresolved: []
                                       │
                                       ▼
                    2. Controlled Knowledge Graph Retriever
                (Bounded Traversal, Rel Whitelist: USES|EXPLOITS...)
                                       │
                         Depth: 1..3  |  Limits: Entities <= 20, Rels <= 30
                                       │
                                       ▼
                     3. Evidence-First Provenance Filter
                   (Rejects edges with empty evidence_text)
                                       │
                                       ▼
                           4. Structured Retrieval Result
           [Resolved Entities] + [Entities] + [Relationships] + [Paths]
                    + [Evidence Records] + [Sources] + [Warnings]
```

---

## 3. Query Entity Resolver (`entity_resolver.py`)

The entity resolver uses a deterministic multi-stage lookup strategy:
1. **CVE Identifiers**: Matches `CVE-YYYY-NNNN` using regex and checks Neo4j `Vulnerability` nodes.
2. **MITRE ATT&CK Identifiers**: Matches `TXXXX[.NNN]` and `TAXXXX` techniques and tactics.
3. **Known Alias Lookups**: Resolves aliases using dictionary mappings (`Cozy Bear` → `APT29`, `Beacon` → `Cobalt Strike`).
4. **Canonical Name Search**: Executes exact case-insensitive Cypher queries against `name` and `id` properties.
5. **Graph Node Aliases**: Inspects the `n.aliases` string array property on Neo4j nodes.
6. **Ambiguity Handling**: If a candidate term matches multiple distinct entity IDs with conflicting semantics, it is flagged in `unresolved_entities` as ambiguous rather than guessing.

---

## 4. Controlled Graph Retrieval & Bounded Limits (`graph_retriever.py`)

To prevent combinatorial explosion across dense graph clusters and avoid uninformative traversals:
- **Relationship Whitelist**: Only traverses relationships in `SUPPORTED_RELATIONSHIPS` (`USES`, `USES_TECHNIQUE`, `EXPLOITS`, `TARGETS`, `CONDUCTS`, `PART_OF`, `AFFECTS`, `ASSOCIATED_WITH`).
- **Depth Cap**: Enforces `max_depth` (default `1`, hard maximum `3`).
- **Entity Cap**: Enforces `max_entities` (default `20`, hard maximum `50`).
- **Relationship Cap**: Enforces `max_relationships` (default `30`, hard maximum `50`).
- **Evidence Cap**: Enforces `max_evidence` (default `30`, hard maximum `50`).

---

## 5. Evidence-First Retrieval Rules

> [!IMPORTANT]
> **No Ungrounded Facts**: Every returned relationship edge MUST contain non-empty `evidence_text` and a valid `source_id`. Any relationship edge in the graph lacking supporting evidence is excluded from the retrieval result, and an explicit warning is recorded in `warnings`.

---

## 6. GraphRAG Integration & Limitations

- **Authoritative Source**: The Neo4j property knowledge graph serves as the authoritative source of factual relationships.
- **Provider-Independent Interface**: `BaseGraphRetriever` decouples query processing from underlying implementations.
- **Vector Search Context**: Vector similarity across CTI passages is treated as a semantic relevance signal, not proof of factual truth. Factual claims require verified Neo4j property graph edges and provenance records.

---

## 7. REST API Endpoint

### `POST /api/v1/query/retrieve`

**Request Body**:
```json
{
  "question": "How does APT29 attack systems?",
  "config": {
    "max_depth": 1,
    "max_entities": 20,
    "max_relationships": 20
  }
}
```

**Response `200 OK`**:
```json
{
  "original_question": "How does APT29 attack systems?",
  "resolved_entities": [
    {
      "id": "actor_apt29",
      "label": "ThreatActor",
      "name": "APT29",
      "match_method": "canonical_name",
      "confidence_score": 1.0
    }
  ],
  "unresolved_entities": [],
  "retrieved_entities": [
    {
      "id": "actor_apt29",
      "label": "ThreatActor",
      "name": "APT29",
      "aliases": ["Cozy Bear", "The Dukes"],
      "description": "Russian cyber espionage group"
    },
    {
      "id": "malware_cobalt_strike",
      "label": "Malware",
      "name": "Cobalt Strike",
      "aliases": ["Beacon"]
    }
  ],
  "retrieved_relationships": [
    {
      "source_id": "actor_apt29",
      "source_name": "APT29",
      "source_label": "ThreatActor",
      "rel_type": "USES",
      "target_id": "malware_cobalt_strike",
      "target_name": "Cobalt Strike",
      "target_label": "Malware",
      "provenance": {
        "source_id": "source_demo_001",
        "evidence_text": "APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations."
      }
    }
  ],
  "graph_paths": [],
  "evidence_records": [
    {
      "source_id": "source_demo_001",
      "evidence_text": "APT29 deployed Cobalt Strike Beacon payloads during targeted cyber operations.",
      "relationship": "(APT29)-[USES]->(Cobalt Strike)"
    }
  ],
  "sources": [],
  "warnings": [],
  "statistics": {
    "execution_time_ms": 14.2,
    "entities_resolved_count": 1,
    "nodes_retrieved_count": 2,
    "edges_retrieved_count": 1,
    "evidence_records_count": 1,
    "paths_count": 1
  }
}
```
