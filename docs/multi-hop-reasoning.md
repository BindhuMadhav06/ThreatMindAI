# ThreatMind Multi-Hop Threat Reasoning & Path Verification

## 1. Executive Summary

Phase 6 implements the **Multi-Hop Threat Reasoning Engine** for ThreatMind. Given a natural-language cyber threat question (e.g. *"How does APT29 attack systems?"*), the engine:
1. Identifies and resolves query entities using the Phase 5 entity resolver.
2. Traverses the knowledge graph using bounded, permitted relationship paths ($\le 3$ hops).
3. Validates each traversed edge independently against strict schema rules, endpoint integrity, and non-empty source evidence.
4. Generates explicit **semantic caveats** preventing unsupported conclusions of causality, attack success, or chronology.
5. Employs reusable **path templates** for structured cyber threat scenarios.
6. Returns structured reasoning paths (`accepted_paths`, `partial_paths`, `rejected_paths`, `evidence_records`, and `referenced_sources`) without generating a speculative final LLM narrative answer.

---

## 2. Reasoning Architecture & Pipeline

```
                        MULTI-HOP REASONING PIPELINE
                                     │
               Analyst Query: "How does APT29 attack systems?"
                                     │
                                     ▼
                      1. GraphRAG Context Retrieval
                    (Resolved: APT29, Edges: USES, etc.)
                                     │
                                     ▼
                      2. Bounded Path Construction
                    (DFS Traversal, Allowlist Filter, Depth <= 3)
                                     │
                                     ▼
                      3. Independent Edge Validation
               - Endpoint integrity check
               - Whitelisted relationship check
               - Non-empty evidence & source_id check
               - Cycle & continuity verification
                                     │
                                     ├── Edge fails -> Flag as partial or reject
                                     ▼
                      4. Path Template Matching & Caveats
               - Actor Attack Pattern
               - Actor Vulnerability Exploitation
               - Malware Capabilities
               - Vulnerability Impact
                                     │
                                     ▼
                      5. Deterministic Path Ranking
               - Keyword relevance score (0.0 to 1.0)
               - Template alignment
                                     │
                                     ▼
                        6. Structured Reasoning Result
              [Accepted Paths] + [Partial Paths] + [Rejected Paths]
                   + [Evidence per Edge] + [Semantic Caveats]
```

---

## 3. Path Validation Rules (`path_validator.py`)

A graph path is **NOT** evidence-backed merely because its nodes are connected in a database. Every step in a path must pass independent verification:
1. **Endpoint Integrity**: Source and target entity IDs must exist and have valid primary labels (`PRIMARY_NODE_LABELS`).
2. **Relationship Whitelist**: Relationship types must belong to `SUPPORTED_RELATIONSHIPS`.
3. **Mandatory Provenance**: Every edge must have attached `EvidenceRecord`s with non-empty `evidence_text` and `source_id`.
4. **Continuity**: The target entity of step $i$ must strictly match the source entity of step $i+1$.
5. **Acyclic Constraint**: Re-visiting an entity within the same path is detected as a cycle and causes path rejection.

---

## 4. Semantic Caveats & Unsupported Conclusions Prevention

ThreatMind enforces a strict research rule: **Graph connectivity does NOT prove causality or chronology.**

For example, when a path:
$$\text{ThreatActor} \xrightarrow{\text{USES}} \text{Malware} \xrightarrow{\text{USES\_TECHNIQUE}} \text{Technique}$$
is established, ThreatMind automatically attaches explicit semantic caveats:
- *Graph association documents software capability/usage; it does not prove specific attack campaign attribution without dedicated campaign evidence.*
- *Documented technique usage does not guarantee success against all defended environments.*
- *No chronological sequence of execution is implied solely by graph node connectivity.*

---

## 5. Controlled Path Templates (`path_templates.py`)

| Template ID | Scenario Description | Canonical Sequence |
| :--- | :--- | :--- |
| `actor_attack_pattern` | How does a threat actor attack/operate? | `ThreatActor` -[USES]-> `Malware\|Tool` -[USES_TECHNIQUE]-> `Technique` |
| `actor_vulnerability_exploitation` | What CVEs are exploited by an actor? | `ThreatActor` -[EXPLOITS]-> `Vulnerability` -[AFFECTS]-> `Product\|OS` |
| `actor_targeting` | Who does an actor target? | `ThreatActor` -[TARGETS]-> `Organization` |
| `malware_capabilities` | What techniques are implemented by malware? | `Malware` -[USES_TECHNIQUE]-> `Technique` -[PART_OF]-> `Tactic` |
| `vulnerability_impact` | What software is affected by a CVE? | `Vulnerability` -[AFFECTS]-> `Product\|OperatingSystem` |

---

## 6. REST API Endpoint

### `POST /api/v1/query/reason`

**Request Body**:
```json
{
  "question": "How does APT29 attack systems?",
  "max_depth": 3,
  "max_paths": 10
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
  "candidate_paths_considered": 7,
  "accepted_paths": [
    {
      "path_id": "reason_path_0",
      "length": 2,
      "is_complete": true,
      "is_valid": true,
      "relevance_score": 0.85,
      "template_applied": "actor_attack_pattern",
      "steps": [
        {
          "step_number": 1,
          "source_id": "actor_apt29",
          "source_label": "ThreatActor",
          "source_name": "APT29",
          "rel_type": "USES",
          "target_id": "malware_cobaltstrike",
          "target_label": "Malware",
          "target_name": "Cobalt Strike",
          "evidence_records": [
            {
              "source_id": "source_demo_001",
              "evidence_text": "APT29 has deployed Cobalt Strike Beacon payloads during lateral movement operations.",
              "relationship": "(APT29)-[USES]->(Cobalt Strike)"
            }
          ]
        },
        {
          "step_number": 2,
          "source_id": "malware_cobaltstrike",
          "source_label": "Malware",
          "source_name": "Cobalt Strike",
          "rel_type": "USES_TECHNIQUE",
          "target_id": "tech_t1059_001",
          "target_label": "Technique",
          "target_name": "PowerShell",
          "evidence_records": [
            {
              "source_id": "source_demo_001",
              "evidence_text": "Cobalt Strike Beacon invokes PowerShell (T1059.001) scripts for stager execution.",
              "relationship": "(Cobalt Strike)-[USES_TECHNIQUE]->(PowerShell)"
            }
          ]
        }
      ],
      "semantic_caveats": [
        "Graph association documents software capability/usage; it does not prove specific attack campaign attribution without dedicated campaign evidence.",
        "Documented technique usage does not guarantee success against all defended environments.",
        "No chronological sequence of execution is implied solely by graph node connectivity."
      ]
    }
  ],
  "rejected_paths": [],
  "partial_paths": [],
  "referenced_sources": [],
  "warnings": [],
  "statistics": {
    "execution_time_ms": 19.4,
    "candidate_paths": 7,
    "accepted_paths": 1,
    "partial_paths": 0,
    "rejected_paths": 0
  }
}
```

---

## 7. Future Evaluation Plan (Real CTI Reports)

To benchmark multi-hop reasoning accuracy for future academic evaluation:
1. **Benchmark Dataset**: Curate 20 real public CTI reports (CISA Advisories, Mandiant Threat Intelligence, MITRE ATT&CK Group profiles).
2. **Gold-Standard Paths**: Manually annotate ground-truth attack chains:
   - Gold Standard 1: `APT29 -> USES -> Cobalt Strike -> USES_TECHNIQUE -> PowerShell (T1059.001)`
   - Gold Standard 2: `APT29 -> EXPLOITS -> CVE-2021-44228 -> AFFECTS -> Apache Log4j`
3. **Metrics**:
   - Path Precision: $\frac{|\text{Accepted Valid Paths} \cap \text{Gold Standard}|}{|\text{Accepted Valid Paths}|}$
   - Evidence Completeness: Percentage of path edges with verified source citations ($\ge 95\%$).
   - Hallucination Rate: Target $0.0\%$.
