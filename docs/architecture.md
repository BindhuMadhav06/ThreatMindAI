# ThreatMind System Architecture

## Executive Overview

ThreatMind is an AI-powered Cyber Threat Intelligence (CTI) detective system built on a foundation of Cybersecurity Knowledge Graphs, GraphRAG (Graph Retrieval-Augmented Generation), Multi-Hop Graph Reasoning, and Evidence Provenance.

Unlike traditional NIDS, malware scanners, or generic LLM chatbots, ThreatMind enforces strict evidence groundings for all CTI relationships. It eliminates hallucinated threat actor mappings, fabricated CVE associations, and unsupported attack paths by grounding all LLM inferences in explicit Neo4j knowledge graph nodes, edges, and original source provenance records.

---

## High-Level Architecture Diagram

```
                                    THREATMIND ARCHITECTURE
                                              |
               +------------------------------+------------------------------+
               |                                                             |
         React UI Frontend                                            FastAPI Backend
    (TypeScript, Vite, Cytoscape)                                      (Python 3.12, REST)
               |                                                             |
               +------------------------ REST API Calls ---------------------+
                                                                             |
                                                      +----------------------+----------------------+
                                                      |                                             |
                                               Query Engine                                     Ingestion Engine
                                                      |                                             |
                                           (Intent Parsing, Entity Extraction)             (PDF/JSON/CSV/HTML/TXT)
                                                      |                                             |
                                                      +----------------------+----------------------+
                                                                             |
                                                                        GraphRAG Layer
                                                               (Neo4j GraphRAG + Embeddings)
                                                                             |
                                                                             ↓
                                                                      Neo4j Database
                                                            +----------------+----------------+
                                                            |                                 |
                                                     Knowledge Graph                    Vector Index
                                              (Entities, Relationships)             (CTI Passages & Text)
                                                            |                                 |
                                                            +----------------+----------------+
                                                                             |
                                                                      LLM Abstraction Layer
                                                             (Gemini, OpenAI, Ollama, Anthropic)
                                                                             |
                                                                             ↓
                                                                   Grounded Response Engine
                                                                             |
                                                            +----------------+----------------+
                                                            |                                 |
                                                       Graph Paths                     Source Provenance
```

---

## Subsystem Architecture & Responsibilities

### 1. Ingestion Subsystem (`services/ingestion/`, `services/extraction/`, `services/normalization/`)
- **Document Processing**: Parses structured/unstructured CTI documents (`.pdf`, `.json`, `.csv`, `.txt`, `.html`) using PyMuPDF and BeautifulSoup.
- **Source Tracking**: Assigns unique `source_id`, tracking publisher, published date, URL, and raw text chunks.
- **Entity Extraction**: Uses structured LLM prompts validated by Pydantic models to extract entities (ThreatActor, Malware, Tool, Technique, Tactic, Vulnerability, Product, OS, Organization, Campaign, Indicator).
- **Relationship Extraction**: Extracts relationships **only** when explicit textual evidence supports the link, storing `evidence_text` and `confidence`.
- **Entity Normalization**: Standardizes entity names to canonical aliases (e.g., MITRE ATT&CK technique IDs like `T1059`, CVE IDs like `CVE-2021-44228`, threat actor aliases like `APT29 / Cozy Bear / The Dukes`).

### 2. Knowledge Graph Subsystem (`services/graph/`)
- **Neo4j Storage**: Primary database storing labeled nodes and typed relationships.
- **Idempotent Ingestion**: Employs Neo4j `MERGE` queries and explicit constraints on unique entity identifiers (`id`, `cve_id`, `attack_id`, `name`) to prevent duplicate node creation.
- **Provenance Constraints**: Every relationship edge embeds metadata linking back to its supporting `Source` node ID and exact textual snippet.

### 3. GraphRAG & Traversal Subsystem (`services/retrieval/`, `services/reasoning/`, `services/evidence/`)
- **Hybrid Retrieval**: Combines Cypher multi-hop graph queries with Neo4j Vector Indexes for semantic passage lookup.
- **Multi-Hop Traversal**: Executes constrained graph paths (up to configurable depth $N$) traversing relationships like `(:ThreatActor)-[:USES]->(:Malware)-[:IMPLEMENTS]->(:Technique)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(:Product)`.
- **Whitelisting & Filtering**: Constrains traversal paths using relationship whitelists to prevent uninformative combinatorial explosion across dense graph clusters.
- **Evidence Collector**: Gathers and formats verified claims, target entities, relationship chains, and source citations.

### 4. LLM Abstraction Subsystem (`services/llm/`)
- **Provider Isolation**: Decouples the backend from specific LLM providers via an abstract interface `BaseLLMProvider`.
- **Supported Providers**: Integrates Google Gemini, OpenAI, Anthropic, and local Ollama deployments without changing domain logic.
- **Strict Grounding Prompts**: Enforces strict instructions prohibiting out-of-context extrapolation or invented citations.

### 5. Frontend Dashboard (`frontend/src/`)
- **Interactive UI**: Built with React 18, TypeScript, Vite, and Tailwind CSS.
- **Graph Visualization**: Uses Cytoscape.js to render interactive multi-hop attack graphs corresponding exactly to backend traversal results.
- **Analyst Workstation**: Displays synthesized answers, visual threat paths, evidence text panels, and source references.

---

## Security & Data Privacy

1. **Zero Credential Leakage**: All keys and connection parameters are loaded via environment variables using `pydantic-settings`.
2. **Input Sanitization**: Strictly validates REST query parameters and uploaded CTI files using Pydantic schemas.
3. **No Dynamic Execution**: CTI document content is treated strictly as passive text data; no scripts or embedded code within documents are ever executed.
4. **Parameterized Cypher Queries**: All database read/write queries use parameterized inputs to mitigate Cypher injection vulnerabilities.
