# ThreatMind Architecture & Implementation Plan

## Problem Statement & Goal

Modern Cyber Threat Intelligence (CTI) analysis requires navigating vast amounts of disparate security advisories, vulnerability reports, and malware analyses. Existing generic LLM chatbots frequently hallucinate threat actor behaviors, invent CVE relationships, and cite non-existent sources. Traditional NIDS or simple malware scanners lack high-level contextual reasoning.

**ThreatMind** solves this by establishing an AI-Powered CTI Detective system. It integrates:
1. Automated CTI Ingestion & Extraction (PDF, JSON, CSV, HTML, TXT)
2. Strict Entity & Relationship Extraction with Pydantic validation
3. Alias & Identifier Normalization (MITRE ATT&CK IDs, CVE IDs)
4. Neo4j Property Knowledge Graph with mandatory Edge Provenance metadata
5. Multi-Hop Cypher Traversal & Neo4j GraphRAG hybrid retrieval
6. Provider-Independent LLM Abstraction (Gemini, OpenAI, Ollama, Anthropic)
7. Grounded Answer Engine with mandatory graph path and evidence visualization via Cytoscape.js

---

## 1. Initial Repository Analysis

- **Current Repository State**: Empty directory (`d:\madhav\ThreatMindAi`).
- **Existing Stack**: None (Clean initial setup).
- **Reusable Code**: None.
- **Missing Infrastructure**: Modular FastAPI backend, Neo4j connection drivers & GraphRAG pipeline, LLM abstraction layer, Cytoscape.js frontend dashboard, reproducible demo dataset, unit/integration test suites.

---

## 2. Final Technology Stack

- **Backend**: Python 3.12, FastAPI, Uvicorn, Pydantic v2, `pydantic-settings`
- **Knowledge Graph**: Neo4j (Cypher Query Language)
- **GraphRAG**: `neo4j-graphrag` Python SDK
- **LLM Abstraction**: Provider-independent interface (`BaseLLMProvider`) supporting Google Gemini, OpenAI, Ollama, Anthropic.
- **Embeddings**: `sentence-transformers` (`all-MiniLM-L6-v2`)
- **Vector Search**: Neo4j Vector Index
- **Frontend**: React 18, TypeScript, Vite, Tailwind CSS
- **Graph Visualization**: Cytoscape.js (`cytoscape`, `react-cytoscapejs`)
- **Document Processing**: PyMuPDF (`fitz`), BeautifulSoup4 (`bs4`), Pandas
- **Testing**: Pytest (Backend), Vitest (Frontend)
- **Containerization**: Docker, Docker Compose

---

## 3. Proposed Directory Structure

```
threatmind/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   └── routes/
│   │   │       ├── query.py
│   │   │       ├── graph.py
│   │   │       ├── sources.py
│   │   │       ├── ingestion.py
│   │   │       └── health.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   ├── logging.py
│   │   │   └── security.py
│   │   ├── models/
│   │   │   ├── query.py
│   │   │   ├── threat_actor.py
│   │   │   ├── malware.py
│   │   │   ├── vulnerability.py
│   │   │   ├── technique.py
│   │   │   └── source.py
│   │   ├── services/
│   │   │   ├── ingestion/
│   │   │   ├── extraction/
│   │   │   ├── normalization/
│   │   │   ├── graph/
│   │   │   ├── retrieval/
│   │   │   ├── reasoning/
│   │   │   ├── evidence/
│   │   │   └── llm/
│   │   └── utils/
│   ├── tests/
│   │   ├── test_health.py
│   │   ├── test_extraction.py
│   │   ├── test_normalization.py
│   │   ├── test_graph_construction.py
│   │   ├── test_query_engine.py
│   │   └── test_llm_grounding.py
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── GraphViewer.tsx
│   │   │   ├── EvidencePanel.tsx
│   │   │   ├── ThreatPath.tsx
│   │   │   └── QueryInput.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── ThreatActors.tsx
│   │   │   ├── Malware.tsx
│   │   │   ├── Vulnerabilities.tsx
│   │   │   ├── Techniques.tsx
│   │   │   └── Sources.tsx
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── hooks/
│   │   ├── types/
│   │   └── utils/
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   └── .env.example
├── data/
│   ├── raw/
│   ├── processed/
│   └── sample/
│       └── demo_apt29_cti.json
├── scripts/
│   ├── ingest.py
│   ├── build_graph.py
│   └── seed_demo_data.py
├── docs/
│   ├── architecture.md
│   ├── data-model.md
│   ├── api-design.md
│   ├── research-alignment.md
│   └── implementation-plan.md
├── docker-compose.yml
├── README.md
└── .gitignore
```

---

## 4. Detailed Implementation Phases

### Phase 1 — Repository Analysis & Documentation Setup
- Validate repository structure.
- Generate architecture, data model, API design, research alignment, and implementation plan documents in `docs/`.

### Phase 2 — Core Environment & Dependency Setup
- Create Python 3.12 virtual environment & `backend/requirements.txt`.
- Set up Vite + React + TypeScript frontend in `frontend/`.
- Configure `docker-compose.yml` for Neo4j database service (ports 7474, 7687).
- Verify basic backend health check (`GET /api/v1/health`) and frontend Vite startup.

### Phase 3 — Neo4j Schema, Constraints & Provenance Data Model
- Define Cypher schemas, node types (`ThreatActor`, `Malware`, `Tool`, `Technique`, `Vulnerability`, `Product`, `Source`), and constraints.
- Implement edge provenance property dictionary (`source_id`, `evidence_text`, `confidence`, `source_url`).
- Seed initial verifiable CTI demo dataset (`data/sample/demo_apt29_cti.json`).

### Phase 4 — Controlled CTI Ingestion Pipeline
- Implement multi-format document parser (`PDF`, `TXT`, `JSON`, `CSV`, `HTML`) in `services/ingestion/`.
- Generate source tracking metadata (`source_id`, `title`, `url`, `publisher`, `published_date`).

### Phase 5 & 6 — Entity & Relation Extraction with Validation
- Implement Pydantic-enforced LLM structured entity extraction (`ThreatActor`, `Malware`, `Vulnerability`, etc.).
- Implement evidence-backed relation extraction; log invalid extractions and reject hallucinated edges.
- Add unit tests for entity and relation extraction.

### Phase 7 — Entity Normalization & Alias Resolution
- Canonicalize entity identifiers (e.g., `APT29`, `CVE-2021-44228`, `T1059.001`).
- Support alias mappings (`Cozy Bear` -> `APT29`) while preserving domain uncertainty when evidence is ambiguous.

### Phase 8 — Idempotent Knowledge Graph Construction
- Build Cypher MERGE query builder in `services/graph/builder.py`.
- Guarantee idempotent ingestion (re-running ingestion will not create duplicate nodes or edges).
- Verify Neo4j insertion with unit tests.

### Phase 9 & 10 — Query Engine & GraphRAG Retrieval
- Implement `POST /api/v1/query` endpoint.
- Parse query intent and extract query target entities.
- Integrate Neo4j GraphRAG hybrid graph + vector index traversal.

### Phase 11 & 12 — Multi-Hop Reasoning & Evidence Collector
- Implement bounded multi-hop graph path traversal (whitelisted relation types, depth <= 4).
- Aggregate exact evidence quotes and source metadata for each traversed graph path.

### Phase 13 — Provider-Independent LLM Grounded Answer Generation
- Build `BaseLLMProvider` abstraction interface and concrete implementations (`GeminiProvider`, `OpenAIProvider`, `OllamaProvider`).
- Implement strict grounding prompts preventing un-cited claim generation.
- Return structured payload (`answer`, `graph_path`, `evidence`, `sources`, `warnings`).

### Phase 14 — Frontend Cybersecurity Analyst Dashboard
- Build React + TypeScript + Vite UI with Tailwind CSS.
- Implement Cytoscape.js interactive graph view displaying the retrieved attack path.
- Build evidence inspector drawer, threat path breadcrumb view, and source citations.

### Phase 15 — System Integration & End-to-End Testing
- Connect React frontend to FastAPI backend, Neo4j database, and LLM provider.
- Execute automated Pytest backend suite and Vitest frontend suite.
- Test MVP query: `"How does APT29 attack systems?"` end-to-end.

### Phase 16 & 17 — Evaluation Metrics, Documentation & Final Polish
- Evaluate extraction accuracy, multi-hop retrieval correctness, and groundings.
- Update `README.md` with setup commands, architecture diagrams, and execution guides.

---

## 5. Verification & Testing Strategy

### Backend Automated Tests (`pytest`)
- `test_health.py`: Verifies FastAPI routes and Neo4j connectivity.
- `test_extraction.py`: Validates entity and relationship extraction Pydantic parsing.
- `test_normalization.py`: Validates canonical alias resolution (`Cozy Bear` -> `APT29`).
- `test_graph_construction.py`: Tests idempotent node & edge insertion in Neo4j.
- `test_query_engine.py`: Verifies multi-hop path retrieval for APT29 queries.
- `test_llm_grounding.py`: Ensures LLM rejects queries with missing evidence without hallucinating facts.

### Frontend Tests (`vitest`)
- Component rendering tests for `GraphViewer.tsx`, `EvidencePanel.tsx`, `ThreatPath.tsx`.
