# ThreatMind Research Alignment & Code Mapping

## Research Foundations Mapping Matrix

ThreatMind integrates research concepts from state-of-the-art CTI Knowledge Graph literature into modular, testable software components.

| Research Concept / Paper | Core Domain Feature | Code Implementation File | Verification Test Suite |
| :--- | :--- | :--- | :--- |
| **CTINexus** | Multi-format CTI document acquisition & structured extraction pipeline | [loaders.py](file:///d:/madhav/ThreatMindAi/backend/app/services/ingestion/loaders.py)<br>[pipeline.py](file:///d:/madhav/ThreatMindAi/backend/app/services/ingestion/pipeline.py) | [test_ingestion_loaders.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_ingestion_loaders.py)<br>[test_ingestion_pipeline.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_ingestion_pipeline.py) |
| **AttacKG & Open-CyKG** | Structured relationship extraction with edge provenance tracking | [relation_extractor.py](file:///d:/madhav/ThreatMindAi/backend/app/services/extraction/relation_extractor.py)<br>[repository.py](file:///d:/madhav/ThreatMindAi/backend/app/services/graph/repository.py) | [test_extraction.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_extraction.py)<br>[test_repository.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_repository.py) |
| **Evidence Grounding Layer** | Rejecting ungrounded / hallucinated LLM relationships against source text | [validator.py](file:///d:/madhav/ThreatMindAi/backend/app/services/ingestion/validator.py) | [test_validator.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_validator.py) |
| **Deterministic Normalization** | Canonical identifier format (CVE, MITRE ATT&CK IDs) and alias resolution | [normalizer.py](file:///d:/madhav/ThreatMindAi/backend/app/services/normalization/normalizer.py) | [test_normalization.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_normalization.py) |
| **Knowledge Graph Schema** | 13 primary entity node labels & Neo4j 5.x constraints | [schema_manager.py](file:///d:/madhav/ThreatMindAi/backend/app/services/graph/schema_manager.py) | [test_schema.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_schema.py) |
| **Idempotent Insertion** | Preventing duplicate node/edge creation across repeated ingestion runs | `MERGE` query patterns in [repository.py](file:///d:/madhav/ThreatMindAi/backend/app/services/graph/repository.py) | [test_ingestion_pipeline.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_ingestion_pipeline.py) |
| **GraphRAG & Entity Resolution** | Deterministic entity resolution and bounded graph context retrieval | [entity_resolver.py](file:///d:/madhav/ThreatMindAi/backend/app/services/retrieval/entity_resolver.py)<br>[graph_retriever.py](file:///d:/madhav/ThreatMindAi/backend/app/services/retrieval/graph_retriever.py) | [test_entity_resolver.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_entity_resolver.py)<br>[test_graph_retriever.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_graph_retriever.py) |
| **Evidence-First Retrieval** | Excluding unevidenced relationships from answer-ready retrieval context | [graph_retriever.py](file:///d:/madhav/ThreatMindAi/backend/app/services/retrieval/graph_retriever.py) | [test_graph_retriever.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_graph_retriever.py) |
| **Multi-Hop Path Reasoning** | Transparent assembly of validated multi-hop attack paths with semantic caveats | [path_builder.py](file:///d:/madhav/ThreatMindAi/backend/app/services/reasoning/path_builder.py)<br>[path_validator.py](file:///d:/madhav/ThreatMindAi/backend/app/services/reasoning/path_validator.py)<br>[reasoning_service.py](file:///d:/madhav/ThreatMindAi/backend/app/services/reasoning/reasoning_service.py) | [test_path_templates.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_path_templates.py)<br>[test_path_validator.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_path_validator.py)<br>[test_path_builder.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_path_builder.py)<br>[test_reasoning_service.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_reasoning_service.py) |
| **Evidence-Grounded Answering** | Citation-indexed answering with deterministic fallback and abstention | [prompt_builder.py](file:///d:/madhav/ThreatMindAi/backend/app/services/answering/prompt_builder.py)<br>[answer_generator.py](file:///d:/madhav/ThreatMindAi/backend/app/services/answering/answer_generator.py) | [test_prompt_builder.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_prompt_builder.py)<br>[test_answer_generator.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_answer_generator.py) |
| **Multi-Stage Claim Verification** | Decoupled citation integrity, attack success detection, and semantic alignment checks | [answer_validator.py](file:///d:/madhav/ThreatMindAi/backend/app/services/answering/answer_validator.py) | [test_answer_validator.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_answer_validator.py) |
| **Answering REST API** | Production endpoint for citation-backed Q&A with strict grounding validation | [query.py](file:///d:/madhav/ThreatMindAi/backend/app/api/routes/query.py) | [test_api_answer.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_api_answer.py) |
| **Safe Graph Exploration API** | Parameterized stats and entity lookup without arbitrary Cypher exposure | [entities.py](file:///d:/madhav/ThreatMindAi/backend/app/api/routes/entities.py) | [test_api_entities.py](file:///d:/madhav/ThreatMindAi/backend/tests/test_api_entities.py) |
| **Analyst Investigation Workstation** | Persistent React UI with interactive evidence drawers, claim markers, and path viewer | [InvestigationPage.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/pages/InvestigationPage.tsx)<br>[AnswerCard.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/components/investigation/AnswerCard.tsx)<br>[CitationDrawer.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/components/evidence/CitationDrawer.tsx) | [AnswerCard.test.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/test/AnswerCard.test.tsx)<br>[ClaimsAndEvidence.test.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/test/ClaimsAndEvidence.test.tsx) |
| **Cytoscape Knowledge Graph** | Interactive canvas with node type color-coding, path highlights, and accessible view | [CytoscapeGraph.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/components/graph/CytoscapeGraph.tsx)<br>[GraphInspector.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/components/graph/GraphInspector.tsx) | [GraphAndPaths.test.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/test/GraphAndPaths.test.tsx) |
| **CTI Ingestion Workbench** | Document uploader (PDF, HTML, JSON, TXT) with extraction metrics | [IngestionPage.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/pages/IngestionPage.tsx)<br>[IngestionForm.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/components/ingestion/IngestionForm.tsx) | [Ingestion.test.tsx](file:///d:/madhav/ThreatMindAi/frontend/src/test/Ingestion.test.tsx) |

---

## Component Deep Dive

### 1. Multi-Hop Path Validator ([path_validator.py](file:///d:/madhav/ThreatMindAi/backend/app/services/reasoning/path_validator.py))
- Validates each hop independently for endpoint integrity, whitelisted relationship types, non-empty evidence quotes, path continuity, and cycle detection.

### 2. Semantic Caveats & Unsupported Claims Guard ([path_templates.py](file:///d:/madhav/ThreatMindAi/backend/app/services/reasoning/path_templates.py))
- Prevents treating knowledge graph connectivity as proof of causality, chronology, or universal attribution.
- Injects explicit caveats stating that graph links reflect observed capability/usage.

### 3. Answer Generator & Deterministic Fallback ([answer_generator.py](file:///d:/madhav/ThreatMindAi/backend/app/services/answering/answer_generator.py))
- Connects GraphRAG retrieval, path validation, and LLM structured generation.
- Handles abstention immediately if no entities or valid paths are found (*"ThreatMind could not establish a sufficiently supported relationship from the currently available sources."*).
- Provides a deterministic, evidence-backed fallback for offline or unconfigured environments that is subject to the exact same validation rules.

### 4. Answer Validator & Grounding Guard ([answer_validator.py](file:///d:/madhav/ThreatMindAi/backend/app/services/answering/answer_validator.py))
- Separates structural citation checks from semantic alignment.
- Performs deterministic checks for citation existence, deterministic evidence ID hashes (`ev_...`), unsupported compromise/causality keywords, and lexical passage alignment.
- Assigns granular grounding statuses (`fully_grounded`, `partially_grounded`, `insufficient_evidence`, `unsupported`).

### 5. Interactive Knowledge Graph & Investigation UI ([frontend/src/](file:///d:/madhav/ThreatMindAi/frontend/src/))
- Provides responsive cybersecurity analyst workstation with persistent navigation shell, live health indicators, and genuine Neo4j graph statistics.
- Direct answer narratives feature interactive `[CIT-X]` badges that open evidence inspection drawers.
- Interactive Cytoscape.js canvas renders validated multi-hop paths with path-highlighting, pan/zoom/fit controls, and an accessible textual fallback.
- Multi-format CTI ingestion workbench supporting PDF, HTML, JSON, and TXT documents.

---

## Empirical Research Evaluation & Validation (Phase 9.1 Results)

ThreatMind's core design objective—**"No guessing. No hallucination. Only graph-backed facts"**—was formally evaluated under strict research integrity protocols on an isolated benchmark corpus consisting of **7 authentic public CTI advisories** from CISA and MITRE ATT&CK and **15 structured benchmark questions** (`data/evaluation/`).

### 1. Research Hypothesis vs. Empirical Outcome Matrix

| Research Question / Paper Concept | Target Metric | Verified Empirical Outcome | Scientific Interpretation & Boundary Condition |
| :--- | :--- | :--- | :--- |
| **CTINexus**: Information Extraction Integrity | Entity & Relation Extraction | **NOT RUN (Offline Mode - LLM Ingestion requires live provider)** | Offline deterministic evaluation rigorously isolates GraphRAG retrieval, reasoning, and grounding; it does not measure live LLM document extraction against unparsed text. |
| **Cti-Thinker**: GraphRAG Fact Retrieval | Retrieval Recall@5 & Precision | **58.3% Recall@5** (14/24 facts)<br>**34.1% Pooled Retrieved-Fact Precision (top-5 windows)** (14/41 opportunities)<br>**13.3% Query-Level Zero-Resolved-Seed Rate** (2/15 queries; 0/10 on answerable)<br>**87.5% Entity-Mention Resolution** (21/24 candidate mentions) | Successfully recovers primary attack facts; precision bounded by top-5 retrieval window over multi-hop subgraphs; zero-resolved seed rate reflects intentional out-of-graph queries ($q_{11}, q_{12}$). Mention resolution resolved 21 of 24 entity mentions across the 15 queries (3 unresolved: $q_{11}$, $q_{12}$, $q_{15}$). |
| **Multi-Hop Threat Reasoning**: Path Validity | Path Structural Validity & Continuity | **100.0% Validity** (70/70 paths)<br>**100.0% Continuity** (70/70 paths)<br>**0/0 (N/A) Cycle Rejection** | Zero broken hops; zero cycles encountered in benchmark queries (reported as `0/0 (N/A)`); all paths satisfy strict Cypher schema templates and endpoint connectivity constraints. |
| **Evidence Grounding**: Citation Integrity | Citation ID Integrity | **100.0% Integrity** (71/71 citations) | Emitted citations referencing valid deterministic `ev_` hashes backed by authentic text. |
| **Evidence Grounding**: Citation Completeness | Citation Completeness | **100.0% Completeness** (78/78 claims) | Proportion of emitted answer claims indexed to at least one valid citation (Numerator: 78 claims with valid citations / Denominator: 78 total emitted claims across accepted answers = 78/78). |
| **Evidence Grounding**: Claim Hallucination Guard | Automated Validation Failure Rate | **0.0% Failure Rate** (0/78 claims) | Proportion of claims failing automated validation checks ($0/78$). *Methodological Distinction*: Reflects automated deterministic and lexical verification against graph paths; does not constitute independent human assessment of natural-language semantic entailment. |
| **RAG Attribution**: Abstention Reliability | Abstention on Missing Evidence | **100.0% Precision** (5/5 correct rejections)<br>**100.0% Recall** (5/5 unanswerables caught) | Enforces general endpoint-validation invariant: multi-entity queries require an accepted path connecting all queried endpoints. Successfully catches unobserved entities ($q_{11}, q_{12}$), disconnected relationships ($q_{13}, q_{14}$), and false premises ($q_{15}$). |

---

### 2. Controlled Baseline Comparison

All baselines were evaluated against the identical **7 authentic source documents** and **15 structured benchmark questions** under zero-leakage conditions:

| System / Baseline | Architecture | Multi-Hop Traversal | Abstention Precision | Abstention Recall | False Abstention Rate | Evidence Traceability |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **Baseline A: Keyword Lookup** | BM25 / Regex Snippet Search | No | **0/0 (N/A)** | 0/5 (0.0%) | 0/10 (0.0%) | Raw text snippet |
| **Baseline B: 1-Hop Graph Retrieval** | Bounded 1-Hop Neo4j Query | No | 2/2 (100.0%) | 2/5 (40.0%) | 0/10 (0.0%) | Direct edge only |
| **ThreatMind Full Pipeline** | GraphRAG + Path Validation + Provenance | **Yes (Up to 3 hops)** | **5/5 (100.0%)** | **5/5 (100.0%)** | **0/10 (0.0%)** | **Full Cytoscape Path + Drawer** |

---

### 3. Methodological Boundaries & Separation of Claims

To preserve academic and engineering integrity:
1. **Implemented Features**: Graph schema, GraphRAG retrieval, Cypher path traversal, deterministic evidence hashes, citation drawers, Cytoscape graph rendering.
2. **Unit-Test Verification**: Invariant enforcement, cycle rejection, schema validation, endpoint validation, and API contract conformity across 108 backend tests and 14 frontend tests.
3. **Synthetic Demonstration Fixture**: Dedicated demo records in `data/sample/demo_synthetic_cti.json` explicitly tagged `is_synthetic: true`.
4. **Real-Source Empirical Evaluation**: 7 authentic public CTI documents in `data/evaluation/` (`is_synthetic: false`) and 15 structured questions, evaluated in leakage-free offline deterministic mode (`scripts/run_evaluation.py`).
5. **Endpoint Validation & Abstention Invariant**:
   - Queries with multiple resolved entities ($k \ge 2$) require an accepted path connecting the queried concepts rather than accepting isolated subgraphs of a single entity.
   - For 3+ entity queries ($k \ge 3$), the entire queried relationship chain must be supported, ensuring that queries inquiring about actor exploitation do not falsely answer using disconnected target subgraphs.
6. **Known Limitations & Future Work**:
   - Lexical vs. Semantic Grounding: Token-based and regex validation catches hallucinated relations and compromise claims, but formal semantic entailment requires automated natural language inference (NLI) models or independent human evaluation.
   - Real-World Scale: The benchmark evaluates 7 authentic public advisories; scaling to hundreds of thousands of advisories will require hybrid dense-sparse vector indexing alongside GraphRAG.


