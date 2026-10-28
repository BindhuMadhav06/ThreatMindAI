# ThreatMind: A Graph-Grounded Neurosymbolic Architecture for Evidence-Traceable Cyber Threat Intelligence Investigation

**Bindhu Madhav**  
*Department of Computer Science & Engineering*  
*ThreatMind Cyber Research Group*  
*Email: bindhumadhav@example.org*  

---

### Abstract
Cyber Threat Intelligence (CTI) investigation requires synthesizing complex, multi-hop relationships across heterogeneous threat advisories, malware reports, and vulnerability disclosures. While Large Language Models (LLMs) offer fluent natural-language querying, their deployment in high-stakes security operations is critically impeded by hallucination, spurious relational synthesis, and unverified attribution. In this paper, we propose **ThreatMind**, an open-source, evidence-grounded neurosymbolic architecture for transparent cyber threat investigation. ThreatMind constrains LLM reasoning within a "deterministic sandwich": pre-generation retrieval is bounded to a Neo4j knowledge graph using schema-governed, multi-hop graph traversal ($\le 3$ hops) with strict endpoint-connectivity invariants; post-generation responses undergo a multi-stage deterministic AnswerValidator that verifies citation pool integrity, validates stable SHA-256 evidence hashes (`ev_...`), enforces lexical passage alignment, and suppresses unsubstantiated attack-success and causality claims.

We empirically evaluate ThreatMind on a zero-leakage benchmark comprising **seven authentic public CTI advisories** from CISA and MITRE ATT&CK and **15 structured benchmark questions** spanning factual lookup, multi-hop attribution, disconnected entity pairs, and adversarial false premises. In offline deterministic evaluation, ThreatMind achieves **100.0% Abstention Precision (5/5)** and **100.0% Abstention Recall (5/5)** across unanswerable queries—eliminating false answers where keyword lookup and 1-hop graph baselines fail. Evaluated multi-hop paths demonstrate **100.0% structural validity (70/70)** and **100.0% step continuity (70/70)** with **0/0 (N/A) cycle rejection**. Emitted claims achieve **100.0% Citation Completeness (78/78)** and **100.0% Citation ID Integrity (71/71)**, with an **Automated Validation Failure Rate of 0.0% (0/78)** under automated guard checks. We provide complete reproducibility instructions, discuss failure modes including the isolated subgraph trap, and transparently delineate the boundary between deterministic syntactic verification and human semantic entailment.

### Index Terms
Cyber Threat Intelligence (CTI), Knowledge Graphs, GraphRAG, Multi-Hop Reasoning, Neurosymbolic AI, Hallucination Mitigation, Evidence Provenance, Neo4j.

---

## I. Introduction

The modern cybersecurity threat landscape produces an overwhelming volume of unstructured Cyber Threat Intelligence (CTI) in the form of government security advisories, vendor whitepapers, vulnerability reports, and threat group profiles [1]. Security Operations Center (SOC) analysts and threat hunters face the formidable challenge of manually correlating these disparate narratives into actionable attack chains—mapping adversary groups to custom malware, exploited Common Vulnerabilities and Exposures (CVEs), and targeted enterprise infrastructure [2].

Recent advancements in generative artificial intelligence and Large Language Models (LLMs) have motivated their application as natural-language interfaces for threat intelligence [3]. However, off-the-shelf generative LLMs suffer from severe failure modes in domain-critical cybersecurity tasks:
1. **Relational Hallucination**: Generative models frequently confabulate relationships between well-known but unassociated entities, such as falsely attributing a ransomware campaign to a high-profile Advanced Persistent Threat (APT) group due to training corpus co-occurrence [4].
2. **Unsupported Causality and Compromise Claims**: LLMs often convert documented capabilities into factual assertions of compromise (e.g., asserting that an actor "successfully destroyed" a network when the intelligence source merely noted that the actor "utilized" a utility) [5].
3. **Ghost Citations and Ungrounded Assertions**: Models invent non-existent report numbers, invalid CVE identifiers, or quote passages that do not exist in the source literature [6].

In mission-critical security environments, an ungrounded or fabricated intelligence assessment can misdirect incident response teams, waste forensic engineering hours, or result in severe misattribution [1], [2]. To address this challenge, we present **ThreatMind**, an evidence-grounded neurosymbolic investigation system designed around the operational principle:
> *"No guessing. No hallucination. Only graph-backed facts."*

ThreatMind couples the structural rigor of property knowledge graphs with the expressive querying capabilities of LLMs while enforcing strict deterministic constraints before and after generation. Rather than allowing the generative model to infer unverified paths, ThreatMind bounds retrieval to explicit Cypher graph traversals, validates path endpoint connectivity, anchors every relationship edge to verbatim source text via deterministic cryptographic hashes, and subjects candidate answers to independent deterministic verification stages.

### Contributions
This paper presents the following primary contributions:
- **A Neurosymbolic CTI Architecture**: We design and implement ThreatMind, an end-to-end investigation system featuring controlled document ingestion, a 13-entity Neo4j knowledge graph schema, GraphRAG retrieval, bounded multi-hop reasoning, and a responsive React analyst workstation.
- **Endpoint-Connected Path Traversal**: We formulate an endpoint-connectivity invariant for multi-entity queries that prevents "isolated subgraph hallucination," ensuring that queries involving multiple entities abstain unless an unbroken, evidenced relationship chain connects all queried endpoints.
- **Decoupled Citation and Grounding Validation**: We implement a multi-stage validation engine that separates syntactic citation integrity from lexical passage alignment and suppresses unsupported attack-success assertions.
- **Empirical Benchmark and Baseline Comparison**: We evaluate ThreatMind on a curated benchmark of **seven authentic public CTI advisories** and **15 structured evaluation questions**, benchmarking against BM25/keyword search (Baseline A) and 1-hop graph retrieval (Baseline B). We transparently report exact numerators, denominators, and methodological boundaries.

---

## II. Problem Statement & Research Objectives

### A. Problem Formulation
Let a CTI corpus $\mathcal{D} = \{d_1, d_2, \dots, d_m\}$ consist of unstructured text advisories from reputable cybersecurity authorities. Let $\mathcal{G} = (\mathcal{V}, \mathcal{E}, \mathcal{P})$ denote a property knowledge graph where $\mathcal{V}$ is a set of typed cybersecurity entities (e.g., ThreatActor, Malware, Vulnerability), $\mathcal{E} \subseteq \mathcal{V} \times \mathcal{R} \times \mathcal{V}$ is a set of directed, typed relationship edges, and $\mathcal{P}: \mathcal{E} \to \mathcal{M}$ maps each edge to provenance metadata containing a source identifier $s \in \mathcal{D}$, verbatim passage text $t$, and publication metadata.

Given an analyst question $q$ containing resolved entity mentions $\mathcal{E}_q = \{e_1, e_2, \dots, e_k\} \subseteq \mathcal{V}$, the objective is to generate an evidence-grounded answer $\mathcal{A}$ that satisfies three core conditions:
1. **Relational Faithfulness**: Every relational assertion $(u, r, v)$ expressed in $\mathcal{A}$ must correspond to a verified path $p \in \mathcal{G}$ supported by valid provenance $\mathcal{P}(u, r, v)$.
2. **Endpoint Connectivity**: If $k \ge 2$, $\mathcal{A}$ must only confirm relationships if there exists a valid, unbroken path $p$ in $\mathcal{G}$ such that $\mathcal{E}_q \subseteq \text{Nodes}(p)$. If no bridging path exists, the system must trigger formal abstention:
$$\mathcal{A} = \text{ABSTAIN}$$
3. **Traceable Attribution**: Every substantive assertion in $\mathcal{A}$ must reference an active citation $[CIT\text{-}i]$ bound to a deterministic evidence hash $\text{ev\_id} = \text{SHA256}(s \parallel r \parallel t)_{[:12]}$.

### B. Research Objectives
1. **RO1 (Structural Faithfulness)**: Can bounded knowledge graph traversals restrict multi-hop reasoning strictly to documented intelligence without inventing missing edges?
2. **RO2 (Abstention Reliability)**: Does enforcing endpoint connectivity eliminate false answers on unobserved entities, disconnected entities, and false relational premises?
3. **RO3 (Provenance and Grounding Integrity)**: Can deterministic post-generation validation eliminate broken citations, fabricated identifiers, and unsubstantiated compromise claims?

---

## III. Related Work

### A. CTI Knowledge Graph Construction
Transforming unstructured cybersecurity reports into structured knowledge graphs has been explored through various methodologies. Sarhan and Spruit introduced **Open-CyKG** [7], an open cyber threat knowledge graph that extracts relational triplets using Open Information Extraction (OpenIE) and neural language representations. While Open-CyKG demonstrated the feasibility of automated CTI graphing, its OpenIE pipeline suffered from noisy entity resolution and lacked explicit edge provenance linked to source paragraphs.

Li et al. proposed **AttacKG** [8], which parses CTI reports into attack behavior graphs and maps extracted actions to the MITRE ATT&CK framework using template-based alignment. AttacKG successfully formalized technique-level dependencies; however, it was primarily designed for threat graph construction rather than interactive natural-language question answering or multi-hop path query answering.

More recently, Cheng et al. developed **CTINexus** [1], an automated framework utilizing LLM in-context learning, hierarchical entity alignment, and long-distance relation prediction to construct comprehensive CTI knowledge graphs without extensive manual annotation. ThreatMind builds upon the structural insights of CTINexus and AttacKG, adopting standardized ontologies (CVE, MITRE ATT&CK, CPE) and strict edge provenance, but introduces an operational reasoning and answering layer that enforces deterministic abstention on ungrounded multi-hop queries.

### B. Retrieval-Augmented Generation (RAG) and GraphRAG
Retrieval-Augmented Generation, introduced by Lewis et al. [3], mitigates hallucinations by injecting retrieved document passages into the LLM context window. However, standard naive RAG systems rely on flat vector similarity searches over chunked text. As demonstrated by Edge et al. in Microsoft **GraphRAG** [9], flat dense retrieval struggles with global sensemaking, complex multi-hop relationship chains, and aggregate threat queries because relevant information is fragmented across disparate document chunks.

ThreatMind implements a controlled GraphRAG paradigm specifically tailored for CTI: instead of unconstrained semantic embedding search over raw text chunks, ThreatMind performs schema-bounded Cypher traversals across verified property graph nodes, ensuring that every retrieved context item represents an unbroken relational chain backed by specific evidence passages.

### C. Hallucination Mitigation and Abstention
Hallucination in natural language generation remains a pervasive challenge [4]. In domain-specific, high-consequence applications such as medicine, law, and cybersecurity, selective generation and abstention—enabling a system to state "I do not know" or reject ungrounded premises—are essential for safe deployment [10]. Recent works demonstrate that standard instruction-tuned LLMs struggle with abstention when prompted with false premises, frequently accommodating the user's erroneous assumptions [4], [10]. ThreatMind addresses this vulnerability through a neurosymbolic architecture: the decision to answer or abstain is governed by deterministic graph-connectivity checks rather than LLM self-assessment.

---

## IV. Proposed System Architecture

ThreatMind is structured as a decoupled, multi-tier system separating user interaction, business logic, knowledge graph storage, and language modeling. Fig. 1 illustrates the end-to-end system architecture.

```
+---------------------------------------------------------------------------------------------------+
|                        THREATMIND INVESTIGATION WORKSTATION (REACT 18 / TYPESCRIPT)                |
|  - Natural-Language Threat Querying    - Interactive Cytoscape.js Graph Canvas                    |
|  - Real-Time Node/Edge Filtering      - Deep Evidence & Provenance Inspection Drawers             |
+--------------------------------------------------+------------------------------------------------+
                                                   | REST API (HTTP / JSON)
+--------------------------------------------------v------------------------------------------------+
|                             FASTAPI APPLICATION CORE (PYTHON 3.12)                                |
|                                                                                                   |
|  +---------------------------------------+       +---------------------------------------------+  |
|  |       CONTROLLED INGESTION ENGINE     |       |         GRAPHRAG & REASONING ENGINE         |  |
|  | - PyMuPDF / BeautifulSoup Ingestion   |       | - Subject-Ordered Entity Resolver           |  |
|  | - Canonical Entity Normalizer         |       | - Bounded Depth-3 Graph Traversal (DFS)     |  |
|  | - Structured Pydantic Extraction      |       | - Endpoint-Connected Path Invariant         |  |
|  | - Deterministic Hash Anchor (ev_...)  |       | - Semantic Caveat & Attack Template Engine  |  |
|  +-------------------+-------------------+       +----------------------+----------------------+  |
|                      |                                                  |                         |
|                      | Parameterized Cypher                             | Parameterized Cypher    |
|  +-------------------v--------------------------------------------------v----------------------+  |
|  |             EVIDENCE-GROUNDED ANSWER GENERATION & VALIDATION SANDWICH                       |  |
|  | - Citation Pool Builder [CIT-1...N]        - Provider-Independent LLM Interface             |  |
|  | - Deterministic Evidence-Backed Fallback   - 5-Stage AnswerValidator Guard                   |  |
|  | - Lexical Passage Alignment Check          - Canonical Grounded Abstention Trigger           |  |
|  +---------------------------------------------------------------------------------------------+  |
+--------------------------------------------------+------------------------------------------------+
                                                   | Bolt Protocol (bolt://localhost:7687)
+--------------------------------------------------v------------------------------------------------+
|                             NEO4J 5.x CYBERSECURITY KNOWLEDGE GRAPH                               |
|  - 13 Primary Entity Labels (ThreatActor, Malware, Tool, Vulnerability, Technique, etc.)          |
|  - Strict Unique Constraints (id, cve_id, attack_id) & Schema Indexes                            |
|  - Edge Provenance Metadata (source_id, evidence_text, published_date)                            |
+---------------------------------------------------------------------------------------------------+
```
*Fig. 1. ThreatMind End-to-End System Architecture. The system decouples interactive visualization, REST query processing, graph-guided reasoning, answer validation, and graph persistence.*

The application consists of five major subsystems:
1. **Analyst Investigation Workstation**: A responsive single-page application built with React 18, TypeScript, Tailwind CSS, and Cytoscape.js. It features citation badges (`[CIT-1]`), interactive evidence drawers, color-coded node styling, and accessible graph views.
2. **FastAPI Backend Core**: A high-performance Python 3.12 REST server providing parameterized endpoints for natural-language answering (`/api/v1/query/answer`), GraphRAG retrieval (`/api/v1/query/retrieve`), multi-hop reasoning (`/api/v1/reasoning/paths`), entity exploration (`/api/v1/entities`), and document ingestion (`/api/v1/ingest/upload`).
3. **Controlled Ingestion Subsystem**: Converts raw unstructured reports into validated property graph nodes and edges with cryptographic provenance anchors.
4. **GraphRAG & Reasoning Subsystem**: Resolves entity mentions, traverses bounded graph paths up to three hops, enforces endpoint connectivity invariants, prunes cyclic paths, and injects semantic caveats.
5. **Answer Generation & Validation Sandwich**: Wraps candidate generation in pre-generation citation bounding and post-generation multi-stage deterministic verification.

TABLE I summarizes the foundational technology stack.

**TABLE I: ThreatMind Technology Stack**
| Architectural Layer | Core Technologies | Primary Function |
| :--- | :--- | :--- |
| **Frontend Workstation** | React 18, TypeScript, Vite, Tailwind CSS, Cytoscape.js | Interactive query UI, graph visualization, evidence inspection |
| **Backend REST API** | FastAPI, Uvicorn, Pydantic v2, Python 3.12 | REST routing, request validation, async orchestration |
| **Knowledge Graph** | Neo4j 5.20 Community Edition, Cypher Query Language | Property graph persistence, schema indexing, graph traversal |
| **Document Processing** | PyMuPDF (fitz), BeautifulSoup4, regex | Multi-format parsing (PDF, HTML, JSON, TXT), chunking |
| **LLM Interface** | Abstract Provider Interface (`BaseLLMProvider`), Google Gemini API | Structured natural-language synthesis with deterministic fallback |
| **Testing & Evaluation** | pytest, pytest-asyncio, vitest, python-docx, matplotlib | Automated test suites (108 backend, 14 frontend), benchmark evaluation |

---

## V. Knowledge Graph Schema & Provenance Architecture

### A. Entity Ontology and Schema Constraints
ThreatMind implements a cybersecurity property graph schema on Neo4j 5.x. The ontology comprises 13 primary node labels, as detailed in TABLE II.

**TABLE II: Primary Knowledge Graph Entity Labels and Uniqueness Constraints**
| Node Label | Unique Identifier Property | Secondary Indexed Properties | Description / Domain Scope |
| :--- | :--- | :--- | :--- |
| `ThreatActor` | `id` (e.g., `actor_apt29`) | `name`, `aliases`, `country` | Nation-state groups, cybercrime syndicates, APTs |
| `Malware` | `id` (e.g., `malware_blackenergy`) | `name`, `aliases`, `malware_type` | Malicious code, ransomware, backdoors, wipers |
| `Tool` | `id` (e.g., `tool_cobaltstrike`) | `name`, `aliases`, `category` | Dual-use software, penetration testing utilities |
| `Vulnerability` | `id` (e.g., `cve_2021_44228`) | `name`, `cve_id`, `cvss_score` | Security flaws with canonical CVE identifiers |
| `Technique` | `id` (e.g., `technique_t1059_001`) | `name`, `attack_id`, `description` | MITRE ATT&CK techniques and sub-techniques |
| `Tactic` | `id` (e.g., `tactic_ta0002`) | `name`, `attack_id`, `description` | High-level MITRE ATT&CK adversary tactics |
| `Campaign` | `id` (e.g., `campaign_solarwinds`) | `name`, `description`, `year` | Time-bounded, targeted cyber threat campaigns |
| `Product` | `id` (e.g., `prod_log4j`) | `name`, `vendor`, `version` | Target commercial or open-source software applications |
| `Software` | `id` (e.g., `sw_python`) | `name`, `version` | General platform software or library dependencies |
| `OperatingSystem`| `id` (e.g., `os_windows`) | `name`, `version` | Target host operating systems |
| `Organization` | `id` (e.g., `org_ukraine_energy`) | `name`, `sector`, `country` | Targeted victim organizations or industry sectors |
| `Indicator` | `id` (e.g., `ioc_hash_...`) | `type`, `value` | Indicators of Compromise (SHA-256 hashes, IP addresses) |
| `Source` | `id` (e.g., `cisa_aa22_110a`) | `title`, `url`, `publisher`, `published_date` | Ingested CTI document metadata and provenance root |

Schema integrity is enforced via 13 unique property constraints (`CREATE CONSTRAINT ... REQUIRE node.id IS UNIQUE`) and nine property indexes. This ensures idempotent entity ingestion and sub-millisecond indexed lookups.

### B. Relationship Vocabulary
Nodes are interconnected via 15 permissible relationship types:
- `(:ThreatActor)-[:USES]->(:Malware | :Tool)`
- `(:ThreatActor)-[:USES_TECHNIQUE]->(:Technique)`
- `(:ThreatActor)-[:EXPLOITS]->(:Vulnerability)`
- `(:ThreatActor)-[:TARGETS]->(:Organization)`
- `(:ThreatActor)-[:CONDUCTS]->(:Campaign)`
- `(:Malware)-[:USES_TECHNIQUE]->(:Technique)`
- `(:Malware)-[:TARGETS]->(:OperatingSystem | :Product)`
- `(:Tool)-[:USES_TECHNIQUE]->(:Technique)`
- `(:Technique)-[:PART_OF]->(:Tactic)`
- `(:Vulnerability)-[:AFFECTS]->(:Product | :OperatingSystem)`
- `(:Indicator)-[:ASSOCIATED_WITH]->(:ThreatActor | :Malware | :Tool)`
- `(:Entity)-[:SUPPORTED_BY]->(:Source)`

### C. Edge Provenance Model
A core vulnerability of standard knowledge graphs is the loss of context: once an edge $(u, r, v)$ is inserted, the original textual nuance, author confidence, and reporting context are often discarded. ThreatMind enforces mandatory provenance metadata on every relationship edge:
```json
{
  "source_id": "cisa_aa21_116a",
  "source_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a",
  "evidence_text": "SVR cyber operators frequently exploit CVE-2019-19781 affecting Citrix ADC systems.",
  "published_date": "2021-04-26",
  "evidence_id": "ev_8a9f3b12c4d5"
}
```
The deterministic evidence identifier is computed as:
$$\text{ev\_id} = \text{"ev\_"} + \text{SHA256}(s \parallel r \parallel t)_{[:12]}$$
where $s$ is the source identifier, $r$ is the relationship type, and $t$ is the verbatim passage text. This hash provides an audit anchor: every graph step traversed during investigation can be traced directly to the exact source paragraph from which it was extracted.

---

## VI. Controlled CTI Ingestion Pipeline

Fig. 2 illustrates the Controlled CTI Ingestion and Knowledge Graph Construction Workflow.

```
+---------------------------------------------------------------------------------------------------+
|                        CONTROLLED CTI INGESTION & GRAPH CONSTRUCTION PIPELINE                     |
|                                                                                                   |
|  +--------------------+     +---------------------+     +--------------------+                    |
|  | CTI Document Input | --> | Entity Normalizer   | --> | Structured         |                    |
|  | - PDF, HTML, JSON  |     | - CVE Regex         |     |   Extraction       |                    |
|  | - SHA-256 Digest   |     | - MITRE Technique ID|     | - Pydantic Schemas |                    |
|  | - Text Chunking    |     | - Threat Actor Alias|     | - Verbatim Quotes  |                    |
|  +--------------------+     +---------------------+     +---------+----------+                    |
|                                                                   |                               |
|                                                                   v                               |
|  +--------------------+     +---------------------+     +---------+----------+                    |
|  | Neo4j Idempotent   | <-- | Cypher MERGE        | <-- | Provenance Hash    |                    |
|  |   Knowledge Graph  |     |   Construction      |     |   Generation       |                    |
|  | - Unique Entities  |     | - MATCH (u), (v)    |     | - ev_sha256(...)   |                    |
|  | - Evidenced Edges  |     | - MERGE (u)-[r]->(v)|     | - Metadata Anchor  |                    |
|  +--------------------+     +---------------------+     +--------------------+                    |
+---------------------------------------------------------------------------------------------------+
```
*Fig. 2. CTI Ingestion and Knowledge Graph Construction Workflow.*

1. **Document Parsing**: Ingestion loaders extract raw text from PDF (via PyMuPDF), HTML (via BeautifulSoup), JSON, and plain text files. The file's cryptographic SHA-256 digest is recorded in the corresponding `Source` node to prevent duplicate document ingestion.
2. **Canonical Normalization**: Threat intelligence documents routinely refer to the same entity using disparate synonyms (e.g., "APT29", "Cozy Bear", "The Dukes", "SVR"). The Normalizer maps aliases to canonical identifiers (`actor_apt29`), validates CVE formats using strict regular expressions (`CVE-\d{4}-\d{4,7}`), and resolves MITRE ATT&CK technique numbers (`T\d{4}(\.\d{3})?`).
3. **Structured Entity and Relation Extraction**: Extraction is constrained by Pydantic models. Every extracted relationship must include an exact textual quote (`evidence_text`) from the parent document chunk; triplets without supporting text are rejected.
4. **Idempotent Cypher Insertion**: Triplet insertions use parameterized Cypher `MERGE` queries:
```cypher
MATCH (u:ThreatActor {id: $source_entity_id})
MATCH (v:Malware {id: $target_entity_id})
MERGE (u)-[r:USES]->(v)
ON CREATE SET r.evidence_text = $evidence_text,
              r.source_id = $source_id,
              r.evidence_id = $evidence_id,
              r.created_at = datetime()
```
This guarantees that repeated ingestion of identical advisories does not create duplicate nodes or parallel redundant edges.

---

## VII. GraphRAG Retrieval & Multi-Hop Path Reasoning

### A. Subject-Ordered Entity Resolution
When an analyst submits a query (e.g., *"Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?"*), the `QueryEntityResolver` extracts candidate tokens and queries the Neo4j index for known entity identifiers. Candidate tokens are normalized by stripping leading English interrogative and auxiliary verbs (`Did`, `Does`, `Is`, `Can`).

Crucially, resolved entities are sorted by character offset in the query string:
$$\mathcal{E}_q = (e_1, e_2, \dots, e_k), \quad \text{where } \text{Offset}(e_1) < \text{Offset}(e_2) < \dots < \text{Offset}(e_k)$$
This identifies the primary query subject $e_1$ (e.g., `Sandworm Team`), which anchors the graph traversal.

### B. Bounded Graph Traversal and the Endpoint-Connectivity Invariant
Graph traversal uses a bounded Depth-First Search (DFS) exploring permitted relationship paths up to depth $N = 3$. Traversal is constrained by relationship allowlists to prevent combinatorial explosion across dense hub nodes (e.g., general tactics like TA0002).

Fig. 3 illustrates the reasoning pipeline and the critical distinction between disconnected subgraphs and verified bridging paths.

```
+---------------------------------------------------------------------------------------------------+
|                        GRAPHRAG & ENDPOINT-CONNECTED MULTI-HOP REASONING                          |
|                                                                                                   |
|  Analyst Query: "Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?"                      |
|  Resolved Entities: E1 = Sandworm Team (Subject), E2 = CVE-2021-44228, E3 = Apache Log4j          |
|                                                                                                   |
|       [ISOLATED SUBGRAPH TRAP: REJECTED]                     [VERIFIED BRIDGING PATH: ACCEPTED]   |
|                                                                                                   |
|       (Sandworm Team)   [Disconnected]                       (Sandworm Team)                      |
|              x                                                      |                             |
|              x                                                      v [:USES]                     |
|       (CVE-2021-44228)                                       (BlackEnergy Malware)                |
|              |                                                      |                             |
|              v [:AFFECTS]                                           v [:EXPLOITS]                 |
|       (Apache Log4j)                                         (CVE-2021-44228)                     |
|                                                                     |                             |
|  • Graph contains valid CVE->Product subpath.                       v [:AFFECTS]                  |
|  • Subject E1 is NOT connected to E2.                        (Apache Log4j)                       |
|  • Endpoint Invariant: FAILED (Missing E1)                                                        |
|  • Outcome: REJECT PATH -> TRIGGER ABSTENTION                • Path bridges {E1, E2, E3}           |
|                                                              • Continuity: Valid (No broken hops) |
|                                                              • Endpoint Invariant: PASSED         |
+---------------------------------------------------------------------------------------------------+
```
*Fig. 3. GraphRAG Traversal and the Endpoint-Connected Reasoning Invariant.*

#### The Isolated Subgraph Trap
In naive GraphRAG implementations, if an analyst asks whether an adversary exploits a specific vulnerability, the retrieval layer may retrieve the vulnerability's relationship to an affected product (e.g., `CVE-2021-44228 -> Apache Log4j`). Because that relationship is factually present in the graph, an unconstrained LLM will frequently synthesize an affirmative answer, hallucinating an association between the adversary and the vulnerability.

To resolve this, ThreatMind enforces the **General Endpoint-Connectivity Invariant**:
1. For two-entity queries ($k = 2$): An accepted path $p$ must connect both endpoints:
$$\{e_1, e_2\} \subseteq \text{Nodes}(p)$$
2. For multi-entity queries ($k \ge 3$): The primary subject $e_1$ must be present in $p$, and all queried entities across the chain must be connected:
$$\mathcal{E}_q \subseteq \text{Nodes}(p)$$
3. **Continuity & Acyclicity**: For each adjacent hop $(h_i, h_{i+1})$, $\text{Target}(h_i) = \text{Source}(h_{i+1})$. Any path containing a repeated node ($u_i = u_j, i \ne j$) is pruned as cyclic.

If no active path satisfies this invariant, all partial paths are flagged as `unsupported_endpoint_relationship`, and the reasoning engine emits zero accepted paths.

### C. Semantic Caveat Injection
Knowledge graph connectivity does not imply causality or operational success. An edge `(:ThreatActor)-[:EXPLOITS]->(:Vulnerability)` indicates documented exploitation capability or activity, not universal breach success. ThreatMind automatically attaches explicit semantic caveats to accepted paths:
> *"Intelligence reports document observed usage or capability; graph connectivity does not imply attribution permanence, temporal sequence, or guaranteed exploitation success."*

---

## VIII. Evidence-Grounded Answer Generation & Abstention

Fig. 4 outlines the generation and validation workflow.

```
+---------------------------------------------------------------------------------------------------+
|                     EVIDENCE-GROUNDED ANSWER GENERATION & ABSTENTION WORKFLOW                     |
|                                                                                                   |
|  +-------------------------+     +--------------------------+     +----------------------------+  |
|  | Stage 1: Pre-Gen Bound  | --> | Stage 2: Structured Gen  | --> | Stage 3: AnswerValidator   |  |
|  | - Active Bridging Paths |     | - LLM Provider / Fallback|     | - Check 1: Citation Pool   |  |
|  | - Verbatim Evidence     |     | - Grounded Prompting     |     | - Check 2: ev_ Hash Match  |  |
|  | - Citation Pool [CIT-X] |     | - Structured Claims      |     | - Check 3: Causality Guard |  |
|  | - Deterministic ev_ IDs |     | - Explicit Citation Tags |     | - Check 4: Lexical Overlap |  |
|  +-------------------------+     +--------------------------+     +--------------+-------------+  |
|                                                                                  |                |
|                                                                                  v                |
|  +-------------------------------------------------------------------------------+-------------+  |
|  |                                  DECISION & PAYLOAD DISPATCH                                |  |
|  | If Active Bridging Paths == 0:                                                              |  |
|  |   -> Emit Canonical Abstention:                                                             |  |
|  |      "ThreatMind could not establish a sufficiently supported relationship from the         |  |
|  |       currently available sources."                                                         |  |
|  |   -> Grounding Status: 'insufficient_evidence', 0 Citations Emitted                         |  |
|  |                                                                                             |  |
|  | If All Verification Checks Pass:                                                           |  |
|  |   -> Emit Grounded AnswerResponse: Validated Claims, Citations, Active Paths, 'fully_grounded'|
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```
*Fig. 4. Evidence-Grounded Answer Generation and Abstention Sandwich.*

### A. Pre-Generation Bounding and the Stable Citation Pool
If active bridging paths exist, the `PromptBuilder` constructs an isolated prompt containing:
1. The validated path steps.
2. Verbatim source evidence text for each hop.
3. A stable, immutable citation pool:
$$[CIT\text{-}1] \to (s_1, r_1, \text{ev\_id}_1), \quad [CIT\text{-}2] \to (s_2, r_2, \text{ev\_id}_2), \quad \dots$$

The LLM is strictly instructed:
- Every substantive claim must cite at least one $[CIT\text{-}i]$ tag.
- No facts, entities, or relationships outside the provided evidence may be introduced.
- Speculation regarding compromise outcome or attribution is prohibited.

In offline or unconfigured environments, a deterministic evidence-backed generator synthesizes the answer directly from the validated path steps, ensuring complete testability without live API dependencies.

### B. Post-Generation Multi-Stage Verification (`AnswerValidator`)
Candidate responses are processed by five independent validation stages:
1. **Citation Pool Membership Check**: Verifies that every emitted $[CIT\text{-}i]$ tag exists in the active citation pool. Hallucinated tags (e.g., $[CIT\text{-}999]$) trigger immediate rejection.
2. **Evidence Hash Integrity Check**: Confirms that each citation's `evidence_id` conforms to the canonical `ev_[a-f0-9]{12}` structure and matches a retrieved graph record.
3. **Attack-Success and Causality Guard**: Scans claim text for aggressive compromise verbs (*"successfully breached"*, *"took over"*, *"destroyed"*, *"full control"*). If the cited evidence only documents capability or usage without confirmed impact, the claim is flagged as unsupported.
4. **Passage and Relationship Alignment Check**: Computes substantive token overlap between the claim text and the cited passage $(t \cup r)$. Requires at least two substantive domain keywords or $\ge 25\%$ token overlap.
5. **Conflicting Evidence Preservation**: If multiple sources report conflicting data (e.g., disparate CVE scores or contradictory target sectors), the validator prevents silent consensus and preserves the discrepancy in the response payload.

### C. Grounded Abstention Trigger
If the query entities cannot be resolved, or if the reasoning engine returns zero accepted bridging paths connecting the query endpoints, ThreatMind bypasses LLM generation and emits the canonical abstention response:
> *"ThreatMind could not establish a sufficiently supported relationship from the currently available sources."*

The response payload is assigned a grounding status of `insufficient_evidence`, contains zero emitted citations, and lists the unevidenced relationships under `warnings`.

---

## IX. Experimental Setup & Benchmark Corpus

### A. Evaluation Dataset Provenance
To prevent synthetic contamination, evaluation was conducted on an isolated benchmark corpus consisting of **seven authentic public CTI source documents** published by the Cybersecurity and Infrastructure Security Agency (CISA) and the MITRE Corporation. All records are tagged `is_synthetic: false`. TABLE III details the document manifest.

**TABLE III: Benchmark Corpus Document Manifest (v1.1.0)**
| Source ID | Document Title | Publishing Authority | Publication Date | SHA-256 Digest (Prefix) |
| :--- | :--- | :--- | :---: | :--- |
| `cisa_aa22_110a` | Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure | CISA / FBI / NSA | 2022-04-20 | `47802f041d14...` |
| `cisa_aa21_116a` | Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders | CISA | 2021-04-26 | `a04d84df2fb1...` |
| `cisa_aa21_356a` | Mitigating Log4Shell and Other Log4j-Related Vulnerabilities | CISA | 2021-12-22 | `e3f3c90c0385...` |
| `cisa_aa24_060b` | Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways | CISA | 2024-02-29 | `7e3fa36c1831...` |
| `cisa_aa24_038a` | PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure | CISA / NSA / FBI | 2024-02-07 | `115236b84058...` |
| `mitre_g0016_apt29` | Enterprise ATT&CK Group G0016: APT29 | MITRE Corporation | 2024-03-25 | `2108bf0854b1...` |
| `mitre_g0034_sandworm` | Enterprise ATT&CK Group G0034: Sandworm Team | MITRE Corporation | 2024-03-25 | `dc9a9db6c84a...` |

From these documents, 30 canonical entities and 25 relational facts were curated with character-exact offsets and verbatim source quotes.

### B. Benchmark Query Suite
The benchmark comprises **15 structured evaluation questions** designed to test diverse query complexities and failure conditions:
- **Factual Direct ($q_{01}$–$q_{05}$, $q_{09}$, $q_{10}$)**: Single-hop queries assessing documented relationships (e.g., $q_{01}$: *"What malware is associated with APT29?"*, $q_{03}$: *"What vulnerability affects Apache Log4j?"*).
- **Multi-Hop Traversal ($q_{06}$–$q_{08}$)**: Queries requiring 2- to 3-hop reasoning chains (e.g., $q_{06}$: *"How does APT29 attack systems?"*, $q_{07}$: *"Which vulnerabilities and products are associated with APT29 intrusions?"*).
- **Unanswerable: Unknown Entity ($q_{11}$, $q_{12}$)**: Queries concerning entities entirely absent from the corpus (e.g., $q_{11}$: *"What malware is used by PhantomSpider99?"*, $q_{12}$: *"What products are affected by CVE-2099-99999?"*). Expected response: Abstention.
- **Unanswerable: Disconnected Entities ($q_{13}$, $q_{14}$)**: Queries naming two or more known entities that have no documented relationship connecting them in the corpus (e.g., $q_{13}$: *"Did Volt Typhoon deploy BlackEnergy malware?"*, $q_{14}$: *"Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?"*). Expected response: Abstention.
- **Adversarial: False Premise ($q_{15}$)**: A multi-entity query with an asserted false premise (e.g., $q_{15}$: *"How did APT29 use Olympic Destroyer to attack the Ukrainian power grid?"*). While APT29, Olympic Destroyer, and Ukraine exist as concepts, Sandworm—not APT29—deployed Olympic Destroyer. Expected response: Abstention.

### C. Baselines for Comparison
ThreatMind is benchmarked against two standard architectural baselines:
- **Baseline A (Keyword Lookup)**: Standard BM25/lexical retrieval over raw text passages. If keyword matches for the query entities are found, the baseline attempts to answer from matching snippets without relational validation.
- **Baseline B (1-Hop Graph Retrieval)**: Retrieves only direct, immediate neighbors ($k = 1$) in the Neo4j knowledge graph without multi-hop path traversal or endpoint-chain validation.

---

## X. Empirical Results & Baseline Comparison

### A. Primary Benchmark Results
The benchmark was executed in zero-leakage offline deterministic mode (`scripts/run_evaluation.py --offline`). TABLE IV presents the consolidated empirical results.

**TABLE IV: ThreatMind Empirical Evaluation Benchmark Results**
| Metric Category | Specific Metric Name | Numerator / Denominator | Value | Scientific Definition & Notes |
| :--- | :--- | :---: | :---: | :--- |
| **Abstention Behavior** | **Abstention Precision** | 5 / 5 | **100.0%** | $\text{True Abstentions} / \text{Total System Abstentions}$. Rejections requiring abstention. |
| | **Abstention Recall** | 5 / 5 | **100.0%** | $\text{True Abstentions} / \text{Total Ground-Truth Unanswerable Queries}$ ($q_{11}$–$q_{15}$). |
| | **False Abstention Rate** | 0 / 10 | **0.0%** | $\text{False Abstentions} / \text{Total Answerable Queries}$. Legitimate queries rejected. |
| **GraphRAG Retrieval** | **Pooled Retrieved-Fact Precision (top-5 windows)** | 14 / 41 | **34.1%** | Micro-averaged precision across retrieved facts in top-5 retrieval windows. |
| | **Retrieval Recall@5** | 14 / 24 | **58.3%** | Proportion of documented gold attack facts recovered across answerable queries. |
| | **Query-Level Zero-Resolved-Seed Rate** | 2 / 15 | **13.3%** | Queries where zero required starting entities could be resolved in graph ($q_{11}$, $q_{12}$; $0/10$, $0.0\%$ on answerable queries). |
| | **Entity-Mention Resolution (candidate-to-node coverage)** | 21 / 24 | **87.5%** | Candidate entity mentions successfully resolved to graph nodes (3 unresolved: $q_{11}$, $q_{12}$, $q_{15}$). |
| **Multi-Hop Reasoning** | **Path Structural Validity** | 70 / 70 | **100.0%** | Evaluated paths satisfying Cypher schema templates and property constraints. |
| | **Path Step Continuity** | 70 / 70 | **100.0%** | Traversed steps satisfying $\text{Target}(h_i) = \text{Source}(h_{i+1})$ across all paths. |
| | **Cycle Rejection Rate** | 0 / 0 | **0/0 (N/A)** | Cyclic paths encountered and pruned (reported as N/A due to 0 candidate cycles). |
| **Evidence Grounding** | **Citation ID Integrity** | 71 / 71 | **100.0%** | Emitted citations referencing valid deterministic $\text{ev\_}$ hashes backed by text. |
| | **Citation Completeness** | 78 / 78 | **100.0%** | Emitted claims with $\ge 1$ valid citation / Total emitted claims in accepted answers. |
| | **Automated Validation Failure Rate** | 0 / 78 | **0.0%** | Claims failing automated deterministic guard checks ($0/78$). |
| **Document Extraction** | **Entity & Relation Extraction** | — | **NOT RUN** | **Offline Mode - LLM Ingestion requires live provider** (Disclosed boundary). |

*Retrieval Performance Analysis & Boundary Considerations*:
The empirical retrieval results reflect both the system's core strengths and its remaining operational boundaries. ThreatMind achieves a **Retrieval Recall@5 of 58.3%** (14 of 24 gold attack facts recovered across answerable queries) with a 0.0% zero-resolved seed rate on legitimate in-graph queries (0/10 on $q_{01}$–$q_{10}$), confirming that entity resolution and bounded Cypher traversal reliably locate the primary adversary tactics, malware families, and exploited CVEs. Across the full 15-query suite, the **Query-Level Zero-Resolved-Seed Rate is 13.3% (2/15)**, strictly measuring queries where no required starting entity could resolve in the graph: queries $q_{11}$ (*PhantomSpider99*) and $q_{12}$ (*CVE-2099-99999*) that intentionally query unobserved entities. Crucially, having zero resolved seeds on unobserved entities is the expected prerequisite that triggers canonical pre-retrieval abstention ($5/5$, 100.0% recall). At the mention level, **Entity-Mention Resolution (candidate-to-node coverage) is 87.5% (21/24)**. The three unresolved mentions fall into two distinct operational categories: (1) deliberately unobserved threat entities ($q_{11}$ *PhantomSpider99* and $q_{12}$ *CVE-2099-99999*) where resolution failure is the required condition to trigger canonical pre-retrieval abstention; and (2) a candidate-extraction artifact in $q_{15}$ where the geographic adjective "Ukrainian" was extracted as an entity candidate alongside the primary attack entities (*APT29* and *Olympic Destroyer*), which resolved cleanly and were subsequently neutralized downstream by the multi-hop endpoint invariant. However, **Pooled Retrieved-Fact Precision (top-5 windows) is bounded at 34.1%** (14 of 41 facts retrieved across top-5 candidate windows). This reflects an architectural trade-off: when exploring multi-hop subgraphs around an actor or vulnerability, the top-5 retrieval window inevitably captures structurally valid neighboring relationships (e.g., auxiliary malware techniques or secondary product impacts) that fall outside the concise gold answer subset for that specific query. Furthermore, 41.7% of gold facts were unrecovered within the top-5 cutoff on complex multi-hop queries, demonstrating the necessity of adaptive retrieval depth and hybrid dense-sparse vector indexing for future iterations.

### B. Controlled Baseline Comparison
TABLE V compares ThreatMind against Baseline A and Baseline B across all 15 benchmark questions.

**TABLE V: Controlled Baseline Comparison (15 Benchmark Questions)**
| Architecture / System | Multi-Hop Traversal | Abstention Precision | Abstention Recall | False Abstention Rate | Evidence Traceability |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Baseline A: Keyword Lookup (BM25)** | No | **0/0 (N/A)** | 0 / 5 (**0.0%**) | 0 / 10 (**0.0%**) | Raw text passage match only |
| **Baseline B: 1-Hop Graph Retrieval** | No | 2 / 2 (**100.0%**) | 2 / 5 (**40.0%**) | 0 / 10 (**0.0%**) | Direct 1-hop edge only |
| **ThreatMind Full Pipeline** | **Yes ($\le 3$ hops)** | **5 / 5 (100.0%)** | **5 / 5 (100.0%)** | **0 / 10 (0.0%)** | **Full Cytoscape Path + Provenance** |

Fig. 5 summarizes the baseline comparison across the benchmark categories.

```
+---------------------------------------------------------------------------------------------------+
|                        CONTROLLED BASELINE COMPARISON OVERVIEW                                    |
|                                                                                                   |
|  [Baseline A: Keyword Lookup]       [Baseline B: 1-Hop Graph]           [ThreatMind Full Pipeline] |
|  • Abstention Precision: 0/0 (N/A)  • Abstention Precision: 2/2 (100%)  • Abstention Prec: 5/5 (100%)|
|  • Abstention Recall: 0/5 (0.0%)    • Abstention Recall: 2/5 (40.0%)    • Abstention Rec: 5/5 (100%) |
|  • Multi-Hop Traversal: None        • Multi-Hop Traversal: None         • Multi-Hop: Yes (<= 3 hops)  |
|  • Evidence: Raw text match         • Evidence: Direct edge only        • Evidence: Verified Path     |
|                                                                                                   |
|  CRITICAL FAILURE:                  CRITICAL FAILURE:                   REASONING SUCCESS:            |
|  Keyword matching retrieves         Catches unknown entities (q11,q12)  Endpoint Invariant validates  |
|  passages containing query words    but cannot resolve multi-hop        connected bridging paths;     |
|  and produces false answers on      chains (q06, q07) and misses        abstains cleanly on isolated  |
|  false premises (q13, q15).         disconnected subgraphs (q14).       subgraphs (q13, q14, q15).    |
+---------------------------------------------------------------------------------------------------+
```
*Fig. 5. Controlled Baseline Comparison Overview.*

---

## XI. Discussion & Failure Analysis

### A. Analysis of Baseline Failures
The experimental findings illustrate why traditional text search and unconstrained RAG are fundamentally unsuited for high-stakes CTI investigation:

1. **Failure of Keyword Matching (Baseline A)**: In query $q_{13}$ (*"Did Volt Typhoon deploy BlackEnergy malware?"*), both "Volt Typhoon" and "BlackEnergy" appear extensively in the benchmark corpus across separate CISA advisories. Baseline A retrieves passages containing both entity terms and attempts to synthesize an answer, failing to abstain (**0.0% Abstention Recall, 0/5**; note that this reflects failure to abstain on ungrounded queries, not zero passage-retrieval recall). Similarly, in $q_{15}$ (*"How did APT29 use Olympic Destroyer to attack the Ukrainian power grid?"*), keyword matching finds all four terms across the documents and fabricates a narrative linking them, falsely validating the adversarial premise.
2. **Failure of 1-Hop Graph Retrieval (Baseline B)**: Baseline B successfully abstains on unknown entities ($q_{11}$ and $q_{12}$) because those nodes do not exist in the graph. However, it fails on multi-hop answerable queries ($q_{06}$, $q_{07}$, $q_{08}$), which require traversing from `ThreatActor` through `Malware` or `Vulnerability` to `Product`. Because no direct 1-hop edge connects the actor directly to the affected product, Baseline B produces incomplete or ungrounded answers. Furthermore, in $q_{14}$, Baseline B cannot determine whether a multi-hop path connects Sandworm to Log4j, failing on disconnected multi-entity queries.

### B. Resolution via ThreatMind Endpoint Validation
ThreatMind resolved all five unanswerable/adversarial queries ($q_{11}$–$q_{15}$):
- For $q_{11}$ and $q_{12}$, the `QueryEntityResolver` detected unresolvable entities (`PhantomSpider99`, `CVE-2099-99999`), triggering immediate abstention. This demonstrates that ThreatMind reliably abstained on the two designated out-of-graph queries; it reflects the observed behavior on these benchmark queries rather than a universal guarantee that graph-node hallucination is impossible across arbitrary open-domain queries.
- For $q_{13}$, both `Volt Typhoon` and `BlackEnergy` were resolved as valid nodes, but DFS traversal found zero paths connecting them within $N = 3$ hops. The endpoint invariant rejected candidate subgraphs, triggering abstention.
- For $q_{14}$ (*"Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?"*), the graph contained the valid subpath `(CVE-2021-44228)-[:AFFECTS]->(Apache Log4j)`. ThreatMind's endpoint-validation invariant detected that the primary subject (`Sandworm Team`) was disconnected from this subpath, rejecting the candidate path and triggering canonical abstention.
- For $q_{15}$, the adversarial false premise was neutralized because no unbroken path connected `APT29` to `Olympic Destroyer`.

---

## XII. Limitations & Threats to Validity

To preserve research integrity, we explicitly document the following technical and methodological limitations:

1. **Benchmark Scale Limitations**: The empirical evaluation was conducted on a curated pilot benchmark of seven authentic CTI advisories and 15 structured questions. While sufficient to validate architectural invariants and edge-case behavior, evaluating performance at production enterprise scale (e.g., millions of nodes across hundreds of thousands of reports) will require distributed graph partitioning and advanced indexing.
2. **Scope of the 100% Abstention Metric**: The reported 100.0% abstention precision and recall apply specifically to the five designated unanswerable and adversarial questions within this pilot evaluation suite. In particular, the unknown-entity tests demonstrate that ThreatMind successfully abstained on the two designated out-of-graph queries ($q_{11}$ and $q_{12}$). This result supports the specific observed behavior under controlled conditions; it **does not** constitute mathematical proof of complete hallucination immunity or a universal guarantee across arbitrary open-domain queries.
3. **Automated Verification vs. Human Semantic Entailment**: The 0.0% Automated Validation Failure Rate (0/78) reflects deterministic checks (citation pool existence, SHA-256 evidence hash verification, token overlap thresholds, and regex scanning for forbidden compromise verbs). These automated syntactic and lexical guards do not guarantee formal semantic entailment. A claim could theoretically pass lexical overlap while subtly distorting the author's intent. True semantic verification requires formal Natural Language Inference (NLI) models or independent human evaluation.
4. **Structural Validity vs. Factual Ground Truth**: ThreatMind's 100.0% path structural validity confirms that traversed paths conform to schema constraints, exhibit unbroken step continuity, and link to non-empty source evidence. It **does not** independently verify that the original intelligence publisher's factual assertions are true in the real world. ThreatMind reflects the ground truth of the ingested reports, including any errors or biases present in the underlying advisories.
5. **Offline Mode Extraction Disclosure**: In the reported offline deterministic benchmark, live LLM document extraction was marked as **`NOT RUN`**. The benchmark evaluated retrieval, multi-hop reasoning, and grounded answer synthesis from pre-ingested, authenticated graph data. Live document extraction against unparsed text requires an active LLM provider and remains subject to LLM parsing variance.

---

## XIII. Future Work

1. **Neural Natural Language Inference (NLI) for Semantic Entailment**: We plan to replace lexical token overlap in `AnswerValidator` with fine-tuned cross-encoder NLI models (e.g., DeBERTa-v3) to compute directional premise-to-hypothesis entailment scores, distinguishing true semantic entailment from lexical keyword sharing.
2. **Hybrid Dense-Sparse Graph Indexing**: To scale GraphRAG across massive corpora, we will integrate Neo4j Vector Indexing (hybrid dense embeddings + BM25 full-text indexes) with community-level graph summarization, as explored in Microsoft GraphRAG [9].
3. **Automated Contradiction and Temporal Resolution**: Threat intelligence reports frequently disagree regarding attribution or attack dates. Future iterations will implement automated belief-revision algorithms and temporal graph reasoning to weigh conflicting intelligence sources based on publisher reputation and report recency.
4. **Expanded Multi-Source Benchmarking**: We intend to expand the evaluation corpus to hundreds of MITRE ATT&CK group profiles and thousands of vendor threat advisories, establishing a community benchmark for CTI GraphRAG evaluation.

---

## XIV. Conclusion

In this paper, we introduced **ThreatMind**, an open-source, evidence-grounded neurosymbolic architecture for cybersecurity threat intelligence investigation. By constraining generative models within a deterministic sandwich—governed by schema-constrained property graph traversal, an endpoint-connectivity invariant, cryptographic evidence provenance hashing, and multi-stage answer validation—ThreatMind eliminates relational hallucinations and false premise synthesis. On an isolated empirical benchmark of seven authentic public CTI advisories and 15 structured questions, ThreatMind achieved 100.0% abstention precision and recall on unanswerable queries, 100.0% path validity, and 100.0% citation completeness, outperforming keyword lookup and 1-hop graph baselines. ThreatMind demonstrates that coupling structured knowledge graphs with deterministic verification provides a defensible foundation for deploying AI in high-stakes cybersecurity operations.

---

## Acknowledgment
The authors thank the Cybersecurity and Infrastructure Security Agency (CISA) and the MITRE Corporation for maintaining public-domain cyber threat intelligence advisories and frameworks. We also acknowledge the open-source communities behind Neo4j, FastAPI, React, and Cytoscape.js.

---

## References

[1] Y. Cheng, O. Bajaber, S. A. Tsegai, D. Song, and P. Gao, "CTINexus: Automatic Cyber Threat Intelligence Knowledge Graph Construction Using Large Language Models," in *Proc. 2025 IEEE European Symposium on Security and Privacy (EuroS&P)*, 2025. [Preprint: arXiv:2410.21060].

[2] B. E. Strom, J. A. Battaglia, M. S. Kemmerer, W. Kupersanin, D. P. Miller, C. W. Peach, D. R. Schroeder, and C. S. Stephenson, "MITRE ATT&CK: Design and Philosophy," MITRE Corporation, Bedford, MA, Tech. Rep. MTR180183, Mar. 2020.

[3] P. Lewis, E. Perez, A. Piktus, F. Petroni, V. Karpukhin, N. Goyal, H. Küttler, M. Lewis, W. Yih, T. Rocktäschel, S. Riedel, and D. Kiela, "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," in *Advances in Neural Information Processing Systems (NeurIPS 2020)*, vol. 33, 2020, pp. 9459–9474.

[4] Z. Ji, N. Lee, R. Frieske, T. Yu, D. Su, Y. Xu, E. Ishii, Y. J. Bang, A. Madotto, and P. Fung, "Survey of Hallucination in Natural Language Generation," *ACM Computing Surveys*, vol. 55, no. 12, pp. 1–38, Mar. 2023. DOI: 10.1145/3571730.

[5] Cybersecurity and Infrastructure Security Agency (CISA), "Alert AA21-116A: Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders," CISA Joint Cybersecurity Advisory, Apr. 26, 2021. [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a

[6] Cybersecurity and Infrastructure Security Agency (CISA), "Alert AA24-060B: Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways," CISA Joint Cybersecurity Advisory, Feb. 29, 2024. [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b

[7] I. Sarhan and M. Spruit, "Open-CyKG: An Open Cyber Threat Intelligence Knowledge Graph," *Knowledge-Based Systems*, vol. 233, p. 107524, Dec. 2021. DOI: 10.1016/j.knosys.2021.107524.

[8] Z. Li, J. Zeng, Y. Chen, and Z. Liang, "AttacKG: Constructing Technique Knowledge Graph from Cyber Threat Intelligence Reports," in *Computer Security – ESORICS 2022: 27th European Symposium on Research in Computer Security*, Copenhagen, Denmark, Part I, Lecture Notes in Computer Science, vol. 13554, Springer, 2022, pp. 617–639. DOI: 10.1007/978-3-031-17140-6_29.

[9] D. Edge, H. Trinh, N. Cheng, J. Bradley, A. Chao, A. Mody, S. Truitt, D. Metropolitansky, R. O. Ness, and J. Larson, "From Local to Global: A Graph RAG Approach to Query-Focused Summarization," *arXiv preprint arXiv:2404.16130*, Apr. 2024.

[10] A. Kamath, R. Jia, and P. Liang, "Selective Question Answering under Domain Shift," in *Proc. 58th Annual Meeting of the Association for Computational Linguistics (ACL)*, Online, Jul. 2020, pp. 5684–5696. DOI: 10.18653/v1/2020.acl-main.503.

[11] Cybersecurity and Infrastructure Security Agency (CISA), "Alert AA22-110A: Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure," CISA Joint Cybersecurity Advisory, Apr. 20, 2022 (revised May 9, 2022). [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a

[12] Cybersecurity and Infrastructure Security Agency (CISA), "Alert AA21-356A: Mitigating Log4Shell and Other Log4j-Related Vulnerabilities," CISA Joint Cybersecurity Advisory, Dec. 22, 2021 (revised Dec. 28, 2021). [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a

[13] Cybersecurity and Infrastructure Security Agency (CISA), NSA, and FBI, "Alert AA24-038A: PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure," CISA Joint Cybersecurity Advisory, Feb. 7, 2024 (revised Feb. 29, 2024). [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a

[14] MITRE Corporation, "APT29, Enterprise ATT&CK Group G0016," MITRE ATT&CK Framework, Mar. 2024. [Online]. Available: https://attack.mitre.org/groups/G0016/

[15] MITRE Corporation, "Sandworm Team, Enterprise ATT&CK Group G0034," MITRE ATT&CK Framework, Mar. 2024. [Online]. Available: https://attack.mitre.org/groups/G0034/

[16] Neo4j, Inc., "Neo4j Graph Database: Operations and Cypher Manual (v5.20)," San Mateo, CA, 2024. [Online]. Available: https://neo4j.com/docs/
