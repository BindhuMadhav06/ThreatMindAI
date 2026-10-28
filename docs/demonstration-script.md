# ThreatMind: 5-to-7 Minute Analyst Demonstration Script

**Title**: *ThreatMind: AI-Powered Cyber Threat Intelligence Detective*  
**Presenter**: Security Operations Center (SOC) Lead / Threat Intelligence Researcher  
**Target Audience**: Security Analysts, CTI Researchers, and Technical Evaluators  
**Total Duration**: ~6 Minutes  

---

## Pre-Demonstration Notice
> [!NOTE]
> This demonstration utilizes the **Synthetic Demonstration Fixture** (`data/sample/demo_synthetic_cti.json`, explicitly flagged `is_synthetic: true`) alongside public CTI samples. Synthetic records are utilized exclusively for integration verification and pipeline demonstration, and are never presented as real threat intelligence.

---

## Demonstration Timeline & Workflow

| Scene | Duration | Focus Area | Key Visuals / UI Components |
| :---: | :---: | :--- | :--- |
| **1** | 0:00–1:00 | **The Problem & System Overview** | Persistent Shell, Health Badge (`Connected`), Neo4j Stats |
| **2** | 1:00–2:30 | **Direct Factual Query & Provenance Inspection** | Query Input, Grounded Answer Card, `[CIT-1]` Badge, Evidence Drawer |
| **3** | 2:30–4:15 | **Multi-Hop Reasoning & Knowledge Graph** | Multi-Hop Query, Cytoscape Canvas, Node Highlighting, Path Viewer |
| **4** | 4:15–5:30 | **Adversarial Query & Deterministic Abstention** | Disconnected Query, Canonical Abstention Banner, Zero Hallucinations |
| **5** | 5:30–6:30 | **CTI Ingestion Workbench & Conclusion** | Ingestion Page, Drag-and-Drop Uploader, Architectural Summary |

---

## Detailed Scene Breakdown

### Scene 1: The Problem & System Overview (0:00 – 1:00)
**Presenter Action**:
- Navigate to `http://localhost:5173`.
- Point out the top header bar: **ThreatMind Workstation**, live **Neo4j Connected** status badge, and graph statistics counter.

**Spoken Dialogue**:
> "Welcome everyone. Today we are demonstrating ThreatMind, an AI-powered Cyber Threat Intelligence investigation system.
> 
> In modern cybersecurity operations, analysts are inundated with unstructured threat reports from CISA, MITRE, and private vendors. While generative LLMs can summarize text, they present a catastrophic vulnerability in security operations: **hallucination**. Off-the-shelf LLMs frequently invent attack paths, misattribute malware, or turn documented capabilities into false assertions of successful compromise.
> 
> ThreatMind operates on a strict principle: *'No guessing. No hallucination. Only graph-backed facts.'* Every substantive claim is grounded in a Neo4j knowledge graph using schema-governed traversals and anchored to verbatim evidence passages via cryptographic SHA-256 hashes."

---

### Scene 2: Direct Factual Query & Evidence Drawer Inspection (1:00 – 2:30)
**Presenter Action**:
- In the Investigation Search bar, enter:
  `What malware is associated with APT29?`
- Click **Investigate**.
- When the answer appears, highlight the **Grounding Status: Fully Grounded** badge.
- Click on the interactive citation badge `[CIT-1]`.
- Demonstrate the **Evidence Drawer** sliding open from the right.

**Spoken Dialogue**:
> "Let's begin with a factual lookup: *'What malware is associated with APT29?'*
> 
> Notice what happens behind the scenes: ThreatMind resolves the entity `APT29`, queries the Neo4j knowledge graph, and retrieves documented relationship edges.
> 
> In the response card, ThreatMind doesn't just return prose—it indexes every assertion to an interactive citation badge like `[CIT-1]`.
> 
> When I click `[CIT-1]`, our Evidence Drawer opens. Notice what we see:
> 1. The exact source document: CISA Advisory AA21-116A.
> 2. The relationship type: `ThreatActor -[USES]-> Malware`.
> 3. The verbatim evidence quote from the advisory.
> 4. The stable cryptographic identifier: `ev_8a9f3b12c4d5`.
> 
> There are no ghost citations or invented sources. Every assertion is verifiable down to the character offset."

---

### Scene 3: Multi-Hop Threat Path Reasoning & Interactive Graph (2:30 – 4:15)
**Presenter Action**:
- Enter a multi-hop query:
  `Which vulnerabilities and products are associated with APT29 intrusions?`
- Click **Investigate**.
- Scroll to the **Interactive Knowledge Graph** (Cytoscape canvas) and the **Validated Threat Paths** section.
- Click a node on the Cytoscape graph (e.g., `CVE-2019-19781` or `Citrix ADC`) to inspect properties.
- Click **Highlight Path** to see the continuous path illuminate on the graph canvas.

**Spoken Dialogue**:
> "Threat intelligence rarely exists as a single hop. In an active intrusion, analysts need to know: *How does an adversary move from initial capability to enterprise software impact?*
> 
> Let's ask: *'Which vulnerabilities and products are associated with APT29 intrusions?'*
> 
> ThreatMind executes a bounded Depth-First Search up to 3 hops in Neo4j. It traverses:
> `APT29` $\to$ `EXPLOITS` $\to$ `CVE-2019-19781` $\to$ `AFFECTS` $\to$ `Citrix ADC`.
> 
> Notice three critical features:
> 1. **Path Continuity**: The target of hop 1 perfectly matches the source of hop 2.
> 2. **Interactive Visualization**: In our Cytoscape.js canvas, nodes are color-coded by entity type—red for threat actors, amber for vulnerabilities, purple for products. Clicking on any node displays its canonical attributes in the inspector.
> 3. **Semantic Caveats**: Notice the warning banner automatically injected below the path: *'Graph connectivity reflects observed usage; it does not imply attribution permanence or temporal sequence.'* ThreatMind refuses to let the analyst assume causality where the source only documented usage."

---

### Scene 4: Adversarial Query & Deterministic Abstention (4:15 – 5:30)
**Presenter Action**:
- In the search bar, enter an adversarial false-premise query:
  `Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?`
- Click **Investigate**.
- Observe the immediate response: The **Canonical Abstention Banner** is displayed.
- Point out the grounding status: **Insufficient Evidence**.

**Spoken Dialogue**:
> "Now let's test what happens when the intelligence does *not* exist.
> 
> We ask: *'Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?'*
> 
> Both Sandworm Team and the Log4j vulnerability exist in our database. In fact, our graph has a valid relationship proving that CVE-2021-44228 affects Apache Log4j.
> 
> A standard LLM or naive RAG system will fall into what we call the **Isolated Subgraph Trap**: it sees the valid CVE-to-product edge and synthesizes a confident answer falsely claiming Sandworm exploited Log4j.
> 
> But observe ThreatMind: it enforces our **General Endpoint-Connectivity Invariant**. Because the primary subject—Sandworm Team—is disconnected from the Log4j subpath, ThreatMind rejects the path and refuses to answer.
> 
> It emits our canonical abstention phrase:
> *'ThreatMind could not establish a sufficiently supported relationship from the currently available sources.'*
> 
> Status is `insufficient_evidence`. Citations emitted: **zero**. It refuses to guess."

---

### Scene 5: CTI Ingestion Workbench & Conclusion (5:30 – 6:30)
**Presenter Action**:
- Click on **Ingestion** in the top navigation shell.
- Show the document upload interface supporting PDF, HTML, JSON, and TXT.
- Point out the schema extraction indicators and SHA-256 deduplication notice.

**Spoken Dialogue**:
> "Finally, how does new intelligence enter the system?
> 
> On our Ingestion Workbench, analysts can upload fresh threat advisories. ThreatMind extracts entities using Pydantic schemas, normalizes aliases to canonical MITRE ATT&CK and CVE identifiers, computes SHA-256 evidence hashes, and executes idempotent Cypher `MERGE` queries to update the knowledge graph without duplicates.
> 
> In summary: ThreatMind demonstrates that by constraining LLMs within a deterministic graph sandwich—bounded Cypher traversal before generation, and multi-stage cryptographic verification after generation—we can provide analysts with transparent, evidence-traceable intelligence without the risk of hallucination.
> 
> Thank you, and I welcome any questions."
