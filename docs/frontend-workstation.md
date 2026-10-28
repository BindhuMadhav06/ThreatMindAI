# ThreatMind: Investigation Workstation & Knowledge Graph Visualization

## 1. Overview & Architecture

Phase 8 introduces the **ThreatMind Investigation Workstation**, a modern, responsive React 18 / TypeScript / Vite frontend application connecting security analysts to ThreatMind's Neo4j Cyber Threat Intelligence Knowledge Graph, GraphRAG retrieval, and evidence-grounded answer generation.

### Design Principles:
- **Zero Fabrication**: The workstation renders authentic backend API data only. It does not fabricate metrics, hard-code mock entities, or invent fake citations.
- **Strict Evidence Transparency**: Substantive factual claims in generated answers feature interactive `[CIT-X]` citation tags linking directly to verbatim quotes, source metadata, and graph provenance.
- **Synthetic Data Notices**: When responses derive from synthetic test fixtures (e.g. `demo_synthetic_cti.json`), prominent warnings ensure analysts know findings are for integration verification rather than real-world threat intelligence.
- **Cybersecurity Workstation Aesthetics**: High-contrast, dark slate/navy palette (`#020617`, `#0f172a`), restrained cyan accents (`#06b6d4`), monospace data labels, and WCAG AA contrast compliance.

---

## 2. Workstation Pages & Workflows

### A. Dashboard (`Dashboard.tsx`)
- **Real-Time Health Status**: Live indicators querying `/api/v1/health` for FastAPI API availability, Neo4j connectivity, and LLM provider status.
- **Genuine Graph Distribution**: Queries `/api/v1/graph/stats` to show real counts of nodes by primary label (`ThreatActor`, `Malware`, `Tool`, `Vulnerability`, `Technique`, etc.), total relationships, and stored sources.
- **Workstation Shortcuts**: Quick access to Threat Investigation, Knowledge Graph canvas, and CTI Ingestion.
- **Recent Investigations**: Displays queries executed in the current session (stored in browser `sessionStorage`; explicitly disclosed as not persisted on remote servers).

### B. Threat Investigation (`InvestigationPage.tsx`)
The central analyst workflow:
1. **Natural-Language Query Input** (`QuestionInput.tsx`):
   - Input field with query submission and loading indicators.
   - Request cancellation support via browser `AbortController`.
   - Labeled example queries (e.g., *"How does APT29 attack systems?"*, *"What vulnerabilities are exploited by APT29?"*).
   - Traversal controls (configurable depth 1–3, max paths 1–20, entity hints).
2. **Grounded Answer Card** (`AnswerCard.tsx`):
   - Executive summary of findings.
   - Direct narrative explanation with inline interactive citation tags `[CIT-1]`, `[CIT-2]`.
   - Application grounding status badge (`Fully Grounded`, `Partially Grounded`, `Insufficient Evidence`, `Unsupported Claims`).
   - Strict abstention display when evidence is missing: *"ThreatMind could not establish a sufficiently supported relationship from the currently available sources."*
   - Expandable analytical caveats and operational warnings.
3. **Integrated Knowledge Graph Canvas** (`CytoscapeGraph.tsx`):
   - Renders actual multi-hop attack paths returned by the answer endpoint.
4. **Reasoning Path Viewer** (`PathViewer.tsx`):
   - Step-by-step traversal chains with template badges and relevance scores.
   - Clicking a path highlights the corresponding nodes and edges on the Cytoscape graph.
5. **Granular Claim-Level Inspector** (`ClaimsList.tsx`):
   - Evaluates each claim independently with `VERIFIED` or `UNVERIFIED` badges and validation reasons.

### C. Evidence & Citation Drawer (`CitationDrawer.tsx`)
Clicking any `[CIT-X]` badge opens a dedicated slide-out drawer showing:
- Citation ID and deterministic evidence ID (`ev_<sha256>`).
- Verbatim quoted evidence passage from the source document.
- Supported graph relationship: `(Actor) -[REL]-> (Target)`.
- Source metadata: Title, publisher, publication date, extraction confidence.
- Source URL with safe external link (`target="_blank" rel="noopener noreferrer"`).
- Explicit synthetic demonstration data disclosure if applicable.

### D. Knowledge Graph Canvas (`KnowledgeGraphPage.tsx`)
Interactive Cytoscape.js exploration canvas:
- Color-coded entity nodes: ThreatActor (Rose), Malware (Orange), Tool (Amber), Vulnerability (Purple), Technique (Blue), Product (Emerald), Organization (Teal).
- Directional relationship edges with relationship type labels.
- Pan, zoom, and fit-to-screen controls.
- Node & Edge Inspector (`GraphInspector.tsx`) showing properties and evidence.
- Accessible textual fallback view (`AccessibleGraphList.tsx`) for screen readers.

### E. CTI Document Ingestion (`IngestionPage.tsx`)
- Multi-format ingestion uploader (`IngestionForm.tsx`) supporting PDF, HTML, JSON, and TXT files (up to 10MB) as well as direct text input.
- Metadata fields: Title, Source URL, Publisher, Publication Date.
- No automated retries on failure (preventing unintentional duplicate document processing).
- Results card (`IngestionResult.tsx`) showing chunk count, extracted entities, accepted vs rejected relationships, and validation notes.

### F. Entity Directory (`EntitiesPage.tsx`)
- Filterable directory by approved primary label and search query.
- Inspects real Neo4j nodes and their 1-hop connections and evidence via `/api/v1/entities/{id}`.

---

## 3. API Integration & Backend Endpoints

The frontend communicates with FastAPI via centralized Axios client in `frontend/src/api/`:

| Endpoint | Method | Purpose | Frontend Client Function |
| :--- | :---: | :--- | :--- |
| `/api/v1/health` | `GET` | Health status (API, Neo4j, LLM) | `fetchHealth()` |
| `/api/v1/graph/stats` | `GET` | Authentic node, edge, and source counts | `fetchGraphStats()` |
| `/api/v1/entities` | `GET` | Filtered entity list (max 100) | `fetchEntities()` |
| `/api/v1/entities/{id}` | `GET` | 1-hop neighbors and provenance | `fetchEntityDetails()` |
| `/api/v1/query/answer` | `POST` | Evidence-grounded natural-language Q&A | `askQuestion()` |
| `/api/v1/query/reason` | `POST` | Multi-hop reasoning path exploration | `executeReasoning()` |
| `/api/v1/query/retrieve` | `POST` | Bounded graph context retrieval | `retrieveContext()` |
| `/api/v1/ingestion` | `POST` | Multi-format CTI document ingestion | `ingestDocument()` |

---

## 4. Security & Accessibility Controls

1. **Zero Secret Exposure**: All database credentials and Gemini API keys remain exclusively on the backend (`.env`). The Vite production bundle (`dist/`) was scanned to verify that no credentials or secrets are leaked.
2. **Untrusted Text Rendering**: All document quotes, entity names, and answer texts are rendered as plain text nodes `{text}`. `dangerouslySetInnerHTML` is strictly prohibited.
3. **Safe Links**: External URLs use `target="_blank" rel="noopener noreferrer"`.
4. **Accessibility (WCAG AA)**:
   - High contrast text on dark backgrounds.
   - Screen-reader labels (`aria-label`, `aria-labelledby`, `role="dialog"`, `role="status"`).
   - Keyboard navigation and Escape-key drawer dismissal.
   - Textual graph alternative (`AccessibleGraphList.tsx`) for users who cannot interpret visual canvases.

---

## 5. Development & Production Commands

### Run Frontend in Development:
```powershell
cd frontend
npm run dev
```
Runs Vite development server on `http://localhost:3000` (proxies `/api` to `http://localhost:8000`).

### Run Frontend Tests:
```powershell
cd frontend
npm test
```
Runs Vitest test suite (`14 passed, 0 failed`).

### Build Frontend for Production:
```powershell
cd frontend
npm run build
```
Type-checks TypeScript and compiles production bundle to `frontend/dist/`.
