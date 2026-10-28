# ThreatMind: Demonstration Setup & Verification Checklist

This checklist provides step-by-step instructions to configure, verify, and launch the **ThreatMind Investigation Workstation** for a live demonstration or presentation.

---

## 1. Prerequisites & Environment Check

Before launching the system, confirm that all software prerequisites are installed:
- **Operating System**: Windows 10/11, Linux, or macOS
- **Python**: Version 3.12 or 3.13 (`python --version`)
- **Node.js**: Version 18+ and npm (`node -v`, `npm -v`)
- **Neo4j**: Local Community Server 5.x installed and running on `bolt://localhost:7687`

Verify repository root path:
```powershell
# Expected: d:\madhav\ThreatMindAi
Get-Location
```

---

## 2. Step-by-Step Launch Sequence

### Step 2.1: Verify Neo4j Graph Database
1. Check that the Neo4j service is listening on port 7687:
```powershell
Test-NetConnection -ComputerName localhost -Port 7687
```
*Expected: `TcpTestSucceeded : True`*

2. Verify or restore the synthetic demo data fixture:
```powershell
.\venv\Scripts\python.exe scripts\cleanup_eval_graph.py --restore-demo
```
*Expected output*:
- Cleaned up evaluation nodes.
- Initialized Neo4j Schema: 13 constraints, 9 indexes.
- Seeded 1 Source node, 9 Entity nodes, 7 Relationships with edge provenance.
- Synthetic demo fixture restored.

### Step 2.2: Launch the FastAPI Backend
In a dedicated terminal:
```powershell
cd d:\madhav\ThreatMindAi
.\venv\Scripts\uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Verify backend health in a separate shell or browser:
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/health"
```
*Expected JSON*:
```json
{
  "status": "healthy",
  "project": "ThreatMind AI",
  "version": "1.0.0",
  "environment": "development",
  "neo4j_connected": true,
  "llm_provider": "gemini",
  "llm_available": false
}
```
*(Note: `/api/v1/health` is the canonical versioned endpoint; `/api/health` and `/health` are also supported aliases).*

### Step 2.3: Launch the React Investigation Frontend
In a dedicated terminal:
```powershell
cd d:\madhav\ThreatMindAi\frontend
npm run dev
```
*Expected output*:
```
  VITE v5.4.21  ready in ~500 ms

  ➜  Local:   http://localhost:5173/
  ➜  Network: use --host to expose
```

Open a web browser and navigate to: `http://localhost:5173`.

---

## 3. Pre-Flight Visual Verification

Verify each UI component before presenting to an audience:

| Check | Expected Visual Result | Verification Action |
| :--- | :--- | :--- |
| **Top Navigation** | "ThreatMind" logo, "Investigation", "Ingestion", "Graph" tabs | Visual check |
| **Connection Badge** | Green pulse badge indicating `Neo4j: Connected` | Inspect header |
| **Graph Stats** | Displays non-zero Entity and Relationship counts | Inspect header stats |
| **Search Input** | Visible prompt: "Ask a cyber threat intelligence question..." | Visual check |
| **Interactive Graph** | Cytoscape.js canvas initializes with pan/zoom/fit controls | Click "Graph" tab or view on query |

---

## 4. Test Queries for Pre-Demo Dry Run

Execute these three queries to verify end-to-end routing:

1. **Factual Query Test**:
   - Query: `What malware does Sandworm Team use?`
   - Verify: Returns answer, highlights `BlackEnergy`, displays `[CIT-1]`, opens Evidence Drawer on click.
2. **Multi-Hop Query Test**:
   - Query: `How does APT29 attack systems?`
   - Verify: Cytoscape graph renders multi-hop path, path steps listed with continuity, caveats displayed.
3. **Abstention Test**:
   - Query: `Did Volt Typhoon deploy BlackEnergy malware?`
   - Verify: Returns canonical abstention message (*"ThreatMind could not establish a sufficiently supported relationship..."*), status is `insufficient_evidence`, zero citations emitted.

---

## 5. Post-Demo Recovery & Teardown

If you executed an evaluation benchmark or modified graph data during the demo, restore the environment to the clean synthetic demo fixture:

```powershell
# 1. Clean evaluation graph nodes and restore clean synthetic fixture
.\venv\Scripts\python.exe scripts\cleanup_eval_graph.py --restore-demo

# 2. Re-run backend regression tests to confirm 100% test integrity
.\venv\Scripts\pytest backend\tests -v
```

---

## 6. Troubleshooting & Recovery Matrix

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **Header shows `Neo4j: Disconnected`** | Neo4j service stopped or port 7687 blocked | Start Neo4j: `& "d:\madhav\ThreatMindAi\neo4j-server\neo4j-community-5.20.0\bin\neo4j.ps1" console` |
| **Backend returns 500 on query** | Schema constraints uninitialized | Run: `.\venv\Scripts\python.exe scripts\seed_demo_data.py` |
| **Frontend displays blank screen** | Vite dev server not compiled or port conflict | Kill existing node process, run `npm install` and `npm run dev` |
| **Query returns no graph results** | Database is empty or wiped | Run `.\venv\Scripts\python.exe scripts\cleanup_eval_graph.py --restore-demo` |
| **CORS errors in browser console** | Backend origins not allowing `localhost:5173` | Confirm `backend/app/main.py` includes CORS middleware for `http://localhost:5173` |
