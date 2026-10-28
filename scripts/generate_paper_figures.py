import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Ensure docs/figures directory exists
os.makedirs("docs/figures", exist_ok=True)

plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.size"] = 9

def create_figure1_architecture():
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # Colors
    c_blue = "#1e3a8a"
    c_light_blue = "#dbeafe"
    c_slate = "#334155"
    c_light_slate = "#f1f5f9"
    c_green = "#065f46"
    c_light_green = "#d1fae5"
    c_amber = "#92400e"
    c_light_amber = "#fef3c7"
    c_border = "#475569"

    # UI Layer
    ax.add_patch(patches.FancyBboxPatch((5, 82), 90, 14, boxstyle="round,pad=1", ec=c_blue, fc=c_light_blue, lw=1.5))
    ax.text(50, 92, "ThreatMind Investigation Workstation (React 18 / TypeScript / Cytoscape.js)", ha="center", va="center", weight="bold", color=c_blue, fontsize=11)
    ax.text(50, 86, "Natural-Language Query Interface  |  Interactive Multi-Hop Path Visualizer  |  Evidence & Provenance Drawers", ha="center", va="center", color=c_slate, fontsize=9)

    # Arrow Down
    ax.annotate("", xy=(50, 75), xytext=(50, 82), arrowprops=dict(arrowstyle="->", lw=1.5, color=c_border))
    ax.text(53, 78.5, "REST API (FastAPI)", color=c_border, fontsize=8, style="italic")

    # Backend Core Box
    ax.add_patch(patches.FancyBboxPatch((5, 32), 90, 43, boxstyle="round,pad=1", ec=c_slate, fc=c_light_slate, lw=1.5))
    ax.text(50, 71.5, "ThreatMind Backend Architecture (FastAPI / Python 3.12)", ha="center", va="center", weight="bold", color=c_slate, fontsize=11)

    # Ingestion Pipeline Box
    ax.add_patch(patches.FancyBboxPatch((8, 48), 38, 19, boxstyle="round,pad=0.8", ec=c_amber, fc=c_light_amber, lw=1.2))
    ax.text(27, 63, "Controlled CTI Ingestion Engine", ha="center", va="center", weight="bold", color=c_amber, fontsize=9.5)
    ax.text(27, 57, "Multi-Format Parsers (PDF, HTML, JSON, TXT)\nPydantic Schemas & MITRE / CVE Normalization\nDeterministic Evidence ID Hashing (ev_...)", ha="center", va="center", color=c_slate, fontsize=8)

    # Query & Reasoning Box
    ax.add_patch(patches.FancyBboxPatch((54, 48), 38, 19, boxstyle="round,pad=0.8", ec=c_blue, fc=c_light_blue, lw=1.2))
    ax.text(73, 63, "GraphRAG & Reasoning Engine", ha="center", va="center", weight="bold", color=c_blue, fontsize=9.5)
    ax.text(73, 57, "Subject-Ordered Entity Resolution\nBounded Depth-3 Graph Traversal (DFS)\nEndpoint-Connected Multi-Hop Invariant", ha="center", va="center", color=c_slate, fontsize=8)

    # Grounded Answering Box
    ax.add_patch(patches.FancyBboxPatch((8, 35), 84, 10, boxstyle="round,pad=0.8", ec=c_green, fc=c_light_green, lw=1.2))
    ax.text(50, 41.5, "Evidence-Grounded Answer Generation & Validation Sandwich", ha="center", va="center", weight="bold", color=c_green, fontsize=9.5)
    ax.text(50, 37.5, "Citation Pool Construction  |  AnswerValidator (Integrity, Semantic Caveats, Token Alignment)  |  Canonical Abstention", ha="center", va="center", color=c_slate, fontsize=8)

    # Arrow Down to DB
    ax.annotate("", xy=(50, 23), xytext=(50, 32), arrowprops=dict(arrowstyle="->", lw=1.5, color=c_border))
    ax.text(53, 27.5, "Parameterized Cypher", color=c_border, fontsize=8, style="italic")

    # Neo4j Storage Layer
    ax.add_patch(patches.FancyBboxPatch((15, 5), 70, 18, boxstyle="round,pad=1", ec="#047857", fc="#ecfdf5", lw=1.5))
    ax.text(50, 18.5, "Neo4j 5.x Cybersecurity Knowledge Graph", ha="center", va="center", weight="bold", color="#047857", fontsize=11)
    ax.text(50, 12, "13 Primary Entity Labels (ThreatActor, Malware, Technique, Vulnerability, etc.)\nStrict Uniqueness Constraints & Schema Indexes\nEdge Provenance Metadata (source_id, evidence_text, published_date)", ha="center", va="center", color=c_slate, fontsize=8)

    plt.tight_layout()
    fig.savefig("docs/figures/figure1_architecture.png", bbox_inches="tight")
    plt.close(fig)
    print("Saved figure1_architecture.png")

def create_figure2_ingestion():
    fig, ax = plt.subplots(figsize=(10, 4.5), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    c_blue = "#1e3a8a"
    c_light_blue = "#eff6ff"
    c_slate = "#334155"
    c_border = "#475569"

    steps = [
        ("1. CTI Document Acquisition", "PDF, HTML, JSON, TXT\nSHA-256 Digest Tracking\nSection & Chunk Parsing", (4, 20, 16, 60)),
        ("2. Normalization & Resolver", "MITRE ATT&CK Technique IDs\nCanonical CVE Regex\nThreat Actor Alias Mapping", (23, 20, 16, 60)),
        ("3. Structured Extraction", "Pydantic Schema Validation\nStrict Evidence Quoting\nConfidence Scoring", (42, 20, 16, 60)),
        ("4. Provenance Hashing", "Deterministic ID Hash:\nev_sha256(src|rel|txt)[:12]\nImmutable Metadata Anchor", (61, 20, 16, 60)),
        ("5. Idempotent Graph MERGE", "Neo4j Schema Constraints\nUnique Node MERGE\nEdge Provenance Ingestion", (80, 20, 16, 60))
    ]

    for title, desc, (x, y, w, h) in steps:
        ax.add_patch(patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.8", ec=c_blue, fc=c_light_blue, lw=1.2))
        ax.text(x + w/2, y + h - 12, title, ha="center", va="center", weight="bold", color=c_blue, fontsize=8.5)
        ax.plot([x + 1, x + w - 1], [y + h - 22, y + h - 22], color="#cbd5e1", lw=1)
        ax.text(x + w/2, y + (h - 22)/2, desc, ha="center", va="center", color=c_slate, fontsize=7.5)

    # Arrows between steps
    for i in range(4):
        x1 = steps[i][2][0] + steps[i][2][2]
        x2 = steps[i+1][2][0]
        y_mid = 50
        ax.annotate("", xy=(x2, y_mid), xytext=(x1, y_mid), arrowprops=dict(arrowstyle="->", lw=1.5, color=c_border))

    plt.tight_layout()
    fig.savefig("docs/figures/figure2_ingestion.png", bbox_inches="tight")
    plt.close(fig)
    print("Saved figure2_ingestion.png")

def create_figure3_reasoning():
    fig, ax = plt.subplots(figsize=(10, 4.8), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    c_blue = "#1e3a8a"
    c_red = "#991b1b"
    c_green = "#065f46"
    c_slate = "#334155"

    # Query Input
    ax.add_patch(patches.FancyBboxPatch((4, 75), 92, 18, boxstyle="round,pad=0.8", ec=c_blue, fc="#eff6ff", lw=1.2))
    ax.text(50, 87, "Analyst Query: 'Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?'", ha="center", va="center", weight="bold", color=c_blue, fontsize=9.5)
    ax.text(50, 79, "Subject-Ordered Resolution: E1 = 'Sandworm Team', E2 = 'CVE-2021-44228', E3 = 'Apache Log4j'", ha="center", va="center", color=c_slate, fontsize=8.5)

    # Traversal & Validation Split
    ax.annotate("", xy=(28, 62), xytext=(35, 75), arrowprops=dict(arrowstyle="->", lw=1.2, color=c_slate))
    ax.annotate("", xy=(72, 62), xytext=(65, 75), arrowprops=dict(arrowstyle="->", lw=1.2, color=c_slate))

    # Left: Disconnected Subgraph (Failure Mode)
    ax.add_patch(patches.FancyBboxPatch((4, 18), 44, 44, boxstyle="round,pad=0.8", ec=c_red, fc="#fef2f2", lw=1.2))
    ax.text(26, 56, "Isolated Subgraph Trap (Rejected)", ha="center", va="center", weight="bold", color=c_red, fontsize=9)
    ax.text(26, 46, "Graph contains valid sub-path:\n(CVE-2021-44228)-[:AFFECTS]->(Apache Log4j)\n\nBUT Sandworm Team is disconnected from CVE.\nNaive RAG answers using isolated subgraph.", ha="center", va="center", color=c_slate, fontsize=7.8)
    ax.text(26, 26, "Endpoint Invariant Check: FAILED\nOutcome: Path Rejected (unsupported_endpoint)", ha="center", va="center", weight="bold", color=c_red, fontsize=8)

    # Right: Valid Connected Path (Success Mode)
    ax.add_patch(patches.FancyBboxPatch((52, 18), 44, 44, boxstyle="round,pad=0.8", ec=c_green, fc="#ecfdf5", lw=1.2))
    ax.text(74, 56, "Verified Bridging Path (Accepted)", ha="center", va="center", weight="bold", color=c_green, fontsize=9)
    ax.text(74, 46, "Continuous Bounded Traversal (Depth <= 3):\n(E1)-[:USES]->(Malware)-[:EXPLOITS]->(E2)-[:AFFECTS]->(E3)\n\n1. Endpoint Invariant: {E1, E2, E3} in PathNodes\n2. Continuity: Target(h_i) == Source(h_i+1)\n3. Acyclic: Zero repeated nodes", ha="center", va="center", color=c_slate, fontsize=7.8)
    ax.text(74, 26, "Endpoint Invariant Check: PASSED\nOutcome: Path Accepted + Semantic Caveats Injected", ha="center", va="center", weight="bold", color=c_green, fontsize=8)

    # Bottom Outcome Banner
    ax.add_patch(patches.FancyBboxPatch((4, 2), 92, 12, boxstyle="round,pad=0.6", ec=c_slate, fc="#f8fafc", lw=1.0))
    ax.text(50, 8, "Core Reasoning Rule: Subgraphs missing the primary subject or required relational chain trigger canonical abstention.\n'ThreatMind could not establish a sufficiently supported relationship from the currently available sources.'", ha="center", va="center", color=c_slate, fontsize=8, style="italic")

    plt.tight_layout()
    fig.savefig("docs/figures/figure3_reasoning.png", bbox_inches="tight")
    plt.close(fig)
    print("Saved figure3_reasoning.png")

def create_figure4_answering():
    fig, ax = plt.subplots(figsize=(10, 4.8), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    c_blue = "#1e3a8a"
    c_green = "#065f46"
    c_amber = "#92400e"
    c_slate = "#334155"

    # Pre-generation Bounding
    ax.add_patch(patches.FancyBboxPatch((4, 60), 28, 35, boxstyle="round,pad=0.8", ec=c_blue, fc="#eff6ff", lw=1.2))
    ax.text(18, 88, "Stage 1: Pre-Gen Bounding", ha="center", va="center", weight="bold", color=c_blue, fontsize=8.5)
    ax.text(18, 76, "• Validated Path Context Only\n• Verbatim Evidence Quotes\n• Citation Pool Construction\n  [CIT-1], [CIT-2] ... [CIT-N]\n• Bound to ev_sha256 Hashes", ha="center", va="center", color=c_slate, fontsize=7.5)

    # Generation Engine
    ax.add_patch(patches.FancyBboxPatch((36, 60), 28, 35, boxstyle="round,pad=0.8", ec=c_amber, fc="#fffbeb", lw=1.2))
    ax.text(50, 88, "Stage 2: Structured Gen", ha="center", va="center", weight="bold", color=c_amber, fontsize=8.5)
    ax.text(50, 76, "• Provider Abstraction Layer\n  (Gemini / OpenAI / Claude)\n• Offline Deterministic Fallback\n• Explicit Syntactic Tagging\n  Every claim indexed to [CIT-X]", ha="center", va="center", color=c_slate, fontsize=7.5)

    # Post-Gen Verification
    ax.add_patch(patches.FancyBboxPatch((68, 60), 28, 35, boxstyle="round,pad=0.8", ec=c_green, fc="#ecfdf5", lw=1.2))
    ax.text(82, 88, "Stage 3: AnswerValidator", ha="center", va="center", weight="bold", color=c_green, fontsize=8.5)
    ax.text(82, 76, "• Check 1: Citation Pool Existence\n• Check 2: ev_ Hash Verification\n• Check 3: Causality / Breach Guard\n• Check 4: Lexical Token Overlap\n• Check 5: Conflict Preservation", ha="center", va="center", color=c_slate, fontsize=7.5)

    # Arrows connecting stages
    ax.annotate("", xy=(36, 77.5), xytext=(32, 77.5), arrowprops=dict(arrowstyle="->", lw=1.5, color=c_slate))
    ax.annotate("", xy=(68, 77.5), xytext=(64, 77.5), arrowprops=dict(arrowstyle="->", lw=1.5, color=c_slate))

    # Bottom Decision Flow
    ax.annotate("", xy=(50, 48), xytext=(50, 60), arrowprops=dict(arrowstyle="->", lw=1.5, color=c_slate))

    ax.add_patch(patches.FancyBboxPatch((15, 8), 70, 36, boxstyle="round,pad=0.8", ec=c_slate, fc="#f8fafc", lw=1.2))
    ax.text(50, 37, "Decision & Output Payload Dispatch", ha="center", va="center", weight="bold", color=c_slate, fontsize=9.5)
    ax.text(50, 24, "If Active Bridging Paths == 0 OR Target Entity Not Connected:\n  -> Emit Canonical Abstention: 'ThreatMind could not establish a sufficiently supported relationship...'\n  -> Status: 'insufficient_evidence', Zero Fabricated Citations\n\nIf All Checks Passed:\n  -> Emit AnswerResponse: Grounded Text, Verified Citations, Active Paths, Grounding Status: 'fully_grounded'", ha="center", va="center", color=c_slate, fontsize=7.5)

    plt.tight_layout()
    fig.savefig("docs/figures/figure4_answering.png", bbox_inches="tight")
    plt.close(fig)
    print("Saved figure4_answering.png")

def create_figure5_evaluation():
    fig, ax = plt.subplots(figsize=(10, 4.8), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    c_blue = "#1e3a8a"
    c_slate = "#334155"

    # Header Box
    ax.add_patch(patches.FancyBboxPatch((4, 78), 92, 18, boxstyle="round,pad=0.8", ec=c_blue, fc="#eff6ff", lw=1.2))
    ax.text(50, 89, "Empirical Evaluation Benchmark (7 Authentic CTI Advisories, 15 Structured Questions)", ha="center", va="center", weight="bold", color=c_blue, fontsize=9.5)
    ax.text(50, 83, "10 Answerable Queries (Factual Direct & Multi-Hop)  |  5 Unanswerable & Adversarial Queries (Unknown, Disconnected, False Premise)", ha="center", va="center", color=c_slate, fontsize=8)

    # 3 Baseline Comparisons
    cols = [
        ("Baseline A: Keyword Lookup\n(BM25 / Regex Snippet Search)", "Abstention Precision: 0/0 (N/A)\nAbstention Recall: 0/5 (0.0%)\nFalse Abstention Rate: 0/10 (0.0%)\nMulti-Hop Support: None\nProvenance: Raw text snippet\n\nFailure: Fails on false premises with known entities (q13, q15)", (4, 10, 28, 62), "#fef2f2", "#991b1b"),
        ("Baseline B: 1-Hop Graph Retrieval\n(Bounded 1-Hop Neo4j Query)", "Abstention Precision: 2/2 (100.0%)\nAbstention Recall: 2/5 (40.0%)\nFalse Abstention Rate: 0/10 (0.0%)\nMulti-Hop Support: None\nProvenance: Direct edge only\n\nFailure: Cannot bridge multi-entity queries (q06, q07, q14)", (36, 10, 28, 62), "#fffbeb", "#92400e"),
        ("ThreatMind Full Pipeline\n(GraphRAG + Reasoning + Provenance)", "Abstention Precision: 5/5 (100.0%)\nAbstention Recall: 5/5 (100.0%)\nFalse Abstention Rate: 0/10 (0.0%)\nMulti-Hop Support: Up to 3 hops (70/70)\nCitation ID Integrity: 71/71 (100.0%)\nCitation Completeness: 78/78 (100.0%)\nUnsupported Claims: 0/78 (0.0%)\nProvenance: Full Cytoscape Path + Drawer", (68, 10, 28, 62), "#ecfdf5", "#065f46")
    ]

    for title, desc, (x, y, w, h), bg, border in cols:
        ax.add_patch(patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.8", ec=border, fc=bg, lw=1.2))
        ax.text(x + w/2, y + h - 8, title, ha="center", va="center", weight="bold", color=border, fontsize=8.5)
        ax.plot([x + 1, x + w - 1], [y + h - 16, y + h - 16], color="#cbd5e1", lw=1)
        ax.text(x + w/2, y + (h - 20)/2, desc, ha="center", va="center", color=c_slate, fontsize=7.2)

    plt.tight_layout()
    fig.savefig("docs/figures/figure5_evaluation.png", bbox_inches="tight")
    plt.close(fig)
    print("Saved figure5_evaluation.png")

if __name__ == "__main__":
    create_figure1_architecture()
    create_figure2_ingestion()
    create_figure3_reasoning()
    create_figure4_answering()
    create_figure5_evaluation()
    print("All 5 paper figures generated successfully.")
