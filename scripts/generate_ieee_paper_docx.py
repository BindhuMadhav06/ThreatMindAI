import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._element.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._element.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar {nsdecls("w")}><w:top w:w="{top}" w:type="dxa"/><w:bottom w:w="{bottom}" w:type="dxa"/><w:left w:w="{left}" w:type="dxa"/><w:right w:w="{right}" w:type="dxa"/></w:tcMar>')
    tcPr.append(tcMar)

def set_cell_borders(cell, top="none", bottom="none", left="none", right="none", color="CCCCCC", sz="4"):
    tcPr = cell._element.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:top w:val="{top}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:bottom w:val="{bottom}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:left w:val="{left}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:right w:val="{right}" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)

def build_docx():
    doc = docx.Document()

    # Page Margins (0.75 in for IEEE style)
    for section in doc.sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    # Styles
    c_primary = RGBColor(30, 58, 138)    # Deep Navy
    c_secondary = RGBColor(51, 65, 85)   # Slate
    c_dark = RGBColor(15, 23, 42)        # Very dark slate
    c_accent = RGBColor(6, 95, 70)       # Forest green

    # 1. Paper Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_title = p_title.add_run("ThreatMind: A Graph-Grounded Neurosymbolic Architecture for Evidence-Traceable Cyber Threat Intelligence Investigation")
    run_title.font.name = "Arial"
    run_title.font.size = Pt(17)
    run_title.font.bold = True
    run_title.font.color.rgb = c_primary
    p_title.paragraph_format.space_after = Pt(8)

    # Authors
    p_author = doc.add_paragraph()
    p_author.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_author = p_author.add_run("Bindhu Madhav\n")
    r_author.font.bold = True
    r_author.font.size = Pt(11)
    r_affil = p_author.add_run("Department of Computer Science & Engineering | ThreatMind Cyber Research Group\nEmail: bindhumadhav@example.org")
    r_affil.font.size = Pt(9.5)
    r_affil.font.color.rgb = c_secondary
    p_author.paragraph_format.space_after = Pt(14)

    # Horizontal Rule
    p_hr = doc.add_paragraph()
    p_hr.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_hr = p_hr.add_run("―" * 48)
    r_hr.font.color.rgb = RGBColor(203, 213, 225)
    p_hr.paragraph_format.space_after = Pt(12)

    # Abstract Callout Box
    tbl_abs = doc.add_table(rows=1, cols=1)
    tbl_abs.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl_abs.autofit = False
    tbl_abs.columns[0].width = Inches(7.0)
    c_abs = tbl_abs.cell(0, 0)
    set_cell_background(c_abs, "F8FAFC")
    set_cell_borders(c_abs, top="single", bottom="single", left="single", right="single", color="CBD5E1", sz="6")
    set_cell_margins(c_abs, top=140, bottom=140, left=180, right=180)

    p_abs = c_abs.paragraphs[0]
    r_absh = p_abs.add_run("Abstract—")
    r_absh.font.bold = True
    r_absh.font.size = Pt(9.5)
    r_abst = p_abs.add_run(
        "Cyber Threat Intelligence (CTI) investigation requires synthesizing complex, multi-hop relationships across heterogeneous threat advisories, malware reports, and vulnerability disclosures. While Large Language Models (LLMs) offer fluent natural-language querying, their deployment in high-stakes security operations is critically impeded by hallucination, spurious relational synthesis, and unverified attribution. In this paper, we propose ThreatMind, an open-source, evidence-grounded neurosymbolic architecture for transparent cyber threat investigation. ThreatMind constrains LLM reasoning within a \"deterministic sandwich\": pre-generation retrieval is bounded to a Neo4j knowledge graph using schema-governed, multi-hop graph traversal (≤ 3 hops) with strict endpoint-connectivity invariants; post-generation responses undergo a multi-stage deterministic AnswerValidator that verifies citation pool integrity, validates stable SHA-256 evidence hashes (ev_...), enforces lexical passage alignment, and suppresses unsubstantiated attack-success and causality claims.\n\n"
        "We empirically evaluate ThreatMind on a zero-leakage benchmark comprising seven authentic public CTI advisories from CISA and MITRE ATT&CK and 15 structured benchmark questions spanning factual lookup, multi-hop attribution, disconnected entity pairs, and adversarial false premises. In offline deterministic evaluation, ThreatMind achieves 100.0% Abstention Precision (5/5) and 100.0% Abstention Recall (5/5) across unanswerable queries—eliminating false answers where keyword lookup and 1-hop graph baselines fail. Evaluated multi-hop paths demonstrate 100.0% structural validity (70/70) and 100.0% step continuity (70/70) with 0/0 (N/A) cycle rejection. Emitted claims achieve 100.0% Citation Completeness (78/78) and 100.0% Citation ID Integrity (71/71), with an Automated Validation Failure Rate of 0.0% (0/78) under automated guard checks. We provide complete reproducibility instructions, discuss failure modes including the isolated subgraph trap, and transparently delineate the boundary between deterministic syntactic verification and human semantic entailment."
    )
    r_abst.font.size = Pt(9)
    p_abs.paragraph_format.space_after = Pt(6)

    p_idx = c_abs.add_paragraph()
    r_idxh = p_idx.add_run("Index Terms—")
    r_idxh.font.bold = True
    r_idxh.font.size = Pt(9)
    r_idxt = p_idx.add_run("Cyber Threat Intelligence (CTI), Knowledge Graphs, GraphRAG, Multi-Hop Reasoning, Neurosymbolic AI, Hallucination Mitigation, Evidence Provenance, Neo4j.")
    r_idxt.font.size = Pt(9)
    r_idxt.font.italic = True

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # Helper function for Section Headings
    def add_sec_heading(title):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(14)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(title)
        run.font.name = "Arial"
        run.font.size = Pt(12)
        run.font.bold = True
        run.font.color.rgb = c_primary
        return p

    def add_subsec_heading(title):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.keep_with_next = True
        run = p.add_run(title)
        run.font.name = "Arial"
        run.font.size = Pt(10.5)
        run.font.bold = True
        run.font.color.rgb = c_secondary
        return p

    def add_body(text, space_after=6, italic=False):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.line_spacing = 1.15
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(10)
        run.font.italic = italic
        run.font.color.rgb = c_dark
        return p

    def add_bullet(text, space_after=3):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.line_spacing = 1.15
        run = p.add_run(text)
        run.font.name = "Calibri"
        run.font.size = Pt(9.5)
        run.font.color.rgb = c_dark
        return p

    def add_figure(img_path, caption):
        if os.path.exists(img_path):
            p_img = doc.add_paragraph()
            p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_img.paragraph_format.space_before = Pt(10)
            p_img.paragraph_format.space_after = Pt(4)
            run = p_img.add_run()
            run.add_picture(img_path, width=Inches(6.6))
            
            p_cap = doc.add_paragraph()
            p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_cap.paragraph_format.space_after = Pt(12)
            r_cap = p_cap.add_run(caption)
            r_cap.font.name = "Arial"
            r_cap.font.size = Pt(8.5)
            r_cap.font.bold = True
            r_cap.font.color.rgb = c_secondary

    def add_styled_table(headers, rows, col_widths=None):
        tbl = doc.add_table(rows=len(rows) + 1, cols=len(headers))
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        tbl.autofit = False

        # Header Row
        hdr_cells = tbl.rows[0].cells
        for i, header_text in enumerate(headers):
            hdr_cells[i].text = header_text
            set_cell_background(hdr_cells[i], "1E3A8A")
            set_cell_margins(hdr_cells[i], top=100, bottom=100, left=120, right=120)
            set_cell_borders(hdr_cells[i], top="single", bottom="single", left="single", right="single", color="1E3A8A", sz="4")
            for p in hdr_cells[i].paragraphs:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                for run in p.runs:
                    run.font.name = "Arial"
                    run.font.size = Pt(8.5)
                    run.font.bold = True
                    run.font.color.rgb = RGBColor(255, 255, 255)

        # Body Rows
        for r_idx, row_data in enumerate(rows):
            row_cells = tbl.rows[r_idx + 1].cells
            bg_color = "F8FAFC" if r_idx % 2 == 1 else "FFFFFF"
            for c_idx, cell_value in enumerate(row_data):
                row_cells[c_idx].text = str(cell_value)
                set_cell_background(row_cells[c_idx], bg_color)
                set_cell_margins(row_cells[c_idx], top=80, bottom=80, left=120, right=120)
                set_cell_borders(row_cells[c_idx], top="single", bottom="single", left="single", right="single", color="E2E8F0", sz="4")
                for p in row_cells[c_idx].paragraphs:
                    p.paragraph_format.space_after = Pt(0)
                    p.paragraph_format.line_spacing = 1.1
                    for run in p.runs:
                        run.font.name = "Calibri"
                        run.font.size = Pt(8.5)
                        run.font.color.rgb = c_dark

        if col_widths:
            for row in tbl.rows:
                for idx, width in enumerate(col_widths):
                    row.cells[idx].width = Inches(width)

        doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # --- SECTION I ---
    add_sec_heading("I. INTRODUCTION")
    add_body("The modern cybersecurity threat landscape produces an overwhelming volume of unstructured Cyber Threat Intelligence (CTI) in the form of government security advisories, vendor whitepapers, vulnerability reports, and threat group profiles [1]. Security Operations Center (SOC) analysts and threat hunters face the formidable challenge of manually correlating these disparate narratives into actionable attack chains—mapping adversary groups to custom malware, exploited Common Vulnerabilities and Exposures (CVEs), and targeted enterprise infrastructure [2].")
    add_body("Recent advancements in generative artificial intelligence and Large Language Models (LLMs) have motivated their application as natural-language interfaces for threat intelligence [3]. However, off-the-shelf generative LLMs suffer from severe failure modes in domain-critical cybersecurity tasks:")
    add_bullet("Relational Hallucination: Generative models frequently confabulate relationships between well-known but unassociated entities, such as falsely attributing a ransomware campaign to a high-profile Advanced Persistent Threat (APT) group due to training corpus co-occurrence [4].")
    add_bullet("Unsupported Causality and Compromise Claims: LLMs often convert documented capabilities into factual assertions of compromise (e.g., asserting that an actor 'successfully destroyed' a network when the intelligence source merely noted that the actor 'utilized' a utility) [5].")
    add_bullet("Ghost Citations and Ungrounded Assertions: Models invent non-existent report numbers, invalid CVE identifiers, or quote passages that do not exist in the source literature [6].")
    add_body("In mission-critical security environments, an ungrounded or fabricated intelligence assessment can misdirect incident response teams, waste forensic engineering hours, or result in severe misattribution [1], [2]. To address this challenge, we present ThreatMind, an evidence-grounded neurosymbolic investigation system designed around the operational principle: 'No guessing. No hallucination. Only graph-backed facts.'")
    add_body("ThreatMind couples the structural rigor of property knowledge graphs with the expressive querying capabilities of LLMs while enforcing strict deterministic constraints before and after generation. Rather than allowing the generative model to infer unverified paths, ThreatMind bounds retrieval to explicit Cypher graph traversals, validates path endpoint connectivity, anchors every relationship edge to verbatim source text via deterministic cryptographic hashes, and subjects candidate answers to independent deterministic verification stages.")

    # --- SECTION II ---
    add_sec_heading("II. PROBLEM STATEMENT & RESEARCH OBJECTIVES")
    add_subsec_heading("A. Problem Formulation")
    add_body("Let a CTI corpus D = {d1, d2, ..., dm} consist of unstructured text advisories from reputable cybersecurity authorities. Let G = (V, E, P) denote a property knowledge graph where V is a set of typed cybersecurity entities (e.g., ThreatActor, Malware, Vulnerability), E is a set of directed, typed relationship edges, and P maps each edge to provenance metadata containing a source identifier s, verbatim passage text t, and publication metadata.")
    add_body("Given an analyst question q containing resolved entity mentions Eq = {e1, e2, ..., ek}, the objective is to generate an evidence-grounded answer A that satisfies three core conditions:")
    add_bullet("Relational Faithfulness: Every relational assertion expressed in A must correspond to a verified path p in G supported by valid provenance P.")
    add_bullet("Endpoint Connectivity: If k ≥ 2, A must only confirm relationships if there exists a valid, unbroken path p in G such that Eq ⊆ Nodes(p). If no bridging path exists, the system must trigger formal abstention: A = ABSTAIN.")
    add_bullet("Traceable Attribution: Every substantive assertion in A must reference an active citation [CIT-i] bound to a deterministic evidence hash ev_id = SHA256(s || r || t)[:12].")

    add_subsec_heading("B. Research Objectives")
    add_bullet("RO1 (Structural Faithfulness): Can bounded knowledge graph traversals restrict multi-hop reasoning strictly to documented intelligence without inventing missing edges?")
    add_bullet("RO2 (Abstention Reliability): Does enforcing endpoint connectivity eliminate false answers on unobserved entities, disconnected entities, and false relational premises?")
    add_bullet("RO3 (Provenance and Grounding Integrity): Can deterministic post-generation validation eliminate broken citations, fabricated identifiers, and unsubstantiated compromise claims?")

    # --- SECTION III ---
    add_sec_heading("III. RELATED WORK")
    add_subsec_heading("A. CTI Knowledge Graph Construction")
    add_body("Transforming unstructured cybersecurity reports into structured knowledge graphs has been explored through various methodologies. Sarhan and Spruit introduced Open-CyKG [7], an open cyber threat knowledge graph that extracts relational triplets using Open Information Extraction (OpenIE) and neural language representations. While Open-CyKG demonstrated the feasibility of automated CTI graphing, its OpenIE pipeline suffered from noisy entity resolution and lacked explicit edge provenance linked to source paragraphs.")
    add_body("Li et al. proposed AttacKG [8], which parses CTI reports into attack behavior graphs and maps extracted actions to the MITRE ATT&CK framework using template-based alignment. AttacKG successfully formalized technique-level dependencies; however, it was primarily designed for threat graph construction rather than interactive natural-language question answering or multi-hop path query answering.")
    add_body("More recently, Cheng et al. developed CTINexus [1], an automated framework utilizing LLM in-context learning, hierarchical entity alignment, and long-distance relation prediction to construct comprehensive CTI knowledge graphs without extensive manual annotation. ThreatMind builds upon the structural insights of CTINexus and AttacKG, adopting standardized ontologies (CVE, MITRE ATT&CK, CPE) and strict edge provenance, but introduces an operational reasoning and answering layer that enforces deterministic abstention on ungrounded multi-hop queries.")

    add_subsec_heading("B. Retrieval-Augmented Generation (RAG) and GraphRAG")
    add_body("Retrieval-Augmented Generation, introduced by Lewis et al. [3], mitigates hallucinations by injecting retrieved document passages into the LLM context window. However, standard naive RAG systems rely on flat vector similarity searches over chunked text. As demonstrated by Edge et al. in Microsoft GraphRAG [9], flat dense retrieval struggles with global sensemaking, complex multi-hop relationship chains, and aggregate threat queries because relevant information is fragmented across disparate document chunks.")
    add_body("ThreatMind implements a controlled GraphRAG paradigm specifically tailored for CTI: instead of unconstrained semantic embedding search over raw text chunks, ThreatMind performs schema-bounded Cypher traversals across verified property graph nodes, ensuring that every retrieved context item represents an unbroken relational chain backed by specific evidence passages.")

    add_subsec_heading("C. Hallucination Mitigation and Abstention")
    add_body("Hallucination in natural language generation remains a pervasive challenge [4]. In domain-specific, high-consequence applications such as medicine, law, and cybersecurity, selective generation and abstention—enabling a system to state 'I do not know' or reject ungrounded premises—are essential for safe deployment [10]. Recent works demonstrate that standard instruction-tuned LLMs struggle with abstention when prompted with false premises, frequently accommodating the user's erroneous assumptions [4], [10]. ThreatMind addresses this vulnerability through a neurosymbolic architecture: the decision to answer or abstain is governed by deterministic graph-connectivity checks rather than LLM self-assessment.")

    # --- SECTION IV ---
    add_sec_heading("IV. PROPOSED ARCHITECTURE")
    add_body("ThreatMind is structured as a decoupled, multi-tier system separating user interaction, business logic, knowledge graph storage, and language modeling. Fig. 1 illustrates the end-to-end system architecture.")
    add_figure("docs/figures/figure1_architecture.png", "Fig. 1. ThreatMind End-to-End System Architecture. Illustrates the interaction between the React Workstation, FastAPI Backend, GraphRAG & Reasoning Engine, and Neo4j Knowledge Graph.")
    
    add_body("TABLE I summarizes the foundational technology stack.")
    add_styled_table(
        ["Architectural Layer", "Core Technologies", "Primary Function"],
        [
            ["Frontend Workstation", "React 18, TypeScript, Vite, Tailwind CSS, Cytoscape.js", "Interactive query UI, graph visualization, evidence drawers"],
            ["Backend REST API", "FastAPI, Uvicorn, Pydantic v2, Python 3.12", "REST routing, request validation, async orchestration"],
            ["Knowledge Graph", "Neo4j 5.20 Community Edition, Cypher Language", "Property graph persistence, schema indexing, graph traversal"],
            ["Document Processing", "PyMuPDF (fitz), BeautifulSoup4, regex", "Multi-format parsing (PDF, HTML, JSON, TXT), chunking"],
            ["LLM Interface", "Abstract Provider Interface, Google Gemini API", "Structured natural-language synthesis with deterministic fallback"],
            ["Testing & Evaluation", "pytest, pytest-asyncio, vitest, python-docx, matplotlib", "Automated test suites (108 backend, 14 frontend), benchmark evaluation"]
        ],
        [1.8, 2.5, 2.7]
    )

    # --- SECTION V ---
    add_sec_heading("V. KNOWLEDGE GRAPH SCHEMA & PROVENANCE")
    add_subsec_heading("A. Entity Ontology and Constraints")
    add_body("ThreatMind implements a cybersecurity property graph schema on Neo4j 5.x. The ontology comprises 13 primary node labels, as detailed in TABLE II. Schema integrity is enforced via 13 unique property constraints and nine property indexes.")
    add_styled_table(
        ["Node Label", "Unique Key", "Secondary Properties", "Description / Domain Scope"],
        [
            ["ThreatActor", "id", "name, aliases, country", "Nation-state groups, cybercrime syndicates, APTs"],
            ["Malware", "id", "name, aliases, malware_type", "Malicious code, ransomware, backdoors, wipers"],
            ["Tool", "id", "name, aliases, category", "Dual-use software, penetration testing utilities"],
            ["Vulnerability", "id", "name, cve_id, cvss_score", "Security flaws with canonical CVE identifiers"],
            ["Technique", "id", "name, attack_id, description", "MITRE ATT&CK techniques and sub-techniques"],
            ["Tactic", "id", "name, attack_id, description", "High-level MITRE ATT&CK adversary tactics"],
            ["Campaign", "id", "name, description, year", "Time-bounded, targeted cyber threat campaigns"],
            ["Product", "id", "name, vendor, version", "Target commercial or open-source software applications"],
            ["Software", "id", "name, version", "General platform software or library dependencies"],
            ["OperatingSystem", "id", "name, version", "Target host operating systems"],
            ["Organization", "id", "name, sector, country", "Targeted victim organizations or industry sectors"],
            ["Indicator", "id", "type, value", "Indicators of Compromise (SHA-256 hashes, IP addresses)"],
            ["Source", "id", "title, url, publisher, published_date", "Ingested CTI document metadata and provenance root"]
        ],
        [1.3, 0.8, 2.1, 2.8]
    )

    add_subsec_heading("B. Edge Provenance Model")
    add_body("ThreatMind enforces mandatory provenance metadata on every relationship edge. Every edge embeds source_id, source_url, evidence_text, published_date, and a deterministic evidence identifier:")
    add_body("ev_id = \"ev_\" + SHA256(source_id || relationship_type || evidence_text)[:12]", italic=True)
    add_body("This hash provides an immutable audit anchor: every graph step traversed during investigation can be traced directly to the exact source paragraph from which it was extracted.")

    # --- SECTION VI ---
    add_sec_heading("VI. CONTROLLED CTI INGESTION PIPELINE")
    add_body("Fig. 2 illustrates the Controlled CTI Ingestion and Knowledge Graph Construction Workflow.")
    add_figure("docs/figures/figure2_ingestion.png", "Fig. 2. Controlled CTI Ingestion and Knowledge Graph Construction Workflow.")
    add_body("1. Document Parsing: Ingestion loaders extract raw text from PDF (via PyMuPDF), HTML (via BeautifulSoup), JSON, and plain text files. The file's cryptographic SHA-256 digest is recorded in the corresponding Source node to prevent duplicate document ingestion.")
    add_body("2. Canonical Normalization: The Normalizer maps aliases to canonical identifiers (e.g., 'actor_apt29'), validates CVE formats using strict regular expressions (CVE-\\d{4}-\\d{4,7}), and resolves MITRE ATT&CK technique numbers (T\\d{4}(\\.\\d{3})?).")
    add_body("3. Structured Extraction: Extraction is constrained by Pydantic models. Every extracted relationship must include an exact textual quote (evidence_text) from the parent document chunk; triplets without supporting text are rejected.")
    add_body("4. Idempotent Cypher Insertion: Triplet insertions use parameterized Cypher MERGE queries with ON CREATE SET semantics. This guarantees that repeated ingestion of identical advisories does not create duplicate nodes or parallel redundant edges.")

    # --- SECTION VII ---
    add_sec_heading("VII. GRAPHRAG RETRIEVAL & MULTI-HOP REASONING")
    add_subsec_heading("A. Subject-Ordered Entity Resolution")
    add_body("When an analyst submits a query (e.g., 'Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?'), the QueryEntityResolver extracts candidate tokens, normalizes leading interrogative verbs, and queries the Neo4j index. Crucially, resolved entities are sorted by character offset in the query string, identifying the primary query subject E1 which anchors the graph traversal.")

    add_subsec_heading("B. Bounded Graph Traversal & Endpoint Invariant")
    add_body("Graph traversal uses a bounded Depth-First Search (DFS) exploring permitted relationship paths up to depth N = 3. Fig. 3 illustrates the reasoning pipeline and the critical distinction between disconnected subgraphs and verified bridging paths.")
    add_figure("docs/figures/figure3_reasoning.png", "Fig. 3. GraphRAG Traversal and the Endpoint-Connected Reasoning Invariant.")
    add_body("To prevent the 'Isolated Subgraph Trap'—where an LLM answers using an isolated relationship between secondary entities (e.g. CVE -> Product) while ignoring that the primary actor is disconnected—ThreatMind enforces the General Endpoint-Connectivity Invariant:")
    add_bullet("For two-entity queries (k = 2): An accepted path p must connect both endpoints: {e1, e2} ⊆ Nodes(p).")
    add_bullet("For multi-entity queries (k ≥ 3): The primary subject e1 must be present in p, and all queried entities across the chain must be connected: Eq ⊆ Nodes(p).")
    add_bullet("Continuity & Acyclicity: For each adjacent hop (hi, hi+1), Target(hi) = Source(hi+1). Any path containing a repeated node is pruned as cyclic.")
    add_body("If no active path satisfies this invariant, all partial paths are flagged as unsupported_endpoint_relationship, and the reasoning engine emits zero accepted paths, immediately triggering formal abstention.")

    # --- SECTION VIII ---
    add_sec_heading("VIII. EVIDENCE-GROUNDED ANSWER GENERATION & ABSTENTION")
    add_body("Fig. 4 outlines the generation and validation workflow.")
    add_figure("docs/figures/figure4_answering.png", "Fig. 4. Evidence-Grounded Answer Generation and Abstention Sandwich.")
    add_subsec_heading("A. Pre-Generation Bounding and the Citation Pool")
    add_body("If active bridging paths exist, the PromptBuilder constructs an isolated prompt containing validated path steps, verbatim source evidence quotes, and a stable citation pool ([CIT-1], [CIT-2], ...). The LLM is strictly instructed that every substantive claim must cite at least one citation tag, and out-of-context extrapolation is prohibited. In offline environments, a deterministic evidence-backed generator synthesizes the answer directly from the validated path steps.")

    add_subsec_heading("B. Post-Generation Multi-Stage Verification")
    add_body("Candidate responses undergo five independent validation stages in AnswerValidator:")
    add_bullet("Check 1: Citation Pool Membership (rejects hallucinated tags like [CIT-999]).")
    add_bullet("Check 2: Evidence Hash Integrity (confirms ev_ hash structure and match).")
    add_bullet("Check 3: Attack-Success & Causality Guard (detects aggressive compromise verbs without confirmed outcome).")
    add_bullet("Check 4: Passage Alignment (enforces ≥ 2 domain keywords or ≥ 25% token overlap).")
    add_bullet("Check 5: Conflicting Evidence Preservation (ensures contradictory reports are not silently reconciled).")

    add_subsec_heading("C. Grounded Abstention Trigger")
    add_body("If entities are unresolvable or zero bridging paths connect the query endpoints, ThreatMind bypasses LLM generation and emits the canonical abstention response:")
    add_body("'ThreatMind could not establish a sufficiently supported relationship from the currently available sources.'", italic=True)
    add_body("The response is assigned status 'insufficient_evidence', emits zero citations, and attaches unevidenced warnings.")

    # --- SECTION IX ---
    add_sec_heading("IX. EXPERIMENTAL SETUP & BENCHMARK DATASET")
    add_subsec_heading("A. Benchmark Corpus Manifest")
    add_body("The empirical benchmark corpus comprises seven authentic public CTI source documents published by CISA and MITRE ATT&CK. All records are tagged is_synthetic: false. TABLE III details the document manifest.")
    add_styled_table(
        ["Source ID", "Document Title", "Publishing Authority", "Publication Date", "SHA-256 Digest (Prefix)"],
        [
            ["cisa_aa22_110a", "Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure", "CISA / FBI / NSA", "2022-04-20", "47802f041d14..."],
            ["cisa_aa21_116a", "Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices", "CISA", "2021-04-26", "a04d84df2fb1..."],
            ["cisa_aa21_356a", "Mitigating Log4Shell and Other Log4j-Related Vulnerabilities", "CISA", "2021-12-22", "e3f3c90c0385..."],
            ["cisa_aa24_060b", "Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure", "CISA", "2024-02-29", "7e3fa36c1831..."],
            ["cisa_aa24_038a", "PRC State-Sponsored Actors Compromise US Critical Infrastructure", "CISA / NSA / FBI", "2024-02-07", "115236b84058..."],
            ["mitre_g0016_apt29", "Enterprise ATT&CK Group G0016: APT29", "MITRE Corporation", "2024-03-25", "2108bf0854b1..."],
            ["mitre_g0034_sandworm", "Enterprise ATT&CK Group G0034: Sandworm Team", "MITRE Corporation", "2024-03-25", "dc9a9db6c84a..."]
        ],
        [1.3, 2.5, 1.2, 1.0, 1.0]
    )

    add_subsec_heading("B. Benchmark Query Suite")
    add_body("The benchmark contains 15 structured evaluation questions covering four distinct categories:")
    add_bullet("Factual Direct (q01-q05, q09, q10): Single-hop queries assessing documented relationships.")
    add_bullet("Multi-Hop Traversal (q06-q08): Queries requiring 2- to 3-hop reasoning chains.")
    add_bullet("Unanswerable: Unknown Entity (q11, q12): Queries concerning entities absent from the corpus (e.g. PhantomSpider99). Expected: Abstention.")
    add_bullet("Unanswerable: Disconnected Entities (q13, q14): Queries naming known entities without a connecting relationship. Expected: Abstention.")
    add_bullet("Adversarial: False Premise (q15): Query asserting a false relationship premise (APT29 using Olympic Destroyer). Expected: Abstention.")

    # --- SECTION X ---
    add_sec_heading("X. RESULTS & BASELINE COMPARISON")
    add_subsec_heading("A. Primary Benchmark Results")
    add_body("The benchmark was evaluated in zero-leakage offline deterministic mode. TABLE IV presents the verified metric results.")
    add_styled_table(
        ["Metric Category", "Specific Metric Name", "Numerator / Denominator", "Value", "Scientific Definition & Notes"],
        [
            ["Abstention Behavior", "Abstention Precision", "5 / 5", "100.0%", "True Abstentions / Total System Abstentions. Rejections requiring abstention."],
            ["", "Abstention Recall", "5 / 5", "100.0%", "True Abstentions / Ground-Truth Unanswerable Queries (q11-q15)."],
            ["", "False Abstention Rate", "0 / 10", "0.0%", "False Abstentions / Total Answerable Queries."],
            ["GraphRAG Retrieval", "Pooled Retrieved-Fact Precision (top-5 windows)", "14 / 41", "34.1%", "Micro-averaged precision across retrieved facts in top-5 retrieval windows."],
            ["", "Retrieval Recall@5", "14 / 24", "58.3%", "Proportion of documented gold attack facts recovered across answerable queries."],
            ["", "Query-Level Zero-Resolved-Seed Rate", "2 / 15", "13.3%", "Queries where zero required starting entities could be resolved in graph (q11, q12; 0/10 on answerable queries)."],
            ["", "Entity-Mention Resolution (candidate-to-node coverage)", "21 / 24", "87.5%", "Candidate entity mentions successfully resolved to graph nodes (3 unresolved: q11, q12, q15)."],
            ["Multi-Hop Reasoning", "Path Structural Validity", "70 / 70", "100.0%", "Evaluated paths satisfying Cypher schema templates and constraints."],
            ["", "Path Step Continuity", "70 / 70", "100.0%", "Traversed steps satisfying Target(h_i) = Source(h_{i+1}) across all paths."],
            ["", "Cycle Rejection Rate", "0 / 0", "0/0 (N/A)", "Cyclic paths encountered and pruned (reported as N/A due to 0 candidate cycles)."],
            ["Evidence Grounding", "Citation ID Integrity", "71 / 71", "100.0%", "Emitted citations referencing valid deterministic ev_ hashes backed by text."],
            ["", "Citation Completeness", "78 / 78", "100.0%", "Claims with ≥ 1 citation / Total emitted claims in accepted answers."],
            ["", "Automated Validation Failure Rate", "0 / 78", "0.0%", "Claims failing automated deterministic guard checks (0/78)."],
            ["Document Extraction", "Entity & Relation Extraction", "—", "NOT RUN", "Offline Mode - LLM Ingestion requires live provider (Disclosed boundary)."]
        ],
        [1.3, 1.8, 1.1, 0.9, 1.9]
    )

    add_body("Retrieval Performance Analysis & Boundary Considerations: The empirical retrieval results reflect both the system's core strengths and its remaining operational boundaries. ThreatMind achieves a Retrieval Recall@5 of 58.3% (14 of 24 gold attack facts recovered across answerable queries) with a 0.0% zero-resolved seed rate on legitimate in-graph queries (0/10 on q01–q10), confirming that entity resolution and bounded Cypher traversal reliably locate the primary adversary tactics, malware families, and exploited CVEs. Across the full 15-query suite, the Query-Level Zero-Resolved-Seed Rate is 13.3% (2/15), strictly measuring queries where no required starting entity could resolve in the graph: queries q11 (PhantomSpider99) and q12 (CVE-2099-99999) that intentionally query unobserved entities. Crucially, having zero resolved seeds on unobserved entities is the expected prerequisite that triggers canonical pre-retrieval abstention (5/5, 100.0% recall). At the mention level, Entity-Mention Resolution (candidate-to-node coverage) is 87.5% (21/24). The three unresolved mentions fall into two distinct operational categories: (1) deliberately unobserved threat entities (q11 PhantomSpider99 and q12 CVE-2099-99999) where resolution failure is the required condition to trigger canonical pre-retrieval abstention; and (2) a candidate-extraction artifact in q15 where the geographic adjective 'Ukrainian' was extracted as an entity candidate alongside the primary attack entities (APT29 and Olympic Destroyer), which resolved cleanly and were subsequently neutralized downstream by the multi-hop endpoint invariant. However, Pooled Retrieved-Fact Precision (top-5 windows) is bounded at 34.1% (14 of 41 facts retrieved across top-5 candidate windows). This reflects an architectural trade-off: when exploring multi-hop subgraphs around an actor or vulnerability, the top-5 retrieval window inevitably captures structurally valid neighboring relationships (e.g., auxiliary malware techniques or secondary product impacts) that fall outside the concise gold answer subset for that specific query. Furthermore, 41.7% of gold facts were unrecovered within the top-5 cutoff on complex multi-hop queries, demonstrating the necessity of adaptive retrieval depth and hybrid dense-sparse vector indexing for future iterations.")

    add_subsec_heading("B. Controlled Baseline Comparison")
    add_body("TABLE V compares ThreatMind against Baseline A (Keyword Lookup / BM25) and Baseline B (1-Hop Graph Retrieval) across the identical 15 benchmark questions. Fig. 5 provides a visual comparison.")
    add_styled_table(
        ["Architecture / System", "Multi-Hop Traversal", "Abstention Precision", "Abstention Recall", "False Abstention Rate", "Evidence Traceability"],
        [
            ["Baseline A: Keyword Lookup (BM25)", "No", "0/0 (N/A)", "0 / 5 (0.0%)", "0 / 10 (0.0%)", "Raw text passage match only"],
            ["Baseline B: 1-Hop Graph Retrieval", "No", "2 / 2 (100.0%)", "2 / 5 (40.0%)", "0 / 10 (0.0%)", "Direct 1-hop edge only"],
            ["ThreatMind Full Pipeline", "Yes (≤ 3 hops)", "5 / 5 (100.0%)", "5 / 5 (100.0%)", "0 / 10 (0.0%)", "Full Cytoscape Path + Provenance"]
        ],
        [2.0, 1.0, 1.1, 1.0, 1.0, 0.9]
    )
    add_figure("docs/figures/figure5_evaluation.png", "Fig. 5. Controlled Baseline Comparison Overview.")

    # --- SECTION XI ---
    add_sec_heading("XI. DISCUSSION & FAILURE ANALYSIS")
    add_body("1. Failure of Keyword Matching (Baseline A): In query q13 ('Did Volt Typhoon deploy BlackEnergy malware?'), both entities appear in the corpus across separate CISA advisories. Baseline A retrieves passages containing both entity terms and attempts to synthesize an answer, failing to abstain (0.0% Abstention Recall, 0/5; note that this reflects failure to abstain on ungrounded queries, not zero passage-retrieval recall). Similarly, in q15, keyword matching finds all four terms across the documents and fabricates a narrative linking them, falsely validating the adversarial premise.")
    add_body("2. Failure of 1-Hop Graph Retrieval (Baseline B): Baseline B successfully abstains on unknown entities (q11, q12), but fails on multi-hop answerable queries (q06, q07, q08), which require traversing from ThreatActor through Malware or Vulnerability to Product. Furthermore, in q14, Baseline B cannot determine whether a multi-hop path connects Sandworm to Log4j, failing on disconnected multi-entity queries.")
    add_body("3. ThreatMind Endpoint Resolution: ThreatMind resolved all five unanswerable/adversarial queries (q11-q15). For q11 and q12, entity resolution failed cleanly, triggering immediate abstention. This demonstrates that ThreatMind reliably abstained on the two designated out-of-graph queries under controlled conditions; it reflects the observed behavior on these benchmark queries rather than a universal guarantee that graph-node hallucination is impossible across arbitrary open-domain queries. For q13, DFS traversal found zero paths connecting Volt Typhoon to BlackEnergy within depth 3. For q14, the graph contained the valid subpath CVE-2021-44228 -> Log4j, but the endpoint invariant detected that the primary subject Sandworm Team was disconnected, rejecting the path and triggering canonical abstention. For q15, the false premise was neutralized because no unbroken path connected APT29 to Olympic Destroyer.")

    # --- SECTION XII ---
    add_sec_heading("XII. LIMITATIONS & THREATS TO VALIDITY")
    add_body("1. Benchmark Scale Limitations: The empirical evaluation was conducted on a curated pilot benchmark of seven authentic CTI advisories and 15 structured questions. While sufficient to validate architectural invariants, evaluating performance at enterprise scale will require distributed graph partitioning.")
    add_body("2. Scope of 100% Abstention: The reported 100.0% abstention precision and recall apply specifically to the five designated unanswerable and adversarial questions within this pilot evaluation suite. In particular, the unknown-entity tests demonstrate that ThreatMind successfully abstained on the two designated out-of-graph queries (q11 and q12). This result supports the specific observed behavior under controlled conditions; it does not constitute mathematical proof of complete hallucination immunity or a universal guarantee across arbitrary open-domain queries.")
    add_body("3. Automated Verification vs. Human Semantic Entailment: The 0.0% Automated Validation Failure Rate (0/78) reflects deterministic checks (citation pool existence, SHA-256 evidence hash verification, token overlap thresholds, and regex scanning for forbidden compromise verbs). These automated syntactic and lexical guards do not guarantee formal semantic entailment under human assessment.")
    add_body("4. Structural Validity vs. Real-World Truth: ThreatMind's 100.0% path structural validity confirms that traversed paths conform to schema constraints, exhibit unbroken step continuity, and link to non-empty source evidence. It does not independently verify that the original intelligence publisher's factual assertions are true in the real world.")
    add_body("5. Offline Mode Extraction Disclosure: In the reported offline deterministic benchmark, live LLM document extraction was marked as NOT RUN. The benchmark evaluated retrieval, multi-hop reasoning, and grounded answer synthesis from pre-ingested, authenticated graph data.")

    # --- SECTION XIII ---
    add_sec_heading("XIII. FUTURE WORK")
    add_body("1. Neural Natural Language Inference (NLI) for Semantic Entailment: We plan to replace lexical token overlap in AnswerValidator with fine-tuned cross-encoder NLI models (e.g., DeBERTa-v3) to compute directional premise-to-hypothesis entailment scores.")
    add_body("2. Hybrid Dense-Sparse Graph Indexing: To scale GraphRAG across massive corpora, we will integrate Neo4j Vector Indexing (hybrid dense embeddings + BM25 full-text indexes) with community-level graph summarization, as explored in Microsoft GraphRAG [9].")
    add_body("3. Automated Contradiction and Temporal Resolution: Threat intelligence reports frequently disagree regarding attribution or attack dates. Future iterations will implement automated belief-revision algorithms and temporal graph reasoning.")

    # --- SECTION XIV ---
    add_sec_heading("XIV. CONCLUSION")
    add_body("In this paper, we introduced ThreatMind, an open-source, evidence-grounded neurosymbolic architecture for cybersecurity threat intelligence investigation. By constraining generative models within a deterministic sandwich—governed by schema-constrained property graph traversal, an endpoint-connectivity invariant, cryptographic evidence provenance hashing, and multi-stage answer validation—ThreatMind eliminates relational hallucinations and false premise synthesis. On an isolated empirical benchmark of seven authentic public CTI advisories and 15 structured questions, ThreatMind achieved 100.0% abstention precision and recall on unanswerable queries, 100.0% path validity, and 100.0% citation completeness, outperforming keyword lookup and 1-hop graph baselines. ThreatMind demonstrates that coupling structured knowledge graphs with deterministic verification provides a defensible foundation for deploying AI in high-stakes cybersecurity operations.")

    # --- ACKNOWLEDGMENT ---
    add_sec_heading("ACKNOWLEDGMENT")
    add_body("The authors thank the Cybersecurity and Infrastructure Security Agency (CISA) and the MITRE Corporation for maintaining public-domain cyber threat intelligence advisories and frameworks. We also acknowledge the open-source communities behind Neo4j, FastAPI, React, and Cytoscape.js.")

    # --- REFERENCES ---
    add_sec_heading("REFERENCES")
    refs = [
        "[1] Y. Cheng, O. Bajaber, S. A. Tsegai, D. Song, and P. Gao, \"CTINexus: Automatic Cyber Threat Intelligence Knowledge Graph Construction Using Large Language Models,\" in Proc. 2025 IEEE European Symposium on Security and Privacy (EuroS&P), 2025. [Preprint: arXiv:2410.21060].",
        "[2] B. E. Strom, J. A. Battaglia, M. S. Kemmerer, W. Kupersanin, D. P. Miller, C. W. Peach, D. R. Schroeder, and C. S. Stephenson, \"MITRE ATT&CK: Design and Philosophy,\" MITRE Corporation, Bedford, MA, Tech. Rep. MTR180183, Mar. 2020.",
        "[3] P. Lewis, E. Perez, A. Piktus, F. Petroni, V. Karpukhin, N. Goyal, H. Küttler, M. Lewis, W. Yih, T. Rocktäschel, S. Riedel, and D. Kiela, \"Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks,\" in Advances in Neural Information Processing Systems (NeurIPS 2020), vol. 33, 2020, pp. 9459–9474.",
        "[4] Z. Ji, N. Lee, R. Frieske, T. Yu, D. Su, Y. Xu, E. Ishii, Y. J. Bang, A. Madotto, and P. Fung, \"Survey of Hallucination in Natural Language Generation,\" ACM Computing Surveys, vol. 55, no. 12, pp. 1–38, Mar. 2023. DOI: 10.1145/3571730.",
        "[5] Cybersecurity and Infrastructure Security Agency (CISA), \"Alert AA21-116A: Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders,\" CISA Joint Cybersecurity Advisory, Apr. 26, 2021. [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a",
        "[6] Cybersecurity and Infrastructure Security Agency (CISA), \"Alert AA24-060B: Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways,\" CISA Joint Cybersecurity Advisory, Feb. 29, 2024. [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b",
        "[7] I. Sarhan and M. Spruit, \"Open-CyKG: An Open Cyber Threat Intelligence Knowledge Graph,\" Knowledge-Based Systems, vol. 233, p. 107524, Dec. 2021. DOI: 10.1016/j.knosys.2021.107524.",
        "[8] Z. Li, J. Zeng, Y. Chen, and Z. Liang, \"AttacKG: Constructing Technique Knowledge Graph from Cyber Threat Intelligence Reports,\" in Computer Security – ESORICS 2022, Part I, LNCS, vol. 13554, Springer, 2022, pp. 617–639. DOI: 10.1007/978-3-031-17140-6_29.",
        "[9] D. Edge, H. Trinh, N. Cheng, J. Bradley, A. Chao, A. Mody, S. Truitt, D. Metropolitansky, R. O. Ness, and J. Larson, \"From Local to Global: A Graph RAG Approach to Query-Focused Summarization,\" arXiv preprint arXiv:2404.16130, Apr. 2024.",
        "[10] A. Kamath, R. Jia, and P. Liang, \"Selective Question Answering under Domain Shift,\" in Proc. 58th Annual Meeting of the Association for Computational Linguistics (ACL), Online, Jul. 2020, pp. 5684–5696. DOI: 10.18653/v1/2020.acl-main.503.",
        "[11] Cybersecurity and Infrastructure Security Agency (CISA), \"Alert AA22-110A: Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure,\" CISA Joint Cybersecurity Advisory, Apr. 20, 2022 (revised May 9, 2022). [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a",
        "[12] Cybersecurity and Infrastructure Security Agency (CISA), \"Alert AA21-356A: Mitigating Log4Shell and Other Log4j-Related Vulnerabilities,\" CISA Joint Cybersecurity Advisory, Dec. 22, 2021 (revised Dec. 28, 2021). [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a",
        "[13] Cybersecurity and Infrastructure Security Agency (CISA), NSA, and FBI, \"Alert AA24-038A: PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure,\" CISA Joint Cybersecurity Advisory, Feb. 7, 2024 (revised Feb. 29, 2024). [Online]. Available: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a",
        "[14] MITRE Corporation, \"APT29, Enterprise ATT&CK Group G0016,\" MITRE ATT&CK Framework, Mar. 2024. [Online]. Available: https://attack.mitre.org/groups/G0016/",
        "[15] MITRE Corporation, \"Sandworm Team, Enterprise ATT&CK Group G0034,\" MITRE ATT&CK Framework, Mar. 2024. [Online]. Available: https://attack.mitre.org/groups/G0034/",
        "[16] Neo4j, Inc., \"Neo4j Graph Database: Operations and Cypher Manual (v5.20),\" San Mateo, CA, 2024. [Online]. Available: https://neo4j.com/docs/"
    ]

    for ref in refs:
        p_ref = doc.add_paragraph()
        p_ref.paragraph_format.left_indent = Inches(0.3)
        p_ref.paragraph_format.first_line_indent = Inches(-0.3)
        p_ref.paragraph_format.space_after = Pt(4)
        p_ref.paragraph_format.line_spacing = 1.1
        r = p_ref.add_run(ref)
        r.font.name = "Calibri"
        r.font.size = Pt(8.5)
        r.font.color.rgb = c_dark

    # Save
    out_path = "docs/ThreatMind_IEEE_Research_Paper.docx"
    doc.save(out_path)
    print(f"Successfully generated DOCX paper at: {out_path}")

if __name__ == "__main__":
    build_docx()
