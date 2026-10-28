# ThreatMind — Phase 9: Research Evaluation & Validation Plan

## 1. Executive Summary & Research Objectives

ThreatMind is an AI-powered Cyber Threat Intelligence (CTI) investigation system engineered around a cybersecurity knowledge graph, GraphRAG retrieval, transparent multi-hop graph reasoning, and provenance-anchored answer generation.

Its central design principle is:
> **"No guessing. No hallucination. Only graph-backed facts."**

The objective of Phase 9 is to rigorously evaluate this claim against an authentic, public-domain CTI benchmark dataset. We measure the system's empirical capabilities, failure modes, abstention reliability, and ground-truth alignment without fabricating results or conflating structural consistency with factual truth.

### Research Questions (RQs)

1. **RQ1 (Information Extraction Quality)**: What are the precision, recall, and F1 scores of CTI entity and relationship extraction against manually verified public advisories?
2. **RQ2 (GraphRAG Retrieval Quality)**: How effectively does ThreatMind's entity resolver and bounded graph retriever recover relevant threat intelligence facts compared to direct keyword lookup?
3. **RQ3 (Multi-Hop Threat Path Validity)**: What proportion of multi-hop attack paths assembled by the reasoning engine satisfy schema constraints, path continuity, non-cyclic traversal, and ground-truth documentation?
4. **RQ4 (Evidence Grounding & Citation Integrity)**: Are all substantive statements generated in analyst answers backed by valid, traceable citation records and verbatim source text? What is the rate of unsupported assertions?
5. **RQ5 (Abstention Precision & Reliability)**: Does ThreatMind reliably abstain when queried about undocumented threat actors, unobserved relationships, or insufficient evidence, without gratuitously abstaining on legitimate questions?

---

## 2. Research Integrity & Isolation Architecture

To ensure experimental validity and prevent bias, Phase 9 enforces four architectural boundaries:

```
[ Real CTI Corpus (CISA / MITRE) ]       [ Synthetic Demo Fixture ]
            │                                      │
            ▼                                      ▼
    data/evaluation/                     data/sample/demo_synthetic_cti.json
  (is_synthetic: false)                   (is_synthetic: true)
            │                                      │
            ▼                                      ▼
[ Evaluator Graph Namespace ]            [ Development Graph Namespace ]
  (IDs: cisa_*, mitre_*)                  (IDs: actor_apt29, etc.)
            │
            ├─────────────── Isolated Ingestion & Cleanup ───────────────┤
            ▼
    [ Benchmark Queries ]
       (Input ONLY: query text & depth)
            │
            ▼
     [ System Predictions ] ────────► [ Post-Hoc Scoring Engine ]
                                                   ▲
                                                   │ (NO LEAKAGE)
                                      [ Gold Ground Truth ]
                                      (Quarantined References)
```

### Isolation & Cleanup Protocol
1. **Corpus Segregation**: Evaluation documents reside exclusively in `data/evaluation/documents/`. All metadata fields specify `is_synthetic: false`.
2. **Namespace Partitioning**: Node and source IDs generated during evaluation ingestion use strict prefixes (`eval_cisa_`, `eval_mitre_`).
3. **Cleanup Procedure**: The isolation module (`backend/app/evaluation/isolation.py` and `scripts/cleanup_eval_graph.py`) provides targeted Cypher deletion of evaluation nodes without modifying schema constraints or corrupting the development graph:
   ```cypher
   MATCH (s:Source) WHERE s.id STARTS WITH 'eval_' OR s.is_synthetic = false
   OPTIONAL MATCH (s)-[r]-()
   DELETE r, s
   ```
4. **Leakage Prevention**: System components under test receive only the analyst query string (`question: str`). They never receive gold entities, gold path templates, or ground-truth citations. The scoring module evaluates output objects post-hoc.
5. **Execution Mode Labeling**: Every benchmark report explicitly identifies its operational mode:
   - `OFFLINE_DETERMINISTIC`: Evaluates rule-based deterministic fallback and graph retrieval logic without live external API dependencies.
   - `OFFLINE_MOCK`: Verifies pipeline mechanics with mocked responses.
   - `LIVE_LLM`: Runs live LLM inference with recorded model parameters (`gemini-2.0-flash`, `temperature=0.0`).

---

## 3. Real CTI Evaluation Dataset Structure

The benchmark corpus consists of 7 authentic, public-domain CTI advisories and threat profiles published by the **Cybersecurity and Infrastructure Security Agency (CISA)** and **MITRE ATT&CK**:

1. **`cisa_aa21_356a`**: *Mitigating Apache Log4j2 Vulnerabilities* (CVE-2021-44228, Apache Log4j, Cobalt Strike, living-off-the-land techniques).
2. **`cisa_aa24_038a`**: *PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure* (Volt Typhoon, living-off-the-land, Ivanti Connect Secure, Fortinet FortiOS, T1078, T1059).
3. **`cisa_aa21_116a`**: *Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders* (APT29 / SVR, WellMess, WellMail, CVE-2019-19781 Citrix ADC, CVE-2020-0688 Microsoft Exchange).
4. **`cisa_aa22_110a`**: *Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure* (Sandworm Team / GRU Unit 74455, BlackEnergy, CrashOverride / Industroyer, NotPetya).
5. **`cisa_aa24_060b`**: *Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways* (CVE-2023-46805, CVE-2024-21887, Web shells, command injection).
6. **`mitre_g0016_apt29`**: *APT29, Group G0016* (PowerShell T1059.001, Valid Accounts T1078, Archive Collected Data T1560).
7. **`mitre_g0034_sandworm`**: *Sandworm Team, Group G0034* (Olympic Destroyer / Software S0365, Data Destruction T1485, Command and Scripting Interpreter T1059, Network Denial of Service T1498).

### Directory Layout
```text
data/
  evaluation/
    README.md
    dataset_manifest.json
    documents/
      cisa_aa21_356a.json
      cisa_aa24_038a.json
      cisa_aa21_116a.json
      cisa_aa22_110a.json
      cisa_aa24_060b.json
      mitre_g0016_apt29.json
      mitre_g0034_sandworm.json
    annotations/
      entities.json
      relationships.json
    queries.json
    ground_truth.json
    results.json
    results.csv
```

---

## 4. Benchmark Metrics & Mathematical Formulations

To ensure full transparency, every metric defines its unit of analysis, formula, numerator, denominator, and boundary behavior for zero denominators.

### 4.1 Entity Extraction Metrics
- **Unit of Analysis**: Extracted entity mention $(name, label)$ normalized to lower-case.
- **True Positive ($TP_E$)**: Predicted entity whose canonical name matches a gold entity under the same primary label.
- **False Positive ($FP_E$)**: Predicted entity not in gold standard or mapped to incorrect label.
- **False Negative ($FN_E$)**: Gold entity missed in prediction.

$$\text{Precision}_E = \frac{TP_E}{TP_E + FP_E}, \quad \text{Recall}_E = \frac{TP_E}{TP_E + FN_E}, \quad F_1 = \frac{2 \cdot P \cdot R}{P + R}$$

*Zero Denominator Rule*: If $TP_E + FP_E = 0$ and $TP_E + FN_E = 0$, $P=1.0, R=1.0, F_1=1.0$. If $TP_E + FP_E = 0$ but $FN_E > 0$, $P=0.0, R=0.0, F_1=0.0$.

### 4.2 Relationship Extraction Metrics
- **Unit of Analysis**: Normalized triple $(Subj_{norm}, RelType, Obj_{norm})$.
- A predicted relationship is counted as a **True Positive ($TP_R$)** if and only if:
  1. Subject entity matches gold subject.
  2. Relationship type matches gold type exactly.
  3. Object entity matches gold object.
  4. Supporting evidence quote shares substantial lexical overlap ($\ge 70\%$) with gold passage.
- Mere co-occurrence of subject and object without verified grammatical relationship is classified as $FP_R$.

$$\text{Precision}_R = \frac{TP_R}{TP_R + FP_R}, \quad \text{Recall}_R = \frac{TP_R}{TP_R + FN_R}, \quad F_1 = \frac{2 \cdot P \cdot R}{P + R}$$

### 4.3 GraphRAG Retrieval Metrics
- **Unit of Analysis**: Retrieved graph relationship triples for a query at cutoff $k$.
- **Relevant Items ($Rel_Q$)**: Gold triples documented in corpus addressing question $Q$.
- **Retrieved Items ($Ret_Q^k$)**: Top-$k$ relationship triples returned by retriever.

$$\text{Precision@}k = \frac{|Ret_Q^k \cap Rel_Q|}{k}, \quad \text{Recall@}k = \frac{|Ret_Q^k \cap Rel_Q|}{|Rel_Q|}$$

*Zero Denominator Rule*: If $|Rel_Q| = 0$ (unanswerable query), Recall is defined as $1.0$ if $|Ret_Q^k| = 0$ (properly retrieved nothing) and $0.0$ otherwise.

### 4.4 Multi-Hop Path Reasoning Metrics
- **Path Validity Rate ($PVR$)**:
  $$PVR = \frac{\text{Number of structurally valid, non-cyclic paths with unbroken continuity}}{\text{Total assembled paths}}$$
- **Path Factual Precision ($PFP$)**:
  $$PFP = \frac{\text{Accepted paths where all constituent hops match verified gold relationships}}{\text{Total accepted paths}}$$
- **Cycle Rejection Rate**:
  $$CRR = \frac{\text{Cyclic candidate paths rejected by reasoning engine}}{\text{Total candidate paths containing cycles}}$$

### 4.5 Evidence Grounding & Citation Integrity
- **Citation ID Integrity ($CII$)**:
  $$CII = \frac{\text{Citations referencing valid, deterministic evidence IDs}}{\text{Total citations emitted}}$$
- **Evidence Passage Support ($EPS$)**:
  $$EPS = \frac{\text{Citations whose cited verbatim text entails the associated claim}}{\text{Total citations emitted}}$$
- **Unsupported Claim Rate ($UCR$)**:
  $$UCR = \frac{\text{Factual claims marked unverified or lacking citation support}}{\text{Total factual claims in generated answers}}$$

### 4.6 Abstention Precision & Recall
- Evaluated on a balanced set of answerable and unanswerable/insufficient-evidence queries.
- **Contingency Table**:
  - $TP_A$: Correct abstention when evidence is absent/insufficient.
  - $FP_A$: Erroneous abstention when complete evidence was available in graph.
  - $TN_A$: Proper answer generated when evidence was available.
  - $FN_A$: Erroneous hallucinated answer generated when evidence was missing.

$$\text{Abstention Precision} = \frac{TP_A}{TP_A + FP_A}, \quad \text{Abstention Recall} = \frac{TP_A}{TP_A + FN_A}$$

$$\text{False Abstention Rate} = \frac{FP_A}{FP_A + TN_A}$$

---

## 5. Controlled Baseline Specifications

To fairly demonstrate ThreatMind's value, the identical query set is evaluated across three conditions:

| Baseline | Architecture | Retrieval Scope | Abstention Rule |
| :--- | :--- | :--- | :--- |
| **Baseline A: Keyword Lookup** | Regex / BM25 search over raw corpus text | Matches keywords; extracts raw text snippets | Abstains if keyword match count $< 1$ |
| **Baseline B: 1-Hop Graph Retrieval** | Resolves entity, queries immediate Neo4j neighbors | Strictly depth $= 1$; cannot bridge 2-hop or 3-hop hops | Abstains if entity unresolved or 0 neighbors |
| **ThreatMind (Full GraphRAG)** | Entity resolver + multi-hop Cypher traversal + path validator + grounded prompt generator + answer validator | Traverses up to depth $= 3$; validates template semantics | Abstains if entity unresolved or 0 validated paths |

---

## 6. Reproducibility & Verification Roadmap

1. **Step 1**: Curate authentic CTI source documents in `data/evaluation/documents/`.
2. **Step 2**: Manually annotate entities, relationships, queries, and ground truth in `data/evaluation/`.
3. **Step 3**: Validate dataset integrity with `scripts/validate_dataset.py` and pytest.
4. **Step 4**: Implement modular evaluation framework under `backend/app/evaluation/`.
5. **Step 5**: Execute offline deterministic benchmark via `python scripts/run_evaluation.py --offline`.
6. **Step 6**: Generate machine-readable JSON/CSV metrics and human-readable `docs/evaluation-results.md`.
7. **Step 7**: Update research alignment documentation in `docs/research-alignment.md`.
8. **Step 8**: Perform full regression testing across backend, frontend, and production build.
