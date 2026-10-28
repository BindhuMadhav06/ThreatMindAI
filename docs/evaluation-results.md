# ThreatMind — Empirical Research Evaluation & Validation Report

**Execution Mode**: `OFFLINE_DETERMINISTIC`  
**Evaluation Date**: `2026-10-14T09:09:08.794889+00:00`  
**Benchmark Version**: `1.0.0`  
**Total Benchmark Queries**: `15`  

---

## 1. Executive Summary & Design Principle Assessment

ThreatMind's core objective is:
> **"No guessing. No hallucination. Only graph-backed facts."**

This report presents an empirical evaluation of ThreatMind across 15 structured CTI benchmark questions evaluated against a curated, manually verified knowledge graph comprising 7 authentic public advisories from CISA and MITRE ATT&CK.

### High-Level Empirical Findings:
- **Abstention Reliability**: 5/5 (100.0%) precision, 5/5 (100.0%) recall across 15 benchmark questions. ThreatMind reliably refused to fabricate relationships for unknown entities and undocumented links.
- **Multi-Hop Path Validity**: 70/70 (100.0%) of assembled paths satisfied schema constraints, unbroken continuity, and cycle rejection.
- **Citation ID Integrity**: 71/71 (100.0%) of citations referenced valid deterministic evidence IDs backed by authentic source text.
- **Citation Completeness**: 78/78 (100.0%) of emitted claims were indexed to at least one valid citation.
- **Automated Validation Failure Rate**: 0/78 (0.0%) failed automated grounding-guard validation. All claims emitted in accepted answers were tied to validated graph paths (*distinguishes automated deterministic validation from independent human assessment of semantic entailment*).

---

## 2. Benchmark Corpus & Provenance Manifest

The evaluation corpus is strictly isolated from synthetic demo data (`is_synthetic: false` across all records) and comprises **7 authentic public domain CTI source documents** and **15 structured benchmark questions**.

| Source ID | Title | Publisher | Publication Date | SHA-256 Digest (Prefix) |
| :--- | :--- | :--- | :--- | :--- |
| `cisa_aa22_110a` | Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure | Cybersecurity and Infrastructure Security Agency | 2022-04-20 | `47802f041d14...` |
| `cisa_aa21_116a` | Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders | Cybersecurity and Infrastructure Security Agency | 2021-04-26 | `a04d84df2fb1...` |
| `cisa_aa21_356a` | Mitigating Log4Shell and Other Log4j-Related Vulnerabilities | Cybersecurity and Infrastructure Security Agency | 2021-12-22 | `e3f3c90c0385...` |
| `cisa_aa24_060b` | Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways | Cybersecurity and Infrastructure Security Agency | 2024-02-29 | `7e3fa36c1831...` |
| `cisa_aa24_038a` | PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure | Cybersecurity and Infrastructure Security Agency | 2024-02-07 | `115236b84058...` |
| `mitre_g0016_apt29` | MITRE ATT&CK Group G0016: APT29 | MITRE Corporation | 2024-03-25 | `2108bf0854b1...` |
| `mitre_g0034_sandworm` | MITRE ATT&CK Group G0034: Sandworm Team | MITRE Corporation | 2024-03-25 | `dc9a9db6c84a...` |

- **Total Public Source Documents**: 7 (CISA and MITRE ATT&CK advisories)
- **Total Curated Entities**: 30 (verified with character-exact offsets)
- **Total Curated Relationships**: 25 (verified with verbatim source quotes)
- **Total Benchmark Queries**: 15 (covering factual, multi-hop, unanswerable, and adversarial categories)

---

## 3. Comprehensive Metric Results (With Exact Denominators)

### A. Abstention Behavior on Insufficient-Evidence Queries
| Metric | Numerator / Denominator | Score | Interpretation |
| :--- | :---: | :---: | :--- |
| **Abstention Precision** | 5 / 5 | **100.0%** | Proportion of abstention decisions that were required by ground truth |
| **Abstention Recall** | 5 / 5 | **100.0%** | Proportion of unanswerable queries correctly rejected |
| **False Abstention Rate** | 0 / 10 | **0.0%** | Rate at which answerable questions were unnecessarily rejected |

*Contingency Table*: True Abstentions ($TP$): 5, False Abstentions ($FP$): 0, True Answers ($TN$): 10, Failed Abstentions ($FN$): 0.

### B. Knowledge Graph Retrieval (GraphRAG vs Baselines)
| Metric | Numerator / Denominator | Value | Denominator Context |
| :--- | :---: | :---: | :--- |
| **Pooled Retrieved-Fact Precision (top-5 windows)** | 14 / 41 | **14/41 (34.1%)** | Evaluated on top-5 retrieved facts across answerable queries |
| **Recall@5** | 14 / 24 | **14/24 (58.3%)** | Proportion of documented gold facts recovered in retrieval |
| **Query-Level Zero-Resolved-Seed Rate** | 2 / 15 | **2/15 (13.3%)** | Queries with zero resolved starting seeds (q11, q12; 0/10 on answerable queries) |
| **Entity-Mention Resolution (candidate-to-node coverage)** | 21 / 24 | **21/24 (87.5%)** | Candidate entity mentions successfully resolved to graph nodes (3 unresolved: q11, q12, q15) |

*Retrieval Analysis & Limitations*:
- **Strengths**: Recovers primary documented attack facts across answerable questions (14/24 (58.3%)) with 0.0% zero-resolved queries on legitimate in-graph queries (0/10 on q01–q10).
- **Out-of-Graph Entity Resolution**: The Query-Level Zero-Resolved-Seed Rate is 2/15 (13.3%) (2/15), strictly measuring questions where no required starting entity could resolve in the graph (queries q11 PhantomSpider99 and q12 CVE-2099-99999). Inability to resolve these entities is the expected prerequisite that triggers canonical abstention (5/5 precision and recall).
- **Entity-Mention Resolution (Candidate-to-Node Coverage)**: Evaluated at the mention level, candidate-to-node resolution coverage is 21/24 (87.5%) (21/24). The 3 unresolved candidate mentions represent two distinct categories: (1) deliberately unobserved entities (PhantomSpider99 in q11 and CVE-2099-99999 in q12) where non-resolution correctly triggers canonical pre-retrieval abstention; and (2) an extraction tokenization artifact in q15 where the geographic adjective 'Ukrainian' was extracted as an entity candidate alongside the primary attack entities (APT29 and Olympic Destroyer), which resolved correctly and whose false relationship premise was subsequently rejected by the endpoint-connectivity invariant.
- **Remaining Limitations**: Pooled Retrieved-Fact Precision (top-5 windows) is bounded at 14/41 (34.1%) because the top-5 retrieval window over multi-hop subgraphs returns valid neighboring relationships that fall outside the concise gold fact subset. Additionally, 10/24 gold facts (41.7%) were not captured within the top-5 cutoff on multi-hop questions, demonstrating the need for adaptive retrieval depth and hybrid vector-graph indexing.

### C. Multi-Hop Threat Path Reasoning
| Metric | Numerator / Denominator | Rate | Notes |
| :--- | :---: | :---: | :--- |
| **Path Structural Validity** | 70 / 70 | **70/70 (100.0%)** | Evaluates non-cyclic traversal and schema conformance |
| **Path Step Continuity** | 70 / 70 | **70/70 (100.0%)** | Target of hop $i$ matches source of hop $i+1$ |
| **Cycle Rejection Rate** | 0 / 0 | **0/0 (N/A)** | Cyclic candidate paths eliminated by path builder (N/A when 0 cycles encountered) |

### D. Evidence Grounding & Citation Integrity
| Metric | Numerator / Denominator | Rate | Definition & Scientific Interpretation |
| :--- | :---: | :---: | :--- |
| **Citation ID Integrity** | 71 / 71 | **71/71 (100.0%)** | Emitted citations referencing valid deterministic `ev_` hashes backed by authentic text |
| **Citation Completeness** | 78 / 78 | **78/78 (100.0%)** | Proportion of emitted answer claims indexed to at least one valid citation (Claims With Citations / Total Claims = 78/78) |
| **Automated Validation Failure Rate** | 0 / 78 | **0/78 (0.0%)** | Proportion of claims failing automated validation checks ($0/78$). *Methodological Distinction*: Reflects automated deterministic and lexical verification against graph paths; does not constitute independent human assessment of natural-language semantic entailment. |

### E. Document Entity & Relation Extraction
| Metric | Status | Methodological Disclosure |
| :--- | :--- | :--- |
| **Entity Extraction** | `NOT RUN` | Offline Deterministic Mode — Evaluates GraphRAG retrieval, multi-hop reasoning, and grounding on verified graph data; does not execute live LLM document extraction against unparsed text. |
| **Relation Extraction** | `NOT RUN` | Live extraction benchmarks require an active LLM provider (e.g. Gemini 2.0 Flash) with empirical document-chunk parsing. |

---

## 4. Controlled Baseline Comparison

All baselines were evaluated against the identical 15 benchmark questions and source documents under zero-leakage conditions:

| System / Baseline | Architecture | Multi-Hop Traversal | Abstention Precision | Abstention Recall | False Abstention Rate | Evidence Traceability |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline A: Keyword Lookup** | BM25 / Regex Snippet Search | No | 0/0 (N/A) | 0/5 (0.0%) | 0/10 (0.0%) | Raw text match only |
| **Baseline B: 1-Hop Graph Retrieval** | Bounded 1-Hop Neo4j Query | No | 2/2 (100.0%) | 2/5 (40.0%) | 0/10 (0.0%) | Direct edge only |
| **ThreatMind Full Pipeline** | GraphRAG + Path Validation + Provenance | **Yes (Up to 3 hops)** | **5/5 (100.0%)** | **5/5 (100.0%)** | **0/10 (0.0%)** | Full Cytoscape path + Drawer |

### Qualitative Analysis of Baselines:
1. **Baseline A (Keyword Lookup)**: Frequently failed on unanswerable queries containing known entity names (e.g., `q_13`: *"Did Volt Typhoon deploy BlackEnergy?"* and `q_15`: false premise attack), resulting in **0.0% Abstention Recall (0/5)** (note: this reflects failure to abstain on ungrounded queries, not zero passage retrieval). Because both words appeared in the corpus, keyword matching retrieved passages and failed to abstain, producing false answers without relational validation.
2. **Baseline B (1-Hop Retrieval)**: Accurately handled simple direct questions, but could not bridge multi-hop queries (e.g. `q_06`: *"How does APT29 attack systems?"* and `q_07`) requiring traversing from ThreatActor through Vulnerability to affected Product.
3. **ThreatMind**: Successfully bridged multi-hop exploit paths while correctly abstaining on both unobserved entities and false relational premises.

---

## 5. Detailed Query-by-Query Results

| Query ID | Category | Question | Expected Abstain | System Abstain | Status | Grounding |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| `q_01` | `factual_direct` | What malware is associated with APT29? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_02` | `factual_direct` | What malware does Sandworm Team use? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_03` | `factual_direct` | What vulnerability affects Apache Log4j? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_04` | `factual_direct` | Which products are affected by CVE-2023-46805? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_05` | `factual_direct` | What techniques does Volt Typhoon use? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_06` | `multi_hop` | How does APT29 attack systems? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_07` | `multi_hop` | Which vulnerabilities and products are associated with APT29 intrusions? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_08` | `multi_hop` | What organizations are targeted by Sandworm Team? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_09` | `factual_direct` | What techniques are associated with Sandworm Team? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_10` | `factual_direct` | What techniques does APT29 use for credential access and collection? | `False` | `False` | **PASS** | `fully_grounded` |
| `q_11` | `unanswerable_unknown_actor` | What malware is used by PhantomSpider99? | `True` | `True` | **PASS** | `insufficient_evidence` |
| `q_12` | `unanswerable_undocumented_cve` | What products are affected by CVE-2099-99999? | `True` | `True` | **PASS** | `insufficient_evidence` |
| `q_13` | `unanswerable_no_relationship` | Did Volt Typhoon deploy BlackEnergy malware? | `True` | `True` | **PASS** | `insufficient_evidence` |
| `q_14` | `unanswerable_no_relationship` | Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j? | `True` | `True` | **PASS** | `insufficient_evidence` |
| `q_15` | `adversarial_false_premise` | How did APT29 use Olympic Destroyer to attack the Ukrainian power grid? | `True` | `True` | **PASS** | `insufficient_evidence` |

---

## 6. Known Limitations & Threats to Validity

1. **Lexical vs. Semantic Grounding**: Deterministic validation checks verify exact token overlap, citation integrity, and presence of forbidden compromise verbs. While highly effective at catching hallucinated associations, full semantic entailment requires human review or specialized formal methods.
2. **Benchmark Scale**: The pilot evaluation corpus contains 7 public advisories, 30 entities, 25 relationships, and 15 benchmark questions. While hand-verified and zero-leakage, scaling to thousands of documents may introduce alias ambiguity and entity resolution challenges.
3. **Execution Mode**: This benchmark was executed in `OFFLINE_DETERMINISTIC` mode. Deterministic fallback behavior was tested without live non-deterministic LLM tokens, ensuring complete reproducibility.

---

## 7. Exact Reproducibility Commands

To reproduce this evaluation independently from a clean environment:

```powershell
# 1. Validate dataset integrity and SHA-256 hashes
.\venv\Scripts\python.exe scripts\validate_dataset.py

# 2. Run automated test suites
.\venv\Scripts\pytest backend\tests\test_dataset_validation.py backend\tests\test_evaluation_metrics.py -v

# 3. Run full benchmark evaluation
.\venv\Scripts\python.exe scripts\run_evaluation.py --offline

# 4. Clean up evaluation graph (optional)
.\venv\Scripts\python.exe scripts\cleanup_eval_graph.py --restore-demo
```
