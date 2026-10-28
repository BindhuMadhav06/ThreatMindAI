# ThreatMind Real CTI Evaluation Dataset

This dataset constitutes the authentic, un-contaminated benchmark corpus for evaluating **ThreatMind**.

## 1. Dataset Integrity & Research Principles

- **Zero Contamination**: Strictly separated from the synthetic demo dataset (`data/sample/demo_synthetic_cti.json`). Every document, entity, and relationship declares `"is_synthetic": false`.
- **Public Domain Sources**: All documents are derived from official Cybersecurity and Infrastructure Security Agency (CISA) alerts or the MITRE ATT&CK knowledge base.
- **Character-Exact Grounding**: Every entity annotation maps to an exact substring span (`[start_char:end_char]`), and every relationship maps to a verbatim evidence quote (`[char_start:char_end]`) in its canonical source document.
- **Cryptographic Provenance**: Every document's integrity is protected via SHA-256 digests over its JSON file contents.

## 2. Benchmark Corpus Composition (v1.1.0)

| Source ID | Canonical Title | Publisher | Published Date | Documented Entities & Topics |
| :--- | :--- | :--- | :--- | :--- |
| `cisa_aa22_110a` | Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure | CISA / FBI / NSA | 2022-04-20 | Sandworm Team, BlackEnergy, Industroyer, NotPetya, Ukrainian power grid |
| `cisa_aa21_116a` | Russian Foreign Intelligence Service (SVR) Cyber Operations: Trends and Best Practices for Network Defenders | CISA | 2021-04-26 | APT29, WellMess, WellMail, CVE-2019-19781, Citrix ADC, CVE-2020-0688, Exchange |
| `cisa_aa21_356a` | Mitigating Log4Shell and Other Log4j-Related Vulnerabilities | CISA | 2021-12-22 | Apache Log4j, CVE-2021-44228, Cobalt Strike, PowerShell, Windows |
| `cisa_aa24_060b` | Threat Actors Exploit Multiple Vulnerabilities in Ivanti Connect Secure and Policy Secure Gateways | CISA | 2024-02-29 | Ivanti Connect Secure, CVE-2023-46805, CVE-2024-21887 |
| `cisa_aa24_038a` | PRC State-Sponsored Actors Compromise and Maintain Persistent Access to U.S. Critical Infrastructure | CISA / FBI / NSA | 2024-02-07 | Volt Typhoon, Fortinet FortiOS, Ivanti Connect Secure, Valid Accounts |
| `mitre_g0016_apt29` | MITRE ATT&CK Group G0016: APT29 | MITRE Corporation | 2024-03-25 | APT29, Archive Collected Data, Valid Accounts |
| `mitre_g0034_sandworm` | MITRE ATT&CK Group G0034: Sandworm Team | MITRE Corporation | 2024-03-25 | Sandworm Team, Olympic Destroyer, Data Destruction, Command Interpreter, Network DoS |

## 3. Directory Structure

```
data/evaluation/
├── dataset_manifest.json          # Master manifest with metadata and SHA-256 digests
├── README.md                      # This specification
├── queries.json                   # 15 evaluation queries (factual, multi-hop, unanswerable)
├── ground_truth.json              # Quarantined ground truth triples, paths, and quotes
├── documents/                     # Canonical source documents (JSON fixtures)
│   ├── cisa_aa22_110a.json
│   ├── cisa_aa21_116a.json
│   ├── cisa_aa21_356a.json
│   ├── cisa_aa24_060b.json
│   ├── cisa_aa24_038a.json
│   ├── mitre_g0016_apt29.json
│   └── mitre_g0034_sandworm.json
└── annotations/
    ├── entities.json              # 30 curated entities with character spans
    └── relationships.json         # 25 curated relationships with verbatim quotes
```

## 4. Verification

Run the dataset validation script to verify all cryptographic hashes, entity spans, and evidence quotes:

```powershell
.\venv\Scripts\python.exe scripts\validate_dataset.py
```
