# ThreatMind: Demonstration Query Suite & Verification Guide

This document catalogues the demonstration and verification questions for **ThreatMind**. It specifies expected system responses, graph traversals, citation pools, and abstention behaviors across four query categories.

---

## 1. Direct Answerable Factual Queries (Single-Hop)

### Query 1: APT29 Malware Attribution
- **Question**: `What malware is associated with APT29?`
- **Category**: `factual_direct`
- **Expected Outcome**: **ANSWER GENERATED** (Grounding Status: `fully_grounded`)
- **Resolved Entities**: `APT29` (`actor_apt29`)
- **Traversed Relationships**: `(:ThreatActor {name: 'APT29'})-[:USES]->(:Malware)`
- **Discovered Entities**: `Cobalt Strike Beacon`, `WellMess`, `WellMail`
- **Expected Citations**: Citations referencing CISA Advisory `cisa_aa21_116a` or MITRE `mitre_g0016_apt29`.
- **Analyst Takeaway**: Shows fast single-hop entity resolution and deterministic citation attribution.

### Query 2: Sandworm Team Tooling
- **Question**: `What malware does Sandworm Team use?`
- **Category**: `factual_direct`
- **Expected Outcome**: **ANSWER GENERATED** (Grounding Status: `fully_grounded`)
- **Resolved Entities**: `Sandworm Team` (`actor_sandworm`)
- **Traversed Relationships**: `(:ThreatActor {name: 'Sandworm Team'})-[:USES]->(:Malware)`
- **Discovered Entities**: `BlackEnergy`, `Olympic Destroyer`, `Industroyer / CrashOverride`
- **Expected Citations**: Citations referencing CISA Advisory `cisa_aa22_110a` or MITRE `mitre_g0034_sandworm`.
- **Analyst Takeaway**: Demonstrates accurate actor-to-malware mapping from official advisories.

### Query 3: Log4j Vulnerability Impact
- **Question**: `What vulnerability affects Apache Log4j?`
- **Category**: `factual_direct`
- **Expected Outcome**: **ANSWER GENERATED** (Grounding Status: `fully_grounded`)
- **Resolved Entities**: `Apache Log4j` (`prod_log4j`)
- **Traversed Relationships**: `(:Vulnerability)-[:AFFECTS]->(:Product {name: 'Apache Log4j'})`
- **Discovered Entities**: `CVE-2021-44228` (Log4Shell)
- **Expected Citations**: Citations referencing CISA Advisory `cisa_aa21_356a`.
- **Analyst Takeaway**: Demonstrates reverse product-to-vulnerability lookup.

---

## 2. Supported Multi-Hop Threat Queries (2–3 Hops)

### Query 4: APT29 Multi-Hop Attack Patterns
- **Question**: `How does APT29 attack systems?`
- **Category**: `multi_hop`
- **Expected Outcome**: **ANSWER GENERATED** (Grounding Status: `fully_grounded`)
- **Resolved Entities**: `APT29` (`actor_apt29`)
- **Traversed Paths (Depth 2–3)**:
  1. `(:ThreatActor)-[:USES]->(:Malware)-[:USES_TECHNIQUE]->(:Technique)`
  2. `(:ThreatActor)-[:EXPLOITS]->(:Vulnerability)-[:AFFECTS]->(:Product)`
- **Cytoscape Visual**: Highlights multi-hop branches spanning `APT29`, `Cobalt Strike Beacon`, `T1059.001 (PowerShell)`, `CVE-2019-19781`, and `Citrix ADC`.
- **Semantic Caveats Injected**: Injects caveat noting that graph connectivity represents observed capability rather than universal temporal sequence.
- **Analyst Takeaway**: Highlights Cytoscape.js canvas rendering and multi-step continuity.

### Query 5: Adversary Vulnerability-to-Product Intrusions
- **Question**: `Which vulnerabilities and products are associated with APT29 intrusions?`
- **Category**: `multi_hop`
- **Expected Outcome**: **ANSWER GENERATED** (Grounding Status: `fully_grounded`)
- **Resolved Entities**: `APT29` (`actor_apt29`)
- **Traversed Paths (Depth 2)**:
  - `(:ThreatActor {id: 'actor_apt29'})-[:EXPLOITS]->(v:Vulnerability)-[:AFFECTS]->(p:Product)`
- **Discovered Chain**:
  - `APT29` $\to$ `CVE-2019-19781` $\to$ `Citrix ADC`
  - `APT29` $\to$ `CVE-2020-0688` $\to$ `Microsoft Exchange Server`
- **Analyst Takeaway**: Demonstrates full 2-hop traversal bridging an adversary directly to targeted commercial software.

---

## 3. Unanswerable Queries: Missing Entities (Abstention Required)

### Query 6: Fictitious Threat Actor
- **Question**: `What malware is used by PhantomSpider99?`
- **Category**: `unanswerable_unknown_actor`
- **Expected Outcome**: **CANONICAL ABSTENTION** (Grounding Status: `insufficient_evidence`)
- **System Behavior**:
  - `QueryEntityResolver` fails to match `PhantomSpider99` against the knowledge graph.
  - Active bridging paths: **0**.
  - Emitted Response: *"ThreatMind could not establish a sufficiently supported relationship from the currently available sources."*
  - Emitted Citations: **0**.
- **Analyst Takeaway**: Verifies that ThreatMind refuses to hallucinate information for unobserved actors.

### Query 7: Undocumented CVE Identifier
- **Question**: `What products are affected by CVE-2099-99999?`
- **Category**: `unanswerable_undocumented_cve`
- **Expected Outcome**: **CANONICAL ABSTENTION** (Grounding Status: `insufficient_evidence`)
- **System Behavior**:
  - Regex validates CVE format, but entity lookup returns no graph node for `CVE-2099-99999`.
  - Active bridging paths: **0**.
  - Emitted Response: Canonical abstention phrase.
- **Analyst Takeaway**: Verifies that synthetic or unindexed CVEs are rejected immediately.

---

## 4. Unanswerable Queries: Disconnected Entities & False Premises

### Query 8: Disconnected Threat Actor and Malware
- **Question**: `Did Volt Typhoon deploy BlackEnergy malware?`
- **Category**: `unanswerable_no_relationship`
- **Expected Outcome**: **CANONICAL ABSTENTION** (Grounding Status: `insufficient_evidence`)
- **System Behavior**:
  - Resolves `Volt Typhoon` (`actor_volt_typhoon`) and `BlackEnergy` (`malware_blackenergy`).
  - DFS traversal explores paths up to 3 hops from both nodes.
  - Bridging paths found: **0** (Volt Typhoon is documented in CISA AA24-038A; BlackEnergy is documented in CISA AA22-110A with Sandworm).
  - Endpoint invariant rejects disconnected subgraphs.
  - Emitted Response: Canonical abstention phrase.
- **Analyst Takeaway**: Proves that co-existence of two entities in the database does not produce a false positive.

### Query 9: Disconnected Actor and Vulnerability (Isolated Subgraph Trap)
- **Question**: `Does Sandworm Team exploit CVE-2021-44228 in Apache Log4j?`
- **Category**: `unanswerable_no_relationship`
- **Expected Outcome**: **CANONICAL ABSTENTION** (Grounding Status: `insufficient_evidence`)
- **System Behavior**:
  - Resolves `Sandworm Team`, `CVE-2021-44228`, and `Apache Log4j`.
  - Graph contains: `(CVE-2021-44228)-[:AFFECTS]->(Apache Log4j)`.
  - **Endpoint Invariant Check**: The primary subject `Sandworm Team` has no documented path to `CVE-2021-44228`.
  - The subpath `(CVE-2021-44228)-[:AFFECTS]->(Apache Log4j)` is rejected as an unsupported endpoint relationship.
  - Emitted Response: Canonical abstention phrase.
- **Analyst Takeaway**: Demonstrates ThreatMind's defense against the isolated subgraph trap where naive GraphRAG systems fail.

### Query 10: Adversarial False Premise
- **Question**: `How did APT29 use Olympic Destroyer to attack the Ukrainian power grid?`
- **Category**: `adversarial_false_premise`
- **Expected Outcome**: **CANONICAL ABSTENTION** (Grounding Status: `insufficient_evidence`)
- **System Behavior**:
  - Resolves `APT29`, `Olympic Destroyer`, and `Ukrainian Energy Sector`.
  - The benchmark graph links `Olympic Destroyer` and `Ukrainian Energy Sector` to `Sandworm Team`, not `APT29`.
  - DFS traversal finds no continuous path from `APT29` to `Olympic Destroyer`.
  - Candidate paths are rejected; system emits canonical abstention.
- **Analyst Takeaway**: Proves resistance to adversarial prompts designed to elicit erroneous confirmation.
