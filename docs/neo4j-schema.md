# ThreatMind Neo4j Schema & Provenance Architecture

## 1. Overview

The ThreatMind cybersecurity knowledge graph is hosted on Neo4j 5.x. It enforces strict property graph structures, parameterized queries, unique identifiers for all primary nodes, and mandatory edge provenance metadata on every threat intelligence relationship.

---

## 2. Primary Node Labels (13 Core Entities)

| Node Label | Unique Key | Secondary Properties | Description |
| :--- | :--- | :--- | :--- |
| `ThreatActor` | `id` | `name`, `aliases`, `description`, `country` | Threat groups, nation-state actors, APTs |
| `Malware` | `id` | `name`, `aliases`, `description`, `malware_type` | Malicious code, ransomware, C2 frameworks |
| `Tool` | `id` | `name`, `aliases`, `description` | Dual-use utilities (e.g., Mimikatz, PowerShell) |
| `Vulnerability` | `id` | `name`, `aliases`, `description`, `cvss_score` | Known software security flaws (CVE IDs) |
| `Technique` | `id` | `name`, `external_id`, `description` | MITRE ATT&CK techniques (e.g. T1059.001) |
| `Tactic` | `id` | `name`, `external_id`, `description` | MITRE ATT&CK high-level tactics (e.g. TA0002) |
| `Campaign` | `id` | `name`, `description` | Named, time-bounded threat campaigns |
| `Software` | `id` | `name`, `version`, `description` | General software components |
| `OperatingSystem`| `id` | `name`, `version` | Target host operating systems |
| `Product` | `id` | `name`, `vendor`, `version` | Affected commercial software products |
| `Organization` | `id` | `name`, `sector` | Target industry sectors or enterprises |
| `Indicator` | `id` | `type`, `value` | IoCs (hashes, IPs, domains) |
| `Source` | `id` | `title`, `url`, `publisher`, `published_date`, `source_type`, `is_synthetic` | CTI reports & provenance records |

---

## 3. Relationship Vocabulary & Schema

ThreatMind supports the following typed relationship edges:

1. `(:ThreatActor)-[:USES {provenance}]->(:Malware)`
2. `(:ThreatActor)-[:USES {provenance}]->(:Tool)`
3. `(:ThreatActor)-[:USES_TECHNIQUE {provenance}]->(:Technique)`
4. `(:ThreatActor)-[:EXPLOITS {provenance}]->(:Vulnerability)`
5. `(:ThreatActor)-[:TARGETS {provenance}]->(:Organization)`
6. `(:ThreatActor)-[:CONDUCTS {provenance}]->(:Campaign)`
7. `(:Malware)-[:USES_TECHNIQUE {provenance}]->(:Technique)`
8. `(:Malware)-[:TARGETS {provenance}]->(:OperatingSystem)`
9. `(:Malware)-[:TARGETS {provenance}]->(:Product)`
10. `(:Tool)-[:USES_TECHNIQUE {provenance}]->(:Technique)`
11. `(:Technique)-[:PART_OF]->(:Tactic)`
12. `(:Vulnerability)-[:AFFECTS {provenance}]->(:Product)`
13. `(:Vulnerability)-[:AFFECTS {provenance}]->(:OperatingSystem)`
14. `(:Indicator)-[:ASSOCIATED_WITH {provenance}]->(:ThreatActor|Malware|Tool)`
15. `(:Entity)-[:SUPPORTED_BY]->(:Source)`

---

## 4. Edge Provenance Model

Every relationship edge carries a mandatory provenance property dictionary:

```json
{
  "source_id": "source_demo_001",
  "source_url": "https://threatmind.demo/advisories/APT29-2026-SYNTHETIC",
  "evidence_text": "APT29 deployed Cobalt Strike Beacon payloads during lateral movement.",
  "published_date": "2026-01-15",
  "extraction_method": "demo_synthetic_ingestion",
  "confidence": null
}
```

> [!IMPORTANT]
> **No Fabricated Confidence Scores**: If confidence score is not calculated using a documented quantitative method, `confidence` is stored as `null`.

---

## 5. Uniqueness Constraints & Indexes (Neo4j 5.x Cypher)

```cypher
// Uniqueness Constraints
CREATE CONSTRAINT constraint_threatactor_id IF NOT EXISTS FOR (n:ThreatActor) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_malware_id IF NOT EXISTS FOR (n:Malware) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_tool_id IF NOT EXISTS FOR (n:Tool) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_vulnerability_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_technique_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_tactic_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_campaign_id IF NOT EXISTS FOR (n:Campaign) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_software_id IF NOT EXISTS FOR (n:Software) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_operatingsystem_id IF NOT EXISTS FOR (n:OperatingSystem) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_product_id IF NOT EXISTS FOR (n:Product) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_organization_id IF NOT EXISTS FOR (n:Organization) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_indicator_id IF NOT EXISTS FOR (n:Indicator) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT constraint_source_id IF NOT EXISTS FOR (n:Source) REQUIRE n.id IS UNIQUE;

// Secondary Lookup Indexes
CREATE INDEX idx_threatactor_name IF NOT EXISTS FOR (n:ThreatActor) ON (n.name);
CREATE INDEX idx_malware_name IF NOT EXISTS FOR (n:Malware) ON (n.name);
CREATE INDEX idx_tool_name IF NOT EXISTS FOR (n:Tool) ON (n.name);
CREATE INDEX idx_technique_name IF NOT EXISTS FOR (n:Technique) ON (n.name);
CREATE INDEX idx_technique_external_id IF NOT EXISTS FOR (n:Technique) ON (n.external_id);
CREATE INDEX idx_source_url IF NOT EXISTS FOR (n:Source) ON (n.url);
```

---

## 6. Example Provenance Cypher Query

To answer: *"Why does ThreatMind believe APT29 uses Cobalt Strike?"*

```cypher
MATCH (a:ThreatActor {id: 'actor_apt29'})-[r:USES]->(m:Malware {id: 'malware_cobaltstrike'})
OPTIONAL MATCH (s:Source {id: r.source_id})
RETURN a.name AS actor, type(r) AS relationship, m.name AS malware,
       r.evidence_text AS exact_evidence, r.source_url AS url, s.title AS source_title
```

---

## 7. Synthetic Demo Data & Seeding

The development environment is seeded using:
- **Seed Script**: `py -3.13 scripts/seed_demo_data.py`
- **Synthetic Dataset**: `data/sample/demo_synthetic_cti.json`
- **Notice**: All demo nodes contain `is_synthetic: true`.
