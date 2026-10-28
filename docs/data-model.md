# ThreatMind Data Model & Graph Schema

## Core Node Definitions

ThreatMind uses Neo4j property graphs to represent cybersecurity entities and their relationships. Every node includes standard metadata property fields (`id`, `created_at`, `updated_at`).

### 1. Primary Entity Nodes

#### `ThreatActor`
- `id`: String (Unique identifier, e.g., `actor_apt29`)
- `name`: String (Canonical name, e.g., `APT29`)
- `aliases`: List[String] (e.g., `["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"]`)
- `description`: String
- `first_seen`: String / Date
- `country`: String

#### `Malware`
- `id`: String (e.g., `malware_cobaltstrike`)
- `name`: String (e.g., `Cobalt Strike`)
- `aliases`: List[String] (e.g., `["Beacon"]`)
- `type`: String (e.g., `Ransomware`, `Trojan`, `C2 Framework`)
- `description`: String

#### `Tool`
- `id`: String (e.g., `tool_mimikatz`)
- `name`: String (e.g., `Mimikatz`)
- `aliases`: List[String]
- `description`: String

#### `Technique`
- `id`: String (e.g., `tech_t1059_001`)
- `attack_id`: String (Unique MITRE ID, e.g., `T1059.001`)
- `name`: String (e.g., `PowerShell`)
- `description`: String
- `detection`: String

#### `Tactic`
- `id`: String (e.g., `tactic_ta0002`)
- `attack_id`: String (e.g., `TA0002`)
- `name`: String (e.g., `Execution`)
- `description`: String

#### `Vulnerability`
- `id`: String (e.g., `vuln_cve_2021_44228`)
- `cve_id`: String (Unique identifier, e.g., `CVE-2021-44228`)
- `description`: String
- `cvss_score`: Float
- `severity`: String (e.g., `CRITICAL`)

#### `Product`
- `id`: String (e.g., `prod_log4j`)
- `name`: String (e.g., `Apache Log4j`)
- `vendor`: String (e.g., `Apache`)
- `version`: String

#### `OperatingSystem`
- `id`: String (e.g., `os_windows_10`)
- `name`: String (e.g., `Windows 10`)
- `platform`: String (e.g., `Windows`)

#### `Organization` / `Target`
- `id`: String (e.g., `org_government`)
- `name`: String (e.g., `Government Sector`)
- `industry`: String

#### `Campaign`
- `id`: String (e.g., `camp_solarwinds`)
- `name`: String (e.g., `SolarWinds Supply Chain Attack`)
- `timeline`: String

#### `Indicator`
- `id`: String (e.g., `ioc_hash_12345`)
- `type`: String (e.g., `SHA256`, `IPv4`, `Domain`)
- `value`: String (e.g., `4a5e...`)

#### `Source`
- `id`: String (e.g., `source_mitre_apt29`)
- `title`: String
- `url`: String
- `publisher`: String
- `published_date`: String
- `raw_content`: String

---

## Relationships & Provenance Schema

All edges between entity nodes represent verified cyber threat intelligence relations. Each relationship carries mandatory provenance metadata.

### Edge Provenance Properties
- `source_id`: String (Refers to `Source.id`)
- `source_url`: String
- `evidence_text`: String (Exact text quote supporting this link)
- `confidence`: Float (0.0 to 1.0)
- `extraction_method`: String (e.g., `llm_extraction`, `mitre_stix_import`, `manual_rule`)

### Supported Relationship Types
1. `(:ThreatActor)-[:USES {provenance}]->(:Malware)`
2. `(:ThreatActor)-[:USES {provenance}]->(:Tool)`
3. `(:ThreatActor)-[:USES_TECHNIQUE {provenance}]->(:Technique)`
4. `(:ThreatActor)-[:EXPLOITS {provenance}]->(:Vulnerability)`
5. `(:ThreatActor)-[:TARGETS {provenance}]->(:Organization)`
6. `(:ThreatActor)-[:ATTRIBUTED_TO {provenance}]->(:Campaign)`
7. `(:Malware)-[:IMPLEMENTS {provenance}]->(:Technique)`
8. `(:Tool)-[:IMPLEMENTS {provenance}]->(:Technique)`
9. `(:Technique)-[:PART_OF]->(:Tactic)`
10. `(:Technique)-[:EXPLOITS {provenance}]->(:Vulnerability)`
11. `(:Vulnerability)-[:AFFECTS {provenance}]->(:Product)`
12. `(:Vulnerability)-[:AFFECTS {provenance}]->(:OperatingSystem)`
13. `(:Entity)-[:SUPPORTED_BY]->(:Source)`

---

## Neo4j Constraints & Indexes

To ensure idempotency and optimal query execution:

```cypher
// Unique Constraints
CREATE CONSTRAINT threat_actor_id IF NOT EXISTS FOR (n:ThreatActor) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT malware_id IF NOT EXISTS FOR (n:Malware) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT tool_id IF NOT EXISTS FOR (n:Tool) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT technique_attack_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT vuln_cve_id IF NOT EXISTS FOR (n:Vulnerability) REQUIRE n.cve_id IS UNIQUE;
CREATE CONSTRAINT source_id IF NOT EXISTS FOR (n:Source) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT product_id IF NOT EXISTS FOR (n:Product) REQUIRE n.id IS UNIQUE;

// Indexes
CREATE INDEX threat_actor_name_idx IF NOT EXISTS FOR (n:ThreatActor) ON (n.name);
CREATE INDEX malware_name_idx IF NOT EXISTS FOR (n:Malware) ON (n.name);
CREATE INDEX technique_name_idx IF NOT EXISTS FOR (n:Technique) ON (n.name);
CREATE INDEX source_url_idx IF NOT EXISTS FOR (n:Source) ON (n.url);
```
