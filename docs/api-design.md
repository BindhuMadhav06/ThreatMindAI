# ThreatMind API Specification

## Base URL
`http://localhost:8000/api/v1`

---

## Health & System

### `GET /health`
Returns backend health status, Neo4j connectivity, and active LLM configuration.

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "neo4j_connected": true,
  "llm_provider": "gemini",
  "version": "1.0.0"
}
```

---

## Intelligence & Multi-Hop Query Engine

### `POST /query`
Performs natural language CTI analysis, entity matching, multi-hop Cypher traversal, GraphRAG retrieval, evidence aggregation, and grounded LLM answer generation.

**Request Body**:
```json
{
  "question": "How does APT29 attack systems?",
  "max_hops": 3,
  "min_confidence": 0.7
}
```

**Response `200 OK`**:
```json
{
  "question": "How does APT29 attack systems?",
  "answer": "APT29 (Cozy Bear) utilizes Cobalt Strike malware to execute attack techniques such as PowerShell (T1059.001) to exploit vulnerabilities in affected products...",
  "graph_path": [
    {
      "source": "APT29",
      "source_type": "ThreatActor",
      "relationship": "USES",
      "target": "Cobalt Strike",
      "target_type": "Malware"
    },
    {
      "source": "Cobalt Strike",
      "source_type": "Malware",
      "relationship": "IMPLEMENTS",
      "target": "PowerShell (T1059.001)",
      "target_type": "Technique"
    }
  ],
  "evidence": [
    {
      "claim": "APT29 uses Cobalt Strike for persistence and execution.",
      "source_id": "source_001",
      "source_title": "MITRE ATT&CK APT29 Group Report",
      "url": "https://attack.mitre.org/groups/G0016/",
      "evidence_text": "APT29 has executed Cobalt Strike Beacon payloads during operations."
    }
  ],
  "sources": [
    {
      "id": "source_001",
      "title": "MITRE ATT&CK APT29 Group Report",
      "publisher": "MITRE",
      "published_date": "2023-09-01",
      "url": "https://attack.mitre.org/groups/G0016/"
    }
  ],
  "warnings": []
}
```

---

## Knowledge Graph Exploration

### `GET /graph/entity/{id}`
Fetches node details and immediate 1-hop connections.

### `GET /graph/neighbors/{id}?depth=2`
Retrieves multi-hop neighborhood graph centered at a specified node ID for Cytoscape visualization.

### `GET /threat-actors`
Returns list of threat actors with pagination.

### `GET /malware`
Returns list of malware entities.

### `GET /vulnerabilities`
Returns list of CVE vulnerabilities.

### `GET /techniques`
Returns list of MITRE ATT&CK techniques.

### `GET /sources`
Returns list of registered CTI sources.

---

## CTI Ingestion & Graph Construction

### `POST /ingestion`
Uploads CTI documents (PDF, JSON, CSV, HTML, TXT) for parsing and structured extraction.

### `POST /graph/build`
Triggers entity normalization and idempotent Neo4j graph population from ingested sources.

### `GET /investigations/{id}`
Retrieves historical investigation records by ID.
