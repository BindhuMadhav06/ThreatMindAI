# ThreatMind CTI Ingestion Pipeline & Evidence Validation Architecture

## 1. Executive Summary

The ThreatMind CTI Ingestion Pipeline transforms raw, multi-format cyber threat intelligence documents (PDF, HTML, JSON, TXT) into evidence-grounded Neo4j knowledge graph nodes and provenance-backed relationship edges.

### Core Principle
**NO UNGROUNDED RELATIONSHIPS**: If an extracted relationship cannot be verified against exact supporting source text from the document, it is **strictly rejected** and excluded from graph persistence.

---

## 2. Ingestion Pipeline Stages

```
                          CTI INGESTION PIPELINE
                                    │
                              [CTI Source]
                                    │
                                    ▼
                         1. Document Acquisition
                        (PDF / HTML / JSON / TXT)
                                    │
                                    ▼
                         2. Document Parsing
                 (PyMuPDF / BeautifulSoup / JSON Loader)
                                    │
                                    ▼
                         3. Text Cleaning & Chunking
                   (Paragraph Chunker ~250 words/chunk)
                                    │
                                    ▼
                         4. Structured Extraction
                 (LLM Entity & Relationship Extractors)
                                    │
                                    ▼
                         5. Deterministic Normalization
               (CVE format, MITRE technique IDs, Aliases)
                                    │
                                    ▼
                         6. Evidence Validation Layer
                 (Grounding Verification & Whitelists)
                                    │
                                    ├── Rejections logged & discarded
                                    ▼
                         7. Neo4j Idempotent Persistence
                  (MERGE Nodes, Edges & Edge Provenance)
```

---

## 3. Stage Specifications

### Stage 1: Document Acquisition & Parsing (`loaders.py`)
- **PDF**: Text extracted using PyMuPDF (`fitz`).
- **HTML**: Strips scripts, styles, noscript, and executable elements using `BeautifulSoup`.
- **JSON**: Extracts structured CTI fields (`content`, `title`, `publisher`, `published_date`).
- **TXT**: Plain text reader.
- **Source Identification**: Generates a stable `source_id` (SHA-256 digest of header/content).

### Stage 2: Text Cleaning & Semantic Chunking (`chunker.py`)
- Removes control characters and weird unicode spacing.
- Groups text into semantic paragraph chunks targetting ~250 words per chunk to maintain LLM extraction context.

### Stage 3: Entity & Relationship Extraction (`entity_extractor.py`, `relation_extractor.py`)
- Decoupled from specific LLM providers via `BaseLLMProvider`.
- Uses Pydantic JSON schemas for structured extraction.
- **Mandatory Quote Requirement**: Every relationship extraction request requires the LLM to output the verbatim `evidence_text` quote from the chunk.

### Stage 4: Deterministic Normalization (`normalizer.py`)
- Standardizes CVE identifiers to `CVE-YYYY-NNNN` (e.g. `CVE-2021-44228`).
- Standardizes MITRE ATT&CK technique IDs to `TXXXX.NNN` (e.g. `T1059.001`).
- Resolves known threat actor aliases (`Cozy Bear` -> `APT29`) and malware names (`Beacon` -> `Cobalt Strike`).

### Stage 5: Evidence Validation Layer (`validator.py`)
Enforces strict quality controls before database insertion:
1. **Empty Evidence Check**: Rejects relationships where `evidence_text` is missing or empty.
2. **Document Grounding Match**: Searches for the normalized `evidence_text` quote within the raw document text. If not present, rejects the relationship as an LLM hallucination.
3. **Label Whitelist**: Ensures source and target labels belong to the 13 `PRIMARY_NODE_LABELS`.
4. **Relationship Vocabulary**: Ensures relationship type belongs to `SUPPORTED_RELATIONSHIPS`.

### Stage 6: Neo4j Idempotent Persistence (`pipeline.py`, `repository.py`)
- Executes Cypher `MERGE` queries to prevent duplicate node creation.
- Attaches provenance metadata (`source_id`, `source_url`, `evidence_text`, `published_date`, `extraction_method`, `confidence`) directly to edge properties.
- Connects entities to the `Source` node via `SUPPORTED_BY` edges.

---

## 4. REST API Endpoint

### `POST /api/v1/ingestion`
Ingests a CTI advisory via file upload or text payload.

**Response `200 OK`**:
```json
{
  "source_id": "source_7a8b9c0d1e2f",
  "title": "CISA Advisory: APT29 Operations",
  "chunks_count": 3,
  "entities_extracted": 5,
  "relationships_extracted": 3,
  "relationships_accepted": 2,
  "relationships_rejected": 1,
  "warnings": [
    "REJECTED: Evidence text 'APT29 used WannaCry' was not found in source document text."
  ],
  "status": "success"
}
```
