export interface SystemHealth {
  status: string;
  project: string;
  version: string;
  environment: string;
  neo4j_connected: boolean;
  llm_provider: string;
  llm_available: boolean;
}

export interface GraphStats {
  total_nodes: number;
  total_relationships: number;
  total_sources: number;
  node_counts_by_label: Record<string, number>;
}

export interface EntitySummary {
  id: string;
  label: string;
  name: string;
  description?: string | null;
  aliases?: string[];
  is_synthetic: boolean;
  properties?: Record<string, any>;
}

export interface NeighborEdge {
  source_id: string;
  source_name: string;
  source_label: string;
  rel_type: string;
  target_id: string;
  target_name: string;
  target_label: string;
  provenance: Record<string, any>;
  is_synthetic: boolean;
}

export interface EntityDetail {
  entity: EntitySummary;
  neighbors: EntitySummary[];
  relationships: NeighborEdge[];
}

export interface AnswerRequest {
  question: string;
  entity_hints?: string[];
  max_depth?: number;
  max_paths?: number;
  min_confidence?: number;
}

export interface AnswerClaim {
  claim_text: string;
  evidence_references: string[];
  claim_type: string;
  verification_status: 'verified' | 'unverified';
  validation_reasons: string[];
}

export interface AnswerCitation {
  citation_id: string;
  evidence_id: string;
  source_id: string;
  source_title?: string | null;
  source_url?: string | null;
  publisher?: string | null;
  published_date?: string | null;
  evidence_text: string;
  supported_relationship: string;
  confidence?: number | null;
  is_synthetic: boolean;
}

export interface ReasoningStep {
  step_number: number;
  source_id: string;
  source_label: string;
  source_name: string;
  rel_type: string;
  target_id: string;
  target_label: string;
  target_name: string;
  evidence_records?: Array<{
    source_id: string;
    source_title?: string | null;
    source_url?: string | null;
    publisher?: string | null;
    published_date?: string | null;
    evidence_text: string;
    relationship: string;
    confidence?: number | null;
  }>;
  is_valid: boolean;
  validation_notes?: string[];
}

export interface EvidenceBackedPath {
  path_id: string;
  steps: ReasoningStep[];
  length: number;
  is_complete: boolean;
  is_valid: boolean;
  relevance_score: number;
  template_applied?: string | null;
  semantic_caveats: string[];
}

export interface GroundedAnswer {
  summary: string;
  direct_answer: string;
  claims: AnswerClaim[];
  citations: AnswerCitation[];
  referenced_paths: string[];
  caveats: string[];
  sufficiency_status: 'sufficient' | 'partial' | 'insufficient';
  is_synthetic: boolean;
}

export type GroundingStatus = 'fully_grounded' | 'partially_grounded' | 'insufficient_evidence' | 'unsupported';

export interface AnswerResponse {
  original_question: string;
  answer: GroundedAnswer;
  claims: AnswerClaim[];
  citations: AnswerCitation[];
  graph_paths: EvidenceBackedPath[];
  unresolved_entities: string[];
  warnings: string[];
  grounding_status: GroundingStatus;
  statistics: Record<string, any>;
}

export interface IngestionResponse {
  source_id: string;
  title: string;
  chunks_count: number;
  entities_extracted: number;
  relationships_extracted: number;
  relationships_accepted: number;
  relationships_rejected: number;
  warnings: string[];
  status: string;
}

export interface CytoscapeNodeData {
  id: string;
  label: string;
  name: string;
  is_synthetic?: boolean;
  type?: string;
}

export interface CytoscapeEdgeData {
  id: string;
  source: string;
  target: string;
  label: string;
  path_id?: string;
  is_synthetic?: boolean;
  evidence_text?: string;
  source_id?: string;
}

// -------------------------------------------------------------
// Phase 11.0: MITRE D3FEND & Vulnerability Intelligence Types
// -------------------------------------------------------------

export type D3fendTactic = 'Model' | 'Harden' | 'Detect' | 'Isolate' | 'Deceive' | 'Evict' | 'Restore';

export type ApplicabilityClassification =
  | 'officially_mapped'
  | 'potentially_relevant'
  | 'requires_environment_review';

export interface D3fendCountermeasure {
  id: string;
  name: string;
  tactic: D3fendTactic;
  definition: string;
  official_url?: string | null;
}

export interface DefensiveRecommendation {
  original_framework_id: string;
  attack_technique_id: string;
  attack_technique_name: string;
  mitigation_id?: string | null;
  mitigation_name?: string | null;
  mapping_relationship: string;
  mapping_direction: string;
  countermeasure: D3fendCountermeasure;
  applicability: ApplicabilityClassification;
  mapping_provenance: string;
  source_version: string;
  retrieval_date: string;
  rationale: string;
  environment_limitations: string;
}

export interface DefensiveResponse {
  target_techniques: string[];
  recommendations: DefensiveRecommendation[];
  summary_by_tactic: Record<string, number>;
  summary_by_applicability: Record<string, number>;
  catalog_version: string;
  snapshot_date: string;
  catalog_sha256: string;
  disclaimer: string;
}

export type DataProvenance = 'live' | 'cached' | 'offline_fixture' | 'mixed' | 'unavailable';
export type FreshnessState = 'fresh' | 'stale' | 'partial' | 'unavailable';
export type KevState = 'Listed' | 'Not listed' | 'Unable to verify';
export type CvssSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'None' | 'Unavailable';

export interface CvssIntel {
  version?: string | null;
  base_score?: number | null;
  vector_string?: string | null;
  severity: CvssSeverity;
  source: string;
  provenance: DataProvenance;
  freshness: FreshnessState;
  retrieved_at?: string | null;
  data_as_of?: string | null;
  source_updated_at?: string | null;
  source_url?: string | null;
  retrieval_status: string;
}

export interface EpssIntel {
  probability?: number | null;
  probability_percentage?: string | null;
  percentile?: number | null;
  score_date?: string | null;
  model_version?: string | null;
  api_version?: string | null;
  provenance: DataProvenance;
  freshness: FreshnessState;
  retrieved_at?: string | null;
  data_as_of?: string | null;
  source_url?: string | null;
  definition: string;
  retrieval_status: string;
}

export interface CisaKevIntel {
  status: KevState;
  date_added?: string | null;
  due_date?: string | null;
  known_ransomware_campaign_use?: string | null;
  notes?: string | null;
  catalog_source: string;
  catalog_snapshot_date?: string | null;
  is_stale_assertion?: boolean;
  provenance: DataProvenance;
  freshness: FreshnessState;
  retrieved_at?: string | null;
  data_as_of?: string | null;
  source_url?: string | null;
}

export interface VulnerabilityIntelResponse {
  cve_id: string;
  title?: string | null;
  description?: string | null;
  provenance: DataProvenance;
  provenance_by_source: Record<string, DataProvenance>;
  freshness: FreshnessState;
  freshness_by_source: Record<string, FreshnessState>;
  as_of_date?: string | null;
  last_retrieved_at: string;
  cvss: CvssIntel;
  epss: EpssIntel;
  cisa_kev: CisaKevIntel;
  source_urls: string[];
  disclaimer: string;
}

