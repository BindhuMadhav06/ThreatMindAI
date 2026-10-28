import React, { useState, useRef } from 'react';
import { AnswerResponse, AnswerCitation, AnswerRequest, DefensiveResponse } from '../types/api';
import { askQuestion } from '../api/investigations';
import { getDefensesBatch } from '../api/defense';
import { parseApiError } from '../api/client';
import { QuestionInput } from '../components/investigation/QuestionInput';
import { AnswerCard } from '../components/investigation/AnswerCard';
import { ClaimsList } from '../components/investigation/ClaimsList';
import { PathViewer } from '../components/investigation/PathViewer';
import { CytoscapeGraph } from '../components/graph/CytoscapeGraph';
import { CitationDrawer } from '../components/evidence/CitationDrawer';
import { DefensesPanel } from '../components/defense/DefensesPanel';
import { VulnerabilityCard } from '../components/vulnerability/VulnerabilityCard';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { AlertCircle, Network, Bug, CheckCircle, Info } from 'lucide-react';

interface InvestigationPageProps {
  initialQuery?: string | null;
}

export interface ExtractedCveItem {
  cveId: string;
  isGraphVerified: boolean;
  sourcePathIds: string[];
}

export interface ExtractedTechniqueItem {
  techniqueId: string;
  isGraphVerified: boolean;
  sourcePathIds: string[];
}

function isValidAttackId(id: string): boolean {
  // Enterprise ATT&CK techniques follow T1000..T1999 format (e.g. T1059, T1059.001)
  return /^T1\d{3}(?:\.\d{3})?$/i.test(id);
}

function extractTechniquesAndCves(data: AnswerResponse): {
  techniques: ExtractedTechniqueItem[];
  cves: ExtractedCveItem[];
} {
  const cveMap = new Map<string, { isGraphVerified: boolean; sourcePathIds: Set<string> }>();
  const techMap = new Map<string, { isGraphVerified: boolean; sourcePathIds: Set<string> }>();

  const cveRegex = /CVE-\d{4}-\d{4,7}/gi;
  const techRegex = /\bT1\d{3}(?:\.\d{3})?\b/gi;

  const addCve = (id: string, verified: boolean, pathId?: string) => {
    const norm = id.toUpperCase();
    if (!cveMap.has(norm)) {
      cveMap.set(norm, { isGraphVerified: verified, sourcePathIds: new Set() });
    }
    const entry = cveMap.get(norm)!;
    if (verified) entry.isGraphVerified = true;
    if (pathId) entry.sourcePathIds.add(pathId);
  };

  const addTech = (id: string, verified: boolean, pathId?: string) => {
    const norm = id.toUpperCase();
    if (!isValidAttackId(norm)) return;
    if (!techMap.has(norm)) {
      techMap.set(norm, { isGraphVerified: verified, sourcePathIds: new Set() });
    }
    const entry = techMap.get(norm)!;
    if (verified) entry.isGraphVerified = true;
    if (pathId) entry.sourcePathIds.add(pathId);
  };

  const nameToIdMap: Record<string, string> = {
    powershell: 'T1059.001',
    'command and scripting interpreter': 'T1059',
    'valid accounts': 'T1078',
    'process injection': 'T1055',
    'exploit public-facing application': 'T1190',
    'data destruction': 'T1485',
    'archive collected data': 'T1560',
    'network denial of service': 'T1498',
    'web shell': 'T1505.003',
    'os credential dumping': 'T1003',
    mimikatz: 'T1003',
    'credential dumper': 'T1003',
  };

  // 1. Extract from verified Cypher reasoning paths (verified graph edges)
  if (data.graph_paths) {
    for (const path of data.graph_paths) {
      if (path.steps) {
        for (const step of path.steps) {
          if (step.source_label === 'Vulnerability') {
            const mId = (step.source_id || '').match(cveRegex);
            if (mId) mId.forEach((c) => addCve(c, true, path.path_id));
            const mName = (step.source_name || '').match(cveRegex);
            if (mName) mName.forEach((c) => addCve(c, true, path.path_id));
          }
          if (step.source_label === 'Technique') {
            if (step.source_id.startsWith('tech_t')) {
              const t = step.source_id.replace('tech_t', 'T').replace('_', '.');
              addTech(t, true, path.path_id);
            }
            const mId = (step.source_id || '').match(techRegex);
            if (mId) mId.forEach((x) => addTech(x, true, path.path_id));
            const mName = (step.source_name || '').match(techRegex);
            if (mName) mName.forEach((x) => addTech(x, true, path.path_id));
            const mapped = nameToIdMap[(step.source_name || '').toLowerCase()];
            if (mapped) addTech(mapped, true, path.path_id);
          }

          if (step.target_label === 'Vulnerability') {
            const mId = (step.target_id || '').match(cveRegex);
            if (mId) mId.forEach((c) => addCve(c, true, path.path_id));
            const mName = (step.target_name || '').match(cveRegex);
            if (mName) mName.forEach((c) => addCve(c, true, path.path_id));
          }
          if (step.target_label === 'Technique') {
            if (step.target_id.startsWith('tech_t')) {
              const t = step.target_id.replace('tech_t', 'T').replace('_', '.');
              addTech(t, true, path.path_id);
            }
            const mId = (step.target_id || '').match(techRegex);
            if (mId) mId.forEach((x) => addTech(x, true, path.path_id));
            const mName = (step.target_name || '').match(techRegex);
            if (mName) mName.forEach((x) => addTech(x, true, path.path_id));
            const mapped = nameToIdMap[(step.target_name || '').toLowerCase()];
            if (mapped) addTech(mapped, true, path.path_id);
          }
        }
      }
    }
  }

  // 2. Extract from verified citations
  if (data.citations) {
    for (const cit of data.citations) {
      const rel = cit.supported_relationship || '';
      const cveM = rel.match(cveRegex);
      if (cveM) cveM.forEach((c) => addCve(c, true));
      const techM = rel.match(techRegex);
      if (techM) techM.forEach((t) => addTech(t, true));
    }
  }

  // 3. Scan query and narrative text (mark as unverified narrative reference if not found in graph)
  const textToScan = `${data.original_question} ${data.answer.direct_answer} ${data.answer.summary}`;
  const cveMatches = textToScan.match(cveRegex);
  if (cveMatches) {
    cveMatches.forEach((c) => addCve(c, false));
  }

  const techMatches = textToScan.match(techRegex);
  if (techMatches) {
    techMatches.forEach((t) => addTech(t, false));
  }

  const lowerText = textToScan.toLowerCase();
  for (const [name, id] of Object.entries(nameToIdMap)) {
    if (lowerText.includes(name)) {
      addTech(id, false);
    }
  }

  return {
    techniques: Array.from(techMap.entries()).map(([techniqueId, info]) => ({
      techniqueId,
      isGraphVerified: info.isGraphVerified,
      sourcePathIds: Array.from(info.sourcePathIds),
    })),
    cves: Array.from(cveMap.entries()).map(([cveId, info]) => ({
      cveId,
      isGraphVerified: info.isGraphVerified,
      sourcePathIds: Array.from(info.sourcePathIds),
    })),
  };
}

export const InvestigationPage: React.FC<InvestigationPageProps> = ({ initialQuery }) => {
  const [response, setResponse] = useState<AnswerResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedCitation, setSelectedCitation] = useState<AnswerCitation | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);

  // Phase 11.0 states
  const [defenseData, setDefenseData] = useState<DefensiveResponse | null>(null);
  const [loadingDefenses, setLoadingDefenses] = useState(false);
  const [defenseError, setDefenseError] = useState<string | null>(null);
  const [detectedCves, setDetectedCves] = useState<ExtractedCveItem[]>([]);
  const [groundedTechniqueIds, setGroundedTechniqueIds] = useState<string[]>([]);

  const abortControllerRef = useRef<AbortController | null>(null);

  const handleInvestigate = async (
    question: string,
    options?: { maxDepth?: number; maxPaths?: number; hints?: string[] }
  ) => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setLoading(true);
    setError(null);
    setSelectedPathId(null);
    setDefenseData(null);
    setDefenseError(null);
    setDetectedCves([]);
    setGroundedTechniqueIds([]);

    const requestPayload: AnswerRequest = {
      question,
      max_depth: options?.maxDepth ?? 3,
      max_paths: options?.maxPaths ?? 10,
      entity_hints: options?.hints,
    };

    try {
      const data = await askQuestion(requestPayload, controller.signal);
      setResponse(data);

      // Phase 11.0: Extract techniques and CVEs preserving explicit graph grounding vs narrative origin
      const { techniques, cves } = extractTechniquesAndCves(data);
      setDetectedCves(cves);
      const verifiedTechs = techniques.filter((t) => t.isGraphVerified).map((t) => t.techniqueId);
      setGroundedTechniqueIds(verifiedTechs);

      const techIds = techniques.map((t) => t.techniqueId);
      if (techIds.length > 0) {
        setLoadingDefenses(true);
        setDefenseError(null);
        try {
          const defenses = await getDefensesBatch(techIds, controller.signal);
          setDefenseData(defenses);
        } catch (dErr) {
          setDefenseError(parseApiError(dErr));
        } finally {
          setLoadingDefenses(false);
        }
      }

      // Save to local session history
      try {
        const stored = sessionStorage.getItem('tm_recent_queries');
        const history: string[] = stored ? JSON.parse(stored) : [];
        if (!history.includes(question)) {
          const updated = [question, ...history].slice(0, 10);
          sessionStorage.setItem('tm_recent_queries', JSON.stringify(updated));
        }
      } catch {
        // Ignore session storage error
      }
    } catch (err) {
      setError(parseApiError(err));
    } finally {
      setLoading(false);
      abortControllerRef.current = null;
    }
  };

  const handleCancel = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setLoading(false);
      setError('Investigation cancelled by analyst.');
    }
  };

  const handleSelectCitation = (citationId: string) => {
    if (!response) return;
    const found = response.citations.find((c) => c.citation_id === citationId);
    if (found) {
      setSelectedCitation(found);
      setIsDrawerOpen(true);
    }
  };

  return (
    <div className="space-y-6">
      {/* Search Input Box */}
      <QuestionInput
        onSubmit={handleInvestigate}
        onCancel={handleCancel}
        loading={loading}
      />

      {/* Loading Indicator */}
      {loading && (
        <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl">
          <LoadingSpinner size="lg" label="Traversing Knowledge Graph & Generating Evidence-Grounded Answer..." />
          <p className="text-xs text-slate-500 mt-2 font-mono">
            Evaluating multi-hop Cypher paths, validating citations, and running strict grounding checks
          </p>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-900/80 text-rose-300 text-xs flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <h4 className="font-semibold text-rose-200">Investigation Error</h4>
            <p className="mt-0.5 leading-relaxed">{error}</p>
          </div>
        </div>
      )}

      {/* Answer & Graph Visualization */}
      {response && !loading && (
        <div className="space-y-6">
          {/* Main Answer Card */}
          <AnswerCard
            answer={response.answer}
            groundingStatus={response.grounding_status}
            warnings={response.warnings}
            unresolvedEntities={response.unresolved_entities}
            onSelectCitation={handleSelectCitation}
          />

          {/* Phase 11.0: Sourced Vulnerability Intelligence Cards */}
          {detectedCves.length > 0 && (
            <div className="space-y-3">
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Bug className="w-4 h-4 text-rose-400" />
                  Sourced Vulnerability Intelligence ({detectedCves.length} Referenced)
                </h3>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  Operational vulnerability risk metrics (CVSS, EPSS, CISA KEV). Sourced intelligence scores provide contextual risk and do not upgrade narrative text mentions into verified graph facts.
                </p>
              </div>
              <div className="space-y-4">
                {detectedCves.map((item) => (
                  <div key={item.cveId} className="space-y-1.5">
                    <div className="flex items-center justify-between px-1">
                      {item.isGraphVerified ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-950/80 border border-emerald-800 text-emerald-300">
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                          Evidence Grounding: Verified Knowledge Graph Entity
                          {item.sourcePathIds.length > 0 && ` (Path: ${item.sourcePathIds.join(', ')})`}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-950/80 border border-amber-800 text-amber-300">
                          <Info className="w-3.5 h-3.5 text-amber-400" />
                          Evidence Grounding: Narrative / Query Reference (Not established as graph edge)
                        </span>
                      )}
                    </div>
                    <VulnerabilityCard cveId={item.cveId} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Phase 11.0: Recommended Defenses Panel (MITRE D3FEND) */}
          {(defenseData || loadingDefenses || defenseError) && (
            <DefensesPanel
              defenseData={defenseData}
              loading={loadingDefenses}
              error={defenseError}
              groundedTechniqueIds={groundedTechniqueIds}
            />
          )}

          {/* Interactive Knowledge Graph Canvas */}
          {response.graph_paths && response.graph_paths.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Network className="w-4 h-4 text-cyan-400" />
                  Visual Investigation Knowledge Graph
                </h3>
                {selectedPathId && (
                  <span className="text-xs text-cyan-400 font-mono">
                    Highlighting Path: {selectedPathId}
                  </span>
                )}
              </div>
              <CytoscapeGraph
                paths={response.graph_paths}
                selectedPathId={selectedPathId}
                height="450px"
              />
            </div>
          )}

          {/* Reasoning Paths Viewer */}
          {response.graph_paths && response.graph_paths.length > 0 && (
            <PathViewer
              paths={response.graph_paths}
              selectedPathId={selectedPathId}
              onSelectPath={(pathId) =>
                setSelectedPathId((prev) => (prev === pathId ? null : pathId))
              }
            />
          )}

          {/* Granular Claim Provenance Inspector */}
          {response.claims && response.claims.length > 0 && (
            <ClaimsList
              claims={response.claims}
              onSelectCitation={handleSelectCitation}
            />
          )}
        </div>
      )}

      {/* Evidence Slide-out Drawer */}
      <CitationDrawer
        citation={selectedCitation}
        isOpen={isDrawerOpen}
        onClose={() => setIsDrawerOpen(false)}
      />
    </div>
  );
};
