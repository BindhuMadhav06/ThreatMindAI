import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Clock,
  Fingerprint,
  FileCheck2,
  CheckCircle2,
  XCircle,
  HelpCircle,
  RefreshCw,
} from 'lucide-react';

interface ClaimItem {
  id: string;
  subject: string;
  predicate: string;
  object: string;
  doc_id: string;
  doc_sha256: string;
  offset_start: number;
  offset_end: number;
  quoted_evidence: string;
  confidence: number;
  validation_state: 'verified' | 'supported_unverified' | 'disputed' | 'rejected';
}

interface DisputeItem {
  id: string;
  type: string;
  subject: string;
  claim_a: { id: string; value: string; source: string };
  claim_b: { id: string; value: string; source: string };
  status: 'open' | 'analyst_resolved';
  resolved_favored?: string;
  resolution_rationale?: string;
}

export const IntelligenceQualityPanel: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'claims' | 'disputes' | 'freshness' | 'sources' | 'dedup'>('claims');

  // Sample raw document
  const rawDocument = "Mandiant APT29 intelligence bulletin: The threat actor APT29 was observed executing PowerShell scripts to drop Cobalt Strike beacons across targeted enterprise systems.";
  
  // Sample claims
  const [claims, setClaims] = useState<ClaimItem[]>([
    {
      id: "claim_001",
      subject: "APT29",
      predicate: "USES",
      object: "Cobalt Strike",
      doc_id: "doc_mnd_2026_01",
      doc_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      offset_start: 38,
      offset_end: 119,
      quoted_evidence: "APT29 was observed executing PowerShell scripts to drop Cobalt Strike beacons",
      confidence: 0.94,
      validation_state: "verified"
    },
    {
      id: "claim_002",
      subject: "FIN7",
      predicate: "USES",
      object: "Cobalt Strike",
      doc_id: "doc_crowd_2026_04",
      doc_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      offset_start: 10,
      offset_end: 75,
      quoted_evidence: "FIN7 leveraged customized Cobalt Strike loaders during financial intrusion",
      confidence: 0.82,
      validation_state: "supported_unverified"
    }
  ]);

  // Disputes state
  const [disputes, setDisputes] = useState<DisputeItem[]>([
    {
      id: "disp_001",
      type: "ATTRIBUTION_DISPUTE",
      subject: "Campaign Operation SolarWorm",
      claim_a: { id: "claim_001", value: "APT29", source: "Mandiant" },
      claim_b: { id: "claim_002", value: "FIN7", source: "External Forum" },
      status: "open"
    }
  ]);

  const [selectedDispute, setSelectedDispute] = useState<DisputeItem | null>(null);
  const [resolutionRationale, setResolutionRationale] = useState("");

  // Freshness calculation state
  const [entityType, setEntityType] = useState("ipv4");
  const [ageDays, setAgeDays] = useState(30);

  const halfLifeMap: Record<string, number> = {
    ipv4: 14,
    domain: 60,
    url: 7,
    file_hash: 365,
    vulnerability: 730
  };

  const currentHalfLife = halfLifeMap[entityType] || 14;
  const freshnessScore = Math.pow(2, -ageDays / currentHalfLife);
  const isStale = ageDays > currentHalfLife;

  const resolveDisputeAction = (favoredClaim: 'claim_a' | 'claim_b') => {
    if (!selectedDispute) return;
    const favoredId = favoredClaim === 'claim_a' ? selectedDispute.claim_a.id : selectedDispute.claim_b.id;
    const updatedDisputes = disputes.map(d => {
      if (d.id === selectedDispute.id) {
        return {
          ...d,
          status: 'analyst_resolved' as const,
          resolved_favored: favoredId,
          resolution_rationale: resolutionRationale || "Resolved based on authoritative telemetry corroboration."
        };
      }
      return d;
    });
    setDisputes(updatedDisputes);
    setSelectedDispute(null);
    setResolutionRationale("");
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-slate-100">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-8 h-8 text-cyan-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">ThreatMind Intelligence Quality Engine</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-900/40 text-cyan-400 border border-cyan-800">
              Phase 13
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Evidence-first grounding, immutable dispute ledgers, temporal decay modeling, and Bayesian calibration.
          </p>
        </div>
      </div>

      {/* Sub-Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveSubTab('claims')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'claims'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Grounding & Claim Offsets
        </button>
        <button
          onClick={() => setActiveSubTab('disputes')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'disputes'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Dispute Ledger ({disputes.filter(d => d.status === 'open').length} Open)
        </button>
        <button
          onClick={() => setActiveSubTab('freshness')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'freshness'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Temporal Freshness Decay
        </button>
        <button
          onClick={() => setActiveSubTab('sources')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'sources'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Source Reliability & Poisoning
        </button>
        <button
          onClick={() => setActiveSubTab('dedup')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeSubTab === 'dedup'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          SimHash Deduplication
        </button>
      </div>

      {/* Content Area */}
      {activeSubTab === 'claims' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Raw Source Document (Evidence Offset Highlighter)
            </h3>
            <div className="bg-slate-950 p-4 rounded border border-slate-800/80 font-mono text-sm leading-relaxed text-slate-300">
              {rawDocument.slice(0, 38)}
              <mark className="bg-cyan-900/60 text-cyan-200 px-1 py-0.5 rounded border border-cyan-500 font-semibold">
                {rawDocument.slice(38, 119)}
              </mark>
              {rawDocument.slice(119)}
            </div>
            <div className="mt-2 text-xs text-slate-400 flex items-center gap-2">
              <span className="font-mono text-cyan-400">[38:119]</span>
              <span>Exact 0-indexed character coordinates verified against SHA-256 digest</span>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
              <h3 className="text-sm font-semibold text-slate-200">Anchored Structured Claims</h3>
              <span className="text-xs text-slate-400">{claims.length} claims registered</span>
            </div>
            <div className="divide-y divide-slate-800">
              {claims.map((claim) => (
                <div key={claim.id} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-white">({claim.subject})</span>
                      <span className="text-cyan-400 text-xs font-mono">-[{claim.predicate}]-&gt;</span>
                      <span className="font-semibold text-white">({claim.object})</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                        claim.validation_state === 'verified' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
                      }`}>
                        {claim.validation_state}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 italic">"{claim.quoted_evidence}"</p>
                    <div className="text-[11px] text-slate-500 font-mono">
                      Doc SHA: {claim.doc_sha256.slice(0, 16)}... | Offsets: [{claim.offset_start}:{claim.offset_end}]
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <div className="text-xs text-slate-400">Bayesian Confidence</div>
                      <div className="text-sm font-bold text-cyan-400">{(claim.confidence * 100).toFixed(0)}%</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeSubTab === 'disputes' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Persistent Attribution Dispute Ledger
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Contradictions are stored immutably. When an analyst resolves a dispute, the favored claim is marked verified while the alternative is flagged as disputed without deleting either record.
            </p>
            <div className="space-y-4">
              {disputes.map((disp) => (
                <div key={disp.id} className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                      <span className="font-semibold text-white">{disp.subject}</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">
                        {disp.type}
                      </span>
                    </div>
                    <span className={`text-xs px-2.5 py-1 rounded font-semibold ${
                      disp.status === 'open' ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      {disp.status.toUpperCase()}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    <div className="p-3 rounded bg-slate-900 border border-slate-800">
                      <div className="text-slate-400">Claim A ({disp.claim_a.source}):</div>
                      <div className="text-cyan-300 font-bold text-sm mt-1">{disp.claim_a.value}</div>
                    </div>
                    <div className="p-3 rounded bg-slate-900 border border-slate-800">
                      <div className="text-slate-400">Claim B ({disp.claim_b.source}):</div>
                      <div className="text-rose-300 font-bold text-sm mt-1">{disp.claim_b.value}</div>
                    </div>
                  </div>

                  {disp.status === 'open' ? (
                    <div className="pt-2 flex justify-end">
                      <button
                        onClick={() => setSelectedDispute(disp)}
                        className="px-3 py-1.5 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white rounded transition"
                      >
                        Analyst Resolution Workflow
                      </button>
                    </div>
                  ) : (
                    <div className="text-xs text-slate-400 bg-slate-900/60 p-3 rounded border border-slate-800">
                      <span className="text-emerald-400 font-semibold">Resolved in favor of:</span> {disp.resolved_favored}<br />
                      <span className="text-slate-300">Rationale:</span> {disp.resolution_rationale}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {selectedDispute && (
            <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-lg w-full space-y-4">
                <h3 className="text-base font-bold text-white">Resolve Dispute: {selectedDispute.subject}</h3>
                <p className="text-xs text-slate-400">
                  Select which intelligence track is supported by enterprise ground truth. Both records will remain in the database.
                </p>
                <div className="space-y-2">
                  <label className="text-xs text-slate-300 font-semibold">Resolution Rationale</label>
                  <textarea
                    value={resolutionRationale}
                    onChange={(e) => setResolutionRationale(e.target.value)}
                    placeholder="Document corroborated forensic evidence or sandbox report ID..."
                    className="w-full h-20 bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setSelectedDispute(null)}
                    className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => resolveDisputeAction('claim_a')}
                    className="px-3 py-1.5 text-xs font-semibold bg-cyan-700 hover:bg-cyan-600 text-white rounded"
                  >
                    Favor Claim A ({selectedDispute.claim_a.value})
                  </button>
                  <button
                    onClick={() => resolveDisputeAction('claim_b')}
                    className="px-3 py-1.5 text-xs font-semibold bg-rose-700 hover:bg-rose-600 text-white rounded"
                  >
                    Favor Claim B ({selectedDispute.claim_b.value})
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {activeSubTab === 'freshness' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Temporal Freshness Decay Calculator
            </h3>
            <p className="text-xs text-slate-400">
              Formula: <code className="text-cyan-300">freshness(t) = 2^(-age / half_life)</code>. Freshness measures recency and decay; stale indicators flag warnings without being marked false.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-300">Entity Indicator Type</label>
                <select
                  value={entityType}
                  onChange={(e) => setEntityType(e.target.value)}
                  className="w-full mt-1 bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200"
                >
                  <option value="ipv4">IPv4 Address (Half-life: 14 days)</option>
                  <option value="domain">Domain Name (Half-life: 60 days)</option>
                  <option value="url">URL Path (Half-life: 7 days)</option>
                  <option value="file_hash">Cryptographic Hash (Half-life: 365 days)</option>
                  <option value="vulnerability">Vulnerability / CVE (Half-life: 730 days)</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-slate-300">Observation Age: {ageDays} days</label>
                <input
                  type="range"
                  min="1"
                  max="120"
                  value={ageDays}
                  onChange={(e) => setAgeDays(parseInt(e.target.value))}
                  className="w-full mt-2"
                />
              </div>
            </div>

            <div className="p-4 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-400">Calculated Freshness Score</div>
                <div className="text-2xl font-bold text-cyan-400">{(freshnessScore * 100).toFixed(1)}%</div>
                <div className="text-[11px] text-slate-500">Half-life threshold: {currentHalfLife} days</div>
              </div>
              <div>
                {isStale ? (
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-amber-950/80 border border-amber-800 text-amber-300 text-xs">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Stale Warning: Observation exceeds half-life.</span>
                  </div>
                ) : (
                  <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Active: Within current freshness horizon.</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeSubTab === 'sources' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Source Reliability & Feed Poisoning Detection
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Discounts circular corroboration and isolates anomalous feed bursts.
            </p>
            <div className="space-y-3">
              <div className="p-3 rounded bg-slate-950 border border-slate-800 flex justify-between items-center text-xs">
                <div>
                  <div className="font-semibold text-white">US-CERT / CISA Automated Feeds</div>
                  <div className="text-slate-500">Government CERT | Historical Accuracy: 98%</div>
                </div>
                <div className="text-emerald-400 font-bold">Reliability: 0.96</div>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800 flex justify-between items-center text-xs">
                <div>
                  <div className="font-semibold text-white">Commercial Threat Intelligence Syndicate A</div>
                  <div className="text-slate-500">Feed Overlap: 78% (Circular discount applied)</div>
                </div>
                <div className="text-cyan-400 font-bold">Reliability: 0.74</div>
              </div>
              <div className="p-3 rounded bg-rose-950/30 border border-rose-900/60 flex justify-between items-center text-xs">
                <div>
                  <div className="font-semibold text-rose-300 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span>Anomalous OSINT Ingestion Feed #14</span>
                  </div>
                  <div className="text-rose-400/80">Alert: Volume burst detected (1,450 synthetic indicators / 3 min)</div>
                </div>
                <span className="px-2 py-0.5 rounded bg-rose-900 text-rose-200 text-[10px] font-bold">
                  QUARANTINED
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeSubTab === 'dedup' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Multi-Tier Deduplication (SimHash & Jaccard)
            </h3>
            <p className="text-xs text-slate-400">
              Evaluates cryptographic digests, 64-bit locality-sensitive SimHash Hamming distance, and token Jaccard similarity to prevent syndication spam.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Tier 1: Cryptographic Digest</div>
                <div className="text-cyan-300 font-bold text-sm mt-1">SHA-256 Hash</div>
                <div className="text-slate-500 text-[11px] mt-1">Exact match detection</div>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Tier 2: Locality Sensitive</div>
                <div className="text-cyan-300 font-bold text-sm mt-1">64-bit SimHash</div>
                <div className="text-slate-500 text-[11px] mt-1">Hamming distance &le; 3</div>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Tier 3: Set Overlap</div>
                <div className="text-cyan-300 font-bold text-sm mt-1">Jaccard Index</div>
                <div className="text-slate-500 text-[11px] mt-1">Syndicated wire copies (&ge; 0.80)</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
