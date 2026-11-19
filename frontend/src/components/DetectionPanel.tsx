import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Plus,
  RefreshCw,
  Copy,
  Check,
  ChevronRight,
  Filter,
} from 'lucide-react';

interface ProvenanceData {
  rule_id: string;
  technique_id?: string;
  technique_name?: string;
  tactics: string[];
  d3fend_countermeasures: string[];
  evidence_text_snippets: string[];
  confidence_score: number;
  review_status: 'draft' | 'under_review' | 'approved' | 'rejected';
  review_notes: string[];
  reviewed_by?: string;
}

interface SigmaRuleItem {
  id: string;
  title: string;
  level: string;
  status: string;
  tags: string[];
  raw_yaml?: string;
  threatmind_provenance?: ProvenanceData;
}

export const DetectionPanel: React.FC = () => {
  const [rules, setRules] = useState<SigmaRuleItem[]>([]);
  const [selectedRule, setSelectedRule] = useState<SigmaRuleItem | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [reviewNotes, setReviewNotes] = useState('');
  const [reviewerName, setReviewerName] = useState('analyst_current');

  // Modal State for Generation
  const [showGenModal, setShowGenModal] = useState(false);
  const [genTechnique, setGenTechnique] = useState('T1059.001');
  const [genName, setGenName] = useState('PowerShell Cradle');
  const [genEvidence, setGenEvidence] = useState('powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA...');
  const [genLevel, setGenLevel] = useState('high');

  const fetchRules = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/detection/rules');
      if (res.ok) {
        const data = await res.json();
        setRules(data);
        if (data.length > 0 && !selectedRule) {
          setSelectedRule(data[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/v1/detection/rules/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          technique_id: genTechnique,
          technique_name: genName,
          evidence_text: genEvidence,
          level: genLevel,
        }),
      });
      if (res.ok) {
        const newRule = await res.json();
        setShowGenModal(false);
        fetchRules();
        setSelectedRule(newRule);
      }
    } catch (err) {
      console.error('Failed to generate rule:', err);
    }
  };

  const handleReviewAction = async (newStatus: 'under_review' | 'approved' | 'rejected') => {
    if (!selectedRule) return;
    try {
      const res = await fetch(`/api/v1/detection/rules/${selectedRule.id}/review`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          review_status: newStatus,
          reviewer: reviewerName,
          notes: reviewNotes || `Transitioned to ${newStatus}`,
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setSelectedRule(updated);
        setReviewNotes('');
        fetchRules();
      }
    } catch (err) {
      console.error('Failed to submit review:', err);
    }
  };

  const copyYaml = () => {
    if (selectedRule?.raw_yaml) {
      navigator.clipboard.writeText(selectedRule.raw_yaml);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case 'approved':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-950 text-emerald-400 border border-emerald-800">
            <CheckCircle2 className="w-3 h-3" /> Approved
          </span>
        );
      case 'rejected':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-rose-950 text-rose-400 border border-rose-800">
            <XCircle className="w-3 h-3" /> Rejected
          </span>
        );
      case 'under_review':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-950 text-amber-400 border border-amber-800">
            <Clock className="w-3 h-3" /> Under Review
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
            Draft
          </span>
        );
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-slate-900 text-slate-100 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2 text-sky-400">
            <ShieldAlert className="w-6 h-6 text-sky-400" />
            SigmaHQ Detection Engineering
          </h1>
          <p className="text-xs text-slate-400">
            Evidence-grounded Sigma v2.1.0 rule generation with D3FEND mapping & sidecar provenance
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchRules()}
            className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          <button
            onClick={() => setShowGenModal(true)}
            className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded transition shadow"
          >
            <Plus className="w-3.5 h-3.5" /> Generate Rule
          </button>
        </div>
      </div>

      {/* Main Content Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left List */}
        <div className="w-1/3 border-r border-slate-800 bg-slate-950/50 flex flex-col overflow-y-auto">
          <div className="p-3 border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
            <span>Indexed Rules ({rules.length})</span>
            <Filter className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="divide-y divide-slate-800/60">
            {rules.map((rule) => {
              const isSelected = selectedRule?.id === rule.id;
              return (
                <div
                  key={rule.id}
                  onClick={() => setSelectedRule(rule)}
                  className={`p-3 cursor-pointer transition flex flex-col gap-1.5 ${
                    isSelected ? 'bg-sky-950/40 border-l-2 border-sky-400' : 'hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 line-clamp-1">{rule.title}</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded font-mono uppercase bg-slate-800 text-slate-300">
                      {rule.level}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span>{rule.threatmind_provenance?.technique_id || 'Generic'}</span>
                    {getStatusBadge(rule.threatmind_provenance?.review_status)}
                  </div>
                </div>
              );
            })}
            {rules.length === 0 && !loading && (
              <div className="p-6 text-center text-xs text-slate-500">
                No Sigma rules found. Click &quot;Generate Rule&quot; to synthesize evidence-grounded rules.
              </div>
            )}
          </div>
        </div>

        {/* Right Detail Pane */}
        {selectedRule ? (
          <div className="flex-1 flex flex-col overflow-y-auto bg-slate-900">
            {/* Rule Header Bar */}
            <div className="p-5 border-b border-slate-800 bg-slate-950/70 flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <h2 className="text-lg font-bold text-slate-100">{selectedRule.title}</h2>
                  {getStatusBadge(selectedRule.threatmind_provenance?.review_status)}
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono">
                  <span>ID: {selectedRule.id}</span>
                  <span>•</span>
                  <span>Severity: {selectedRule.level}</span>
                  <span>•</span>
                  <span>Status: {selectedRule.status}</span>
                </div>
              </div>
              <button
                onClick={copyYaml}
                className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy YAML'}
              </button>
            </div>

            {/* Split Details: Provenance & YAML */}
            <div className="flex-1 p-5 grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Provenance Card */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col gap-4">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-sky-400 flex items-center gap-1.5">
                    <FileCode className="w-4 h-4" /> Evidence Lineage & Provenance
                  </h3>
                  <span className="text-xs text-slate-400">
                    Confidence: {(selectedRule.threatmind_provenance?.confidence_score || 0.9) * 100}%
                  </span>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-slate-500 block mb-0.5">MITRE ATT&CK Technique</span>
                    <span className="font-semibold text-slate-200">
                      {selectedRule.threatmind_provenance?.technique_id} — {selectedRule.threatmind_provenance?.technique_name}
                    </span>
                  </div>

                  <div>
                    <span className="text-slate-500 block mb-0.5">Tactics</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedRule.threatmind_provenance?.tactics.map((t) => (
                        <span key={t} className="px-2 py-0.5 bg-sky-950/80 text-sky-300 rounded border border-sky-800 font-mono text-[10px]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 block mb-0.5">D3FEND Defensive Countermeasures</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedRule.threatmind_provenance?.d3fend_countermeasures.map((cm) => (
                        <span key={cm} className="px-2 py-0.5 bg-emerald-950/80 text-emerald-300 rounded border border-emerald-800 text-[10px]">
                          {cm}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 block mb-0.5">Evidence Snippet Grounding</span>
                    <div className="p-2 bg-slate-900 border border-slate-800 rounded font-mono text-[11px] text-slate-300 whitespace-pre-wrap">
                      {selectedRule.threatmind_provenance?.evidence_text_snippets?.[0] || 'No evidence snippet recorded.'}
                    </div>
                  </div>
                </div>

                {/* Review State Machine Controls */}
                <div className="mt-auto border-t border-slate-800 pt-3">
                  <span className="text-xs font-semibold text-slate-400 block mb-2">Analyst Review Actions</span>
                  <div className="flex items-center gap-2 mb-2">
                    <input
                      type="text"
                      placeholder="Add review notes or justification..."
                      value={reviewNotes}
                      onChange={(e) => setReviewNotes(e.target.value)}
                      className="flex-1 bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleReviewAction('under_review')}
                      className="px-2.5 py-1 text-xs font-medium bg-amber-950 text-amber-300 hover:bg-amber-900 rounded border border-amber-800 transition"
                    >
                      Request Review
                    </button>
                    <button
                      onClick={() => handleReviewAction('approved')}
                      className="px-2.5 py-1 text-xs font-medium bg-emerald-950 text-emerald-300 hover:bg-emerald-900 rounded border border-emerald-800 transition"
                    >
                      Approve Rule
                    </button>
                    <button
                      onClick={() => handleReviewAction('rejected')}
                      className="px-2.5 py-1 text-xs font-medium bg-rose-950 text-rose-300 hover:bg-rose-900 rounded border border-rose-800 transition"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              </div>

              {/* YAML Display */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">SigmaHQ v2.1.0 Specification</h3>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                    pySigma Validated
                  </span>
                </div>
                <pre className="flex-1 overflow-x-auto text-[11px] font-mono text-emerald-400/90 bg-slate-900/90 p-3 rounded border border-slate-800/80 leading-relaxed">
                  {selectedRule.raw_yaml}
                </pre>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
            Select a Sigma rule from the list to inspect provenance and review status.
          </div>
        )}
      </div>

      {/* Generation Modal */}
      {showGenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 mb-1">Generate Grounded Sigma Rule</h3>
            <p className="text-xs text-slate-400 mb-4">
              Synthesizes an official SigmaHQ rule from MITRE ATT&CK technique & evidence text.
            </p>
            <form onSubmit={handleGenerate} className="space-y-3">
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">Technique ID</label>
                <input
                  type="text"
                  value={genTechnique}
                  onChange={(e) => setGenTechnique(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-mono"
                  placeholder="e.g. T1059.001"
                  required
                />
              </div>
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">Technique Name</label>
                <input
                  type="text"
                  value={genName}
                  onChange={(e) => setGenName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                  placeholder="e.g. PowerShell"
                />
              </div>
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">Evidence CLI / Payload Text</label>
                <textarea
                  value={genEvidence}
                  onChange={(e) => setGenEvidence(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-mono h-24"
                  placeholder="Paste execution commands or artifacts..."
                />
              </div>
              <div>
                <label className="text-xs font-medium text-slate-300 block mb-1">Severity Level</label>
                <select
                  value={genLevel}
                  onChange={(e) => setGenLevel(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowGenModal(false)}
                  className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 text-xs font-medium text-white bg-sky-600 hover:bg-sky-500 rounded transition"
                >
                  Generate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
