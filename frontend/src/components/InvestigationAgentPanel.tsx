import React, { useState } from 'react';
import {
  Bot,
  Shield,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Clock,
  Terminal,
  UserCheck,
  XCircle,
  HelpCircle,
  Download,
  Lock,
} from 'lucide-react';

interface ToolTrace {
  id: string;
  tool: string;
  status: 'success' | 'blocked_permission' | 'error';
  latency_ms: number;
  summary: string;
}

interface GroundedClaimView {
  id: string;
  claim: string;
  evidence_ref: string;
  confidence: number;
  uncertainty: number;
  status: string;
}

interface ProposedActionView {
  id: string;
  action_type: string;
  proposed: string;
  impact: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
}

export const InvestigationAgentPanel: React.FC = () => {
  const [targetEntity, setTargetEntity] = useState("APT29");
  const [objective, setObjective] = useState("Investigate threat actor staging capabilities and identify detection gaps.");
  const [isExecuting, setIsExecuting] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'traces' | 'hitl' | 'report'>('overview');

  // Execution state
  const [currentState, setCurrentState] = useState<'IDLE' | 'RETRIEVING' | 'PIVOTING' | 'EVALUATING' | 'COMPLETED'>('COMPLETED');
  
  // Traces
  const [traces] = useState<ToolTrace[]>([
    {
      id: "trace_01",
      tool: "READ_GRAPH_ENTITY",
      status: "success",
      latency_ms: 14.2,
      summary: "Retrieved graph node for APT29 with 4 connected capability edges."
    },
    {
      id: "trace_02",
      tool: "RETRIEVE_EVIDENCE",
      status: "success",
      latency_ms: 8.5,
      summary: "Found grounded passage in Mandiant M-Trends 2026 [offsets: 38:119]."
    },
    {
      id: "trace_03",
      tool: "LOOKUP_ATTACK_D3FEND",
      status: "success",
      latency_ms: 19.1,
      summary: "Mapped 4 D3FEND countermeasures for technique T1059.001."
    },
    {
      id: "trace_04",
      tool: "VALIDATE_SIGMA_RULE",
      status: "success",
      latency_ms: 22.4,
      summary: "Generated and validated Sigma rule 'Suspicious PowerShell Download Cradle'."
    },
    {
      id: "trace_05",
      tool: "EXECUTE_SHELL_COMMAND",
      status: "blocked_permission",
      latency_ms: 0.8,
      summary: "BLOCKED: Arbitrary shell execution forbidden by sandbox security policy."
    }
  ]);

  // Grounded claims
  const [claims] = useState<GroundedClaimView[]>([
    {
      id: "clm_01",
      claim: "APT29 executes PowerShell download cradles to drop Cobalt Strike payloads.",
      evidence_ref: "doc_mnd_2026_01 [offsets: 38:119]",
      confidence: 0.94,
      uncertainty: 0.06,
      status: "VERIFIED"
    }
  ]);

  // HITL Proposed Actions
  const [actions, setActions] = useState<ProposedActionView[]>([
    {
      id: "act_01",
      action_type: "DEPLOY_SIGMA_DETECTION",
      proposed: "Deploy Sigma detection rule 'Suspicious PowerShell Download Cradle' across EDR telemetry.",
      impact: "Zero host disruption. Monitors and alerts on process creation events.",
      risk: "LOW",
      status: "PENDING"
    },
    {
      id: "act_02",
      action_type: "PATCH_VULNERABLE_PACKAGE",
      proposed: "Apply patch for CVE-2021-44228 across edge application servers.",
      impact: "Planned rolling restart of web application pool required.",
      risk: "HIGH",
      status: "PENDING"
    }
  ]);

  const handleReviewAction = (id: string, decision: 'APPROVED' | 'REJECTED') => {
    setActions(actions.map(a => a.id === id ? { ...a, status: decision } : a));
  };

  const handleRunInvestigation = () => {
    setIsExecuting(true);
    setCurrentState('RETRIEVING');
    setTimeout(() => setCurrentState('PIVOTING'), 600);
    setTimeout(() => setCurrentState('EVALUATING'), 1200);
    setTimeout(() => {
      setCurrentState('COMPLETED');
      setIsExecuting(false);
    }, 1800);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-slate-100">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <Bot className="w-8 h-8 text-emerald-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">Trusted AI Investigation Agent</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-900/40 text-emerald-400 border border-emerald-800">
              Phase 15
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Bounded read-only investigation orchestrator with strict tool sandboxing, evidence grounding, and Human-in-the-Loop approval.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>Read-Only Sandbox Enforced</span>
          </div>
        </div>
      </div>

      {/* Launcher Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-3 w-full">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Target Entity / Alert</label>
            <input
              type="text"
              value={targetEntity}
              onChange={(e) => setTargetEntity(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white"
            />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-slate-400 block mb-1">Investigation Objective</label>
            <input
              type="text"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white"
            />
          </div>
        </div>
        <button
          onClick={handleRunInvestigation}
          disabled={isExecuting}
          className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold flex items-center gap-2 self-end shrink-0 transition"
        >
          <Play className="w-4 h-4" />
          <span>{isExecuting ? `State: ${currentState}...` : "Execute Investigation"}</span>
        </button>
      </div>

      {/* Sub-Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'overview'
              ? 'border-emerald-400 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Investigation Findings
        </button>
        <button
          onClick={() => setActiveTab('hitl')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'hitl'
              ? 'border-emerald-400 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          HITL Action Approvals ({actions.filter(a => a.status === 'PENDING').length} Pending)
        </button>
        <button
          onClick={() => setActiveTab('traces')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'traces'
              ? 'border-emerald-400 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Tool Execution Traces ({traces.length})
        </button>
        <button
          onClick={() => setActiveTab('report')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'report'
              ? 'border-emerald-400 text-emerald-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Structured Report & Reproducibility
        </button>
      </div>

      {/* Findings Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Grounded Claims */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Evidence-Grounded Agent Conclusions
            </h3>
            <div className="space-y-3">
              {claims.map((c) => (
                <div key={c.id} className="p-4 rounded bg-slate-950 border border-slate-800 flex justify-between items-center text-xs">
                  <div className="space-y-1">
                    <div className="text-white font-medium text-sm">{c.claim}</div>
                    <div className="text-slate-400 font-mono text-[11px]">
                      Anchor: <span className="text-cyan-400">{c.evidence_ref}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold text-[10px]">
                      {c.status}
                    </span>
                    <div className="text-slate-400 text-[11px] mt-1">
                      Confidence: {(c.confidence * 100).toFixed(0)}% (±{(c.uncertainty * 100).toFixed(0)}%)
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Analytical Invariants: Knowns, Unknowns, Contradictions, Stale */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="p-4 rounded bg-slate-900 border border-slate-800 space-y-2">
              <div className="font-semibold text-emerald-400 flex items-center gap-1.5 uppercase">
                <CheckCircle2 className="w-4 h-4" />
                <span>What is Known?</span>
              </div>
              <ul className="list-disc list-inside text-slate-300 space-y-1">
                <li>APT29 actively leverages PowerShell download cradles (T1059.001).</li>
                <li>Grounded Sigma rule coverage exists for suspicious download syntax.</li>
                <li>Vulnerability CVE-2021-44228 is targeted with high exploitability.</li>
              </ul>
            </div>

            <div className="p-4 rounded bg-slate-900 border border-slate-800 space-y-2">
              <div className="font-semibold text-amber-400 flex items-center gap-1.5 uppercase">
                <HelpCircle className="w-4 h-4" />
                <span>What is Unknown?</span>
              </div>
              <ul className="list-disc list-inside text-slate-300 space-y-1">
                <li>Initial access broker identity and staging infrastructure origin.</li>
                <li>Internal exfiltration target outside designated C2 IP pools.</li>
              </ul>
            </div>

            <div className="p-4 rounded bg-slate-900 border border-slate-800 space-y-2">
              <div className="font-semibold text-rose-400 flex items-center gap-1.5 uppercase">
                <AlertTriangle className="w-4 h-4" />
                <span>What Contradicts Current Hypothesis?</span>
              </div>
              <p className="text-slate-300">
                Vendor B attributes recent campaign staging to FIN7 rather than APT29. Tracked in Dispute Ledger without deleting competing evidence.
              </p>
            </div>

            <div className="p-4 rounded bg-slate-900 border border-slate-800 space-y-2">
              <div className="font-semibold text-cyan-400 flex items-center gap-1.5 uppercase">
                <Clock className="w-4 h-4" />
                <span>What Evidence is Stale?</span>
              </div>
              <p className="text-slate-300">
                Primary C2 IP observation is 45 days old, which exceeds the 14-day half-life decay threshold. Confidence is mathematically discounted.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* HITL Approvals Tab */}
      {activeTab === 'hitl' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Human-in-the-Loop (HITL) Defensive Action Approval Queue
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              AI investigation agents are strictly read-only. Environment-altering actions are queued as proposals and require explicit human sign-off.
            </p>
            <div className="space-y-4">
              {actions.map((act) => (
                <div key={act.id} className="p-4 rounded bg-slate-950 border border-slate-800 space-y-3 text-xs">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <Shield className="w-4 h-4 text-indigo-400" />
                      <span className="font-bold text-white">{act.proposed}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        act.risk === 'HIGH' ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}>
                        {act.risk} RISK
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      act.status === 'PENDING' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                      act.status === 'APPROVED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                      'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {act.status}
                    </span>
                  </div>

                  <div className="text-slate-400">
                    <span className="text-slate-300 font-semibold">Potential Impact:</span> {act.impact}
                  </div>

                  {act.status === 'PENDING' ? (
                    <div className="flex justify-end gap-2 pt-2 border-t border-slate-900">
                      <button
                        onClick={() => handleReviewAction(act.id, 'REJECTED')}
                        className="px-3 py-1.5 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 font-semibold"
                      >
                        Reject Action
                      </button>
                      <button
                        onClick={() => handleReviewAction(act.id, 'APPROVED')}
                        className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold flex items-center gap-1.5"
                      >
                        <UserCheck className="w-4 h-4" />
                        Approve & Enforce
                      </button>
                    </div>
                  ) : (
                    <div className="text-[11px] text-slate-500 italic">
                      Review completed. Recorded in immutable action audit history.
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Traces Tab */}
      {activeTab === 'traces' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Auditable Tool Execution Traces
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              All tool invocations are logged with latency, parameters, and permission enforcement checks.
            </p>
            <div className="space-y-2">
              {traces.map((t) => (
                <div key={t.id} className="p-3 rounded bg-slate-950 border border-slate-800 flex justify-between items-center text-xs">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-cyan-300 font-semibold">{t.tool}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        t.status === 'success' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                      }`}>
                        {t.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="text-slate-400 text-[11px]">{t.summary}</div>
                  </div>
                  <div className="text-slate-500 font-mono text-[11px]">{t.latency_ms} ms</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Report Tab */}
      {activeTab === 'report' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                Reproducible Investigation Report Envelope
              </h3>
              <button className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-white flex items-center gap-1.5">
                <Download className="w-4 h-4" />
                Export Signed JSON
              </button>
            </div>
            <div className="p-4 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 space-y-2">
              <div><span className="text-slate-500">Report ID:</span> rep_7f10b89e32a1</div>
              <div><span className="text-slate-500">Target Entity:</span> APT29 (Attribution: Mandiant M-Trends 2026)</div>
              <div><span className="text-slate-500">Grounded Claims:</span> 1 verified claim, 0 unsupported claims</div>
              <div><span className="text-slate-500">Reproducibility Digest (RFC 8785):</span></div>
              <div className="text-cyan-400 break-all">6b7e9231f8a8461a9bc24df97b772ad389e18b76df42951e70e28198f12d8a55</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
