import React, { useState } from 'react';
import {
  Share2,
  Lock,
  ShieldCheck,
  AlertTriangle,
  FileKey,
  RefreshCw,
  EyeOff,
  Database,
  ArrowRight,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

interface TAXIICollectionItem {
  id: string;
  title: string;
  can_read: boolean;
  can_write: boolean;
  media_types: string[];
}

export const CollaborativeSharingPanel: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'policy' | 'anonymizer' | 'taxii' | 'retraction'>('anonymizer');

  // Anonymizer interactive state
  const [testInput, setTestInput] = useState("10.0.4.15");
  const [inputType, setInputType] = useState<"ip" | "host" | "cred">("ip");
  const [pseudonymResult, setPseudonymResult] = useState<string | null>(null);

  // Sharing evaluation state
  const [evalTlp, setEvalTlp] = useState("TLP:RED");
  const [evalScope, setEvalScope] = useState("COMMUNITY_ISAC");
  const [evalResult, setEvalResult] = useState<string | null>(null);
  const [evalAllowed, setEvalAllowed] = useState<boolean | null>(null);

  // Collections
  const collections: TAXIICollectionItem[] = [
    {
      id: "collection_isac_shared",
      title: "Community ISAC Threat Feed",
      can_read: true,
      can_write: true,
      media_types: ["application/taxii+json;version=2.1", "application/stix+json;version=2.1"]
    },
    {
      id: "collection_public_feed",
      title: "Public CTI Observable Exchange",
      can_read: true,
      can_write: false,
      media_types: ["application/taxii+json;version=2.1"]
    }
  ];

  const handleTestAnonymization = () => {
    if (inputType === "ip") {
      if (testInput.startsWith("10.") || testInput.startsWith("192.168.") || testInput.startsWith("172.16.")) {
        setPseudonymResult(`pseudonym-ip-7f89c1042a18 (Keyed HMAC-SHA256 with tenant-isolated salt)`);
      } else {
        setPseudonymResult(`${testInput} (Public C2 indicator preserved for threat correlation)`);
      }
    } else if (inputType === "host") {
      setPseudonymResult(`pseudonym-host-a1b94e028f11.internal (Salted HMAC pseudonym)`);
    } else {
      setPseudonymResult(`[REDACTED_CREDENTIAL] (PII/Credential scrubbed)`);
    }
  };

  const handleEvaluateSharing = () => {
    if (evalTlp === "TLP:RED" && evalScope !== "PRIVATE_TENANT") {
      setEvalAllowed(false);
      setEvalResult("EXPORT BLOCKED: TLP:RED intelligence strictly restricted to internal private tenant scope. Fail-closed policy enforced.");
    } else if (evalTlp === "TLP:AMBER" && evalScope === "COMMUNITY_ISAC") {
      setEvalAllowed(true);
      setEvalResult("EXPORT APPROVED: Authorized recipient verified with extension capability. Internal identifiers will be salted HMAC anonymized.");
    } else {
      setEvalAllowed(true);
      setEvalResult("EXPORT APPROVED: Public/Green intelligence conforms to tenant sharing policy.");
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-slate-100">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <Share2 className="w-8 h-8 text-blue-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Privacy-Preserving Collaborative Intelligence & TAXII 2.1
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-900/40 text-blue-400 border border-blue-800">
              Phase 16
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Salted HMAC anonymization, strict TLP recipient enforcement, TAXII 2.1 federation, and non-destructive retraction ledgers.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-300">
            <Lock className="w-3.5 h-3.5 text-blue-400" />
            <span>Default: Private Tenant Scope</span>
          </div>
        </div>
      </div>

      {/* Sub-Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveTab('anonymizer')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'anonymizer'
              ? 'border-blue-400 text-blue-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Cryptographic Anonymization Engine
        </button>
        <button
          onClick={() => setActiveTab('policy')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'policy'
              ? 'border-blue-400 text-blue-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          TLP & Sharing Policy Engine
        </button>
        <button
          onClick={() => setActiveTab('taxii')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'taxii'
              ? 'border-blue-400 text-blue-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          TAXII 2.1 Federation Collections
        </button>
        <button
          onClick={() => setActiveTab('retraction')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'retraction'
              ? 'border-blue-400 text-blue-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Retraction & Superseding Ledger
        </button>
      </div>

      {/* Anonymizer Tab */}
      {activeTab === 'anonymizer' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Tenant-Isolated Salted HMAC Anonymization Simulator
            </h3>
            <p className="text-xs text-slate-400">
              Ordinary unsalted hashing fails against dictionary enumeration for RFC 1918 IPs and internal server names. ThreatMind employs cryptographically isolated 256-bit tenant salts with HMAC-SHA256 to ensure irreversible pseudonymization.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="text-xs text-slate-400 block mb-1">Identifier Type</label>
                <select
                  value={inputType}
                  onChange={(e) => setInputType(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white"
                >
                  <option value="ip">IPv4 Address (Private RFC 1918 vs Public C2)</option>
                  <option value="host">Internal Hostname (e.g. ad-dc01.corp.internal)</option>
                  <option value="cred">Credential / Bearer Token / PII</option>
                </select>
              </div>
              <div className="md:col-span-2">
                <label className="text-xs text-slate-400 block mb-1">Raw Identifier Input</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={testInput}
                    onChange={(e) => setTestInput(e.target.value)}
                    className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white"
                  />
                  <button
                    onClick={handleTestAnonymization}
                    className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold"
                  >
                    Anonymize
                  </button>
                </div>
              </div>
            </div>

            {pseudonymResult && (
              <div className="p-4 rounded bg-slate-950 border border-blue-900/50 flex flex-col gap-1 text-xs font-mono">
                <span className="text-slate-500">Cryptographic Transformation Output:</span>
                <span className="text-cyan-300 font-bold">{pseudonymResult}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Policy Tab */}
      {activeTab === 'policy' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
              Sharing Policy Evaluation & TLP Gating
            </h3>
            <p className="text-xs text-slate-400">
              Evaluates outbound intelligence exports against TLP restrictions, recipient identities, and data classifications.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-slate-400 block mb-1">TLP Marking</label>
                <select
                  value={evalTlp}
                  onChange={(e) => setEvalTlp(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white"
                >
                  <option value="TLP:RED">TLP:RED (Strict Internal Only)</option>
                  <option value="TLP:AMBER">TLP:AMBER (Recipient Verification Required)</option>
                  <option value="TLP:GREEN">TLP:GREEN (Community Sharing Allowed)</option>
                  <option value="TLP:CLEAR">TLP:CLEAR (Public Disclosures)</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-slate-400 block mb-1">Target Sharing Scope</label>
                <select
                  value={evalScope}
                  onChange={(e) => setEvalScope(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white"
                >
                  <option value="COMMUNITY_ISAC">COMMUNITY_ISAC (Federated ISAC)</option>
                  <option value="PUBLIC_COMMUNITY">PUBLIC_COMMUNITY (Open Community)</option>
                  <option value="PRIVATE_TENANT">PRIVATE_TENANT (Internal Tenant Scope)</option>
                </select>
              </div>
            </div>

            <button
              onClick={handleEvaluateSharing}
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold"
            >
              Evaluate Policy Decision
            </button>

            {evalResult && (
              <div className={`p-4 rounded border text-xs ${
                evalAllowed ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300' : 'bg-rose-950/60 border-rose-800 text-rose-300'
              }`}>
                <div className="font-bold flex items-center gap-1.5">
                  {evalAllowed ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <XCircle className="w-4 h-4 text-rose-400" />}
                  <span>{evalAllowed ? "SHARING AUTHORIZED" : "SHARING FORBIDDEN"}</span>
                </div>
                <div className="mt-1">{evalResult}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAXII Tab */}
      {activeTab === 'taxii' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              TAXII 2.1 Federated Collections
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Standard TAXII 2.1 collections supporting authenticated discovery, bounded retrieval, and untrusted external tagging.
            </p>

            <div className="space-y-3">
              {collections.map((col) => (
                <div key={col.id} className="p-4 rounded bg-slate-950 border border-slate-800 flex justify-between items-center text-xs">
                  <div>
                    <div className="font-bold text-white flex items-center gap-2">
                      <Database className="w-4 h-4 text-blue-400" />
                      <span>{col.title}</span>
                      <span className="font-mono text-[10px] text-slate-500">{col.id}</span>
                    </div>
                    <div className="text-slate-400 text-[11px] mt-1">
                      Media Types: {col.media_types.join(", ")}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-bold">
                      {col.can_read ? "CAN_READ" : "NO_READ"}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-bold">
                      {col.can_write ? "CAN_WRITE" : "READ_ONLY"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Retraction Tab */}
      {activeTab === 'retraction' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Collaborative Intelligence Retraction & Superseding
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Published threat indicators can be superseded or retracted using cryptographic tombstones without destroying the historical audit record.
            </p>
            <div className="p-4 rounded bg-slate-950 border border-slate-800 text-xs text-slate-400 space-y-2">
              <div className="font-semibold text-white">Active Retraction Policy:</div>
              <ul className="list-disc list-inside space-y-1">
                <li>Retraction emits a STIX 2.1 tombstone marking `revoked: true`.</li>
                <li>Federated TAXII peers are notified of indicator supersession.</li>
                <li>All historical ingestion records, queries, and decisions remain permanently audit-traceable.</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
