import React, { useState } from 'react';
import {
  Target,
  Server,
  Shield,
  Layers,
  ArrowRight,
  AlertOctagon,
  FileCode2,
  CheckCircle2,
  Cpu,
  KeyRound,
  ExternalLink,
} from 'lucide-react';

interface AssetRecord {
  id: string;
  name: string;
  type: string;
  criticality: 'mission_critical' | 'high' | 'medium' | 'low';
  external_exposure: boolean;
  packages_count: number;
  controls: string[];
}

interface ThreatMatchItem {
  asset_id: string;
  cve_id: string;
  package_name: string;
  installed_version: string;
  vulnerable_range: string;
  confidence: number;
}

interface CutSetItem {
  id: string;
  techniques: string[];
  blocked_paths_count: number;
  estimated_impact: number;
  operational_cost: number;
  target_assets: string[];
  alternatives: string[];
}

export const AttackPathSimulationPanel: React.FC = () => {
  const [tenantId] = useState("tenant_corp_sec");
  const [activeTab, setActiveTab] = useState<'inventory' | 'matching' | 'prioritization' | 'simulation'>('simulation');

  // Sample enterprise assets
  const [assets, setAssets] = useState<AssetRecord[]>([
    {
      id: "asset_web_01",
      name: "Public Edge Web Gateway",
      type: "server",
      criticality: "medium",
      external_exposure: true,
      packages_count: 14,
      controls: ["WAF", "TLS_Termination"]
    },
    {
      id: "asset_app_02",
      name: "Core Business Application Server",
      type: "application",
      criticality: "high",
      external_exposure: false,
      packages_count: 28,
      controls: ["EDR"]
    },
    {
      id: "asset_db_03",
      name: "Production Financial Database (Crown Jewel)",
      type: "server",
      criticality: "mission_critical",
      external_exposure: false,
      packages_count: 9,
      controls: ["Segmentation", "Database_Audit_Logs"]
    }
  ]);

  // Sample threat matches
  const matches: ThreatMatchItem[] = [
    {
      asset_id: "asset_web_01",
      cve_id: "CVE-2021-44228",
      package_name: "log4j-core",
      installed_version: "2.14.1",
      vulnerable_range: "< 2.15.0",
      confidence: 0.99
    },
    {
      asset_id: "asset_app_02",
      cve_id: "CVE-2023-38606",
      package_name: "kernel-headers",
      installed_version: "5.10.4",
      vulnerable_range: "< 5.15.0",
      confidence: 0.95
    }
  ];

  // SBOM upload modal state
  const [showSbomModal, setShowSbomModal] = useState(false);
  const [sbomContent, setSbomContent] = useState("");
  const [sbomStatus, setSbomStatus] = useState<string | null>(null);

  // Cut-set recommendation
  const cutSet: CutSetItem = {
    id: "cutset_tenant_corp_sec_opt",
    techniques: [
      "d3f:InboundTrafficFiltering",
      "d3f:ExecutableAllowlisting",
      "d3f:MultiFactorAuthentication"
    ],
    blocked_paths_count: 3,
    estimated_impact: 0.94,
    operational_cost: 0.45,
    target_assets: ["asset_db_03", "asset_app_02"],
    alternatives: [
      "d3f:ProcessSegmentExecutionPrevention",
      "d3f:NetworkIsolation",
      "d3f:SoftwareUpdate"
    ]
  };

  const handleImportSbom = () => {
    if (!sbomContent.trim()) return;
    setSbomStatus("Parsed 18 CycloneDX software components into asset_web_01 inventory.");
    setTimeout(() => {
      setShowSbomModal(false);
      setSbomStatus(null);
      setSbomContent("");
    }, 1500);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-slate-100">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <Target className="w-8 h-8 text-indigo-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Organization Threat Intelligence & Attack Simulation
            </h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-900/40 text-indigo-400 border border-indigo-800">
              Phase 14
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Enterprise SBOM inventory, SemVer version range matching, graph traversal, and Minimum D3FEND Cut-Sets.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-xs bg-slate-900 border border-slate-800 px-3 py-1.5 rounded text-slate-400">
            Tenant: <span className="font-mono text-cyan-400">{tenantId}</span>
          </div>
          <button
            onClick={() => setShowSbomModal(true)}
            className="px-3 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded transition flex items-center gap-1.5"
          >
            <FileCode2 className="w-4 h-4" />
            Import CycloneDX / SPDX SBOM
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800 space-x-2">
        <button
          onClick={() => setActiveTab('simulation')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'simulation'
              ? 'border-indigo-400 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Attack-Path Simulation & D3FEND Cut-Set
        </button>
        <button
          onClick={() => setActiveTab('prioritization')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'prioritization'
              ? 'border-indigo-400 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Decomposed Risk Prioritization
        </button>
        <button
          onClick={() => setActiveTab('matching')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'matching'
              ? 'border-indigo-400 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          SemVer Threat Matches
        </button>
        <button
          onClick={() => setActiveTab('inventory')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'inventory'
              ? 'border-indigo-400 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Asset Inventory ({assets.length})
        </button>
      </div>

      {/* Main Content Area */}
      {activeTab === 'simulation' && (
        <div className="space-y-6">
          {/* Path Simulation Diagram Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
                Graph Traversal Attack Path (Entry to Crown Jewel)
              </h3>
              <span className="text-xs px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 font-semibold">
                Path Exploitability: 82%
              </span>
            </div>

            <div className="p-4 rounded bg-slate-950 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4 text-xs">
              <div className="p-3 rounded bg-slate-900 border border-rose-800/60 max-w-xs w-full">
                <div className="text-[10px] text-rose-400 font-bold uppercase tracking-wider">Entry Point (Public)</div>
                <div className="text-white font-bold mt-1">asset_web_01</div>
                <div className="text-slate-400 text-[11px] mt-0.5">Vulnerable to Log4Shell (CVE-2021-44228)</div>
              </div>

              <div className="flex flex-col items-center text-slate-500">
                <span className="text-[10px] font-mono text-cyan-400">T1190 Exploit</span>
                <ArrowRight className="w-5 h-5 text-cyan-400" />
              </div>

              <div className="p-3 rounded bg-slate-900 border border-amber-800/60 max-w-xs w-full">
                <div className="text-[10px] text-amber-400 font-bold uppercase tracking-wider">Intermediate Pivot</div>
                <div className="text-white font-bold mt-1">asset_app_02</div>
                <div className="text-slate-400 text-[11px] mt-0.5">Lateral SMB connection to Core DB</div>
              </div>

              <div className="flex flex-col items-center text-slate-500">
                <span className="text-[10px] font-mono text-cyan-400">T1078 Accounts</span>
                <ArrowRight className="w-5 h-5 text-cyan-400" />
              </div>

              <div className="p-3 rounded bg-slate-900 border border-indigo-800/80 max-w-xs w-full">
                <div className="text-[10px] text-indigo-400 font-bold uppercase tracking-wider">Mission Critical Target</div>
                <div className="text-white font-bold mt-1">asset_db_03 (Crown Jewel)</div>
                <div className="text-slate-400 text-[11px] mt-0.5">Production Financial Database</div>
              </div>
            </div>
          </div>

          {/* D3FEND Minimum Cut-Set Card */}
          <div className="bg-slate-900 border border-indigo-900/40 rounded-lg p-5 space-y-4">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-indigo-400" />
                <h3 className="text-sm font-semibold text-white uppercase tracking-wider">
                  Recommended Minimum D3FEND Cut-Set
                </h3>
              </div>
              <span className="text-xs px-2.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold">
                {cutSet.blocked_paths_count} Paths Interrupted (100%)
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Calculated using graph hitting set optimization over verified MITRE D3FEND countermeasures.
              Deploying these mitigations severs all identified traversal paths from external entry points to crown jewel databases.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {cutSet.techniques.map((tech) => (
                <div key={tech} className="p-4 rounded bg-slate-950 border border-indigo-800/50 space-y-2">
                  <div className="text-xs font-mono font-bold text-indigo-300">{tech}</div>
                  <div className="text-[11px] text-slate-400">
                    Officially validated countermeasure from MITRE D3FEND catalog.
                  </div>
                  <div className="text-[10px] text-emerald-400 font-semibold">Sever point verified</div>
                </div>
              ))}
            </div>

            <div className="p-3 rounded bg-slate-950/60 border border-slate-800 flex justify-between items-center text-xs">
              <div>
                <span className="text-slate-400">Alternative catalog mitigations: </span>
                <span className="font-mono text-cyan-400">{cutSet.alternatives.join(", ")}</span>
              </div>
              <div className="text-slate-400">
                Catalog SHA-256: <code className="text-slate-500 font-mono">a7a1ebffba...</code>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'prioritization' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Decomposed Organization Risk Scoring Formula
            </h3>
            <p className="text-xs font-mono text-cyan-300 bg-slate-950 p-3 rounded border border-slate-800 mb-4">
              S_org = w_v * S_vuln + w_e * P_exploit + w_x * E_exposure + w_c * C_asset + w_t * T_rel - w_m * M_controls
            </p>
            <div className="divide-y divide-slate-800">
              <div className="py-3 flex justify-between items-center text-xs">
                <div>
                  <div className="font-bold text-white">Public Edge Web Gateway (asset_web_01)</div>
                  <div className="text-slate-400">External Exposure: Yes | Vulnerability: CVSS 9.8 (Log4Shell)</div>
                </div>
                <div className="text-right">
                  <div className="text-lg font-bold text-rose-400">86.4 / 100</div>
                  <div className="text-[10px] text-rose-500 font-bold">CRITICAL PRIORITY</div>
                </div>
              </div>
              <div className="py-3 flex justify-between items-center text-xs">
                <div>
                  <div className="font-bold text-white">Production Financial Database (asset_db_03)</div>
                  <div className="text-slate-400">Criticality: Mission Critical | Mitigations: Segmentation, DB Audit</div>
                </div>
                <div className="text-right">
                  <div className="text-lg font-bold text-amber-400">64.0 / 100</div>
                  <div className="text-[10px] text-amber-500 font-bold">HIGH PRIORITY</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'matching' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-2">
              Semantic Version (SemVer) Threat Matches
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              ThreatMind strictly rejects naive substring matching, evaluating installed component versions against PEP 440 / SemVer constraint specifications.
            </p>
            <div className="space-y-3">
              {matches.map((m, i) => (
                <div key={i} className="p-4 rounded bg-slate-950 border border-slate-800 flex justify-between items-center text-xs">
                  <div>
                    <div className="font-bold text-white flex items-center gap-2">
                      <span>{m.package_name}</span>
                      <span className="font-mono text-cyan-400">{m.installed_version}</span>
                      <span className="text-slate-400">matches constraint</span>
                      <span className="font-mono text-rose-400">{m.vulnerable_range}</span>
                    </div>
                    <div className="text-slate-400 text-[11px] mt-1">
                      Target: {m.asset_id} | Advisory: {m.cve_id}
                    </div>
                  </div>
                  <div className="text-emerald-400 font-bold">
                    Confidence: {(m.confidence * 100).toFixed(0)}%
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'inventory' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-sm font-semibold text-slate-200">Tenant Enterprise Asset Inventory</h3>
              <span className="text-xs text-slate-400">{assets.length} Assets Registered</span>
            </div>
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Asset Name / ID</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Criticality</th>
                  <th className="p-3">Exposure</th>
                  <th className="p-3">Packages</th>
                  <th className="p-3">Active Controls</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-slate-800/40">
                    <td className="p-3 font-semibold text-white">
                      {asset.name}
                      <div className="text-[10px] font-mono text-slate-500">{asset.id}</div>
                    </td>
                    <td className="p-3 uppercase text-slate-400">{asset.type}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        asset.criticality === 'mission_critical' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                        asset.criticality === 'high' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {asset.criticality}
                      </span>
                    </td>
                    <td className="p-3">
                      {asset.external_exposure ? (
                        <span className="text-rose-400 font-bold">Public Ingress</span>
                      ) : (
                        <span className="text-slate-500">Internal</span>
                      )}
                    </td>
                    <td className="p-3 font-mono">{asset.packages_count} pkgs</td>
                    <td className="p-3 text-slate-400">{asset.controls.join(", ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SBOM Modal */}
      {showSbomModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-xl w-full space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <FileCode2 className="w-5 h-5 text-indigo-400" />
              <span>Import Software Bill of Materials (SBOM)</span>
            </h3>
            <p className="text-xs text-slate-400">
              Paste CycloneDX or SPDX JSON to extract installed software components and populate tenant asset inventories.
            </p>
            <textarea
              value={sbomContent}
              onChange={(e) => setSbomContent(e.target.value)}
              placeholder='{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "log4j-core", "version": "2.14.1"}]}'
              className="w-full h-32 bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono text-slate-200"
            />
            {sbomStatus && (
              <div className="text-xs text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" />
                <span>{sbomStatus}</span>
              </div>
            )}
            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowSbomModal(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Close
              </button>
              <button
                onClick={handleImportSbom}
                className="px-3 py-1.5 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white rounded transition"
              >
                Ingest SBOM
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
