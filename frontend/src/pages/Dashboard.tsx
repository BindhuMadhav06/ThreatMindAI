import React, { useEffect, useState } from 'react';
import { SystemHealth, GraphStats } from '../types/api';
import { fetchGraphStats } from '../api/graph';
import { parseApiError } from '../api/client';
import {
  Shield,
  Database,
  Cpu,
  Search,
  Network,
  UploadCloud,
  Layers,
  ArrowRight,
  History,
  Activity,
  AlertCircle,
} from 'lucide-react';

interface DashboardProps {
  health: SystemHealth | null;
  healthLoading: boolean;
  healthError: string | null;
  onNavigate: (tab: any) => void;
  onSelectRecentQuery?: (query: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  health,
  healthLoading,
  healthError,
  onNavigate,
  onSelectRecentQuery,
}) => {
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [recentQueries, setRecentQueries] = useState<string[]>([]);

  useEffect(() => {
    // Load recent session investigations from sessionStorage
    try {
      const stored = sessionStorage.getItem('tm_recent_queries');
      if (stored) {
        setRecentQueries(JSON.parse(stored));
      }
    } catch (e) {
      // Ignore session storage errors
    }

    // Fetch genuine graph stats
    const controller = new AbortController();
    fetchGraphStats(controller.signal)
      .then((data) => {
        setStats(data);
        setStatsLoading(false);
      })
      .catch((err) => {
        setStatsError(parseApiError(err));
        setStatsLoading(false);
      });

    return () => controller.abort();
  }, []);

  return (
    <div className="space-y-6">
      {/* Welcome Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-1">
            <Activity className="w-4 h-4" />
            <span>Cyber Threat Intelligence Operations</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100 mb-2">
            ThreatMind Investigation Workstation
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            AI-powered threat analysis grounded in Neo4j Knowledge Graphs, GraphRAG multi-hop Cypher traversal,
            and strict evidence provenance. Every substantive cybersecurity claim is verified against source documents.
          </p>
        </div>
      </div>

      {/* Real Infrastructure Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Backend Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-xs mb-3">
            <span className="text-slate-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-cyan-400" />
              API Service
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                healthLoading
                  ? 'bg-slate-800 text-slate-400'
                  : healthError || !health
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}
            >
              {healthLoading ? 'CHECKING' : healthError || !health ? 'OFFLINE' : 'OPERATIONAL'}
            </span>
          </div>
          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between text-slate-400">
              <span>Environment:</span>
              <span className="text-slate-200">{health?.environment || 'Unavailable'}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Version:</span>
              <span className="text-slate-200">v{health?.version || 'Unavailable'}</span>
            </div>
          </div>
        </div>

        {/* Neo4j Database */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-xs mb-3">
            <span className="text-slate-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Database className="w-4 h-4 text-purple-400" />
              Neo4j Graph Database
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                health?.neo4j_connected
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : 'bg-amber-950 text-amber-300 border border-amber-800'
              }`}
            >
              {health?.neo4j_connected ? 'ONLINE' : 'STANDBY'}
            </span>
          </div>
          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between text-slate-400">
              <span>Total Nodes:</span>
              <span className="text-slate-200">{statsLoading ? '...' : stats?.total_nodes ?? 'Unavailable'}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Total Edges:</span>
              <span className="text-slate-200">{statsLoading ? '...' : stats?.total_relationships ?? 'Unavailable'}</span>
            </div>
          </div>
        </div>

        {/* LLM Engine */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between text-xs mb-3">
            <span className="text-slate-400 font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-blue-400" />
              Intelligence Engine
            </span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                health?.llm_available
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'bg-slate-800 text-slate-400'
              }`}
            >
              {health?.llm_available ? 'ONLINE' : 'FALLBACK MODE'}
            </span>
          </div>
          <div className="space-y-1.5 text-xs font-mono">
            <div className="flex justify-between text-slate-400">
              <span>Provider:</span>
              <span className="text-cyan-300">{health?.llm_provider || 'Unavailable'}</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Sources Stored:</span>
              <span className="text-slate-200">{statsLoading ? '...' : stats?.total_sources ?? 'Unavailable'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Genuine Knowledge Graph Entities Breakdown */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Knowledge Graph Entity Distribution (Neo4j)
            </h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            Real-time entity counts from database
          </span>
        </div>

        {statsLoading ? (
          <div className="p-6 text-center text-xs text-slate-400 animate-pulse">
            Querying Neo4j primary node distributions...
          </div>
        ) : statsError ? (
          <div className="p-4 rounded-lg bg-rose-950/30 border border-rose-900 text-rose-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400" />
            <span>Could not load database metrics: {statsError}</span>
          </div>
        ) : stats && stats.node_counts_by_label ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            {Object.entries(stats.node_counts_by_label).map(([label, count]) => (
              <div key={label} className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
                <div className="text-lg font-bold text-slate-100">{count}</div>
                <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider truncate">
                  {label}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-4 text-center text-xs text-slate-500">
            No graph entities recorded. Ingest CTI documents to populate the database.
          </div>
        )}
      </div>

      {/* Workstation Navigation Shortcuts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button
          onClick={() => onNavigate('investigation')}
          className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-600/80 transition-all text-left group shadow-lg"
        >
          <Search className="w-6 h-6 text-cyan-400 mb-3 group-hover:scale-110 transition-transform" />
          <h4 className="text-sm font-semibold text-slate-100 mb-1 flex items-center justify-between">
            <span>Threat Investigation</span>
            <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-colors" />
          </h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Ask natural language threat questions and receive evidence-grounded answers with multi-hop graph paths.
          </p>
        </button>

        <button
          onClick={() => onNavigate('graph')}
          className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-600/80 transition-all text-left group shadow-lg"
        >
          <Network className="w-6 h-6 text-purple-400 mb-3 group-hover:scale-110 transition-transform" />
          <h4 className="text-sm font-semibold text-slate-100 mb-1 flex items-center justify-between">
            <span>Knowledge Graph Canvas</span>
            <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-purple-400 transition-colors" />
          </h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Visualize adversary behaviors, malware usages, CVEs, and MITRE techniques in Cytoscape.js.
          </p>
        </button>

        <button
          onClick={() => onNavigate('ingestion')}
          className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-600/80 transition-all text-left group shadow-lg"
        >
          <UploadCloud className="w-6 h-6 text-emerald-400 mb-3 group-hover:scale-110 transition-transform" />
          <h4 className="text-sm font-semibold text-slate-100 mb-1 flex items-center justify-between">
            <span>CTI Document Ingestion</span>
            <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-emerald-400 transition-colors" />
          </h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Parse PDF, HTML, JSON, and TXT threat reports with strict passage verification and edge provenance.
          </p>
        </button>
      </div>

      {/* Session-Only Investigation History */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Recent Session Investigations
            </h3>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Local browser session only — not persisted on remote server
          </span>
        </div>

        {recentQueries.length > 0 ? (
          <ul className="space-y-2 text-xs">
            {recentQueries.map((q, idx) => (
              <li
                key={idx}
                onClick={() => {
                  if (onSelectRecentQuery) {
                    onSelectRecentQuery(q);
                    onNavigate('investigation');
                  }
                }}
                className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 hover:border-cyan-800 text-slate-300 hover:text-cyan-300 cursor-pointer flex items-center justify-between transition-colors"
              >
                <span className="truncate">{q}</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 shrink-0 ml-2" />
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-slate-500 py-2 italic">
            No queries performed in the current browser session. Start an investigation above to track history.
          </p>
        )}
      </div>
    </div>
  );
};
