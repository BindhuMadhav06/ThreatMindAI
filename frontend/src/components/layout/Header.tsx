import React from 'react';
import { SystemHealth } from '../../types/api';
import { Shield, Database, Cpu, Wifi, WifiOff } from 'lucide-react';

interface HeaderProps {
  health: SystemHealth | null;
  loading: boolean;
  error: string | null;
}

export const Header: React.FC<HeaderProps> = ({ health, loading, error }) => {
  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      <div className="flex items-center space-x-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-bold text-slate-950 shadow-lg shadow-cyan-950/50">
          <Shield className="w-5 h-5 text-slate-950 stroke-[2.5]" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-wide text-slate-100">ThreatMind AI</h1>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800/60">
              v{health?.version || '1.0.0'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Knowledge Graph & GraphRAG Threat Intelligence</p>
        </div>
      </div>

      <div className="flex items-center space-x-3 text-xs">
        {/* Backend Status */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800">
          {loading ? (
            <span className="w-2 h-2 rounded-full bg-slate-500 animate-pulse" />
          ) : error || !health ? (
            <WifiOff className="w-3.5 h-3.5 text-rose-400" />
          ) : (
            <Wifi className="w-3.5 h-3.5 text-emerald-400" />
          )}
          <span className="text-slate-400">API:</span>
          <span className={error || !health ? 'text-rose-400 font-semibold' : 'text-emerald-400 font-semibold'}>
            {loading ? 'Checking...' : error || !health ? 'Disconnected' : 'Active'}
          </span>
        </div>

        {/* Neo4j Status */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800">
          <Database className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400">Neo4j:</span>
          <span
            className={`font-semibold ${
              health?.neo4j_connected ? 'text-emerald-400' : 'text-amber-400'
            }`}
          >
            {health?.neo4j_connected ? 'ONLINE' : 'UNAVAILABLE'}
          </span>
        </div>

        {/* LLM Provider */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 font-mono text-[11px]">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-400">LLM:</span>
          <span className="text-cyan-300">
            {health?.llm_provider || 'Unavailable'}
          </span>
        </div>
      </div>
    </header>
  );
};
