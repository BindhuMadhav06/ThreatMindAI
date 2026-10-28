import React from 'react';
import { IngestionResponse } from '../../types/api';
import { CheckCircle2, AlertTriangle, Layers, GitBranch, FileCheck, Hash } from 'lucide-react';

interface IngestionResultProps {
  result: IngestionResponse;
}

export const IngestionResult: React.FC<IngestionResultProps> = ({ result }) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-5">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Ingestion Execution Succeeded</h3>
            <p className="text-[11px] text-slate-400 font-mono">Source ID: {result.source_id}</p>
          </div>
        </div>
        <span className="px-2.5 py-1 rounded text-xs font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
          STATUS: {result.status.toUpperCase()}
        </span>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
          <Layers className="w-4 h-4 text-cyan-400 mx-auto mb-1" />
          <div className="text-lg font-bold text-slate-100">{result.chunks_count}</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider">Chunks Processed</div>
        </div>

        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
          <Hash className="w-4 h-4 text-purple-400 mx-auto mb-1" />
          <div className="text-lg font-bold text-slate-100">{result.entities_extracted}</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider">Entities Extracted</div>
        </div>

        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
          <GitBranch className="w-4 h-4 text-emerald-400 mx-auto mb-1" />
          <div className="text-lg font-bold text-emerald-400">{result.relationships_accepted}</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider">Edges Persisted</div>
        </div>

        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-center">
          <FileCheck className="w-4 h-4 text-rose-400 mx-auto mb-1" />
          <div className="text-lg font-bold text-slate-300">{result.relationships_rejected}</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider">Edges Rejected</div>
        </div>
      </div>

      {/* Extraction Warnings */}
      {result.warnings && result.warnings.length > 0 && (
        <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-800/40 space-y-1.5 text-xs text-amber-300/80">
          <div className="flex items-center gap-1.5 font-semibold text-amber-300">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <span>Ingestion Pipeline Validation Notes:</span>
          </div>
          <ul className="space-y-1 pl-5 list-disc text-[11px]">
            {result.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
