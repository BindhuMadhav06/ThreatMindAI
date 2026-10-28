import React from 'react';
import { EvidenceBackedPath } from '../../types/api';
import { Route, ArrowRight, CheckCircle2, AlertCircle } from 'lucide-react';

interface PathViewerProps {
  paths: EvidenceBackedPath[];
  selectedPathId?: string | null;
  onSelectPath?: (pathId: string) => void;
}

export const PathViewer: React.FC<PathViewerProps> = ({
  paths,
  selectedPathId,
  onSelectPath,
}) => {
  if (!paths || paths.length === 0) return null;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Route className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            Validated Multi-Hop Graph Paths ({paths.length})
          </h3>
        </div>
        <span className="text-[11px] text-slate-500 font-mono">
          Click a path to highlight on graph canvas
        </span>
      </div>

      <div className="space-y-3">
        {paths.map((path) => {
          const isSelected = selectedPathId === path.path_id;
          return (
            <div
              key={path.path_id}
              onClick={() => onSelectPath && onSelectPath(path.path_id)}
              className={`p-4 rounded-lg border text-xs cursor-pointer transition-all ${
                isSelected
                  ? 'bg-slate-950 border-cyan-500 shadow-md shadow-cyan-950/40 ring-1 ring-cyan-500/50'
                  : 'bg-slate-950/70 border-slate-800/80 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono font-semibold text-cyan-300">
                    {path.path_id}
                  </span>
                  {path.template_applied && (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-900 text-slate-400 border border-slate-800 font-mono">
                      {path.template_applied}
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                  <span>Score: {path.relevance_score.toFixed(2)}</span>
                  <span>•</span>
                  <span>{path.length} {path.length === 1 ? 'hop' : 'hops'}</span>
                </div>
              </div>

              {/* Step Sequence Chain */}
              <div className="flex flex-wrap items-center gap-1.5 font-mono">
                {path.steps.map((step, sIdx) => (
                  <React.Fragment key={sIdx}>
                    <span className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-slate-200">
                      <span className="text-slate-500 text-[10px] block font-sans">{step.source_label}</span>
                      {step.source_name}
                    </span>
                    <span className="flex items-center text-cyan-400 font-bold px-1 text-[11px]">
                      <ArrowRight className="w-3 h-3 mr-0.5" />
                      [{step.rel_type}]
                    </span>
                    {sIdx === path.steps.length - 1 && (
                      <span className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-slate-200">
                        <span className="text-slate-500 text-[10px] block font-sans">{step.target_label}</span>
                        {step.target_name}
                      </span>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
