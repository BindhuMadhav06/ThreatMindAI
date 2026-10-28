import React, { useState } from 'react';
import { DefensiveRecommendation, DefensiveResponse, ApplicabilityClassification } from '../../types/api';
import { ShieldCheck, ExternalLink, ChevronDown, ChevronUp, AlertCircle, Info, ShieldAlert } from 'lucide-react';

interface DefensesPanelProps {
  defenseData: DefensiveResponse | null;
  loading?: boolean;
  error?: string | null;
  groundedTechniqueIds?: string[];
}

export const DefensesPanel: React.FC<DefensesPanelProps> = ({
  defenseData,
  loading = false,
  error = null,
  groundedTechniqueIds,
}) => {
  const [expandedIndices, setExpandedIndices] = useState<Set<number>>(new Set());

  if (loading) {
    return (
      <div
        role="status"
        aria-label="Loading defensive recommendations"
        className="p-6 rounded-xl bg-slate-900 border border-slate-800 animate-pulse text-center"
      >
        <ShieldCheck className="w-6 h-6 text-emerald-400 mx-auto animate-bounce mb-2" />
        <p className="text-xs text-slate-400">Mapping attack techniques to MITRE D3FEND™ countermeasures...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div
        role="alert"
        aria-label="Defensive recommendations error"
        className="p-4 rounded-xl bg-rose-950/40 border border-rose-900/80 text-rose-300 text-xs flex items-start gap-3"
      >
        <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
        <div>
          <h4 className="font-semibold text-rose-200">Defensive Recommendations Error</h4>
          <p className="mt-0.5 leading-relaxed">{error}</p>
        </div>
      </div>
    );
  }

  if (!defenseData || !defenseData.recommendations) {
    return null;
  }

  if (defenseData.recommendations.length === 0) {
    return (
      <div
        role="status"
        aria-label="No defensive recommendations found"
        className="p-5 rounded-xl bg-slate-900 border border-slate-800 text-center text-xs text-slate-400 flex items-center justify-center gap-2"
      >
        <ShieldAlert className="w-4 h-4 text-slate-500" />
        <span>No MITRE D3FEND™ defensive countermeasures mapped for the identified techniques.</span>
      </div>
    );
  }

  if (!defenseData) {
    return null;
  }

  const toggleExpand = (idx: number) => {
    setExpandedIndices((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) {
        next.delete(idx);
      } else {
        next.add(idx);
      }
      return next;
    });
  };

  const getApplicabilityBadge = (status: ApplicabilityClassification) => {
    switch (status) {
      case 'officially_mapped':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-950/70 border border-emerald-800 text-emerald-300">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            Officially mapped
          </span>
        );
      case 'potentially_relevant':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-950/70 border border-amber-800 text-amber-300">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            Potentially relevant
          </span>
        );
      case 'requires_environment_review':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-slate-800/80 border border-slate-700 text-slate-300">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
            Requires environment review
          </span>
        );
    }
  };

  const getTacticColor = (tactic: string) => {
    switch (tactic) {
      case 'Detect':
        return 'text-cyan-400 bg-cyan-950/50 border-cyan-800/60';
      case 'Harden':
        return 'text-emerald-400 bg-emerald-950/50 border-emerald-800/60';
      case 'Isolate':
        return 'text-amber-400 bg-amber-950/50 border-amber-800/60';
      case 'Deceive':
        return 'text-purple-400 bg-purple-950/50 border-purple-800/60';
      case 'Restore':
        return 'text-blue-400 bg-blue-950/50 border-blue-800/60';
      default:
        return 'text-slate-300 bg-slate-800 border-slate-700';
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden shadow-lg">
      {/* Header */}
      <div className="p-4 bg-slate-850 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-emerald-950/80 border border-emerald-800 text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              Recommended Defenses (MITRE D3FEND™)
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                {defenseData.recommendations.length} Countermeasures
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Traceable mapping: ATT&CK Technique → Documented Mitigation → D3FEND Countermeasure
            </p>
          </div>
        </div>

        {/* Tactic summary pill tags */}
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
          {Object.entries(defenseData.summary_by_tactic).map(([tactic, count]) => (
            <span
              key={tactic}
              className={`px-2 py-0.5 rounded border ${getTacticColor(tactic)} font-medium`}
            >
              {tactic}: {count}
            </span>
          ))}
        </div>
      </div>

      {/* Recommendations List */}
      <div className="divide-y divide-slate-800/80 max-h-[500px] overflow-y-auto">
        {defenseData.recommendations.map((rec, idx) => {
          const isExpanded = expandedIndices.has(idx);

          return (
            <div
              key={`${rec.attack_technique_id}-${rec.countermeasure.id}-${idx}`}
              className="p-4 hover:bg-slate-850/60 transition-colors"
            >
              <div
                className="flex items-start justify-between gap-4 cursor-pointer"
                onClick={() => toggleExpand(idx)}
              >
                <div className="space-y-1.5 flex-1">
                  {/* Top Badges */}
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-rose-950/60 border border-rose-900/80 text-rose-300">
                      Offensive: {rec.attack_technique_id} ({rec.attack_technique_name})
                    </span>

                    {groundedTechniqueIds && (
                      groundedTechniqueIds.includes(rec.attack_technique_id) ? (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/70 border border-emerald-800 text-emerald-300" title="Technique verified in knowledge graph reasoning path">
                          Graph Verified
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 border border-slate-700 text-slate-400" title="Technique referenced in narrative/query text">
                          Narrative Reference
                        </span>
                      )
                    )}

                    {rec.mitigation_id && (
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-indigo-950/60 border border-indigo-900/80 text-indigo-300">
                        Mitigation: {rec.mitigation_id} {rec.mitigation_name ? `(${rec.mitigation_name})` : ''}
                      </span>
                    )}

                    <span
                      className={`px-2 py-0.5 rounded text-xs font-semibold border ${getTacticColor(
                        rec.countermeasure.tactic
                      )}`}
                    >
                      {rec.countermeasure.tactic}
                    </span>

                    {getApplicabilityBadge(rec.applicability)}
                  </div>

                  {/* Countermeasure Title */}
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-semibold text-slate-100">
                      {rec.countermeasure.name}
                    </h4>
                    <span className="text-xs font-mono text-cyan-400">
                      [{rec.countermeasure.id}]
                    </span>
                  </div>

                  {/* Rationale Brief */}
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {rec.rationale}
                  </p>
                </div>

                <button
                  type="button"
                  className="p-1 rounded text-slate-400 hover:text-slate-200 mt-1"
                  aria-label="Toggle details"
                >
                  {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </button>
              </div>

              {/* Expanded Details Drawer */}
              {isExpanded && (
                <div className="mt-4 pt-3 border-t border-slate-800 space-y-3 text-xs bg-slate-950/50 p-3.5 rounded-lg">
                  {/* Formal Definition */}
                  <div>
                    <span className="text-slate-400 font-medium">Formal D3FEND Definition:</span>
                    <p className="mt-0.5 text-slate-200 leading-relaxed font-sans">
                      {rec.countermeasure.definition}
                    </p>
                  </div>

                  {/* Environmental Limitations & Prerequisites */}
                  <div className="p-2.5 rounded bg-amber-950/30 border border-amber-900/60 text-amber-200 flex items-start gap-2">
                    <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-amber-300">Environment Limitations & Telemetry Prerequisites:</span>
                      <p className="mt-0.5 leading-relaxed text-amber-200/90">{rec.environment_limitations}</p>
                    </div>
                  </div>

                  {/* Provenance & Official Source Link */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono">
                    <span>Provenance: {rec.mapping_provenance}</span>
                    {rec.countermeasure.official_url && !rec.countermeasure.id.startsWith('app:') ? (
                      <a
                        href={rec.countermeasure.official_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 underline"
                      >
                        Canonical MITRE Reference <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span className="text-amber-400/90 font-sans italic text-[11px]">
                        Application-defined conceptual defense (not an official D3FEND technique)
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Panel Footer Disclaimer */}
      <div className="p-3 bg-slate-950 border-t border-slate-800 flex items-start gap-2 text-[11px] text-slate-400 leading-relaxed">
        <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <span>{defenseData.disclaimer}</span>
          <div className="mt-1 flex items-center gap-3 text-slate-400 font-mono text-[10px]">
            <span>Catalog: {defenseData.catalog_version}</span>
            <span>Snapshot: {defenseData.snapshot_date}</span>
            <span>SHA-256: {defenseData.catalog_sha256.slice(0, 12)}...</span>
          </div>
        </div>
      </div>
    </div>
  );
};
