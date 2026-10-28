import React, { useState, useEffect } from 'react';
import { EntitySummary, EntityDetail } from '../types/api';
import { fetchEntities, fetchEntityDetails } from '../api/graph';
import { parseApiError } from '../api/client';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { Layers, Search, ArrowRight, Shield, ExternalLink, AlertCircle, ShieldCheck } from 'lucide-react';
import { VulnerabilityCard } from '../components/vulnerability/VulnerabilityCard';
import { DefensesPanel } from '../components/defense/DefensesPanel';
import { getDefensesBatch } from '../api/defense';
import { DefensiveResponse } from '../types/api';

const FILTER_LABELS = [
  'All',
  'ThreatActor',
  'Malware',
  'Tool',
  'Vulnerability',
  'Technique',
  'Product',
  'Organization',
];

export const EntitiesPage: React.FC = () => {
  const [entities, setEntities] = useState<EntitySummary[]>([]);
  const [selectedLabel, setSelectedLabel] = useState<string>('All');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [loadingList, setLoadingList] = useState(false);
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [entityDetail, setEntityDetail] = useState<EntityDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [techniqueDefenses, setTechniqueDefenses] = useState<DefensiveResponse | null>(null);
  const [loadingDefenses, setLoadingDefenses] = useState(false);
  const [techniqueDefensesError, setTechniqueDefensesError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadEntities();
  }, [selectedLabel]);

  const loadEntities = async () => {
    setLoadingList(true);
    setError(null);
    try {
      const labelParam = selectedLabel === 'All' ? undefined : selectedLabel;
      const data = await fetchEntities({ label: labelParam, search: searchTerm || undefined, limit: 50 });
      setEntities(data);
      if (data.length > 0 && !selectedEntityId) {
        handleSelectEntity(data[0].id);
      }
    } catch (err) {
      setError(parseApiError(err));
    } finally {
      setLoadingList(false);
    }
  };

  const handleSelectEntity = async (entityId: string) => {
    setSelectedEntityId(entityId);
    setLoadingDetail(true);
    setTechniqueDefenses(null);
    setTechniqueDefensesError(null);
    try {
      const detail = await fetchEntityDetails(entityId);
      setEntityDetail(detail);

      // If entity is a technique, resolve D3FEND defenses
      if (detail && detail.entity.label === 'Technique') {
        const candidateIds: string[] = [];
        if (detail.entity.properties?.external_id) {
          candidateIds.push(detail.entity.properties.external_id);
        }
        if (detail.entity.aliases) {
          detail.entity.aliases.forEach(a => {
            if (/^T\d{4}/i.test(a)) candidateIds.push(a);
          });
        }
        if (detail.entity.name && /^T\d{4}/i.test(detail.entity.name)) {
          candidateIds.push(detail.entity.name);
        }
        if (candidateIds.length > 0) {
          setLoadingDefenses(true);
          try {
            const defData = await getDefensesBatch(candidateIds);
            setTechniqueDefenses(defData);
          } catch (dErr) {
            setTechniqueDefensesError(parseApiError(dErr));
          } finally {
            setLoadingDefenses(false);
          }
        }
      }
    } catch (err) {
      setError(parseApiError(err));
    } finally {
      setLoadingDetail(false);
    }
  };

  const extractCveFromEntity = (entity: EntityDetail['entity']): string | null => {
    const text = `${entity.name || ''} ${(entity.aliases || []).join(' ')} ${entity.properties?.external_id || ''} ${entity.id || ''}`;
    const match = text.match(/CVE-\d{4}-\d{4,7}/i);
    return match ? match[0].toUpperCase() : null;
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    loadEntities();
  };

  return (
    <div className="space-y-6">
      {/* Search and Filters */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">Knowledge Graph Entity Directory</h2>
              <p className="text-[11px] text-slate-400">Browse authenticated threat entities and inspect 1-hop connections</p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {FILTER_LABELS.map((lbl) => (
            <button
              key={lbl}
              onClick={() => setSelectedLabel(lbl)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                selectedLabel === lbl
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {lbl}
            </button>
          ))}
        </div>

        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="Search entity name or unique ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold flex items-center gap-1.5"
          >
            <Search className="w-4 h-4" />
            <span>Search</span>
          </button>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-900 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Two Column Layout: List & Details */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-start">
        {/* Left Column: Entity List */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-xl max-h-[600px] overflow-y-auto space-y-2">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider mb-2">
            Entities Found ({entities.length})
          </div>

          {loadingList ? (
            <div className="p-8 text-center">
              <LoadingSpinner size="sm" label="Loading entities..." />
            </div>
          ) : entities.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500">
              No entities found matching search criteria.
            </div>
          ) : (
            entities.map((ent) => {
              const isSelected = selectedEntityId === ent.id;
              return (
                <div
                  key={ent.id}
                  onClick={() => handleSelectEntity(ent.id)}
                  className={`p-3 rounded-lg border text-xs cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-slate-950 border-cyan-500 text-cyan-300 shadow-sm'
                      : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-slate-100 truncate">{ent.name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-900 text-slate-400 border border-slate-800 font-mono">
                      {ent.label}
                    </span>
                  </div>
                  <div className="text-[10px] font-mono text-slate-500 truncate">{ent.id}</div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column: Entity Details & 1-Hop Neighbors */}
        <div className="md:col-span-2 space-y-4">
          {loadingDetail ? (
            <div className="p-16 text-center bg-slate-900 border border-slate-800 rounded-xl">
              <LoadingSpinner size="md" label="Loading entity connections & provenance..." />
            </div>
          ) : entityDetail ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-5">
              {/* Entity Header */}
              <div className="pb-4 border-b border-slate-800">
                <div className="flex items-center gap-2 mb-1">
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                    {entityDetail.entity.label}
                  </span>
                  <span className="text-xs font-mono text-slate-500">{entityDetail.entity.id}</span>
                </div>
                <h3 className="text-lg font-bold text-slate-100">{entityDetail.entity.name}</h3>
                {entityDetail.entity.description && (
                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                    {entityDetail.entity.description}
                  </p>
                )}
                {entityDetail.entity.aliases && entityDetail.entity.aliases.length > 0 && (
                  <div className="flex items-center gap-1.5 mt-2 text-xs">
                    <span className="text-slate-500 text-[11px]">Aliases:</span>
                    {entityDetail.entity.aliases.map((a, i) => (
                      <span key={i} className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 text-[10px] font-mono">
                        {a}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Enriched Vulnerability Intelligence Card */}
              {entityDetail.entity.label === 'Vulnerability' && (() => {
                const cve = extractCveFromEntity(entityDetail.entity);
                return cve ? (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      Sourced Vulnerability Intelligence (CVSS / EPSS / CISA KEV)
                    </h4>
                    <VulnerabilityCard cveId={cve} />
                  </div>
                ) : null;
              })()}

              {/* MITRE D3FEND Defensive Recommendations Panel */}
              {entityDetail.entity.label === 'Technique' && (
                <div className="space-y-2">
                  <DefensesPanel
                    defenseData={techniqueDefenses}
                    loading={loadingDefenses}
                    error={techniqueDefensesError}
                  />
                </div>
              )}

              {/* 1-Hop Connected Relationships */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                  Documented Connections & Evidence ({entityDetail.relationships.length})
                </h4>

                <div className="space-y-2.5">
                  {entityDetail.relationships.length === 0 ? (
                    <p className="text-xs text-slate-500 italic">No connected edges documented for this node.</p>
                  ) : (
                    entityDetail.relationships.map((rel, idx) => (
                      <div key={idx} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-cyan-300 font-semibold">
                            ({rel.source_name}) -[{rel.rel_type}]-&gt; ({rel.target_name})
                          </span>
                          <span className="text-[10px] text-slate-500 uppercase">{rel.target_label}</span>
                        </div>
                        {rel.provenance?.evidence_text && (
                          <blockquote className="p-2 rounded bg-slate-900 text-slate-300 text-[11px] italic border-l-2 border-l-cyan-500 mt-1">
                            "{rel.provenance.evidence_text}"
                          </blockquote>
                        )}
                        {rel.provenance?.source_id && (
                          <div className="text-[10px] text-slate-500 font-mono">
                            Source: {rel.provenance.source_id}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-500">
              Select an entity from the directory to inspect its details and connections.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
