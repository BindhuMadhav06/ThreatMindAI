import React, { useState, useEffect } from 'react';
import { CytoscapeGraph } from '../components/graph/CytoscapeGraph';
import { fetchEntities, fetchEntityDetails } from '../api/graph';
import { parseApiError } from '../api/client';
import { EntitySummary } from '../types/api';
import { Network, Search, Filter, AlertCircle, RefreshCw } from 'lucide-react';
import { LoadingSpinner } from '../components/common/LoadingSpinner';

const PRIMARY_LABELS = [
  'All Entities',
  'ThreatActor',
  'Malware',
  'Tool',
  'Vulnerability',
  'Technique',
  'Product',
  'Organization',
];

export const KnowledgeGraphPage: React.FC = () => {
  const [entities, setEntities] = useState<EntitySummary[]>([]);
  const [selectedEntityId, setSelectedEntityId] = useState<string>('');
  const [selectedLabel, setSelectedLabel] = useState<string>('All Entities');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [graphElements, setGraphElements] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load initial entities for exploration dropdown
  useEffect(() => {
    loadEntityDirectory();
  }, [selectedLabel]);

  const loadEntityDirectory = async () => {
    try {
      const labelParam = selectedLabel === 'All Entities' ? undefined : selectedLabel;
      const data = await fetchEntities({ label: labelParam, search: searchTerm || undefined, limit: 30 });
      setEntities(data);
      if (data.length > 0 && !selectedEntityId) {
        setSelectedEntityId(data[0].id);
        loadNeighborhood(data[0].id);
      }
    } catch (err) {
      setError(parseApiError(err));
    }
  };

  const loadNeighborhood = async (entityId: string) => {
    if (!entityId) return;
    setLoading(true);
    setError(null);

    try {
      const detail = await fetchEntityDetails(entityId);
      
      const nodesMap = new Map<string, any>();
      // Central entity
      nodesMap.set(detail.entity.id, {
        data: {
          id: detail.entity.id,
          name: detail.entity.name,
          label: detail.entity.label,
          color: '#38bdf8', // Bright cyan for selected root
          is_synthetic: detail.entity.is_synthetic,
          properties: detail.entity.properties,
        },
      });

      // Neighbors
      detail.neighbors.forEach((nbr) => {
        if (!nodesMap.has(nbr.id)) {
          nodesMap.set(nbr.id, {
            data: {
              id: nbr.id,
              name: nbr.name,
              label: nbr.label,
              is_synthetic: nbr.is_synthetic,
              properties: nbr.properties,
            },
          });
        }
      });

      // Edges
      const edges = detail.relationships.map((r) => ({
        data: {
          id: `${r.source_id}-${r.rel_type}-${r.target_id}`,
          source: r.source_id,
          target: r.target_id,
          label: r.rel_type,
          source_name: r.source_name,
          target_name: r.target_name,
          provenance: r.provenance,
          is_synthetic: r.is_synthetic,
        },
      }));

      setGraphElements([...Array.from(nodesMap.values()), ...edges]);
    } catch (err) {
      setError(parseApiError(err));
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadEntityDirectory();
  };

  return (
    <div className="space-y-6">
      {/* Header & Filter Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-base font-semibold text-slate-100">Knowledge Graph Explorer</h2>
              <p className="text-[11px] text-slate-400">Explore entity neighborhoods, attack links, and edge provenance</p>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          {/* Label Filter */}
          <div>
            <label className="text-[11px] text-slate-400 block mb-1 font-medium">Filter by Label:</label>
            <select
              value={selectedLabel}
              onChange={(e) => setSelectedLabel(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {PRIMARY_LABELS.map((lbl) => (
                <option key={lbl} value={lbl}>
                  {lbl}
                </option>
              ))}
            </select>
          </div>

          {/* Search Term */}
          <form onSubmit={handleSearchSubmit}>
            <label className="text-[11px] text-slate-400 block mb-1 font-medium">Search Entity Name:</label>
            <div className="flex gap-1.5">
              <input
                type="text"
                placeholder="e.g. APT29, Cobalt, Log4j..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg shrink-0 transition-colors"
                title="Search"
              >
                <Search className="w-4 h-4" />
              </button>
            </div>
          </form>

          {/* Select Entity Center */}
          <div>
            <label className="text-[11px] text-slate-400 block mb-1 font-medium">Center Graph on Entity:</label>
            <select
              value={selectedEntityId}
              onChange={(e) => {
                setSelectedEntityId(e.target.value);
                loadNeighborhood(e.target.value);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {entities.map((ent) => (
                <option key={ent.id} value={ent.id}>
                  [{ent.label}] {ent.name} ({ent.id})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-900 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Graph Visualizer Canvas */}
      {loading ? (
        <div className="p-16 text-center bg-slate-900 border border-slate-800 rounded-xl">
          <LoadingSpinner size="lg" label="Loading Graph Neighborhood from Neo4j..." />
        </div>
      ) : (
        <CytoscapeGraph
          customElements={graphElements}
          height="580px"
        />
      )}
    </div>
  );
};
