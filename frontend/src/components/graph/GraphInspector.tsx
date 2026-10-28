import React from 'react';
import { X, ExternalLink, Shield, Tag, FileText } from 'lucide-react';
import { VulnerabilityCard } from '../vulnerability/VulnerabilityCard';

export interface SelectedGraphItem {
  type: 'node' | 'edge';
  id: string;
  label: string;
  name?: string;
  source_name?: string;
  target_name?: string;
  properties?: Record<string, any>;
  provenance?: Record<string, any>;
  is_synthetic?: boolean;
}

interface GraphInspectorProps {
  item: SelectedGraphItem | null;
  onClose: () => void;
}

export const GraphInspector: React.FC<GraphInspectorProps> = ({ item, onClose }) => {
  if (!item) return null;

  const cveMatch =
    item.type === 'node' && (item.label === 'Vulnerability' || /CVE-\d{4}-\d{4,7}/i.test(item.name || item.id))
      ? `${item.name || ''} ${item.id} ${JSON.stringify(item.properties || {})}`.match(/CVE-\d{4}-\d{4,7}/i)
      : null;
  const cveId = cveMatch ? cveMatch[0].toUpperCase() : null;

  return (
    <div className="absolute top-4 right-4 z-20 w-80 sm:w-96 max-h-[calc(100%-2rem)] overflow-y-auto bg-slate-900/95 backdrop-blur-md border border-slate-800 rounded-xl p-4 shadow-2xl text-xs space-y-3">
      <div className="flex items-start justify-between pb-2 border-b border-slate-800">
        <div>
          <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-950 text-cyan-400 border border-slate-800">
            {item.type === 'node' ? item.label : `RELATIONSHIP [${item.label}]`}
          </span>
          <h3 className="font-semibold text-slate-100 mt-1 truncate">
            {item.name || `${item.source_name} → ${item.target_name}`}
          </h3>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          aria-label="Close inspector"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {item.is_synthetic && (
        <div className="p-2 rounded bg-amber-950/40 border border-amber-800/60 text-amber-300 text-[11px] font-mono">
          SYNTHETIC TEST FIXTURE ELEMENT
        </div>
      )}

      {item.type === 'node' ? (
        <div className="space-y-2 text-slate-300">
          <div>
            <span className="text-slate-500 text-[10px] uppercase block">Identifier:</span>
            <code className="text-slate-300 text-xs font-mono">{item.id}</code>
          </div>

          {item.properties?.description && (
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Description:</span>
              <p className="text-slate-300 leading-relaxed mt-0.5">{item.properties.description}</p>
            </div>
          )}

          {item.properties?.aliases && item.properties.aliases.length > 0 && (
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Known Aliases:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {item.properties.aliases.map((alias: string, i: number) => (
                  <span key={i} className="px-1.5 py-0.5 rounded bg-slate-950 text-slate-400 text-[10px]">
                    {alias}
                  </span>
                ))}
              </div>
            </div>
          )}

          {cveId && (
            <div className="pt-2 border-t border-slate-800">
              <VulnerabilityCard cveId={cveId} />
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-2.5 text-slate-300">
          <div>
            <span className="text-slate-500 text-[10px] uppercase block">Relationship:</span>
            <span className="font-mono text-cyan-300">
              ({item.source_name}) -[{item.label}]-&gt; ({item.target_name})
            </span>
          </div>

          {item.provenance?.evidence_text && (
            <div>
              <span className="text-slate-500 text-[10px] uppercase block flex items-center gap-1">
                <FileText className="w-3 h-3 text-cyan-400" />
                Supporting Evidence Quote:
              </span>
              <blockquote className="p-2 rounded bg-slate-950 text-slate-300 text-[11px] italic border-l-2 border-l-cyan-500 mt-1">
                "{item.provenance.evidence_text}"
              </blockquote>
            </div>
          )}

          {item.provenance?.source_id && (
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Source ID:</span>
              <code className="text-slate-400 text-[11px] font-mono">{item.provenance.source_id}</code>
            </div>
          )}

          {item.provenance?.source_url && (
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Source URL:</span>
              <a
                href={item.provenance.source_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:underline flex items-center gap-1 text-[11px] break-all mt-0.5"
              >
                <span>{item.provenance.source_url}</span>
                <ExternalLink className="w-3 h-3 shrink-0" />
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
