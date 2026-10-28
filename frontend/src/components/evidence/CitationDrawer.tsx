import React, { useEffect } from 'react';
import { AnswerCitation } from '../../types/api';
import { X, ExternalLink, FileText, Calendar, Building, Hash, ShieldCheck, AlertCircle } from 'lucide-react';
import { SyntheticNotice } from '../common/SyntheticNotice';

interface CitationDrawerProps {
  citation: AnswerCitation | null;
  isOpen: boolean;
  onClose: () => void;
}

export const CitationDrawer: React.FC<CitationDrawerProps> = ({
  citation,
  isOpen,
  onClose,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !citation) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-title"
    >
      {/* Backdrop click */}
      <div className="absolute inset-0" onClick={onClose} />

      <aside className="relative w-full max-w-lg bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 shadow-2xl flex flex-col justify-between z-10">
        <div>
          {/* Header */}
          <div className="flex items-start justify-between pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                  [{citation.citation_id}]
                </span>
                <span className="text-xs font-mono text-slate-400">
                  {citation.evidence_id}
                </span>
              </div>
              <h2 id="drawer-title" className="text-sm font-semibold text-slate-100">
                Evidence Provenance Record
              </h2>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              aria-label="Close drawer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Synthetic Disclosure */}
          {citation.is_synthetic && (
            <div className="mt-4">
              <SyntheticNotice />
            </div>
          )}

          {/* Verbatim Evidence Quote */}
          <div className="mt-5">
            <label className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 mb-2">
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              Verbatim Evidence Passage
            </label>
            <blockquote className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-slate-200 leading-relaxed font-serif italic border-l-4 border-l-cyan-500">
              "{citation.evidence_text}"
            </blockquote>
          </div>

          {/* Supported Relationship */}
          <div className="mt-5">
            <label className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-1.5 mb-2">
              <Hash className="w-3.5 h-3.5 text-cyan-400" />
              Supported Graph Relationship
            </label>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300">
              {citation.supported_relationship}
            </div>
          </div>

          {/* Source Metadata */}
          <div className="mt-5 space-y-3">
            <label className="text-[11px] font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              Source Information
            </label>

            <div className="rounded-lg bg-slate-950/50 border border-slate-800 p-3.5 space-y-2.5 text-xs">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Title:</span>
                <span className="font-medium text-slate-200">
                  {citation.source_title || 'Unavailable'}
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Publisher / Authority:</span>
                <div className="flex items-center gap-1.5 text-slate-300 mt-0.5">
                  <Building className="w-3.5 h-3.5 text-slate-500" />
                  <span>{citation.publisher || 'Unavailable'}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Publication Date:</span>
                <div className="flex items-center gap-1.5 text-slate-300 mt-0.5">
                  <Calendar className="w-3.5 h-3.5 text-slate-500" />
                  <span>{citation.published_date || 'Unavailable'}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Extraction Confidence:</span>
                <span className="font-mono text-slate-300">
                  {citation.confidence !== null && citation.confidence !== undefined
                    ? `${(citation.confidence * 100).toFixed(1)}%`
                    : 'Unknown (Not quantitatively calculated)'}
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Source URL / Reference:</span>
                {citation.source_url ? (
                  <a
                    href={citation.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 hover:underline break-all mt-0.5"
                  >
                    <span>{citation.source_url}</span>
                    <ExternalLink className="w-3 h-3 shrink-0" />
                  </a>
                ) : (
                  <span className="text-slate-500 italic">No external URL provided</span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-500">
          Source identifier: <code className="text-slate-400">{citation.source_id}</code>
        </div>
      </aside>
    </div>
  );
};
