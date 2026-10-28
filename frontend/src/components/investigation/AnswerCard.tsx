import React, { useState } from 'react';
import { GroundedAnswer, GroundingStatus } from '../../types/api';
import { StatusBadge } from '../common/StatusBadge';
import { SyntheticNotice } from '../common/SyntheticNotice';
import { EvidenceBadge } from '../evidence/EvidenceBadge';
import {
  FileText,
  AlertTriangle,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  Tag,
} from 'lucide-react';

interface AnswerCardProps {
  answer: GroundedAnswer;
  groundingStatus: GroundingStatus;
  warnings: string[];
  unresolvedEntities: string[];
  onSelectCitation: (citationId: string) => void;
}

export const AnswerCard: React.FC<AnswerCardProps> = ({
  answer,
  groundingStatus,
  warnings,
  unresolvedEntities,
  onSelectCitation,
}) => {
  const [showCaveats, setShowCaveats] = useState(false);

  const renderTextWithCitations = (text: string) => {
    const regex = /\[CIT-\d+\]/g;
    const parts: React.ReactNode[] = [];
    let lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const preText = text.substring(lastIndex, match.index);
      if (preText) {
        parts.push(preText);
      }
      const citId = match[0].replace('[', '').replace(']', '');
      parts.push(
        <EvidenceBadge
          key={`cit-${match.index}`}
          citationId={citId}
          onClick={onSelectCitation}
        />
      );
      lastIndex = match.index + match[0].length;
    }

    const remaining = text.substring(lastIndex);
    if (remaining) {
      parts.push(remaining);
    }

    return parts;
  };

  if (!answer) return null;

  const isAbstention = answer.sufficiency_status === 'insufficient';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-5">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <FileText className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-100">
            Evidence-Grounded Investigation Findings
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={groundingStatus} />
          {answer.is_synthetic && <SyntheticNotice compact />}
        </div>
      </div>

      {/* Synthetic Banner */}
      {answer.is_synthetic && <SyntheticNotice />}

      {/* Executive Summary */}
      {answer.summary && (
        <div className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800/80">
          <h3 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
            Executive Summary
          </h3>
          <p className="text-xs text-slate-300 leading-relaxed font-medium">
            {answer.summary}
          </p>
        </div>
      )}

      {/* Direct Answer Narrative */}
      <div>
        <h3 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
          Direct Analysis & Evidence Attributions
        </h3>
        <div
          className={`p-4 rounded-lg leading-relaxed text-sm ${
            isAbstention
              ? 'bg-rose-950/20 border border-rose-900/60 text-rose-200'
              : 'bg-slate-950 border border-slate-800 text-slate-200'
          }`}
        >
          {renderTextWithCitations(answer.direct_answer)}
        </div>
      </div>

      {/* Unresolved Entities */}
      {unresolvedEntities && unresolvedEntities.length > 0 && (
        <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-start gap-2.5 text-xs">
          <Tag className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="text-slate-400 font-medium">Unresolved Candidate Entities:</span>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {unresolvedEntities.map((ent, idx) => (
                <span
                  key={idx}
                  className="px-2 py-0.5 rounded text-[11px] bg-slate-900 text-amber-300/90 border border-amber-900/40 font-mono"
                >
                  {ent}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Caveats and Warnings Accordion */}
      {(answer.caveats.length > 0 || warnings.length > 0) && (
        <div className="pt-2 border-t border-slate-800/60">
          <button
            type="button"
            onClick={() => setShowCaveats(!showCaveats)}
            className="w-full flex items-center justify-between text-xs text-slate-400 hover:text-slate-200 transition-colors py-1"
          >
            <span className="flex items-center gap-1.5 font-medium">
              <HelpCircle className="w-3.5 h-3.5 text-slate-500" />
              <span>Analytical Caveats & System Notices ({answer.caveats.length + warnings.length})</span>
            </span>
            {showCaveats ? (
              <ChevronUp className="w-4 h-4 text-slate-500" />
            ) : (
              <ChevronDown className="w-4 h-4 text-slate-500" />
            )}
          </button>

          {showCaveats && (
            <div className="mt-3 space-y-2 text-xs">
              {answer.caveats.map((c, i) => (
                <div key={`c-${i}`} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex items-start gap-2">
                  <span className="text-cyan-400 font-bold">•</span>
                  <span>{c}</span>
                </div>
              ))}
              {warnings.map((w, i) => (
                <div key={`w-${i}`} className="p-2.5 rounded bg-slate-950/80 border border-amber-900/40 text-amber-300/80 flex items-start gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <span>{w}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
