import React from 'react';
import { AnswerClaim } from '../../types/api';
import { EvidenceBadge } from '../evidence/EvidenceBadge';
import { CheckCircle2, AlertOctagon, ListOrdered } from 'lucide-react';

interface ClaimsListProps {
  claims: AnswerClaim[];
  onSelectCitation: (id: string) => void;
}

export const ClaimsList: React.FC<ClaimsListProps> = ({
  claims,
  onSelectCitation,
}) => {
  if (!claims || claims.length === 0) return null;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <ListOrdered className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">
            Granular Claim-Level Provenance ({claims.length})
          </h3>
        </div>
        <span className="text-[11px] text-slate-500 font-mono">
          {claims.filter((c) => c.verification_status === 'verified').length} / {claims.length} verified
        </span>
      </div>

      <div className="space-y-3">
        {claims.map((claim, idx) => {
          const isVerified = claim.verification_status === 'verified';
          return (
            <div
              key={idx}
              className={`p-3.5 rounded-lg border text-xs transition-colors ${
                isVerified
                  ? 'bg-slate-950 border-slate-800/90'
                  : 'bg-rose-950/20 border-rose-900/50'
              }`}
            >
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-center gap-2">
                  {isVerified ? (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/80">
                      <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                      VERIFIED
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950 text-rose-300 border border-rose-800/80">
                      <AlertOctagon className="w-3 h-3 text-rose-400" />
                      UNVERIFIED
                    </span>
                  )}
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-800 uppercase">
                    {claim.claim_type}
                  </span>
                </div>

                {/* Referenced Citation Badges */}
                <div className="flex flex-wrap items-center gap-1 shrink-0">
                  {(claim.evidence_references || []).map((ref, rIdx) => (
                    <EvidenceBadge
                      key={rIdx}
                      citationId={ref}
                      onClick={onSelectCitation}
                    />
                  ))}
                </div>
              </div>

              <p className="text-slate-200 leading-relaxed font-medium mb-1.5">
                {claim.claim_text}
              </p>

              {/* Validation Notes */}
              {claim.validation_reasons && claim.validation_reasons.length > 0 && (
                <div className="mt-2 pt-2 border-t border-slate-900 space-y-1">
                  {claim.validation_reasons.map((reason, reasonIdx) => (
                    <p
                      key={reasonIdx}
                      className={`text-[11px] leading-tight ${
                        isVerified ? 'text-slate-500' : 'text-rose-300/90'
                      }`}
                    >
                      • {reason}
                    </p>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
