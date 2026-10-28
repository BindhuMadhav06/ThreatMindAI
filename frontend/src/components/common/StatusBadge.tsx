import React from 'react';
import { GroundingStatus } from '../../types/api';
import { ShieldCheck, AlertTriangle, AlertCircle, XCircle } from 'lucide-react';

interface StatusBadgeProps {
  status: GroundingStatus;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className = '' }) => {
  switch (status) {
    case 'fully_grounded':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 ${className}`}
          title="All claims validated against retrieved graph evidence"
        >
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          Fully Grounded
        </span>
      );
    case 'partially_grounded':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-700/60 ${className}`}
          title="Some claims verified; some unverified or partial paths used"
        >
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          Partially Grounded
        </span>
      );
    case 'insufficient_evidence':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-slate-900 text-slate-300 border border-slate-700 ${className}`}
          title="Query abstained: No supporting entities or graph paths found"
        >
          <AlertCircle className="w-3.5 h-3.5 text-slate-400" />
          Insufficient Evidence
        </span>
      );
    case 'unsupported':
      return (
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-700/60 ${className}`}
          title="Claims failed verification checks against retrieved evidence"
        >
          <XCircle className="w-3.5 h-3.5 text-rose-400" />
          Unsupported Claims
        </span>
      );
    default:
      return (
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-300 ${className}`}>
          {status}
        </span>
      );
  }
};
