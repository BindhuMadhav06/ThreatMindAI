import React from 'react';
import { AlertCircle } from 'lucide-react';

interface SyntheticNoticeProps {
  className?: string;
  compact?: boolean;
}

export const SyntheticNotice: React.FC<SyntheticNoticeProps> = ({ className = '', compact = false }) => {
  if (compact) {
    return (
      <span
        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-950/60 text-amber-300 border border-amber-800/60 ${className}`}
        title="Demonstration data for integration and verification testing"
      >
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
        SYNTHETIC DATA
      </span>
    );
  }

  return (
    <div
      className={`flex items-start gap-3 p-3.5 rounded-lg bg-amber-950/30 border border-amber-800/60 text-amber-200/90 text-xs ${className}`}
      role="status"
    >
      <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
      <div>
        <p className="font-semibold text-amber-300 uppercase tracking-wider text-[11px] mb-0.5">
          Synthetic Demonstration Data Notice
        </p>
        <p className="text-amber-200/80 leading-relaxed">
          This investigation is grounded in synthetic demonstration test fixtures created for algorithm verification.
          Relationships and indicators must not be treated as real-world threat intelligence.
        </p>
      </div>
    </div>
  );
};
