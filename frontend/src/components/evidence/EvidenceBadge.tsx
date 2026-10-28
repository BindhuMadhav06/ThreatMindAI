import React from 'react';

interface EvidenceBadgeProps {
  citationId: string;
  onClick: (id: string) => void;
  className?: string;
}

export const EvidenceBadge: React.FC<EvidenceBadgeProps> = ({
  citationId,
  onClick,
  className = '',
}) => {
  return (
    <button
      type="button"
      onClick={() => onClick(citationId)}
      className={`inline-flex items-center px-1.5 py-0.5 mx-0.5 rounded text-[11px] font-mono font-semibold bg-cyan-950/70 text-cyan-300 border border-cyan-800/80 hover:bg-cyan-900 hover:text-cyan-200 transition-colors cursor-pointer select-none ${className}`}
      title={`Inspect evidence for [${citationId}]`}
    >
      [{citationId}]
    </button>
  );
};
