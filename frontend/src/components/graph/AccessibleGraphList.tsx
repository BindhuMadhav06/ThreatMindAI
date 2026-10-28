import React from 'react';
import { EvidenceBackedPath } from '../../types/api';

interface AccessibleGraphListProps {
  paths?: EvidenceBackedPath[];
  className?: string;
}

export const AccessibleGraphList: React.FC<AccessibleGraphListProps> = ({
  paths = [],
  className = '',
}) => {
  if (!paths || paths.length === 0) return null;

  return (
    <div className={`mt-3 p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 ${className}`}>
      <h4 className="font-semibold text-slate-200 mb-2">
        Textual Graph Structure (Accessibility View)
      </h4>
      <ul className="space-y-2 list-disc list-inside">
        {paths.map((path) => (
          <li key={path.path_id} className="leading-relaxed">
            <span className="font-mono text-cyan-300 font-semibold">{path.path_id}: </span>
            {path.steps.map((step, idx) => (
              <span key={idx}>
                {idx > 0 ? ' then ' : ''}
                <strong>{step.source_name}</strong> ({step.source_label}){' '}
                <em>{step.rel_type.toLowerCase().replace(/_/g, ' ')}</em>{' '}
                <strong>{step.target_name}</strong> ({step.target_label})
              </span>
            ))}
          </li>
        ))}
      </ul>
    </div>
  );
};
