import React from 'react';
import { Loader2 } from 'lucide-react';

interface LoadingSpinnerProps {
  label?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  label = 'Processing...',
  size = 'md',
  className = '',
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  };

  return (
    <div className={`flex items-center justify-center gap-2.5 text-slate-400 ${className}`} role="status">
      <Loader2 className={`animate-spin text-cyan-400 ${sizeClasses[size]}`} />
      {label && <span className="text-xs font-mono">{label}</span>}
      <span className="sr-only">{label}</span>
    </div>
  );
};
