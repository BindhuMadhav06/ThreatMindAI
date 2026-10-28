import React from 'react';
import { Header } from './Header';
import { Sidebar, NavTab } from './Sidebar';
import { SystemHealth } from '../../types/api';

interface ShellProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  health: SystemHealth | null;
  loading: boolean;
  error: string | null;
  children: React.ReactNode;
}

export const Shell: React.FC<ShellProps> = ({
  currentTab,
  onTabChange,
  health,
  loading,
  error,
  children,
}) => {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header health={health} loading={loading} error={error} />
      <div className="flex-1 flex overflow-hidden">
        <Sidebar currentTab={currentTab} onTabChange={onTabChange} />
        <main className="flex-1 overflow-y-auto bg-slate-950/60 p-6">
          <div className="max-w-7xl mx-auto">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};
