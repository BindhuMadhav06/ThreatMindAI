import React from 'react';
import {
  LayoutDashboard,
  Search,
  Network,
  UploadCloud,
  Layers,
  HelpCircle,
  ShieldAlert,
  Clock,
  ShieldCheck,
  Target,
} from 'lucide-react';

export type NavTab = 'dashboard' | 'investigation' | 'graph' | 'ingestion' | 'entities' | 'detection' | 'timeline' | 'quality' | 'organization';

interface SidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onTabChange }) => {
  const navItems = [
    {
      id: 'dashboard' as NavTab,
      label: 'Dashboard',
      icon: LayoutDashboard,
      description: 'System health & graph overview',
    },
    {
      id: 'investigation' as NavTab,
      label: 'Threat Investigation',
      icon: Search,
      description: 'Grounded Q&A & path reasoning',
    },
    {
      id: 'graph' as NavTab,
      label: 'Knowledge Graph',
      icon: Network,
      description: 'Cytoscape visual graph canvas',
    },
    {
      id: 'ingestion' as NavTab,
      label: 'CTI Ingestion',
      icon: UploadCloud,
      description: 'Parse & ground CTI documents',
    },
    {
      id: 'entities' as NavTab,
      label: 'Entity Explorer',
      icon: Layers,
      description: 'Browse actors, malware & CVEs',
    },
    {
      id: 'detection' as NavTab,
      label: 'Detection Engineering',
      icon: ShieldAlert,
      description: 'Sigma v2.1.0 rule generation',
    },
    {
      id: 'timeline' as NavTab,
      label: 'Attack Timeline',
      icon: Clock,
      description: 'Allen algebra interval ordering',
    },
    {
      id: 'quality' as NavTab,
      label: 'Intelligence Quality',
      icon: ShieldCheck,
      description: 'Grounding & dispute ledger',
    },
    {
      id: 'organization' as NavTab,
      label: 'Attack Simulation',
      icon: Target,
      description: 'Enterprise SBOM & D3FEND cut-sets',
    },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950 flex flex-col justify-between shrink-0">
      <nav className="p-3 space-y-1" aria-label="Main Navigation">
        <div className="px-3 py-2 text-[10px] font-semibold tracking-wider text-slate-500 uppercase">
          Workstation Navigation
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all text-left group ${
                isActive
                  ? 'bg-slate-900 text-cyan-400 border border-slate-700/80 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <Icon
                className={`w-4 h-4 shrink-0 transition-colors ${
                  isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-300'
                }`}
              />
              <div className="truncate">
                <div className="font-semibold leading-tight">{item.label}</div>
                <div className="text-[10px] text-slate-500 truncate">{item.description}</div>
              </div>
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-900 text-[11px] text-slate-500">
        <div className="flex items-center gap-1.5 mb-1 text-slate-400 font-medium">
          <HelpCircle className="w-3.5 h-3.5 text-slate-500" />
          <span>Analyst Protocol</span>
        </div>
        <p className="text-[10px] text-slate-600 leading-normal">
          All findings require traceable graph provenance. Connectivity does not guarantee real-world causality.
        </p>
      </div>
    </aside>
  );
};
