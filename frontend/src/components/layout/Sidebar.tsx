import React from 'react';
import {
  LayoutDashboard,
  FolderSearch,
  Sparkles,
  GitMerge,
  Share2,
  BrainCircuit
} from 'lucide-react';


export type NavView = 'overview' | 'investigations' | 'evidence_graph' | 'novelty' | 'campaigns' | 'training';

interface SidebarProps {
  activeView: NavView;
  onSelectView: (view: NavView) => void;
  alertCount: number;
  novelCount: number;
  campaignCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeView,
  onSelectView,
  alertCount,
  novelCount,
  campaignCount,
}) => {
  const navItems: {
    key: NavView;
    label: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number;
    badgeColor?: string;
  }[] = [
    {
      key: 'overview',
      label: 'Overview',
      description: 'Security posture & active alerts',
      icon: LayoutDashboard,
      badge: alertCount > 0 ? alertCount : undefined,
      badgeColor: 'bg-blue-100 text-blue-700',
    },
    {
      key: 'investigations',
      label: 'Alert Triage',
      description: 'Forensic incident workbench',
      icon: FolderSearch,
    },
    {
      key: 'evidence_graph',
      label: 'Network Topology',
      description: 'Entity relationship graph',
      icon: Share2,
    },
    {
      key: 'novelty',
      label: 'Anomaly Detection',
      description: 'Isolation Forest outlier lane',
      icon: Sparkles,
      badge: novelCount > 0 ? novelCount : undefined,
      badgeColor: 'bg-amber-100 text-amber-700',
    },
    {
      key: 'campaigns',
      label: 'Attack Chains',
      description: 'Correlated multi-stage incidents',
      icon: GitMerge,
      badge: campaignCount > 0 ? campaignCount : undefined,
      badgeColor: 'bg-rose-100 text-rose-700',
    },
    {
      key: 'training',
      label: 'Dataset & Training',
      description: 'CSV manager & ML pipeline',
      icon: BrainCircuit,
    }
  ];

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col shrink-0 font-sans">
      {/* Navigation Items */}
      <nav className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
          Navigation
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.key;

          return (
            <button
              key={item.key}
              onClick={() => onSelectView(item.key)}
              className={`w-full text-left px-3 py-2.5 rounded-lg flex items-center justify-between transition group cursor-pointer ${
                isActive
                  ? 'bg-blue-50 text-blue-700 font-semibold border border-blue-200/80 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`h-4 w-4 shrink-0 transition ${
                    isActive ? 'text-blue-600' : 'text-slate-400 group-hover:text-slate-600'
                  }`}
                />
                <div>
                  <div className="text-xs">{item.label}</div>
                  <div className="text-[11px] text-slate-400 font-normal">{item.description}</div>
                </div>
              </div>

              {item.badge !== undefined && (
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full font-mono ${item.badgeColor}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Passive Enclave Status */}
      <div className="p-4 border-t border-slate-200 text-xs text-slate-500 bg-slate-50/50 space-y-1.5 font-sans">
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-slate-400">Monitoring Mode</span>
          <span className="text-emerald-700 font-semibold text-[11px] bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
            Passive Diode
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-slate-400">Return Path</span>
          <span className="text-slate-600 text-[11px] font-mono">0 (Blocked)</span>
        </div>
      </div>
    </aside>
  );
};
