import React from 'react';
import {
  LayoutDashboard,
  Clock,
  Server,
  Share2,
  GitCompare,
  HelpCircle,
  AlertTriangle,
  GitMerge
} from 'lucide-react';

export type TabKey =
  | 'overview'
  | 'timeline'
  | 'host'
  | 'graph'
  | 'hypotheses'
  | 'why_alert'
  | 'novelty'
  | 'campaigns';

interface NavigationProps {
  activeTab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  alertCount: number;
  campaignCount: number;
  novelCount: number;
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onSelectTab,
  alertCount,
  campaignCount,
  novelCount
}) => {
  const tabs: { key: TabKey; label: string; icon: React.ReactNode; count?: number; countColor?: string }[] = [
    { key: 'overview', label: '1. Overview & Triage', icon: <LayoutDashboard className="h-4 w-4" />, count: alertCount, countColor: 'bg-slate-800 text-slate-300' },
    { key: 'timeline', label: '2. Multi-Timescale Timeline', icon: <Clock className="h-4 w-4" /> },
    { key: 'host', label: '3. Host Baselines', icon: <Server className="h-4 w-4" /> },
    { key: 'graph', label: '4. Evidence Graph', icon: <Share2 className="h-4 w-4" /> },
    { key: 'hypotheses', label: '5. Competing Hypotheses', icon: <GitCompare className="h-4 w-4" /> },
    { key: 'why_alert', label: '6. "Why This Alert?"', icon: <HelpCircle className="h-4 w-4" /> },
    { key: 'novelty', label: '7. Novelty Lane', icon: <AlertTriangle className="h-4 w-4" />, count: novelCount, countColor: 'bg-amber-950 text-amber-400 border border-amber-800/80' },
    { key: 'campaigns', label: '8. Attack Chains', icon: <GitMerge className="h-4 w-4" />, count: campaignCount, countColor: 'bg-rose-950 text-rose-400 border border-rose-800/80' },
  ];

  return (
    <nav className="bg-slate-900/60 border-b border-slate-800 px-6 overflow-x-auto">
      <div className="flex items-center space-x-1 py-1">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => onSelectTab(tab.key)}
              className={`flex items-center gap-2 px-3.5 py-2.5 rounded-md text-xs font-medium transition cursor-pointer whitespace-nowrap ${
                isActive
                  ? 'bg-blue-600/15 text-blue-400 border-b-2 border-blue-500 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.count !== undefined && tab.count > 0 && (
                <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded ${tab.countColor || 'bg-slate-800 text-slate-300'}`}>
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
