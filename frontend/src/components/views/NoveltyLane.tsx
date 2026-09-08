import React from 'react';
import type { Alert } from '../../types/investigation';
import { Sparkles, Search } from 'lucide-react';


interface NoveltyLaneProps {
  alerts: Alert[];
  onSelectAlert: (alert: Alert) => void;
}

export const NoveltyLane: React.FC<NoveltyLaneProps> = ({ alerts, onSelectAlert }) => {
  const novelAlerts = alerts.filter((a) => a.type === 'NOVEL_BEHAVIOUR');

  return (
    <div className="space-y-6 font-sans">
      {/* Header Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-center text-amber-600 shadow-xs">
            <Sparkles className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-slate-900 text-base">Unsupervised Anomaly Lane</h3>
              <span className="text-[11px] px-2 py-0.5 rounded bg-amber-50 text-amber-700 font-medium border border-amber-200">
                Isolation Forest Outliers
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Traffic events scoring high Isolation Forest novelty (&gt; 0.55) without matching known signature families enter this zero-day triage queue.
            </p>
          </div>
        </div>
      </div>

      {/* Novel Events List */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <h4 className="text-sm font-bold text-slate-900">
            Active Outlier Events ({novelAlerts.length})
          </h4>
          <span className="text-xs text-slate-500">Unsupervised Cluster Candidates</span>
        </div>

        {novelAlerts.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            No unclassified novel behaviour detected in active dataset. All events match known threat baselines.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {novelAlerts.map((na) => (
              <div
                key={na.alert_id}
                className="bg-slate-50 border border-amber-200/80 rounded-xl p-4 text-xs space-y-3 hover:border-amber-400 transition shadow-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-amber-700">{na.alert_id}</span>
                  <span className="text-slate-400 text-[11px] font-mono">{na.timestamp}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase font-medium">Host IP</span>
                    <span className="text-slate-900 font-mono font-bold">{na.host}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase font-medium">Novelty Score</span>
                    <span className="text-amber-700 font-mono font-bold">{(na.novelty * 100).toFixed(0)}%</span>
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-white border border-slate-200 text-xs text-slate-700 leading-relaxed">
                  {na.explanation || 'Anomalous multi-variate feature vector outside normal baseline distribution.'}
                </div>

                <div className="flex items-center justify-between pt-1">
                  <span className="text-xs text-slate-500 font-mono font-semibold">Risk: {na.risk}/100</span>
                  <button
                    onClick={() => onSelectAlert(na)}
                    className="flex items-center gap-1 text-xs text-blue-700 hover:text-blue-800 font-semibold px-2.5 py-1 rounded-md bg-blue-50 border border-blue-200 cursor-pointer"
                  >
                    <Search className="h-3.5 w-3.5" />
                    Inspect Event
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
