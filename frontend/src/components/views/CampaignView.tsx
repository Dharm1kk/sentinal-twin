import React from 'react';
import type { Campaign } from '../../types/investigation';
import { GitMerge, CheckCircle, AlertCircle } from 'lucide-react';


interface CampaignViewProps {
  campaigns: Campaign[];
}

export const CampaignView: React.FC<CampaignViewProps> = ({ campaigns }) => {
  return (
    <div className="space-y-6 font-sans">
      {/* Header Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
        <div className="flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-xl bg-rose-50 border border-rose-200 flex items-center justify-center text-rose-600 shadow-xs">
            <GitMerge className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-slate-900 text-base">Multi-Stage Attack Chains</h3>
              <span className="text-[11px] px-2 py-0.5 rounded bg-rose-50 text-rose-700 font-medium border border-rose-200">
                Correlated Campaigns
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Correlates isolated detections into multi-stage attack progression sequences (e.g. Recon &rarr; C2 &rarr; DNS Tunnel &rarr; Exfiltration).
            </p>
          </div>
        </div>
      </div>

      {/* Empty State */}
      {campaigns.length === 0 ? (
        <div className="bg-white border border-slate-200 rounded-xl p-12 text-center space-y-3 shadow-xs">
          <AlertCircle className="h-8 w-8 text-slate-400 mx-auto" />
          <h4 className="text-sm font-bold text-slate-800">No Multi-Stage Campaigns Correlated Yet</h4>
          <p className="text-xs text-slate-500 max-w-lg mx-auto leading-relaxed">
            Attack-chain correlation triggers when a monitored host triggers multiple sequential stages across related network paths in the analyzed dataset.
          </p>
        </div>
      ) : (
        /* Campaigns List */
        <div className="space-y-4">
          {campaigns.map((cmp) => (
            <div
              key={cmp.campaign_id}
              className="bg-white border border-slate-200 rounded-xl p-5 space-y-4 shadow-xs"
            >
              {/* Top Row: ID, Host, Severity, Risk */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-bold font-mono text-rose-700">{cmp.campaign_id}</span>
                  <span className="text-xs text-slate-500">
                    Victim Host: <span className="text-slate-900 font-mono font-bold">{cmp.host}</span>
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold px-2.5 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200">
                    {cmp.severity}
                  </span>
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-slate-50 text-slate-800 border border-slate-200">
                    Risk: {cmp.risk}/100
                  </span>
                </div>
              </div>

              {/* Narrative Box */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-700 leading-relaxed">
                {cmp.narrative}
              </div>

              {/* Attack Chain Stepper */}
              <div>
                <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider mb-2.5">
                  Multi-Stage Attack Sequence
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
                  {cmp.stages.map((stage, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs space-y-1.5 relative"
                    >
                      <div className="flex items-center justify-between text-[10px] text-slate-400 font-medium">
                        <span>STAGE {idx + 1}</span>
                        <CheckCircle className="h-3.5 w-3.5 text-emerald-600" />
                      </div>
                      <div className="font-semibold text-slate-900 text-xs">{stage}</div>
                      {cmp.correlated_alert_ids[idx] && (
                        <div className="text-[10px] text-blue-600 font-mono pt-1">
                          {cmp.correlated_alert_ids[idx]}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Correlated Alert Badges */}
              <div className="flex items-center gap-2 text-xs pt-1">
                <span className="text-slate-500 text-xs font-medium">Correlated Alerts:</span>
                <div className="flex flex-wrap gap-1.5">
                  {cmp.correlated_alert_ids.map((aid) => (
                    <span
                      key={aid}
                      className="px-2 py-0.5 rounded font-mono bg-blue-50 border border-blue-200 text-blue-700 text-[11px] font-semibold"
                    >
                      {aid}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
