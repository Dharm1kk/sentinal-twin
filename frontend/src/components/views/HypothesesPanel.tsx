import React from 'react';
import type { Alert, Hypothesis } from '../../types/investigation';
import { GitCompare, Scale, AlertOctagon, CheckCircle2 } from 'lucide-react';

interface HypothesesPanelProps {
  selectedAlert?: Alert;
}

export const HypothesesPanel: React.FC<HypothesesPanelProps> = ({ selectedAlert }) => {
  const defaultHypotheses: Hypothesis[] = [
    { type: 'DNS_TUNNEL', score: 0.91 },
    { type: 'DGA', score: 0.38 },
    { type: 'DATA_EXFILTRATION', score: 0.24 },
    { type: 'C2', score: 0.12 },
  ];

  const hypotheses = selectedAlert?.hypotheses && selectedAlert.hypotheses.length > 0
    ? selectedAlert.hypotheses
    : defaultHypotheses;

  const topHypothesis = hypotheses[0];
  const runnerUp = hypotheses.length > 1 ? hypotheses[1] : null;

  return (
    <div className="space-y-5">
      {/* Header Banner */}
      <div className="bg-white border border-slate-200 rounded-lg p-4">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded bg-purple-50 border border-purple-200 flex items-center justify-center text-purple-600">
            <GitCompare className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold font-mono text-slate-900">Evidence Fusion & Competing Hypotheses</h3>
              <span className="text-[11px] px-2 py-0.5 rounded bg-purple-50 text-purple-700 font-mono border border-purple-200">
                Section 10: Anti-Argmax Principle
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5 font-mono">
              Sentinel avoids single-model argmax classifications. Multiple threat hypotheses are maintained concurrently
              until discriminating behavioral evidence separates them.
            </p>
          </div>
        </div>
      </div>

      {/* Mathematical Formulation Box */}
      <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 font-mono text-xs text-slate-700 space-y-2">
        <div className="flex items-center gap-2 text-cyan-700 font-bold uppercase text-[11px]">
          <Scale className="h-4 w-4" />
          Mathematical Fusion Equation
        </div>
        <div className="bg-white p-3 rounded border border-slate-200 text-slate-900 overflow-x-auto text-[11px] leading-relaxed">
          <code>
            hypothesis_score = w1·ML + w2·Baseline_Dev + w3·Temporal + w4·Graph + w5·Statistical + w6·Novelty - Contradiction_Penalty
          </code>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-[10px] text-slate-500 pt-1">
          <div>w1 (ML): <span className="text-slate-900 font-semibold">0.35</span></div>
          <div>w2 (Baseline): <span className="text-slate-900 font-semibold">0.25</span></div>
          <div>w3 (Temporal): <span className="text-slate-900 font-semibold">0.15</span></div>
          <div>w4 (Graph): <span className="text-slate-900 font-semibold">0.10</span></div>
          <div>w5 (Stat): <span className="text-slate-900 font-semibold">0.10</span></div>
          <div>w6 (Novel): <span className="text-slate-900 font-semibold">0.05</span></div>
        </div>
      </div>

      {/* Competing Hypotheses Visual Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-700 mb-3">
            Active Competing Threat Hypotheses
          </h4>

          <div className="space-y-4">
            {hypotheses.map((h, idx) => {
              const pct = Math.round(h.score * 100);
              const isWinner = idx === 0;

              return (
                <div
                  key={h.type}
                  className={`p-3 rounded-lg border font-mono ${
                    isWinner
                      ? 'bg-blue-50 border-blue-300'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-900">{h.type}</span>
                      {isWinner && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-blue-600 text-white font-bold">
                          PRIMARY LEADER
                        </span>
                      )}
                    </div>
                    <span className="font-bold text-sm text-cyan-600">{pct}%</span>
                  </div>

                  {/* Progress Bar */}
                  <div className="h-2 w-full bg-slate-200 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        isWinner ? 'bg-cyan-500' : 'bg-slate-400'
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Discrimination & Separation Analysis */}
        <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-4 font-mono text-xs">
          <h4 className="font-bold uppercase tracking-wider text-slate-700">
            Discriminative Feature Separation
          </h4>

          {runnerUp ? (
            <div className="space-y-3">
              <div className="p-3 rounded bg-slate-50 border border-slate-200 text-slate-700 leading-relaxed text-[11px]">
                <span className="font-bold text-slate-900">{topHypothesis.type}</span> ({Math.round(topHypothesis.score * 100)}%) vs{' '}
                <span className="font-bold text-slate-900">{runnerUp.type}</span> ({Math.round(runnerUp.score * 100)}%):
              </div>

              <div className="space-y-2">
                <div className="flex items-start gap-2 text-[11px] text-slate-700">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
                  <div>
                    <strong>Query Frequency & Parent Repeat:</strong> Traffic persists to a single parent domain with sustained high query rates, heavily penalizing the DGA hypothesis.
                  </div>
                </div>

                <div className="flex items-start gap-2 text-[11px] text-slate-700">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
                  <div>
                    <strong>Payload Length Ratio:</strong> Subdomain character lengths exceed 45 characters, consistent with encoded Base32/Base64 exfiltration tunneling.
                  </div>
                </div>

                <div className="flex items-start gap-2 text-[11px] text-slate-700">
                  <AlertOctagon className="h-4 w-4 text-amber-600 shrink-0 mt-0.5" />
                  <div>
                    <strong>Contradiction Applied:</strong> Absence of NXDOMAIN error responses applied a -0.40 penalty to the DGA classifier score.
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-slate-500 py-6 text-center">
              No competing threat hypothesis has accumulated sufficient evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
