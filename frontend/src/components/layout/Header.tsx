import React from 'react';
import { Shield, PlayCircle, UploadCloud, RefreshCw, AlertTriangle } from 'lucide-react';
import type { ActiveDatasetInfo } from '../../types/investigation';

interface HeaderProps {
  activeDataset: ActiveDatasetInfo | null;
  riskIndex: number;
  onOpenUpload: () => void;
  onAnalyzeDataset: () => void;
  isProcessing: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeDataset,
  riskIndex,
  onOpenUpload,
  onAnalyzeDataset,
  isProcessing
}) => {
  const securityScore = activeDataset?.network_security_score ?? Math.max(0, 100 - riskIndex);
  const isNetworkAlert = activeDataset?.network_alert_triggered || securityScore < 50;

  const getSecurityScoreBadge = (score: number) => {
    if (score >= 80) return { label: 'OPTIMAL', bg: 'bg-emerald-50 text-emerald-700 border-emerald-200' };
    if (score >= 50) return { label: 'DEGRADED', bg: 'bg-amber-50 text-amber-700 border-amber-200' };
    if (score >= 25) return { label: 'CRITICAL', bg: 'bg-rose-50 text-rose-700 border-rose-200' };
    return { label: 'COMPROMISED', bg: 'bg-red-100 text-red-800 border-red-300' };
  };

  const scoreBadge = getSecurityScoreBadge(securityScore);

  return (
    <>
      <header className="bg-white border-b border-slate-200 px-6 py-3 sticky top-0 z-40 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4">
          {/* Brand and Console Identity */}
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight text-slate-900 font-sans">SENTINEL</span>
              </div>
              <p className="text-xs text-slate-500 font-sans">
                Passive Cyber Threat Detection & Anomaly Platform
              </p>
            </div>
          </div>

          {/* Right Stats & Action Controls */}
          <div className="flex items-center gap-3">
            {/* 0-100 Network Security Score (Slide 2 & 3) */}
            <div className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs">
              <span className="text-slate-500 text-[11px] font-medium">Security Score:</span>
              <span className={`font-bold font-mono text-sm ${securityScore < 50 ? 'text-rose-600' : 'text-emerald-700'}`}>
                {securityScore}/100
              </span>
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${scoreBadge.bg}`}>
                {scoreBadge.label}
              </span>
            </div>

            <button
              onClick={onAnalyzeDataset}
              disabled={isProcessing}
              className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 disabled:text-slate-500 text-white text-xs font-semibold px-3.5 py-2 rounded-lg transition shadow-xs cursor-pointer"
            >
              {isProcessing ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <PlayCircle className="h-3.5 w-3.5" />
              )}
              Analyze Dataset
            </button>

            <button
              onClick={onOpenUpload}
              className="flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold px-3.5 py-2 rounded-lg border border-slate-200 transition cursor-pointer"
            >
              <UploadCloud className="h-3.5 w-3.5 text-slate-500" />
              Train / Upload CSV
            </button>
          </div>
        </div>
      </header>

      {/* Network-Wide Critical Alert Banner (Slide 2: "If score goes low, sends a network wide alert") */}
      {isNetworkAlert && (
        <div className="bg-rose-600 text-white px-6 py-2 text-xs font-sans flex items-center justify-between shadow-xs sticky top-[61px] z-30 animate-pulse">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-white shrink-0" />
            <span className="font-bold tracking-wide uppercase">Network-Wide Alert:</span>
            <span>
              Enclave security health dropped to <strong className="font-mono">{securityScore}/100</strong>! Multiple severe threat signatures detected. Immediate host isolation recommended.
            </span>
          </div>
          <span className="text-[10px] font-mono bg-rose-700 px-2 py-0.5 rounded border border-rose-500">
            ACTION REQUIRED
          </span>
        </div>
      )}
    </>
  );
};

