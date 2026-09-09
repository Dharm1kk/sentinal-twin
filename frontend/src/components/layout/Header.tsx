import React from 'react';
import { Shield, PlayCircle, UploadCloud, RefreshCw, AlertTriangle, Menu, X } from 'lucide-react';
import type { ActiveDatasetInfo } from '../../types/investigation';

interface HeaderProps {
  activeDataset: ActiveDatasetInfo | null;
  riskIndex: number;
  onOpenUpload: () => void;
  onAnalyzeDataset: () => void;
  isProcessing: boolean;
  isMobileMenuOpen: boolean;
  onToggleMobileMenu: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeDataset,
  riskIndex,
  onOpenUpload,
  onAnalyzeDataset,
  isProcessing,
  isMobileMenuOpen,
  onToggleMobileMenu
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
      <header className="bg-white border-b border-slate-200 px-4 sm:px-6 py-2.5 sm:py-3 sticky top-0 z-40 shadow-xs">
        <div className="flex items-center justify-between gap-3">
          {/* Brand and Mobile Hamburger Toggle */}
          <div className="flex items-center gap-2.5 sm:gap-3">
            {/* Hamburger button visible only on mobile / tablet (< lg) */}
            <button
              onClick={onToggleMobileMenu}
              className="lg:hidden p-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 transition cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              {isMobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>

            <div className="h-8 w-8 sm:h-9 sm:w-9 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-xs shrink-0">
              <Shield className="h-4 w-4 sm:h-5 sm:w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm sm:text-base tracking-tight text-slate-900 font-sans">SENTINEL</span>
              </div>
              <p className="text-[10px] sm:text-xs text-slate-500 font-sans line-clamp-1 hidden sm:block">
                Passive Cyber Threat Detection & Anomaly Platform
              </p>
            </div>
          </div>

          {/* Right Stats & Action Controls */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* 0-100 Network Security Score */}
            <div className="flex items-center gap-1 sm:gap-1.5 px-2 sm:px-3 py-1 sm:py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs">
              <span className="text-slate-500 text-[10px] sm:text-[11px] font-medium hidden xs:inline">Score:</span>
              <span className={`font-bold font-mono text-xs sm:text-sm ${securityScore < 50 ? 'text-rose-600' : 'text-emerald-700'}`}>
                {securityScore}/100
              </span>
              <span className={`text-[9px] sm:text-[10px] font-bold px-1 sm:px-1.5 py-0.5 rounded border ${scoreBadge.bg} hidden md:inline`}>
                {scoreBadge.label}
              </span>
            </div>

            <button
              onClick={onAnalyzeDataset}
              disabled={isProcessing}
              className="flex items-center gap-1 sm:gap-1.5 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 disabled:text-slate-500 text-white text-[11px] sm:text-xs font-semibold px-2.5 sm:px-3.5 py-1.5 sm:py-2 rounded-lg transition shadow-xs cursor-pointer"
            >
              {isProcessing ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <PlayCircle className="h-3.5 w-3.5" />
              )}
              <span className="hidden xs:inline">Analyze Dataset</span>
              <span className="xs:hidden">Analyze</span>
            </button>

            <button
              onClick={onOpenUpload}
              className="hidden sm:flex items-center gap-1.5 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold px-3.5 py-2 rounded-lg border border-slate-200 transition cursor-pointer"
            >
              <UploadCloud className="h-3.5 w-3.5 text-slate-500" />
              Train / Upload
            </button>
          </div>
        </div>
      </header>

      {/* Network-Wide Critical Alert Banner */}
      {isNetworkAlert && (
        <div className="bg-rose-600 text-white px-4 sm:px-6 py-2 text-xs font-sans flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 shadow-xs sticky top-[53px] sm:top-[61px] z-30 animate-pulse">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-white shrink-0" />
            <span className="font-bold tracking-wide uppercase text-[11px] sm:text-xs">Network-Wide Alert:</span>
            <span className="text-[11px] sm:text-xs leading-tight">
              Security health dropped to <strong className="font-mono">{securityScore}/100</strong>! Severe threats active.
            </span>
          </div>
          <span className="self-start sm:self-auto text-[9px] sm:text-[10px] font-mono bg-rose-700 px-2 py-0.5 rounded border border-rose-500">
            ACTION REQUIRED
          </span>
        </div>
      )}
    </>
  );
};
