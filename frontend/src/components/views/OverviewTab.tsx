import React, { useState, useEffect } from 'react';
import type { Alert, ThroughputMetrics, ActiveDatasetInfo } from '../../types/investigation';
import { ThreatDistributionChart } from '../../charts/ThreatDistributionChart';
import { TimelineAttackGraph } from '../../charts/TimelineAttackGraph';
import {
  ShieldCheck,
  AlertTriangle,
  Cpu,
  CheckCircle2,
  Search,
  Code,
  Check,
  Database,
  PlayCircle,
  Upload,
  Shield,
} from 'lucide-react';

interface OverviewTabProps {
  alerts: Alert[];
  metrics: ThroughputMetrics;
  riskIndex: number;
  activeDataset: ActiveDatasetInfo | null;
  onSelectAlert: (alert: Alert) => void;
  onViewJson: (alert: Alert) => void;
  onAcknowledge: (alertId: string) => void;
  onAnalyzeDataset: () => void;
  onOpenUpload: () => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  alerts,
  riskIndex,
  activeDataset,
  onSelectAlert,
  onViewJson,
  onAcknowledge,
  onAnalyzeDataset,
  onOpenUpload
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [visibleAlerts, setVisibleAlerts] = useState<Alert[]>(alerts);

  useEffect(() => {
    setVisibleAlerts(alerts);
  }, [alerts]);

  const displayAlerts = visibleAlerts.length > 0 ? visibleAlerts : alerts;

  const securityScore = activeDataset?.network_security_score ?? Math.max(0, 100 - riskIndex);
  const isNetworkAlertTriggered = activeDataset?.network_alert_triggered || securityScore < 50;

  const getSecurityScoreStatus = (score: number) => {
    if (score >= 80) return { label: 'OPTIMAL POSTURE', color: 'text-emerald-700', bg: 'bg-emerald-50 border-emerald-200' };
    if (score >= 50) return { label: 'HEALTHY / ELEVATED', color: 'text-amber-700', bg: 'bg-amber-50 border-amber-200' };
    if (score >= 25) return { label: 'CRITICAL THREAT ACTIVE', color: 'text-rose-700', bg: 'bg-rose-50 border-rose-200' };
    return { label: 'SYSTEM COMPROMISED', color: 'text-red-800', bg: 'bg-red-100 border-red-300' };
  };

  const scoreStatus = getSecurityScoreStatus(securityScore);

  const getSeverityBadge = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'HIGH':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'MEDIUM':
        return 'bg-yellow-50 text-yellow-700 border-yellow-200';
      default:
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
  };

  const criticalCount = displayAlerts.filter((a) => a.severity === 'CRITICAL').length;
  const highCount = displayAlerts.filter((a) => a.severity === 'HIGH').length;
  const novelCount = displayAlerts.filter((a) => a.type === 'NOVEL_BEHAVIOUR').length;

  const filteredAlerts = displayAlerts.filter((a) => {
    const matchesSearch =
      a.alert_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.type.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity =
      severityFilter === 'ALL' || a.severity.toUpperCase() === severityFilter.toUpperCase();
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6 font-sans">
      {/* Top Quick Setup if No Dataset or Alerts */}
      {!activeDataset && alerts.length === 0 && (
        <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200/80 rounded-xl p-6 shadow-xs">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Database className="h-5 w-5 text-blue-600" />
                <h3 className="font-bold text-slate-900 text-base">No Dataset Analyzed Yet</h3>
              </div>
              <p className="text-sm text-slate-600 max-w-2xl">
                Sentinel analyzes passive traffic datasets using 7 specialized threat classifiers, an unsupervised Isolation Forest anomaly lane, and an immutable SHA-256 alert hash chain.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={onAnalyzeDataset}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg transition shadow-xs cursor-pointer"
              >
                <PlayCircle className="h-4 w-4" />
                Generate & Analyze Dataset
              </button>
              <button
                onClick={onOpenUpload}
                className="flex items-center gap-2 px-4 py-2 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold rounded-lg border border-slate-200 transition shadow-xs cursor-pointer"
              >
                <Upload className="h-4 w-4 text-slate-500" />
                Upload CSV
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 4 Top KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 0-100 Network Security Score (Slide 2 & 3) */}
        <div className={`rounded-xl p-4 shadow-xs border transition-all ${isNetworkAlertTriggered ? 'bg-rose-50/40 border-rose-200' : 'bg-white border-slate-200'}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-500 tracking-wider">
              Network Security Score
            </span>
            <div className={`h-7 w-7 rounded-md flex items-center justify-center ${securityScore < 50 ? 'bg-rose-100 text-rose-700' : 'bg-emerald-50 text-emerald-600'}`}>
              <Shield className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-3xl font-bold font-mono ${securityScore < 50 ? 'text-rose-600' : 'text-slate-900'}`}>
              {securityScore}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="mt-2 flex items-center gap-1.5">
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${scoreStatus.bg} ${scoreStatus.color}`}>
              {scoreStatus.label}
            </span>
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-500 tracking-wider">
              Active Incidents
            </span>
            <div className="h-7 w-7 rounded-md bg-amber-50 flex items-center justify-center text-amber-600">
              <AlertTriangle className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-slate-900">{displayAlerts.length}</span>
            <span className="text-xs text-rose-600 font-medium">({criticalCount} Critical, {highCount} High)</span>
          </div>
          <p className="text-xs text-slate-500 mt-1">Multi-stage threats detected</p>
        </div>

        {/* Zero-Day Outliers */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-500 tracking-wider">
              Novelty Anomaly Lane
            </span>
            <div className="h-7 w-7 rounded-md bg-violet-50 flex items-center justify-center text-violet-600">
              <Cpu className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-violet-700">{novelCount}</span>
            <span className="text-xs text-slate-400 font-mono">outliers</span>
          </div>
          <p className="text-xs text-slate-500 mt-1">Isolation Forest zero-day lane</p>
        </div>

        {/* SHA-256 Blockchain Ledger Blocks */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-500 tracking-wider">
              SHA-256 Ledger
            </span>
            <div className="h-7 w-7 rounded-md bg-emerald-50 flex items-center justify-center text-emerald-600">
              <ShieldCheck className="h-4 w-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-emerald-700">
              {activeDataset?.ledger_blocks || alerts.length}
            </span>
            <span className="text-xs text-slate-400 font-mono">blocks</span>
          </div>
          <div className="mt-1 flex items-center gap-1 text-[11px] text-emerald-700 font-semibold">
            <CheckCircle2 className="h-3 w-3 text-emerald-600" />
            Cryptographically Anchored
          </div>
        </div>
      </div>

      {/* Chronological Attack Sequence & Timeline Graph */}
      <TimelineAttackGraph
        alerts={alerts}
        onSelectAlert={onSelectAlert}
        onVisibleAlertsChange={setVisibleAlerts}
      />

      {/* Main 2-Column Grid: Incidents Table + Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 sm:gap-6">
        {/* Left Column: Active Incidents Table (2 cols) */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-3.5 sm:p-5 shadow-xs space-y-3 sm:space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 sm:gap-3 border-b border-slate-100 pb-3 sm:pb-4">
            <div>
              <h3 className="text-xs sm:text-sm font-bold text-slate-900">
                Active Detections & Incident Triage
              </h3>
              <p className="text-[11px] sm:text-xs text-slate-500 mt-0.5">
                Calibrated multi-detector alerts with SHA-256 cryptographic chain proof.
              </p>
            </div>

            {/* Severity Filter Chips */}
            <div className="flex items-center gap-1 text-[11px] overflow-x-auto pb-1 max-w-full">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 sm:px-2.5 py-1 rounded-md font-medium transition cursor-pointer shrink-0 text-[10px] sm:text-xs ${
                    severityFilter === sev
                      ? 'bg-blue-600 text-white shadow-xs'
                      : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by Alert ID, Host IP, or Threat Class..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition"
            />
          </div>

          {/* Table */}
          <div className="overflow-x-auto rounded-lg border border-slate-100">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-500 font-semibold uppercase text-[10px] tracking-wider border-b border-slate-100">
                <tr>
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Host IP</th>
                  <th className="py-2.5 px-3">Threat Class</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-sans">
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-400 text-xs">
                      {alerts.length === 0
                        ? 'No alerts detected. Click "Generate & Analyze Dataset" above to run detection.'
                        : 'No alerts match the current filter.'}
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((a) => (
                    <tr key={a.alert_id} className="hover:bg-slate-50/80 transition group">
                      <td className="py-2.5 px-3 font-mono font-semibold text-blue-600">
                        <div className="flex items-center gap-1.5">
                          <span>{a.alert_id}</span>
                          {a.sha256_hash && (
                            <span title={`SHA-256: ${a.sha256_hash}`} className="inline-flex items-center text-[10px] text-emerald-600 bg-emerald-50 px-1 py-0.2 rounded border border-emerald-200">
                              #
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-700 font-medium">
                        {a.host}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded text-[11px] bg-slate-100 text-slate-700 font-medium font-mono">
                          {a.type}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                            a.severity
                          )}`}
                        >
                          {a.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-slate-600">
                        {(a.confidence * 100).toFixed(0)}%
                      </td>
                      <td className="py-2.5 px-3 font-mono font-bold text-slate-800">
                        {a.risk}
                      </td>
                      <td className="py-2.5 px-3 text-right space-x-1.5">
                        <button
                          onClick={() => onSelectAlert(a)}
                          className="px-2.5 py-1 bg-blue-50 hover:bg-blue-100 text-blue-700 rounded-md border border-blue-200 font-medium transition text-[11px] cursor-pointer"
                        >
                          Inspect
                        </button>
                        <button
                          onClick={() => onViewJson(a)}
                          title="View JSON Record"
                          className="px-2 py-1 bg-white hover:bg-slate-50 text-slate-600 rounded-md border border-slate-200 transition text-[11px] cursor-pointer"
                        >
                          <Code className="h-3 w-3 inline" />
                        </button>
                        {!a.acknowledged && (
                          <button
                            onClick={() => onAcknowledge(a.alert_id)}
                            title="Acknowledge Alert"
                            className="px-2 py-1 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 rounded-md border border-emerald-200 transition text-[11px] cursor-pointer"
                          >
                            <Check className="h-3 w-3 inline" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Threat Distribution */}
        <div>
          <ThreatDistributionChart alerts={displayAlerts} />
        </div>
      </div>
    </div>
  );
};
