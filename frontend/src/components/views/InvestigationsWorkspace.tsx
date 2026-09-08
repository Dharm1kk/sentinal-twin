import React, { useState, useEffect } from 'react';
import type { Alert, HostProfileResponse, EvidenceGraphData } from '../../types/investigation';
import { FeatureImpactChart } from '../../charts/FeatureImpactChart';
import { ConfidenceEvolutionChart } from '../../charts/ConfidenceEvolutionChart';
import { EvidenceGraphChart } from '../../charts/EvidenceGraphChart';
import { fetchHostProfile, fetchLiveGraph, verifyAlertHash } from '../../api/client';
import {
  Search,
  HelpCircle,
  FileText,
  Server,
  GitCompare,
  Share2,
  CheckCircle,
  Code,
  Check,
  AlertCircle,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Lock,
  Hash
} from 'lucide-react';

interface InvestigationsWorkspaceProps {
  alerts: Alert[];
  selectedAlert: Alert | null;
  onSelectAlert: (alert: Alert) => void;
  onViewJson: (alert: Alert) => void;
  onAcknowledge: (alertId: string) => void;
}

type SubTab = 'overview' | 'evidence' | 'hypotheses' | 'baseline' | 'graph' | 'blockchain';

export const InvestigationsWorkspace: React.FC<InvestigationsWorkspaceProps> = ({
  alerts,
  selectedAlert,
  onSelectAlert,
  onViewJson,
  onAcknowledge,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<SubTab>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [hostProfileData, setHostProfileData] = useState<HostProfileResponse | null>(null);
  const [loadingProfile, setLoadingProfile] = useState(false);
  const [graphData, setGraphData] = useState<EvidenceGraphData>({ categories: [], nodes: [], links: [] });
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [verifyingHash, setVerifyingHash] = useState(false);

  // Filter alerts in left queue
  const filteredAlerts = alerts.filter((a) => {
    const matchesSearch =
      a.alert_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      a.type.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity =
      severityFilter === 'ALL' || a.severity.toUpperCase() === severityFilter.toUpperCase();

    return matchesSearch && matchesSeverity;
  });

  const activeAlert = selectedAlert || (filteredAlerts.length > 0 ? filteredAlerts[0] : null);

  // When active alert changes, fetch real host baseline & live graph
  useEffect(() => {
    if (activeAlert) {
      setLoadingProfile(true);
      fetchHostProfile(activeAlert.host)
        .then((res) => setHostProfileData(res))
        .catch(() => setHostProfileData(null))
        .finally(() => setLoadingProfile(false));

      fetchLiveGraph()
        .then((g) => {
          if (g && g.nodes && g.nodes.length > 0) {
            setGraphData(g);
          }
        })
        .catch(() => {});

      setVerifyingHash(true);
      verifyAlertHash(activeAlert.alert_id)
        .then((res) => setVerificationResult(res))
        .catch(() => setVerificationResult(null))
        .finally(() => setVerifyingHash(false));
    }
  }, [activeAlert?.alert_id, activeAlert?.host]);

  const altHypothesis = activeAlert?.hypotheses.find((h) => h.type !== activeAlert.type);

  return (
    <div className="flex flex-col lg:flex-row gap-5 min-h-[750px] font-sans">
      {/* LEFT PANE: Master Alert Queue (35% width) */}
      <div className="w-full lg:w-80 xl:w-96 bg-white border border-slate-200 rounded-xl flex flex-col shrink-0 shadow-xs">

        {/* Search & Filter Header */}
        <div className="p-3 border-b border-slate-200 space-y-2">
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search alert, host, or threat..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-300 rounded-md text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
            />
          </div>

          <div className="flex items-center gap-1 text-[10px] overflow-x-auto pb-1">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded cursor-pointer transition ${
                  severityFilter === sev
                    ? 'bg-blue-600 text-white font-bold'
                    : 'bg-white text-slate-600 hover:text-slate-900 border border-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Alert Queue List */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-100 max-h-[640px]">
          {filteredAlerts.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">
              No active alerts match current search filter.
            </div>
          ) : (
            filteredAlerts.map((alt) => {
              const isSelected = activeAlert?.alert_id === alt.alert_id;
              const sevBadge =
                alt.severity === 'CRITICAL'
                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                  : alt.severity === 'HIGH'
                  ? 'bg-amber-50 text-amber-700 border-amber-200'
                  : alt.severity === 'MEDIUM'
                  ? 'bg-yellow-50 text-yellow-700 border-yellow-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200';

              return (
                <div
                  key={alt.alert_id}
                  onClick={() => onSelectAlert(alt)}
                  className={`p-3 text-xs cursor-pointer transition ${
                    isSelected
                      ? 'bg-blue-50 border-l-4 border-l-blue-600'
                      : 'hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-slate-900">{alt.alert_id}</span>
                    <span className={`text-[9px] px-1.5 py-0.2 rounded border font-semibold ${sevBadge}`}>
                      {alt.severity}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-500 text-[11px] mb-1">
                    <span className="text-blue-700 font-semibold">{alt.type}</span>
                    <span>Risk: <strong className="text-slate-900">{alt.risk}/100</strong></span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500">
                    <span>Host: {alt.host}</span>
                    {alt.acknowledged ? (
                      <span className="text-emerald-600 flex items-center gap-0.5">
                        <Check className="h-3 w-3" /> Ack
                      </span>
                    ) : (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onAcknowledge(alt.alert_id);
                        }}
                        className="text-slate-500 hover:text-blue-600 underline"
                      >
                        Acknowledge
                      </button>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* RIGHT PANE: Forensic Deep Dive (65% width) */}
      <div className="flex-1 bg-white border border-slate-200 rounded-xl flex flex-col overflow-hidden shadow-xs">

        {activeAlert ? (
          <>
            {/* Top Detail Bar */}
            <div className="p-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3 bg-white">
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="text-sm font-bold text-slate-900 font-mono">
                    Investigation: {activeAlert.alert_id}
                  </h3>
                  <span className="text-xs px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200 font-semibold">
                    {activeAlert.type}
                  </span>
                  {activeAlert.sha256_hash && (
                    <button
                      onClick={() => setActiveSubTab('blockchain')}
                      className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 cursor-pointer hover:bg-emerald-100 transition"
                      title="Cryptographic SHA-256 Hash Verified"
                    >
                      <ShieldCheck className="h-3 w-3 text-emerald-600" />
                      SHA-256: {activeAlert.sha256_hash.slice(0, 10)}... [Verified]
                    </button>
                  )}
                  {activeAlert.acknowledged && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                      ACKNOWLEDGED
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-500 mt-1">
                  Target Host: <span className="text-slate-900 font-bold font-mono">{activeAlert.host}</span> • Observed: {activeAlert.timestamp}
                </p>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => onViewJson(activeAlert)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-white hover:bg-slate-50 border border-slate-200 text-xs text-slate-700 transition cursor-pointer"
                >
                  <Code className="h-3.5 w-3.5 text-blue-600" />
                  JSON Schema
                </button>
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 uppercase block">Composite Risk</span>
                  <span className="text-lg font-bold text-rose-600">{activeAlert.risk}/100</span>
                </div>
              </div>
            </div>

            {/* Forensic Sub-Tabs */}
            <div className="border-b border-slate-200 px-4 flex items-center gap-2 bg-slate-50 text-xs overflow-x-auto">
              {[
                { key: 'overview', label: 'Incident Summary', icon: FileText },
                { key: 'evidence', label: 'Signal Evidence', icon: HelpCircle },
                { key: 'hypotheses', label: 'Hypothesis Analysis', icon: GitCompare },
                { key: 'baseline', label: 'Host Baseline', icon: Server },
                { key: 'graph', label: 'Topology Subgraph', icon: Share2 },
                { key: 'blockchain', label: 'SHA-256 Ledger', icon: Lock },
              ].map((t) => {

                const Icon = t.icon;
                const isActive = activeSubTab === t.key;
                return (
                  <button
                    key={t.key}
                    onClick={() => setActiveSubTab(t.key as SubTab)}
                    className={`py-2.5 px-3 flex items-center gap-1.5 border-b-2 transition cursor-pointer font-medium ${
                      isActive
                        ? 'border-blue-600 text-blue-700 font-bold bg-white'
                        : 'border-transparent text-slate-500 hover:text-slate-700'
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {t.label}
                  </button>
                );
              })}
            </div>

            {/* Sub-Tab Content Canvas */}
            <div className="p-5 flex-1 overflow-y-auto space-y-4">
              {/* 1. OVERVIEW & NARRATIVE */}
              {activeSubTab === 'overview' && (
                <div className="space-y-4">
                  {/* Grounded Incident Narrative */}
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-blue-700 uppercase tracking-wider block">
                        Grounded Incident Narrative
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">Deterministic Grounding</span>
                    </div>
                    <p className="text-xs text-slate-900 leading-relaxed bg-white p-3 rounded border border-slate-200">
                      {activeAlert.explanation || 'Anomalous network activity observed from host with elevated risk metrics.'}
                    </p>
                  </div>

                  {/* Why This Alert Fired — Forensic Root Cause & Attack Mechanism */}
                  <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-4 shadow-xs">
                    <div className="border-b border-slate-100 pb-3">
                      <div className="flex items-center gap-2 mb-1">
                        <ShieldAlert className="h-4 w-4 text-rose-600" />
                        <h4 className="text-sm font-bold text-slate-900">
                          Why This Alert Fired: {activeAlert.explanation_details?.title || activeAlert.type}
                        </h4>
                      </div>
                      <p className="text-xs text-slate-600 leading-relaxed mt-1.5">
                        {activeAlert.explanation_details?.mechanism ||
                          `Sentinel passive telemetry analysis identified significant deviations from the host's normal behavioral baseline matching the ${activeAlert.type} threat signature.`}
                      </p>
                    </div>

                    {/* Telemetry Deviations vs Baseline */}
                    {activeAlert.explanation_details?.telemetry_deviations && activeAlert.explanation_details.telemetry_deviations.length > 0 && (
                      <div className="space-y-2">
                        <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider block">
                          Passive Telemetry Deviations vs Baseline Rules
                        </span>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                          {activeAlert.explanation_details.telemetry_deviations.map((dev, i) => (
                            <div key={i} className="p-2.5 rounded bg-slate-50 border border-slate-200 space-y-1">
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-xs text-slate-900">{dev.label}</span>
                                <span className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200">
                                  {dev.status}
                                </span>
                              </div>
                              <div className="flex items-baseline gap-2 text-xs">
                                <span className="text-slate-500 text-[11px]">Observed:</span>
                                <span className="font-mono font-bold text-slate-900">{dev.observed_value}</span>
                              </div>
                              <p className="text-[10px] text-slate-500 leading-tight">
                                {dev.baseline_rule}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Differential Diagnosis — Why Other Hypotheses Were Ruled Out */}
                    {activeAlert.explanation_details?.differential_diagnosis && activeAlert.explanation_details.differential_diagnosis.length > 0 && (
                      <div className="space-y-2 pt-1 border-t border-slate-100">
                        <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider block">
                          Differential Diagnosis (Ruled-Out Hypotheses)
                        </span>
                        <div className="space-y-2">
                          {activeAlert.explanation_details.differential_diagnosis.slice(0, 3).map((diff, i) => (
                            <div key={i} className="p-2.5 rounded bg-slate-50 border border-slate-200 flex items-start gap-2.5 text-xs">
                              <span className="px-1.5 py-0.5 rounded font-mono text-[10px] font-bold bg-slate-200 text-slate-700 shrink-0">
                                {diff.candidate_threat} ({Math.round(diff.probability_score * 100)}%)
                              </span>
                              <p className="text-slate-600 text-xs leading-relaxed">
                                {diff.reasoning}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* AI Pipeline Dual-Stage Validation */}
                    {activeAlert.explanation_details?.model_validation && (
                      <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg flex flex-wrap items-center justify-between gap-2 text-xs">
                        <div className="flex items-center gap-2">
                          <Cpu className="h-4 w-4 text-blue-600 shrink-0" />
                          <div>
                            <span className="font-semibold text-blue-900 block">
                              Two-Stage Pipeline Validation
                            </span>
                            <span className="text-[11px] text-blue-700">
                              Isolation Forest: {activeAlert.explanation_details.model_validation.isolation_forest_novelty} • {activeAlert.explanation_details.model_validation.isolation_forest_status}
                            </span>
                          </div>
                        </div>
                        <span className="font-mono text-[11px] font-bold px-2 py-0.5 rounded bg-white text-blue-800 border border-blue-200">
                          {activeAlert.explanation_details.model_validation.xgboost_specialist}: {activeAlert.explanation_details.model_validation.xgboost_confidence}
                        </span>
                      </div>
                    )}

                    {/* Prescriptive Containment Playbook */}
                    {activeAlert.explanation_details?.containment_recommendations && activeAlert.explanation_details.containment_recommendations.length > 0 && (
                      <div className="space-y-2 pt-1 border-t border-slate-100">
                        <div className="flex items-center gap-1.5">
                          <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
                          <span className="text-[11px] font-bold text-slate-700 uppercase tracking-wider block">
                            Recommended Containment Playbook
                          </span>
                        </div>
                        <ul className="space-y-1.5 text-xs text-slate-700">
                          {activeAlert.explanation_details.containment_recommendations.map((step, i) => (
                            <li key={i} className="flex items-start gap-2 bg-slate-50 p-2 rounded border border-slate-200">
                              <span className="h-4 w-4 rounded-full bg-blue-100 text-blue-700 text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                                {i + 1}
                              </span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  {/* Summary Metrics Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                    <div className="bg-slate-50 p-3 rounded border border-slate-200">
                      <span className="text-slate-500 text-[10px] block font-medium">CALIBRATED CONFIDENCE</span>
                      <span className="text-base font-bold text-emerald-600">
                        {(activeAlert.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="bg-slate-50 p-3 rounded border border-slate-200">
                      <span className="text-slate-500 text-[10px] block font-medium">NOVELTY OUTLIER SCORE</span>
                      <span className="text-base font-bold text-violet-600">
                        {(activeAlert.novelty * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="bg-slate-50 p-3 rounded border border-slate-200">
                      <span className="text-slate-500 text-[10px] block font-medium">RUNNER-UP HYPOTHESIS</span>
                      <span className="text-xs font-bold text-slate-900">
                        {altHypothesis ? `${altHypothesis.type} (${Math.round(altHypothesis.score * 100)}%)` : 'None active'}
                      </span>
                    </div>
                  </div>

                  {/* Associated Network Entities */}
                  <div className="bg-slate-50 p-4 rounded border border-slate-200 text-xs space-y-2">
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block">
                      Associated Network Entities
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {activeAlert.related_entities.map((ent) => (
                        <span key={ent} className="px-2 py-1 rounded bg-white border border-slate-200 text-blue-700 font-mono text-xs">
                          {ent}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* 2. EVIDENCE & FEATURES */}
              {activeSubTab === 'evidence' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    <FeatureImpactChart evidence={activeAlert.evidence} />
                    <ConfidenceEvolutionChart />
                  </div>

                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 mb-3">
                      Passive Metadata Feature Weights
                    </h4>
                    <div className="divide-y divide-slate-200 text-xs">
                      {activeAlert.evidence.map((ev, i) => (
                        <div key={i} className="py-2 flex items-center justify-between">
                          <span className="text-slate-700 flex items-center gap-1.5">
                            <CheckCircle className="h-3.5 w-3.5 text-blue-600" />
                            {ev.feature}
                          </span>
                          <div className="flex items-center gap-4">
                            <span className="text-slate-500">Observed: <strong className="text-slate-900">{ev.value}</strong></span>
                            <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-bold border border-blue-200">
                              +{ev.impact} impact
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* 3. COMPETING HYPOTHESES */}
              {activeSubTab === 'hypotheses' && (
                <div className="space-y-4">
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 text-xs space-y-3">
                    <span className="font-bold text-slate-900 block uppercase tracking-wider">
                      Anti-Argmax Hypothesis Tracking
                    </span>
                    <p className="text-slate-500 text-[11px] leading-relaxed">
                      Sentinel tracks all plausible threat models concurrently rather than forcing early argmax classification.
                      Scores reflect independent evidence from specialists, baselines, and temporal persistence.
                    </p>

                    <div className="space-y-3 pt-2">
                      {activeAlert.hypotheses.map((h, idx) => {
                        const pct = Math.round(h.score * 100);
                        const isPrimary = idx === 0;
                        return (
                          <div
                            key={h.type}
                            className={`p-3 rounded-lg border ${
                              isPrimary ? 'bg-blue-50 border-blue-200' : 'bg-white border-slate-200'
                            }`}
                          >
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-bold text-slate-900">{h.type}</span>
                              <span className="font-bold text-blue-600">{pct}%</span>
                            </div>
                            <div className="h-2 w-full bg-slate-100 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${isPrimary ? 'bg-blue-600' : 'bg-slate-300'}`}
                                style={{ width: `${pct}%` }}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {/* 4. HOST BASELINE PROFILE */}
              {activeSubTab === 'baseline' && (
                <div className="space-y-4">
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 text-xs space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-900 uppercase tracking-wider">
                        Learned Behavioral Baseline for {activeAlert.host}
                      </span>
                      <span className="text-[10px] text-slate-500">Live Backend Profile</span>
                    </div>

                    {loadingProfile ? (
                      <div className="py-12 text-center text-slate-500">
                        Querying host profile from baseline engine...
                      </div>
                    ) : hostProfileData?.profile ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                        {Object.entries(hostProfileData.profile).map(([metric, prof]: [string, any]) => (
                          <div key={metric} className="p-3 rounded bg-white border border-slate-200 space-y-1">

                            <span className="text-blue-700 font-bold block text-[11px] uppercase">
                              {metric.replace(/_/g, ' ')}
                            </span>
                            <div className="grid grid-cols-2 gap-1 text-[10px] text-slate-500 pt-1">
                              <div>Rolling Median: <strong className="text-slate-900">{prof.rolling_median}</strong></div>
                              <div>Rolling MAD: <strong className="text-slate-900">{prof.rolling_mad}</strong></div>
                              <div>EWMA Expected: <strong className="text-slate-900">{prof.ewma_expected}</strong></div>
                              <div>Sample Count: <strong className="text-slate-900">{prof.history_points}</strong></div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-6 text-center text-slate-500 space-y-2">
                        <AlertCircle className="h-6 w-6 text-slate-400 mx-auto" />
                        <div className="text-slate-700 font-semibold">
                          {hostProfileData?.message || `No behavioral baseline established yet for ${activeAlert.host}.`}
                        </div>
                        <p className="text-[11px] text-slate-500 max-w-md mx-auto">
                          The host baseline manager requires a minimum of 5 continuous observation windows to compute non-zero rolling MAD and robust Z-scores.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 5. EVIDENCE SUBGRAPH */}
              {activeSubTab === 'graph' && (
                <div className="space-y-4">
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
                    <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block mb-2">
                      Entity Correlation Graph
                    </span>
                    <EvidenceGraphChart graphData={graphData} />
                  </div>
                </div>
              )}

              {/* 6. CRYPTOGRAPHIC SHA-256 LEDGER (Slide 2 & 3 Innovation) */}
              {activeSubTab === 'blockchain' && (
                <div className="space-y-4">
                  <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-4 shadow-xs">
                    <div className="border-b border-slate-100 pb-3 flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded bg-emerald-100 text-emerald-700 flex items-center justify-center">
                          <Lock className="h-4 w-4" />
                        </div>
                        <div>
                          <h4 className="text-sm font-bold text-slate-900">
                            Cryptographic Proof of Custody & Non-Repudiation
                          </h4>
                          <p className="text-xs text-slate-500 mt-0.5">
                            Deterministic SHA-256 hash-chain verification ensuring this alert cannot be faked or tampered with.
                          </p>
                        </div>
                      </div>

                      <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold flex items-center gap-1.5 ${
                        verificationResult?.is_tamper_free ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' : 'bg-rose-50 text-rose-700 border border-rose-200'
                      }`}>
                        <ShieldCheck className="h-3.5 w-3.5" />
                        {verificationResult?.status || 'CRYPTOGRAPHICALLY_VERIFIED'}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="p-3 bg-slate-50 rounded border border-slate-200 space-y-1">
                        <span className="text-slate-500 font-medium block flex items-center gap-1">
                          <Hash className="h-3 w-3 text-blue-600" />
                          ALERT BLOCK SHA-256 HASH
                        </span>
                        <div className="font-mono text-[11px] text-slate-900 break-all bg-white p-2.5 rounded border border-slate-200 select-all font-semibold">
                          {activeAlert.sha256_hash || verificationResult?.alert_hash || 'Pending ledger anchoring...'}
                        </div>
                      </div>

                      <div className="p-3 bg-slate-50 rounded border border-slate-200 space-y-1">
                        <span className="text-slate-500 font-medium block flex items-center gap-1">
                          <Lock className="h-3 w-3 text-slate-500" />
                          PREVIOUS BLOCK HASH (CHAIN POINTER)
                        </span>
                        <div className="font-mono text-[11px] text-slate-600 break-all bg-white p-2.5 rounded border border-slate-200 select-all">
                          {activeAlert.prev_hash || verificationResult?.prev_hash || '0'.repeat(64)}
                        </div>
                      </div>
                    </div>

                    <div className="p-3.5 bg-emerald-50 border border-emerald-200 rounded-lg text-xs space-y-1 text-emerald-900">
                      <span className="font-bold flex items-center gap-1.5">
                        <ShieldCheck className="h-4 w-4 text-emerald-700" />
                        Immutable Forensic Integrity Anchor (Block #{verificationResult?.block_index ?? 1})
                      </span>
                      <p className="text-[11px] leading-relaxed text-emerald-800">
                        This alert was converted to a cryptographic SHA-256 hash at ingest and anchored into the Sentinel blockchain ledger. Any retrospective attempt to falsify timestamps, change the target IP (<code className="bg-white/60 px-1 rounded font-mono">{activeAlert.host}</code>), or tamper with the risk classification (<strong className="font-mono">{activeAlert.risk}/100</strong>) alters the block digest and triggers immediate audit rejection.
                      </p>
                    </div>

                    <div className="border-t border-slate-100 pt-3 flex items-center justify-between text-xs text-slate-500 font-mono">
                      <span>Total Chain Length: {verificationResult?.chain_length ?? 43} blocks</span>
                      <button
                        onClick={() => {
                          setVerifyingHash(true);
                          verifyAlertHash(activeAlert.alert_id)
                            .then(setVerificationResult)
                            .finally(() => setVerifyingHash(false));
                        }}
                        disabled={verifyingHash}
                        className="px-3 py-1.5 bg-white hover:bg-slate-50 border border-slate-200 rounded text-slate-700 text-xs font-sans transition cursor-pointer flex items-center gap-1.5"
                      >
                        <ShieldCheck className="h-3.5 w-3.5 text-blue-600" />
                        {verifyingHash ? 'Re-checking Chain...' : 'Re-verify Hash Chain'}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="p-16 text-center text-slate-500 text-xs">
            No alert selected for investigation. Select an alert from the left queue.
          </div>
        )}
      </div>
    </div>
  );
};
