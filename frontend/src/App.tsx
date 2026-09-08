import React, { useState, useEffect, useRef } from 'react';
import { Header } from './components/layout/Header';
import { Sidebar } from './components/layout/Sidebar';
import type { NavView } from './components/layout/Sidebar';

import { OverviewTab } from './components/views/OverviewTab';
import { EvidenceGraphView } from './components/views/EvidenceGraphView';
import { InvestigationsWorkspace } from './components/views/InvestigationsWorkspace';
import { NoveltyLane } from './components/views/NoveltyLane';
import { CampaignView } from './components/views/CampaignView';
import { AlertJsonModal } from './components/views/AlertJsonModal';
import { TrainingView } from './components/views/TrainingView';

import type {
  Alert,
  ThroughputMetrics,
  Campaign,
  EvidenceGraphData,
  ActiveDatasetInfo,
} from './types/investigation';
import {
  fetchAlerts,
  fetchThroughput,
  fetchLiveGraph,
  fetchCampaigns,
  fetchDatasetStatus,
  analyzeDataset,
  acknowledgeAlert,
} from './api/client';

export const App: React.FC = () => {
  const [activeView, setActiveView] = useState<NavView>('overview');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [activeDataset, setActiveDataset] = useState<ActiveDatasetInfo | null>(null);
  const [metrics, setMetrics] = useState<ThroughputMetrics>({
    timestamp: Date.now() / 1000,
    packets_per_sec: 0.0,
    flows_per_sec: 0.0,
    mbps: 0.0,
    latency_ms: 0.45,
    total_packets: 0,
    total_flows: 0,
    active_hosts: 0,
  });
  const [graphData, setGraphData] = useState<EvidenceGraphData>({ categories: [], nodes: [], links: [] });
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const selectedAlertIdRef = useRef<string | null>(null);
  const [jsonModalAlert, setJsonModalAlert] = useState<Alert | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  const loadData = async () => {
    try {
      const [alertsData, metricsData, gData, campData, statusData] = await Promise.all([
        fetchAlerts().catch(() => []),
        fetchThroughput().catch(() => null),
        fetchLiveGraph().catch(() => ({ categories: [], nodes: [], links: [] })),
        fetchCampaigns().catch(() => []),
        fetchDatasetStatus().catch(() => ({ active_dataset: null, alerts_count: 0, campaigns_count: 0, monitored_hosts: 0 })),
      ]);

      if (alertsData && alertsData.length > 0) {
        setAlerts(alertsData);
        if (!selectedAlertIdRef.current) {
          selectedAlertIdRef.current = alertsData[0].alert_id;
          setSelectedAlertId(alertsData[0].alert_id);
        }
      }
      if (metricsData) setMetrics(metricsData);
      if (gData && gData.nodes && gData.nodes.length > 0) setGraphData(gData);
      if (campData) setCampaigns(campData);
      if (statusData && statusData.active_dataset) {
        setActiveDataset(statusData.active_dataset);
      }
    } catch (err) {
      console.error('Error fetching data:', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleAnalyzeDataset = async () => {
    setIsProcessing(true);
    try {
      const res = await analyzeDataset();
      if (res && res.dataset_info) {
        setActiveDataset(res.dataset_info);
      }
      await loadData();
    } catch (err) {
      console.error('Dataset analysis error:', err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleAcknowledge = async (alertId: string) => {
    try {
      await acknowledgeAlert(alertId);
      setAlerts((prev) =>
        prev.map((a) => (a.alert_id === alertId ? { ...a, acknowledged: true } : a))
      );
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    }
  };

  const handleSelectAlert = (alert: Alert) => {
    selectedAlertIdRef.current = alert.alert_id;
    setSelectedAlertId(alert.alert_id);
    setActiveView('investigations');
  };

  const handleSelectNode = (nodeId: string) => {
    const matched = alerts.find(
      (a) => a.host === nodeId || a.related_entities?.includes(nodeId)
    );
    if (matched) {
      selectedAlertIdRef.current = matched.alert_id;
      setSelectedAlertId(matched.alert_id);
      setActiveView('investigations');
    }
  };

  const selectedAlert = alerts.find((a) => a.alert_id === selectedAlertId) || alerts[0] || null;

  const globalRisk = alerts.length > 0 ? Math.max(...alerts.map((a) => a.risk)) : (activeDataset?.composite_risk || 0);
  const novelCount = alerts.filter((a) => a.type === 'NOVEL_BEHAVIOUR').length;

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Header */}
      <Header
        activeDataset={activeDataset}
        riskIndex={globalRisk}
        onOpenUpload={() => setActiveView('training')}
        onAnalyzeDataset={handleAnalyzeDataset}
        isProcessing={isProcessing}
      />

      {/* Main Body: Sidebar + Workspace Canvas */}
      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          activeView={activeView}
          onSelectView={setActiveView}
          alertCount={alerts.length}
          novelCount={novelCount}
          campaignCount={campaigns.length}
        />

        <main className="flex-1 p-6 overflow-y-auto bg-slate-50">
          <div className="max-w-7xl mx-auto">
            {activeView === 'overview' && (
              <OverviewTab
                alerts={alerts}
                metrics={metrics}
                riskIndex={globalRisk}
                activeDataset={activeDataset}
                onSelectAlert={handleSelectAlert}
                onViewJson={(a) => setJsonModalAlert(a)}
                onAcknowledge={handleAcknowledge}
                onAnalyzeDataset={handleAnalyzeDataset}
                onOpenUpload={() => setActiveView('training')}
              />
            )}

            {activeView === 'evidence_graph' && (
              <EvidenceGraphView
                graphData={graphData}
                onSelectNode={handleSelectNode}
              />
            )}

            {activeView === 'investigations' && (
              <InvestigationsWorkspace
                alerts={alerts}
                selectedAlert={selectedAlert}
                onSelectAlert={handleSelectAlert}
                onViewJson={(a) => setJsonModalAlert(a)}
                onAcknowledge={handleAcknowledge}
              />
            )}

            {activeView === 'novelty' && (
              <NoveltyLane alerts={alerts} onSelectAlert={handleSelectAlert} />
            )}

            {activeView === 'campaigns' && <CampaignView campaigns={campaigns} />}

            {activeView === 'training' && (
              <TrainingView onDatasetAnalyzed={loadData} />
            )}
          </div>
        </main>
      </div>

      {/* Modals */}
      <AlertJsonModal
        alert={jsonModalAlert}
        onClose={() => setJsonModalAlert(null)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-2.5 px-6 text-center text-xs text-slate-400 font-sans">
        Sentinel • Passive Read-Only Cyber Threat Detection & Anomaly Platform
      </footer>
    </div>
  );
};

export default App;
