import type {
  Alert,
  ThroughputMetrics,
  TelemetrySample,
  EvidenceGraphData,
  InvestigationCase,
  Campaign,
  HostProfileResponse
} from '../types/investigation';

const API_BASE = '/api/v1';

export async function fetchAlerts(threatType?: string): Promise<Alert[]> {
  const url = threatType ? `${API_BASE}/alerts?threat_type=${threatType}` : `${API_BASE}/alerts`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function fetchAlert(alertId: string): Promise<Alert> {
  const res = await fetch(`${API_BASE}/alerts/${alertId}`);
  if (!res.ok) throw new Error(`Failed to fetch alert ${alertId}`);
  return res.json();
}

export async function acknowledgeAlert(alertId: string): Promise<{ alert_id: string; acknowledged: boolean }> {
  const res = await fetch(`${API_BASE}/alerts/${alertId}/acknowledge`, { method: 'POST' });
  if (!res.ok) throw new Error(`Failed to acknowledge alert ${alertId}`);
  return res.json();
}

export async function fetchInvestigation(investigationId: string): Promise<InvestigationCase> {
  const res = await fetch(`${API_BASE}/investigations/${investigationId}`);
  if (!res.ok) throw new Error(`Failed to fetch investigation ${investigationId}`);
  return res.json();
}

export async function fetchLiveGraph(): Promise<EvidenceGraphData> {
  const res = await fetch(`${API_BASE}/graph`);
  if (!res.ok) throw new Error('Failed to fetch evidence graph');
  return res.json();
}

export async function fetchCampaigns(): Promise<Campaign[]> {
  const res = await fetch(`${API_BASE}/campaigns`);
  if (!res.ok) throw new Error('Failed to fetch campaigns');
  return res.json();
}

export async function fetchThroughput(): Promise<ThroughputMetrics> {
  const res = await fetch(`${API_BASE}/metrics/throughput`);
  if (!res.ok) throw new Error('Failed to fetch throughput metrics');
  return res.json();
}

export async function fetchTelemetryBuffer(): Promise<TelemetrySample[]> {
  const res = await fetch(`${API_BASE}/telemetry/buffer`);
  if (!res.ok) throw new Error('Failed to fetch telemetry buffer');
  return res.json();
}

export async function fetchHostProfile(hostIp: string): Promise<HostProfileResponse> {
  const res = await fetch(`${API_BASE}/hosts/${hostIp}`);
  if (!res.ok) throw new Error(`Failed to fetch profile for ${hostIp}`);
  return res.json();
}

export async function uploadPcap(file: File): Promise<{ job_id: string; status: string }> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`${API_BASE}/ingest/pcap`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) throw new Error('Failed to upload PCAP');
  return res.json();
}

export async function triggerBenchmark(): Promise<{ job_id: string; status: string; alerts_generated: number; campaigns_found: number }> {
  const res = await fetch(`${API_BASE}/generate/benchmark`, {
    method: 'POST',
  });
  if (!res.ok) throw new Error('Failed to run benchmark');
  return res.json();
}

export async function generateTrainingDataset(): Promise<{ path: string; rows: number; class_distribution: Record<string, number> }> {
  const res = await fetch(`${API_BASE}/train/generate-dataset`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to generate dataset');
  return res.json();
}

export async function uploadTrainingDataset(file: File): Promise<{ path: string; rows: number; class_distribution: Record<string, number> }> {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API_BASE}/train/upload-dataset`, { method: 'POST', body: form });
  if (!res.ok) throw new Error('Failed to upload dataset');
  return res.json();
}

export async function startTraining(csvPath: string): Promise<{ job_id: string; status: string }> {
  const res = await fetch(`${API_BASE}/train/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ csv_path: csvPath }),
  });
  if (!res.ok) throw new Error('Failed to start training');
  return res.json();
}

export async function analyzeDataset(csvPath?: string): Promise<{ status: string; dataset_info: any }> {
  const res = await fetch(`${API_BASE}/dataset/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(csvPath ? { csv_path: csvPath } : {}),
  });
  if (!res.ok) throw new Error('Failed to analyze dataset');
  return res.json();
}

export async function fetchDatasetStatus(): Promise<{
  active_dataset: any;
  alerts_count: number;
  campaigns_count: number;
  monitored_hosts: number;
}> {
  const res = await fetch(`${API_BASE}/dataset/status`);
  if (!res.ok) throw new Error('Failed to fetch dataset status');
  return res.json();
}

export async function clearDataset(): Promise<{ status: string }> {
  const res = await fetch(`${API_BASE}/dataset/clear`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to clear dataset');
  return res.json();
}

export async function fetchSecurityScore(): Promise<any> {
  const res = await fetch(`${API_BASE}/security-score`);
  if (!res.ok) throw new Error('Failed to fetch security score');
  return res.json();
}

export async function fetchBlockchainLedger(): Promise<{
  status: string;
  verification: any;
  total_blocks: number;
  ledger: any[];
}> {
  const res = await fetch(`${API_BASE}/blockchain/ledger`);
  if (!res.ok) throw new Error('Failed to fetch blockchain ledger');
  return res.json();
}

export async function verifyAlertHash(alertId: string): Promise<any> {
  const res = await fetch(`${API_BASE}/blockchain/verify/${alertId}`);
  if (!res.ok) throw new Error(`Failed to verify alert hash for ${alertId}`);
  return res.json();
}

export async function startReplay(csvPath?: string): Promise<{
  status: string;
  current_index: number;
  total_windows: number;
  dataset: string;
  timeline?: any[];
}> {
  const res = await fetch(`${API_BASE}/replay/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(csvPath ? { csv_path: csvPath } : {}),
  });
  if (!res.ok) throw new Error('Failed to start dataset replay');
  return res.json();
}

export async function stepReplay(): Promise<{
  status: string;
  current_index: number;
  total_windows: number;
  alerts_count?: number;
  visible_alerts?: Alert[];
  security_score?: any;
  is_finished?: boolean;
}> {
  const res = await fetch(`${API_BASE}/replay/step`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to step dataset replay');
  return res.json();
}

export async function resetReplay(): Promise<{
  status: string;
  current_index: number;
  total_windows: number;
  alerts_count: number;
  security_score?: any;
}> {
  const res = await fetch(`${API_BASE}/replay/reset`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reset dataset replay');
  return res.json();
}

export async function fetchReplayTimeline(): Promise<{
  total_events: number;
  timeline: Array<{
    alert_id: string;
    timestamp: string;
    host: string;
    type: string;
    severity: string;
    risk: number;
    confidence: number;
    novelty: number;
    step: number;
    explanation: string;
  }>;
  current_index: number;
}> {
  const res = await fetch(`${API_BASE}/replay/timeline`);
  if (!res.ok) throw new Error('Failed to fetch replay timeline');
  return res.json();
}


