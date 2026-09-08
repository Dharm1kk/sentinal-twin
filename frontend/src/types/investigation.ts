export interface Hypothesis {
  type: string;
  score: number;
}

export interface EvidenceItem {
  feature: string;
  value: number;
  impact: number;
}

export interface TelemetryDeviation {
  feature: string;
  label: string;
  observed_value: number;
  baseline_rule: string;
  status: string;
}

export interface DifferentialCandidate {
  candidate_threat: string;
  probability_score: number;
  reasoning: string;
}

export interface ModelValidation {
  isolation_forest_novelty: string;
  isolation_forest_status: string;
  xgboost_specialist: string;
  xgboost_confidence: string;
  anti_argmax_triggered: boolean;
}

export interface ExplanationDetails {
  threat_type: string;
  title: string;
  root_cause: string;
  mechanism: string;
  telemetry_deviations: TelemetryDeviation[];
  differential_diagnosis: DifferentialCandidate[];
  model_validation: ModelValidation;
  containment_recommendations: string[];
}

export interface Alert {
  alert_id: string;
  timestamp: string;
  host: string;
  type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  novelty: number;
  risk: number;
  hypotheses: Hypothesis[];
  evidence: EvidenceItem[];
  related_entities: string[];
  acknowledged?: boolean;
  explanation?: string;
  explanation_details?: ExplanationDetails;
  sha256_hash?: string;
  prev_hash?: string;
}

export interface BlockchainVerification {
  alert_id: string;
  block_index: number;
  alert_hash: string;
  prev_hash: string;
  timestamp: string;
  is_tamper_free: boolean;
  chain_length: number;
  status: string;
}

export interface SecurityScoreMeta {
  security_score: number;
  status: 'OPTIMAL' | 'HEALTHY' | 'DEGRADED' | 'CRITICAL_RISK' | 'COMPROMISED';
  network_alert_triggered: boolean;
  highest_risk: number;
  active_threats_count: number;
  critical_threats_count: number;
  summary: string;
}

export interface ReplayState {
  active: boolean;
  current_index: number;
  total_windows: number;
  dataset_name?: string;
}

export interface ThroughputMetrics {
  timestamp: number;
  packets_per_sec: number;
  flows_per_sec: number;
  mbps: number;
  latency_ms: number;
  total_packets: number;
  total_flows: number;
  active_hosts: number;
}

export interface TelemetrySample {
  timestamp: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  mbps: number;
  flows_count: number;
  active_hosts_count: number;
  ewma_baseline: number;
  cusum_score: number;
}

export interface GraphNode {
  id: string;
  name: string;
  category: number;
  symbolSize: number;
  value: number;
  itemStyle?: {
    borderColor?: string;
    color?: string;
  };
}

export interface GraphLink {
  source: string;
  target: string;
  value: string;
  lineStyle?: {
    color?: string;
    width?: number;
  };
}

export interface EvidenceGraphData {
  categories: { name: string }[];
  nodes: GraphNode[];
  links: GraphLink[];
}

export interface ConfidenceStep {
  timestamp: number;
  confidence: number;
  confidence_pct: number;
  reason: string;
  dt?: number;
}

export interface InvestigationCase {
  investigation_id: string;
  target_host: string;
  threat_type: string;
  severity: string;
  risk_index: number;
  competing_hypotheses: Hypothesis[];
  contributing_features: EvidenceItem[];
  confidence_history: ConfidenceStep[];
  explanation?: string;
  explanation_details?: ExplanationDetails;
  evidence_graph: EvidenceGraphData;
}

export interface Campaign {
  campaign_id: string;
  host: string;
  stages: string[];
  severity: string;
  risk: number;
  correlated_alert_ids: string[];
  narrative: string;
}

export interface HostMetricProfile {
  rolling_median: number;
  rolling_mad: number;
  ewma_expected: number;
  history_points: number;
}

export interface ActiveDatasetInfo {
  source: string;
  total_rows: number;
  total_packets: number;
  alerts_count: number;
  novel_count: number;
  campaigns_count: number;
  active_hosts: number;
  composite_risk: number;
  network_security_score?: number;
  network_status?: string;
  network_alert_triggered?: boolean;
  network_summary?: string;
  blockchain_verified?: boolean;
  ledger_blocks?: number;
  analyzed_at: string;
}

export interface HostProfileResponse {
  status: string;
  host: string;
  profile: Record<string, HostMetricProfile> | null;
  message?: string;
}


