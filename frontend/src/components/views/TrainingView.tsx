import React, { useState, useEffect, useRef } from 'react';
import {
  Upload,
  BrainCircuit,
  CheckCircle2,
  Loader2,
  Circle,
  AlertCircle,
  Play,
  Database,
  ShieldCheck
} from 'lucide-react';

import { analyzeDataset } from '../../api/client';

interface ClassDist {
  [key: string]: number;
}
interface TrainingStep {
  step: number;
  label: string;
  description: string;
}
interface StepStatus {
  step: number;
  status: 'done' | 'running' | 'pending' | 'error';
}
interface Metrics {
  [specialist: string]: {
    precision: number;
    recall: number;
    f1: number;
    pr_auc: number;
    roc_auc: number;
  };
}

const PIPELINE_STEPS: TrainingStep[] = [
  { step: 1, label: 'Load Dataset & Validate Schema', description: 'Parse CSV, verify 35 canonical Sentinel features, split by class label' },
  { step: 2, label: 'Fit Isolation Forest on Benign Baseline', description: 'Learn normal enclave boundary on clean traffic only without attack labels' },
  { step: 3, label: 'Generate IF-Derived Anomaly Labels', description: 'Score entire dataset with Isolation Forest to produce pseudo-labels for attack specialists' },
  { step: 4, label: 'Train XGBoost Specialist Ensemble (x7)', description: 'Train binary classifiers per threat family using IF-derived signal and evaluate on ground truth' },
  { step: 5, label: 'Persist Models & Hot-Reload Engine', description: 'Save model_*.joblib files to ml/models/ and immediately reload active detectors' },
];

const API = '/api/v1';

interface TrainingViewProps {
  onDatasetAnalyzed?: () => void;
}

export const TrainingView: React.FC<TrainingViewProps> = ({ onDatasetAnalyzed }) => {
  const [datasetInfo, setDatasetInfo] = useState<{ path: string; rows: number; class_distribution: ClassDist } | null>(null);
  const [datasetLoading, setDatasetLoading] = useState(false);
  const [datasetError, setDatasetError] = useState<string | null>(null);

  const [analyzingDataset, setAnalyzingDataset] = useState(false);
  const [analyzeSuccess, setAnalyzeSuccess] = useState<string | null>(null);

  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<string>('idle');
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [progressPct, setProgressPct] = useState<number>(0);
  const [stepName, setStepName] = useState<string>('');
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [trainingError, setTrainingError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleGenerateDataset = async () => {
    setDatasetLoading(true);
    setDatasetError(null);
    setAnalyzeSuccess(null);
    try {
      const res = await fetch(`${API}/train/generate-dataset`, { method: 'POST' });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setDatasetInfo(data);
    } catch (e: any) {
      setDatasetError(e.message);
    } finally {
      setDatasetLoading(false);
    }
  };

  const handleUploadDataset = async (file: File) => {
    setDatasetLoading(true);
    setDatasetError(null);
    setAnalyzeSuccess(null);
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await fetch(`${API}/train/upload-dataset`, { method: 'POST', body: form });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setDatasetInfo(data);
    } catch (e: any) {
      setDatasetError(e.message);
    } finally {
      setDatasetLoading(false);
    }
  };

  const handleAnalyzeInConsole = async () => {
    if (!datasetInfo) return;
    setAnalyzingDataset(true);
    setAnalyzeSuccess(null);
    try {
      await analyzeDataset(datasetInfo.path);
      setAnalyzeSuccess('Dataset successfully analyzed! SOC Console overview, graph, and alerts are now loaded.');
      if (onDatasetAnalyzed) onDatasetAnalyzed();
    } catch (e: any) {
      setDatasetError(e.message);
    } finally {
      setAnalyzingDataset(false);
    }
  };

  const handleStartTraining = async () => {
    if (!datasetInfo) return;
    setJobStatus('running');
    setCurrentStep(0);
    setProgressPct(0);
    setMetrics(null);
    setTrainingError(null);
    try {
      const res = await fetch(`${API}/train/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ csv_path: datasetInfo.path }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setJobId(data.job_id);
    } catch (e: any) {
      setTrainingError(e.message);
      setJobStatus('error');
    }
  };

  useEffect(() => {
    if (!jobId) return;
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API}/train/status/${jobId}`);
        if (!res.ok) return;
        const data = await res.json();
        setCurrentStep(data.step || 0);
        setProgressPct(data.progress_pct || 0);
        setStepName(data.step_name || '');
        if (data.status === 'completed') {
          setJobStatus('completed');
          if (data.result?.metrics) setMetrics(data.result.metrics);
          if (pollRef.current) clearInterval(pollRef.current);
        } else if (data.status === 'error') {
          setJobStatus('error');
          setTrainingError(data.error || 'Training failed');
          if (pollRef.current) clearInterval(pollRef.current);
        }
      } catch {}
    }, 1000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [jobId]);

  const getStepStatus = (step: number): StepStatus['status'] => {
    if (jobStatus === 'idle') return 'pending';
    if (step < currentStep) return 'done';
    if (step === currentStep && jobStatus === 'running') return 'running';
    if (jobStatus === 'completed') return 'done';
    if (jobStatus === 'error' && step === currentStep) return 'error';
    return 'pending';
  };

  const StepIcon: React.FC<{ status: StepStatus['status'] }> = ({ status }) => {
    if (status === 'done') return <CheckCircle2 className="h-5 w-5 text-emerald-600 shrink-0" />;
    if (status === 'running') return <Loader2 className="h-5 w-5 text-blue-600 animate-spin shrink-0" />;
    if (status === 'error') return <AlertCircle className="h-5 w-5 text-rose-600 shrink-0" />;
    return <Circle className="h-5 w-5 text-slate-300 shrink-0" />;
  };

  const SPECIALIST_DISPLAY: Record<string, string> = {
    ddos: 'DDoS Flooding Specialist',
    c2: 'C2 Beaconing Specialist',
    dga: 'DGA Domain Specialist',
    dns_tunnel: 'DNS Tunneling Specialist',
    recon: 'Reconnaissance Specialist',
    encrypted: 'Encrypted Malware Specialist',
    exfil: 'Data Exfiltration Specialist'
  };

  return (
    <div className="space-y-6 max-w-5xl font-sans">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2.5">
          <div className="h-8 w-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center border border-blue-200">
            <BrainCircuit className="h-5 w-5" />
          </div>
          Dataset Management & Model Studio
        </h1>
        <p className="text-xs text-slate-500 mt-1">
          Upload traffic datasets, run the unsupervised-to-supervised Isolation Forest + XGBoost training pipeline, and analyze datasets in the SOC console.
        </p>
      </div>

      {/* Step 1: Dataset Management */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-slate-900">1. Dataset Selection</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Select or upload a CSV dataset containing the 35 canonical Sentinel traffic features.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={handleGenerateDataset}
            disabled={datasetLoading}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition shadow-xs cursor-pointer"
          >
            {datasetLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Database className="h-4 w-4" />}
            Generate Benchmark Dataset (10,800 Rows)
          </button>

          <span className="text-xs text-slate-400 font-medium">or</span>

          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={datasetLoading}
            className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 hover:bg-slate-50 disabled:opacity-50 text-slate-700 text-xs font-semibold rounded-lg transition shadow-xs cursor-pointer"
          >
            <Upload className="h-4 w-4 text-slate-500" />
            Upload Custom CSV
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv"
            className="hidden"
            onChange={(e) => {
              if (e.target.files?.[0]) handleUploadDataset(e.target.files[0]);
            }}
          />
        </div>

        {datasetError && (
          <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-700 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {datasetError}
          </div>
        )}

        {datasetInfo && (
          <div className="mt-4 pt-4 border-t border-slate-100 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-emerald-700">
                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                Loaded {datasetInfo.rows.toLocaleString()} records from{' '}
                <span className="font-mono bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                  {datasetInfo.path.split(/[/\\]/).pop()}
                </span>
              </div>

              {/* One-click analyze action */}
              <button
                onClick={handleAnalyzeInConsole}
                disabled={analyzingDataset}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition shadow-xs cursor-pointer"
              >
                {analyzingDataset ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                Analyze & Populate SOC Dashboard
              </button>
            </div>

            {analyzeSuccess && (
              <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-xs text-emerald-800 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-600 shrink-0" />
                {analyzeSuccess}
              </div>
            )}

            {/* Class distribution table */}
            <div className="overflow-x-auto rounded-lg border border-slate-100">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-100 text-slate-500 font-semibold uppercase text-[10px]">
                    <th className="py-2 px-3 text-left">Traffic Class</th>
                    <th className="py-2 px-3 text-right">Row Count</th>
                    <th className="py-2 px-3 text-right">Percentage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {Object.entries(datasetInfo.class_distribution).map(([cls, count]) => (
                    <tr key={cls} className="hover:bg-slate-50">
                      <td className="py-2 px-3 font-mono font-medium text-slate-800">{cls}</td>
                      <td className="py-2 px-3 text-right font-mono text-slate-600">{count.toLocaleString()}</td>
                      <td className="py-2 px-3 text-right font-mono text-slate-500">
                        {((count / datasetInfo.rows) * 100).toFixed(1)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Step 2: Training Pipeline */}
      {datasetInfo && (
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900">2. Train Model Pipeline (IF -&gt; XGBoost)</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Isolation Forest learns clean baseline boundary -&gt; generates weighted anomaly labels -&gt; XGBoost trains 7 specialists.
              </p>
            </div>
            <button
              onClick={handleStartTraining}
              disabled={jobStatus === 'running'}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold rounded-lg transition shadow-xs cursor-pointer"
            >
              {jobStatus === 'running' ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> Training in Progress...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" /> Start Model Training
                </>
              )}
            </button>
          </div>

          {/* Progress Bar */}
          {jobStatus !== 'idle' && (
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs text-slate-600 font-medium">
                <span>{stepName || 'Initializing...'}</span>
                <span className="font-mono">{progressPct}%</span>
              </div>
              <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-600 rounded-full transition-all duration-500"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
            </div>
          )}

          {/* Pipeline Steps List */}
          <div className="space-y-2.5">
            {PIPELINE_STEPS.map((s) => {
              const status = getStepStatus(s.step);
              return (
                <div
                  key={s.step}
                  className={`flex items-start gap-3 p-3 rounded-lg border transition ${
                    status === 'running'
                      ? 'border-blue-200 bg-blue-50/60'
                      : status === 'done'
                      ? 'border-emerald-200 bg-emerald-50/60'
                      : status === 'error'
                      ? 'border-rose-200 bg-rose-50/60'
                      : 'border-slate-100 bg-slate-50/40'
                  }`}
                >
                  <StepIcon status={status} />
                  <div>
                    <p
                      className={`text-xs font-bold ${
                        status === 'running'
                          ? 'text-blue-900'
                          : status === 'done'
                          ? 'text-emerald-900'
                          : status === 'error'
                          ? 'text-rose-900'
                          : 'text-slate-700'
                      }`}
                    >
                      {s.label}
                    </p>
                    <p className="text-[11px] text-slate-500 mt-0.5">{s.description}</p>
                  </div>
                </div>
              );
            })}
          </div>

          {trainingError && (
            <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg text-xs text-rose-700 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {trainingError}
            </div>
          )}
        </div>
      )}

      {/* Step 3: Evaluation Metrics Report */}
      {metrics && (
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div className="border-b border-slate-100 pb-3">
            <h2 className="text-sm font-bold text-slate-900">3. Specialist Ensemble Evaluation Report</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Evaluated on held-out 20% test split against ground truth labels. Models hot-reloaded into active detector suite.
            </p>
          </div>

          <div className="overflow-x-auto rounded-lg border border-slate-100">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-100 text-slate-500 font-semibold uppercase text-[10px]">
                  <th className="text-left py-2.5 px-3">Specialist</th>
                  <th className="text-right py-2.5 px-3">Precision</th>
                  <th className="text-right py-2.5 px-3">Recall</th>
                  <th className="text-right py-2.5 px-3">F1 Score</th>
                  <th className="text-right py-2.5 px-3">PR-AUC</th>
                  <th className="text-right py-2.5 px-3">ROC-AUC</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {Object.entries(metrics).map(([key, m]) => (
                  <tr key={key} className="hover:bg-slate-50">
                    <td className="py-2.5 px-3 font-sans font-medium text-slate-800">
                      {SPECIALIST_DISPLAY[key] || key}
                    </td>
                    {[m.precision, m.recall, m.f1, m.pr_auc, m.roc_auc].map((v, i) => (
                      <td
                        key={i}
                        className={`py-2.5 px-3 text-right font-semibold ${
                          v >= 0.85
                            ? 'text-emerald-700'
                            : v >= 0.60
                            ? 'text-amber-700'
                            : 'text-slate-600'
                        }`}
                      >
                        {v !== undefined ? v.toFixed(3) : '-'}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-lg text-xs text-emerald-800 flex items-center justify-between">
            <span className="flex items-center gap-1.5 font-medium">
              <CheckCircle2 className="h-4 w-4 text-emerald-600" />
              Trained models saved to ml/models/ and active in detector suite.
            </span>
            <button
              onClick={handleAnalyzeInConsole}
              className="text-xs text-emerald-700 font-bold hover:underline cursor-pointer"
            >
              Analyze in SOC Console &rarr;
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
