import React, { useState, useEffect, useRef } from 'react';
import ReactECharts from 'echarts-for-react';
import type { Alert } from '../types/investigation';
import {
  Play,
  Pause,
  SkipForward,
  RotateCcw,
  Clock,
  Radio,
  Sliders
} from 'lucide-react';

interface TimelineAttackGraphProps {
  alerts: Alert[];
  onSelectAlert?: (alert: Alert) => void;
  onVisibleAlertsChange?: (visibleAlerts: Alert[]) => void;
}

const CATEGORIES = [
  'NOVEL_BEHAVIOUR',
  'DATA_EXFILTRATION',
  'ENCRYPTED_MALWARE',
  'RECON',
  'DNS_TUNNEL',
  'DGA',
  'C2',
  'DDOS'
];

const CATEGORY_LABELS: Record<string, string> = {
  DDOS: 'DDoS Flooding',
  C2: 'C2 Beaconing',
  DGA: 'DGA Queries',
  DNS_TUNNEL: 'DNS Tunnel',
  RECON: 'Port / Host Scan',
  ENCRYPTED_MALWARE: 'Encrypted TLS',
  DATA_EXFILTRATION: 'Data Exfiltration',
  NOVEL_BEHAVIOUR: 'Zero-Day Novelty'
};

const CATEGORY_COLORS: Record<string, string> = {
  DDOS: '#ef4444',
  C2: '#f97316',
  DGA: '#eab308',
  DNS_TUNNEL: '#06b6d4',
  RECON: '#3b82f6',
  ENCRYPTED_MALWARE: '#8b5cf6',
  DATA_EXFILTRATION: '#ec4899',
  NOVEL_BEHAVIOUR: '#10b981'
};

export const TimelineAttackGraph: React.FC<TimelineAttackGraphProps> = ({
  alerts,
  onSelectAlert,
  onVisibleAlertsChange
}) => {
  // Sort alerts chronologically
  const sortedAlerts = React.useMemo(() => {
    return [...alerts].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  }, [alerts]);

  const totalSteps = sortedAlerts.length;
  const [currentStep, setCurrentStep] = useState<number>(totalSteps);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const playTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Sync step when alerts change initially
  useEffect(() => {
    if (totalSteps > 0 && currentStep > totalSteps) {
      setCurrentStep(totalSteps);
    } else if (totalSteps > 0 && currentStep === 0) {
      setCurrentStep(totalSteps);
    }
  }, [totalSteps]);

  // Handle Play/Pause
  useEffect(() => {
    if (isPlaying) {
      const intervalMs = Math.max(400, Math.floor(1400 / playbackSpeed));
      playTimerRef.current = setInterval(() => {
        setCurrentStep((prev) => {
          if (prev >= totalSteps) {
            setIsPlaying(false);
            return totalSteps;
          }
          return prev + 1;
        });
      }, intervalMs);
    } else if (playTimerRef.current) {
      clearInterval(playTimerRef.current);
      playTimerRef.current = null;
    }
    return () => {
      if (playTimerRef.current) clearInterval(playTimerRef.current);
    };
  }, [isPlaying, playbackSpeed, totalSteps]);

  // Notify parent of visible slice
  useEffect(() => {
    if (onVisibleAlertsChange && sortedAlerts.length > 0) {
      const slice = sortedAlerts.slice(0, currentStep);
      onVisibleAlertsChange(slice);
    }
  }, [currentStep, sortedAlerts, onVisibleAlertsChange]);

  const handleStepForward = () => {
    if (currentStep < totalSteps) {
      setCurrentStep((prev) => prev + 1);
    }
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentStep(totalSteps);
  };

  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseInt(e.target.value, 10);
    setCurrentStep(val);
  };

  const activeAlert = sortedAlerts[currentStep - 1] || null;

  // Prepare scatter data for ECharts
  const scatterData = sortedAlerts.map((a, idx) => {
    const catIndex = CATEGORIES.indexOf(a.type);
    const yVal = catIndex !== -1 ? catIndex : 0;
    const isPastOrCurrent = idx < currentStep;
    const isCurrent = idx === currentStep - 1;
    const color = CATEGORY_COLORS[a.type] || '#3b82f6';

    const timeLabel = a.timestamp.includes('T')
      ? a.timestamp.split('T')[1].replace('Z', '')
      : a.timestamp;

    return {
      name: a.alert_id,
      value: [idx + 1, yVal, a.risk, a.confidence, a.severity, a.host, a.type, timeLabel, a.explanation],
      itemStyle: {
        color: isCurrent ? '#2563eb' : isPastOrCurrent ? color : '#cbd5e1',
        borderColor: isCurrent ? '#1d4ed8' : '#ffffff',
        borderWidth: isCurrent ? 3 : 1.5,
        shadowBlur: isCurrent ? 12 : 0,
        shadowColor: color,
        opacity: isPastOrCurrent ? 1.0 : 0.25
      },
      symbolSize: isCurrent ? 22 : 12 + (a.risk / 100) * 12
    };
  });

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: '#ffffff',
      borderColor: '#e2e8f0',
      borderWidth: 1,
      padding: [10, 14],
      textStyle: { color: '#0f172a', fontSize: 12, fontFamily: 'sans-serif' },
      formatter: (params: any) => {
        const val = params.value;
        const alertId = params.name;
        const risk = val[2];
        const conf = Math.round(val[3] * 100);
        const sev = val[4];
        const host = val[5];
        const threat = val[6];
        const time = val[7];
        const desc = val[8] || '';

        return `
          <div style="font-family: sans-serif; line-height: 1.4;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; gap: 12px;">
              <strong style="color: #0f172a; font-family: monospace; font-size: 13px;">${alertId}</strong>
              <span style="font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px; background: #eff6ff; color: #1d4ed8;">${sev}</span>
            </div>
            <div style="font-size: 11px; color: #475569; margin-bottom: 4px;">
              <b>Threat:</b> <span style="color: #0f172a; font-weight: 600;">${CATEGORY_LABELS[threat] || threat}</span>
            </div>
            <div style="font-size: 11px; color: #475569; margin-bottom: 4px;">
              <b>Host:</b> <span style="font-family: monospace; color: #0f172a;">${host}</span>
            </div>
            <div style="font-size: 11px; color: #475569; margin-bottom: 6px;">
              <b>Timeline:</b> ${time} • <b>Risk:</b> <span style="color: #dc2626; font-weight: bold;">${risk}/100</span> • <b>Conf:</b> ${conf}%
            </div>
            <div style="font-size: 10.5px; color: #64748b; max-width: 280px; border-top: 1px solid #f1f5f9; padding-top: 4px;">
              ${desc.slice(0, 110)}${desc.length > 110 ? '...' : ''}
            </div>
          </div>
        `;
      }
    },
    grid: {
      left: '16%',
      right: '4%',
      top: '8%',
      bottom: '14%',
      containLabel: false
    },
    xAxis: {
      type: 'value',
      name: 'Chronological Sequence (Event #)',
      nameLocation: 'middle',
      nameGap: 24,
      nameTextStyle: { color: '#64748b', fontSize: 11, fontWeight: 500 },
      min: 1,
      max: Math.max(totalSteps, 10),
      splitLine: { lineStyle: { color: '#f1f5f9', type: 'dashed' } },
      axisLine: { lineStyle: { color: '#cbd5e1' } },
      axisLabel: {
        color: '#64748b',
        fontSize: 10,
        fontFamily: 'monospace'
      }
    },
    yAxis: {
      type: 'category',
      data: CATEGORIES.map((c) => CATEGORY_LABELS[c]),
      axisLine: { lineStyle: { color: '#cbd5e1' } },
      splitLine: { lineStyle: { color: '#f8fafc' } },
      axisLabel: {
        color: '#334155',
        fontSize: 11,
        fontWeight: 500
      }
    },
    series: [
      {
        name: 'Attack Events',
        type: 'scatter',
        data: scatterData,
        animationDuration: 400
      }
    ]
  };

  const onChartClick = (params: any) => {
    if (params.name && onSelectAlert) {
      const found = sortedAlerts.find((a) => a.alert_id === params.name);
      if (found) {
        onSelectAlert(found);
      }
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-3.5 sm:p-5 shadow-xs space-y-3 sm:space-y-4 font-sans">
      {/* Header bar with controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Radio className="h-4 w-4 text-blue-600 animate-pulse" />
            <h3 className="text-xs sm:text-sm font-bold text-slate-900">
              Chronological Attack Sequence & Timeline
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-semibold border border-blue-200">
              {currentStep} of {totalSteps} Events
            </span>
          </div>
          <p className="text-[11px] sm:text-xs text-slate-500 mt-0.5">
            Interactive timeline plotting detected threats across time. Scrub or step forward to observe attack progression.
          </p>
        </div>

        {/* Playback Controls */}
        <div className="flex flex-wrap items-center gap-1.5 sm:gap-2">
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className={`flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 rounded-lg text-xs font-semibold shadow-xs transition cursor-pointer ${
              isPlaying
                ? 'bg-amber-600 hover:bg-amber-700 text-white'
                : 'bg-blue-600 hover:bg-blue-700 text-white'
            }`}
          >
            {isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            {isPlaying ? 'Pause' : 'Play Timeline'}
          </button>

          <button
            onClick={handleStepForward}
            disabled={currentStep >= totalSteps || isPlaying}
            className="flex items-center gap-1 px-2 sm:px-2.5 py-1.5 bg-slate-50 hover:bg-slate-100 disabled:opacity-40 text-slate-700 border border-slate-200 rounded-lg text-xs font-medium transition cursor-pointer"
            title="Step Forward"
          >
            <SkipForward className="h-3.5 w-3.5" />
            Step
          </button>

          <button
            onClick={handleReset}
            className="flex items-center gap-1 px-2 sm:px-2.5 py-1.5 bg-white hover:bg-slate-50 text-slate-600 border border-slate-200 rounded-lg text-xs font-medium transition cursor-pointer"
            title="Reset to Full Timeline"
          >
            <RotateCcw className="h-3.5 w-3.5 text-slate-400" />
            Full
          </button>

          {/* Speed Selector */}
          <div className="flex items-center gap-1 pl-1 border-l border-slate-200 text-xs">
            {[1, 2, 4].map((s) => (
              <button
                key={s}
                onClick={() => setPlaybackSpeed(s)}
                className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-medium cursor-pointer transition ${
                  playbackSpeed === s
                    ? 'bg-blue-100 text-blue-700 font-bold'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Scrubber Range Slider */}
      <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 sm:px-4 sm:py-2.5 flex items-center gap-2.5 sm:gap-4">
        <Sliders className="h-4 w-4 text-slate-400 shrink-0 hidden xs:block" />
        <div className="flex-1 flex flex-col gap-1 min-w-0">
          <div className="flex flex-col xs:flex-row justify-between items-start xs:items-center text-[11px] gap-0.5">
            <span className="text-slate-500 truncate">
              Position: <strong className="text-slate-800 font-mono">#{currentStep}</strong>
              {activeAlert && (
                <span className="ml-1.5 text-blue-700 font-semibold font-mono text-[10px] sm:text-[11px]">
                  ({activeAlert.alert_id} - {CATEGORY_LABELS[activeAlert.type] || activeAlert.type})
                </span>
              )}
            </span>
            <span className="text-slate-400 font-mono text-[10px]">
              {activeAlert ? activeAlert.timestamp : ''}
            </span>
          </div>
          <input
            type="range"
            min={1}
            max={Math.max(1, totalSteps)}
            value={currentStep}
            onChange={handleSliderChange}
            className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600"
          />
        </div>
      </div>

      {/* Interactive ECharts Scatter Timeline */}
      {totalSteps === 0 ? (
        <div className="h-56 flex flex-col items-center justify-center text-slate-400 text-xs">
          <Clock className="h-6 w-6 text-slate-300 mb-2" />
          No attack events recorded yet. Click &quot;Analyze Dataset&quot; to generate timeline telemetry.
        </div>
      ) : (
        <ReactECharts
          option={option}
          onEvents={{ click: onChartClick }}
          style={{ height: '260px', width: '100%' }}
        />
      )}
    </div>
  );
};
