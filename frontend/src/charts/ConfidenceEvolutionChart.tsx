import React from 'react';
import ReactECharts from 'echarts-for-react';
import type { ConfidenceStep } from '../types/investigation';

interface ConfidenceEvolutionChartProps {
  steps?: ConfidenceStep[];
}

export const ConfidenceEvolutionChart: React.FC<ConfidenceEvolutionChartProps> = ({ steps }) => {
  const defaultSteps: ConfidenceStep[] = [
    { timestamp: 1, confidence: 0.31, confidence_pct: 31, reason: 'Initial baseline deviation detected' },
    { timestamp: 2, confidence: 0.45, confidence_pct: 45, reason: 'High-entropy query repeat observed' },
    { timestamp: 3, confidence: 0.58, confidence_pct: 58, reason: 'Temporal persistence over 3 time windows' },
    { timestamp: 4, confidence: 0.71, confidence_pct: 71, reason: 'Targeted parent domain match confirmed' },
    { timestamp: 5, confidence: 0.83, confidence_pct: 83, reason: 'Evidence fusion convergence (XGB + Baseline)' },
  ];

  const currentSteps = steps && steps.length > 0 ? steps : defaultSteps;

  const categories = currentSteps.map((_, idx) => `Update #${idx + 1}`);
  const values = currentSteps.map((s) => s.confidence_pct);

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#fff',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 11, fontFamily: 'monospace' },
      formatter: (params: any) => {
        const idx = params[0].dataIndex;
        const step = currentSteps[idx];
        return `<strong>${categories[idx]}:</strong> ${step.confidence_pct}% Confidence<br/><em>${step.reason}</em>`;
      }
    },
    grid: {
      left: '4%',
      right: '4%',
      bottom: '10%',
      top: '15%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: categories,
      axisLine: { lineStyle: { color: '#cbd5e1' } },
      axisLabel: { color: '#475569', fontSize: 11, fontFamily: 'monospace' }
    },
    yAxis: {
      type: 'value',
      name: 'Confidence (%)',
      max: 100,
      min: 0,
      nameTextStyle: { color: '#64748b', fontSize: 10 },
      splitLine: { lineStyle: { color: '#f1f5f9' } },
      axisLabel: { color: '#64748b', fontSize: 10, fontFamily: 'monospace' }
    },
    series: [
      {
        name: 'Temporal Confidence',
        type: 'line',
        smooth: true,
        data: values,
        symbolSize: 8,
        itemStyle: { color: '#10b981' },
        lineStyle: { color: '#10b981', width: 2.5 },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(16, 185, 129, 0.35)' },
              { offset: 1, color: 'rgba(16, 185, 129, 0.0)' }
            ]
          }
        },
        markPoint: {
          data: [
            { type: 'max', name: 'Peak' }
          ],
          label: { color: '#ffffff', fontSize: 10, fontFamily: 'monospace' }
        }
      }
    ]
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider font-mono">
          Temporal Confidence Evolution & Decay
        </h4>
        <span className="text-[10px] text-slate-500 font-mono">
          Section 11: E(t) = E0 * exp(-λt)
        </span>
      </div>
      <p className="text-xs text-slate-500 mb-2">
        Confidence accumulates asymptotically as evidence persists across time windows.
      </p>
      <ReactECharts option={option} style={{ height: '230px', width: '100%' }} />
    </div>
  );
};
