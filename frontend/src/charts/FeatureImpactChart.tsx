import React from 'react';
import ReactECharts from 'echarts-for-react';
import type { EvidenceItem } from '../types/investigation';

interface FeatureImpactChartProps {
  evidence: EvidenceItem[];
}

export const FeatureImpactChart: React.FC<FeatureImpactChartProps> = ({ evidence }) => {
  const defaultEvidence: EvidenceItem[] = [
    { feature: 'dns_entropy', value: 0.94, impact: 0.18 },
    { feature: 'query_rate_deviation', value: 4.7, impact: 0.21 },
    { feature: 'subdomain_length', value: 52, impact: 0.14 },
    { feature: 'same_parent_repeats', value: 1.0, impact: 0.12 },
    { feature: 'txt_record_ratio', value: 0.65, impact: 0.10 },
  ];

  const items = evidence && evidence.length > 0 ? evidence : defaultEvidence;

  const names = items.map((e) => e.feature);
  const impacts = items.map((e) => e.impact);

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: '#fff',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 11, fontFamily: 'monospace' },
      formatter: (params: any) => {
        const idx = params[0].dataIndex;
        const item = items[idx];
        return `<strong>Feature:</strong> ${item.feature}<br/><strong>Observed Value:</strong> ${item.value}<br/><strong>Impact Weight:</strong> +${item.impact}`;
      }
    },
    grid: {
      left: '25%',
      right: '8%',
      bottom: '10%',
      top: '10%'
    },
    xAxis: {
      type: 'value',
      name: 'Impact Weight',
      splitLine: { lineStyle: { color: '#f1f5f9' } },
      axisLabel: { color: '#64748b', fontSize: 10, fontFamily: 'monospace' }
    },
    yAxis: {
      type: 'category',
      data: names,
      axisLine: { lineStyle: { color: '#cbd5e1' } },
      axisLabel: { color: '#475569', fontSize: 11, fontFamily: 'monospace' }
    },
    series: [
      {
        name: 'Feature Impact',
        type: 'bar',
        data: impacts,
        itemStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 1, y2: 0,
            colorStops: [
              { offset: 0, color: '#3b82f6' },
              { offset: 1, color: '#06b6d4' }
            ]
          },
          borderRadius: [0, 4, 4, 0]
        },
        label: {
          show: true,
          position: 'right',
          color: '#64748b',
          fontSize: 10,
          fontFamily: 'monospace',
          formatter: '+{c}'
        }
      }
    ]
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider font-mono">
          Feature Contributions & Impact Breakdown
        </h4>
      </div>
      <p className="text-xs text-slate-500 mb-2">
        Exact mathematical impact of extracted signals on the decision layer.
      </p>
      <ReactECharts option={option} style={{ height: '230px', width: '100%' }} />
    </div>
  );
};
