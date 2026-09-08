import React from 'react';
import ReactECharts from 'echarts-for-react';
import type { Alert } from '../types/investigation';

interface ThreatDistributionChartProps {
  alerts: Alert[];
}

export const ThreatDistributionChart: React.FC<ThreatDistributionChartProps> = ({ alerts }) => {
  const threatFamilies = [
    { key: 'DDOS', label: 'DDoS Flooding', color: '#ef4444' },
    { key: 'C2', label: 'C2 Beaconing', color: '#f97316' },
    { key: 'DGA', label: 'DGA Query', color: '#eab308' },
    { key: 'DNS_TUNNEL', label: 'DNS Tunnel', color: '#06b6d4' },
    { key: 'RECON', label: 'Recon / Scan', color: '#3b82f6' },
    { key: 'ENCRYPTED_MALWARE', label: 'Encrypted Malware', color: '#8b5cf6' },
    { key: 'DATA_EXFILTRATION', label: 'Data Exfil', color: '#ec4899' },
    { key: 'NOVEL_BEHAVIOUR', label: 'Zero-Day Novelty', color: '#10b981' }
  ];

  // Count occurrences
  const counts: Record<string, number> = {};
  threatFamilies.forEach((tf) => (counts[tf.key] = 0));

  alerts.forEach((a) => {
    const t = a.type.toUpperCase();
    counts[t] = (counts[t] || 0) + 1;
  });

  const chartData = threatFamilies
    .map((tf) => ({
      name: tf.label,
      value: counts[tf.key] || 0,
      itemStyle: { color: tf.color }
    }))
    .filter((d) => d.value > 0);

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: '#ffffff',
      borderColor: '#e2e8f0',
      borderWidth: 1,
      padding: [8, 12],
      textStyle: { color: '#0f172a', fontSize: 12, fontFamily: 'sans-serif' },
      formatter: '{b}: <b>{c}</b> events ({d}%)'
    },
    series: [
      {
        name: 'Threat Class',
        type: 'pie',
        radius: ['52%', '78%'],
        center: ['50%', '50%'],
        avoidLabelOverlap: true,
        itemStyle: {
          borderRadius: 5,
          borderColor: '#ffffff',
          borderWidth: 2
        },
        label: { show: false },
        emphasis: {
          label: {
            show: true,
            fontSize: 12,
            fontWeight: 'bold',
            color: '#0f172a',
            formatter: '{b}\n{c} alerts'
          }
        },
        data: chartData
      }
    ]
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs font-sans">
      <div className="flex items-center justify-between mb-2 border-b border-slate-100 pb-2.5">
        <h4 className="text-xs font-bold text-slate-800 uppercase tracking-wider">
          Threat Class Distribution
        </h4>
        <span className="text-[11px] font-mono text-blue-700 bg-blue-50 px-2 py-0.5 rounded border border-blue-200 font-semibold">
          {alerts.length} total events
        </span>
      </div>

      {alerts.length === 0 ? (
        <div className="h-56 flex flex-col items-center justify-center text-slate-400 text-xs">
          No threat events to distribute.
        </div>
      ) : (
        <>
          <div className="relative">
            <ReactECharts option={option} style={{ height: '190px', width: '100%' }} />
            {/* Center label */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold font-mono text-slate-900 leading-none">
                {alerts.length}
              </span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold mt-1">
                Incidents
              </span>
            </div>
          </div>

          {/* Breakdown legend list */}
          <div className="mt-3 grid grid-cols-2 gap-1.5 pt-2 border-t border-slate-100 text-xs">
            {threatFamilies.map((tf) => {
              const count = counts[tf.key] || 0;
              if (count === 0 && alerts.length > 0) return null;
              return (
                <div key={tf.key} className="flex items-center justify-between p-1 rounded hover:bg-slate-50">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="h-2 w-2 rounded-full shrink-0" style={{ backgroundColor: tf.color }} />
                    <span className="text-[11px] text-slate-600 truncate">{tf.label}</span>
                  </div>
                  <span className="text-[11px] font-mono font-semibold text-slate-900 shrink-0 ml-1">
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
};
