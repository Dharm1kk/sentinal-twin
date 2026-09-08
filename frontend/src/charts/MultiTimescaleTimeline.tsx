import React, { useState } from 'react';
import ReactECharts from 'echarts-for-react';

interface MultiTimescaleTimelineProps {
  currentWindow?: string;
  onWindowChange?: (w: string) => void;
}

export const MultiTimescaleTimeline: React.FC<MultiTimescaleTimelineProps> = () => {
  const [selectedWindow, setSelectedWindow] = useState<string>('5s');
  const timescales = ['1s', '5s', '30s', '1m', '5m', '15m'];

  // Generate synthetic multi-timescale telemetry points to visualize Section 8
  const generateData = () => {
    const times = [];
    const packetRates = [];
    const cusumSpikes = [];
    const ewmaExpected = [];

    const now = Date.now();
    const count = 30;

    for (let i = 0; i < count; i++) {
      const t = new Date(now - (count - i) * 5000).toLocaleTimeString();
      times.push(t);

      // Normal background with periodic spikes
      let pRate = 120 + Math.sin(i * 0.5) * 35;
      let cusum = Math.max(0, Math.sin(i * 0.3) * 2.5);
      let ewma = 120;

      // Simulate Recon burst at i=8, C2 beacon at i=15, DNS tunnel at i=22
      if (i >= 8 && i <= 10) {
        pRate += 450;
        cusum += 6.5;
      } else if (i === 15 || i === 18) {
        pRate += 200;
        cusum += 4.0;
      } else if (i >= 22 && i <= 26) {
        pRate += 850;
        cusum += 9.2;
      }

      packetRates.push(Math.round(pRate));
      cusumSpikes.push(parseFloat(cusum.toFixed(2)));
      ewmaExpected.push(Math.round(ewma));
    }

    return { times, packetRates, cusumSpikes, ewmaExpected };
  };

  const data = generateData();

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#fff',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 11, fontFamily: 'monospace' }
    },
    legend: {
      data: ['Observed Packet Rate', 'Adaptive EWMA Baseline', 'CUSUM Change-Point Evidence'],
      textStyle: { color: '#64748b', fontSize: 11 },
      top: 5
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '10%',
      top: '18%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: data.times,
      axisLine: { lineStyle: { color: '#cbd5e1' } },
      axisLabel: { color: '#475569', fontSize: 10, fontFamily: 'monospace' }
    },
    yAxis: [
      {
        type: 'value',
        name: 'Packets / sec',
        nameTextStyle: { color: '#64748b', fontSize: 10 },
        splitLine: { lineStyle: { color: '#f1f5f9' } },
        axisLabel: { color: '#64748b', fontSize: 10, fontFamily: 'monospace' }
      },
      {
        type: 'value',
        name: 'CUSUM Score',
        nameTextStyle: { color: '#d97706', fontSize: 10 },
        splitLine: { show: false },
        axisLabel: { color: '#d97706', fontSize: 10, fontFamily: 'monospace' }
      }
    ],
    series: [
      {
        name: 'Observed Packet Rate',
        type: 'line',
        smooth: true,
        data: data.packetRates,
        lineStyle: { color: '#0ea5e9', width: 2 },
        areaStyle: {
          color: {
            type: 'linear',
            x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(14, 165, 233, 0.25)' },
              { offset: 1, color: 'rgba(14, 165, 233, 0.0)' }
            ]
          }
        }
      },
      {
        name: 'Adaptive EWMA Baseline',
        type: 'line',
        data: data.ewmaExpected,
        lineStyle: { color: '#94a3b8', width: 1.5, type: 'dashed' }
      },
      {
        name: 'CUSUM Change-Point Evidence',
        type: 'bar',
        yAxisIndex: 1,
        data: data.cusumSpikes,
        itemStyle: { color: '#f59e0b' },
        barWidth: '25%'
      }
    ]
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3 border-b border-slate-200 pb-3">
        <div>
          <h3 className="text-sm font-bold text-slate-900 font-mono flex items-center gap-2">
            <span>Multi-Timescale Live & Replay Timeline</span>
            <span className="text-[10px] text-slate-500 font-normal">Section 8: Windows [1s, 5s, 30s, 1m, 5m, 15m]</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Synchronized co-plotting of volume shifts, EWMA baseline, and CUSUM change-point spikes.
          </p>
        </div>

        {/* Timescale Selector Buttons */}
        <div className="flex items-center gap-1 bg-slate-50 p-1 rounded-md border border-slate-200 text-xs font-mono">
          <span className="text-[10px] text-slate-500 uppercase px-1.5">Window:</span>
          {timescales.map((w) => (
            <button
              key={w}
              onClick={() => setSelectedWindow(w)}
              className={`px-2 py-0.5 rounded text-xs transition cursor-pointer ${
                selectedWindow === w
                  ? 'bg-blue-600 text-white font-bold'
                  : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              {w}
            </button>
          ))}
        </div>
      </div>

      <ReactECharts option={option} style={{ height: '340px', width: '100%' }} />
    </div>
  );
};
