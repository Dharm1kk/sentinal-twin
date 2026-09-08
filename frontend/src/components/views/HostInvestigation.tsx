import React, { useState } from 'react';
import { Server, ArrowUpRight } from 'lucide-react';

interface HostInvestigationProps {
  initialHost?: string;
}

export const HostInvestigation: React.FC<HostInvestigationProps> = ({ initialHost = '10.0.0.24' }) => {
  const [selectedHost, setSelectedHost] = useState<string>(initialHost);

  const availableHosts = ['10.0.0.24', '10.0.0.102', '10.0.0.15', '10.0.0.42', '10.0.0.88'];

  // Host baseline profile data mapping strictly to Section 7
  const hostProfiles: Record<string, any> = {
    '10.0.0.24': {
      role: 'Workstation / Finance Client',
      status: 'UNDER_INVESTIGATION',
      metrics: [
        { name: 'Packet Rate', observed: 850.0, median: 45.2, mad: 8.4, robust_z: 64.3, ewma: 48.1, cusum: 9.2, unit: 'pkts/s', anomalous: true },
        { name: 'Byte Rate', observed: 980000.0, median: 18500.0, mad: 3400.0, robust_z: 190.8, ewma: 21000.0, cusum: 14.5, unit: 'bytes/s', anomalous: true },
        { name: 'DNS Query Rate', observed: 35.0, median: 1.2, mad: 0.4, robust_z: 56.9, ewma: 1.5, cusum: 11.8, unit: 'q/s', anomalous: true },
        { name: 'Unique Destinations', observed: 4, median: 3.0, mad: 1.0, robust_z: 0.67, ewma: 3.2, cusum: 0.2, unit: 'IPs', anomalous: false },
        { name: 'Exfil Byte Ratio', observed: 38.5, median: 0.22, mad: 0.05, robust_z: 516.5, ewma: 0.25, cusum: 22.1, unit: 'out/in', anomalous: true },
      ],
      sessions: [
        { time: '18:22:15', dst: '198.51.100.77', port: 8443, proto: 'TCP', alert: 'C2_BEACON' },
        { time: '18:23:40', dst: '8.8.8.8', port: 53, proto: 'UDP', alert: 'DNS_TUNNEL' },
        { time: '18:24:02', dst: '203.0.113.88', port: 443, proto: 'TCP', alert: 'DATA_EXFILTRATION' },
      ]
    },
    '10.0.0.102': {
      role: 'Internal Workstation (Compromised)',
      status: 'ACTIVE_RECON',
      metrics: [
        { name: 'Packet Rate', observed: 420.0, median: 30.0, mad: 5.0, robust_z: 52.6, ewma: 32.0, cusum: 8.5, unit: 'pkts/s', anomalous: true },
        { name: 'Byte Rate', observed: 25000.0, median: 12000.0, mad: 2000.0, robust_z: 4.38, ewma: 12500.0, cusum: 2.1, unit: 'bytes/s', anomalous: false },
        { name: 'DNS Query Rate', observed: 0.8, median: 0.9, mad: 0.2, robust_z: -0.34, ewma: 0.9, cusum: 0.0, unit: 'q/s', anomalous: false },
        { name: 'Unique Destinations', observed: 100, median: 2.0, mad: 0.5, robust_z: 132.2, ewma: 2.1, cusum: 24.0, unit: 'IPs/ports', anomalous: true },
        { name: 'Exfil Byte Ratio', observed: 0.15, median: 0.18, mad: 0.04, robust_z: -0.50, ewma: 0.18, cusum: 0.0, unit: 'out/in', anomalous: false },
      ],
      sessions: [
        { time: '18:21:05', dst: '10.0.0.24', port: 22, proto: 'TCP', alert: 'RECON_SCAN' },
        { time: '18:21:06', dst: '10.0.0.24', port: 80, proto: 'TCP', alert: 'RECON_SCAN' },
        { time: '18:21:07', dst: '10.0.0.24', port: 443, proto: 'TCP', alert: 'RECON_SCAN' },
      ]
    }
  };

  const currentProfile = hostProfiles[selectedHost] || hostProfiles['10.0.0.24'];

  return (
    <div className="space-y-5">
      {/* Top Selector Bar */}
      <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
            <Server className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-bold font-mono text-slate-900">Host Baseline Explorer</h3>
              <span className="text-[11px] px-2 py-0.5 rounded bg-blue-50 text-blue-700 font-mono border border-blue-200">
                Section 7: Behavioral Profiling
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5 font-mono">
              Individual host profiles isolate server vs workstation baselines, avoiding global threshold false alarms.
            </p>
          </div>
        </div>

        {/* Host Selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-mono">Target Host:</span>
          <select
            value={selectedHost}
            onChange={(e) => setSelectedHost(e.target.value)}
            className="bg-white text-slate-900 border border-slate-300 text-xs font-mono rounded px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            {availableHosts.map((h) => (
              <option key={h} value={h}>
                {h}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Host Specific Metrics Table */}
      <div className="bg-white border border-slate-200 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3 border-b border-slate-200 pb-3">
          <div>
            <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-700">
              {selectedHost} • {currentProfile.role}
            </h4>
            <div className="text-xs text-slate-500 font-mono mt-0.5">
              Formulation: <code className="text-blue-600">robust_z = (observed - median) / (1.4826 * MAD)</code>
            </div>
          </div>
          <span className="text-xs font-bold font-mono px-2 py-1 rounded bg-rose-50 text-rose-700 border border-rose-200">
            {currentProfile.status}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50 text-slate-500 uppercase text-[10px] border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-3">Monitored Metric</th>
                <th className="py-2.5 px-3">Observed Window Value</th>
                <th className="py-2.5 px-3">Rolling Median</th>
                <th className="py-2.5 px-3">Rolling MAD</th>
                <th className="py-2.5 px-3">Robust Z-Score</th>
                <th className="py-2.5 px-3">Adaptive EWMA</th>
                <th className="py-2.5 px-3">CUSUM Mean Shift</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {currentProfile.metrics.map((m: any, idx: number) => (
                <tr key={idx} className="hover:bg-slate-50 transition">
                  <td className="py-2.5 px-3 font-semibold text-slate-900">{m.name}</td>
                  <td className="py-2.5 px-3 text-cyan-600 font-bold">
                    {m.observed.toLocaleString()} <span className="text-[10px] text-slate-400">{m.unit}</span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-700">{m.median}</td>
                  <td className="py-2.5 px-3 text-slate-500">±{m.mad}</td>
                  <td className={`py-2.5 px-3 font-bold ${m.anomalous ? 'text-rose-600' : 'text-slate-500'}`}>
                    {m.robust_z > 0 ? `+${m.robust_z}` : m.robust_z}σ
                  </td>
                  <td className="py-2.5 px-3 text-slate-500">{m.ewma}</td>
                  <td className="py-2.5 px-3 text-amber-600 font-bold">{m.cusum}</td>
                  <td className="py-2.5 px-3 text-right">
                    {m.anomalous ? (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                        DEVIATION
                      </span>
                    ) : (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                        NOMINAL
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Associated Sessions */}
      <div className="bg-white border border-slate-200 rounded-lg p-4">
        <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-700 mb-3">
          Correlated Active Outbound Sessions
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {currentProfile.sessions.map((s: any, idx: number) => (
            <div key={idx} className="bg-slate-50 border border-slate-200 rounded p-3 text-xs font-mono">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-slate-500">{s.time}</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-50 text-rose-700 border border-rose-200">
                  {s.alert}
                </span>
              </div>
              <div className="text-slate-900 font-semibold flex items-center gap-1">
                {s.dst}:{s.port}
                <ArrowUpRight className="h-3.5 w-3.5 text-slate-400" />
              </div>
              <div className="text-[11px] text-slate-500 mt-1">Protocol: {s.proto}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
