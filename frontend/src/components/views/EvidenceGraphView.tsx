import React, { useState } from 'react';
import { EvidenceGraphChart } from '../../charts/EvidenceGraphChart';
import type { EvidenceGraphData } from '../../types/investigation';
import { Share2, Info, Search } from 'lucide-react';

interface EvidenceGraphViewProps {
  graphData: EvidenceGraphData;
  onSelectNode?: (nodeId: string) => void;
}

export const EvidenceGraphView: React.FC<EvidenceGraphViewProps> = ({ graphData, onSelectNode }) => {
  const [selectedNodeInfo, setSelectedNodeInfo] = useState<string | null>(null);
  const [searchFilter, setSearchFilter] = useState('');

  const handleNodeClick = (nodeId: string) => {
    setSelectedNodeInfo(nodeId);
    if (onSelectNode) {
      onSelectNode(nodeId);
    }
  };

  const filteredNodes = searchFilter
    ? graphData.nodes.filter((n) => n.name.toLowerCase().includes(searchFilter.toLowerCase()))
    : graphData.nodes;

  const activeGraph = {
    ...graphData,
    nodes: filteredNodes.length > 0 ? filteredNodes : graphData.nodes,
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Header Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="h-10 w-10 rounded-xl bg-indigo-50 border border-indigo-200 flex items-center justify-center text-indigo-600 shadow-xs">
              <Share2 className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-slate-900 text-base">Network Topology & Evidence Graph</h3>
                <span className="text-[11px] px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-medium border border-indigo-200">
                  Interactive Graph
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-1">
                Force-directed entity mapping linking internal enclave hosts, external C2 endpoints, and attack paths.
              </p>
            </div>
          </div>

          {/* Node/Link Counts */}
          <div className="flex items-center gap-3 text-xs">
            <div className="bg-slate-50 px-3.5 py-1.5 rounded-lg border border-slate-200">
              <span className="text-slate-400 text-[10px] uppercase font-medium block">Total Entities</span>
              <span className="font-bold font-mono text-indigo-700 text-sm">{graphData.nodes.length} Nodes</span>
            </div>
            <div className="bg-slate-50 px-3.5 py-1.5 rounded-lg border border-slate-200">
              <span className="text-slate-400 text-[10px] uppercase font-medium block">Observed Links</span>
              <span className="font-bold font-mono text-cyan-700 text-sm">{graphData.links.length} Edges</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Graph Canvas */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
        {/* Controls Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="relative w-72">
            <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search entity (e.g. 10.0.0.24)..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:bg-white transition"
            />
          </div>

          <div className="text-xs text-slate-400">
            Scroll to zoom • Drag nodes to reposition • Click to inspect host in triage
          </div>
        </div>

        {/* ECharts Force-Directed Graph */}
        <div className="w-full bg-slate-50/50 rounded-xl border border-slate-200 overflow-hidden">
          <EvidenceGraphChart
            graphData={activeGraph}
            onSelectNode={handleNodeClick}
          />
        </div>

        {/* Selected Node Details */}
        {selectedNodeInfo && (
          <div className="p-3.5 rounded-lg bg-indigo-50 border border-indigo-200 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-indigo-600" />
              <span className="text-slate-800">
                Selected Entity: <strong className="font-mono text-slate-900">{selectedNodeInfo}</strong>
              </span>
            </div>
            <span className="text-indigo-700 text-[11px] font-medium">
              Open &quot;Alert Triage&quot; tab to investigate forensic timeline for this host.
            </span>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
        <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center gap-2 text-blue-700 font-bold">
            <span className="h-2.5 w-2.5 rounded-full bg-blue-500" />
            Monitored Hosts
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            Internal protected endpoints with active behavioral baselines.
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center gap-2 text-amber-700 font-bold">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
            Remote External IPs
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            External C2 drops and destination servers observed across the mirror.
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center gap-2 text-purple-700 font-bold">
            <span className="h-2.5 w-2.5 rounded-full bg-purple-500" />
            DNS Query Domains
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            Queried domain entities and DGA candidates observed in UDP/53 flows.
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-3.5 space-y-1 shadow-xs">
          <div className="flex items-center gap-2 text-cyan-700 font-bold">
            <span className="h-2.5 w-2.5 rounded-full bg-cyan-500" />
            Ports & Services
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            Target ports and protocols. Red edges denote detected attack flows.
          </p>
        </div>
      </div>
    </div>
  );
};
