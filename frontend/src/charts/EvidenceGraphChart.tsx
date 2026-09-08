import React from 'react';
import ReactECharts from 'echarts-for-react';
import type { EvidenceGraphData } from '../types/investigation';

interface EvidenceGraphChartProps {
  graphData: EvidenceGraphData;
  onSelectNode?: (nodeId: string) => void;
}

export const EvidenceGraphChart: React.FC<EvidenceGraphChartProps> = ({ graphData, onSelectNode }) => {
  const nodes = graphData.nodes || [];
  const links = graphData.links || [];

  if (nodes.length === 0) {
    return (
      <div className="bg-white border border-slate-200 rounded-lg p-8 text-center">
        <div className="max-w-md mx-auto space-y-3">
          <div className="h-10 w-10 bg-slate-100 rounded-full flex items-center justify-center mx-auto text-slate-400 font-mono text-xs">
            Ø
          </div>
          <h3 className="text-sm font-semibold text-slate-900">No Topology Graph Available</h3>
          <p className="text-xs text-slate-500 leading-relaxed">
            No active entities or flows are currently mapped. Scan or analyze a dataset to project the dynamic multi-stage evidence graph.
          </p>
        </div>
      </div>
    );
  }

  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      backgroundColor: '#fff',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 11, fontFamily: 'monospace' },
      formatter: (params: any) => {
        if (params.dataType === 'node') {
          return `<strong>Entity:</strong> ${params.data.name}<br/><strong>Risk Index:</strong> ${params.data.value || 0}/100`;
        }
        if (params.dataType === 'edge') {
          return `<strong>Observation:</strong> ${params.data.value || 'Connection'}`;
        }
        return '';
      }
    },
    legend: {
      data: ['Host', 'External IP', 'Domain', 'Port', 'Service'],
      textStyle: { color: '#64748b', fontSize: 11 },
      top: 5
    },
    series: [
      {
        type: 'graph',
        layout: 'force',
        data: nodes,
        links: links,
        categories: [
          { name: 'Host', itemStyle: { color: '#3b82f6' } },
          { name: 'External IP', itemStyle: { color: '#f59e0b' } },
          { name: 'Domain', itemStyle: { color: '#8b5cf6' } },
          { name: 'Port', itemStyle: { color: '#06b6d4' } },
          { name: 'Service', itemStyle: { color: '#10b981' } },
        ],
        roam: true,
        label: {
          show: true,
          position: 'right',
          color: '#475569',
          fontSize: 10,
          fontFamily: 'monospace'
        },
        force: {
          repulsion: 260,
          edgeLength: [60, 160],
          gravity: 0.1
        },
        lineStyle: {
          color: '#cbd5e1',
          curveness: 0.1,
          width: 1.5
        },
        emphasis: {
          focus: 'adjacency',
          lineStyle: {
            width: 3,
            color: '#0ea5e9'
          }
        }
      }
    ]
  };

  const onChartClick = (params: any) => {
    if (params.dataType === 'node' && onSelectNode) {
      onSelectNode(params.data.id || params.data.name);
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3 border-b border-slate-200 pb-3">
        <div>
          <h3 className="text-sm font-bold text-slate-900 font-mono flex items-center gap-2">
            <span>Dynamic NetworkX Evidence Graph</span>
            <span className="text-[10px] text-slate-500 font-normal">Section 13: Host-Domain-IP-Port Entities</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Interactive topological mapping of observed flows, beaconing endpoints, and multi-stage campaign links.
          </p>
        </div>
        <div className="text-xs font-mono text-slate-500">
          Nodes: {nodes.length} | Edges: {links.length}
        </div>
      </div>

      <ReactECharts
        option={option}
        style={{ height: '420px', width: '100%' }}
        onEvents={{ click: onChartClick }}
      />
    </div>
  );
};
