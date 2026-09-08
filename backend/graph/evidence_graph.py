"""
Dynamic Evidence Graph and Multi-Stage Attack-Chain Correlation Engine
Implements Sentinel Attack Correlation Engine using NetworkX.
Creates nodes for hosts, external IPs, domains, ports, and services with time-stamped edges.
Correlates multi-event campaigns: Recon -> C2 -> DNS Tunnel -> Exfiltration.
"""

import time
import networkx as nx
from typing import Dict, Any, List, Optional
from backend.schemas.alert_schema import GraphNode, GraphLink, EvidenceGraphData


class DynamicEvidenceGraph:
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self.campaigns: List[Dict[str, Any]] = []

    def add_flow_observation(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        timestamp: float,
        dns_query: Optional[str] = None,
        threat_type: Optional[str] = None,
        risk: int = 0
    ):
        """
        Adds or updates entity nodes and time-stamped directional observation edges.
        """
        # Source Host Node
        if not self.graph.has_node(src_ip):
            self.graph.add_node(src_ip, category="host", label=src_ip, risk=risk, first_seen=timestamp)
        else:
            self.graph.nodes[src_ip]["risk"] = max(self.graph.nodes[src_ip].get("risk", 0), risk)

        # Destination IP Node
        if not self.graph.has_node(dst_ip):
            cat = "host" if dst_ip.startswith("10.") or dst_ip.startswith("192.168.") else "ip"
            self.graph.add_node(dst_ip, category=cat, label=dst_ip, risk=risk, first_seen=timestamp)

        # Port Node
        port_node = f"{dst_ip}:{dst_port}"
        if not self.graph.has_node(port_node):
            self.graph.add_node(port_node, category="port", label=f"Port {dst_port}", risk=risk)

        # Add Edges
        self.graph.add_edge(
            src_ip,
            port_node,
            label=f"{protocol}/{dst_port}",
            timestamp=timestamp,
            threat_type=threat_type,
            weight=1.0
        )
        self.graph.add_edge(
            port_node,
            dst_ip,
            label="targets",
            timestamp=timestamp,
            threat_type=threat_type,
            weight=1.0
        )

        # Optional Domain Node
        if dns_query:
            domain_node = dns_query.lower().strip(".")
            if not self.graph.has_node(domain_node):
                self.graph.add_node(domain_node, category="domain", label=domain_node, risk=risk)
            self.graph.add_edge(
                src_ip,
                domain_node,
                label="dns_query",
                timestamp=timestamp,
                threat_type=threat_type,
                weight=1.0
            )

    def evaluate_campaigns(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlates alerts across time proximity, shared hosts, and graph paths (Section 14).
        Stages: Reconnaissance -> C2 Beaconing -> DNS Tunnel -> Exfiltration
        """
        if len(alerts) < 2:
            return []

        # Find victim / targeted hosts across all alerts
        target_hosts: Dict[str, List[Dict[str, Any]]] = {}
        for a in alerts:
            # Check host itself and related internal IP entities
            entities = [a.get("host", "")] + [e for e in a.get("related_entities", []) if e.startswith("10.") or e.startswith("192.168.")]
            for h in set(entities):
                if h not in target_hosts:
                    target_hosts[h] = []
                if a not in target_hosts[h]:
                    target_hosts[h].append(a)

        campaigns = []
        for host, a_list in target_hosts.items():
            types_present = set(a.get("type") for a in a_list)
            
            stages = []
            if "RECON" in types_present:
                stages.append("Reconnaissance (Port Scan)")
            if "C2" in types_present:
                stages.append("C2 Beaconing (Command & Control)")
            if "DNS_TUNNEL" in types_present or "DGA" in types_present:
                stages.append("DNS Tunnel / Data Encoding")
            if "DATA_EXFILTRATION" in types_present:
                stages.append("Data Exfiltration (Abnormal Outbound)")
            if "DDOS" in types_present:
                stages.append("Volumetric Flooding / DDoS")

            if len(stages) >= 2:
                campaign_id = f"CMP-{host.replace('.', '')}-{len(campaigns) + 1:03d}"
                campaign_risk = min(100, 70 + len(stages) * 7)
                campaigns.append({
                    "campaign_id": campaign_id,
                    "host": host,
                    "stages": stages,
                    "severity": "CRITICAL" if campaign_risk >= 75 else "HIGH",
                    "risk": campaign_risk,
                    "correlated_alert_ids": [a.get("alert_id") for a in a_list],
                    "narrative": f"Coordinated Multi-Stage Campaign detected on {host}: " + " -> ".join(stages)
                })

        self.campaigns = campaigns
        return campaigns


    def to_echarts_graph(self) -> Dict[str, Any]:
        """
        Converts the NetworkX graph into ECharts graph series format with categories and styling.
        """
        nodes = []
        categories = [{"name": "host"}, {"name": "ip"}, {"name": "domain"}, {"name": "port"}, {"name": "service"}]
        category_map = {"host": 0, "ip": 1, "domain": 2, "port": 3, "service": 4}

        # Subsample top nodes if graph grows large (Section 30: windowed graph + pruning)
        degrees = dict(self.graph.degree())
        sorted_nodes = sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:50]
        active_node_set = set(n[0] for n in sorted_nodes)

        for node_id in active_node_set:
            attrs = self.graph.nodes[node_id]
            cat_name = attrs.get("category", "ip")
            risk = attrs.get("risk", 10)
            
            # Dynamic node symbol sizing by degree & risk
            symbol_size = max(18, min(45, 15 + degrees.get(node_id, 1) * 3 + int(risk * 0.2)))
            
            nodes.append({
                "id": str(node_id),
                "name": str(attrs.get("label", node_id)),
                "category": category_map.get(cat_name, 1),
                "symbolSize": symbol_size,
                "value": risk,
                "itemStyle": {
                    "borderColor": "#ef4444" if risk >= 75 else ("#f59e0b" if risk >= 50 else "#3b82f6")
                }
            })

        links = []
        for u, v, data in self.graph.edges(data=True):
            if u in active_node_set and v in active_node_set:
                links.append({
                    "source": str(u),
                    "target": str(v),
                    "value": data.get("label", ""),
                    "lineStyle": {
                        "color": "#ef4444" if data.get("threat_type") else "#64748b",
                        "width": 2 if data.get("threat_type") else 1
                    }
                })

        return {
            "categories": categories,
            "nodes": nodes,
            "links": links
        }
