"""
Threat Behavior Graph (Stage 4/5 correlation layer).

Nodes: hosts (src_ip), destinations (dst_ip). Edges: alerts, carrying
threat_class, confidence, and timestamp. Alerts touching the same host (or
sharing a destination/fingerprint across hosts) within a correlation
window are merged into one incident instead of being reported as isolated
events -- this is the brief's central differentiator: one correlated
incident with multiple evidence signals beats four unrelated alerts.
"""

from __future__ import annotations

import itertools
import uuid
from collections import defaultdict

import networkx as nx

from schema.alert_schema import Alert

_CORRELATION_WINDOW_S = 120.0
_incident_counter = itertools.count(1)


class ThreatGraph:
    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()
        # host_ip -> list of (timestamp_epoch_ms, incident_id) for recent alerts on that host
        self._host_recent_incidents: dict[str, list[tuple[float, str]]] = defaultdict(list)

    def _new_incident_id(self) -> str:
        return f"incident-{next(_incident_counter):04d}-{uuid.uuid4().hex[:4]}"

    def _parse_ts(self, iso_ts: str) -> float:
        # ISO8601 -> epoch seconds, tolerant of the "Z" suffix we emit
        from datetime import datetime
        return datetime.fromisoformat(iso_ts.replace("Z", "+00:00")).timestamp()

    def ingest(self, alert: Alert) -> str:
        """Add an alert to the graph, merge with a recent incident on the
        same host if one exists within the correlation window, and return
        the resulting incident_id."""
        now = self._parse_ts(alert.timestamp)
        host = alert.src_ip or "unknown"

        recent = self._host_recent_incidents[host]
        recent[:] = [(t, iid) for (t, iid) in recent if now - t <= _CORRELATION_WINDOW_S]

        if recent:
            incident_id = recent[-1][1]
        else:
            incident_id = self._new_incident_id()

        recent.append((now, incident_id))
        alert.incident_id = incident_id

        self.graph.add_node(host, kind="host")
        if alert.dst_ip:
            self.graph.add_node(alert.dst_ip, kind="destination")
            self.graph.add_edge(
                host, alert.dst_ip,
                key=alert.flow_id,
                threat_class=alert.threat_class.value,
                confidence=alert.confidence,
                severity=alert.severity.value,
                incident_id=incident_id,
                timestamp=alert.timestamp,
            )
        return incident_id

    def incident_summary(self, incident_id: str) -> dict:
        """Pull together every alert edge tagged with this incident for a drill-down view."""
        edges = [
            {"src": u, "dst": v, **data}
            for u, v, data in self.graph.edges(data=True)
            if data.get("incident_id") == incident_id
        ]
        threat_classes = sorted({e["threat_class"] for e in edges})
        max_conf = max((e["confidence"] for e in edges), default=0.0)
        return {
            "incident_id": incident_id,
            "threat_classes": threat_classes,
            "alert_count": len(edges),
            "max_confidence": round(max_conf, 3),
            "edges": edges,
        }

    def shared_fingerprint_hosts(self, min_hosts: int = 2, max_hosts: int = 15) -> dict[str, list[str]]:
        """Internal hosts sharing an external destination/fingerprint across
        *non-volumetric* alerts -- surfaces potential coordinated behavior
        (e.g. multiple implants beaconing to the same C2, or several hosts
        exfiltrating to the same drop point).

        Volumetric DDoS is deliberately excluded: a flood victim naturally
        has thousands of distinct (often spoofed) sources, which is a
        different phenomenon from genuine coordinated host behavior and
        would otherwise drown out this signal.
        """
        dst_to_hosts: dict[str, set] = defaultdict(set)
        for u, v, data in self.graph.edges(data=True):
            if data.get("threat_class") == "volumetric_ddos":
                continue
            if self.graph.nodes.get(v, {}).get("kind") == "destination":
                dst_to_hosts[v].add(u)
        return {
            dst: sorted(hosts)
            for dst, hosts in dst_to_hosts.items()
            if min_hosts <= len(hosts) <= max_hosts
        }

    def to_cytoscape_json(self) -> dict:
        """Export in a shape Cytoscape.js can consume directly for the dashboard."""
        elements = []
        for node, data in self.graph.nodes(data=True):
            elements.append({"data": {"id": node, "kind": data.get("kind", "unknown")}})
        for u, v, data in self.graph.edges(data=True):
            elements.append({"data": {"source": u, "target": v, **data}})
        return {"elements": elements}
