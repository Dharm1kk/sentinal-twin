"""
Unit tests for Dynamic Evidence Graph and Campaign Correlation (Section 13 & 14)
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.graph import DynamicEvidenceGraph


class TestEvidenceGraph(unittest.TestCase):
    def test_graph_nodes_and_campaign(self):
        graph = DynamicEvidenceGraph()
        t = 100.0

        graph.add_flow_observation(
            src_ip="10.0.0.102",
            dst_ip="10.0.0.24",
            dst_port=80,
            protocol="TCP",
            timestamp=t,
            threat_type="RECON"
        )
        graph.add_flow_observation(
            src_ip="10.0.0.24",
            dst_ip="198.51.100.77",
            dst_port=8443,
            protocol="TCP",
            timestamp=t + 5,
            threat_type="C2"
        )

        echarts_data = graph.to_echarts_graph()
        self.assertGreater(len(echarts_data["nodes"]), 0)
        self.assertGreater(len(echarts_data["links"]), 0)

        alerts = [
            {"alert_id": "ARG-001", "host": "10.0.0.102", "type": "RECON", "related_entities": ["10.0.0.24"]},
            {"alert_id": "ARG-002", "host": "10.0.0.24", "type": "C2", "related_entities": ["198.51.100.77"]},
            {"alert_id": "ARG-003", "host": "10.0.0.24", "type": "DNS_TUNNEL", "related_entities": ["10.0.0.24"]},
        ]
        campaigns = graph.evaluate_campaigns(alerts)
        self.assertGreater(len(campaigns), 0)
        self.assertIn("10.0.0.24", campaigns[0]["host"])


if __name__ == "__main__":
    unittest.main()
