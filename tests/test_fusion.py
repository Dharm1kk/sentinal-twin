"""
Unit tests for Evidence Fusion and Competing Hypotheses (Section 10)
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.fusion import EvidenceFusionEngine
from backend.features import FEATURE_COLUMNS


class TestEvidenceFusion(unittest.TestCase):
    def setUp(self):
        self.fusion = EvidenceFusionEngine()

    def test_competing_hypotheses_and_penalties(self):
        threat_scores = {
            "DNS_TUNNEL": 0.90,
            "DGA": 0.85,
            "C2": 0.10,
            "DDOS": 0.05
        }
        evidence_maps = {
            "DNS_TUNNEL": {"dns_entropy": 0.35, "subdomain_length": 0.30},
            "DGA": {"dns_entropy": 0.35, "nxdomain_ratio": 0.30}
        }
        feats = {col: 0.0 for col in FEATURE_COLUMNS}
        feats["dns_mean_query_length"] = 55.0
        feats["dns_mean_entropy"] = 4.2
        feats["dns_nxdomain_ratio"] = 0.0  # Zero NXDOMAINs should penalize DGA

        top_threat, top_conf, hyps, ev = self.fusion.fuse(
            threat_scores=threat_scores,
            evidence_maps=evidence_maps,
            baseline_deviation=0.7,
            temporal_score=0.6,
            graph_score=0.4,
            novelty_score=0.2,
            features_dict=feats
        )

        self.assertEqual(top_threat, "DNS_TUNNEL")
        self.assertGreater(top_conf, 0.60)
        self.assertTrue(len(hyps) >= 2)


if __name__ == "__main__":
    unittest.main()
