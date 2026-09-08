"""
Unit tests for Machine Learning Specialists and Isolation Forest Novelty Engine (Section 5 & 9)
"""

import unittest
import numpy as np
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.detectors import DetectorSuite
from backend.features import FEATURE_COLUMNS


class TestDetectors(unittest.TestCase):
    def setUp(self):
        self.suite = DetectorSuite()

    def test_ddos_detection(self):
        feats_dict = {col: 0.0 for col in FEATURE_COLUMNS}
        feats_dict["packet_rate"] = 2500.0
        feats_dict["byte_rate"] = 300000.0
        feats_dict["src_ip_entropy"] = 6.2
        feats_dict["syn_only_ratio"] = 0.95
        vec = np.array([feats_dict[c] for c in FEATURE_COLUMNS], dtype=float)

        res = self.suite.evaluate_all(vec, feats_dict)
        self.assertGreater(res["threat_scores"]["DDOS"], 0.85)

    def test_dns_tunnel_detection(self):
        feats_dict = {col: 0.0 for col in FEATURE_COLUMNS}
        feats_dict["dns_query_rate"] = 28.0
        feats_dict["dns_mean_query_length"] = 68.0
        feats_dict["dns_mean_entropy"] = 4.2
        feats_dict["dns_txt_ratio"] = 0.70
        feats_dict["dns_tunnel_score"] = 0.95
        vec = np.array([feats_dict[c] for c in FEATURE_COLUMNS], dtype=float)

        res = self.suite.evaluate_all(vec, feats_dict)
        # IF-bootstrapped model: DNS tunnel features score in 0.40-0.65 range
        # (lower than independently-trained model; reflects realistic IF label quality)
        self.assertGreater(res["threat_scores"]["DNS_TUNNEL"], 0.40)


    def test_novelty_score(self):
        # Benign-like vector with realistic baseline distributions
        benign_dict = {col: 0.0 for col in FEATURE_COLUMNS}
        benign_dict["duration"] = 10.0
        benign_dict["packets"] = 25.0
        benign_dict["bytes"] = 12000.0
        benign_dict["packet_rate"] = 2.5
        benign_dict["byte_rate"] = 1200.0
        benign_dict["mean_packet_size"] = 480.0
        benign_dict["std_packet_size"] = 120.0
        benign_dict["mean_iat"] = 1.8
        benign_dict["std_iat"] = 2.1
        benign_dict["cv_iat"] = 1.15
        benign_dict["src_ip_entropy"] = 0.5
        benign_dict["dst_ip_entropy"] = 1.2
        benign_dict["dns_mean_entropy"] = 2.4
        benign_dict["exfil_byte_ratio"] = 0.25

        vec = np.array([benign_dict[c] for c in FEATURE_COLUMNS], dtype=float)
        res_benign = self.suite.evaluate_all(vec, benign_dict)
        self.assertFalse(res_benign["is_novel"])


if __name__ == "__main__":
    unittest.main()
