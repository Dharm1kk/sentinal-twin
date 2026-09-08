"""
Unit tests for Host Behavioral Baselines Engine (Section 7)
"""

import unittest
import numpy as np
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.baselines import MetricTracker, HostBaselineManager


class TestHostBaselines(unittest.TestCase):
    def test_robust_z_and_mad(self):
        tracker = MetricTracker(name="packet_rate", window_size=30)
        # Feed normal baseline points around 50
        for _ in range(25):
            tracker.update(50.0 + np.random.uniform(-3.0, 3.0))

        # Test normal point
        res_normal = tracker.update(51.0)
        self.assertLess(abs(res_normal["robust_z"]), 2.0)

        # Test attack surge
        res_spike = tracker.update(600.0)
        self.assertGreater(res_spike["robust_z"], 10.0)
        self.assertGreater(res_spike["cusum_score"], 3.0)

    def test_host_baseline_manager(self):
        mgr = HostBaselineManager()
        host = "10.0.0.24"

        for _ in range(20):
            mgr.update_host(host, {
                "packet_rate": 30.0,
                "byte_rate": 15000.0,
                "dns_query_rate": 1.0,
                "unique_destinations": 2.0,
                "exfil_byte_ratio": 0.2
            })

        profile = mgr.get_host_profile(host)
        self.assertIsNotNone(profile)
        self.assertIn("packet_rate", profile)
        self.assertAlmostEqual(profile["packet_rate"]["rolling_median"], 30.0, delta=2.0)


if __name__ == "__main__":
    unittest.main()
