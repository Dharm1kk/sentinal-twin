import unittest
import numpy as np
from backend.ml.gru_detector import GRUSequenceDetector


class TestGRUSequenceDetector(unittest.TestCase):
    def setUp(self):
        self.detector = GRUSequenceDetector(input_dim=34, hidden_dim=16)

    def test_single_step(self):
        x = np.random.randn(1, 34)
        res = self.detector.evaluate_sequence(x)
        self.assertIn("sequence_score", res)
        self.assertTrue(0.0 <= res["sequence_score"] <= 1.0)
        self.assertEqual(res["timesteps"], 1)

    def test_multi_step_sequence(self):
        # 10 timesteps of 34 features
        x = np.random.randn(10, 34)
        res = self.detector.evaluate_sequence(x)
        self.assertEqual(len(res["step_scores"]), 10)
        self.assertTrue(0.0 <= res["sequence_score"] <= 1.0)
        self.assertEqual(res["model"], "Sentinel-GRU-v1")


if __name__ == "__main__":
    unittest.main()
