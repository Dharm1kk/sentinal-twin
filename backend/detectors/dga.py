"""
DGA Domain Detector Specialist
Implements Section 5.1 & 9.3: Evaluates character randomness, n-gram scores, and NXDOMAIN ratios.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_dga.joblib"))


class DGASpecialist:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

    def score(self, features_vector: np.ndarray, features_dict: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        if self.model is None:
            return 0.0, {}

        prob = float(self.model.predict_proba(features_vector.reshape(1, -1))[0, 1])

        evidence = {
            "domain_entropy": round(min(1.0, features_dict.get("dns_mean_entropy", 0.0) / 4.5) * 0.45, 3),
            "nxdomain_ratio": round(features_dict.get("dns_nxdomain_ratio", 0.0) * 0.35, 3),
            "dga_score": round(features_dict.get("dns_dga_score", 0.0) * 0.20, 3),
        }
        return round(prob, 4), evidence
