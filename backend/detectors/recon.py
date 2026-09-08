"""
Reconnaissance & Port Scanning Specialist
Implements Section 5.1 & 9.5: Detects horizontal/vertical port sweeps and high fan-out reconnaissance.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_recon.joblib"))


class ReconSpecialist:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

    def score(self, features_vector: np.ndarray, features_dict: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        if self.model is None:
            return 0.0, {}

        prob = float(self.model.predict_proba(features_vector.reshape(1, -1))[0, 1])

        evidence = {
            "ports_per_sec": round(min(1.0, features_dict.get("ports_per_sec", 0.0) / 100.0) * 0.40, 3),
            "syn_only_ratio": round(features_dict.get("syn_only_ratio", 0.0) * 0.30, 3),
            "fan_out_score": round(min(1.0, (features_dict.get("unique_destinations", 0.0) * features_dict.get("unique_ports", 0.0)) / 200.0) * 0.30, 3),
        }
        return round(prob, 4), evidence
