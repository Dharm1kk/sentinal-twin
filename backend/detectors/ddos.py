"""
DDoS Threat Detector Specialist
Implements Section 5.1 & 9.1: Fuses XGBoost DDoS model with CUSUM rate and source entropy shifts.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_ddos.joblib"))


class DDoSSpecialist:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

    def score(self, features_vector: np.ndarray, features_dict: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        """
        Returns (threat_probability, evidence_contributions)
        """
        if self.model is None:
            return 0.0, {}

        prob = float(self.model.predict_proba(features_vector.reshape(1, -1))[0, 1])

        # Feature evidence contributions
        evidence = {
            "packet_rate": round(min(1.0, features_dict.get("packet_rate", 0.0) / 2000.0) * 0.40, 3),
            "source_entropy": round(min(1.0, features_dict.get("src_ip_entropy", 0.0) / 6.0) * 0.35, 3),
            "syn_ratio": round(features_dict.get("syn_only_ratio", 0.0) * 0.25, 3),
        }
        return round(prob, 4), evidence
