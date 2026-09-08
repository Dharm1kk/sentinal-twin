"""
Botnet / C2 Beaconing Threat Detector Specialist
Implements Section 5.1, 5.6 & 9.2: Evaluates timing regularity, autocorrelation, and inter-arrival regularity.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_c2.joblib"))


class C2Specialist:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

    def score(self, features_vector: np.ndarray, features_dict: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        if self.model is None:
            return 0.0, {}

        prob = float(self.model.predict_proba(features_vector.reshape(1, -1))[0, 1])

        evidence = {
            "timing_regularity": round(features_dict.get("timing_regularity", 0.0) * 0.45, 3),
            "autocorrelation_lag1": round(max(0.0, features_dict.get("autocorrelation_lag1", 0.0)) * 0.35, 3),
            "cv_iat_constancy": round(max(0.0, 1.0 - min(1.0, features_dict.get("cv_iat", 1.0))) * 0.20, 3),
        }
        return round(prob, 4), evidence
