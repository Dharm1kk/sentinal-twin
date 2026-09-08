"""
DNS Tunnelling Threat Detector Specialist
Implements Section 5.1 & 9.4: Detects exfiltration/tunneling via long subdomains, TXT records, and elevated query rates.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_dns_tunnel.joblib"))


class DNSTunnelSpecialist:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

    def score(self, features_vector: np.ndarray, features_dict: Dict[str, float]) -> Tuple[float, Dict[str, float]]:
        if self.model is None:
            return 0.0, {}

        prob = float(self.model.predict_proba(features_vector.reshape(1, -1))[0, 1])

        evidence = {
            "subdomain_length": round(min(1.0, features_dict.get("dns_mean_query_length", 0.0) / 60.0) * 0.35, 3),
            "dns_entropy": round(min(1.0, features_dict.get("dns_mean_entropy", 0.0) / 4.5) * 0.30, 3),
            "txt_ratio": round(features_dict.get("dns_txt_ratio", 0.0) * 0.20, 3),
            "query_rate_deviation": round(min(1.0, features_dict.get("dns_query_rate", 0.0) / 25.0) * 0.15, 3),
        }
        return round(prob, 4), evidence
