"""
Encrypted Malware Traffic & Exfiltration Specialist
Implements Section 5.1 & 9.6: Detects malicious TLS configurations and high asymmetric byte exfiltration.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple

MODEL_TLS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_encrypted.joblib"))
MODEL_EXFIL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_exfil.joblib"))


class EncryptedMalwareSpecialist:
    def __init__(self):
        self.model_tls = joblib.load(MODEL_TLS_PATH) if os.path.exists(MODEL_TLS_PATH) else None
        self.model_exfil = joblib.load(MODEL_EXFIL_PATH) if os.path.exists(MODEL_EXFIL_PATH) else None

    def score(self, features_vector: np.ndarray, features_dict: Dict[str, float]) -> Tuple[float, Dict[str, float], float, Dict[str, float]]:
        """
        Returns (tls_prob, tls_evidence, exfil_prob, exfil_evidence)
        """
        vec = features_vector.reshape(1, -1)
        
        # TLS malware score
        p_tls = float(self.model_tls.predict_proba(vec)[0, 1]) if self.model_tls else 0.0
        tls_evidence = {
            "tls_suspicion": round(features_dict.get("tls_suspicion_score", 0.0) * 0.45, 3),
            "missing_sni": round((1.0 - features_dict.get("has_sni", 1.0)) * 0.35, 3),
            "rare_ciphers": round((1.0 if features_dict.get("tls_cipher_count", 20.0) < 4 else 0.0) * 0.20, 3),
        }

        # Exfiltration score
        p_exfil = float(self.model_exfil.predict_proba(vec)[0, 1]) if self.model_exfil else 0.0
        exfil_evidence = {
            "exfil_byte_ratio": round(min(1.0, features_dict.get("exfil_byte_ratio", 0.0) / 10.0) * 0.60, 3),
            "outbound_volume": round(min(1.0, features_dict.get("outbound_bytes", 0.0) / 1000000.0) * 0.40, 3),
        }

        return round(p_tls, 4), tls_evidence, round(p_exfil, 4), exfil_evidence
