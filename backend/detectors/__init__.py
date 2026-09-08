"""
Detector Suite Initializer
Assembles all specialist threat models and the novelty engine.
"""

from typing import Dict, Any, Tuple
import numpy as np

from .ddos import DDoSSpecialist
from .c2 import C2Specialist
from .dga import DGASpecialist
from .dns_tunnel import DNSTunnelSpecialist
from .recon import ReconSpecialist
from .encrypted import EncryptedMalwareSpecialist
from .novelty import NoveltyDetector


class DetectorSuite:
    def __init__(self):
        self.ddos = DDoSSpecialist()
        self.c2 = C2Specialist()
        self.dga = DGASpecialist()
        self.dns_tunnel = DNSTunnelSpecialist()
        self.recon = ReconSpecialist()
        self.encrypted = EncryptedMalwareSpecialist()
        self.novelty = NoveltyDetector()

    def evaluate_all(
        self,
        features_vector: np.ndarray,
        features_dict: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Runs all 7 specialist classifiers and the Isolation Forest model.
        Returns:
            - known_threat_scores: Dict[str, float]
            - evidence_breakdowns: Dict[str, Dict[str, float]]
            - novelty_score: float
            - is_novel_outlier: bool
        """
        p_ddos, ev_ddos = self.ddos.score(features_vector, features_dict)
        p_c2, ev_c2 = self.c2.score(features_vector, features_dict)
        p_dga, ev_dga = self.dga.score(features_vector, features_dict)
        p_dns, ev_dns = self.dns_tunnel.score(features_vector, features_dict)
        p_recon, ev_recon = self.recon.score(features_vector, features_dict)
        p_tls, ev_tls, p_exfil, ev_exfil = self.encrypted.score(features_vector, features_dict)

        novelty_score, is_novel = self.novelty.score(features_vector)

        threat_scores = {
            "DDOS": p_ddos,
            "C2": p_c2,
            "DGA": p_dga,
            "DNS_TUNNEL": p_dns,
            "RECON": p_recon,
            "ENCRYPTED_MALWARE": p_tls,
            "DATA_EXFILTRATION": p_exfil,
        }

        evidence_maps = {
            "DDOS": ev_ddos,
            "C2": ev_c2,
            "DGA": ev_dga,
            "DNS_TUNNEL": ev_dns,
            "RECON": ev_recon,
            "ENCRYPTED_MALWARE": ev_tls,
            "DATA_EXFILTRATION": ev_exfil,
        }

        return {
            "threat_scores": threat_scores,
            "evidence_maps": evidence_maps,
            "novelty_score": novelty_score,
            "is_novel": is_novel
        }
