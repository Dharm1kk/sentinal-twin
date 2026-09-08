"""
Evidence Fusion and Competing Hypotheses Engine
Implements Sentinel Evidence Fusion Engine:
Fuses ML scores, baseline deviations, temporal persistence, graph centrality, and statistical evidence.
Applies contradiction penalties and maintains top competing hypotheses.
"""

from typing import Dict, Any, List, Tuple
from backend.schemas.alert_schema import Hypothesis, EvidenceItem


class EvidenceFusionEngine:
    def __init__(
        self,
        w_ml: float = 0.35,
        w_base: float = 0.25,
        w_temp: float = 0.15,
        w_graph: float = 0.10,
        w_stat: float = 0.10,
        w_nov: float = 0.05
    ):
        self.w_ml = w_ml
        self.w_base = w_base
        self.w_temp = w_temp
        self.w_graph = w_graph
        self.w_stat = w_stat
        self.w_nov = w_nov

    def fuse(
        self,
        threat_scores: Dict[str, float],
        evidence_maps: Dict[str, Dict[str, float]],
        baseline_deviation: float,
        temporal_score: float,
        graph_score: float,
        novelty_score: float,
        features_dict: Dict[str, float]
    ) -> Tuple[str, float, List[Hypothesis], List[EvidenceItem]]:
        """
        Executes multi-evidence fusion across competing threat hypotheses.
        Returns:
            - winning_threat: str
            - winning_confidence: float
            - sorted_hypotheses: List[Hypothesis]
            - top_evidence_items: List[EvidenceItem]
        """
        fused_hypotheses: Dict[str, float] = {}

        for threat, p_ml in threat_scores.items():
            # 1. Base statistical contribution tailored to threat
            stat_score = 0.0
            penalty = 0.0

            if threat == "DDOS":
                stat_score = min(1.0, (features_dict.get("packet_rate", 0.0) / 1500.0) * 0.5 + features_dict.get("src_ip_entropy", 0.0) / 10.0)
                # Contradiction: if packet rate is low, severely penalize DDoS
                if features_dict.get("packet_rate", 0.0) < 50.0:
                    penalty += 0.40

            elif threat == "C2":
                stat_score = features_dict.get("timing_regularity", 0.0)
                # Contradiction: high jitter / high CV penalizes C2
                if features_dict.get("cv_iat", 0.0) > 0.80:
                    penalty += 0.35

            elif threat == "DNS_TUNNEL":
                stat_score = min(1.0, features_dict.get("dns_mean_query_length", 0.0) / 50.0)
                # Contradiction: low query length (< 25) penalizes tunnel
                if features_dict.get("dns_mean_query_length", 0.0) < 25.0:
                    penalty += 0.40

            elif threat == "DGA":
                stat_score = min(1.0, features_dict.get("dns_mean_entropy", 0.0) / 4.0)
                # Contradiction: normal domain entropy penalizes DGA
                if features_dict.get("dns_mean_entropy", 0.0) < 2.5:
                    penalty += 0.40

            elif threat == "RECON":
                stat_score = min(1.0, features_dict.get("ports_per_sec", 0.0) / 50.0)
                if features_dict.get("ports_per_sec", 0.0) < 2.0:
                    penalty += 0.40

            elif threat == "ENCRYPTED_MALWARE":
                stat_score = features_dict.get("tls_suspicion_score", 0.0)
                if features_dict.get("has_tls", 0.0) == 0.0:
                    penalty += 0.80

            elif threat == "DATA_EXFILTRATION":
                stat_score = min(1.0, features_dict.get("exfil_byte_ratio", 0.0) / 5.0)
                if features_dict.get("exfil_byte_ratio", 0.0) < 1.0:
                    penalty += 0.50

            # Linear multi-factor fusion
            raw_fused = (
                self.w_ml * p_ml
                + self.w_base * baseline_deviation
                + self.w_temp * temporal_score
                + self.w_graph * graph_score
                + self.w_stat * stat_score
                + self.w_nov * novelty_score
            ) - penalty

            fused_score = float(max(0.0, min(1.0, raw_fused)))
            fused_hypotheses[threat] = round(fused_score, 3)

        # Sort hypotheses by score descending
        sorted_hyps = sorted(fused_hypotheses.items(), key=lambda x: x[1], reverse=True)
        top_threat, top_score = sorted_hyps[0]

        # Check Section 12 Novel Behaviour condition:
        # if novelty_score > 0.60 and max(known_hypothesis_scores) < 0.50: alert_type = "NOVEL_BEHAVIOUR"
        if novelty_score >= 0.55 and top_score < 0.50:
            top_threat = "NOVEL_BEHAVIOUR"
            top_score = novelty_score

        # Convert to Pydantic Hypothesis models
        hypotheses_models = [Hypothesis(type=t, score=s) for t, s in sorted_hyps[:4]]

        # Extract top feature evidence items for the winning threat
        top_ev_map = evidence_maps.get(top_threat, {})
        evidence_items = []
        for feat_name, impact in top_ev_map.items():
            feat_val = float(features_dict.get(feat_name, impact))
            evidence_items.append(EvidenceItem(feature=feat_name, value=round(feat_val, 2), impact=round(impact, 3)))

        return top_threat, top_score, hypotheses_models, evidence_items
