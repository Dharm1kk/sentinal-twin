"""
Transparent Risk Scoring Engine
Implements Sentinel Risk Scoring Engine:
Risk = 0.30 * threat_conf + 0.20 * baseline_dev + 0.15 * temp_persist + 0.15 * graph_corr + 0.10 * novelty + 0.10 * ev_quality
Scales strictly to 0-100: LOW (0-24), MEDIUM (25-49), HIGH (50-74), CRITICAL (75-100).
"""

from typing import Dict, Any, Tuple


class RiskEngine:
    def __init__(
        self,
        w_threat: float = 0.30,
        w_base: float = 0.20,
        w_temp: float = 0.15,
        w_graph: float = 0.15,
        w_novelty: float = 0.10,
        w_quality: float = 0.10
    ):
        self.w_threat = w_threat
        self.w_base = w_base
        self.w_temp = w_temp
        self.w_graph = w_graph
        self.w_novelty = w_novelty
        self.w_quality = w_quality

    def calculate_risk(
        self,
        threat_confidence: float,
        baseline_deviation: float,
        temporal_persistence: float,
        graph_correlation: float,
        novelty: float,
        evidence_quality: float = 0.90
    ) -> Tuple[int, str, Dict[str, float]]:
        """
        Calculates composite risk (0-100) and severity category.
        Returns (risk_score_int, severity_str, breakdown_dict)
        """
        # Ensure all components are in [0.0, 1.0]
        c_threat = min(1.0, max(0.0, threat_confidence))
        d_base = min(1.0, max(0.0, baseline_deviation))
        p_temp = min(1.0, max(0.0, temporal_persistence))
        g_graph = min(1.0, max(0.0, graph_correlation))
        s_novelty = min(1.0, max(0.0, novelty))
        q_quality = min(1.0, max(0.0, evidence_quality))

        composite_float = (
            self.w_threat * c_threat
            + self.w_base * d_base
            + self.w_temp * p_temp
            + self.w_graph * g_graph
            + self.w_novelty * s_novelty
            + self.w_quality * q_quality
        ) * 100.0

        risk_score = int(round(min(100.0, max(0.0, composite_float))))

        # Section 15 Severity Tiers
        if risk_score >= 75:
            severity = "CRITICAL"
        elif risk_score >= 50:
            severity = "HIGH"
        elif risk_score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        breakdown = {
            "threat_confidence_part": round(self.w_threat * c_threat * 100.0, 2),
            "baseline_deviation_part": round(self.w_base * d_base * 100.0, 2),
            "temporal_persistence_part": round(self.w_temp * p_temp * 100.0, 2),
            "graph_correlation_part": round(self.w_graph * g_graph * 100.0, 2),
            "novelty_part": round(self.w_novelty * s_novelty * 100.0, 2),
            "evidence_quality_part": round(self.w_quality * q_quality * 100.0, 2),
        }

        return risk_score, severity, breakdown

    @staticmethod
    def calculate_network_security_score(alerts: list) -> dict:
        """
        Calculates the 0-100 Network Security Score as specified in SIH 2026 Slide 2 & 3:
        "Continuously measures how the network's security score changes. If score goes low, sends a network wide alert."
        100 = Optimal Network Health
        < 50 = Critical Threat Active -> Triggers Network-Wide Security Alert
        """
        if not alerts:
            return {
                "security_score": 98,
                "status": "OPTIMAL",
                "network_alert_triggered": False,
                "highest_risk": 2,
                "active_threats_count": 0,
                "critical_threats_count": 0,
                "summary": "Network operates within established behavioral baseline norms."
            }

        max_risk = max([a.get("risk", 0) for a in alerts], default=0)
        critical_count = sum(1 for a in alerts if a.get("severity") in ("CRITICAL", "HIGH"))

        penalty = max_risk * 0.75 + min(25, critical_count * 5)
        security_score = int(round(max(0.0, min(100.0, 100.0 - penalty))))

        alert_triggered = security_score < 50

        if security_score >= 80:
            status = "HEALTHY"
        elif security_score >= 50:
            status = "DEGRADED"
        elif security_score >= 25:
            status = "CRITICAL_RISK"
        else:
            status = "COMPROMISED"

        summary = (
            f"Network-Wide Alert Active: Enclave security health dropped to {security_score}/100 "
            f"due to {critical_count} high-severity threat incidents."
            if alert_triggered else
            f"Network Security Score is {security_score}/100 ({status}). Telemetry monitored across active hosts."
        )

        return {
            "security_score": security_score,
            "status": status,
            "network_alert_triggered": alert_triggered,
            "highest_risk": max_risk,
            "active_threats_count": len(alerts),
            "critical_threats_count": critical_count,
            "summary": summary
        }
