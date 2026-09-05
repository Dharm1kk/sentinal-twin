"""
Alert manager (Stage 5).

Takes raw detector output (deterministic rule hits + Isolation Forest
anomaly score) for a single flow and produces zero or more standardized
Alert objects. When both a rule and the anomaly model agree, confidence is
boosted -- that agreement is itself evidence. When only the anomaly model
fires with no rule support, we tag it as a lower-confidence generic
anomaly rather than guessing a specific threat class it wasn't designed to
name.
"""

from __future__ import annotations

from typing import Any

from schema.alert_schema import Alert, ThreatClass
from detect.rules import run_rules

# anomaly scores below this are not worth alerting on at all
_IF_ALERT_FLOOR = 0.55


def build_alerts(feats: dict[str, Any], anomaly_score: float, flow_src_ip: str, flow_dst_ip: str) -> list[Alert]:
    alerts: list[Alert] = []
    rule_hits = run_rules(feats)
    rule_classes = {tc for tc, _, _ in rule_hits}

    for threat_class, rule_confidence, evidence in rule_hits:
        confidence = rule_confidence
        source = "rule"
        if anomaly_score >= _IF_ALERT_FLOOR:
            # rule + model agreement is stronger evidence than either alone
            confidence = min(1.0, rule_confidence + 0.15 * anomaly_score)
            source = "rule+isolation_forest"
            evidence = {**evidence, "isolation_forest_anomaly_score": round(anomaly_score, 3)}
        alerts.append(Alert(
            flow_id=feats["flow_id"],
            threat_class=threat_class,
            confidence=confidence,
            supporting_evidence=evidence,
            src_ip=flow_src_ip,
            dst_ip=flow_dst_ip,
            detector_source=source,
        ))

    # if the anomaly model fires strongly but no rule explains why, still
    # surface it -- this is exactly the "encrypted session malware" /
    # unknown-pattern case the brief calls out, where we have no
    # deterministic signature to name it
    if anomaly_score >= _IF_ALERT_FLOOR and not rule_classes:
        alerts.append(Alert(
            flow_id=feats["flow_id"],
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
            confidence=anomaly_score * 0.8,  # discount: no rule corroboration
            supporting_evidence={
                "isolation_forest_anomaly_score": round(anomaly_score, 3),
                "tls_ja3_host_count": feats.get("tls_ja3_host_count"),
                "new_destination_for_host": feats.get("new_destination_for_host"),
                "note": "unsupervised anomaly with no deterministic rule match",
            },
            src_ip=flow_src_ip,
            dst_ip=flow_dst_ip,
            detector_source="isolation_forest",
        ))

    return alerts
