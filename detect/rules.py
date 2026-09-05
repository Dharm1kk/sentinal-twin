"""
Deterministic streaming detectors (Stage 4, rule half of the hybrid).

Each function takes the feature dict produced by FeatureEngine.compute()
for a single flow and returns (threat_class, confidence, evidence) or None
if the rule doesn't fire. Confidence here is a hand-tuned evidence-strength
score based on how far past threshold the signal is -- not a calibrated
probability. These thresholds are demo defaults; the brief is explicit
that they must be measured/re-tuned against a labeled dataset, not assumed.
"""

from __future__ import annotations

from typing import Any

from schema.alert_schema import ThreatClass

Evidence = dict[str, Any]
RuleResult = tuple[ThreatClass, float, Evidence] | None


def _scale(value: float, low: float, high: float) -> float:
    """Linearly map value in [low, high] to confidence in [0, 1], clamped."""
    if high == low:
        return 1.0 if value >= high else 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def detect_ddos(feats: dict) -> RuleResult:
    syn_rate = feats["dst_syn_rate"]
    half_open_rate = feats["dst_half_open_rate"]
    source_entropy = feats["dst_source_entropy"]
    unique_sources = feats["dst_unique_sources"]

    # fires when a destination is seeing a burst of half-open connections
    # from many distinct sources -- the signature of a SYN flood, not a
    # legitimate flash crowd (which would complete handshakes)
    if half_open_rate > 200 and unique_sources > 20:
        confidence = 0.5 * _scale(half_open_rate, 200, 2000) + 0.5 * _scale(source_entropy, 2.0, 5.0)
        return ThreatClass.VOLUMETRIC_DDOS, confidence, {
            "dst_syn_rate": round(syn_rate, 1),
            "dst_half_open_rate": round(half_open_rate, 1),
            "dst_source_entropy": round(source_entropy, 2),
            "dst_unique_sources": unique_sources,
        }
    return None


def detect_port_scan(feats: dict) -> RuleResult:
    unique_ports = feats["src_unique_ports"]
    fanout_rate = feats["src_fanout_rate"]
    failed_ratio = feats["src_failed_ratio"]

    if unique_ports > 30 and failed_ratio > 0.8:
        confidence = 0.6 * _scale(unique_ports, 30, 300) + 0.4 * _scale(failed_ratio, 0.8, 1.0)
        return ThreatClass.PORT_SCAN, confidence, {
            "src_unique_ports": unique_ports,
            "src_fanout_rate": round(fanout_rate, 1),
            "src_failed_ratio": round(failed_ratio, 2),
        }
    return None


def detect_dns_tunneling(feats: dict) -> RuleResult:
    entropy = feats["dns_label_entropy"]
    query_rate = feats["dns_query_rate"]
    qlen = feats["dns_query_len"]

    if entropy == 0.0:
        return None
    if entropy > 3.3 and qlen > 25:
        confidence = 0.6 * _scale(entropy, 3.3, 4.5) + 0.4 * _scale(query_rate, 0.05, 0.5)
        return ThreatClass.DNS_TUNNELING, confidence, {
            "dns_label_entropy": round(entropy, 2),
            "dns_query_rate": round(query_rate, 3),
            "dns_query_length": qlen,
        }
    return None


def detect_c2_beaconing(feats: dict) -> RuleResult:
    periodicity = feats["periodicity_score"]
    beacon_count = feats["beacon_count"]

    if beacon_count >= 4 and periodicity > 0.7:
        confidence = 0.7 * _scale(periodicity, 0.7, 0.98) + 0.3 * _scale(beacon_count, 4, 20)
        evidence = {
            "periodicity_score": round(periodicity, 2),
            "beacon_count": beacon_count,
            "new_destination_for_host": feats["new_destination_for_host"],
        }
        if "median_inter_arrival_seconds" in feats:
            evidence["median_inter_arrival_seconds"] = round(feats["median_inter_arrival_seconds"], 1)
        return ThreatClass.C2_BEACONING, confidence, evidence
    return None


def detect_data_exfiltration(feats: dict) -> RuleResult:
    ratio = feats["outbound_baseline_ratio"]
    outbound_bytes = feats["outbound_bytes"]

    if outbound_bytes > 5_000_000 and ratio > 10:
        confidence = 0.6 * _scale(ratio, 10, 100) + 0.4 * _scale(outbound_bytes, 5_000_000, 100_000_000)
        return ThreatClass.DATA_EXFILTRATION, confidence, {
            "outbound_bytes": outbound_bytes,
            "outbound_baseline_ratio": round(ratio, 1),
            "new_destination_for_host": feats["new_destination_for_host"],
        }
    return None


ALL_RULES = [
    detect_ddos,
    detect_port_scan,
    detect_dns_tunneling,
    detect_c2_beaconing,
    detect_data_exfiltration,
]


def run_rules(feats: dict) -> list[tuple[ThreatClass, float, Evidence]]:
    hits = []
    for rule in ALL_RULES:
        result = rule(feats)
        if result is not None:
            hits.append(result)
    return hits
