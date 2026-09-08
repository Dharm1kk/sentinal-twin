"""
Reconnaissance and Port Scanning Feature Extraction
Calculates horizontal and vertical fan-out metrics, unique destination ports/hosts per second,
and TCP SYN-only connection failure ratios (Sentinel Feature Pipeline).
"""

from typing import List, Dict, Any, Set


def analyze_scan_patterns(
    flows_or_packets: List[Dict[str, Any]],
    time_window: float = 1.0
) -> Dict[str, float]:
    """
    Computes fan-out and scan indicators from a window of network attempts.
    Each item contains: {'src_ip', 'dst_ip', 'dst_port', 'tcp_flags', 'timestamp'}
    """
    total_events = len(flows_or_packets)
    if total_events == 0:
        return {
            "hosts_per_sec": 0.0,
            "ports_per_sec": 0.0,
            "unique_destinations": 0.0,
            "unique_ports": 0.0,
            "syn_only_ratio": 0.0,
            "fan_out": 0.0,
            "vertical_scan_score": 0.0,
            "horizontal_scan_score": 0.0,
        }

    effective_window = max(0.1, time_window)

    unique_hosts: Set[str] = set()
    unique_ports: Set[int] = set()
    syn_count = 0
    ack_count = 0

    for item in flows_or_packets:
        unique_hosts.add(item.get("dst_ip", ""))
        unique_ports.add(int(item.get("dst_port", 0)))
        flags = str(item.get("tcp_flags", "")).upper()
        if "S" in flags and "A" not in flags:
            syn_count += 1
        elif "A" in flags:
            ack_count += 1

    hosts_per_sec = len(unique_hosts) / effective_window
    ports_per_sec = len(unique_ports) / effective_window
    syn_only_ratio = syn_count / total_events if total_events > 0 else 0.0
    fan_out = float(len(unique_hosts) * len(unique_ports))

    # Vertical scan: single destination host, many destination ports (e.g. nmap -p 1-1000)
    # Horizontal scan: many destination hosts, single or few destination ports (e.g. masscan port 22/445)
    vertical_score = 0.0
    if len(unique_hosts) == 1 and len(unique_ports) >= 10:
        vertical_score = min(1.0, len(unique_ports) / 50.0)

    horizontal_score = 0.0
    if len(unique_hosts) >= 10 and len(unique_ports) <= 3:
        horizontal_score = min(1.0, len(unique_hosts) / 50.0)

    return {
        "hosts_per_sec": round(float(hosts_per_sec), 2),
        "ports_per_sec": round(float(ports_per_sec), 2),
        "unique_destinations": float(len(unique_hosts)),
        "unique_ports": float(len(unique_ports)),
        "syn_only_ratio": round(float(syn_only_ratio), 3),
        "fan_out": round(float(fan_out), 2),
        "vertical_scan_score": round(float(vertical_score), 3),
        "horizontal_scan_score": round(float(horizontal_score), 3),
    }
