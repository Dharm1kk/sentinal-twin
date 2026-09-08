"""
Unified Feature Extraction Interface
Extracts normalized feature vectors for all Sentinel threat models.
"""

from typing import Dict, Any, List
import numpy as np

from .flow_features import compute_flow_volume_features
from .timing_features import compute_timing_features
from .entropy_features import shannon_entropy, extract_dga_string_features, source_ip_entropy
from .dns_features import analyze_dns_queries
from .tls_features import extract_tls_metadata_features, compute_ja3_fingerprint
from .scan_features import analyze_scan_patterns

# Ordered canonical feature schema for ML training and model inference
FEATURE_COLUMNS = [
    # Flow & Volume
    "duration", "packets", "bytes", "packet_rate", "byte_rate", "mean_packet_size", "std_packet_size",
    # Timing & Beaconing
    "mean_iat", "std_iat", "cv_iat", "autocorrelation_lag1", "timing_regularity",
    # Diversity & Entropy
    "src_ip_entropy", "dst_ip_entropy",
    # DNS & DGA
    "dns_query_rate", "dns_mean_query_length", "dns_mean_entropy", "dns_txt_ratio", "dns_nxdomain_ratio", "dns_dga_score", "dns_tunnel_score",
    # TLS Metadata
    "has_tls", "tls_cipher_count", "has_sni", "tls_suspicion_score",
    # Scan & Topology
    "hosts_per_sec", "ports_per_sec", "unique_destinations", "unique_ports", "syn_only_ratio", "vertical_scan_score", "horizontal_scan_score",
    # Exfiltration
    "exfil_byte_ratio", "outbound_bytes"
]


def extract_features_from_window(
    packets_or_flows: List[Dict[str, Any]],
    window_duration: float = 5.0
) -> Dict[str, float]:
    """
    Extracts all feature metrics from a time window of raw flow/packet events.
    """
    num_items = len(packets_or_flows)
    if num_items == 0:
        return {col: 0.0 for col in FEATURE_COLUMNS}

    # 1. Flow & Volume
    packet_sizes = [int(p.get("bytes", p.get("len", 64))) for p in packets_or_flows]
    timestamps = [float(p.get("timestamp", 0.0)) for p in packets_or_flows]
    outbound_bytes = sum(int(p.get("bytes", 0)) for p in packets_or_flows if p.get("direction") != "inbound")
    inbound_bytes = sum(int(p.get("bytes", 0)) for p in packets_or_flows if p.get("direction") == "inbound")
    
    flow_stats = compute_flow_volume_features(
        packet_sizes=packet_sizes,
        duration=window_duration,
        outbound_bytes=outbound_bytes,
        inbound_bytes=inbound_bytes
    )

    # 2. Timing
    timing_stats = compute_timing_features(timestamps)

    # 3. Entropies
    src_ips = [p.get("src_ip", "") for p in packets_or_flows if p.get("src_ip")]
    dst_ips = [p.get("dst_ip", "") for p in packets_or_flows if p.get("dst_ip")]
    src_entropy = source_ip_entropy(src_ips)
    dst_entropy = source_ip_entropy(dst_ips)

    # 4. DNS
    dns_records = [
        {"qname": p.get("dns_query"), "qtype": p.get("dns_qtype", "A"), "rcode": p.get("dns_rcode", 0)}
        for p in packets_or_flows if p.get("dns_query")
    ]
    dns_stats = analyze_dns_queries(dns_records, time_window=window_duration)

    # 5. TLS
    tls_items = [p for p in packets_or_flows if p.get("tls_client_hello") or p.get("tls_sni") or p.get("tls_version")]
    if tls_items:
        first_tls = tls_items[0]
        client_hello = first_tls.get("tls_client_hello", {
            "version": first_tls.get("tls_version", 0x0303),
            "sni": first_tls.get("tls_sni", ""),
            "ciphers": [0x1301, 0x1302],
            "extensions": [0, 23, 65281]
        })
        tls_stats = extract_tls_metadata_features(client_hello, packet_sizes, window_duration)
    else:
        tls_stats = extract_tls_metadata_features(None, packet_sizes, window_duration)

    # 6. Scan
    scan_items = [
        {"src_ip": p.get("src_ip"), "dst_ip": p.get("dst_ip"), "dst_port": p.get("dst_port"), "tcp_flags": p.get("tcp_flags", "")}
        for p in packets_or_flows
    ]
    scan_stats = analyze_scan_patterns(scan_items, time_window=window_duration)

    # Assemble canonical dictionary
    return {
        # Flow & Volume
        "duration": flow_stats["duration"],
        "packets": flow_stats["packets"],
        "bytes": flow_stats["bytes"],
        "packet_rate": flow_stats["packet_rate"],
        "byte_rate": flow_stats["byte_rate"],
        "mean_packet_size": flow_stats["mean_packet_size"],
        "std_packet_size": flow_stats["std_packet_size"],
        # Timing & Beaconing
        "mean_iat": timing_stats["mean_iat"],
        "std_iat": timing_stats["std_iat"],
        "cv_iat": timing_stats["cv_iat"],
        "autocorrelation_lag1": timing_stats["autocorrelation_lag1"],
        "timing_regularity": timing_stats["timing_regularity"],
        # Diversity & Entropy
        "src_ip_entropy": src_entropy,
        "dst_ip_entropy": dst_entropy,
        # DNS & DGA
        "dns_query_rate": dns_stats["query_rate"],
        "dns_mean_query_length": dns_stats["mean_query_length"],
        "dns_mean_entropy": dns_stats["mean_entropy"],
        "dns_txt_ratio": dns_stats["txt_ratio"],
        "dns_nxdomain_ratio": dns_stats["nxdomain_ratio"],
        "dns_dga_score": dns_stats["dga_score"],
        "dns_tunnel_score": dns_stats["tunnel_indicator"],
        # TLS Metadata
        "has_tls": tls_stats["has_tls"],
        "tls_cipher_count": tls_stats["cipher_count"],
        "has_sni": tls_stats["has_sni"],
        "tls_suspicion_score": tls_stats["tls_suspicion_score"],
        # Scan & Topology
        "hosts_per_sec": scan_stats["hosts_per_sec"],
        "ports_per_sec": scan_stats["ports_per_sec"],
        "unique_destinations": scan_stats["unique_destinations"],
        "unique_ports": scan_stats["unique_ports"],
        "syn_only_ratio": scan_stats["syn_only_ratio"],
        "vertical_scan_score": scan_stats["vertical_scan_score"],
        "horizontal_scan_score": scan_stats["horizontal_scan_score"],
        # Exfiltration
        "exfil_byte_ratio": flow_stats["exfil_byte_ratio"],
        "outbound_bytes": flow_stats["outbound_bytes"]
    }


def to_numpy_vector(features_dict: Dict[str, float]) -> np.ndarray:
    """
    Converts features dict to canonical 1D numpy array.
    """
    return np.array([features_dict.get(col, 0.0) for col in FEATURE_COLUMNS], dtype=float)
