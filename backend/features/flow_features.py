"""
Flow and Volumetric Feature Extraction
Extracts rate, packet size statistics, duration, and asymmetric byte exfiltration ratios
as specified in Sentinel Feature Pipeline.
"""

import numpy as np
from typing import List, Dict, Any


def compute_flow_volume_features(
    packet_sizes: List[int],
    duration: float,
    outbound_bytes: int = 0,
    inbound_bytes: int = 0
) -> Dict[str, float]:
    """
    Computes volumetric flow statistics and exfiltration ratios.
    """
    num_packets = len(packet_sizes)
    total_bytes = sum(packet_sizes) if packet_sizes else (outbound_bytes + inbound_bytes)
    
    # Avoid zero-division on microsecond bursts
    effective_duration = max(0.001, duration)

    packet_rate = num_packets / effective_duration
    byte_rate = total_bytes / effective_duration

    if num_packets > 0:
        sizes_arr = np.array(packet_sizes, dtype=float)
        mean_size = float(np.mean(sizes_arr))
        std_size = float(np.std(sizes_arr))
        max_size = float(np.max(sizes_arr))
    else:
        mean_size = 0.0
        std_size = 0.0
        max_size = 0.0

    # Data Exfiltration Asymmetry Ratio
    # In normal web browsing, inbound bytes >> outbound bytes (ratio < 0.3)
    # In exfiltration, outbound bytes >> inbound bytes (ratio > 5.0 to 100.0)
    effective_inbound = max(1, inbound_bytes)
    exfil_byte_ratio = float(outbound_bytes) / float(effective_inbound)

    return {
        "duration": round(float(duration), 4),
        "packets": float(num_packets),
        "bytes": float(total_bytes),
        "packet_rate": round(float(packet_rate), 2),
        "byte_rate": round(float(byte_rate), 2),
        "mean_packet_size": round(mean_size, 2),
        "std_packet_size": round(std_size, 2),
        "max_packet_size": round(max_size, 2),
        "outbound_bytes": float(outbound_bytes),
        "inbound_bytes": float(inbound_bytes),
        "exfil_byte_ratio": round(exfil_byte_ratio, 3),
    }
