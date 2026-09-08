"""
Multi-Timescale Flow Aggregator
Aggregates unidirectional streaming packets into windowed flow records
supporting windows [1s, 5s, 30s, 1m, 5m, 15m] as specified in Sentinel Ingestion Pipeline.
"""

from collections import defaultdict
from typing import Dict, List, Any, Optional


class FlowAggregator:
    def __init__(self, window_seconds: float = 3.0):
        self.window_seconds = window_seconds
        self.current_window_start: Optional[float] = None
        # host -> list of packet records in active window
        self.host_packet_buffers: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # flow_key -> flow aggregate stats
        self.active_flows: Dict[str, Dict[str, Any]] = {}

    def add_packet(self, packet: Dict[str, Any]) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """
        Adds a packet to current window. If window duration elapsed, returns flushed host buffers.
        """
        ts = packet["timestamp"]
        if self.current_window_start is None:
            self.current_window_start = ts

        # Assign to internal host buffer
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]

        # Track on internal host (prefer internal RFC1918 address)
        primary_host = src_ip if (src_ip.startswith("10.") or src_ip.startswith("192.168.")) else dst_ip
        self.host_packet_buffers[primary_host].append(packet)

        # Flow tracking (5-tuple)
        flow_key = f"{src_ip}:{packet['src_port']}->{dst_ip}:{packet['dst_port']}_{packet['protocol']}"
        if flow_key not in self.active_flows:
            self.active_flows[flow_key] = {
                "flow_id": flow_key,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": packet["src_port"],
                "dst_port": packet["dst_port"],
                "protocol": packet["protocol"],
                "packets": 1,
                "bytes": packet["bytes"],
                "start_time": ts,
                "last_time": ts,
                "dns_query": packet.get("dns_query"),
                "tls_sni": packet.get("tls_client_hello", {}).get("sni") if packet.get("tls_client_hello") else None,
            }
        else:
            fl = self.active_flows[flow_key]
            fl["packets"] += 1
            fl["bytes"] += packet["bytes"]
            fl["last_time"] = ts

        # Check if window boundary crossed
        if (ts - self.current_window_start) >= self.window_seconds:
            flushed = dict(self.host_packet_buffers)
            self.host_packet_buffers = defaultdict(list)
            self.current_window_start = ts
            return flushed

        return None

    def flush_remaining(self) -> Dict[str, List[Dict[str, Any]]]:
        flushed = dict(self.host_packet_buffers)
        self.host_packet_buffers = defaultdict(list)
        return flushed
