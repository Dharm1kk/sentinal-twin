"""
Streaming feature engine (Stage 3 of the architecture).

Maintains bounded sliding-window state per host and per destination so that
each incoming flow can be scored using only recent context -- no full
history is kept, which is what keeps this usable at streaming rates.

All windows are time-bounded (seconds) and use deques so old entries are
evicted cheaply as new flows arrive.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from typing import Any

from simulate.flow_generator import FlowRecord

# window sizes, tuned for the demo's traffic rates -- would be re-tuned
# against real link rates before production use
_DDOS_WINDOW_S = 2.0
_SCAN_WINDOW_S = 5.0
_DNS_WINDOW_S = 60.0
_BEACON_WINDOW_S = 900.0  # 15 min, long enough to see several beacon periods
_EXFIL_BASELINE_WINDOW_S = 3600.0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class FeatureEngine:
    def __init__(self) -> None:
        # dst_ip -> deque[(ts, src_ip, syn, synack)]  -- for DDoS / victim concentration
        self._dst_window: dict[str, deque] = defaultdict(deque)
        # src_ip -> deque[(ts, dst_port, synack)] -- for port-scan fan-out
        self._scan_window: dict[str, deque] = defaultdict(deque)
        # src_ip -> deque[(ts, qname)] -- for DNS tunneling
        self._dns_window: dict[str, deque] = defaultdict(deque)
        # (src_ip, dst_ip) -> deque[ts] -- for beaconing periodicity
        self._beacon_window: dict[tuple[str, str], deque] = defaultdict(deque)
        # src_ip -> deque[(ts, outbound_bytes)] -- rolling baseline for exfil deviation
        self._outbound_baseline: dict[str, deque] = defaultdict(deque)
        # src_ip -> set of destinations previously observed for that host
        self._known_destinations: dict[str, set] = defaultdict(set)
        # ja3 fingerprint -> count of distinct hosts ever seen using it (rarity)
        self._ja3_host_sets: dict[str, set] = defaultdict(set)

    @staticmethod
    def _evict(dq: deque, now: float, window_s: float, ts_index: int = 0) -> None:
        while dq and (now - dq[0][ts_index] if isinstance(dq[0], tuple) else now - dq[0]) > window_s:
            dq.popleft()

    def compute(self, flow: FlowRecord) -> dict[str, Any]:
        now = flow.ts
        feats: dict[str, Any] = {
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "duration": flow.duration,
            "packets": flow.packets,
            "bytes": flow.bytes,
            "outbound_bytes": flow.outbound_bytes,
            "inbound_bytes": flow.inbound_bytes,
            "outbound_inbound_ratio": flow.outbound_bytes / max(1, flow.inbound_bytes),
            "half_open": int(flow.tcp_syn == 1 and flow.tcp_synack == 0),
        }

        # --- DDoS / victim-concentration window (keyed by destination) ---
        dq = self._dst_window[flow.dst_ip]
        dq.append((now, flow.src_ip, flow.tcp_syn, flow.tcp_synack))
        self._evict(dq, now, _DDOS_WINDOW_S)
        src_ips_in_window = [e[1] for e in dq]
        half_open_count = sum(1 for e in dq if e[2] == 1 and e[3] == 0)
        feats["dst_syn_rate"] = len(dq) / _DDOS_WINDOW_S
        feats["dst_half_open_rate"] = half_open_count / _DDOS_WINDOW_S
        feats["dst_source_entropy"] = shannon_entropy("".join(src_ips_in_window)) if src_ips_in_window else 0.0
        feats["dst_unique_sources"] = len(set(src_ips_in_window))

        # --- port-scan fan-out window (keyed by source) ---
        sq = self._scan_window[flow.src_ip]
        sq.append((now, flow.dst_port, flow.tcp_synack))
        self._evict(sq, now, _SCAN_WINDOW_S)
        feats["src_unique_ports"] = len({e[1] for e in sq})
        feats["src_fanout_rate"] = len(sq) / _SCAN_WINDOW_S
        failed = sum(1 for e in sq if e[2] == 0)
        feats["src_failed_ratio"] = failed / len(sq) if sq else 0.0

        # --- DNS tunneling window (keyed by source) ---
        feats["dns_label_entropy"] = 0.0
        feats["dns_query_rate"] = 0.0
        feats["dns_query_len"] = 0
        if flow.dns_qname:
            label = flow.dns_qname.split(".")[0]
            dnq = self._dns_window[flow.src_ip]
            dnq.append((now, flow.dns_qname))
            self._evict(dnq, now, _DNS_WINDOW_S)
            feats["dns_label_entropy"] = shannon_entropy(label)
            feats["dns_query_rate"] = len(dnq) / _DNS_WINDOW_S
            feats["dns_query_len"] = len(flow.dns_qname)

        # --- beaconing periodicity window (keyed by src->dst pair) ---
        feats["periodicity_score"] = 0.0
        feats["beacon_count"] = 0
        if flow.protocol == "TCP" and flow.dst_port in (443, 8443):
            bq = self._beacon_window[(flow.src_ip, flow.dst_ip)]
            bq.append(now)
            self._evict(bq, now, _BEACON_WINDOW_S)
            feats["beacon_count"] = len(bq)
            if len(bq) >= 3:
                inter_arrivals = [bq[i + 1] - bq[i] for i in range(len(bq) - 1)]
                mean_ia = sum(inter_arrivals) / len(inter_arrivals)
                if mean_ia > 0:
                    var = sum((x - mean_ia) ** 2 for x in inter_arrivals) / len(inter_arrivals)
                    cov = math.sqrt(var) / mean_ia  # coefficient of variation
                    # low CoV (regular spacing) -> high periodicity score
                    feats["periodicity_score"] = max(0.0, 1.0 - min(cov, 1.0))
                    feats["median_inter_arrival_seconds"] = sorted(inter_arrivals)[len(inter_arrivals) // 2]

        # --- outbound byte baseline deviation (exfil) ---
        obq = self._outbound_baseline[flow.src_ip]
        prior = list(obq)
        obq.append((now, flow.outbound_bytes))
        self._evict(obq, now, _EXFIL_BASELINE_WINDOW_S)
        if prior:
            baseline_mean = sum(v for _, v in prior) / len(prior)
            feats["outbound_baseline_ratio"] = flow.outbound_bytes / max(1.0, baseline_mean)
        else:
            feats["outbound_baseline_ratio"] = 1.0
        known = self._known_destinations[flow.src_ip]
        feats["new_destination_for_host"] = flow.dst_ip not in known
        known.add(flow.dst_ip)

        # --- TLS/QUIC fingerprint rarity (proxy for encrypted-session malware) ---
        feats["tls_ja3_host_count"] = 0
        feats["tls_ja3"] = flow.tls_ja3
        if flow.tls_ja3:
            hosts = self._ja3_host_sets[flow.tls_ja3]
            hosts.add(flow.src_ip)
            feats["tls_ja3_host_count"] = len(hosts)

        return feats
