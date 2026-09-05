"""
Passive replay simulator (Stage 1 of the architecture).

Generates synthetic flow records that mimic what a read-only NetFlow/IPFIX
collector would see off a mirror port. No packets are ever sent anywhere;
this only produces flow *records* (dicts / rows) with timestamps, so the
downstream pipeline can be replayed deterministically and benchmarked.

Ground-truth `label` is attached for evaluation only -- the detection
pipeline never reads it.
"""

from __future__ import annotations

import itertools
import random
import string
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Iterator

_flow_counter = itertools.count(1)


def _new_flow_id() -> str:
    return f"flow-{next(_flow_counter):06x}-{uuid.uuid4().hex[:4]}"


def _random_ip(prefix: str = "10.0") -> str:
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_external_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _random_high_entropy_label(length: int = 22) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


@dataclass
class FlowRecord:
    flow_id: str
    ts: float  # unix epoch seconds, simulated
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    packets: int
    bytes: int
    outbound_bytes: int
    inbound_bytes: int
    tcp_syn: int
    tcp_synack: int
    dns_qname: str | None
    tls_ja3: str | None
    label: str  # ground truth, NOT visible to detectors

    def to_dict(self) -> dict:
        return asdict(self)


# --- benign background traffic -------------------------------------------------

_KNOWN_CLOUD_IPS = [_random_external_ip() for _ in range(12)]
_KNOWN_JA3 = ["a0e9f5d64349fb13191bc781f81f42e1", "51c64c77e60f3980eea90869b68c58a8", "e7d705a3286e19ea42f587b344ee6865"]


def benign_flow(t: float, host_pool: list[str]) -> FlowRecord:
    src = random.choice(host_pool)
    dst = random.choice(_KNOWN_CLOUD_IPS)
    packets = random.randint(4, 60)
    total_bytes = packets * random.randint(200, 1400)
    return FlowRecord(
        flow_id=_new_flow_id(),
        ts=t,
        src_ip=src,
        dst_ip=dst,
        src_port=random.randint(1024, 65535),
        dst_port=random.choice([443, 443, 443, 80, 53]),
        protocol="TCP",
        duration=round(random.uniform(0.05, 8.0), 3),
        packets=packets,
        bytes=total_bytes,
        outbound_bytes=int(total_bytes * random.uniform(0.2, 0.5)),
        inbound_bytes=int(total_bytes * random.uniform(0.5, 0.8)),
        tcp_syn=1,
        tcp_synack=1,
        dns_qname=None,
        tls_ja3=random.choice(_KNOWN_JA3),
        label="benign",
    )


# --- attack scenario generators -------------------------------------------------

def ddos_burst(t: float, victim_ip: str, n_flows: int) -> list[FlowRecord]:
    """Volumetric SYN flood: many src IPs, one victim, tiny flows, no completion."""
    out = []
    for _ in range(n_flows):
        out.append(FlowRecord(
            flow_id=_new_flow_id(),
            ts=t + random.uniform(0, 0.05),
            src_ip=_random_external_ip(),
            dst_ip=victim_ip,
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol="TCP",
            duration=0.0,
            packets=1,
            bytes=random.randint(40, 60),
            outbound_bytes=0,
            inbound_bytes=random.randint(40, 60),
            tcp_syn=1,
            tcp_synack=0,  # never completes -- half-open
            dns_qname=None,
            tls_ja3=None,
            label="volumetric_ddos",
        ))
    return out


def port_scan_burst(t: float, scanner_ip: str, target_ip: str, n_ports: int) -> list[FlowRecord]:
    ports = random.sample(range(1, 65535), min(n_ports, 65534))
    out = []
    for i, p in enumerate(ports):
        out.append(FlowRecord(
            flow_id=_new_flow_id(),
            ts=t + i * 0.01,
            src_ip=scanner_ip,
            dst_ip=target_ip,
            src_port=random.randint(1024, 65535),
            dst_port=p,
            protocol="TCP",
            duration=0.0,
            packets=1,
            bytes=44,
            outbound_bytes=44,
            inbound_bytes=0,
            tcp_syn=1,
            tcp_synack=0,
            dns_qname=None,
            tls_ja3=None,
            label="port_scan",
        ))
    return out


def dns_tunnel_burst(t: float, host_ip: str, n_queries: int) -> list[FlowRecord]:
    domain_suffix = "exfil.example-c2.net"
    out = []
    for i in range(n_queries):
        qname = f"{_random_high_entropy_label()}.{domain_suffix}"
        out.append(FlowRecord(
            flow_id=_new_flow_id(),
            ts=t + i * random.uniform(0.5, 2.0),
            src_ip=host_ip,
            dst_ip=_random_external_ip(),
            src_port=random.randint(1024, 65535),
            dst_port=53,
            protocol="UDP",
            duration=round(random.uniform(0.01, 0.05), 3),
            packets=2,
            bytes=len(qname) + random.randint(60, 90),
            outbound_bytes=len(qname) + 40,
            inbound_bytes=50,
            tcp_syn=0,
            tcp_synack=0,
            dns_qname=qname,
            tls_ja3=None,
            label="dns_tunneling",
        ))
    return out


def c2_beacon_series(t0: float, host_ip: str, c2_ip: str, n_beacons: int, period_s: float = 60.0) -> list[FlowRecord]:
    rare_ja3 = "6734f37431670b3ab4292b8f60f29984"
    out = []
    for i in range(n_beacons):
        jitter = random.uniform(-1.5, 1.5)
        out.append(FlowRecord(
            flow_id=_new_flow_id(),
            ts=t0 + i * period_s + jitter,
            src_ip=host_ip,
            dst_ip=c2_ip,
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol="TCP",
            duration=round(random.uniform(0.2, 0.6), 3),
            packets=random.randint(3, 6),
            bytes=random.randint(300, 700),
            outbound_bytes=random.randint(150, 300),
            inbound_bytes=random.randint(150, 400),
            tcp_syn=1,
            tcp_synack=1,
            dns_qname=None,
            tls_ja3=rare_ja3,
            label="c2_beaconing",
        ))
    return out


def exfil_flow(t: float, host_ip: str, dst_ip: str) -> FlowRecord:
    out_bytes = random.randint(20_000_000, 80_000_000)
    return FlowRecord(
        flow_id=_new_flow_id(),
        ts=t,
        src_ip=host_ip,
        dst_ip=dst_ip,
        src_port=random.randint(1024, 65535),
        dst_port=443,
        protocol="TCP",
        duration=round(random.uniform(20, 90), 2),
        packets=random.randint(20_000, 60_000),
        bytes=out_bytes,
        outbound_bytes=out_bytes,
        inbound_bytes=int(out_bytes * 0.02),
        tcp_syn=1,
        tcp_synack=1,
        dns_qname=None,
        tls_ja3=random.choice(_KNOWN_JA3),
        label="data_exfiltration",
    )


def generate_session(
    duration_s: float = 300.0,
    benign_rate_per_s: float = 15.0,
    seed: int | None = None,
    include_attacks: bool = True,
) -> list[FlowRecord]:
    """Build one full replayable session: benign background + injected attack scenarios.

    Returns records sorted by timestamp, ready to be fed to the streaming
    pipeline in order.
    """
    if seed is not None:
        random.seed(seed)

    t_start = time.time()
    host_pool = [_random_ip() for _ in range(25)]
    records: list[FlowRecord] = []

    # benign background across the whole window
    n_benign = int(duration_s * benign_rate_per_s)
    for _ in range(n_benign):
        t = t_start + random.uniform(0, duration_s)
        records.append(benign_flow(t, host_pool))

    if include_attacks:
        # DDoS burst around 1/4 into the session
        records += ddos_burst(t_start + duration_s * 0.25, victim_ip=_random_ip("10.0"), n_flows=4000)

        # Port scan around 1/2
        records += port_scan_burst(
            t_start + duration_s * 0.5, scanner_ip=_random_external_ip(),
            target_ip=random.choice(host_pool), n_ports=800,
        )

        # DNS tunneling drips throughout the last third
        records += dns_tunnel_burst(t_start + duration_s * 0.65, host_ip=random.choice(host_pool), n_queries=40)

        # C2 beaconing spread across the session (periodic). Ensure enough
        # beacons land inside the session regardless of session length --
        # detection needs >=4 samples to compute a periodicity score.
        beacon_host = random.choice(host_pool)
        n_beacons = max(6, int(duration_s // 45))
        period_s = max(15.0, (duration_s * 0.8) / n_beacons)
        records += c2_beacon_series(t_start + 5, host_ip=beacon_host, c2_ip=_random_external_ip(), n_beacons=n_beacons, period_s=period_s)

        # Data exfiltration near the end
        records.append(exfil_flow(t_start + duration_s * 0.9, host_ip=random.choice(host_pool), dst_ip=_random_external_ip()))

    records.sort(key=lambda r: r.ts)
    return records


def stream_session(records: list[FlowRecord], speed_factor: float = 1.0) -> Iterator[FlowRecord]:
    """Yield records paced by their timestamps, compressed/expanded by speed_factor.

    speed_factor=1.0 replays at real recorded pacing; higher values replay
    faster (useful for throughput benchmarking).
    """
    if not records:
        return
    t0_sim = records[0].ts
    t0_wall = time.time()
    for rec in records:
        target_wall = t0_wall + (rec.ts - t0_sim) / speed_factor
        sleep_for = target_wall - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)
        yield rec
