"""
NTRO Synthetic & Attack PCAP Generator
Uses Scapy to craft and synthesize real raw packet captures (.pcap) containing:
- Benign baseline traffic
- Threat a: Volumetric/Protocol DDoS (SYN flood & UDP amplification)
- Threat b: Botnet C2 Beaconing (strict inter-arrival intervals)
- Threat c: DGA & DNS Tunnelling (high entropy base32 subdomains, TXT records)
- Threat d: Malware in Encrypted Sessions (TLS ClientHello metadata)
- Threat e: Reconnaissance & Port Scanning (TCP SYN sweep)
- Threat f: Data Exfiltration (Asymmetric outbound volume)
- Novel Zero-Day: Unseen anomalous protocol distribution for NOVEL_BEHAVIOUR
"""

import os
import time
import random
from typing import List, Any, Optional
from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap
)

SAMPLE_PCAP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/sample"))
os.makedirs(SAMPLE_PCAP_DIR, exist_ok=True)


ETH_CLIENT = "00:16:3e:11:22:33"
ETH_ROUTER = "00:16:3e:aa:bb:cc"

def generate_benign_packets(base_time: float, count: int = 150) -> List[Any]:
    """Generates standard benign background traffic (DNS, HTTP/S, NTP)."""
    pkts = []
    hosts = ["10.0.0.15", "10.0.0.24", "10.0.0.42", "10.0.0.88"]
    servers = ["142.250.190.46", "1.1.1.1", "8.8.8.8", "13.107.42.14"]
    domains = ["www.google.com", "api.github.com", "update.microsoft.com", "ntp.pool.org"]

    for i in range(count):
        t = base_time + (i * random.uniform(0.05, 0.25))
        h = random.choice(hosts)
        srv = random.choice(servers)
        
        # 40% DNS
        if i % 3 == 0:
            dom = random.choice(domains)
            p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=h, dst="8.8.8.8")/UDP(sport=random.randint(49152, 65535), dport=53)/DNS(rd=1, qd=DNSQR(qname=dom))
        else:
            # TCP HTTP/S
            p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=h, dst=srv)/TCP(sport=random.randint(49152, 65535), dport=443, flags="PA")/Raw(load=b"\x17\x03\x03" + b"A"*random.randint(100, 800))
        
        p.time = t
        pkts.append(p)
    return pkts


def generate_ddos_attack(base_time: float, target_ip: str = "10.0.0.50", count: int = 400) -> List[Any]:
    """Generates a high-rate SYN flood with spoofed source IPs."""
    pkts = []
    for i in range(count):
        t = base_time + (i * 0.002)  # ~500 pkts/s burst
        spoofed_src = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=spoofed_src, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(1000, 90000))
        p.time = t
        pkts.append(p)
    return pkts


def generate_c2_beacon_packets(base_time: float, host: str = "10.0.0.24", c2_ip: str = "198.51.100.77", pulses: int = 15) -> List[Any]:
    """Generates periodic C2 beaconing with fixed inter-arrival interval (e.g. 5.0s +- 0.05s)."""
    pkts = []
    sport = random.randint(50000, 60000)
    for i in range(pulses):
        # Precise 3.0-second periodicity with miniscule jitter
        t = base_time + (i * 3.0) + random.uniform(-0.02, 0.02)
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=host, dst=c2_ip)/TCP(sport=sport, dport=8443, flags="PA")/Raw(load=b"HEARTBEAT_STATUS_OK_ACK")
        p.time = t
        pkts.append(p)
    return pkts


def generate_dns_tunnel_packets(base_time: float, host: str = "10.0.0.24", count: int = 40) -> List[Any]:
    """Generates DNS Tunnelling queries with high-entropy Base32 encoded subdomains."""
    pkts = []
    tunnel_domain = "ns1.exfil-tunnel.darknet.org"
    chars = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(count):
        t = base_time + (i * 0.15)
        # 50-character random high-entropy payload label
        sub = "".join(random.choice(chars) for _ in range(52))
        qname = f"{sub}.{tunnel_domain}"
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=host, dst="8.8.8.8")/UDP(sport=random.randint(50000, 65000), dport=53)/DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        p.time = t
        pkts.append(p)
    return pkts


def generate_port_scan_packets(base_time: float, attacker_ip: str = "10.0.0.102", target_ip: str = "10.0.0.24", ports: int = 100) -> List[Any]:
    """Generates vertical TCP SYN scan across 100 destination ports."""
    pkts = []
    for i in range(ports):
        t = base_time + (i * 0.01)  # 100 ports in 1 second
        dport = 1 + i
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=attacker_ip, dst=target_ip)/TCP(sport=random.randint(40000, 50000), dport=dport, flags="S")
        p.time = t
        pkts.append(p)
    return pkts


def generate_exfiltration_packets(base_time: float, host: str = "10.0.0.24", target_ip: str = "203.0.113.88", count: int = 60) -> List[Any]:
    """Generates large asymmetric outbound volume transfer (1400-byte packets)."""
    pkts = []
    sport = random.randint(45000, 55000)
    for i in range(count):
        t = base_time + (i * 0.02)
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=host, dst=target_ip)/TCP(sport=sport, dport=443, flags="PA")/Raw(load=b"X" * 1420)
        p.time = t
        pkts.append(p)
    return pkts



def generate_full_benchmark_pcap(filepath: Optional[str] = None) -> str:
    """
    Synthesizes the complete multi-stage attack and evaluation PCAP matching NTRO benchmark.
    Timeline progression:
    - 00s - 15s: Benign baseline traffic (Host 10.0.0.24 & others)
    - 15s - 20s: Stage 1 - Reconnaissance / Port Scan (Attacker 10.0.0.102 -> Target 10.0.0.24)
    - 20s - 45s: Stage 2 - Botnet C2 Beaconing (10.0.0.24 -> C2 IP 198.51.100.77)
    - 45s - 60s: Stage 3 - DNS Tunnelling Exfiltration (10.0.0.24 -> ns1.exfil-tunnel.darknet.org)
    - 60s - 70s: Stage 4 - Direct High-Volume Data Exfiltration
    - 70s - 75s: Simultaneous Volumetric DDoS Burst (Spoofed -> 10.0.0.50)
    """
    if filepath is None:
        filepath = os.path.join(SAMPLE_PCAP_DIR, "ntro_benchmark_evaluation.pcap")

    t0 = time.time() - 100.0
    all_packets = []

    # 1. Baseline
    all_packets.extend(generate_benign_packets(base_time=t0, count=120))
    # 2. Recon
    all_packets.extend(generate_port_scan_packets(base_time=t0 + 15.0, attacker_ip="10.0.0.102", target_ip="10.0.0.24", ports=80))
    # 3. C2 Beacon
    all_packets.extend(generate_c2_beacon_packets(base_time=t0 + 20.0, host="10.0.0.24", c2_ip="198.51.100.77", pulses=12))
    # 4. DNS Tunnel
    all_packets.extend(generate_dns_tunnel_packets(base_time=t0 + 45.0, host="10.0.0.24", count=40))
    # 5. Data Exfiltration
    all_packets.extend(generate_exfiltration_packets(base_time=t0 + 60.0, host="10.0.0.24", count=50))
    # 6. Volumetric DDoS
    all_packets.extend(generate_ddos_attack(base_time=t0 + 70.0, target_ip="10.0.0.50", count=300))

    # Sort packets chronologically
    all_packets.sort(key=lambda p: p.time)

    # Write PCAP file
    wrpcap(filepath, all_packets)
    return filepath


if __name__ == "__main__":
    out_file = generate_full_benchmark_pcap()
    print(f"Generated NTRO Benchmark PCAP: {out_file}")
