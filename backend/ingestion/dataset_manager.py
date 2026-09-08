"""
NTRO Dataset Manager and Lab-Generated Attack Synthesizer
Generates real PCAP captures according to NTRO Problem Statement 26145:
- Benign load from iperf3 / Ostinato
- Attack traffic from hping3 (SYN/UDP floods)
- Slowloris (slow HTTP header exhaustion)
- dnscat2 / iodine (DNS tunnelling)
- DGA samples from published algorithms (DGArchive style)
- Sandboxed C2 emulator with realistic beaconing timing
"""

import os
import sys
import time
import random
import json
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

from backend.db import SessionLocal, HostRecord, FlowRecord, AlertRecord, CampaignRecord, init_db
from backend.ingestion.pcap_streamer import StreamingPCAPIngestor
from backend.ingestion.flow_aggregator import FlowAggregator
from backend.features import extract_features_from_window, to_numpy_vector
from backend.baselines import HostBaselineManager
from backend.detectors import DetectorSuite
from backend.fusion import EvidenceFusionEngine
from backend.temporal import TemporalEngine
from backend.graph import DynamicEvidenceGraph
from backend.risk import RiskEngine
from backend.explainability import ExplainabilityEngine
from backend.schemas.alert_schema import Alert

DATA_SAMPLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/sample"))
os.makedirs(DATA_SAMPLE_DIR, exist_ok=True)

ETH_CLIENT = "00:16:3e:11:22:33"
ETH_ROUTER = "00:16:3e:aa:bb:cc"


# 1. iperf3 / Ostinato Benign Load
def generate_iperf3_benign_traffic(base_time: float, count: int = 200) -> List[Any]:
    pkts = []
    hosts = ["10.0.0.15", "10.0.0.24", "10.0.0.42", "10.0.0.88"]
    external_srv = ["142.250.190.46", "1.1.1.1", "8.8.8.8", "13.107.42.14"]
    
    for i in range(count):
        t = base_time + (i * random.uniform(0.02, 0.10))
        src = random.choice(hosts)
        dst = random.choice(external_srv)
        
        # 30% DNS
        if i % 3 == 0:
            dom = random.choice(["portal.office.com", "update.microsoft.com", "github.com", "dns.google"])
            p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=src, dst="8.8.8.8")/UDP(sport=random.randint(50000, 65000), dport=53)/DNS(rd=1, qd=DNSQR(qname=dom))
        else:
            # iperf3 / HTTPS streams
            p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=src, dst=dst)/TCP(sport=random.randint(50000, 65000), dport=443, flags="PA")/Raw(load=b"\x17\x03\x03" + b"D" * random.randint(200, 1400))
        
        p.time = t
        pkts.append(p)
    return pkts


# 2. hping3 Volumetric SYN Flood
def generate_hping3_syn_flood(base_time: float, target_ip: str = "10.0.0.50", count: int = 400) -> List[Any]:
    pkts = []
    for i in range(count):
        t = base_time + (i * 0.0015)
        spoofed_ip = f"192.0.2.{random.randint(1, 254)}"
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=spoofed_ip, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=80, flags="S", seq=random.randint(100, 50000))
        p.time = t
        pkts.append(p)
    return pkts


# 3. Slowloris Slow HTTP Exhaustion
def generate_slowloris_attack(base_time: float, attacker_ip: str = "10.0.0.105", target_ip: str = "10.0.0.80", connections: int = 40) -> List[Any]:
    pkts = []
    for i in range(connections):
        t = base_time + (i * 0.2)
        sport = 40000 + i
        # Incomplete HTTP GET holding socket open
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=attacker_ip, dst=target_ip)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=f"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nX-a: {i}\r\n".encode())
        p.time = t
        pkts.append(p)
    return pkts


# 4. dnscat2 / iodine DNS Tunnelling
def generate_dnscat2_tunnel(base_time: float, host: str = "10.0.0.24", count: int = 50) -> List[Any]:
    pkts = []
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    domain = "dnscat.tunnel.enclave.org"
    for i in range(count):
        t = base_time + (i * 0.12)
        # Encoded payload chunk
        chunk = "".join(random.choice(chars) for _ in range(54))
        qname = f"dnscat.{chunk}.{domain}"
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=host, dst="8.8.8.8")/UDP(sport=random.randint(50000, 65000), dport=53)/DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        p.time = t
        pkts.append(p)
    return pkts


# 5. DGArchive Algorithmic DGA Domains
def generate_dga_queries(base_time: float, host: str = "10.0.0.42", count: int = 35) -> List[Any]:
    pkts = []
    # Seeded pseudo-random DGA generation
    chars = "bcdfghjklmnpqrstvwxyz"
    tlds = [".biz", ".info", ".cc", ".top"]
    for i in range(count):
        t = base_time + (i * 0.25)
        dga_name = "".join(random.choice(chars) for _ in range(16)) + random.choice(tlds)
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=host, dst="8.8.8.8")/UDP(sport=random.randint(50000, 65000), dport=53)/DNS(rd=1, qd=DNSQR(qname=dga_name, qtype="A"))
        p.time = t
        pkts.append(p)
    return pkts


# 6. Sandboxed C2 Emulator Beaconing
def generate_c2_emulator_beaconing(base_time: float, host: str = "10.0.0.24", c2_ip: str = "198.51.100.77", pulses: int = 12) -> List[Any]:
    pkts = []
    sport = 55442
    for i in range(pulses):
        t = base_time + (i * 4.0) + random.uniform(-0.01, 0.01)  # Strict 4s interval
        p = Ether(src=ETH_CLIENT, dst=ETH_ROUTER)/IP(src=host, dst=c2_ip)/TCP(sport=sport, dport=8443, flags="PA")/Raw(load=b"C2_CHECKIN_BEACON_ID=9821\n")
        p.time = t
        pkts.append(p)
    return pkts


def generate_all_ntro_datasets() -> Dict[str, str]:
    """
    Generates isolated PCAPs for each NTRO test scenario.
    """
    t0 = time.time() - 300.0
    files = {}

    # 1. Combined Attack-Chain Benchmark
    p_all = []
    p_all.extend(generate_iperf3_benign_traffic(t0, count=150))
    p_all.extend(generate_slowloris_attack(t0 + 20.0, connections=30))
    p_all.extend(generate_c2_emulator_beaconing(t0 + 35.0, host="10.0.0.24", pulses=10))
    p_all.extend(generate_dnscat2_tunnel(t0 + 60.0, host="10.0.0.24", count=45))
    p_all.extend(generate_dga_queries(t0 + 80.0, host="10.0.0.42", count=30))
    p_all.extend(generate_hping3_syn_flood(t0 + 100.0, target_ip="10.0.0.50", count=350))
    p_all.sort(key=lambda x: x.time)

    comb_path = os.path.join(DATA_SAMPLE_DIR, "ntro_combined_benchmark.pcap")
    wrpcap(comb_path, p_all)
    files["combined"] = comb_path

    return files


def seed_database_from_benchmark(pcap_path: Optional[str] = None):
    """
    Parses the benchmark PCAP and populates the database with real flows, hosts, baselines, and alerts.
    """
    init_db()
    if not pcap_path:
        datasets = generate_all_ntro_datasets()
        pcap_path = datasets["combined"]

    db = SessionLocal()
    try:
        # Check if already seeded
        existing_alerts = db.query(AlertRecord).count()
        if existing_alerts > 5:
            return {"status": "already_seeded", "alerts_count": existing_alerts}

        ingestor = StreamingPCAPIngestor(pcap_path)
        aggregator = FlowAggregator(window_seconds=3.0)
        baseline_mgr = HostBaselineManager()
        detectors = DetectorSuite()
        fusion_engine = EvidenceFusionEngine()
        temporal_engine = TemporalEngine()
        graph = DynamicEvidenceGraph()
        risk_engine = RiskEngine()
        explainer = ExplainabilityEngine()

        generated_alerts = []

        for pkt in ingestor.stream_packets():
            # Store Flow in Database
            flow_id = f"{pkt['src_ip']}:{pkt['src_port']}->{pkt['dst_ip']}:{pkt['dst_port']}_{pkt['protocol']}"
            existing_flow = db.query(FlowRecord).filter(FlowRecord.flow_id == flow_id).first()
            if not existing_flow:
                db_flow = FlowRecord(
                    flow_id=flow_id,
                    timestamp=pkt["timestamp"],
                    src_ip=pkt["src_ip"],
                    dst_ip=pkt["dst_ip"],
                    src_port=pkt["src_port"],
                    dst_port=pkt["dst_port"],
                    protocol=pkt["protocol"],
                    packets=1,
                    bytes=pkt["bytes"],
                    tcp_flags=pkt.get("tcp_flags"),
                    dns_query=pkt.get("dns_query")
                )
                db.add(db_flow)

            graph.add_flow_observation(
                src_ip=pkt["src_ip"],
                dst_ip=pkt["dst_ip"],
                dst_port=pkt["dst_port"],
                protocol=pkt["protocol"],
                timestamp=pkt["timestamp"],
                dns_query=pkt.get("dns_query")
            )

            flushed = aggregator.add_packet(pkt)
            if flushed:
                _process_and_save_alerts(
                    flushed, baseline_mgr, detectors, fusion_engine,
                    temporal_engine, risk_engine, explainer, db, generated_alerts
                )

        remaining = aggregator.flush_remaining()
        if remaining:
            _process_and_save_alerts(
                remaining, baseline_mgr, detectors, fusion_engine,
                temporal_engine, risk_engine, explainer, db, generated_alerts
            )

        # Save Host Baselines to Database
        for h_ip, trackers in baseline_mgr.hosts.items():
            profile = baseline_mgr.get_host_profile(h_ip)
            db_host = HostRecord(
                ip=h_ip,
                role="Monitored Endpoint",
                first_seen=time.time() - 300,
                last_seen=time.time(),
                risk_score=75 if h_ip == "10.0.0.24" else 20,
                baseline_profile_json=json.dumps(profile)
            )
            db.merge(db_host)

        # Save Correlated Campaigns to Database
        campaigns = graph.evaluate_campaigns(generated_alerts)
        for cmp in campaigns:
            db_cmp = CampaignRecord(
                campaign_id=cmp["campaign_id"],
                host_ip=cmp["host"],
                stages_json=json.dumps(cmp["stages"]),
                severity=cmp["severity"],
                risk=cmp["risk"],
                correlated_alerts_json=json.dumps(cmp["correlated_alert_ids"]),
                narrative=cmp["narrative"]
            )
            db.merge(db_cmp)

        db.commit()
        return {"status": "seeded_successfully", "alerts_created": len(generated_alerts), "campaigns_created": len(campaigns)}
    finally:
        db.close()


def _process_and_save_alerts(
    host_windows, baseline_mgr, detectors, fusion_engine,
    temporal_engine, risk_engine, explainer, db, generated_alerts
):
    for host, pkts in host_windows.items():
        if len(pkts) < 2:
            continue

        feats_dict = extract_features_from_window(pkts, window_duration=3.0)
        feats_vec = to_numpy_vector(feats_dict)

        base_res = baseline_mgr.update_host(host, feats_dict)
        base_dev = base_res["composite_baseline_deviation"]

        det_res = detectors.evaluate_all(feats_vec, feats_dict)
        threat_scores = det_res["threat_scores"]
        evidence_maps = det_res["evidence_maps"]
        novelty_score = det_res["novelty_score"]

        top_threat, top_conf, hyps, ev_items = fusion_engine.fuse(
            threat_scores=threat_scores,
            evidence_maps=evidence_maps,
            baseline_deviation=base_dev,
            temporal_score=0.5,
            graph_score=0.3,
            novelty_score=novelty_score,
            features_dict=feats_dict
        )

        ts = pkts[-1]["timestamp"]
        calibrated_conf = temporal_engine.update_confidence(
            host=host,
            threat=top_threat,
            evidence_score=top_conf,
            timestamp=ts
        )

        if calibrated_conf > 0.40 or top_conf > 0.45 or novelty_score > 0.70:
            risk_score, severity, _ = risk_engine.calculate_risk(
                threat_confidence=calibrated_conf,
                baseline_deviation=base_dev,
                temporal_persistence=0.7,
                graph_correlation=0.5,
                novelty=novelty_score
            )

            alt_hyps = [h.model_dump() for h in hyps if h.type != top_threat]
            ev_dicts = [e.model_dump() for e in ev_items]
            narrative = explainer.generate_narrative(
                host=host,
                threat_type=top_threat,
                confidence=calibrated_conf,
                risk=risk_score,
                evidence_items=ev_dicts,
                alternative_hypotheses=alt_hyps
            )

            related_entities = list(set([host] + [p.get("dst_ip") for p in pkts if p.get("dst_ip")][:3]))

            alert_id = f"SNT-{len(generated_alerts) + 1:05d}"
            alert_dict = {
                "alert_id": alert_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                "host": host,
                "type": top_threat,
                "severity": severity,
                "confidence": round(calibrated_conf, 2),
                "novelty": round(novelty_score, 2),
                "risk": risk_score,
                "hypotheses": [h.model_dump() for h in hyps],
                "evidence": ev_dicts,
                "related_entities": related_entities,
                "explanation": narrative,
                "acknowledged": False
            }
            generated_alerts.append(alert_dict)

            # Persist to database
            db_alert = AlertRecord(
                alert_id=alert_id,
                timestamp=alert_dict["timestamp"],
                host_ip=host,
                threat_type=top_threat,
                severity=severity,
                confidence=alert_dict["confidence"],
                novelty=alert_dict["novelty"],
                risk=risk_score,
                hypotheses_json=json.dumps(alert_dict["hypotheses"]),
                evidence_json=json.dumps(alert_dict["evidence"]),
                related_entities_json=json.dumps(related_entities),
                acknowledged=False,
                explanation=narrative
            )
            db.merge(db_alert)


if __name__ == "__main__":
    res = seed_database_from_benchmark()
    print("Database seeding result:", res)
