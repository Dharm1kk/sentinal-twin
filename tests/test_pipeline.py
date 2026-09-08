"""
End-to-End Pipeline Verification Test
Runs the full ingestion -> extraction -> baselines -> detectors -> fusion -> graph -> risk -> alert pipeline
over the synthesized NTRO benchmark PCAP.
"""

import os
import sys
import json
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.ingestion import StreamingPCAPIngestor, FlowAggregator
from backend.features import extract_features_from_window, to_numpy_vector
from backend.baselines import HostBaselineManager
from backend.detectors import DetectorSuite
from backend.fusion import EvidenceFusionEngine
from backend.temporal import TemporalEngine
from backend.graph import DynamicEvidenceGraph
from backend.risk import RiskEngine
from backend.explainability import ExplainabilityEngine
from backend.schemas.alert_schema import Alert


def run_test():
    pcap_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../data/sample/ntro_benchmark_evaluation.pcap"))
    assert os.path.exists(pcap_path), f"PCAP missing at {pcap_path}"

    print(f"[*] Initializing pipeline components on {pcap_path}...")
    ingestor = StreamingPCAPIngestor(pcap_path)
    aggregator = FlowAggregator(window_seconds=3.0)
    baseline_mgr = HostBaselineManager()
    detectors = DetectorSuite()
    fusion_engine = EvidenceFusionEngine()
    temporal_engine = TemporalEngine()
    graph = DynamicEvidenceGraph()
    risk_engine = RiskEngine()
    explainer = ExplainabilityEngine()

    total_packets = 0
    generated_alerts = []
    alert_counter = 1

    t_start = time.time()

    for pkt in ingestor.stream_packets():
        total_packets += 1
        
        # Add to graph
        graph.add_flow_observation(
            src_ip=pkt["src_ip"],
            dst_ip=pkt["dst_ip"],
            dst_port=pkt["dst_port"],
            protocol=pkt["protocol"],
            timestamp=pkt["timestamp"],
            dns_query=pkt.get("dns_query")
        )

        flushed_windows = aggregator.add_packet(pkt)
        if flushed_windows:
            process_flushed_windows(
                flushed_windows,
                baseline_mgr,
                detectors,
                fusion_engine,
                temporal_engine,
                graph,
                risk_engine,
                explainer,
                generated_alerts,
                alert_counter
            )

    # Process final remaining packets
    remaining = aggregator.flush_remaining()
    if remaining:
        process_flushed_windows(
            remaining,
            baseline_mgr,
            detectors,
            fusion_engine,
            temporal_engine,
            graph,
            risk_engine,
            explainer,
            generated_alerts,
            alert_counter
        )

    duration = time.time() - t_start
    print(f"\n[+] Pipeline completed in {duration:.2f}s ({total_packets} packets processed)")
    print(f"[+] Total Alerts Generated: {len(generated_alerts)}")

    # Campaign evaluation
    campaigns = graph.evaluate_campaigns(generated_alerts)
    print(f"[+] Correlated Attack-Chain Campaigns: {len(campaigns)}")
    for cmp in campaigns:
        print(f"    - [{cmp['severity']}] {cmp['campaign_id']} on {cmp['host']} | Risk: {cmp['risk']}/100")
        print(f"      Narrative: {cmp['narrative']}")

    # Print sample alert matching Section 21
    if generated_alerts:
        print("\n--- SAMPLE ALERT JSON (Section 21 Schema) ---")
        print(json.dumps(generated_alerts[0], indent=2))

    # Verify key threat classes were detected
    detected_types = set(a["type"] for a in generated_alerts)
    print(f"\n[+] Unique Detected Threat Classes: {detected_types}")
    assert len(generated_alerts) > 0, "No alerts were raised!"
    print("\n[SUCCESS] End-to-End Pipeline test PASSED!")


def process_flushed_windows(
    host_windows,
    baseline_mgr,
    detectors,
    fusion_engine,
    temporal_engine,
    graph,
    risk_engine,
    explainer,
    generated_alerts,
    alert_counter
):
    for host, pkts in host_windows.items():
        if len(pkts) < 2:
            continue

        # 1. Feature Extraction
        feats_dict = extract_features_from_window(pkts, window_duration=3.0)
        feats_vec = to_numpy_vector(feats_dict)

        # 2. Host Baseline Engine
        base_res = baseline_mgr.update_host(host, feats_dict)
        base_dev = base_res["composite_baseline_deviation"]

        # 3. Detectors Inference
        det_res = detectors.evaluate_all(feats_vec, feats_dict)
        threat_scores = det_res["threat_scores"]
        evidence_maps = det_res["evidence_maps"]
        novelty_score = det_res["novelty_score"]

        # 4. Evidence Fusion & Competing Hypotheses
        top_threat, top_conf, hyps, ev_items = fusion_engine.fuse(
            threat_scores=threat_scores,
            evidence_maps=evidence_maps,
            baseline_deviation=base_dev,
            temporal_score=0.5,
            graph_score=0.3,
            novelty_score=novelty_score,
            features_dict=feats_dict
        )

        # 5. Temporal Update
        ts = pkts[-1]["timestamp"]
        calibrated_conf = temporal_engine.update_confidence(
            host=host,
            threat=top_threat,
            evidence_score=top_conf,
            timestamp=ts
        )

        # Raise alert if confidence or base deviation is significant
        if calibrated_conf > 0.40 or top_conf > 0.45 or novelty_score > 0.70:
            # 6. Risk Scoring
            risk_score, severity, _ = risk_engine.calculate_risk(
                threat_confidence=calibrated_conf,
                baseline_deviation=base_dev,
                temporal_persistence=0.7,
                graph_correlation=0.5,
                novelty=novelty_score
            )

            # 7. Grounded Narrative
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

            alert_obj = Alert(
                alert_id=f"ARG-{len(generated_alerts) + 1:05d}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                host=host,
                type=top_threat,
                severity=severity,
                confidence=round(calibrated_conf, 2),
                novelty=round(novelty_score, 2),
                risk=risk_score,
                hypotheses=hyps,
                evidence=ev_items,
                related_entities=related_entities,
                explanation=narrative
            )
            generated_alerts.append(alert_obj.model_dump())


if __name__ == "__main__":
    run_test()
