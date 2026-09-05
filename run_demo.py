"""
One-command demo (Phase 6 packaging target).

Usage:
    python run_demo.py                  # normal-speed demo with printed alerts
    python run_demo.py --benchmark      # fast replay + throughput/latency report
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from simulate.flow_generator import generate_session, stream_session
from detect.pipeline import SentinelTwinPipeline


def make_benign_training_set(n: int = 4000, seed: int = 1):
    session = generate_session(duration_s=n / 15.0, benign_rate_per_s=15.0, seed=seed, include_attacks=False)
    return session


def run(speed_factor: float, session_duration_s: float, seed: int, quiet: bool):
    print("=" * 70)
    print("SentinelTwin -- passive-only threat detection demo")
    print("=" * 70)

    print("\n[1/4] Training Isolation Forest baseline on benign-only traffic...")
    pipeline = SentinelTwinPipeline()
    benign_training_flows = make_benign_training_set()
    pipeline.train_baseline(benign_training_flows)
    print(f"      trained on {len(benign_training_flows)} benign flows")

    print(f"\n[2/4] Generating a {session_duration_s:.0f}s replay session (benign + injected attacks)...")
    session = generate_session(duration_s=session_duration_s, benign_rate_per_s=15.0, seed=seed, include_attacks=True)
    print(f"      {len(session)} total flow records to replay")

    print(f"\n[3/4] Replaying at speed_factor={speed_factor} and running the detection pipeline...")
    ground_truth_counts = Counter(f.label for f in session)
    detected_counts = Counter()
    true_positive_labels = set()
    all_alerts = []

    printed = 0
    max_print = 15
    for flow in stream_session(session, speed_factor=speed_factor):
        alerts = pipeline.process_flow(flow)
        for alert in alerts:
            all_alerts.append(alert)
            detected_counts[alert.threat_class.value] += 1
            if flow.label == alert.threat_class.value:
                true_positive_labels.add(flow.label)
            if not quiet and alert.confidence >= 0.6 and printed < max_print:
                print(f"      ALERT  {json.dumps(alert.to_dict())}")
                printed += 1
    if not quiet and len(all_alerts) > max_print:
        print(f"      ... ({len(all_alerts) - printed} more alerts not shown)")

    print("\n[4/4] Session complete. Summary:")
    print("-" * 70)
    print("Ground truth flow counts by label:")
    for label, count in ground_truth_counts.items():
        print(f"  {label:22s} {count}")

    print("\nAlerts raised by threat_class:")
    for tc, count in detected_counts.items():
        print(f"  {tc:22s} {count}")

    attack_labels = set(ground_truth_counts) - {"benign"}
    recalled = attack_labels & true_positive_labels
    missed = attack_labels - true_positive_labels
    print(f"\nInjected attack categories recalled: {sorted(recalled)}")
    if missed:
        print(f"Injected attack categories MISSED:   {sorted(missed)}")

    print("\nPerformance:")
    stats = pipeline.stats.summary()
    for k, v in stats.items():
        print(f"  {k:20s} {v}")

    shared = pipeline.graph.shared_fingerprint_hosts()
    if shared:
        print("\nShared-destination correlations (possible coordinated behavior):")
        for dst, hosts in list(shared.items())[:10]:
            print(f"  {dst} <- {hosts}")

    benign_flow_ids = {f.flow_id for f in session if f.label == "benign"}
    false_positives = sum(1 for a in all_alerts if a.flow_id in benign_flow_ids)
    print(f"\nFalse positives on benign flows: {false_positives} / {len(benign_flow_ids)} "
          f"({100 * false_positives / max(1, len(benign_flow_ids)):.2f}%)")

    print("\nSafety check: no outbound production-network connection was ever opened.")
    print("This pipeline only reads FlowRecord objects generated in-process.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelTwin demo runner")
    parser.add_argument("--benchmark", action="store_true", help="fast replay for throughput/latency measurement")
    parser.add_argument("--duration", type=float, default=180.0, help="simulated session duration in seconds")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quiet", action="store_true", help="suppress per-alert printing")
    args = parser.parse_args()

    speed = 500.0 if args.benchmark else 20.0
    run(speed_factor=speed, session_duration_s=args.duration, seed=args.seed, quiet=args.quiet or args.benchmark)
