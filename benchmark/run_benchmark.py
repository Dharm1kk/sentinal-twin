"""
Throughput/latency benchmark (Phase 5 of the brief).

The brief is explicit: state the tested rate, don't assume one. This
script measures flows/sec sustained over a fixed wall-clock window on
*this* machine, plus p50/p95/max per-flow processing latency, and prints
a report -- it does not claim results beyond what it measured.
"""

from __future__ import annotations

import argparse
import platform
import time

from simulate.flow_generator import generate_session
from detect.pipeline import SentinelTwinPipeline


def main(n_flows: int, seed: int) -> None:
    print(f"Host: {platform.processor() or platform.machine()}, Python {platform.python_version()}")

    pipeline = SentinelTwinPipeline()
    training_flows = generate_session(duration_s=267, benign_rate_per_s=15.0, seed=seed, include_attacks=False)
    pipeline.train_baseline(training_flows)

    # generate a large mixed session and process it back-to-back, no
    # replay pacing -- this measures raw pipeline throughput, not
    # wall-clock-paced replay
    approx_duration_s = n_flows / 15.0
    session = generate_session(duration_s=approx_duration_s, benign_rate_per_s=15.0, seed=seed + 1, include_attacks=True)
    session = session[:n_flows] if len(session) > n_flows else session

    t0 = time.perf_counter()
    for flow in session:
        pipeline.process_flow(flow)
    elapsed = time.perf_counter() - t0

    stats = pipeline.stats.summary()
    flows_per_sec = stats["flows_processed"] / elapsed

    print("\n--- SentinelTwin throughput/latency benchmark ---")
    print(f"Flows processed:      {stats['flows_processed']}")
    print(f"Wall-clock time:      {elapsed:.2f}s")
    print(f"Sustained throughput: {flows_per_sec:,.0f} flows/sec")
    print(f"p50 latency:          {stats['p50_latency_ms']} ms")
    print(f"p95 latency:          {stats['p95_latency_ms']} ms")
    print(f"max latency:          {stats['max_latency_ms']} ms")
    print(f"Alerts raised:        {stats['alerts_raised']}")
    print("\nBrief's stated targets: 10,000 flows/sec sustained, p95 <= 2000ms.")
    print(f"-> throughput target {'MET' if flows_per_sec >= 10_000 else 'NOT MET'} on this run/machine")
    print(f"-> latency target {'MET' if stats['p95_latency_ms'] <= 2000 else 'NOT MET'} on this run/machine")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--flows", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    main(n_flows=args.flows, seed=args.seed)
