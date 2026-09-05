"""
End-to-end streaming pipeline wiring stages 2-5 together.

process_flow() is the single entry point a real ingest gateway would call
per record. It is intentionally synchronous and side-effect-scoped to one
flow at a time so it can be dropped into an async queue consumer or a
Kafka handler without modification.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from simulate.flow_generator import FlowRecord
from detect.features import FeatureEngine
from detect.iforest_model import AnomalyDetector, FEATURE_COLUMNS, to_vector
from alerts.alert_manager import build_alerts
from alerts.graph_correlator import ThreatGraph
from schema.alert_schema import Alert


@dataclass
class PipelineStats:
    flows_processed: int = 0
    alerts_raised: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    def record_latency(self, ms: float) -> None:
        self.latencies_ms.append(ms)

    def summary(self) -> dict:
        if not self.latencies_ms:
            return {"flows_processed": self.flows_processed, "alerts_raised": self.alerts_raised}
        sorted_lat = sorted(self.latencies_ms)
        n = len(sorted_lat)
        return {
            "flows_processed": self.flows_processed,
            "alerts_raised": self.alerts_raised,
            "p50_latency_ms": round(sorted_lat[n // 2], 3),
            "p95_latency_ms": round(sorted_lat[int(n * 0.95)] if n > 1 else sorted_lat[0], 3),
            "max_latency_ms": round(sorted_lat[-1], 3),
        }


class SentinelTwinPipeline:
    def __init__(self) -> None:
        self.feature_engine = FeatureEngine()
        self.anomaly_detector = AnomalyDetector()
        self.graph = ThreatGraph()
        self.stats = PipelineStats()
        self._benign_means: dict[str, float] = {}
        self._is_trained = False

    def train_baseline(self, benign_flows: list[FlowRecord]) -> None:
        """Fit the Isolation Forest on a corpus of known-benign flows.

        A dedicated FeatureEngine instance is used here so training-time
        window state never leaks into the live engine's state.
        """
        training_engine = FeatureEngine()
        feats_list = [training_engine.compute(f) for f in benign_flows]
        self.anomaly_detector.fit(feats_list)

        import numpy as np
        vectors = np.array([to_vector(f) for f in feats_list])
        self._benign_means = dict(zip(FEATURE_COLUMNS, vectors.mean(axis=0).tolist()))
        self._is_trained = True

    def process_flow(self, flow: FlowRecord) -> list[Alert]:
        if not self._is_trained:
            raise RuntimeError("call train_baseline() before processing live traffic")

        t0 = time.perf_counter()
        feats = self.feature_engine.compute(flow)
        anomaly_score = self.anomaly_detector.score(feats)
        alerts = build_alerts(feats, anomaly_score, flow.src_ip, flow.dst_ip)

        for alert in alerts:
            self.graph.ingest(alert)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.stats.record_latency(elapsed_ms)
        self.stats.flows_processed += 1
        self.stats.alerts_raised += len(alerts)

        return alerts
