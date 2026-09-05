"""
Isolation Forest anomaly layer (Stage 4, ML half of the hybrid).

Per the brief's model recommendation: start with Isolation Forest over
engineered features rather than a Transformer/GNN. It requires no labeled
attack data (only a corpus of "normal" flows to fit on), gives fast
streaming inference, and its anomaly score can be explained via which
input features are most extreme relative to the training distribution --
which is what we surface as supporting evidence.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

FEATURE_COLUMNS = [
    "duration",
    "packets",
    "bytes",
    "outbound_inbound_ratio",
    "half_open",
    "dst_syn_rate",
    "dst_half_open_rate",
    "dst_source_entropy",
    "src_unique_ports",
    "src_fanout_rate",
    "src_failed_ratio",
    "dns_label_entropy",
    "dns_query_rate",
    "periodicity_score",
    "outbound_baseline_ratio",
    "tls_ja3_host_count",
]


def to_vector(feats: dict[str, Any]) -> list[float]:
    return [float(feats.get(col, 0.0) or 0.0) for col in FEATURE_COLUMNS]


class AnomalyDetector:
    def __init__(self, contamination: float = 0.02, random_state: int = 7, n_estimators: int = 50) -> None:
        # NOTE: n_estimators trades detection stability for per-flow latency.
        # sklearn's per-call overhead dominates at streaming (one-row-at-a-
        # time) scoring, so this is tuned down from a batch-scoring-friendly
        # default (200) to keep single-flow latency low. Measured impact of
        # this tradeoff is reported by benchmark/run_benchmark.py -- it is
        # not assumed.
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=1,  # single flow per call: thread-pool dispatch overhead exceeds its benefit
        )
        self._fitted = False
        self._raw_scale = 1.0  # std of training decision_function scores, for logistic squashing

    def fit(self, benign_feature_dicts: list[dict[str, Any]]) -> None:
        X = np.array([to_vector(f) for f in benign_feature_dicts])
        self.model.fit(X)
        # decision_function is ~0 at the contamination-implied anomaly threshold
        # (positive = more normal, negative = more anomalous). We squash around
        # that zero point rather than using training-set percentiles directly --
        # percentile-based min/max calibration is too tight and misclassifies
        # ordinary variance in *held-out* benign traffic as anomalous.
        raw = self.model.decision_function(X)
        self._raw_scale = max(1e-6, float(np.std(raw)))
        self._fitted = True

    def score(self, feats: dict[str, Any]) -> float:
        """Return anomaly confidence in [0, 1]; higher = more anomalous.

        Logistic squash of the decision function around its zero point:
        raw == 0 (the contamination-implied boundary) maps to 0.5, and each
        std-dev of raw training variance moves the score by a controlled
        amount, so ordinary benign variance stays well under the alerting
        floor instead of saturating to 0/1.
        """
        if not self._fitted:
            raise RuntimeError("AnomalyDetector.fit() must be called before score()")
        x = np.array([to_vector(feats)])
        raw = self.model.decision_function(x)[0]
        anomaly = 1.0 / (1.0 + np.exp(raw / self._raw_scale))
        return float(max(0.0, min(1.0, anomaly)))

    def top_contributing_features(self, feats: dict[str, Any], benign_means: dict[str, float], k: int = 3) -> dict[str, float]:
        """Cheap explainability: features furthest (in relative terms) from benign mean."""
        deviations = {}
        for col in FEATURE_COLUMNS:
            mean = benign_means.get(col, 0.0)
            val = float(feats.get(col, 0.0) or 0.0)
            denom = abs(mean) if abs(mean) > 1e-6 else 1.0
            deviations[col] = abs(val - mean) / denom
        top = sorted(deviations.items(), key=lambda kv: kv[1], reverse=True)[:k]
        return {col: round(float(feats.get(col, 0.0) or 0.0), 3) for col, _ in top}
