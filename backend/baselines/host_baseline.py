"""
Host-Specific Behavioural Baseline Engine
Implements Rolling Median, Rolling MAD, Robust Z-score, Adaptive EWMA, and Two-Sided CUSUM
as specified in Sentinel Behavioral Engine.
"""

from collections import deque
from typing import Dict, Any, List, Optional
import numpy as np


class MetricTracker:
    """
    Tracks rolling statistics for a single metric on a specific host.
    """
    def __init__(self, name: str, window_size: int = 60, alpha: float = 0.05, cusum_k: float = 0.5, cusum_h: float = 5.0):
        self.name = name
        self.window_size = window_size
        self.history = deque(maxlen=window_size)
        self.alpha = alpha  # EWMA smoothing factor (slow adaptation)
        self.ewma = 0.0
        self.is_initialized = False

        # Two-sided CUSUM state
        self.cusum_k = cusum_k  # allowance
        self.cusum_h = cusum_h  # decision threshold
        self.cusum_pos = 0.0
        self.cusum_neg = 0.0

    def update(self, value: float, freeze_adaptation: bool = False) -> Dict[str, float]:
        val = float(value)
        
        # Calculate deviation against current baseline BEFORE updating
        if not self.is_initialized:
            self.history.append(val)
            self.ewma = val
            if len(self.history) >= 5:
                self.is_initialized = True
            return {
                "median": val,
                "mad": 1.0,
                "ewma": val,
                "robust_z": 0.0,
                "ewma_dev": 0.0,
                "ratio": 1.0,
                "cusum_score": 0.0,
                "total_deviation": 0.0,
                "warmup": True
            }

        hist_arr = np.array(self.history, dtype=float)
        median = float(np.median(hist_arr))
        mad = float(np.median(np.abs(hist_arr - median)))
        if mad < 1e-4:
            mad = max(1e-3, float(0.1 * abs(median)))

        # Section 5.4: robust_z = (x - median) / (1.4826 * MAD)
        robust_z = (val - median) / (1.4826 * mad)

        # EWMA deviation
        ewma_dev = abs(val - self.ewma) / max(1e-3, self.ewma) if self.ewma > 1e-3 else 0.0
        ratio = val / max(1e-3, self.ewma) if self.ewma > 1e-3 else 1.0

        # Section 5.3: CUSUM mean-shift update
        std_est = 1.4826 * mad
        standardized_diff = (val - median) / max(1e-3, std_est)
        self.cusum_pos = max(0.0, self.cusum_pos + standardized_diff - self.cusum_k)
        self.cusum_neg = max(0.0, self.cusum_neg - standardized_diff - self.cusum_k)
        cusum_score = max(self.cusum_pos, self.cusum_neg)

        # Section 7: deviation = robust_z(current) + EWMA deviation + ratio(current / expected) + CUSUM evidence
        deviation = abs(robust_z) + (ewma_dev * 2.0) + (max(0.0, ratio - 1.0) * 1.5) + (cusum_score * 0.5)

        # Update baseline state (freeze if an active attack is detected to avoid learning attacks as normal)
        if not freeze_adaptation:
            self.history.append(val)
            self.ewma = (self.alpha * val) + ((1.0 - self.alpha) * self.ewma)

        return {
            "median": round(median, 3),
            "mad": round(mad, 3),
            "ewma": round(self.ewma, 3),
            "robust_z": round(robust_z, 3),
            "ewma_dev": round(ewma_dev, 3),
            "ratio": round(ratio, 3),
            "cusum_score": round(cusum_score, 3),
            "total_deviation": round(deviation, 3),
            "warmup": len(self.history) < 15
        }


class HostBaselineManager:
    """
    Manages multi-metric behavioral baselines for all observed hosts on the monitored link.
    """
    TRACKED_METRICS = [
        "packet_rate",
        "byte_rate",
        "dns_query_rate",
        "unique_destinations",
        "exfil_byte_ratio"
    ]

    def __init__(self):
        # host_ip -> metric_name -> MetricTracker
        self.hosts: Dict[str, Dict[str, MetricTracker]] = {}
        self.active_attack_hosts: set = set()

    def get_or_create_host(self, host_ip: str) -> Dict[str, MetricTracker]:
        if host_ip not in self.hosts:
            self.hosts[host_ip] = {
                metric: MetricTracker(name=metric) for metric in self.TRACKED_METRICS
            }
        return self.hosts[host_ip]

    def update_host(
        self,
        host_ip: str,
        metrics_dict: Dict[str, float],
        is_attack_active: bool = False
    ) -> Dict[str, Any]:
        """
        Updates host baseline with observed metrics and returns composite deviation signals.
        """
        host_trackers = self.get_or_create_host(host_ip)
        results = {}
        max_robust_z = 0.0
        max_cusum = 0.0
        cumulative_deviation = 0.0

        for metric in self.TRACKED_METRICS:
            val = metrics_dict.get(metric, 0.0)
            res = host_trackers[metric].update(val, freeze_adaptation=is_attack_active)
            results[metric] = res
            
            if abs(res["robust_z"]) > abs(max_robust_z):
                max_robust_z = res["robust_z"]
            if res["cusum_score"] > max_cusum:
                max_cusum = res["cusum_score"]
            cumulative_deviation += res["total_deviation"]

        # Normalized baseline deviation score between 0.0 and 1.0
        # Normal host traffic is usually < 2.0 total deviation; attacks exceed 10.0+
        norm_deviation = min(1.0, cumulative_deviation / 25.0)

        return {
            "host": host_ip,
            "metrics": results,
            "max_robust_z": round(max_robust_z, 3),
            "max_cusum": round(max_cusum, 3),
            "composite_baseline_deviation": round(norm_deviation, 3),
            "is_warmup": any(r["warmup"] for r in results.values())
        }

    def get_host_profile(self, host_ip: str) -> Optional[Dict[str, Any]]:
        if host_ip not in self.hosts:
            return None
        profile = {}
        for m_name, tracker in self.hosts[host_ip].items():
            hist_arr = np.array(tracker.history, dtype=float) if tracker.history else np.array([0.0])
            median = float(np.median(hist_arr))
            mad = float(np.median(np.abs(hist_arr - median)))
            profile[m_name] = {
                "rolling_median": round(median, 3),
                "rolling_mad": round(mad, 3),
                "ewma_expected": round(tracker.ewma, 3),
                "history_points": len(tracker.history)
            }
        return profile
