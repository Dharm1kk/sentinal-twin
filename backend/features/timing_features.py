"""
Timing and Periodicity Feature Extraction
Implements Inter-Arrival Time (IAT) statistics, Autocorrelation, and Periodicity detection
for C2 Beaconing and regular automated malware traffic (Sentinel Feature Pipeline).
"""

import numpy as np
from typing import List, Dict, Any


def compute_timing_features(timestamps: List[float]) -> Dict[str, float]:
    """
    Computes statistical timing features from a sequence of packet or flow timestamps.
    """
    if len(timestamps) < 2:
        return {
            "mean_iat": 0.0,
            "std_iat": 0.0,
            "cv_iat": 0.0,
            "autocorrelation_lag1": 0.0,
            "periodicity_score": 0.0,
            "timing_regularity": 0.0,
        }

    # Sort timestamps in case of out-of-order delivery
    sorted_ts = sorted(timestamps)
    iats = np.diff(sorted_ts)

    # Filter out exact zero or negative IATs (sub-millisecond batches)
    valid_iats = iats[iats >= 0.0]
    if len(valid_iats) < 2:
        return {
            "mean_iat": float(np.mean(valid_iats)) if len(valid_iats) > 0 else 0.0,
            "std_iat": 0.0,
            "cv_iat": 0.0,
            "autocorrelation_lag1": 0.0,
            "periodicity_score": 0.0,
            "timing_regularity": 0.0,
        }

    mean_iat = float(np.mean(valid_iats))
    std_iat = float(np.std(valid_iats))
    
    # Coefficient of Variation (CV = std / mean). 
    # Periodic beaconing has very low CV (< 0.20), whereas human traffic has CV > 1.0.
    cv_iat = float(std_iat / mean_iat) if mean_iat > 1e-6 else 0.0

    # Lag-1 Autocorrelation
    if len(valid_iats) >= 4 and std_iat > 1e-6:
        n = len(valid_iats)
        y = valid_iats - mean_iat
        autocorr = np.correlate(y, y, mode='full')
        autocorr = autocorr[n-1:] / (autocorr[n-1] + 1e-9)
        lag1_ac = float(autocorr[1]) if len(autocorr) > 1 else 0.0
    else:
        lag1_ac = 0.0

    # Periodicity score (inverse of CV bounded between 0 and 1)
    # Low variance in IAT -> high regularity
    timing_regularity = float(1.0 / (1.0 + cv_iat))

    # FFT-based dominant frequency detection if sample is large enough
    periodicity_score = 0.0
    if len(valid_iats) >= 8:
        fft_vals = np.abs(np.fft.rfft(valid_iats - mean_iat))
        if len(fft_vals) > 1:
            power_sum = np.sum(fft_vals[1:])
            if power_sum > 1e-6:
                peak_power = np.max(fft_vals[1:])
                periodicity_score = float(peak_power / power_sum)

    # Composite regularity metric
    beacon_score = 0.7 * timing_regularity + 0.3 * max(0.0, lag1_ac)

    return {
        "mean_iat": round(mean_iat, 4),
        "std_iat": round(std_iat, 4),
        "cv_iat": round(cv_iat, 4),
        "autocorrelation_lag1": round(lag1_ac, 4),
        "periodicity_score": round(periodicity_score, 4),
        "timing_regularity": round(beacon_score, 4),
    }
