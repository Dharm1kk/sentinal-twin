"""
Temporal Confidence and Evidence Decay Engine
Implements Sentinel Temporal Engine:
E(t) = E0 * exp(-lambda * t)
Tracks temporal persistence, evolves confidence curves (31% -> 45% -> 58% -> 71% -> 83%),
and handles decay during silence or contradiction.
"""

import math
from typing import Dict, Any, List, Optional


class TemporalTrack:
    """
    Maintains temporal confidence state for a specific host-threat pair.
    """
    def __init__(self, host: str, threat: str, lambda_decay: float = 0.05):
        self.host = host
        self.threat = threat
        self.lambda_decay = lambda_decay
        self.current_confidence = 0.0
        self.last_update_time = 0.0
        self.history: List[Dict[str, Any]] = []

    def update(
        self,
        new_evidence_score: float,
        timestamp: float,
        evidence_reason: str = "Corroborating flow signature"
    ) -> float:
        """
        Updates confidence with time decay and new evidence.
        """
        if self.last_update_time == 0.0:
            dt = 0.0
        else:
            dt = max(0.0, timestamp - self.last_update_time)

        self.last_update_time = timestamp

        # Apply exponential decay over elapsed delta-t: E(t) = E0 * exp(-lambda * dt)
        decay_factor = math.exp(-self.lambda_decay * dt)
        decayed_conf = self.current_confidence * decay_factor

        # Incorporate new evidence with asymptotic accumulation
        if new_evidence_score > 0.4:
            # Positive reinforcement
            gain = (1.0 - decayed_conf) * (new_evidence_score * 0.35)
            self.current_confidence = min(0.99, decayed_conf + gain)
        elif new_evidence_score < 0.2:
            # Contradictory evidence decays confidence faster
            self.current_confidence = max(0.0, decayed_conf * 0.60)
        else:
            self.current_confidence = decayed_conf

        self.current_confidence = round(self.current_confidence, 3)

        # Store step in evolution history for UI visualization
        self.history.append({
            "timestamp": timestamp,
            "confidence": self.current_confidence,
            "confidence_pct": int(self.current_confidence * 100),
            "reason": evidence_reason,
            "dt": round(dt, 2)
        })

        return self.current_confidence


class TemporalEngine:
    def __init__(self):
        # (host, threat) -> TemporalTrack
        self.tracks: Dict[str, TemporalTrack] = {}

    def update_confidence(
        self,
        host: str,
        threat: str,
        evidence_score: float,
        timestamp: float,
        reason: str = "Repeated attack signature"
    ) -> float:
        key = f"{host}_{threat}"
        if key not in self.tracks:
            self.tracks[key] = TemporalTrack(host=host, threat=threat)
        return self.tracks[key].update(evidence_score, timestamp, reason)

    def get_confidence_timeline(self, host: str, threat: str) -> List[Dict[str, Any]]:
        key = f"{host}_{threat}"
        if key in self.tracks:
            return self.tracks[key].history
        return []
