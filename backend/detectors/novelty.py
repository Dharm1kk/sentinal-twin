"""
Novelty and Unknown-Threat Detector Specialist
Implements Section 5.2 & Section 12: Uses Isolation Forest to score unknown anomalies
independent of predefined attack classes (NOVEL_BEHAVIOUR lane).
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ml/models/model_novelty.joblib"))


class NoveltyDetector:
    def __init__(self, novelty_threshold: float = 0.55, known_threshold: float = 0.50):
        self.model = joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None
        self.novelty_threshold = novelty_threshold
        self.known_threshold = known_threshold

    def score(self, features_vector: np.ndarray) -> Tuple[float, bool]:
        """
        Computes anomaly score between 0.0 (strictly normal) and 1.0 (highly novel outlier).
        Returns (novelty_score, is_outlier)
        """
        if self.model is None:
            return 0.0, False

        raw_score = float(self.model.score_samples(features_vector.reshape(1, -1))[0])
        # Calibrate raw_score (benign median is ~ -0.49, outliers < -0.65)
        # Normal benign traffic -> novelty < 0.30. Extreme anomaly -> novelty > 0.65+
        normalized_novelty = float(np.clip((-raw_score - 0.48) / 0.28, 0.0, 1.0))

        is_novel = normalized_novelty >= self.novelty_threshold
        return round(normalized_novelty, 3), is_novel


