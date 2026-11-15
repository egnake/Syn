"""
SYN - AI Network Vector Analyzer
"""

from typing import Any, Dict, List
import numpy as np
from syn.core.logger import logger


class AIAnalyzer:
    """Runs OS prediction and network anomaly scoring only on vectors with valid observed TTL."""

    def __init__(self, classifier, anomaly_detector, scaler):
        self.classifier = classifier
        self.anomaly_detector = anomaly_detector
        self.scaler = scaler

    def analyze(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not results:
            return []

        logger.info("[AI_EXEC] Preprocessing network vectors for AI consumption...")
        analyzed: List[Dict[str, Any]] = [dict(row) for row in results]

        try:
            valid_indices: List[int] = []
            valid_vectors: List[List[float]] = []

            for idx, row in enumerate(analyzed):
                ttl = row.get("ttl", -1)
                latency = row.get("latency_ms", -1.0)
                if (
                    isinstance(ttl, (int, float))
                    and isinstance(latency, (int, float))
                    and not np.isnan(ttl)
                    and not np.isnan(latency)
                    and ttl > 0
                    and latency >= 0
                ):
                    valid_indices.append(idx)
                    valid_vectors.append([float(ttl), float(latency)])
                else:
                    row["anomaly_score"] = None
                    row["ai_os_tahmini"] = "Unknown (No TTL)"

            if valid_vectors:
                X = np.array(valid_vectors, dtype=float)
                X_scaled = self.scaler.transform(X)
                anomaly_scores = self.anomaly_detector.decision_function(X_scaled)
                os_preds = self.classifier.predict(X)

                for pos, orig_idx in enumerate(valid_indices):
                    analyzed[orig_idx]["anomaly_score"] = float(anomaly_scores[pos])
                    analyzed[orig_idx]["ai_os_tahmini"] = str(os_preds[pos])

            logger.info("[AI_EXEC] Inference successful: OS footprints and anomaly scores mapped.")
        except Exception as exc:
            logger.error(f"[AI_ERROR] Inference failure: {exc}")
            for row in analyzed:
                row.setdefault("anomaly_score", None)
                row["ai_os_tahmini"] = "ERROR/AI"

        return analyzed
