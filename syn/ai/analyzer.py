"""
SYN - AI Network Vector Analyzer
"""

from collections import Counter
import re
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from syn.core.logger import logger

_BANNER_OS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("Windows", re.compile(r"\b(?:Microsoft-IIS|Microsoft Windows|Windows|Win32|Win64|IIS/[0-9])\b", re.IGNORECASE)),
    ("Linux (Ubuntu/Debian)", re.compile(r"\b(?:Ubuntu|Debian|Raspbian)\b", re.IGNORECASE)),
    ("Linux (RHEL/CentOS)", re.compile(r"\b(?:CentOS|Red Hat|RHEL|Fedora|AlmaLinux|Rocky Linux)\b", re.IGNORECASE)),
    ("Linux", re.compile(r"\b(?:Linux|Alpine)\b", re.IGNORECASE)),
    ("FreeBSD", re.compile(r"\b(?:FreeBSD|OpenBSD|NetBSD)\b", re.IGNORECASE)),
    ("macOS / Darwin", re.compile(r"\b(?:Darwin|macOS)\b", re.IGNORECASE)),
]


def infer_os_from_banner(banner: str) -> Optional[str]:
    """Infer likely host OS cleanly from explicit OS tokens in real service banners."""
    if not banner or banner == "Unknown (No Banner)" or "(Port Fallback)" in banner:
        return None
    for label, pattern in _BANNER_OS_PATTERNS:
        if pattern.search(banner):
            return label
    return None


class AIAnalyzer:
    """Runs OS prediction with TTL/latency ML vectors and banner/host-level OS fallback."""

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

            host_os_candidates: List[str] = []
            if valid_vectors:
                X = np.array(valid_vectors, dtype=float)
                X_scaled = self.scaler.transform(X)
                anomaly_scores = self.anomaly_detector.decision_function(X_scaled)
                os_preds = self.classifier.predict(X)

                for pos, orig_idx in enumerate(valid_indices):
                    pred = str(os_preds[pos])
                    analyzed[orig_idx]["anomaly_score"] = float(anomaly_scores[pos])
                    analyzed[orig_idx]["ai_os_tahmini"] = pred
                    if pred and not pred.startswith("Unknown") and "ERROR" not in pred:
                        host_os_candidates.append(pred)

            # Banner-level OS hints & host-level OS correlation when TTL was unavailable (ASYNC)
            banner_hints: Dict[int, str] = {}
            for idx, row in enumerate(analyzed):
                hint = infer_os_from_banner(str(row.get("banner", "")))
                if hint:
                    banner_hints[idx] = hint
                    host_os_candidates.append(hint)

            os_families = {label.split("/")[0].split(" (")[0] for label in host_os_candidates}
            consensus_os = (
                Counter(host_os_candidates).most_common(1)[0][0]
                if host_os_candidates and len(os_families) == 1
                else None
            )

            valid_set = set(valid_indices)
            for idx, row in enumerate(analyzed):
                if idx in valid_set:
                    continue
                if idx in banner_hints:
                    row["ai_os_tahmini"] = f"{banner_hints[idx]} (Banner Hint)"
                elif consensus_os:
                    row["ai_os_tahmini"] = f"{consensus_os} (Host Correlation)"

            logger.info("[AI_EXEC] Inference successful: OS footprints and anomaly scores mapped.")
        except Exception as exc:
            logger.error(f"[AI_ERROR] Inference failure: {exc}")
            for row in analyzed:
                row.setdefault("anomaly_score", None)
                row["ai_os_tahmini"] = "ERROR/AI"

        return analyzed
