"""
SYN - AI Model Manager
"""

import hashlib
import json
import os
from typing import Dict, Optional, Tuple
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from syn.core.config import get_models_dir
from syn.core.logger import logger

FEATURE_COLUMNS = ["ttl", "latency_ms"]


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_training_dataset() -> Tuple[np.ndarray, np.ndarray]:
    """Build a realistic multi-hop TTL + latency training dataset."""
    rows = []
    labels = []

    # Linux / Unix / macOS / FreeBSD (Default initial TTL 64, typical hop decay 0..28)
    for ttl in (36, 42, 48, 52, 56, 60, 62, 63, 64, 65):
        for lat in (1.0, 5.0, 15.0, 40.0, 90.0, 180.0, 320.0):
            rows.append([float(ttl), lat])
            labels.append("Linux/64")

    # Windows (Default initial TTL 128, typical hop decay 0..30)
    for ttl in (98, 104, 110, 116, 120, 124, 126, 127, 128):
        for lat in (1.0, 5.0, 15.0, 40.0, 90.0, 180.0, 320.0):
            rows.append([float(ttl), lat])
            labels.append("Windows/128")

    # Network Appliances / Solaris / Cisco (Default initial TTL 255, hop decay 0..30)
    for ttl in (225, 232, 238, 244, 248, 252, 254, 255):
        for lat in (1.0, 5.0, 15.0, 40.0, 90.0, 180.0, 320.0):
            rows.append([float(ttl), lat])
            labels.append("Network/255")

    return np.array(rows, dtype=float), np.array(labels)


class ModelManager:
    """Manages loading, integrity verification, and training of ML models."""

    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = models_dir or get_models_dir()
        self.classifier_file = os.path.join(self.models_dir, "umay_mk25_os_classifier.joblib")
        self.anomaly_file = os.path.join(self.models_dir, "umay_mk25_anomaly_detector.joblib")
        self.scaler_file = os.path.join(self.models_dir, "umay_mk25_scaler.joblib")
        self.manifest_file = os.path.join(self.models_dir, "model_checksums.json")

        self.classifier = None
        self.anomaly_detector = None
        self.scaler = None

    def _verify_integrity(self) -> bool:
        """Verify SHA-256 digests of serialized joblib artifacts before unpickling."""
        required_files = {
            "classifier": self.classifier_file,
            "anomaly_detector": self.anomaly_file,
            "scaler": self.scaler_file,
        }
        if not all(os.path.isfile(p) for p in required_files.values()):
            return False
        if not os.path.isfile(self.manifest_file):
            return False

        try:
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                manifest: Dict[str, str] = json.load(f)
            for key, path in required_files.items():
                if manifest.get(key) != _sha256_file(path):
                    logger.warning(f"[AI_SECURITY] Checksum mismatch for '{os.path.basename(path)}'. Retraining clean models.")
                    return False
            return True
        except Exception as exc:
            logger.warning(f"[AI_SECURITY] Failed to validate model manifest ({exc}). Retraining.")
            return False

    def load_or_train_models(self):
        """Load verified models or retrain if missing, corrupt, or tampered."""
        if self._verify_integrity():
            try:
                logger.info("[SYSTEM] Loading AI inference models...")
                self.classifier = joblib.load(self.classifier_file)
                self.anomaly_detector = joblib.load(self.anomaly_file)
                self.scaler = joblib.load(self.scaler_file)
                logger.info("[SYSTEM] AI models initialized successfully.")
                return self.classifier, self.anomaly_detector, self.scaler
            except Exception as exc:
                logger.warning(f"[SYSTEM] Model loading failed ({exc}). Retraining models...")
        else:
            logger.warning("[SYSTEM] Valid verified models not found. Commencing training phase...")

        self._train_models()
        return self.classifier, self.anomaly_detector, self.scaler

    def _train_models(self):
        """Train OS classifier, scaler, and anomaly detector with consistent NumPy inputs."""
        os.makedirs(self.models_dir, exist_ok=True)
        X, y = _build_training_dataset()

        logger.info("[AI_TRAIN] Commencing Classifier Training...")
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.classifier.fit(X, y)
        joblib.dump(self.classifier, self.classifier_file)
        logger.info("[AI_TRAIN] Classifier successfully saved.")

        logger.info("[AI_TRAIN] Commencing Anomaly Detector Training...")
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.anomaly_detector = LocalOutlierFactor(n_neighbors=12, contamination=0.05, novelty=True)
        self.anomaly_detector.fit(X_scaled)
        joblib.dump(self.anomaly_detector, self.anomaly_file)
        joblib.dump(self.scaler, self.scaler_file)

        manifest = {
            "classifier": _sha256_file(self.classifier_file),
            "anomaly_detector": _sha256_file(self.anomaly_file),
            "scaler": _sha256_file(self.scaler_file),
        }
        with open(self.manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        logger.info("[AI_TRAIN] Anomaly Detector, Scaler, and SHA-256 manifest saved.")
