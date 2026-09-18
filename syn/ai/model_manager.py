"""
SYN - Yapay Zeka Model Yöneticisi
"""

import os
import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
from sklearn.ensemble import RandomForestClassifier
from syn.core.config import MODEL_CLASSIFIER_FILE, MODEL_ANOMALY_FILE, MODEL_SCALER_FILE
from syn.core.logger import logger

class ModelManager:
    """Yapay Zeka (Makine Öğrenimi) modellerinin yüklenmesi ve eğitilmesinden sorumludur."""
    
    def __init__(self):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = None

    def load_or_train_models(self):
        """Kayıtlı modelleri yükler veya ilk kez eğitir ve kaydeder."""
        try:
            logger.info("[SYSTEM] Loading AI inference models...")
            self.classifier = joblib.load(MODEL_CLASSIFIER_FILE)
            self.anomaly_detector = joblib.load(MODEL_ANOMALY_FILE)
            self.scaler = joblib.load(MODEL_SCALER_FILE)
            logger.info("[SYSTEM] AI models initialized successfully.")
        except FileNotFoundError:
            logger.warning("[SYSTEM] No models found. Commencing training phase...")
            self._train_models()
            
        return self.classifier, self.anomaly_detector, self.scaler

    def _train_models(self):
        """TTL 127 ve 63 gibi yakın değerler ile güçlendirilmiş eğitim verisi ile modelleri eğitir."""
        training_data = [
            [64, 5.0, 'Linux/64'], [64, 10.0, 'Linux/64'], [63, 15.0, 'Linux/64'], [65, 30.0, 'Linux/64'],
            [128, 5.0, 'Windows/128'], [128, 10.0, 'Windows/128'], [127, 20.0, 'Windows/128'], [126, 50.0, 'Windows/128'],
            [255, 10.0, 'Ağ Cihazı/255'], [254, 50.0, 'Ağ Cihazı/255'], [255, 100.0, 'Ağ Cihazı/255'],
        ]
        df = pd.DataFrame(training_data, columns=['ttl', 'latency_ms', 'OS'])
        X = df[['ttl', 'latency_ms']]
        y = df['OS']
        
        logger.info("[AI_TRAIN] Commencing Classifier Training...")
        self.classifier = RandomForestClassifier(random_state=42)
        self.classifier.fit(X, y)
        joblib.dump(self.classifier, MODEL_CLASSIFIER_FILE)
        logger.info("[AI_TRAIN] Classifier successfully dumped.")
        
        logger.info("[AI_TRAIN] Commencing Anomaly Detector Training...")
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.anomaly_detector = LocalOutlierFactor(contamination='auto', novelty=True) 
        self.anomaly_detector.fit(X_scaled)
        joblib.dump(self.anomaly_detector, MODEL_ANOMALY_FILE)
        joblib.dump(self.scaler, MODEL_SCALER_FILE)
        logger.info("[AI_TRAIN] Anomaly Detector and Scaler successfully dumped.")














