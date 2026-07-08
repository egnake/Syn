"""
SYN - Yapay Zeka Model YÃ¶neticisi
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
    """Yapay Zeka (Makine Ã–ÄŸrenimi) modellerinin yÃ¼klenmesi ve eÄŸitilmesinden sorumludur."""
    
    def __init__(self):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = None

    def load_or_train_models(self):
        """KayÄ±tlÄ± modelleri yÃ¼kler veya ilk kez eÄŸitir ve kaydeder."""
        try:
            logger.info("EÄŸitilmiÅŸ Modeller YÃ¼kleniyor...")
            self.classifier = joblib.load(MODEL_CLASSIFIER_FILE)
            self.anomaly_detector = joblib.load(MODEL_ANOMALY_FILE)
            self.scaler = joblib.load(MODEL_SCALER_FILE)
            logger.info("Modeller baÅŸarÄ±yla yÃ¼klendi.")
        except FileNotFoundError:
            logger.warning("KayÄ±tlÄ± model bulunamadÄ±. Model EÄŸitimi BaÅŸlatÄ±lÄ±yor...")
            self._train_models()
            
        return self.classifier, self.anomaly_detector, self.scaler

    def _train_models(self):
        """TTL 127 ve 63 gibi yakÄ±n deÄŸerler ile gÃ¼Ã§lendirilmiÅŸ eÄŸitim verisi ile modelleri eÄŸitir."""
        training_data = [
            [64, 5.0, 'Linux/64'], [64, 10.0, 'Linux/64'], [63, 15.0, 'Linux/64'], [65, 30.0, 'Linux/64'],
            [128, 5.0, 'Windows/128'], [128, 10.0, 'Windows/128'], [127, 20.0, 'Windows/128'], [126, 50.0, 'Windows/128'],
            [255, 10.0, 'AÄŸ CihazÄ±/255'], [254, 50.0, 'AÄŸ CihazÄ±/255'], [255, 100.0, 'AÄŸ CihazÄ±/255'],
        ]
        df = pd.DataFrame(training_data, columns=['ttl', 'latency_ms', 'OS'])
        X = df[['ttl', 'latency_ms']]
        y = df['OS']
        
        logger.info("1. YZ SÄ±nÄ±flandÄ±rma EÄŸitimi BaÅŸlÄ±yor...")
        self.classifier = RandomForestClassifier(random_state=42)
        self.classifier.fit(X, y)
        joblib.dump(self.classifier, MODEL_CLASSIFIER_FILE)
        logger.info(f"SÄ±nÄ±flandÄ±rma Modeli baÅŸarÄ±yla kaydedildi: {MODEL_CLASSIFIER_FILE}")
        
        logger.info("2. YZ Anomali Tespiti EÄŸitimi BaÅŸlÄ±yor...")
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.anomaly_detector = LocalOutlierFactor(contamination='auto', novelty=True) 
        self.anomaly_detector.fit(X_scaled)
        joblib.dump(self.anomaly_detector, MODEL_ANOMALY_FILE)
        joblib.dump(self.scaler, MODEL_SCALER_FILE)
        logger.info(f"Anomali Modeli ve Ã–lÃ§ekleyici baÅŸarÄ±yla kaydedildi.")


