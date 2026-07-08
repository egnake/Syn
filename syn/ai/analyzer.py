"""
SYN - Yapay Zeka AnalizÃ¶rÃ¼
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any
from syn.core.logger import logger

class AIAnalyzer:
    """Tarama sonuÃ§larÄ±nÄ± YZ modelleri Ã¼zerinden geÃ§irerek tahminler ve anomali skorlarÄ± Ã¼retir."""
    
    def __init__(self, classifier, anomaly_detector, scaler):
        self.classifier = classifier
        self.anomaly_detector = anomaly_detector
        self.scaler = scaler

    def analyze(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not results:
            return []
            
        logger.info("[AI_EXEC] Preprocessing network vectors for AI consumption...")
        df = pd.DataFrame(results)
        X_analysis = df[['ttl', 'latency_ms']].copy()

        X_analysis.loc[X_analysis['ttl'] == -1, ['ttl', 'latency_ms']] = 0 
        
        try:
            X_scaled = self.scaler.transform(X_analysis)

            df['anomaly_score'] = self.anomaly_detector.decision_function(X_scaled) 
            df['ai_os_tahmini'] = self.classifier.predict(X_analysis.values)
            logger.info("[AI_EXEC] Inference successful: OS footprints and anomaly scores mapped.")
        except Exception as e:
            logger.error(f"[AI_ERROR] Inference failure: {e}")
            df['anomaly_score'] = np.nan
            df['ai_os_tahmini'] = 'HATA/YZ'
            
        return df.to_dict('records')




