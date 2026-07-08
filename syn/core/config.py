"""
SYN - YapÄ±landÄ±rma ve Sabitler
"""

import os
from typing import Dict, List

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

MODEL_CLASSIFIER_FILE = os.path.join(MODELS_DIR, 'umay_mk25_os_classifier.joblib')
MODEL_ANOMALY_FILE = os.path.join(MODELS_DIR, 'umay_mk25_anomaly_detector.joblib')
MODEL_SCALER_FILE = os.path.join(MODELS_DIR, 'umay_mk25_scaler.joblib')

ANOMALY_THRESHOLD = -0.15

ASYNC_TIMEOUT = 1.5  # Saniye cinsinden asenkron TCP baÄŸlantÄ± zaman aÅŸÄ±mÄ±
ASYNC_CONCURRENCY_LIMIT = 100  # AynÄ± anda aÃ§Ä±k olabilecek maksimum baÄŸlantÄ± sayÄ±sÄ±

SERVICE_PROBES: Dict[int, List[str]] = {
    80: [
        'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\n\r\n',
        'HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\n\r\n'
    ],
    443: [
        'GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\n\r\n',
        'HEAD / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: syn-Scanner\r\n\r\n'
    ],
    21: [
        '\r\n',
        'USER anonymous\r\n'
    ],
    22: [
        'SSH-2.0-syn-Scanner\r\n',
        'SSH-1.0-syn-Scanner\r\n'
    ],
    23: [
        '\r\n'
    ],
    139: [
        '\\x81\\x04\\x01\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
    ],
    445: [
        '\\x81\\x04\\x01\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
    ],
    3389: [
        '\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00'
    ]
}

QUICK_SCAN_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389]







