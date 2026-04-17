import os
import numpy as np
import pickle
from core.alerting import trigger_alert
from backend.train_model import train_model, MODEL_PATH

class AnomalyEngine:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self._load_or_train_model()

    def _load_or_train_model(self):
        """Loads existing model if present, else trains the advanced ML model."""
        if not os.path.exists(MODEL_PATH):
            print("[INFO] Anomaly Engine: No pre-trained ML model found. Triggering ML Training Pipeline...")
            train_model(contamination=0.01)
            
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                self.model = pickle.load(f)
            self.is_trained = True
            print("[INFO] Anomaly Engine: Loaded Advanced ML Model successfully.")
        else:
            print("[ERROR] Anomaly Engine: Failed to load ML Model.")

    def check_anomaly(self, packet_info):
        """
        Feeds live packet features into the ML Model to detect anomalies.
        """
        if not self.is_trained or not self.model:
            return

        size = packet_info.get('size', 0)
        port = packet_info.get('dst_port', 0)
        proto = packet_info.get('protocol_code', 0)
        flags = packet_info.get('tcp_flags', 0)
        
        if port is None:
            port = 0

        # Feature array required by our advanced ML Model: [size, port, proto, flags]
        features = np.array([[size, port, proto, flags]])
        
        # Predict: 1 for normal traffic, -1 for anomaly
        prediction = self.model.predict(features)
        
        if prediction[0] == -1:
            src_ip = packet_info.get('src_ip', 'Unknown')
            dst_ip = packet_info.get('dst_ip', 'Unknown')
            protocol_name = packet_info.get('protocol', 'Other')
            
            trigger_alert(
                src_ip, dst_ip, port,
                alert_type="ML Anomaly Detected",
                severity="LOW",
                description=f"ML Model flagged traffic pattern. Size={size}, Port={port}, Proto={protocol_name}, Flags={flags}"
            )
