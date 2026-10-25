import numpy as np
from typing import Dict, Any, List, Optional
import time
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    def __init__(self):
        self.baseline_window_size = 30 # Use last 30 samples for baseline
        self.history: List[Dict[str, Any]] = []
        
        # ML Model
        self.ml_model: Optional[IsolationForest] = None
        self.is_model_trained = False
        self.training_features: List[List[float]] = []
        self.min_training_samples = 20

    def process_stats(self, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process the latest stats window and return a list of generated alerts.
        """
        alerts = []
        now = time.time()
        
        # 1. Rule-based detection: Port Scans
        for ip, port_count in stats.get('port_scan_candidates', {}).items():
            if port_count > 25: # Threshold for port scan
                alerts.append({
                    'timestamp': now,
                    'severity': 'Critical',
                    'description': f"Potential port scan from {ip}: {port_count} distinct ports accessed in last window."
                })
        
        # 2. Statistical Z-Score detection (Throughput Spikes)
        current_bytes = stats.get('bytes_per_sec', 0.0)
        has_spike = False
        if len(self.history) >= 10:
            byte_rates = [s['bytes_per_sec'] for s in self.history[-self.baseline_window_size:]]
            mean_bytes = float(np.mean(byte_rates))
            std_bytes = float(np.std(byte_rates))
            
            if std_bytes > 0:
                z_score = (current_bytes - mean_bytes) / std_bytes
                if z_score > 3.0: # 3 standard deviations
                    has_spike = True
                    alerts.append({
                        'timestamp': now,
                        'severity': 'Warning',
                        'description': f"Traffic spike detected! Z-Score: {z_score:.2f} (Current: {current_bytes:.0f} B/s, Mean: {mean_bytes:.0f} B/s)"
                    })
        
        # 3. ML-based detection (IsolationForest)
        current_features = [
            float(stats.get('bytes_per_sec', 0.0)),
            float(stats.get('packets_per_sec', 0.0)),
            float(stats.get('unique_src_ips', 0))
        ]
        self.training_features.append(current_features)
        if len(self.training_features) > 100:
            self.training_features.pop(0)

        # Train model once enough baseline samples are gathered
        if len(self.training_features) >= self.min_training_samples:
            if not self.is_model_trained or len(self.training_features) % 15 == 0:
                try:
                    X = np.array(self.training_features)
                    # Check if there is variance in the features
                    if np.any(np.std(X, axis=0) > 0):
                        self.ml_model = IsolationForest(contamination=0.05, random_state=42)
                        self.ml_model.fit(X)
                        self.is_model_trained = True
                except Exception:
                    pass

            # Predict anomaly if model is ready and no duplicate spike alert was triggered
            if self.is_model_trained and self.ml_model is not None and not has_spike:
                try:
                    sample = np.array([current_features])
                    prediction = self.ml_model.predict(sample)
                    if prediction[0] == -1: # Anomaly detected
                        alerts.append({
                            'timestamp': now,
                            'severity': 'Warning',
                            'description': (
                                f"ML Anomaly Detected (IsolationForest): Unusual traffic signature "
                                f"({current_features[0]:.0f} B/s, {current_features[1]:.0f} pkts/s, "
                                f"{int(current_features[2])} unique IPs)."
                            )
                        })
                except Exception:
                    pass
        
        # Update history
        self.history.append(stats)
        if len(self.history) > self.baseline_window_size:
            self.history.pop(0)
            
        return alerts
