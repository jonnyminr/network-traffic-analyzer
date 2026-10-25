import time
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
from sklearn.ensemble import IsolationForest
from utils.logger import logger


def calculate_mad(values: np.ndarray) -> float:
    """Calculates Median Absolute Deviation (MAD)."""
    if len(values) == 0:
        return 0.0
    med = np.median(values)
    return float(np.median(np.abs(values - med)))


class RollingBaseline:
    """
    Maintains rolling statistical baselines (mean, std, median, MAD,
    percentiles, min/max, EWMA) for a continuous metric.
    Prevents single extreme spikes from immediately corrupting baseline statistics.
    """
    def __init__(self, window_size: int = 40, ewma_alpha: float = 0.15):
        self.window_size = window_size
        self.ewma_alpha = ewma_alpha
        self.history: List[float] = []
        self.ewma: Optional[float] = None

    def update(self, val: float):
        # Update EWMA with outlier damping
        if self.ewma is None:
            self.ewma = val
        else:
            # If val is more than 5x EWMA, damp its contribution to baseline
            damped_val = min(val, self.ewma * 5.0) if self.ewma > 10.0 else val
            self.ewma = self.ewma_alpha * damped_val + (1.0 - self.ewma_alpha) * self.ewma

        self.history.append(float(val))
        if len(self.history) > self.window_size:
            self.history.pop(0)

    @property
    def is_warmed_up(self) -> bool:
        return len(self.history) >= 10

    def get_stats(self) -> Dict[str, float]:
        if not self.history:
            return {
                "mean": 0.0, "std": 0.0, "median": 0.0,
                "mad": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0,
                "ewma": 0.0, "samples": 0
            }
        arr = np.array(self.history)
        mean = float(np.mean(arr))
        std = float(np.std(arr))
        median = float(np.median(arr))
        mad = calculate_mad(arr)
        p95 = float(np.percentile(arr, 95))
        return {
            "mean": mean,
            "std": std,
            "median": median,
            "mad": mad,
            "p95": p95,
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "ewma": float(self.ewma) if self.ewma is not None else mean,
            "samples": len(self.history)
        }

    def compute_z_score(self, val: float) -> Tuple[float, str]:
        stats = self.get_stats()
        if stats["samples"] < 10:
            return 0.0, "Warming Up"

        # If standard deviation is suitable, calculate standard Z-score
        if stats["std"] > 1e-4:
            z = (val - stats["mean"]) / stats["std"]
            return float(z), "Standard Z-Score"

        # Fallback to robust MAD when std is zero or near-zero
        if stats["mad"] > 1e-4:
            robust_z = 0.6745 * (val - stats["median"]) / stats["mad"]
            return float(robust_z), "Robust MAD Score"

        # Baseline is completely flat (e.g. constant 0)
        if val > stats["mean"]:
            return 5.0, "Zero-Variance Spike"
        return 0.0, "Zero Variance"


class AnomalyDetector:
    """
    Advanced Multi-Model Network Anomaly Detector.
    Integrates rolling statistical baselines, mathematically correct Z-scores,
    robust MAD, multi-dimensional IsolationForest with explainability,
    and rule-based network attack heuristics.
    """
    def __init__(self):
        # Configurable thresholds
        self.z_score_threshold = 3.5
        self.mad_threshold = 4.0
        self.port_scan_threshold = 25
        self.warmup_samples = 12
        self.cooldown_seconds = 60.0

        # Rolling Baselines
        self.baseline_bytes = RollingBaseline(window_size=45)
        self.baseline_pkts = RollingBaseline(window_size=45)
        self.baseline_outbound = RollingBaseline(window_size=45)

        # Multi-dimensional IsolationForest
        self.ml_model: Optional[IsolationForest] = None
        self.is_model_trained = False
        self.training_features: List[List[float]] = []
        self.min_training_samples = 25
        self.feature_names = [
            "Bytes/sec", "Packets/sec", "Avg Packet Size",
            "Unique Dst Ports", "Unique Dst IPs", "SYN Ratio", "Outbound Ratio"
        ]

        self.last_alert_times: Dict[str, float] = {}

    def set_thresholds(self, z_score: float = None, port_scan: int = None, warmup: int = None):
        if z_score is not None:
            self.z_score_threshold = max(2.0, z_score)
        if port_scan is not None:
            self.port_scan_threshold = max(5, port_scan)
        if warmup is not None:
            self.warmup_samples = max(5, warmup)

    def _is_in_cooldown(self, alert_key: str, now: float) -> bool:
        last_time = self.last_alert_times.get(alert_key, 0.0)
        return (now - last_time) < self.cooldown_seconds

    def _mark_alert_emitted(self, alert_key: str, now: float):
        self.last_alert_times[alert_key] = now

    def process_stats(self, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes the latest measurement window and generates structured anomaly alerts.
        """
        alerts = []
        now = stats.get("timestamp", time.time())

        current_bytes = float(stats.get("bytes_per_sec", 0.0))
        current_pkts = float(stats.get("packets_per_sec", 0.0))
        outbound_rate = float(stats.get("outbound_rate", 0.0))
        syn_count = int(stats.get("tcp_syn_count", 0))
        ack_count = int(stats.get("tcp_ack_count", 0))
        dst_ports_count = int(stats.get("unique_dst_ports", 0))
        dst_ips_count = int(stats.get("unique_dst_ips", 0))

        # Check warm-up status
        is_warmed_up = self.baseline_bytes.get_stats()["samples"] >= self.warmup_samples

        # -------------------------------------------------------------
        # 1. Rule-Based: Port Scan Detection
        # -------------------------------------------------------------
        port_scan_candidates = stats.get("port_scan_candidates", {})
        for ip, port_count in port_scan_candidates.items():
            if port_count >= self.port_scan_threshold:
                alert_key = f"port_scan_{ip}"
                if not self._is_in_cooldown(alert_key, now):
                    self._mark_alert_emitted(alert_key, now)
                    alerts.append({
                        "category": "Port Scanning",
                        "title": "Port Scan Probing Activity",
                        "detection_method": "Rule-Based Port Counter",
                        "src_ip": ip,
                        "dst_ip": "Multiple",
                        "src_port": 0,
                        "dst_port": 0,
                        "anomaly_score": float(port_count),
                        "current_rate": f"{port_count} distinct ports/window",
                        "baseline_rate": f"<{self.port_scan_threshold} ports",
                        "explanation": f"Single source host probed {port_count} distinct destination ports within a 1-second measurement window.",
                        "recommended_action": f"Inspect firewall logs and examine connections from {ip}. Determine if an unauthorized network scan or vulnerability probe is in progress.",
                        "port_count": port_count,
                        "timestamp": now
                    })

        # -------------------------------------------------------------
        # 2. Rule-Based: Repeated Connection Attempts (SYN Flood / Retries)
        # -------------------------------------------------------------
        if syn_count >= 20 and ack_count <= max(2, int(syn_count * 0.15)):
            alert_key = "syn_flood_detected"
            if not self._is_in_cooldown(alert_key, now):
                self._mark_alert_emitted(alert_key, now)
                alerts.append({
                    "category": "Repeated Connection Attempts",
                    "title": "High SYN-to-ACK Disparity (Possible SYN Flood / Retries)",
                    "detection_method": "TCP Flag Heuristic",
                    "src_ip": "Multiple",
                    "dst_ip": "Local/Target",
                    "anomaly_score": float(syn_count),
                    "current_rate": f"{syn_count} SYNs vs {ack_count} ACKs",
                    "baseline_rate": "Balanced SYN/ACK handshake",
                    "explanation": f"Observed {syn_count} TCP SYN packets with only {ack_count} ACK acknowledgments, suggesting failed handshakes or SYN flood scanning.",
                    "recommended_action": "Check Connection Explorer for SYN_SENT / half-open flows. Verify if target services are unresponsive or rejecting connections.",
                    "timestamp": now
                })

        # -------------------------------------------------------------
        # 3. Statistical Anomaly: Bandwidth Spikes (Z-Score & Robust MAD)
        # -------------------------------------------------------------
        has_bandwidth_spike = False
        if is_warmed_up:
            z_score, method_name = self.baseline_bytes.compute_z_score(current_bytes)
            b_stats = self.baseline_bytes.get_stats()
            mean_kb = b_stats["mean"] / 1024.0
            cur_kb = current_bytes / 1024.0
            ratio = (current_bytes / max(1.0, b_stats["mean"]))

            if z_score >= self.z_score_threshold and current_bytes >= 15000.0: # min 15 KB/s to prevent alert on tiny noise
                has_bandwidth_spike = True
                alert_key = "bandwidth_spike"
                if not self._is_in_cooldown(alert_key, now):
                    self._mark_alert_emitted(alert_key, now)
                    # Extract top talker if available
                    top_ip = "Unknown"
                    if stats.get("top_talkers"):
                        top_ip = stats["top_talkers"][0][0]

                    alerts.append({
                        "category": "Bandwidth Spike",
                        "title": "Unusual Bandwidth Spike",
                        "detection_method": method_name,
                        "src_ip": top_ip,
                        "dst_ip": "Network",
                        "anomaly_score": round(z_score, 2),
                        "current_rate": f"{cur_kb:.2f} KB/s",
                        "baseline_rate": f"{mean_kb:.2f} KB/s (μ)",
                        "explanation": f"Current throughput ({cur_kb:.2f} KB/s) is {ratio:.1f}x the established rolling baseline ({mean_kb:.2f} KB/s). Statistical score: {z_score:.2f}.",
                        "recommended_action": "Inspect Top Talkers and Network Connections to identify the host or application responsible for the sudden volume surge.",
                        "timestamp": now
                    })

        # -------------------------------------------------------------
        # 4. Statistical Anomaly: Packet Rate Spike
        # -------------------------------------------------------------
        if is_warmed_up and not has_bandwidth_spike:
            pkt_z, pkt_method = self.baseline_pkts.compute_z_score(current_pkts)
            p_stats = self.baseline_pkts.get_stats()
            if pkt_z >= self.z_score_threshold and current_pkts >= 50.0:
                alert_key = "packet_rate_spike"
                if not self._is_in_cooldown(alert_key, now):
                    self._mark_alert_emitted(alert_key, now)
                    alerts.append({
                        "category": "Packet Rate Spike",
                        "title": "Unusual Packet Frequency Burst",
                        "detection_method": pkt_method,
                        "src_ip": "Network",
                        "dst_ip": "Local Host",
                        "anomaly_score": round(pkt_z, 2),
                        "current_rate": f"{current_pkts:.0f} pkts/s",
                        "baseline_rate": f"{p_stats['mean']:.0f} pkts/s",
                        "explanation": f"Observed abnormal burst in packet arrival rate ({current_pkts:.0f} pkts/s vs baseline {p_stats['mean']:.0f} pkts/s). Score: {pkt_z:.2f}.",
                        "recommended_action": "Check Packet Inspector to verify packet payload sizes. Many small packets often indicate scanning or heartbeat probing.",
                        "timestamp": now
                    })

        # -------------------------------------------------------------
        # 5. Rule-Based: Outbound Traffic Surge
        # -------------------------------------------------------------
        if is_warmed_up and outbound_rate > 30000.0:
            out_z, _ = self.baseline_outbound.compute_z_score(outbound_rate)
            if out_z >= self.z_score_threshold:
                alert_key = "outbound_traffic_spike"
                if not self._is_in_cooldown(alert_key, now):
                    self._mark_alert_emitted(alert_key, now)
                    alerts.append({
                        "category": "Unusual Outbound Traffic",
                        "title": "Unexpected Surge in Outbound Transmission",
                        "detection_method": "Outbound Baseline Z-Score",
                        "src_ip": "Local Host",
                        "dst_ip": "External Hosts",
                        "anomaly_score": round(out_z, 2),
                        "current_rate": f"{outbound_rate / 1024.0:.1f} KB/s",
                        "baseline_rate": f"{self.baseline_outbound.get_stats()['mean'] / 1024.0:.1f} KB/s",
                        "explanation": f"Outbound transmission from local interface exceeded rolling threshold ({out_z:.2f} deviations above normal).",
                        "recommended_action": "Investigate active outbound connections to external public IPs to ensure no unauthorized exfiltration or background upload is taking place.",
                        "timestamp": now
                    })

        # -------------------------------------------------------------
        # 6. Multi-dimensional IsolationForest ML Detection
        # -------------------------------------------------------------
        avg_pkt_size = (current_bytes / max(1.0, current_pkts)) if current_pkts > 0 else 0.0
        syn_ratio = (syn_count / max(1.0, current_pkts))
        outbound_ratio = (outbound_rate / max(1.0, current_bytes))

        feature_vector = [
            current_bytes,
            current_pkts,
            avg_pkt_size,
            float(dst_ports_count),
            float(dst_ips_count),
            syn_ratio,
            outbound_ratio
        ]

        self.training_features.append(feature_vector)
        if len(self.training_features) > 120:
            self.training_features.pop(0)

        # Train or retrain model periodically once minimum baseline samples are gathered
        if len(self.training_features) >= self.min_training_samples:
            if not self.is_model_trained or len(self.training_features) % 20 == 0:
                try:
                    X = np.array(self.training_features)
                    # Check if there is variance across samples
                    if np.any(np.std(X, axis=0) > 1e-4):
                        self.ml_model = IsolationForest(
                            n_estimators=75,
                            contamination=0.04,
                            random_state=42
                        )
                        self.ml_model.fit(X)
                        self.is_model_trained = True
                except Exception as e:
                    logger.debug(f"IsolationForest fit error: {e}")

            # Predict anomaly if model is ready and no duplicate spike alert was triggered
            if self.is_model_trained and self.ml_model is not None and not has_bandwidth_spike:
                try:
                    sample = np.array([feature_vector])
                    pred = self.ml_model.predict(sample)
                    decision = float(self.ml_model.decision_function(sample)[0])

                    if pred[0] == -1: # Outlier detected by IsolationForest
                        alert_key = "isolation_forest_anomaly"
                        if not self._is_in_cooldown(alert_key, now):
                            self._mark_alert_emitted(alert_key, now)

                            # Explainability: Identify which feature deviated most from median
                            X_train = np.array(self.training_features)
                            medians = np.median(X_train, axis=0)
                            mads = np.array([calculate_mad(X_train[:, i]) for i in range(X_train.shape[1])])

                            deviations = []
                            for idx, f_name in enumerate(self.feature_names):
                                f_val = feature_vector[idx]
                                f_med = medians[idx]
                                f_mad = mads[idx]
                                dev_score = abs(f_val - f_med) / max(1e-4, f_mad) if f_mad > 0 else 0.0
                                deviations.append((f_name, dev_score, f_val, f_med))

                            # Top deviating feature
                            top_dev = sorted(deviations, key=lambda x: x[1], reverse=True)[0]
                            f_title, f_score, f_val, f_med = top_dev

                            alerts.append({
                                "category": "ML Anomaly",
                                "title": "Multi-Dimensional ML Traffic Anomaly",
                                "detection_method": "IsolationForest (scikit-learn)",
                                "src_ip": "Network",
                                "dst_ip": "Local",
                                "anomaly_score": round(abs(decision), 3),
                                "current_rate": f"{current_bytes / 1024.0:.1f} KB/s ({current_pkts:.0f} pkts/s)",
                                "baseline_rate": f"Isolation distance: {decision:.3f}",
                                "explanation": (
                                    f"IsolationForest detected an anomalous multi-dimensional traffic pattern "
                                    f"(isolation score: {decision:.3f}). Most significant deviation: {f_title} "
                                    f"(Observed: {f_val:.1f}, Baseline Median: {f_med:.1f}, Relative Deviation: {f_score:.1f}x MAD)."
                                ),
                                "recommended_action": "Review active connection flows and protocol distributions. ML anomaly signifies an unusual multivariate traffic signature.",
                                "timestamp": now
                            })
                except Exception as e:
                    logger.debug(f"IsolationForest predict error: {e}")

        # Update rolling baselines with current measurements
        self.baseline_bytes.update(current_bytes)
        self.baseline_pkts.update(current_pkts)
        self.baseline_outbound.update(outbound_rate)

        return alerts
