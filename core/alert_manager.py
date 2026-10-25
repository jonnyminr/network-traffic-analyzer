import time
import json
import uuid
import threading
from typing import Dict, List, Optional, Any
from PySide6.QtCore import QObject, Signal
from utils.logger import logger
from core.incident_db import IncidentDatabase
from core.threat_intelligence import classify_ip_address


class SecurityAlert:
    """Represents a standardized, evidence-based security alert."""
    def __init__(
        self,
        alert_id: str,
        title: str,
        category: str,
        severity: str,
        detection_method: str,
        src_ip: str = "Unknown",
        dst_ip: str = "Unknown",
        src_port: int = 0,
        dst_port: int = 0,
        current_rate: str = "Not available",
        baseline_rate: str = "Not available",
        anomaly_score: float = 0.0,
        explanation: str = "",
        recommended_action: str = "",
        timestamp: float = None,
        status: str = "New",
        occurrences: int = 1,
        related_conn_ids: List[str] = None
    ):
        self.alert_id = alert_id
        self.title = title
        self.category = category
        self.severity = severity
        self.detection_method = detection_method
        self.src_ip = src_ip or "Unknown"
        self.dst_ip = dst_ip or "Unknown"
        self.src_port = src_port or 0
        self.dst_port = dst_port or 0
        self.current_rate = current_rate
        self.baseline_rate = baseline_rate
        self.anomaly_score = anomaly_score
        self.first_seen = timestamp if timestamp else time.time()
        self.last_seen = self.first_seen
        self.occurrences = occurrences
        self.status = status
        self.explanation = explanation
        self.recommended_action = recommended_action
        self.related_conn_ids = related_conn_ids or []
        self.notes = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "current_rate": self.current_rate,
            "baseline_rate": self.baseline_rate,
            "anomaly_score": round(self.anomaly_score, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "status": self.status,
            "explanation": self.explanation,
            "recommended_action": self.recommended_action,
            "related_conn_ids": self.related_conn_ids,
            "raw_json": json.dumps({
                "notes": self.notes,
                "related_conn_ids": self.related_conn_ids
            })
        }


class AlertManager(QObject):
    """
    Central coordinator for security alerts.
    Enforces deduplication, grouping by category & IP endpoints within a cooldown window,
    multi-factor severity evaluation, and persistent SQLite storage.
    """
    new_alert_raised = Signal(dict)
    alert_updated = Signal(dict)
    alerts_cleared = Signal()

    _instance = None
    _singleton_lock = threading.Lock()
    _initialized = False

    def __new__(cls):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super(AlertManager, cls).__new__(cls)
            return cls._instance

    def __init__(self):
        if getattr(self, '_initialized', False):
            return
        super().__init__()
        self._initialized = True
        self.db = IncidentDatabase()
        self.lock = threading.Lock()
        self.cooldown_window = 60.0 # seconds for deduplication grouping

        # Key: (category, src_ip, dst_ip) -> SecurityAlert
        self.active_groups: Dict[tuple, SecurityAlert] = {}
        # In-memory list for UI presentation
        self.alerts_list: List[SecurityAlert] = []

        self._load_recent_alerts_from_db()
        logger.info("Initialized AlertManager with persistent SQLite storage and deduplication")

    def _load_recent_alerts_from_db(self):
        saved = self.db.get_all_alerts(limit=300)
        with self.lock:
            for s in saved:
                alert = SecurityAlert(
                    alert_id=s["alert_id"],
                    title=s["title"],
                    category=s["category"],
                    severity=s["severity"],
                    detection_method=s["detection_method"],
                    src_ip=s["src_ip"],
                    dst_ip=s["dst_ip"],
                    src_port=s["src_port"],
                    dst_port=s["dst_port"],
                    current_rate=s["current_rate"],
                    baseline_rate=s["baseline_rate"],
                    anomaly_score=s["anomaly_score"],
                    explanation=s["explanation"],
                    recommended_action=s["recommended_action"],
                    timestamp=s["first_seen"],
                    status=s["status"],
                    occurrences=s["occurrences"]
                )
                alert.last_seen = s["last_seen"]
                self.alerts_list.append(alert)

    def set_cooldown_window(self, seconds: float):
        self.cooldown_window = max(5.0, seconds)

    def evaluate_severity(self, category: str, score: float, occurrences: int, details: dict) -> str:
        """
        Multi-factor severity determination.
        Avoids labelling an anomaly as Critical solely on high Z-score.
        """
        # 1. Port scan severity
        if category == "Port Scanning":
            ports = details.get("port_count", 0)
            if ports >= 100 or occurrences >= 5:
                return "Critical"
            elif ports >= 30:
                return "High"
            else:
                return "Medium"

        # 2. Repeated Connection Attempts / SYN Floods
        if category == "Repeated Connection Attempts":
            if occurrences >= 8:
                return "Critical"
            elif occurrences >= 3:
                return "High"
            return "Medium"

        # 3. Bandwidth / Throughput Spikes
        if category == "Bandwidth Spike":
            # Require both substantial score and sustained occurrences for Critical
            if score >= 10.0 and occurrences >= 10:
                return "Critical"
            elif score >= 6.0 or occurrences >= 4:
                return "High"
            elif score >= 3.0:
                return "Medium"
            else:
                return "Low"

        # 4. ML Anomaly (IsolationForest)
        if category == "ML Anomaly":
            if occurrences >= 5:
                return "High"
            return "Medium"

        # 5. DNS Anomalies
        if category == "DNS Anomaly":
            if "Flood" in details.get("title", "") or occurrences >= 6:
                return "High"
            return "Medium"

        # 6. Outbound traffic anomaly
        if category == "Unusual Outbound Traffic":
            if occurrences >= 5:
                return "High"
            return "Medium"

        return "Informational"

    def process_raw_alert(self, raw_alert: Dict[str, Any]):
        """
        Main entry point for detectors to submit an alert.
        Performs deduplication, occurrence tracking, severity evaluation, and database persistence.
        """
        now = time.time()
        category = raw_alert.get("category", "Traffic Anomaly")
        title = raw_alert.get("title", "Network Traffic Alert")
        src_ip = raw_alert.get("src_ip", "Unknown")
        dst_ip = raw_alert.get("dst_ip", "Unknown")
        src_port = raw_alert.get("src_port", 0)
        dst_port = raw_alert.get("dst_port", 0)
        score = float(raw_alert.get("anomaly_score", 0.0))
        method = raw_alert.get("detection_method", "Rule-Based")
        current_rate = raw_alert.get("current_rate", "Not available")
        baseline_rate = raw_alert.get("baseline_rate", "Not available")
        explanation = raw_alert.get("explanation", "")
        recommended = raw_alert.get("recommended_action", "Inspect related flows and endpoints.")
        related_conns = raw_alert.get("related_conn_ids", [])

        dedup_key = (category, src_ip, dst_ip)

        with self.lock:
            # Check if an existing grouped alert is within the cooldown window
            existing_alert = self.active_groups.get(dedup_key)
            if existing_alert and (now - existing_alert.last_seen <= self.cooldown_window):
                # Update existing grouped alert
                existing_alert.occurrences += 1
                existing_alert.last_seen = now
                existing_alert.current_rate = current_rate
                existing_alert.anomaly_score = max(existing_alert.anomaly_score, score)
                existing_alert.explanation = explanation

                # Re-evaluate multi-factor severity with new occurrences
                existing_alert.severity = self.evaluate_severity(
                    category, existing_alert.anomaly_score, existing_alert.occurrences, raw_alert
                )

                # Persist to database
                self.db.save_alert(existing_alert.to_dict())
                self.db.add_alert_occurrence(
                    existing_alert.alert_id, now, current_rate, score, raw_alert
                )

                self.alert_updated.emit(existing_alert.to_dict())
                return existing_alert.alert_id

            # Create new alert
            date_prefix = time.strftime("%Y%m%d", time.localtime(now))
            unique_suffix = str(uuid.uuid4())[:6].upper()
            alert_id = f"ALT-{date_prefix}-{unique_suffix}"

            severity = self.evaluate_severity(category, score, 1, raw_alert)

            new_alert = SecurityAlert(
                alert_id=alert_id,
                title=title,
                category=category,
                severity=severity,
                detection_method=method,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                current_rate=current_rate,
                baseline_rate=baseline_rate,
                anomaly_score=score,
                explanation=explanation,
                recommended_action=recommended,
                timestamp=now,
                occurrences=1,
                related_conn_ids=related_conns
            )

            self.active_groups[dedup_key] = new_alert
            self.alerts_list.insert(0, new_alert)

            # Persist to SQLite
            self.db.save_alert(new_alert.to_dict())
            self.db.add_alert_occurrence(new_alert.alert_id, now, current_rate, score, raw_alert)

            self.new_alert_raised.emit(new_alert.to_dict())
            return alert_id

    def update_alert_status(self, alert_id: str, new_status: str, notes: str = "") -> bool:
        """Updates alert status (New, Investigating, Resolved, False Positive) with notes."""
        with self.lock:
            for alert in self.alerts_list:
                if alert.alert_id == alert_id:
                    alert.status = new_status
                    if notes:
                        alert.notes = notes
                    self.db.update_alert_status(alert_id, new_status, notes)
                    self.alert_updated.emit(alert.to_dict())
                    return True
        return False

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for alert in self.alerts_list:
                if alert.alert_id == alert_id:
                    return alert.to_dict()
        return None

    def get_all_alerts_snapshot(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [a.to_dict() for a in self.alerts_list]

    def clear_visible_alerts(self):
        """
        Clears the in-memory display list.
        Does NOT silently delete historical records from the SQLite database.
        """
        with self.lock:
            self.active_groups.clear()
            self.alerts_list.clear()
        self.alerts_cleared.emit()
