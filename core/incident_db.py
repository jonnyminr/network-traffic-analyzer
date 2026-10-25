import sqlite3
import os
import json
import time
import threading
from typing import Dict, Any, List, Optional
from utils.logger import logger

DB_DIR = "logs"
DB_FILE = os.path.join(DB_DIR, "analyzer.db")

class IncidentDatabase:
    """
    Lightweight, thread-safe SQLite storage for alerts, alert occurrences,
    incident investigations, audit timeline, and threat intelligence cache.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = DB_FILE):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(IncidentDatabase, cls).__new__(cls)
                cls._instance._init_db(db_path)
            return cls._instance

    def _init_db(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.local = threading.local()
        self._create_schema()
        logger.info(f"Initialized incident database at {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self.local.conn = sqlite3.connect(self.db_path, timeout=10.0)
            self.local.conn.row_factory = sqlite3.Row
            # Enable WAL mode for high concurrency
            try:
                self.local.conn.execute("PRAGMA journal_mode = WAL;")
                self.local.conn.execute("PRAGMA synchronous = NORMAL;")
            except Exception:
                pass
        return self.local.conn

    def _create_schema(self):
        conn = self._get_connection()
        with conn:
            # 1. Alerts Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detection_method TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    current_rate TEXT,
                    baseline_rate TEXT,
                    anomaly_score REAL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'New',
                    explanation TEXT,
                    recommended_action TEXT,
                    raw_json TEXT
                );
            """)

            # 2. Alert Occurrences Table (for deduplicated historical occurrences)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_occurrences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    current_rate TEXT,
                    anomaly_score REAL,
                    detail_json TEXT,
                    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
                );
            """)

            # 3. Investigations Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    severity TEXT NOT NULL DEFAULT 'Medium',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    description TEXT,
                    resolution TEXT,
                    analyst_notes TEXT,
                    alert_ids_json TEXT,
                    involved_ips_json TEXT,
                    related_conn_ids_json TEXT
                );
            """)

            # 4. Investigation Timeline Events Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS investigation_timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence_ref TEXT,
                    FOREIGN KEY(investigation_id) REFERENCES investigations(investigation_id) ON DELETE CASCADE
                );
            """)

            # 5. Threat Intelligence Cache Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    ip TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    score REAL,
                    is_malicious INTEGER DEFAULT 0,
                    data_json TEXT,
                    cached_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
            """)

            # 6. Persistent Settings Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                );
            """)

            # Indexes for fast querying
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_occurrences_alert ON alert_occurrences(alert_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_inv ON investigation_timeline(investigation_id);")

    # -------------------------------------------------------------
    # Alerts Operations
    # -------------------------------------------------------------
    def save_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Inserts or updates an alert record."""
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO alerts (
                        alert_id, title, category, severity, detection_method,
                        src_ip, dst_ip, src_port, dst_port, current_rate,
                        baseline_rate, anomaly_score, first_seen, last_seen,
                        occurrences, status, explanation, recommended_action, raw_json
                    ) VALUES (
                        :alert_id, :title, :category, :severity, :detection_method,
                        :src_ip, :dst_ip, :src_port, :dst_port, :current_rate,
                        :baseline_rate, :anomaly_score, :first_seen, :last_seen,
                        :occurrences, :status, :explanation, :recommended_action, :raw_json
                    )
                    ON CONFLICT(alert_id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        occurrences = excluded.occurrences,
                        current_rate = excluded.current_rate,
                        anomaly_score = excluded.anomaly_score,
                        explanation = excluded.explanation,
                        raw_json = excluded.raw_json;
                """, alert_data)
            return True
        except Exception as e:
            logger.error(f"Failed to save alert {alert_data.get('alert_id')}: {e}")
            return False

    def add_alert_occurrence(self, alert_id: str, timestamp: float, current_rate: str = "", anomaly_score: float = None, detail: dict = None):
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO alert_occurrences (alert_id, timestamp, current_rate, anomaly_score, detail_json)
                    VALUES (?, ?, ?, ?, ?)
                """, (alert_id, timestamp, current_rate, anomaly_score, json.dumps(detail or {})))
        except Exception as e:
            logger.error(f"Failed to record occurrence for alert {alert_id}: {e}")

    def get_alert_occurrences(self, alert_id: str) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM alert_occurrences WHERE alert_id = ? ORDER BY timestamp DESC", (alert_id,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load occurrences for {alert_id}: {e}")
            return []

    def update_alert_status(self, alert_id: str, new_status: str, notes: str = "") -> bool:
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
            return True
        except Exception as e:
            logger.error(f"Failed to update alert status {alert_id}: {e}")
            return False

    def get_all_alerts(self, limit: int = 500) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,))
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []

    # -------------------------------------------------------------
    # Investigation Operations
    # -------------------------------------------------------------
    def save_investigation(self, inv_data: Dict[str, Any]) -> bool:
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO investigations (
                        investigation_id, title, status, severity, created_at, updated_at,
                        description, resolution, analyst_notes, alert_ids_json,
                        involved_ips_json, related_conn_ids_json
                    ) VALUES (
                        :investigation_id, :title, :status, :severity, :created_at, :updated_at,
                        :description, :resolution, :analyst_notes, :alert_ids_json,
                        :involved_ips_json, :related_conn_ids_json
                    )
                    ON CONFLICT(investigation_id) DO UPDATE SET
                        title = excluded.title,
                        status = excluded.status,
                        severity = excluded.severity,
                        updated_at = excluded.updated_at,
                        description = excluded.description,
                        resolution = excluded.resolution,
                        analyst_notes = excluded.analyst_notes,
                        alert_ids_json = excluded.alert_ids_json,
                        involved_ips_json = excluded.involved_ips_json,
                        related_conn_ids_json = excluded.related_conn_ids_json;
                """, inv_data)
            return True
        except Exception as e:
            logger.error(f"Failed to save investigation {inv_data.get('investigation_id')}: {e}")
            return False

    def add_timeline_event(self, inv_id: str, timestamp: float, event_type: str, title: str, description: str = "", evidence_ref: str = ""):
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO investigation_timeline (investigation_id, timestamp, event_type, title, description, evidence_ref)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (inv_id, timestamp, event_type, title, description, evidence_ref))
        except Exception as e:
            logger.error(f"Failed to add timeline event for {inv_id}: {e}")

    def get_investigation(self, inv_id: str) -> Optional[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM investigations WHERE investigation_id = ?", (inv_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to fetch investigation {inv_id}: {e}")
            return None

    def get_all_investigations(self) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM investigations ORDER BY updated_at DESC")
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to fetch investigations: {e}")
            return []

    def get_investigation_timeline(self, inv_id: str) -> List[Dict[str, Any]]:
        try:
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM investigation_timeline WHERE investigation_id = ? ORDER BY timestamp ASC", (inv_id,))
            return [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to fetch timeline for {inv_id}: {e}")
            return []

    # -------------------------------------------------------------
    # Threat Intelligence Cache Operations
    # -------------------------------------------------------------
    def get_cached_threat_intel(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            now = time.time()
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM threat_intel_cache WHERE ip = ? AND expires_at > ?", (ip, now))
            row = cursor.fetchone()
            if row:
                res = dict(row)
                res['data'] = json.loads(res.get('data_json') or '{}')
                return res
        except Exception as e:
            logger.error(f"Cache lookup failed for IP {ip}: {e}")
        return None

    def save_threat_intel_cache(self, ip: str, provider: str, score: float, is_malicious: bool, data: dict, ttl_seconds: int = 86400):
        try:
            now = time.time()
            expires_at = now + ttl_seconds
            conn = self._get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO threat_intel_cache (ip, provider, score, is_malicious, data_json, cached_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        provider = excluded.provider,
                        score = excluded.score,
                        is_malicious = excluded.is_malicious,
                        data_json = excluded.data_json,
                        cached_at = excluded.cached_at,
                        expires_at = excluded.expires_at;
                """, (ip, provider, score, 1 if is_malicious else 0, json.dumps(data), now, expires_at))
        except Exception as e:
            logger.error(f"Failed to cache threat intel for {ip}: {e}")

    # -------------------------------------------------------------
    # Settings Operations
    # -------------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        try:
            conn = self._get_connection()
            cursor = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return json.loads(row['value_json'])
        except Exception:
            pass
        return default

    def set_setting(self, key: str, value: Any):
        try:
            conn = self._get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO settings (key, value_json) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json;
                """, (key, json.dumps(value)))
        except Exception as e:
            logger.error(f"Failed to persist setting {key}: {e}")
