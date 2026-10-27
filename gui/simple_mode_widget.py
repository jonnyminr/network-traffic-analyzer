import time
from typing import Dict, Any, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QScrollArea
)
from PySide6.QtCore import Qt, Signal
from core.alert_manager import AlertManager
from core.connection_tracker import ConnectionTracker
from core.incident_db import IncidentDatabase
from gui.tooltips_helper import get_tooltip


def format_bytes_human(n: float) -> str:
    if n is None or n < 0:
        n = 0.0
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


class SimpleModeWidget(QWidget):
    """
    Beginner-friendly Simple Mode dashboard.
    Translates complex cybersecurity and packet analysis metrics into
    plain-English explanations, friendly connection categories, and actionable guidance.
    """
    switch_to_advanced_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.alert_manager = AlertManager()
        self.tracker = ConnectionTracker()
        self.db = IncidentDatabase()

        self.last_bytes_per_sec = 0.0
        self.total_bytes = 0
        self.total_packets = 0

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(12)

        # 1. Welcome / Simple Mode Banner
        banner = QFrame()
        banner.setStyleSheet("""
            QFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-left: 4px solid #00e5ff;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        h_ban = QHBoxLayout(banner)
        h_ban.setContentsMargins(6, 6, 6, 6)

        v_btxt = QVBoxLayout()
        lbl_b1 = QLabel("🌟 Simple Network Monitor")
        lbl_b1.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 16px;")
        lbl_b2 = QLabel("Easy-to-understand view of your network traffic, internet connection, and unusual activity.")
        lbl_b2.setStyleSheet("color: #a0a0b0; font-size: 12px;")
        v_btxt.addWidget(lbl_b1)
        v_btxt.addWidget(lbl_b2)
        h_ban.addLayout(v_btxt, 1)

        btn_adv = QPushButton("Switch to Advanced Mode ➔")
        btn_adv.setStyleSheet("background-color: #363642; color: #00e5ff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        btn_adv.clicked.connect(self.switch_to_advanced_requested.emit)
        h_ban.addWidget(btn_adv)

        main_layout.addWidget(banner)

        # 2. Key Status Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        # Card 1: Internet Health
        self.card_health = self._create_card(
            "🌐 Internet Health",
            "Online & Healthy",
            "Checking status...",
            "#00e676"
        )
        # Card 2: Traffic Usage
        self.card_traffic = self._create_card(
            "📊 Traffic Activity",
            "Idle",
            "0 B total transferred",
            "#00e5ff"
        )
        # Card 3: Security Status
        self.card_security = self._create_card(
            "🛡 Security Activity",
            "Normal",
            "No unusual activity detected",
            "#00e676"
        )

        cards_layout.addWidget(self.card_health)
        cards_layout.addWidget(self.card_traffic)
        cards_layout.addWidget(self.card_security)
        main_layout.addLayout(cards_layout)

        # 3. Middle Section: Friendly Unusual Activity & Guidance
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(10)

        # Left: Unusual Activity in Plain English
        activity_frame = QFrame()
        activity_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 8px; padding: 10px;")
        v_act = QVBoxLayout(activity_frame)
        v_act.setSpacing(8)

        lbl_act_t = QLabel("🔍 Unusual Network Activity")
        lbl_act_t.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 13px;")
        v_act.addWidget(lbl_act_t)

        self.lbl_activity_desc = QLabel(
            "Your network traffic is currently behaving within normal expected parameters."
        )
        self.lbl_activity_desc.setWordWrap(True)
        self.lbl_activity_desc.setStyleSheet("color: #e0e0e0; font-size: 12px; line-height: 1.4;")
        v_act.addWidget(self.lbl_activity_desc)

        self.recent_alerts_table = QTableWidget()
        self.recent_alerts_table.setColumnCount(3)
        self.recent_alerts_table.setHorizontalHeaderLabels(["Time", "What Happened", "Level"])
        self.recent_alerts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.recent_alerts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.recent_alerts_table.setStyleSheet("background: #1e1e24; color: #fff; border: 1px solid #363642;")
        self.recent_alerts_table.setFixedHeight(140)
        v_act.addWidget(self.recent_alerts_table)

        mid_layout.addWidget(activity_frame, 3)

        # Right: Recommended Next Steps
        rec_frame = QFrame()
        rec_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 8px; padding: 10px;")
        v_rec = QVBoxLayout(rec_frame)
        v_rec.setSpacing(8)

        lbl_rec_t = QLabel("💡 Recommended Next Steps")
        lbl_rec_t.setStyleSheet("color: #ffd600; font-weight: bold; font-size: 13px;")
        v_rec.addWidget(lbl_rec_t)

        self.lbl_recommendation = QLabel(
            "• Keep browsing normally. Your network is active and stable.\n\n"
            "• If you experience internet slowdowns, run the Network Health check.\n\n"
            "• To see raw packet bytes and cybersecurity details, switch to Advanced Mode."
        )
        self.lbl_recommendation.setWordWrap(True)
        self.lbl_recommendation.setStyleSheet("color: #d4d4d4; font-size: 12px; line-height: 1.5;")
        v_rec.addWidget(self.lbl_recommendation)
        v_rec.addStretch()

        mid_layout.addWidget(rec_frame, 2)
        main_layout.addLayout(mid_layout)

        # 4. Bottom Section: Simplified Network Connections
        conn_frame = QFrame()
        conn_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 8px; padding: 10px;")
        v_conn = QVBoxLayout(conn_frame)
        v_conn.setSpacing(8)

        lbl_conn_t = QLabel("🔗 What Your Computer Is Connecting To")
        lbl_conn_t.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 13px;")
        v_conn.addWidget(lbl_conn_t)

        self.tbl_friendly_conns = QTableWidget()
        self.tbl_friendly_conns.setColumnCount(4)
        self.tbl_friendly_conns.setHorizontalHeaderLabels([
            "Connection Type", "Remote Address", "Volume Transferred", "Status"
        ])
        self.tbl_friendly_conns.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_friendly_conns.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_friendly_conns.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_friendly_conns.setStyleSheet("background: #1e1e24; color: #fff; border: 1px solid #363642;")
        v_conn.addWidget(self.tbl_friendly_conns)

        main_layout.addWidget(conn_frame, 1)

    def _create_card(self, title: str, val: str, sub: str, color: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: #25252c;
                border: 1px solid #363642;
                border-left: 4px solid {color};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        v = QVBoxLayout(frame)
        v.setContentsMargins(4, 4, 4, 4)
        v.setSpacing(3)
        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("color: #888898; font-size: 11px; font-weight: bold;")
        lbl_v = QLabel(val)
        lbl_v.setObjectName("CardVal")
        lbl_v.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
        lbl_s = QLabel(sub)
        lbl_s.setObjectName("CardSub")
        lbl_s.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        v.addWidget(lbl_t)
        v.addWidget(lbl_v)
        v.addWidget(lbl_s)
        return frame

    def update_stats(self, stats: dict):
        bps = stats.get('bytes_per_sec', 0.0)
        total_b = stats.get('total_bytes', 0)
        self.last_bytes_per_sec = bps
        self.total_bytes = total_b

        # Traffic activity level in plain terms
        if bps > 2000000: # > 2 MB/s
            status_desc = "High Data Usage"
            color = "#ff9100"
            sub = f"{format_bytes_human(bps)}/s (streaming/large download)"
        elif bps > 300000: # > 300 KB/s
            status_desc = "Moderate Browsing"
            color = "#00e5ff"
            sub = f"{format_bytes_human(bps)}/s (web browsing or music)"
        elif bps > 5000:
            status_desc = "Light Activity"
            color = "#00e676"
            sub = f"{format_bytes_human(bps)}/s (background traffic)"
        else:
            status_desc = "Idle / Quiet"
            color = "#8e8e9f"
            sub = f"{format_bytes_human(total_b)} total session"

        val_lbl = self.card_traffic.findChild(QLabel, "CardVal")
        sub_lbl = self.card_traffic.findChild(QLabel, "CardSub")
        if val_lbl and sub_lbl:
            val_lbl.setText(status_desc)
            val_lbl.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
            sub_lbl.setText(sub)

        # Refresh friendly connections and alerts
        self._refresh_friendly_views()

    def _refresh_friendly_views(self):
        # 1. Update Unusual Activity from Alerts
        alerts = self.alert_manager.get_all_alerts_snapshot()
        if not alerts:
            self.lbl_activity_desc.setText(
                "✅ <b>All clear:</b> Traffic usage matches normal patterns. No unusual network activity detected."
            )
            val_s = self.card_security.findChild(QLabel, "CardVal")
            sub_s = self.card_security.findChild(QLabel, "CardSub")
            if val_s and sub_s:
                val_s.setText("Normal")
                val_s.setStyleSheet("color: #00e676; font-size: 18px; font-weight: bold;")
                sub_s.setText("No unusual activity detected")
            self.recent_alerts_table.setRowCount(0)
        else:
            recent_alert = alerts[0]
            # Translate technical terms into beginner-friendly explanation
            plain_explanation = self._translate_to_plain_english(recent_alert)
            self.lbl_activity_desc.setText(plain_explanation)

            val_s = self.card_security.findChild(QLabel, "CardVal")
            sub_s = self.card_security.findChild(QLabel, "CardSub")
            if val_s and sub_s:
                val_s.setText("Alert Detected")
                val_s.setStyleSheet("color: #ffd600; font-size: 18px; font-weight: bold;")
                sub_s.setText(f"{len(alerts)} events recorded")

            # Fill recent alerts table (up to 5)
            self.recent_alerts_table.setRowCount(min(5, len(alerts)))
            for row, a in enumerate(alerts[:5]):
                t_str = time.strftime("%H:%M:%S", time.localtime(a.get("last_seen", 0)))
                self.recent_alerts_table.setItem(row, 0, QTableWidgetItem(t_str))
                
                # Friendly title
                friendly_t = self._friendly_title(a.get("category", ""), a.get("title", ""))
                self.recent_alerts_table.setItem(row, 1, QTableWidgetItem(friendly_t))
                
                sev = a.get("severity", "Medium")
                self.recent_alerts_table.setItem(row, 2, QTableWidgetItem(sev))

        # 2. Update Friendly Connections Table
        flows = self.tracker.get_all_flows_snapshot()
        self.tbl_friendly_conns.setRowCount(min(15, len(flows)))
        for row, f in enumerate(flows[:15]):
            dst_port = f.get("dst_port", 0)
            proto = f.get("protocol", "TCP")
            bytes_str = format_bytes_human(f.get("total_bytes", 0))

            # Classify into user-friendly bucket
            if dst_port in (80, 443, 8080):
                c_type = "🌐 Web Browsing / Secure Website"
            elif dst_port == 53 or proto == "UDP":
                c_type = "🔍 DNS / Domain Lookup"
            elif f.get("dst_scope") == "Private LAN":
                c_type = "🏠 Local Network / Router"
            else:
                c_type = "☁️ Background Cloud Service"

            self.tbl_friendly_conns.setItem(row, 0, QTableWidgetItem(c_type))
            self.tbl_friendly_conns.setItem(row, 1, QTableWidgetItem(str(f.get("dst_ip"))))
            self.tbl_friendly_conns.setItem(row, 2, QTableWidgetItem(bytes_str))
            
            st = "Active" if f.get("tcp_state") in ("ESTABLISHED", "ACTIVE") else "Closed / Idle"
            self.tbl_friendly_conns.setItem(row, 3, QTableWidgetItem(st))

    def _translate_to_plain_english(self, alert: dict) -> str:
        cat = alert.get("category", "")
        if cat == "ML Anomaly" or "IsolationForest" in alert.get("detection_method", ""):
            return (
                "⚠️ <b>Unusual network activity detected.</b> Some traffic patterns differ from "
                "your computer's normal behavior. This is not necessarily an attack, but indicates "
                "an unexpected combination of traffic frequency and data volume."
            )
        elif cat == "Bandwidth Spike":
            return (
                f"📈 <b>Sudden traffic surge detected:</b> Your computer downloaded or uploaded "
                f"data much faster than its established baseline ({alert.get('current_rate')}). "
                f"A background application or video stream may have started."
            )
        elif cat == "Port Scanning":
            return (
                f"🚪 <b>Network scan detected:</b> A device ({alert.get('src_ip')}) is attempting to "
                f"check multiple connection doors on the network. Check your firewall settings."
            )
        elif cat == "Repeated Connection Attempts":
            return (
                "🔄 <b>Repeated connection retries:</b> A program is repeatedly trying to reach a "
                "remote server that is currently not responding."
            )
        else:
            return f"⚠️ <b>Notice:</b> {alert.get('explanation') or 'An anomaly was detected in current network traffic.'}"

    def _friendly_title(self, cat: str, raw_title: str) -> str:
        if cat == "ML Anomaly":
            return "Unusual Traffic Pattern"
        elif cat == "Bandwidth Spike":
            return "High Data Surge"
        elif cat == "Port Scanning":
            return "Multiple Port Probes"
        elif cat == "Repeated Connection Attempts":
            return "Failed Connection Retries"
        return raw_title
