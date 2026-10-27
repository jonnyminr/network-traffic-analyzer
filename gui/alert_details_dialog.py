import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGroupBox, QGridLayout, QTextBrowser, QTableWidget,
    QTableWidgetItem, QHeaderView, QComboBox, QLineEdit,
    QMessageBox, QFrame, QAbstractItemView
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush
from core.alert_manager import AlertManager
from core.incident_db import IncidentDatabase
from gui.ip_threat_intel_dialog import IPThreatIntelDialog


class AlertDetailsDialog(QDialog):
    """
    Evidence-based Alert Investigation Dialog showing full incident breakdown,
    baselines, historical occurrences, and workflow actions.
    """
    launch_investigation_requested = Signal(dict) # Passes alert dict to open in Investigations tab
    filter_connections_requested = Signal(str, str) # src_ip, dst_ip
    inspect_packets_requested = Signal(str) # IP address to search in packet inspector

    def __init__(self, alert_data: dict, parent=None):
        super().__init__(parent)
        self.alert_data = alert_data
        self.manager = AlertManager()
        self.db = IncidentDatabase()

        self.setWindowTitle(f"Security Alert Details — {alert_data.get('alert_id', 'Unknown')}")
        self.resize(820, 680)
        self.setMinimumSize(740, 580)

        self._init_ui()
        self._load_occurrences()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(16, 16, 16, 16)

        # 1. Header Banner
        header_frame = QFrame()
        header_frame.setObjectName("HeaderFrame")
        sev = self.alert_data.get("severity", "Medium")
        sev_color = {
            "Critical": "#ff5252",
            "High": "#ff9100",
            "Medium": "#ffd600",
            "Low": "#42a5f5",
            "Informational": "#00e5ff"
        }.get(sev, "#00e5ff")

        header_frame.setStyleSheet(f"""
            QFrame#HeaderFrame {{
                background-color: #25252c;
                border-left: 4px solid {sev_color};
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        h_box = QHBoxLayout(header_frame)
        h_box.setContentsMargins(6, 6, 6, 6)

        v_titles = QVBoxLayout()
        lbl_id = QLabel(f"<span style='color:#888898; font-size:11px;'>Incident ID:</span> <b>{self.alert_data.get('alert_id')}</b>")
        lbl_id.setTextFormat(Qt.RichText)
        lbl_title = QLabel(f"<b style='font-size:16px; color:#ffffff;'>{self.alert_data.get('title')}</b>")
        lbl_title.setTextFormat(Qt.RichText)
        v_titles.addWidget(lbl_id)
        v_titles.addWidget(lbl_title)
        h_box.addLayout(v_titles, 1)

        # Severity & Occurrence Badges
        v_badges = QVBoxLayout()
        v_badges.setAlignment(Qt.AlignRight)
        lbl_sev = QLabel(f" {sev.upper()} ")
        lbl_sev.setStyleSheet(f"background-color: {sev_color}; color: #000; font-weight: bold; font-size: 11px; border-radius: 3px; padding: 2px 6px;")
        
        occ = self.alert_data.get("occurrences", 1)
        lbl_occ = QLabel(f"Occurrences: <b>x{occ}</b>")
        lbl_occ.setStyleSheet("color: #00e5ff; font-size: 12px;")
        v_badges.addWidget(lbl_sev)
        v_badges.addWidget(lbl_occ)
        h_box.addLayout(v_badges)

        main_layout.addWidget(header_frame)

        # 2. Evidence & Metric Breakdown Grid
        grid_group = QGroupBox("Detection Evidence && Baseline Comparison")
        grid_group.setStyleSheet("QGroupBox { background-color: #25252c; border: 1px solid #363642; border-radius: 6px; font-weight: bold; color: #00e5ff; }")
        grid = QGridLayout(grid_group)
        grid.setSpacing(8)
        grid.setContentsMargins(12, 14, 12, 10)

        def _k(name):
            l = QLabel(name)
            l.setStyleSheet("color: #888898; font-weight: bold;")
            return l

        first_seen_str = datetime.datetime.fromtimestamp(self.alert_data.get("first_seen", 0)).strftime("%Y-%m-%d %H:%M:%S")
        last_seen_str = datetime.datetime.fromtimestamp(self.alert_data.get("last_seen", 0)).strftime("%H:%M:%S")

        grid.addWidget(_k("Detection Method:"), 0, 0)
        grid.addWidget(QLabel(f"<b>{self.alert_data.get('detection_method', 'Rule-Based')}</b>"), 0, 1)
        grid.addWidget(_k("Category:"), 0, 2)
        grid.addWidget(QLabel(f"<b>{self.alert_data.get('category')}</b>"), 0, 3)

        grid.addWidget(_k("Current Measurement:"), 1, 0)
        lbl_cur = QLabel(f"<span style='color:#ff5252; font-weight:bold;'>{self.alert_data.get('current_rate')}</span>")
        grid.addWidget(lbl_cur, 1, 1)
        grid.addWidget(_k("Baseline Normal:"), 1, 2)
        lbl_base = QLabel(f"<span style='color:#00e676;'>{self.alert_data.get('baseline_rate')}</span>")
        grid.addWidget(lbl_base, 1, 3)

        grid.addWidget(_k("Endpoints:"), 2, 0)
        src_ep = f"{self.alert_data.get('src_ip', 'Unknown')}:{self.alert_data.get('src_port', 0)}"
        dst_ep = f"{self.alert_data.get('dst_ip', 'Unknown')}:{self.alert_data.get('dst_port', 0)}"
        grid.addWidget(QLabel(f"{src_ep} ➔ {dst_ep}"), 2, 1)
        grid.addWidget(_k("Anomaly Score:"), 2, 2)
        grid.addWidget(QLabel(f"<b>{self.alert_data.get('anomaly_score', 0.0)}</b>"), 2, 3)

        grid.addWidget(_k("Time Window:"), 3, 0)
        grid.addWidget(QLabel(f"First: {first_seen_str} | Last: {last_seen_str}"), 3, 1, 1, 3)

        main_layout.addWidget(grid_group)

        # 3. Explanation & Recommended Investigation Steps
        info_group = QGroupBox("Incident Context && Guidance")
        info_group.setStyleSheet("QGroupBox { background-color: #25252c; border: 1px solid #363642; border-radius: 6px; font-weight: bold; color: #00e5ff; }")
        v_info = QVBoxLayout(info_group)
        v_info.setSpacing(6)
        v_info.setContentsMargins(10, 12, 10, 10)

        lbl_exp = QLabel(f"<b>What Happened:</b> {self.alert_data.get('explanation')}")
        lbl_exp.setWordWrap(True)
        lbl_exp.setStyleSheet("color: #e0e0e0; font-size: 12px;")
        v_info.addWidget(lbl_exp)

        lbl_rec = QLabel(f"<b>Recommended Action:</b> <span style='color:#ffd600;'>{self.alert_data.get('recommended_action')}</span>")
        lbl_rec.setWordWrap(True)
        lbl_rec.setStyleSheet("font-size: 12px;")
        v_info.addWidget(lbl_rec)

        main_layout.addWidget(info_group)

        # 4. Grouped Historical Occurrences
        occ_group = QGroupBox("Deduplicated Occurrences Timeline")
        occ_group.setStyleSheet("QGroupBox { background-color: #25252c; border: 1px solid #363642; border-radius: 6px; font-weight: bold; color: #00e5ff; }")
        v_occ = QVBoxLayout(occ_group)
        v_occ.setContentsMargins(6, 12, 6, 6)

        self.tbl_occ = QTableWidget()
        self.tbl_occ.setColumnCount(4)
        self.tbl_occ.setHorizontalHeaderLabels(["Timestamp", "Measured Rate", "Score", "Notes / Detail"])
        self.tbl_occ.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.tbl_occ.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_occ.setStyleSheet("background: #1e1e24; color: #fff; border: none;")
        self.tbl_occ.setFixedHeight(110)
        v_occ.addWidget(self.tbl_occ)

        main_layout.addWidget(occ_group)

        # 5. Analyst Status & Notes Bar
        status_frame = QFrame()
        status_frame.setStyleSheet("background: #1e1e24; border: 1px solid #363642; border-radius: 6px; padding: 6px;")
        h_st = QHBoxLayout(status_frame)
        h_st.setContentsMargins(4, 4, 4, 4)

        lbl_st = QLabel("Incident Status:")
        lbl_st.setStyleSheet("color: #888898; font-weight: bold;")
        h_st.addWidget(lbl_st)

        self.cmb_status = QComboBox()
        self.cmb_status.addItems(["New", "Investigating", "Resolved", "False Positive"])
        self.cmb_status.setCurrentText(self.alert_data.get("status", "New"))
        self.cmb_status.setStyleSheet("background: #25252c; color: #fff; padding: 4px; border: 1px solid #363642;")
        h_st.addWidget(self.cmb_status)

        self.txt_notes = QLineEdit()
        self.txt_notes.setPlaceholderText("Analyst justification or reason (required for False Positive / Resolved)...")
        self.txt_notes.setStyleSheet("background: #25252c; color: #fff; padding: 4px 8px; border: 1px solid #363642; border-radius: 4px;")
        h_st.addWidget(self.txt_notes, 2)

        btn_save_st = QPushButton("💾 Update Status")
        btn_save_st.setStyleSheet("background: #363642; color: #00e5ff; font-weight: bold; padding: 5px 12px; border-radius: 4px;")
        btn_save_st.clicked.connect(self._save_status_update)
        h_st.addWidget(btn_save_st)

        main_layout.addWidget(status_frame)

        # 6. Bottom Action Controls
        bottom_layout = QHBoxLayout()
        
        btn_threat = QPushButton("🛡 Check Threat Intel")
        btn_threat.setStyleSheet("background: #363642; color: #fff; padding: 6px 12px; border-radius: 4px;")
        btn_threat.clicked.connect(self._open_threat_intel)
        bottom_layout.addWidget(btn_threat)

        btn_conns = QPushButton("🔗 View Related Flows")
        btn_conns.setStyleSheet("background: #363642; color: #fff; padding: 6px 12px; border-radius: 4px;")
        btn_conns.clicked.connect(self._filter_connections)
        bottom_layout.addWidget(btn_conns)

        btn_pkts = QPushButton("📦 View Related Packets")
        btn_pkts.setStyleSheet("background: #363642; color: #fff; padding: 6px 12px; border-radius: 4px;")
        btn_pkts.clicked.connect(self._inspect_related_packets)
        bottom_layout.addWidget(btn_pkts)

        btn_export = QPushButton("📥 Export Evidence JSON")
        btn_export.setStyleSheet("background: #363642; color: #00e5ff; padding: 6px 12px; border-radius: 4px;")
        btn_export.clicked.connect(self._export_evidence_json)
        bottom_layout.addWidget(btn_export)

        bottom_layout.addStretch()

        btn_investigate = QPushButton("🚀 Formal Investigation")
        btn_investigate.setStyleSheet("background-color: #b71c1c; color: white; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        btn_investigate.clicked.connect(self._launch_investigation)
        bottom_layout.addWidget(btn_investigate)

        btn_close = QPushButton("Close")
        btn_close.setStyleSheet("background-color: #2e7d32; color: white; padding: 6px 14px; border-radius: 4px;")
        btn_close.clicked.connect(self.accept)
        bottom_layout.addWidget(btn_close)

        main_layout.addLayout(bottom_layout)

    def _load_occurrences(self):
        alert_id = self.alert_data.get("alert_id")
        occurrences = self.db.get_alert_occurrences(alert_id)
        if not occurrences:
            self.tbl_occ.setRowCount(1)
            dt = datetime.datetime.fromtimestamp(self.alert_data.get("first_seen", 0)).strftime("%H:%M:%S")
            self.tbl_occ.setItem(0, 0, QTableWidgetItem(dt))
            self.tbl_occ.setItem(0, 1, QTableWidgetItem(str(self.alert_data.get("current_rate"))))
            self.tbl_occ.setItem(0, 2, QTableWidgetItem(str(self.alert_data.get("anomaly_score"))))
            self.tbl_occ.setItem(0, 3, QTableWidgetItem("Initial detection"))
            return

        self.tbl_occ.setRowCount(len(occurrences))
        for row, occ in enumerate(occurrences):
            dt = datetime.datetime.fromtimestamp(occ.get("timestamp", 0)).strftime("%H:%M:%S")
            self.tbl_occ.setItem(row, 0, QTableWidgetItem(dt))
            self.tbl_occ.setItem(row, 1, QTableWidgetItem(str(occ.get("current_rate") or "-")))
            self.tbl_occ.setItem(row, 2, QTableWidgetItem(str(occ.get("anomaly_score") or "-")))
            self.tbl_occ.setItem(row, 3, QTableWidgetItem(f"Occurrence #{len(occurrences) - row}"))

    def _save_status_update(self):
        new_status = self.cmb_status.currentText()
        notes = self.txt_notes.text().strip()
        alert_id = self.alert_data.get("alert_id")

        if new_status == "False Positive":
            success = self.manager.mark_false_positive(alert_id, notes)
        else:
            success = self.manager.update_alert_status(alert_id, new_status, notes)

        if success:
            self.alert_data["status"] = new_status
            QMessageBox.information(self, "Status Updated", f"Alert {alert_id} status updated to '{new_status}'.")
        else:
            QMessageBox.warning(self, "Update Failed", "Failed to update alert status.")

    def _open_threat_intel(self):
        src_ip = self.alert_data.get("src_ip", "Unknown")
        if src_ip and src_ip not in ("Unknown", "Multiple"):
            dlg = IPThreatIntelDialog(src_ip, parent=self)
            dlg.exec()
        else:
            QMessageBox.information(self, "No IP Available", "No specific source IP address is attached to this alert.")

    def _filter_connections(self):
        src = self.alert_data.get("src_ip", "")
        dst = self.alert_data.get("dst_ip", "")
        self.filter_connections_requested.emit(src, dst)
        self.accept()

    def _inspect_related_packets(self):
        src = self.alert_data.get("src_ip", "")
        dst = self.alert_data.get("dst_ip", "")
        target = src if src and src not in ("Unknown", "Multiple") else dst
        if target:
            self.inspect_packets_requested.emit(target)
            self.accept()
        else:
            QMessageBox.information(self, "No Target IP", "No specific IP address available to filter packets.")

    def _export_evidence_json(self):
        from PySide6.QtWidgets import QFileDialog
        import json
        alert_id = self.alert_data.get("alert_id", "alert")
        evidence = self.manager.get_alert_evidence(alert_id)
        path, _ = QFileDialog.getSaveFileName(self, "Save Alert Evidence", f"{alert_id}_evidence.json", "JSON Files (*.json)")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(evidence, f, indent=2)
                QMessageBox.information(self, "Saved", f"Saved evidence to:\n{path}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to save JSON: {e}")

    def _launch_investigation(self):
        self.launch_investigation_requested.emit(self.alert_data)
        self.accept()
