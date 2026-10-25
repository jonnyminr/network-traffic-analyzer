import json
import csv
import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QTextEdit,
    QFileDialog, QMessageBox, QFrame, QTabWidget,
    QInputDialog, QAbstractItemView
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush, QDesktopServices
from PySide6.QtCore import QUrl
from core.incident_manager import IncidentManager
from core.alert_manager import AlertManager
from gui.ip_threat_intel_dialog import IPThreatIntelDialog


class InvestigationWidget(QWidget):
    """
    Dedicated Incident Investigation Studio allowing cybersecurity analysts
    to manage incidents, inspect chronological timelines, correlate evidence,
    and generate formal reports.
    """
    filter_connections_requested = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = IncidentManager()
        self.alert_manager = AlertManager()
        self.active_inv_id = None

        self._init_ui()
        self.refresh_investigations_list()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # Main horizontal splitter: Left (List) and Right (Investigation Workspace)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #363642; width: 4px; }")

        # -------------------------------------------------------------
        # LEFT PANE: Investigations List
        # -------------------------------------------------------------
        left_pane = QWidget()
        v_left = QVBoxLayout(left_pane)
        v_left.setContentsMargins(0, 0, 0, 0)
        v_left.setSpacing(8)

        lbl_left_title = QLabel("🛡 Case Investigations")
        lbl_left_title.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 14px;")
        v_left.addWidget(lbl_left_title)

        # Filter & New button
        h_ctrl = QHBoxLayout()
        self.cmb_filter_status = QComboBox()
        self.cmb_filter_status.addItems(["All Cases", "Open", "Investigating", "Resolved", "Closed"])
        self.cmb_filter_status.setStyleSheet("background: #25252c; color: #fff; padding: 4px; border: 1px solid #363642;")
        self.cmb_filter_status.currentTextChanged.connect(self.refresh_investigations_list)
        h_ctrl.addWidget(self.cmb_filter_status, 1)

        btn_new = QPushButton("➕ New")
        btn_new.setStyleSheet("background-color: #b71c1c; color: #fff; font-weight: bold; padding: 5px 12px; border-radius: 4px;")
        btn_new.clicked.connect(self._create_manual_investigation)
        h_ctrl.addWidget(btn_new)
        v_left.addLayout(h_ctrl)

        # Investigations Table
        self.tbl_cases = QTableWidget()
        self.tbl_cases.setColumnCount(4)
        self.tbl_cases.setHorizontalHeaderLabels(["ID", "Title", "Status", "Updated"])
        self.tbl_cases.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_cases.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_cases.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tbl_cases.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_cases.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e24;
                alternate-background-color: #25252c;
                color: #e0e0e0;
                border: 1px solid #363642;
                border-radius: 6px;
            }
            QHeaderView::section {
                background-color: #25252c;
                color: #00e5ff;
                padding: 4px;
                border: 1px solid #363642;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background-color: #2a3b5c;
                color: #ffffff;
            }
        """)
        self.tbl_cases.itemSelectionChanged.connect(self._on_case_selected)
        v_left.addWidget(self.tbl_cases, 1)
        splitter.addWidget(left_pane)

        # -------------------------------------------------------------
        # RIGHT PANE: Investigation Detail Studio
        # -------------------------------------------------------------
        right_pane = QWidget()
        v_right = QVBoxLayout(right_pane)
        v_right.setContentsMargins(0, 0, 0, 0)
        v_right.setSpacing(10)

        # Header Frame
        self.header_frame = QFrame()
        self.header_frame.setStyleSheet("""
            QFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        h_hdr = QHBoxLayout(self.header_frame)
        h_hdr.setContentsMargins(6, 6, 6, 6)

        v_htitle = QVBoxLayout()
        self.lbl_inv_id = QLabel("Select an investigation from the left or create a new one.")
        self.lbl_inv_id.setStyleSheet("color: #888898; font-size: 11px;")
        self.lbl_inv_title = QLabel("No Active Investigation")
        self.lbl_inv_title.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 16px;")
        v_htitle.addWidget(self.lbl_inv_id)
        v_htitle.addWidget(self.lbl_inv_title)
        h_hdr.addLayout(v_htitle, 1)

        # Status & Severity Changers
        v_hst = QVBoxLayout()
        h_st_row = QHBoxLayout()
        lbl_s_tag = QLabel("Status:")
        lbl_s_tag.setStyleSheet("color: #888898; font-weight: bold;")
        h_st_row.addWidget(lbl_s_tag)

        self.cmb_case_status = QComboBox()
        self.cmb_case_status.addItems(["Open", "Investigating", "Resolved", "Closed"])
        self.cmb_case_status.setStyleSheet("background: #1e1e24; color: #fff; padding: 4px; border: 1px solid #363642;")
        self.cmb_case_status.currentTextChanged.connect(self._on_status_changed_by_user)
        h_st_row.addWidget(self.cmb_case_status)
        v_hst.addLayout(h_st_row)

        self.lbl_inv_dates = QLabel("Created: -- | Updated: --")
        self.lbl_inv_dates.setStyleSheet("color: #888898; font-size: 10px;")
        v_hst.addWidget(self.lbl_inv_dates)
        h_hdr.addLayout(v_hst)

        v_right.addWidget(self.header_frame)

        # Tabs: Timeline, Correlated Evidence, Analyst Notes, Resolution
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #363642; background: #25252c; border-radius: 6px; }
            QTabBar::tab { background: #1e1e24; color: #a0a0b0; padding: 6px 14px; margin-right: 2px; }
            QTabBar::tab:selected { background: #25252c; color: #00e5ff; font-weight: bold; border-top: 2px solid #00e5ff; }
        """)

        # Tab 1: Chronological Timeline
        tab_timeline = QWidget()
        v_tm = QVBoxLayout(tab_timeline)
        v_tm.setContentsMargins(6, 6, 6, 6)
        self.tbl_timeline = QTableWidget()
        self.tbl_timeline.setColumnCount(4)
        self.tbl_timeline.setHorizontalHeaderLabels(["Timestamp", "Event Type", "Event Title / Description", "Evidence Ref"])
        self.tbl_timeline.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_timeline.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_timeline.setStyleSheet("background: #1e1e24; color: #fff; border: none;")
        v_tm.addWidget(self.tbl_timeline)
        self.tabs.addTab(tab_timeline, "📅 Chronological Timeline")

        # Tab 2: Correlated Evidence
        tab_evidence = QWidget()
        v_ev = QVBoxLayout(tab_evidence)
        v_ev.setContentsMargins(6, 6, 6, 6)

        lbl_ev_desc = QLabel("Correlated Alerts, Network Flows, and Threat Intel associated with involved hosts:")
        lbl_ev_desc.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        v_ev.addWidget(lbl_ev_desc)

        self.tbl_evidence = QTableWidget()
        self.tbl_evidence.setColumnCount(4)
        self.tbl_evidence.setHorizontalHeaderLabels(["Evidence Type", "Identifier / Ref", "Summary", "Action"])
        self.tbl_evidence.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_evidence.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_evidence.setStyleSheet("background: #1e1e24; color: #fff; border: none;")
        v_ev.addWidget(self.tbl_evidence)
        self.tabs.addTab(tab_evidence, "🔗 Correlated Evidence")

        # Tab 3: Analyst Notes & Audit
        tab_notes = QWidget()
        v_nt = QVBoxLayout(tab_notes)
        v_nt.setContentsMargins(6, 6, 6, 6)

        self.txt_audit_log = QTextEdit()
        self.txt_audit_log.setReadOnly(True)
        self.txt_audit_log.setStyleSheet("background: #1a1a20; color: #d0d0d8; font-family: monospace; border: 1px solid #363642; border-radius: 4px;")
        v_nt.addWidget(self.txt_audit_log, 1)

        h_note_input = QHBoxLayout()
        self.txt_new_note = QLineEdit()
        self.txt_new_note.setPlaceholderText("Enter new analyst observation or finding...")
        self.txt_new_note.setStyleSheet("background: #1e1e24; color: #fff; padding: 6px; border: 1px solid #363642; border-radius: 4px;")
        h_note_input.addWidget(self.txt_new_note, 1)

        btn_add_note = QPushButton("➕ Add Note")
        btn_add_note.setStyleSheet("background: #363642; color: #00e5ff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        btn_add_note.clicked.connect(self._add_analyst_note)
        h_note_input.addWidget(btn_add_note)
        v_nt.addLayout(h_note_input)

        self.tabs.addTab(tab_notes, "📝 Analyst Notes & Audit")

        # Tab 4: Resolution & Assessment
        tab_res = QWidget()
        v_res = QVBoxLayout(tab_res)
        v_res.setContentsMargins(8, 8, 8, 8)
        lbl_res_desc = QLabel("Document final findings, root cause, and remediation status:")
        lbl_res_desc.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        v_res.addWidget(lbl_res_desc)

        self.txt_resolution = QTextEdit()
        self.txt_resolution.setPlaceholderText("Enter incident root cause, remediation steps, or false-positive justification...")
        self.txt_resolution.setStyleSheet("background: #1a1a20; color: #fff; border: 1px solid #363642; border-radius: 4px;")
        v_res.addWidget(self.txt_resolution, 1)

        h_res_btn = QHBoxLayout()
        btn_save_res = QPushButton("💾 Save Resolution")
        btn_save_res.setStyleSheet("background: #2e7d32; color: #fff; font-weight: bold; padding: 6px 16px; border-radius: 4px;")
        btn_save_res.clicked.connect(self._save_resolution)
        h_res_btn.addWidget(btn_save_res)
        h_res_btn.addStretch()
        v_res.addLayout(h_res_btn)

        self.tabs.addTab(tab_res, "✅ Final Resolution")

        v_right.addWidget(self.tabs, 1)

        # Bottom Action Bar: Reports
        b_bar = QHBoxLayout()
        self.btn_export_html = QPushButton("🖨 Export HTML / Printable Report")
        self.btn_export_html.setStyleSheet("background: #1e3a5f; color: #00e5ff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_export_html.clicked.connect(self._export_html_report)
        b_bar.addWidget(self.btn_export_html)

        self.btn_export_json = QPushButton("📥 Export JSON")
        self.btn_export_json.setStyleSheet("background: #363642; color: #fff; padding: 6px 12px; border-radius: 4px;")
        self.btn_export_json.clicked.connect(self._export_json_report)
        b_bar.addWidget(self.btn_export_json)

        b_bar.addStretch()
        v_right.addLayout(b_bar)

        splitter.addWidget(right_pane)
        splitter.setSizes([280, 720])
        main_layout.addWidget(splitter, 1)

    def refresh_investigations_list(self):
        cases = self.manager.get_all_investigations()
        filter_st = self.cmb_filter_status.currentText()

        filtered = []
        for c in cases:
            if filter_st != "All Cases" and c.get("status") != filter_st:
                continue
            filtered.append(c)

        self.tbl_cases.setRowCount(len(filtered))
        self._cases_cache = filtered

        for row, c in enumerate(filtered):
            self.tbl_cases.setItem(row, 0, QTableWidgetItem(c["investigation_id"]))
            self.tbl_cases.setItem(row, 1, QTableWidgetItem(c["title"]))

            st_item = QTableWidgetItem(c["status"])
            if c["status"] == "Open":
                st_item.setForeground(QBrush(QColor("#ff5252")))
            elif c["status"] == "Investigating":
                st_item.setForeground(QBrush(QColor("#ffd600")))
            elif c["status"] == "Resolved":
                st_item.setForeground(QBrush(QColor("#00e676")))
            self.tbl_cases.setItem(row, 2, st_item)

            up_dt = datetime.datetime.fromtimestamp(c["updated_at"]).strftime("%m-%d %H:%M")
            self.tbl_cases.setItem(row, 3, QTableWidgetItem(up_dt))

        # Auto-select first if active is None
        if not self.active_inv_id and filtered:
            self.tbl_cases.selectRow(0)

    def _on_case_selected(self):
        row = self.tbl_cases.currentRow()
        if row < 0 or not hasattr(self, "_cases_cache") or row >= len(self._cases_cache):
            return
        inv_data = self._cases_cache[row]
        self.load_investigation(inv_data["investigation_id"])

    def load_investigation(self, inv_id: str):
        inv = self.manager.get_investigation(inv_id)
        if not inv:
            return
        self.active_inv_id = inv_id

        # Update Header
        self.lbl_inv_id.setText(f"Investigation Case: <b>{inv['investigation_id']}</b>")
        self.lbl_inv_title.setText(inv["title"])
        self.cmb_case_status.blockSignals(True)
        self.cmb_case_status.setCurrentText(inv["status"])
        self.cmb_case_status.blockSignals(False)

        c_dt = datetime.datetime.fromtimestamp(inv["created_at"]).strftime("%Y-%m-%d %H:%M")
        u_dt = datetime.datetime.fromtimestamp(inv["updated_at"]).strftime("%Y-%m-%d %H:%M")
        self.lbl_inv_dates.setText(f"Created: {c_dt} | Updated: {u_dt}")

        # Update Timeline Table
        timeline = inv.get("timeline", [])
        self.tbl_timeline.setRowCount(len(timeline))
        for r, t in enumerate(timeline):
            t_dt = datetime.datetime.fromtimestamp(t["timestamp"]).strftime("%H:%M:%S")
            self.tbl_timeline.setItem(r, 0, QTableWidgetItem(t_dt))
            self.tbl_timeline.setItem(r, 1, QTableWidgetItem(t["event_type"]))
            self.tbl_timeline.setItem(r, 2, QTableWidgetItem(f"{t['title']}: {t.get('description', '')}"))
            self.tbl_timeline.setItem(r, 3, QTableWidgetItem(str(t.get("evidence_ref", ""))))

        # Update Evidence Tab
        ev_items = []
        for aid in inv.get("alert_ids", []):
            alert = self.alert_manager.get_alert_by_id(aid)
            if alert:
                ev_items.append(("Alert", aid, f"{alert['title']} ({alert['severity']}) - {alert['current_rate']}"))
        for cid in inv.get("related_conn_ids", []):
            flow = self.manager.tracker.get_flow_by_id(cid)
            if flow:
                ev_items.append(("Flow", cid, f"{flow.initiator_ip} ➔ {flow.responder_ip} [{flow.protocol}] - {flow.total_bytes} bytes"))
        for ip in inv.get("involved_ips", []):
            ev_items.append(("Involved Host", ip, "Endpoint involved in detected incident"))

        self.tbl_evidence.setRowCount(len(ev_items))
        for r, (ev_type, ref, summary) in enumerate(ev_items):
            self.tbl_evidence.setItem(r, 0, QTableWidgetItem(ev_type))
            self.tbl_evidence.setItem(r, 1, QTableWidgetItem(ref))
            self.tbl_evidence.setItem(r, 2, QTableWidgetItem(summary))
            btn_act = QPushButton("Inspect")
            btn_act.setStyleSheet("background:#363642; color:#00e5ff; padding:2px 8px;")
            if ev_type == "Involved Host":
                btn_act.clicked.connect(lambda ch=False, target_ip=ref: IPThreatIntelDialog(target_ip, parent=self).exec())
            elif ev_type == "Flow":
                btn_act.clicked.connect(lambda ch=False, target_ref=ref: self.filter_connections_requested.emit(target_ref, ""))
            self.tbl_evidence.setCellWidget(r, 3, btn_act)

        # Update Notes & Resolution
        self.txt_audit_log.setText(inv.get("analyst_notes") or "No analyst notes logged yet.")
        self.txt_resolution.setText(inv.get("resolution") or "")

    def _create_manual_investigation(self):
        title, ok = QInputDialog.getText(self, "New Investigation", "Enter Investigation Case Title:")
        if ok and title.strip():
            inv = self.manager.create_investigation(title.strip())
            self.refresh_investigations_list()
            self.load_investigation(inv["investigation_id"])

    def open_investigation_from_alert(self, alert_data: dict):
        """Called when user clicks 'Launch Investigation' on an alert."""
        title = f"Investigation: {alert_data.get('title')} ({alert_data.get('alert_id')})"
        inv = self.manager.create_investigation(
            title=title,
            initial_alert=alert_data,
            severity=alert_data.get("severity", "Medium")
        )
        self.refresh_investigations_list()
        self.load_investigation(inv["investigation_id"])

    def _on_status_changed_by_user(self, new_status: str):
        if not self.active_inv_id:
            return
        self.manager.update_status(self.active_inv_id, new_status)
        self.load_investigation(self.active_inv_id)

    def _add_analyst_note(self):
        if not self.active_inv_id:
            return
        text = self.txt_new_note.text().strip()
        if text:
            self.manager.add_analyst_note(self.active_inv_id, text)
            self.txt_new_note.clear()
            self.load_investigation(self.active_inv_id)

    def _save_resolution(self):
        if not self.active_inv_id:
            return
        res = self.txt_resolution.toPlainText().strip()
        self.manager.update_status(self.active_inv_id, self.cmb_case_status.currentText(), resolution_note=res)
        QMessageBox.information(self, "Saved", "Resolution findings successfully saved to audit log.")
        self.load_investigation(self.active_inv_id)

    def _export_html_report(self):
        if not self.active_inv_id:
            return
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Printable Incident Report", f"Incident_Report_{self.active_inv_id}.html", "HTML Files (*.html)"
        )
        if filepath:
            html = self.manager.generate_html_report(self.active_inv_id)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            QMessageBox.information(self, "Report Exported", f"Successfully exported incident report to:\n{filepath}\n\nYou can open this in any browser and print to PDF.")
            QDesktopServices.openUrl(QUrl.fromLocalFile(filepath))

    def _export_json_report(self):
        if not self.active_inv_id:
            return
        inv = self.manager.get_investigation(self.active_inv_id)
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export JSON Investigation", f"Incident_{self.active_inv_id}.json", "JSON Files (*.json)"
        )
        if filepath:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(inv, f, indent=2)
            QMessageBox.information(self, "Export Complete", f"Successfully exported JSON to:\n{filepath}")
