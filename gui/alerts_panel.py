import csv
import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QMessageBox, QFileDialog, QAbstractItemView,
    QMenu
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush
from core.alert_manager import AlertManager
from gui.alert_details_dialog import AlertDetailsDialog
from gui.ip_threat_intel_dialog import IPThreatIntelDialog


class AlertsPanel(QWidget):
    """
    Dedicated Security Alerts panel with intelligent deduplication,
    evidence-based incident details, status workflows, and export capabilities.
    """
    launch_investigation_requested = Signal(dict)
    filter_connections_requested = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = AlertManager()

        self._init_ui()
        self._connect_signals()
        self.refresh_table()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # 1. Top Summary Banner
        banner_frame = QFrame()
        banner_frame.setStyleSheet("""
            QFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        b_layout = QHBoxLayout(banner_frame)
        b_layout.setContentsMargins(6, 6, 6, 6)

        v_head = QVBoxLayout()
        lbl_head = QLabel("🛡 Security Incidents & Anomaly Alerts")
        lbl_head.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 16px;")
        lbl_sub = QLabel("Intelligent evidence-based incident tracking, grouping, and deduplication.")
        lbl_sub.setStyleSheet("color: #888898; font-size: 11px;")
        v_head.addWidget(lbl_head)
        v_head.addWidget(lbl_sub)
        b_layout.addLayout(v_head, 1)

        # Quick Metric Cards
        self.card_total = self._create_card("Total Active", "0", "#00e5ff")
        self.card_crit = self._create_card("Critical/High", "0", "#ff5252")
        self.card_investigating = self._create_card("Investigating", "0", "#ffd600")

        b_layout.addWidget(self.card_total)
        b_layout.addWidget(self.card_crit)
        b_layout.addWidget(self.card_investigating)

        main_layout.addWidget(banner_frame)

        # 2. Filter Bar
        filter_frame = QFrame()
        filter_frame.setObjectName("FilterBar")
        filter_frame.setStyleSheet("""
            QFrame#FilterBar {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 6px;
                padding: 6px;
            }
        """)
        f_layout = QHBoxLayout(filter_frame)
        f_layout.setContentsMargins(4, 4, 4, 4)
        f_layout.setSpacing(8)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Search alerts by ID, title, IP address, or explanation...")
        self.txt_search.setStyleSheet("background: #1e1e24; color: #fff; padding: 6px 10px; border: 1px solid #363642; border-radius: 4px;")
        self.txt_search.textChanged.connect(self.refresh_table)
        f_layout.addWidget(self.txt_search, 2)

        lbl_sev = QLabel("Severity:")
        lbl_sev.setStyleSheet("color: #888898; font-weight: bold;")
        f_layout.addWidget(lbl_sev)

        self.cmb_severity = QComboBox()
        self.cmb_severity.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Informational"])
        self.cmb_severity.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_severity.currentTextChanged.connect(self.refresh_table)
        f_layout.addWidget(self.cmb_severity)

        lbl_cat = QLabel("Category:")
        lbl_cat.setStyleSheet("color: #888898; font-weight: bold;")
        f_layout.addWidget(lbl_cat)

        self.cmb_category = QComboBox()
        self.cmb_category.addItems([
            "All Categories", "Bandwidth Spike", "Port Scanning", "ML Anomaly",
            "DNS Anomaly", "Repeated Connection Attempts", "Unusual Outbound Traffic"
        ])
        self.cmb_category.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_category.currentTextChanged.connect(self.refresh_table)
        f_layout.addWidget(self.cmb_category)

        lbl_st = QLabel("Status:")
        lbl_st.setStyleSheet("color: #888898; font-weight: bold;")
        f_layout.addWidget(lbl_st)

        self.cmb_status = QComboBox()
        self.cmb_status.addItems(["All Statuses", "New", "Investigating", "Resolved", "False Positive"])
        self.cmb_status.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_status.currentTextChanged.connect(self.refresh_table)
        f_layout.addWidget(self.cmb_status)

        # Clear Visible Button
        self.btn_clear = QPushButton("Clear Visible")
        self.btn_clear.setStyleSheet("background: #363642; color: #fff; padding: 5px 12px; border-radius: 4px;")
        self.btn_clear.clicked.connect(self._clear_visible)
        f_layout.addWidget(self.btn_clear)

        # Export CSV Button
        self.btn_export = QPushButton("📥 Export CSV")
        self.btn_export.setStyleSheet("background: #363642; color: #00e5ff; font-weight: bold; padding: 5px 12px; border-radius: 4px;")
        self.btn_export.clicked.connect(self._export_csv)
        f_layout.addWidget(self.btn_export)

        main_layout.addWidget(filter_frame)

        # 3. Alerts Table
        self.table = QTableWidget()
        self.table.setColumnCount(10)
        self.table.setHorizontalHeaderLabels([
            "Alert ID", "Severity", "Title", "Category", "Source IP",
            "Target / Dest", "Rate vs Baseline", "Occurrences", "Status", "Last Seen"
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e24;
                alternate-background-color: #25252c;
                color: #e0e0e0;
                border: 1px solid #363642;
                border-radius: 6px;
                gridline-color: #2e2e38;
            }
            QHeaderView::section {
                background-color: #25252c;
                color: #00e5ff;
                padding: 6px;
                border: 1px solid #363642;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background-color: #2a3b5c;
                color: #ffffff;
            }
        """)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        h.setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)

        main_layout.addWidget(self.table, 1)

    def _create_card(self, title: str, val: str, color: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: #1e1e24;
                border-left: 3px solid {color};
                border-radius: 6px;
                padding: 4px 10px;
            }}
        """)
        v = QVBoxLayout(frame)
        v.setContentsMargins(2, 2, 2, 2)
        v.setSpacing(1)
        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("color: #888898; font-size: 10px; font-weight: bold;")
        lbl_v = QLabel(val)
        lbl_v.setObjectName("CardValue")
        lbl_v.setStyleSheet(f"color: {color}; font-size: 14px; font-weight: bold;")
        v.addWidget(lbl_t)
        v.addWidget(lbl_v)
        return frame

    def _connect_signals(self):
        self.manager.new_alert_raised.connect(lambda a: self.refresh_table())
        self.manager.alert_updated.connect(lambda a: self.refresh_table())
        self.manager.alerts_cleared.connect(self.refresh_table)

    def add_alert(self, alert_data: dict):
        """Bridge for backwards-compatibility with capture engine."""
        self.manager.process_raw_alert(alert_data)

    def refresh_table(self):
        alerts = self.manager.get_all_alerts_snapshot()

        # Update metric cards
        total_active = len(alerts)
        crit_high = sum(1 for a in alerts if a["severity"] in ("Critical", "High"))
        investigating = sum(1 for a in alerts if a["status"] == "Investigating")

        self.card_total.findChild(QLabel, "CardValue").setText(str(total_active))
        self.card_crit.findChild(QLabel, "CardValue").setText(str(crit_high))
        self.card_investigating.findChild(QLabel, "CardValue").setText(str(investigating))

        # Filter criteria
        query = self.txt_search.text().strip().lower()
        sev_filter = self.cmb_severity.currentText()
        cat_filter = self.cmb_category.currentText()
        st_filter = self.cmb_status.currentText()

        filtered = []
        for a in alerts:
            if sev_filter != "All Severities" and a["severity"] != sev_filter:
                continue
            if cat_filter != "All Categories" and a["category"] != cat_filter:
                continue
            if st_filter != "All Statuses" and a["status"] != st_filter:
                continue
            if query:
                match_txt = (
                    query in a["alert_id"].lower() or
                    query in a["title"].lower() or
                    query in a["src_ip"].lower() or
                    query in a["dst_ip"].lower() or
                    query in a.get("explanation", "").lower()
                )
                if not match_txt:
                    continue
            filtered.append(a)

        self.table.setRowCount(len(filtered))
        self._current_filtered = filtered

        for row, a in enumerate(filtered):
            self.table.setItem(row, 0, QTableWidgetItem(a["alert_id"]))

            # Severity item with color badge
            sev = a["severity"]
            sev_item = QTableWidgetItem(sev)
            if sev == "Critical":
                sev_item.setForeground(QBrush(QColor("#ff5252")))
            elif sev == "High":
                sev_item.setForeground(QBrush(QColor("#ff9100")))
            elif sev == "Medium":
                sev_item.setForeground(QBrush(QColor("#ffd600")))
            elif sev == "Low":
                sev_item.setForeground(QBrush(QColor("#42a5f5")))
            else:
                sev_item.setForeground(QBrush(QColor("#00e5ff")))
            self.table.setItem(row, 1, sev_item)

            self.table.setItem(row, 2, QTableWidgetItem(a["title"]))
            self.table.setItem(row, 3, QTableWidgetItem(a["category"]))
            self.table.setItem(row, 4, QTableWidgetItem(a["src_ip"]))
            self.table.setItem(row, 5, QTableWidgetItem(a["dst_ip"]))

            rate_comp = f"{a['current_rate']} (Base: {a['baseline_rate']})"
            self.table.setItem(row, 6, QTableWidgetItem(rate_comp))

            occ_item = QTableWidgetItem(f"x{a['occurrences']}")
            if a["occurrences"] > 1:
                occ_item.setForeground(QBrush(QColor("#00e5ff")))
            self.table.setItem(row, 7, occ_item)

            st_item = QTableWidgetItem(a["status"])
            if a["status"] == "New":
                st_item.setForeground(QBrush(QColor("#ff5252")))
            elif a["status"] == "Investigating":
                st_item.setForeground(QBrush(QColor("#ffd600")))
            elif a["status"] == "Resolved":
                st_item.setForeground(QBrush(QColor("#00e676")))
            elif a["status"] == "False Positive":
                st_item.setForeground(QBrush(QColor("#808090")))
            self.table.setItem(row, 8, st_item)

            last_dt = datetime.datetime.fromtimestamp(a["last_seen"]).strftime("%H:%M:%S")
            self.table.setItem(row, 9, QTableWidgetItem(last_dt))

    def _on_row_double_clicked(self, row: int, col: int):
        if hasattr(self, "_current_filtered") and row < len(self._current_filtered):
            alert_data = self._current_filtered[row]
            dlg = AlertDetailsDialog(alert_data, parent=self)
            dlg.launch_investigation_requested.connect(self.launch_investigation_requested.emit)
            dlg.filter_connections_requested.connect(self.filter_connections_requested.emit)
            dlg.exec()
            self.refresh_table()

    def _show_context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0 or not hasattr(self, "_current_filtered") or row >= len(self._current_filtered):
            return
        self.table.selectRow(row)
        alert = self._current_filtered[row]

        menu = QMenu(self)
        act_inspect = menu.addAction("🔍 Inspect Incident Details")
        act_threat = menu.addAction(f"🛡 Check Threat Intel: {alert['src_ip']}")
        menu.addSeparator()
        act_investigating = menu.addAction("Mark as 'Investigating'")
        act_resolve = menu.addAction("Mark as 'Resolved'")
        act_fp = menu.addAction("Mark as 'False Positive'")
        menu.addSeparator()
        act_launch_inv = menu.addAction("🚀 Launch Formal Investigation")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == act_inspect:
            self._on_row_double_clicked(row, 0)
        elif chosen == act_threat:
            if alert["src_ip"] not in ("Unknown", "Multiple"):
                IPThreatIntelDialog(alert["src_ip"], parent=self).exec()
        elif chosen == act_investigating:
            self.manager.update_alert_status(alert["alert_id"], "Investigating")
            self.refresh_table()
        elif chosen == act_resolve:
            self.manager.update_alert_status(alert["alert_id"], "Resolved")
            self.refresh_table()
        elif chosen == act_fp:
            self.manager.update_alert_status(alert["alert_id"], "False Positive")
            self.refresh_table()
        elif chosen == act_launch_inv:
            self.launch_investigation_requested.emit(alert)

    def _clear_visible(self):
        """Clears visible table without deleting SQLite history."""
        reply = QMessageBox.question(
            self, "Clear Visible Alerts",
            "This will clear the active alerts from the display list.\n\n"
            "Historical incidents will remain safely stored in the persistent database.\nProceed?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.manager.clear_visible_alerts()

    def _export_csv(self):
        alerts = self.manager.get_all_alerts_snapshot()
        if not alerts:
            QMessageBox.information(self, "No Alerts", "No alerts to export.")
            return

        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Security Alerts", "security_alerts.csv", "CSV Files (*.csv)"
        )
        if filepath:
            try:
                fieldnames = [
                    "alert_id", "severity", "title", "category", "detection_method",
                    "src_ip", "dst_ip", "src_port", "dst_port", "current_rate",
                    "baseline_rate", "anomaly_score", "first_seen", "last_seen",
                    "occurrences", "status", "explanation", "recommended_action"
                ]
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
                    writer.writeheader()
                    for a in alerts:
                        writer.writerow(a)
                QMessageBox.information(self, "Export Complete", f"Successfully exported alerts to:\n{filepath}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Failed to export CSV: {e}")

    def clear_alerts(self):
        """Backwards compatibility for MainWindow."""
        self._clear_visible()

    def get_alerts(self):
        """Backwards compatibility for MainWindow."""
        return self.manager.get_all_alerts_snapshot()
