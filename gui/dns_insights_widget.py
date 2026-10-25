import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QGridLayout,
    QFileDialog, QMessageBox, QFrame, QAbstractItemView
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QBrush
from core.dns_monitor import DNSMonitor
from gui.ip_threat_intel_dialog import IPThreatIntelDialog


class DNSInsightsWidget(QWidget):
    """
    Dedicated view for inspecting observable DNS queries, responses,
    query-type distributions, top domains, and encrypted traffic characteristics.
    """
    filter_connections_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitor = DNSMonitor()

        self._init_ui()

        # 1-second refresh timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh_views)
        self.timer.start(1000)

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # 1. Honest Encrypted Traffic & Privacy Disclaimer Banner
        notice_frame = QFrame()
        notice_frame.setStyleSheet("""
            QFrame {
                background-color: #1a1e2e;
                border: 1px solid #283593;
                border-radius: 6px;
                padding: 6px 12px;
            }
        """)
        h_notice = QHBoxLayout(notice_frame)
        h_notice.setContentsMargins(4, 4, 4, 4)
        lbl_disclaimer = QLabel(
            "🔒 <b>Cryptographic & Protocol Transparency:</b> "
            "Ordinary L4 packet sniffing cannot decrypt DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), "
            "or HTTPS request paths. Metadata is observed passively from unencrypted standard DNS (port 53) "
            "and unencrypted TLS Client Hello handshakes (SNI)."
        )
        lbl_disclaimer.setWordWrap(True)
        lbl_disclaimer.setStyleSheet("color: #9fa8da; font-size: 11px;")
        h_notice.addWidget(lbl_disclaimer)
        main_layout.addWidget(notice_frame)

        # 2. Filter & Controls Bar
        filter_frame = QFrame()
        filter_frame.setObjectName("FilterFrame")
        filter_frame.setStyleSheet("""
            QFrame#FilterFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        f_layout = QHBoxLayout(filter_frame)
        f_layout.setContentsMargins(4, 4, 4, 4)
        f_layout.setSpacing(10)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Filter by domain name, client IP, or answer...")
        self.txt_search.setStyleSheet("background: #1e1e24; color: #fff; padding: 6px 10px; border: 1px solid #363642; border-radius: 4px;")
        self.txt_search.textChanged.connect(self._refresh_views)
        f_layout.addWidget(self.txt_search, 2)

        lbl_qtype = QLabel("Query Type:")
        lbl_qtype.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_qtype)

        self.cmb_qtype = QComboBox()
        self.cmb_qtype.addItems(["All Types", "A", "AAAA", "CNAME", "MX", "TXT", "HTTPS", "PTR", "SRV", "OTHER"])
        self.cmb_qtype.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_qtype.currentTextChanged.connect(self._refresh_views)
        f_layout.addWidget(self.cmb_qtype)

        lbl_rcode = QLabel("Response Code:")
        lbl_rcode.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_rcode)

        self.cmb_rcode = QComboBox()
        self.cmb_rcode.addItems(["All Responses", "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "Pending"])
        self.cmb_rcode.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_rcode.currentTextChanged.connect(self._refresh_views)
        f_layout.addWidget(self.cmb_rcode)

        self.btn_export = QPushButton("📥 Export DNS CSV")
        self.btn_export.setStyleSheet("background: #363642; color: #00e5ff; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.btn_export.clicked.connect(self._export_csv)
        f_layout.addWidget(self.btn_export)

        main_layout.addWidget(filter_frame)

        # 3. Main Splitter: Transactions Table (Left 65%) and Sidebar (Right 35%)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #363642; width: 4px; }")

        # Table Section
        table_container = QWidget()
        v_tbl = QVBoxLayout(table_container)
        v_tbl.setContentsMargins(0, 0, 0, 0)
        v_tbl.setSpacing(6)

        lbl_tbl_title = QLabel("Observable DNS Transactions Log")
        lbl_tbl_title.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 13px;")
        v_tbl.addWidget(lbl_tbl_title)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Time", "Client Endpoint", "Server", "Domain Name (QName)",
            "Type", "Status / RCODE", "Latency", "Resolved Answers"
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
        h.setSectionResizeMode(3, QHeaderView.Stretch)
        h.setSectionResizeMode(7, QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self._on_table_double_click)
        v_tbl.addWidget(self.table)
        splitter.addWidget(table_container)

        # Right Sidebar: Summary Cards, Top Domains, and Anomalies
        sidebar = QWidget()
        v_side = QVBoxLayout(sidebar)
        v_side.setContentsMargins(0, 0, 0, 0)
        v_side.setSpacing(10)

        # Top Domains Group
        domains_group = QGroupBox("Frequently Queried Domains")
        domains_group.setStyleSheet("""
            QGroupBox {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 6px;
                margin-top: 14px;
                font-weight: bold;
                color: #00e5ff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
        """)
        v_dom = QVBoxLayout(domains_group)
        self.tbl_domains = QTableWidget()
        self.tbl_domains.setColumnCount(2)
        self.tbl_domains.setHorizontalHeaderLabels(["Domain", "Queries"])
        self.tbl_domains.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tbl_domains.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_domains.setStyleSheet("background: #1e1e24; color: #fff; border: none;")
        self.tbl_domains.cellDoubleClicked.connect(lambda r, c: self._filter_domain_from_table(r))
        v_dom.addWidget(self.tbl_domains)
        v_side.addWidget(domains_group, 1)

        # DNS Security Alerts Group
        alerts_group = QGroupBox("DNS Behavioral Anomalies")
        alerts_group.setStyleSheet("""
            QGroupBox {
                background-color: #25252c;
                border: 1px solid #ff5252;
                border-radius: 6px;
                margin-top: 14px;
                font-weight: bold;
                color: #ff5252;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
        """)
        v_alt = QVBoxLayout(alerts_group)
        self.tbl_dns_alerts = QTableWidget()
        self.tbl_dns_alerts.setColumnCount(3)
        self.tbl_dns_alerts.setHorizontalHeaderLabels(["Time", "Anomaly Indicator", "Target / Client"])
        self.tbl_dns_alerts.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_dns_alerts.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_dns_alerts.setStyleSheet("background: #1e1e24; color: #ffcdd2; border: none;")
        v_alt.addWidget(self.tbl_dns_alerts)
        v_side.addWidget(alerts_group, 1)

        splitter.addWidget(sidebar)
        splitter.setSizes([650, 350])

        main_layout.addWidget(splitter, 1)

    def _refresh_views(self):
        txs = self.monitor.get_transactions_snapshot()

        query = self.txt_search.text().strip().lower()
        qtype_filter = self.cmb_qtype.currentText()
        rcode_filter = self.cmb_rcode.currentText()

        filtered = []
        for tx in txs:
            if qtype_filter != "All Types" and tx["qtype"] != qtype_filter:
                continue
            if rcode_filter != "All Responses" and tx["rcode"] != rcode_filter:
                continue
            if query:
                match_txt = (
                    query in tx["qname"].lower() or
                    query in tx["client_endpoint"].lower() or
                    query in tx["answers"].lower() or
                    query in tx["rcode"].lower()
                )
                if not match_txt:
                    continue
            filtered.append(tx)

        # Update main table
        self.table.setRowCount(len(filtered))
        for row, tx in enumerate(filtered):
            dt_str = datetime.datetime.fromtimestamp(tx["timestamp"]).strftime("%H:%M:%S")
            self.table.setItem(row, 0, QTableWidgetItem(dt_str))
            self.table.setItem(row, 1, QTableWidgetItem(tx["client_endpoint"]))
            self.table.setItem(row, 2, QTableWidgetItem(tx["server_endpoint"]))

            qname_item = QTableWidgetItem(tx["qname"])
            if tx.get("is_anomalous"):
                qname_item.setForeground(QBrush(QColor("#ff5252")))
                qname_item.setToolTip(tx.get("anomaly_reason", "Anomalous DNS behavior"))
            self.table.setItem(row, 3, qname_item)

            self.table.setItem(row, 4, QTableWidgetItem(tx["qtype"]))

            # Rcode styling
            rc = tx["rcode"]
            rc_item = QTableWidgetItem(rc)
            if rc == "NOERROR":
                rc_item.setForeground(QBrush(QColor("#00e676")))
            elif rc == "NXDOMAIN":
                rc_item.setForeground(QBrush(QColor("#ff9100")))
            elif rc in ("SERVFAIL", "REFUSED"):
                rc_item.setForeground(QBrush(QColor("#ff5252")))
            self.table.setItem(row, 5, rc_item)

            lat_str = f"{tx['duration_ms']:.1f} ms" if tx["duration_ms"] > 0 else "..."
            self.table.setItem(row, 6, QTableWidgetItem(lat_str))
            self.table.setItem(row, 7, QTableWidgetItem(tx["answers"]))

        # Update Top Domains
        top_doms = self.monitor.get_top_domains(limit=12)
        self.tbl_domains.setRowCount(len(top_doms))
        for r, (dom, count) in enumerate(top_doms):
            self.tbl_domains.setItem(r, 0, QTableWidgetItem(dom))
            self.tbl_domains.setItem(r, 1, QTableWidgetItem(str(count)))

        # Update DNS Security Alerts
        dns_alerts = self.monitor.get_dns_alerts()
        self.tbl_dns_alerts.setRowCount(min(20, len(dns_alerts)))
        for r, alt in enumerate(dns_alerts[:20]):
            dt = datetime.datetime.fromtimestamp(alt["timestamp"]).strftime("%H:%M:%S")
            self.tbl_dns_alerts.setItem(r, 0, QTableWidgetItem(dt))
            self.tbl_dns_alerts.setItem(r, 1, QTableWidgetItem(alt["title"]))
            self.tbl_dns_alerts.setItem(r, 2, QTableWidgetItem(f"{alt['client_ip']} -> {alt['domain']}"))

    def _filter_domain_from_table(self, row: int):
        item = self.tbl_domains.item(row, 0)
        if item:
            self.txt_search.setText(item.text())

    def _on_table_double_click(self, row: int, col: int):
        # Double clicking an endpoint or answer opens threat intel if IP
        item = self.table.item(row, col)
        if not item:
            return
        val = item.text().split(':')[0].strip()
        # Test if it's an IP
        parts = val.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            IPThreatIntelDialog(val, parent=self).exec()

    def _export_csv(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export DNS Log", "dns_queries.csv", "CSV Files (*.csv)"
        )
        if filepath:
            success = self.monitor.export_to_csv(filepath)
            if success:
                QMessageBox.information(self, "Export Complete", f"Successfully exported DNS queries to:\n{filepath}")
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export DNS log.")
