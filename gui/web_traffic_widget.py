import time
from collections import deque
from datetime import datetime
from typing import Dict, Any, List, Optional

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                               QLineEdit, QPushButton, QComboBox, QCheckBox, 
                               QTableWidget, QTableWidgetItem, QHeaderView, 
                               QSplitter, QFrame, QMessageBox, QFileDialog, 
                               QGroupBox, QAbstractItemView)
from PySide6.QtCore import Qt, QTimer
import pyqtgraph as pg

from core.web_traffic_monitor import WebCaptureEngine, normalize_website_url
from gui.packet_details_dialog import PacketDetailsDialog
from gui.dashboard_widget import MetricCard, format_bytes
from utils.interfaces import get_network_interfaces, get_best_interface
from utils.exporter import (export_to_pcap, export_stats_to_csv, 
                            export_alerts_to_csv, export_connections_to_csv)
from utils.logger import logger

class WebTrafficWidget(QWidget):
    """
    Complete Web Traffic Analyzer widget for capturing and analyzing
    network traffic associated with a specific website URL.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.web_engine: Optional[WebCaptureEngine] = None
        self.stats_history: List[Dict[str, Any]] = []
        self.alerts_history: List[Dict[str, Any]] = []
        self.captured_packets_data: List[Dict[str, Any]] = []
        
        # Batch buffer for table inserts
        self.table_queue = deque()
        self.is_display_paused = False
        
        # 60s rolling data for dual-curve bandwidth chart
        self.max_chart_points = 60
        self.in_bytes_data = [0.0] * self.max_chart_points
        self.out_bytes_data = [0.0] * self.max_chart_points
        self.proto_categories = ['HTTPS', 'HTTP', 'QUIC', 'DNS', 'TCP', 'UDP', 'ICMP', 'Other']
        
        self.init_ui()
        
        # 10 FPS batch table flush timer
        self.flush_timer = QTimer(self)
        self.flush_timer.setInterval(100)
        self.flush_timer.timeout.connect(self._flush_table_batch)
        self.flush_timer.start()

        # Session duration timer
        self.duration_timer = QTimer(self)
        self.duration_timer.setInterval(1000)
        self.duration_timer.timeout.connect(self._update_session_duration)
        self.capture_start_time = 0.0

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(10)

        # -----------------------------------------------------------------
        # 1. Website Analysis Control Panel (Top)
        # -----------------------------------------------------------------
        control_panel = QFrame()
        control_panel.setStyleSheet("""
            QFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
            }
        """)
        panel_layout = QVBoxLayout(control_panel)
        panel_layout.setContentsMargins(12, 10, 12, 10)
        panel_layout.setSpacing(8)

        # Row 1: URL input, Interface, Duration, Start/Stop buttons
        row1_layout = QHBoxLayout()
        row1_layout.setSpacing(8)

        url_label = QLabel("Website URL:")
        url_label.setStyleSheet("font-weight: bold; color: #d4d4d4;")
        row1_layout.addWidget(url_label)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (e.g., https://example.com)")
        self.url_input.setText("https://example.com")
        self.url_input.returnPressed.connect(self.start_capture)
        row1_layout.addWidget(self.url_input, stretch=3)

        iface_label = QLabel("Interface:")
        iface_label.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        row1_layout.addWidget(iface_label)

        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(180)
        # Populate interfaces
        ifaces = get_network_interfaces()
        for ifc in ifaces:
            self.iface_combo.addItem(ifc['display_label'], userData=ifc['name'])
        best = get_best_interface()
        if best:
            idx = self.iface_combo.findData(best['name'])
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
        row1_layout.addWidget(self.iface_combo, stretch=2)

        dur_label = QLabel("Duration:")
        dur_label.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        row1_layout.addWidget(dur_label)

        self.duration_combo = QComboBox()
        self.duration_combo.addItem("No Limit", 0)
        self.duration_combo.addItem("10 seconds", 10)
        self.duration_combo.addItem("30 seconds", 30)
        self.duration_combo.addItem("60 seconds", 60)
        self.duration_combo.addItem("120 seconds", 120)
        self.duration_combo.addItem("300 seconds", 300)
        row1_layout.addWidget(self.duration_combo)

        self.start_btn = QPushButton("▶ Capture Traffic")
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #00897b;
                color: white;
                font-weight: bold;
                padding: 6px 14px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #00a896; }
            QPushButton:disabled { background-color: #384240; color: #707070; }
        """)
        self.start_btn.clicked.connect(self.start_capture)
        row1_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹ Stop Capture")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                font-weight: bold;
                padding: 6px 14px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #f44336; }
            QPushButton:disabled { background-color: #4a2828; color: #707070; }
        """)
        self.stop_btn.clicked.connect(self.stop_capture)
        row1_layout.addWidget(self.stop_btn)

        self.reset_btn = QPushButton("🔄 Reset / Clear")
        self.reset_btn.clicked.connect(self.reset_all)
        row1_layout.addWidget(self.reset_btn)

        panel_layout.addLayout(row1_layout)

        # Row 2: Status indicator, Domain resolution info, and Export actions
        row2_layout = QHBoxLayout()
        row2_layout.setSpacing(10)

        self.status_badge = QLabel("● IDLE")
        self.status_badge.setStyleSheet("color: #8e8e9f; font-weight: bold; font-size: 12px;")
        row2_layout.addWidget(self.status_badge)

        self.dns_summary_label = QLabel("Enter a URL and click 'Capture Traffic' to resolve domain and monitor packets.")
        self.dns_summary_label.setStyleSheet("color: #a0a0b0; font-size: 12px;")
        row2_layout.addWidget(self.dns_summary_label, stretch=3)

        # Quick Export Buttons
        export_label = QLabel("Export:")
        export_label.setStyleSheet("color: #8e8e9f; font-size: 11px;")
        row2_layout.addWidget(export_label)

        exp_pcap_btn = QPushButton("💾 PCAP")
        exp_pcap_btn.setToolTip("Export captured raw packets to Wireshark-compatible PCAP")
        exp_pcap_btn.clicked.connect(self.export_pcap)
        row2_layout.addWidget(exp_pcap_btn)

        exp_stats_btn = QPushButton("📊 Stats CSV")
        exp_stats_btn.setToolTip("Export website bandwidth and traffic statistics to CSV")
        exp_stats_btn.clicked.connect(self.export_stats)
        row2_layout.addWidget(exp_stats_btn)

        exp_conns_btn = QPushButton("🔗 Conns CSV")
        exp_conns_btn.setToolTip("Export observed connections to CSV")
        exp_conns_btn.clicked.connect(self.export_connections)
        row2_layout.addWidget(exp_conns_btn)

        exp_alerts_btn = QPushButton("🚨 Alerts CSV")
        exp_alerts_btn.setToolTip("Export website anomaly alerts to CSV")
        exp_alerts_btn.clicked.connect(self.export_alerts)
        row2_layout.addWidget(exp_alerts_btn)

        panel_layout.addLayout(row2_layout)

        # Row 3: Honest Technical Notice (Collapsible / Informative)
        notice_banner = QLabel(
            "🔒 <b>Attribution & Cryptographic Notice:</b> Traffic is matched via resolved IP addresses, TLS SNI, and DNS queries. "
            "HTTPS payloads are end-to-end encrypted; payload contents and private credentials are not decrypted. "
            "Traffic on shared CDN IPs is clearly labeled as IP-matched."
        )
        notice_banner.setStyleSheet("color: #7e7e8f; font-size: 11px; padding-top: 2px;")
        notice_banner.setWordWrap(True)
        panel_layout.addWidget(notice_banner)

        main_layout.addWidget(control_panel)

        # -----------------------------------------------------------------
        # 2. Real-Time Website KPI Cards Row
        # -----------------------------------------------------------------
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(10)

        self.card_host = MetricCard("TARGET HOSTNAME", "None", "#ffffff")
        self.card_bandwidth = MetricCard("BANDWIDTH (IN / OUT)", "0.0 B/s | 0.0 B/s", "#00e5ff")
        self.card_total_vol = MetricCard("TOTAL VOLUME", "0.0 B (⬇ 0B / ⬆ 0B)", "#ffd600")
        self.card_total_pkts = MetricCard("TOTAL PACKETS", "0 (⬇ 0 / ⬆ 0)", "#ff9100")
        self.card_conns = MetricCard("ACTIVE CONNECTIONS", "0 active", "#00e676")
        self.card_timer = MetricCard("CAPTURE TIME", "00:00:00", "#e040fb")

        kpi_layout.addWidget(self.card_host)
        kpi_layout.addWidget(self.card_bandwidth)
        kpi_layout.addWidget(self.card_total_vol)
        kpi_layout.addWidget(self.card_total_pkts)
        kpi_layout.addWidget(self.card_conns)
        kpi_layout.addWidget(self.card_timer)

        main_layout.addLayout(kpi_layout)

        # -----------------------------------------------------------------
        # 3. Middle Section: Charts & Connection Summary
        # -----------------------------------------------------------------
        mid_splitter = QSplitter(Qt.Horizontal)

        # Left: Live Dual-Curve Bandwidth Chart
        chart_frame = QFrame()
        chart_layout = QVBoxLayout(chart_frame)
        chart_layout.setContentsMargins(0, 0, 0, 0)

        self.bandwidth_plot = pg.PlotWidget(title="Live Bandwidth (Incoming vs Outgoing)")
        self.bandwidth_plot.showGrid(x=True, y=True, alpha=0.25)
        self.bandwidth_plot.setLabel('left', 'Throughput', units='B/s')
        self.bandwidth_plot.setLabel('bottom', 'Time (s)')
        self.bandwidth_plot.setXRange(-60, 0, padding=0.02)
        self.bandwidth_plot.addLegend(offset=(10, 10))

        # Incoming curve (Cyan)
        self.in_curve = self.bandwidth_plot.plot(
            name="Incoming ⬇",
            pen=pg.mkPen('#00e5ff', width=2),
            fillLevel=0,
            brush=pg.mkBrush(0, 229, 255, 30)
        )
        # Outgoing curve (Coral)
        self.out_curve = self.bandwidth_plot.plot(
            name="Outgoing ⬆",
            pen=pg.mkPen('#ff9100', width=2),
            fillLevel=0,
            brush=pg.mkBrush(255, 145, 0, 30)
        )
        chart_layout.addWidget(self.bandwidth_plot)
        mid_splitter.addWidget(chart_frame)

        # Center: Protocol Distribution Bar Chart
        proto_frame = QFrame()
        proto_layout = QVBoxLayout(proto_frame)
        proto_layout.setContentsMargins(0, 0, 0, 0)

        self.proto_plot = pg.PlotWidget(title="Protocol Breakdown")
        self.proto_plot.showGrid(x=False, y=True, alpha=0.25)
        self.proto_plot.setLabel('left', 'Packets')
        proto_ax = self.proto_plot.getAxis('bottom')
        proto_ax.setTicks([[(i, name) for i, name in enumerate(self.proto_categories)]])

        self.proto_bars = pg.BarGraphItem(
            x=list(range(len(self.proto_categories))),
            height=[0] * len(self.proto_categories),
            width=0.6,
            brushes=[
                pg.mkColor('#00e5ff'), # HTTPS
                pg.mkColor('#ffd600'), # HTTP
                pg.mkColor('#e040fb'), # QUIC
                pg.mkColor('#00e676'), # DNS
                pg.mkColor('#448aff'), # TCP
                pg.mkColor('#ff9100'), # UDP
                pg.mkColor('#ff5252'), # ICMP
                pg.mkColor('#b0bec5')  # Other
            ]
        )
        self.proto_plot.addItem(self.proto_bars)
        proto_layout.addWidget(self.proto_plot)
        mid_splitter.addWidget(proto_frame)

        # Right: Connection Summary Table
        conn_frame = QFrame()
        conn_layout = QVBoxLayout(conn_frame)
        conn_layout.setContentsMargins(0, 0, 0, 0)
        conn_header = QLabel("Active Observed Connections")
        conn_header.setStyleSheet("font-weight: bold; font-size: 12px; color: #d4d4d4;")
        conn_layout.addWidget(conn_header)

        self.conn_table = QTableWidget(0, 7)
        self.conn_table.setHorizontalHeaderLabels([
            "Remote Endpoint", "Proto", "State", "Packets (In/Out)", "Volume", "Attribution", "Last Active"
        ])
        c_head = self.conn_table.horizontalHeader()
        c_head.setSectionResizeMode(0, QHeaderView.Stretch)
        for i in range(1, 7):
            c_head.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.conn_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.conn_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.conn_table.setAlternatingRowColors(True)
        conn_layout.addWidget(self.conn_table)
        mid_splitter.addWidget(conn_frame)

        mid_splitter.setSizes([450, 320, 480])
        main_layout.addWidget(mid_splitter, stretch=2)

        # -----------------------------------------------------------------
        # 4. Bottom Section: Packet Inspection Table & Anomaly Alerts
        # -----------------------------------------------------------------
        bottom_splitter = QSplitter(Qt.Horizontal)

        # Packet Table Container (Left, 70%)
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(6)

        # Table Control Bar
        tbl_ctrl = QHBoxLayout()
        tbl_ctrl.setSpacing(8)

        self.tbl_search = QLineEdit()
        self.tbl_search.setPlaceholderText("Search packets (IP, port, protocol, attribution)...")
        self.tbl_search.textChanged.connect(self._apply_table_filter)
        tbl_ctrl.addWidget(self.tbl_search, stretch=3)

        self.proto_filter = QComboBox()
        self.proto_filter.addItems(["All Protocols", "HTTPS", "HTTP", "QUIC", "DNS", "TCP", "UDP", "ICMP"])
        self.proto_filter.currentIndexChanged.connect(self._apply_table_filter)
        tbl_ctrl.addWidget(self.proto_filter)

        self.dir_filter = QComboBox()
        self.dir_filter.addItems(["All Directions", "Incoming Only", "Outgoing Only"])
        self.dir_filter.currentIndexChanged.connect(self._apply_table_filter)
        tbl_ctrl.addWidget(self.dir_filter)

        self.autoscroll_box = QCheckBox("Auto-scroll")
        self.autoscroll_box.setChecked(True)
        tbl_ctrl.addWidget(self.autoscroll_box)

        self.pause_box = QCheckBox("Pause Display")
        self.pause_box.toggled.connect(self._on_pause_toggled)
        tbl_ctrl.addWidget(self.pause_box)

        self.pkt_count_lbl = QLabel("Packets: 0")
        self.pkt_count_lbl.setStyleSheet("color: #8e8e9f; font-weight: bold;")
        tbl_ctrl.addWidget(self.pkt_count_lbl)

        inspect_btn = QPushButton("🔍 Inspect Details")
        inspect_btn.clicked.connect(self.inspect_selected_packet)
        tbl_ctrl.addWidget(inspect_btn)

        clear_tbl_btn = QPushButton("Clear")
        clear_tbl_btn.clicked.connect(self.clear_table)
        tbl_ctrl.addWidget(clear_tbl_btn)

        table_layout.addLayout(tbl_ctrl)

        # Inspection Table
        self.packet_table = QTableWidget(0, 11)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Dest IP", "Src Port", "Dst Port", 
            "Proto", "Length", "Direction", "TCP Flags", "Attribution", "Summary"
        ])
        t_head = self.packet_table.horizontalHeader()
        t_head.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(8, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(9, QHeaderView.ResizeToContents)
        t_head.setSectionResizeMode(10, QHeaderView.Stretch)

        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.doubleClicked.connect(self.inspect_selected_packet)
        table_layout.addWidget(self.packet_table)

        bottom_splitter.addWidget(table_container)

        # Anomaly Alerts Container (Right, 30%)
        alerts_container = QWidget()
        alerts_layout = QVBoxLayout(alerts_container)
        alerts_layout.setContentsMargins(0, 0, 0, 0)
        alerts_layout.setSpacing(6)

        alerts_header = QHBoxLayout()
        alerts_title = QLabel("Website Anomaly Alerts")
        alerts_title.setStyleSheet("font-weight: bold; font-size: 12px; color: #d4d4d4;")
        alerts_header.addWidget(alerts_title)

        self.alerts_count_lbl = QLabel("0 alerts")
        self.alerts_count_lbl.setStyleSheet("color: #8e8e9f; font-size: 11px;")
        alerts_header.addWidget(self.alerts_count_lbl)
        alerts_header.addStretch()

        clear_alerts_btn = QPushButton("Clear")
        clear_alerts_btn.setMaximumWidth(50)
        clear_alerts_btn.clicked.connect(self.clear_alerts)
        alerts_header.addWidget(clear_alerts_btn)
        alerts_layout.addLayout(alerts_header)

        self.alerts_table = QTableWidget(0, 3)
        self.alerts_table.setHorizontalHeaderLabels(["Time", "Severity", "Description"])
        a_head = self.alerts_table.horizontalHeader()
        a_head.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        a_head.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        a_head.setSectionResizeMode(2, QHeaderView.Stretch)
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alerts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.alerts_table.setAlternatingRowColors(True)
        alerts_layout.addWidget(self.alerts_table)

        bottom_splitter.addWidget(alerts_container)

        bottom_splitter.setSizes([850, 400])
        main_layout.addWidget(bottom_splitter, stretch=2)

    # -----------------------------------------------------------------
    # Capture Lifecycle & Controls
    # -----------------------------------------------------------------
    def start_capture(self):
        if self.web_engine and self.web_engine.isRunning():
            return

        url_text = self.url_input.text().strip()
        try:
            norm_url, hostname = normalize_website_url(url_text)
            self.url_input.setText(norm_url)
        except ValueError as e:
            QMessageBox.warning(self, "Invalid URL", str(e))
            return

        selected_iface = self.iface_combo.currentData()
        duration_sec = self.duration_combo.currentData()

        # Update UI state
        self.status_badge.setText("● RESOLVING DOMAIN")
        self.status_badge.setStyleSheet("color: #ffd600; font-weight: bold; font-size: 12px;")
        self.dns_summary_label.setText(f"Resolving DNS for {hostname}...")
        self.card_host.set_value(hostname, "#00e5ff")

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.url_input.setEnabled(False)
        self.iface_combo.setEnabled(False)
        self.duration_combo.setEnabled(False)

        # Initialize WebCaptureEngine
        self.web_engine = WebCaptureEngine(norm_url, selected_iface, duration_sec)
        self.web_engine.packet_captured.connect(self._on_packet_captured, Qt.QueuedConnection)
        self.web_engine.stats_updated.connect(self._on_stats_updated, Qt.QueuedConnection)
        self.web_engine.alerts_generated.connect(self._on_alerts_generated, Qt.QueuedConnection)
        self.web_engine.dns_resolved.connect(self._on_dns_resolved, Qt.QueuedConnection)
        self.web_engine.status_changed.connect(self._on_status_changed, Qt.QueuedConnection)
        self.web_engine.capture_error.connect(self._on_capture_error, Qt.QueuedConnection)
        self.web_engine.capture_stopped.connect(self._on_capture_stopped, Qt.QueuedConnection)

        self.capture_start_time = time.time()
        self.duration_timer.start()
        self.web_engine.start()

    def stop_capture(self):
        if self.web_engine and self.web_engine.isRunning():
            self.status_badge.setText("● STOPPING...")
            self.status_badge.setStyleSheet("color: #ff9100; font-weight: bold; font-size: 12px;")
            self.web_engine.stop()

    def _on_capture_stopped(self):
        self.duration_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.url_input.setEnabled(True)
        self.iface_combo.setEnabled(True)
        self.duration_combo.setEnabled(True)
        self.status_badge.setText("● STOPPED")
        self.status_badge.setStyleSheet("color: #ff9100; font-weight: bold; font-size: 12px;")

    def _on_status_changed(self, status_str: str):
        if status_str == "Capturing":
            self.status_badge.setText("● CAPTURING")
            self.status_badge.setStyleSheet("color: #00e676; font-weight: bold; font-size: 12px;")
        elif status_str == "Resolving Domain":
            self.status_badge.setText("● RESOLVING")
            self.status_badge.setStyleSheet("color: #ffd600; font-weight: bold; font-size: 12px;")
        elif status_str == "Stopped":
            self.status_badge.setText("● STOPPED")
            self.status_badge.setStyleSheet("color: #ff9100; font-weight: bold; font-size: 12px;")
        elif status_str == "Error":
            self.status_badge.setText("● ERROR")
            self.status_badge.setStyleSheet("color: #ff5252; font-weight: bold; font-size: 12px;")

    def _on_capture_error(self, err_msg: str):
        self._on_capture_stopped()
        self.status_badge.setText("● ERROR")
        self.status_badge.setStyleSheet("color: #ff5252; font-weight: bold; font-size: 12px;")
        QMessageBox.critical(self, "Capture Error", err_msg)

    def _on_dns_resolved(self, dns_info: dict):
        host = dns_info.get('hostname', '')
        ips = dns_info.get('all_ips', [])
        err = dns_info.get('error')

        if err:
            self.dns_summary_label.setText(f"<b>{host}</b>: <span style='color:#ff5252;'>{err}</span>")
            return

        ip_preview = ", ".join(ips[:4])
        if len(ips) > 4:
            ip_preview += f" (+{len(ips) - 4} more)"

        cdn_tag = " [Multi-IP / CDN]" if len(ips) > 1 else ""
        self.dns_summary_label.setText(
            f"<b>Target:</b> {host} &nbsp;|&nbsp; <b>Resolved IPs ({len(ips)}):</b> <span style='color:#00e5ff;'>{ip_preview}</span>{cdn_tag}"
        )

    def _update_session_duration(self):
        if self.capture_start_time > 0:
            elapsed = int(time.time() - self.capture_start_time)
            hrs = elapsed // 3600
            mins = (elapsed % 3600) // 60
            secs = elapsed % 60
            self.card_timer.set_value(f"{hrs:02d}:{mins:02d}:{secs:02d}")

    # -----------------------------------------------------------------
    # Real-Time Data Dispatchers
    # -----------------------------------------------------------------
    def _on_packet_captured(self, parsed_pkt: dict):
        self.captured_packets_data.append(parsed_pkt)
        if len(self.captured_packets_data) > 3000:
            self.captured_packets_data.pop(0)

        if not self.is_display_paused:
            self.table_queue.append(parsed_pkt)

    def _flush_table_batch(self):
        if not self.table_queue or self.is_display_paused:
            return

        self.packet_table.setUpdatesEnabled(False)
        while self.table_queue:
            pkt = self.table_queue.popleft()
            row = self.packet_table.rowCount()
            if row >= 2000:
                self.packet_table.removeRow(0)
                row = 1999
            self.packet_table.insertRow(row)

            # Columns
            ts = pkt.get('timestamp', 0)
            try:
                dt_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]
            except Exception:
                dt_str = "00:00:00.000"
            self.packet_table.setItem(row, 0, QTableWidgetItem(dt_str))
            self.packet_table.setItem(row, 1, QTableWidgetItem(str(pkt.get('src_ip', ''))))
            self.packet_table.setItem(row, 2, QTableWidgetItem(str(pkt.get('dst_ip', ''))))
            self.packet_table.setItem(row, 3, QTableWidgetItem(str(pkt.get('src_port') or '')))
            self.packet_table.setItem(row, 4, QTableWidgetItem(str(pkt.get('dst_port') or '')))
            self.packet_table.setItem(row, 5, QTableWidgetItem(str(pkt.get('protocol', ''))))
            self.packet_table.setItem(row, 6, QTableWidgetItem(str(pkt.get('size', 0))))

            dir_str = str(pkt.get('direction', ''))
            dir_item = QTableWidgetItem(dir_str)
            if "Incoming" in dir_str:
                dir_item.setForeground(pg.mkColor('#00e5ff'))
            else:
                dir_item.setForeground(pg.mkColor('#ff9100'))
            self.packet_table.setItem(row, 7, dir_item)

            self.packet_table.setItem(row, 8, QTableWidgetItem(str(pkt.get('tcp_flags', ''))))

            attr_str = str(pkt.get('attribution', ''))
            attr_item = QTableWidgetItem(attr_str)
            if "Verified SNI" in attr_str:
                attr_item.setForeground(pg.mkColor('#00e676'))
            elif "DNS" in attr_str:
                attr_item.setForeground(pg.mkColor('#ffd600'))
            self.packet_table.setItem(row, 9, attr_item)

            self.packet_table.setItem(row, 10, QTableWidgetItem(str(pkt.get('summary', ''))))

        self.packet_table.setUpdatesEnabled(True)
        self.pkt_count_lbl.setText(f"Packets: {self.packet_table.rowCount():,}")

        if self.autoscroll_box.isChecked():
            self.packet_table.scrollToBottom()

    def _on_stats_updated(self, stats: dict):
        self.stats_history.append(stats)
        if len(self.stats_history) > 600:
            self.stats_history.pop(0)

        in_bps = stats.get('incoming_bytes_per_sec', 0.0)
        out_bps = stats.get('outgoing_bytes_per_sec', 0.0)
        tot_bytes = stats.get('total_bytes', 0)
        tot_in_b = stats.get('total_incoming_bytes', 0)
        tot_out_b = stats.get('total_outgoing_bytes', 0)
        tot_pkts = stats.get('total_packets', 0)
        tot_in_p = stats.get('total_incoming_packets', 0)
        tot_out_p = stats.get('total_outgoing_packets', 0)
        active_conns = stats.get('active_connections', 0)

        # 1. Update KPI Cards
        self.card_bandwidth.set_value(f"⬇ {format_bytes(in_bps)}/s | ⬆ {format_bytes(out_bps)}/s")
        self.card_total_vol.set_value(f"{format_bytes(tot_bytes)} (⬇ {format_bytes(tot_in_b)} / ⬆ {format_bytes(tot_out_b)})")
        self.card_total_pkts.set_value(f"{tot_pkts:,} (⬇ {tot_in_p:,} / ⬆ {tot_out_p:,})")
        self.card_conns.set_value(f"{active_conns} active flows")

        # 2. Update Bandwidth Plot (Dual Curves)
        self.in_bytes_data.append(in_bps)
        self.out_bytes_data.append(out_bps)
        if len(self.in_bytes_data) > self.max_chart_points:
            self.in_bytes_data.pop(0)
            self.out_bytes_data.pop(0)

        x_axis = [i - self.max_chart_points + 1 for i in range(len(self.in_bytes_data))]
        self.in_curve.setData(x_axis, self.in_bytes_data)
        self.out_curve.setData(x_axis, self.out_bytes_data)

        # 3. Update Protocol Distribution Bars
        proto_counts = stats.get('protocol_counts', {})
        heights = [proto_counts.get(cat, 0) for cat in self.proto_categories]
        self.proto_bars.setOpts(height=heights)

        # 4. Update Observed Connections Table
        conns = stats.get('connection_list', [])
        self.conn_table.setRowCount(len(conns))
        for idx, c in enumerate(conns):
            self.conn_table.setItem(idx, 0, QTableWidgetItem(c.get('remote_endpoint', '')))
            self.conn_table.setItem(idx, 1, QTableWidgetItem(c.get('app_proto', c.get('protocol', ''))))
            
            st_item = QTableWidgetItem(c.get('state', ''))
            if c.get('state') == 'ESTABLISHED':
                st_item.setForeground(pg.mkColor('#00e676'))
            elif c.get('state') == 'SYN_SENT':
                st_item.setForeground(pg.mkColor('#ffd600'))
            self.conn_table.setItem(idx, 2, st_item)

            pkts_str = f"⬇ {c.get('packets_in', 0)} / ⬆ {c.get('packets_out', 0)}"
            self.conn_table.setItem(idx, 3, QTableWidgetItem(pkts_str))

            vol_str = format_bytes(c.get('total_bytes', 0))
            self.conn_table.setItem(idx, 4, QTableWidgetItem(vol_str))

            attr_item = QTableWidgetItem(c.get('attribution', ''))
            if "Verified SNI" in c.get('attribution', ''):
                attr_item.setForeground(pg.mkColor('#00e676'))
            self.conn_table.setItem(idx, 5, attr_item)

            last_dt = datetime.fromtimestamp(c.get('last_seen', 0)).strftime('%H:%M:%S')
            self.conn_table.setItem(idx, 6, QTableWidgetItem(last_dt))

    def _on_alerts_generated(self, alerts: list):
        for alert in alerts:
            self.alerts_history.append(alert)
            row = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row)

            ts_str = datetime.fromtimestamp(alert.get('timestamp', 0)).strftime('%H:%M:%S')
            self.alerts_table.setItem(row, 0, QTableWidgetItem(ts_str))

            sev = alert.get('severity', 'Info')
            sev_item = QTableWidgetItem(sev.upper())
            if sev == 'Critical':
                sev_item.setForeground(pg.mkColor('#ff5252'))
            elif sev == 'Warning':
                sev_item.setForeground(pg.mkColor('#ffb74d'))
            else:
                sev_item.setForeground(pg.mkColor('#81d4fa'))
            self.alerts_table.setItem(row, 1, sev_item)

            desc = alert.get('description', '')
            self.alerts_table.setItem(row, 2, QTableWidgetItem(desc))

        self.alerts_count_lbl.setText(f"{len(self.alerts_history)} alerts")

    # -----------------------------------------------------------------
    # Filters & Inspection
    # -----------------------------------------------------------------
    def _apply_table_filter(self):
        query = self.tbl_search.text().strip().lower()
        selected_proto = self.proto_filter.currentText()
        selected_dir = self.dir_filter.currentText()

        for row in range(self.packet_table.rowCount()):
            # Proto filter
            proto_item = self.packet_table.item(row, 5)
            proto_val = proto_item.text() if proto_item else ""
            if selected_proto != "All Protocols" and selected_proto.lower() not in proto_val.lower():
                self.packet_table.setRowHidden(row, True)
                continue

            # Direction filter
            dir_item = self.packet_table.item(row, 7)
            dir_val = dir_item.text() if dir_item else ""
            if selected_dir == "Incoming Only" and "Incoming" not in dir_val:
                self.packet_table.setRowHidden(row, True)
                continue
            elif selected_dir == "Outgoing Only" and "Outgoing" not in dir_val:
                self.packet_table.setRowHidden(row, True)
                continue

            # Search text query
            if query:
                match = False
                for col in range(self.packet_table.columnCount()):
                    cell = self.packet_table.item(row, col)
                    if cell and query in cell.text().lower():
                        match = True
                        break
                self.packet_table.setRowHidden(row, not match)
            else:
                self.packet_table.setRowHidden(row, False)

    def _on_pause_toggled(self, checked: bool):
        self.is_display_paused = checked

    def inspect_selected_packet(self):
        row = self.packet_table.currentRow()
        if row < 0 or row >= len(self.captured_packets_data):
            QMessageBox.information(self, "Inspect Packet", "Please select a packet from the table to inspect.")
            return

        pkt_data = self.captured_packets_data[row]
        dlg = PacketDetailsDialog(self, pkt_data)
        dlg.exec()

    def clear_table(self):
        self.table_queue.clear()
        self.captured_packets_data.clear()
        self.packet_table.setRowCount(0)
        self.pkt_count_lbl.setText("Packets: 0")

    def clear_alerts(self):
        self.alerts_history.clear()
        self.alerts_table.setRowCount(0)
        self.alerts_count_lbl.setText("0 alerts")

    def reset_all(self):
        if self.web_engine and self.web_engine.isRunning():
            self.stop_capture()

        self.clear_table()
        self.clear_alerts()
        self.stats_history.clear()

        # Reset charts
        self.in_bytes_data = [0.0] * self.max_chart_points
        self.out_bytes_data = [0.0] * self.max_chart_points
        x_axis = [i - self.max_chart_points + 1 for i in range(self.max_chart_points)]
        self.in_curve.setData(x_axis, self.in_bytes_data)
        self.out_curve.setData(x_axis, self.out_bytes_data)
        self.proto_bars.setOpts(height=[0] * len(self.proto_categories))
        self.conn_table.setRowCount(0)

        # Reset cards
        self.card_host.set_value("None", "#ffffff")
        self.card_bandwidth.set_value("0.0 B/s | 0.0 B/s")
        self.card_total_vol.set_value("0.0 B (⬇ 0B / ⬆ 0B)")
        self.card_total_pkts.set_value("0 (⬇ 0 / ⬆ 0)")
        self.card_conns.set_value("0 active")
        self.card_timer.set_value("00:00:00")
        self.status_badge.setText("● IDLE")
        self.status_badge.setStyleSheet("color: #8e8e9f; font-weight: bold; font-size: 12px;")
        self.dns_summary_label.setText("Enter a URL and click 'Capture Traffic' to resolve domain and monitor packets.")

    # -----------------------------------------------------------------
    # Export Functions
    # -----------------------------------------------------------------
    def export_pcap(self):
        if not self.web_engine:
            QMessageBox.information(self, "Export PCAP", "No packets captured for this website yet.")
            return

        raw_pkts = self.web_engine.get_raw_packets()
        if not raw_pkts:
            QMessageBox.information(self, "Export PCAP", "No raw packets available to export.")
            return

        host = getattr(self.web_engine.web_target, 'hostname', 'website').replace('.', '_')
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f"{host}_{ts}.pcap"

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Website Packets as PCAP", default_name, "PCAP Files (*.pcap)")
        if file_path:
            success = export_to_pcap(file_path, raw_pkts)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved {len(raw_pkts)} packets to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save PCAP file.")

    def export_stats(self):
        if not self.stats_history:
            QMessageBox.information(self, "Export Stats", "No statistics records generated yet.")
            return

        host = self.url_input.text().replace('https://', '').replace('http://', '').replace('/', '').replace('.', '_')
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f"{host}_stats_{ts}.csv"

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Traffic Statistics CSV", default_name, "CSV Files (*.csv)")
        if file_path:
            success = export_stats_to_csv(file_path, self.stats_history)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved statistics to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save CSV file.")

    def export_connections(self):
        if not self.web_engine or not self.web_engine.stats_aggregator.conn_tracker.connections:
            QMessageBox.information(self, "Export Connections", "No connection flows recorded yet.")
            return

        conns = self.web_engine.stats_aggregator.conn_tracker.get_connection_list()
        host = self.url_input.text().replace('https://', '').replace('http://', '').replace('/', '').replace('.', '_')
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f"{host}_connections_{ts}.csv"

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Connection Summary CSV", default_name, "CSV Files (*.csv)")
        if file_path:
            success = export_connections_to_csv(file_path, conns)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved {len(conns)} connection summaries to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save CSV file.")

    def export_alerts(self):
        if not self.alerts_history:
            QMessageBox.information(self, "Export Alerts", "No website alerts generated yet.")
            return

        host = self.url_input.text().replace('https://', '').replace('http://', '').replace('/', '').replace('.', '_')
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f"{host}_alerts_{ts}.csv"

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Website Anomaly Alerts CSV", default_name, "CSV Files (*.csv)")
        if file_path:
            success = export_alerts_to_csv(file_path, self.alerts_history)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved {len(self.alerts_history)} alerts to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save CSV file.")
