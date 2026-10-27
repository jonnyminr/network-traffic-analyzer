import os
import csv
import json
import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QProgressBar, QComboBox, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QMessageBox, QAbstractItemView
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush
import pyqtgraph as pg

from core.pcap_analyzer import PcapAnalysisWorker
from gui.packet_details_dialog import PacketDetailsDialog


def format_bytes_human(n: float) -> str:
    if n is None or n < 0:
        n = 0.0
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


class OfflineAnalysisWidget(QWidget):
    """
    Dedicated Offline PCAP / PCAPNG Analysis Station.
    Streams and processes captured files in the background without requiring Administrator
    privileges, completely isolated from active live capture sessions.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: PcapAnalysisWorker = None
        self.current_file_path = ""
        self.all_parsed_packets = []
        self.all_alerts = []

        self.proto_categories = ['TCP', 'UDP', 'ICMP', 'ARP', 'Other']
        self.throughput_history = []
        self.packet_rate_history = []

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # 1. Prominent Offline Mode Banner
        banner = QFrame()
        banner.setStyleSheet("""
            QFrame {
                background-color: #2b1f1f;
                border: 1px solid #ff5722;
                border-left: 5px solid #ff5722;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        h_ban = QHBoxLayout(banner)
        h_ban.setContentsMargins(6, 6, 6, 6)

        v_btext = QVBoxLayout()
        lbl_b1 = QLabel("📁 OFFLINE PCAP / PCAPNG ANALYSIS MODE")
        lbl_b1.setStyleSheet("color: #ff7043; font-weight: bold; font-size: 15px;")
        lbl_b2 = QLabel("Analyze captured files offline. Does not require Administrator privileges and will not affect live capture.")
        lbl_b2.setStyleSheet("color: #b0bec5; font-size: 11px;")
        v_btext.addWidget(lbl_b1)
        v_btext.addWidget(lbl_b2)
        h_ban.addLayout(v_btext, 1)

        self.lbl_file_status = QLabel("No file loaded")
        self.lbl_file_status.setStyleSheet("color: #ffd600; font-weight: bold; font-size: 12px;")
        h_ban.addWidget(self.lbl_file_status)

        main_layout.addWidget(banner)

        # 2. File Import & Playback Controls Bar
        ctrl_frame = QFrame()
        ctrl_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 6px; padding: 6px;")
        c_layout = QHBoxLayout(ctrl_frame)
        c_layout.setContentsMargins(6, 4, 6, 4)
        c_layout.setSpacing(8)

        self.btn_select_file = QPushButton("📂 Open PCAP / PCAPNG...")
        self.btn_select_file.setStyleSheet("background-color: #363642; color: #00e5ff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_select_file.clicked.connect(self.select_file)
        c_layout.addWidget(self.btn_select_file)

        self.btn_start = QPushButton("▶ Start Analysis")
        self.btn_start.setEnabled(False)
        self.btn_start.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 6px 16px; border-radius: 4px;")
        self.btn_start.clicked.connect(self.start_analysis)
        c_layout.addWidget(self.btn_start)

        self.btn_pause = QPushButton("⏸ Pause")
        self.btn_pause.setEnabled(False)
        self.btn_pause.setStyleSheet("background-color: #363642; color: white; padding: 6px 12px; border-radius: 4px;")
        self.btn_pause.clicked.connect(self.toggle_pause)
        c_layout.addWidget(self.btn_pause)

        self.btn_cancel = QPushButton("⏹ Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setStyleSheet("background-color: #363642; color: #ff5252; padding: 6px 12px; border-radius: 4px;")
        self.btn_cancel.clicked.connect(self.cancel_analysis)
        c_layout.addWidget(self.btn_cancel)

        c_layout.addSpacing(10)
        c_layout.addWidget(QLabel("Speed:"))
        self.cmb_speed = QComboBox()
        self.cmb_speed.addItem("Instant (Maximum Speed)", 0.0)
        self.cmb_speed.addItem("1x (Real-time replay)", 1.0)
        self.cmb_speed.addItem("5x Speed", 5.0)
        self.cmb_speed.addItem("10x Speed", 10.0)
        self.cmb_speed.currentIndexChanged.connect(self._on_speed_changed)
        self.cmb_speed.setStyleSheet("background: #1e1e24; color: #fff; padding: 4px; border: 1px solid #363642;")
        c_layout.addWidget(self.cmb_speed)

        c_layout.addStretch()

        self.btn_export = QPushButton("📥 Export Summary")
        self.btn_export.setStyleSheet("background-color: #363642; color: #00e5ff; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.btn_export.clicked.connect(self.export_results)
        c_layout.addWidget(self.btn_export)

        main_layout.addWidget(ctrl_frame)

        # 3. Progress Bar & Metadata Row
        prog_frame = QFrame()
        prog_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 6px; padding: 6px;")
        p_layout = QHBoxLayout(prog_frame)
        p_layout.setContentsMargins(6, 4, 6, 4)

        self.lbl_progress_info = QLabel("Select a capture file to begin.")
        self.lbl_progress_info.setStyleSheet("color: #e0e0e0; font-size: 11px;")
        p_layout.addWidget(self.lbl_progress_info, 1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedWidth(220)
        self.progress_bar.setStyleSheet("""
            QProgressBar { background-color: #1e1e24; border: 1px solid #363642; border-radius: 3px; }
            QProgressBar::chunk { background-color: #ff7043; }
        """)
        p_layout.addWidget(self.progress_bar)

        main_layout.addWidget(prog_frame)

        # 4. Analysis Dashboard Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #363642; background: #1e1e24; border-radius: 6px; }
            QTabBar::tab { background: #25252c; color: #a0a0b0; padding: 6px 14px; font-weight: bold; }
            QTabBar::tab:selected { background: #1e1e24; color: #ff7043; border-top: 2px solid #ff7043; }
        """)

        # TAB 1: Packet Table
        tab_pkts = QWidget()
        v_pkts = QVBoxLayout(tab_pkts)
        v_pkts.setContentsMargins(6, 6, 6, 6)

        # Search filter
        h_s = QHBoxLayout()
        self.txt_filter = QLineEdit()
        self.txt_filter.setPlaceholderText("Filter packets by IP, port, or protocol...")
        self.txt_filter.textChanged.connect(self._apply_packet_filter)
        self.txt_filter.setStyleSheet("background: #25252c; color: #fff; padding: 5px 10px; border: 1px solid #363642;")
        h_s.addWidget(self.txt_filter, 1)
        self.lbl_packet_count = QLabel("Packets: 0")
        self.lbl_packet_count.setStyleSheet("color: #ff7043; font-weight: bold;")
        h_s.addWidget(self.lbl_packet_count)
        v_pkts.addLayout(h_s)

        self.tbl_packets = QTableWidget(0, 7)
        self.tbl_packets.setHorizontalHeaderLabels([
            "#", "Time", "Source IP", "Src Port", "Destination IP", "Dst Port", "Protocol"
        ])
        self.tbl_packets.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_packets.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.tbl_packets.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_packets.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_packets.setStyleSheet("background: #1e1e24; color: #fff; border: 1px solid #363642;")
        self.tbl_packets.cellDoubleClicked.connect(self._on_packet_double_clicked)
        v_pkts.addWidget(self.tbl_packets)

        self.tabs.addTab(tab_pkts, "📦 Packet Inspector")

        # TAB 2: Charts & Top Talkers
        tab_charts = QWidget()
        v_charts = QVBoxLayout(tab_charts)
        v_charts.setContentsMargins(6, 6, 6, 6)
        h_plots = QHBoxLayout()

        # Throughput Plot
        self.plot_bw = pg.PlotWidget(title="Throughput Over Capture Duration")
        self.plot_bw.showGrid(x=True, y=True, alpha=0.25)
        self.plot_bw.setLabel('left', 'Bytes / sec')
        self.curve_bw = self.plot_bw.plot(pen=pg.mkPen('#ff7043', width=2), brush=pg.mkBrush(255, 112, 67, 40), fillLevel=0)
        h_plots.addWidget(self.plot_bw, 2)

        # Protocol Distribution Bar Chart
        self.plot_proto = pg.PlotWidget(title="Protocol Distribution")
        self.plot_proto.showGrid(x=False, y=True, alpha=0.25)
        proto_ax = self.plot_proto.getAxis('bottom')
        proto_ax.setTicks([[(i, name) for i, name in enumerate(self.proto_categories)]])
        self.proto_bars = pg.BarGraphItem(
            x=list(range(len(self.proto_categories))),
            height=[0] * len(self.proto_categories),
            width=0.6,
            brushes=[pg.mkColor('#448aff'), pg.mkColor('#00e676'), pg.mkColor('#ffd600'), pg.mkColor('#ff9100'), pg.mkColor('#b0bec5')]
        )
        self.plot_proto.addItem(self.proto_bars)
        h_plots.addWidget(self.plot_proto, 1)

        v_charts.addLayout(h_plots, 2)

        # Top Talkers
        lbl_tt = QLabel("Top Talkers in Capture File")
        lbl_tt.setStyleSheet("color: #d4d4d4; font-weight: bold; font-size: 12px;")
        v_charts.addWidget(lbl_tt)

        self.tbl_talkers = QTableWidget(0, 3)
        self.tbl_talkers.setHorizontalHeaderLabels(["Rank", "IP Address", "Volume Transferred"])
        self.tbl_talkers.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_talkers.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_talkers.setFixedHeight(120)
        self.tbl_talkers.setStyleSheet("background: #1e1e24; color: #fff; border: 1px solid #363642;")
        v_charts.addWidget(self.tbl_talkers, 1)

        self.tabs.addTab(tab_charts, "📊 Statistics & Charts")

        # TAB 3: Security Anomalies in PCAP
        tab_alerts = QWidget()
        v_al = QVBoxLayout(tab_alerts)
        v_al.setContentsMargins(6, 6, 6, 6)

        self.tbl_alerts = QTableWidget(0, 5)
        self.tbl_alerts.setHorizontalHeaderLabels(["Severity", "Alert Title", "Source IP", "Target", "Score / Rate"])
        self.tbl_alerts.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_alerts.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_alerts.setStyleSheet("background: #1e1e24; color: #fff; border: 1px solid #363642;")
        v_al.addWidget(self.tbl_alerts)

        self.tabs.addTab(tab_alerts, "🚨 Offline Security Alerts")

        main_layout.addWidget(self.tabs, 1)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Captured PCAP or PCAPNG File", "", "Packet Capture Files (*.pcap *.pcapng *.cap)"
        )
        if file_path:
            self.current_file_path = file_path
            fname = os.path.basename(file_path)
            fsize_mb = os.path.getsize(file_path) / (1024 * 1024)
            self.lbl_file_status.setText(f"Loaded: {fname} ({fsize_mb:.2f} MB)")
            self.lbl_progress_info.setText(f"Ready to analyze {fname}. Click 'Start Analysis' to process.")
            self.btn_start.setEnabled(True)
            self._reset_views()

    def _reset_views(self):
        self.all_parsed_packets.clear()
        self.all_alerts.clear()
        self.throughput_history.clear()
        self.packet_rate_history.clear()
        self.tbl_packets.setRowCount(0)
        self.tbl_talkers.setRowCount(0)
        self.tbl_alerts.setRowCount(0)
        self.progress_bar.setValue(0)
        self.lbl_packet_count.setText("Packets: 0")
        self.proto_bars.setOpts(height=[0] * len(self.proto_categories))
        self.curve_bw.setData([], [])

    def start_analysis(self):
        if not self.current_file_path:
            return

        self._reset_views()
        self.btn_start.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_cancel.setEnabled(True)
        self.btn_select_file.setEnabled(False)

        speed = self.cmb_speed.currentData() or 0.0
        self.worker = PcapAnalysisWorker(self.current_file_path, speed_multiplier=speed)
        self.worker.progress_updated.connect(self._on_progress)
        self.worker.batch_processed.connect(self._on_batch_packets)
        self.worker.stats_updated.connect(self._on_stats_updated)
        self.worker.alerts_generated.connect(self._on_alerts_generated)
        self.worker.analysis_completed.connect(self._on_completed)
        self.worker.analysis_error.connect(self._on_error)
        self.worker.start()

    def toggle_pause(self):
        if not self.worker:
            return
        if self.worker.is_paused:
            self.worker.resume()
            self.btn_pause.setText("⏸ Pause")
        else:
            self.worker.pause()
            self.btn_pause.setText("▶ Resume")

    def cancel_analysis(self):
        if self.worker:
            self.worker.cancel()
            self._cleanup_worker_state()
            self.lbl_progress_info.setText("Analysis cancelled by user.")

    def _on_speed_changed(self, idx):
        if self.worker:
            speed = self.cmb_speed.itemData(idx)
            self.worker.set_speed(speed)

    def _on_progress(self, current_pkt: int, total_estimate: int, pct: float):
        self.progress_bar.setValue(int(pct))
        self.lbl_progress_info.setText(f"Processing packet #{current_pkt:,} of ~{total_estimate:,} ({pct:.1f}%)...")
        self.lbl_packet_count.setText(f"Packets: {current_pkt:,}")

    def _on_batch_packets(self, packets: list):
        self.all_parsed_packets.extend(packets)
        # Cap table display rows to 2000 for smooth UI performance
        max_display = 2000
        cur_row = self.tbl_packets.rowCount()

        self.tbl_packets.setUpdatesEnabled(False)
        for pkt in packets:
            if cur_row >= max_display:
                break
            self.tbl_packets.insertRow(cur_row)
            self.tbl_packets.setItem(cur_row, 0, QTableWidgetItem(str(pkt.get("packet_num", cur_row + 1))))
            
            ts_str = datetime.datetime.fromtimestamp(pkt.get("timestamp", 0)).strftime("%H:%M:%S.%f")[:-3]
            self.tbl_packets.setItem(cur_row, 1, QTableWidgetItem(ts_str))
            self.tbl_packets.setItem(cur_row, 2, QTableWidgetItem(str(pkt.get("src_ip", ""))))
            self.tbl_packets.setItem(cur_row, 3, QTableWidgetItem(str(pkt.get("src_port") or "")))
            self.tbl_packets.setItem(cur_row, 4, QTableWidgetItem(str(pkt.get("dst_ip", ""))))
            self.tbl_packets.setItem(cur_row, 5, QTableWidgetItem(str(pkt.get("dst_port") or "")))
            self.tbl_packets.setItem(cur_row, 6, QTableWidgetItem(str(pkt.get("protocol", ""))))
            cur_row += 1

        self.tbl_packets.setUpdatesEnabled(True)

    def _on_stats_updated(self, stats: dict):
        bps = stats.get('bytes_per_sec', 0.0)
        self.throughput_history.append(bps)
        if len(self.throughput_history) > 120:
            self.throughput_history.pop(0)
        self.curve_bw.setData(list(range(len(self.throughput_history))), self.throughput_history)

        # Update protocol distribution
        proto_counts = stats.get('protocol_counts', {})
        heights = [proto_counts.get(p, 0) for p in self.proto_categories]
        self.proto_bars.setOpts(height=heights)

        # Update top talkers
        talkers = stats.get('top_talkers', [])
        self.tbl_talkers.setRowCount(len(talkers))
        for idx, (ip, b) in enumerate(talkers):
            self.tbl_talkers.setItem(idx, 0, QTableWidgetItem(f"#{idx + 1}"))
            self.tbl_talkers.setItem(idx, 1, QTableWidgetItem(str(ip)))
            self.tbl_talkers.setItem(idx, 2, QTableWidgetItem(format_bytes_human(b)))

    def _on_alerts_generated(self, alerts: list):
        self.all_alerts.extend(alerts)
        self.tbl_alerts.setRowCount(len(self.all_alerts))
        for row, a in enumerate(self.all_alerts):
            sev = a.get("severity", "Medium")
            s_item = QTableWidgetItem(sev)
            s_item.setForeground(QBrush(QColor("#ff5252" if sev in ("Critical", "High") else "#ffd600")))
            self.tbl_alerts.setItem(row, 0, s_item)
            self.tbl_alerts.setItem(row, 1, QTableWidgetItem(a.get("title", "")))
            self.tbl_alerts.setItem(row, 2, QTableWidgetItem(str(a.get("src_ip", ""))))
            self.tbl_alerts.setItem(row, 3, QTableWidgetItem(str(a.get("dst_ip", ""))))
            self.tbl_alerts.setItem(row, 4, QTableWidgetItem(f"{a.get('current_rate', '')}"))

    def _on_completed(self, summary: dict):
        self._cleanup_worker_state()
        self.progress_bar.setValue(100)
        dur = summary.get("capture_duration_seconds", 0)
        tot_pkts = summary.get("total_packets", 0)
        tot_bytes = format_bytes_human(summary.get("total_bytes", 0))
        self.lbl_progress_info.setText(
            f"✅ Complete: {tot_pkts:,} packets analyzed ({tot_bytes}) spanning {dur:.1f}s capture duration."
        )
        QMessageBox.information(
            self, "Analysis Complete",
            f"Successfully analyzed {summary.get('file_name')}:\n\n"
            f"• Total Packets: {tot_pkts:,}\n"
            f"• Total Traffic: {tot_bytes}\n"
            f"• Duration: {dur:.1f} seconds\n"
            f"• Unique Flows: {summary.get('unique_flows_count', 0)}\n"
            f"• Security Alerts: {summary.get('alerts_count', 0)}"
        )

    def _on_error(self, err_msg: str):
        self._cleanup_worker_state()
        self.lbl_progress_info.setText(f"Error: {err_msg}")
        QMessageBox.critical(self, "Offline Analysis Error", err_msg)

    def _cleanup_worker_state(self):
        self.btn_start.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_cancel.setEnabled(False)
        self.btn_select_file.setEnabled(True)
        self.btn_pause.setText("⏸ Pause")

    def _apply_packet_filter(self, text: str):
        q = text.strip().lower()
        for r in range(self.tbl_packets.rowCount()):
            if not q:
                self.tbl_packets.setRowHidden(r, False)
            else:
                match = False
                for c in range(self.tbl_packets.columnCount()):
                    it = self.tbl_packets.item(r, c)
                    if it and q in it.text().lower():
                        match = True
                        break
                self.tbl_packets.setRowHidden(r, not match)

    def _on_packet_double_clicked(self, row: int, col: int):
        if row < len(self.all_parsed_packets):
            pkt_dict = self.all_parsed_packets[row]
            dlg = PacketDetailsDialog(pkt_dict, parent=self)
            dlg.exec()

    def export_results(self):
        if not self.all_parsed_packets:
            QMessageBox.information(self, "Export", "No parsed packets or analysis results available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Offline PCAP Analysis Summary", "offline_analysis.csv", "CSV Files (*.csv)"
        )
        if file_path:
            try:
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(
                        f, fieldnames=["packet_num", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "size"],
                        extrasaction="ignore"
                    )
                    writer.writeheader()
                    for p in self.all_parsed_packets:
                        writer.writerow(p)
                QMessageBox.information(self, "Export Complete", f"Successfully exported {len(self.all_parsed_packets)} packets to:\n{file_path}")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Failed to export results: {e}")
