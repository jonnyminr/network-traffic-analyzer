import time
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame,
    QScrollArea
)
from PySide6.QtCore import Qt, Signal
import pyqtgraph as pg

from core.recommendations_engine import RecommendationsEngine
from core.performance_monitor import PerformanceMonitor
from core.alert_manager import AlertManager
from gui.tooltips_helper import get_tooltip

# Configure pyqtgraph global options before creating widget instances
pg.setConfigOption('background', '#1e1e24')
pg.setConfigOption('foreground', '#d4d4d4')
pg.setConfigOption('antialias', True)

def format_bytes(n: float) -> str:
    """Format bytes into human-readable units (B, KB, MB, GB)."""
    if n is None or n < 0:
        n = 0.0
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"

class MetricCard(QFrame):
    """A modern KPI summary card widget with a title and large value."""
    def __init__(self, title: str, initial_value: str = "0", color: str = "#00e5ff"):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.default_color = color
        self.setStyleSheet("""
            MetricCard {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)
        
        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet("color: #8e8e9f; font-size: 11px; font-weight: bold; letter-spacing: 0.8px;")
        layout.addWidget(self.title_label)
        
        self.value_label = QLabel(initial_value)
        self.value_label.setStyleSheet(f"color: {self.default_color}; font-size: 20px; font-weight: bold;")
        layout.addWidget(self.value_label)
        
    def set_value(self, text: str, color: str = None):
        self.value_label.setText(text)
        use_color = color if color else self.default_color
        self.value_label.setStyleSheet(f"color: {use_color}; font-size: 20px; font-weight: bold;")

class DashboardWidget(QWidget):
    ip_clicked = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.max_points = 60 # 60 seconds rolling window
        
        # Rolling data buffers
        self.bytes_data = [0.0] * self.max_points
        self.packets_data = [0.0] * self.max_points
        self.proto_categories = ['TCP', 'UDP', 'ICMP', 'ARP', 'Other']
        
        self.perf_monitor = PerformanceMonitor()
        self.alert_manager = AlertManager()
        self.update_count = 0
        
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(8)

        # 0. Analyzer Performance Strip (Feature 1E)
        perf_strip = QFrame()
        perf_strip.setStyleSheet("""
            QFrame {
                background-color: #1e1e24;
                border: 1px solid #2e2e3a;
                border-radius: 6px;
                padding: 4px 10px;
            }
        """)
        h_perf = QHBoxLayout(perf_strip)
        h_perf.setContentsMargins(4, 2, 4, 2)
        h_perf.setSpacing(16)

        lbl_p_title = QLabel("⚡ ANALYZER PERFORMANCE:")
        lbl_p_title.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 11px;")
        h_perf.addWidget(lbl_p_title)

        self.lbl_perf_cpu = QLabel("CPU: 0.0%")
        self.lbl_perf_cpu.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        h_perf.addWidget(self.lbl_perf_cpu)

        self.lbl_perf_mem = QLabel("RAM: 0.0 MB")
        self.lbl_perf_mem.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        h_perf.addWidget(self.lbl_perf_mem)

        self.lbl_perf_q = QLabel("Queue: 0")
        self.lbl_perf_q.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        h_perf.addWidget(self.lbl_perf_q)

        self.lbl_perf_lat = QLabel("Latency: 0.0 ms")
        self.lbl_perf_lat.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        h_perf.addWidget(self.lbl_perf_lat)

        self.lbl_perf_fps = QLabel("GUI: 0.0 FPS")
        self.lbl_perf_fps.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        h_perf.addWidget(self.lbl_perf_fps)

        self.lbl_perf_drops = QLabel("Drops: 0")
        self.lbl_perf_drops.setStyleSheet("color: #00e676; font-size: 11px; font-weight: bold;")
        h_perf.addWidget(self.lbl_perf_drops)

        h_perf.addStretch()
        main_layout.addWidget(perf_strip)
        
        # 1. KPI Cards Row with Educational Tooltips (Feature 3D)
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(8)
        self.card_throughput = MetricCard("Current Bandwidth", "0.0 B/s", "#00e5ff")
        self.card_throughput.setToolTip(get_tooltip("Bandwidth"))
        
        self.card_packet_rate = MetricCard("Packet Rate", "0 pkts/s", "#00e676")
        self.card_packet_rate.setToolTip(get_tooltip("Packet rate"))
        
        self.card_total_volume = MetricCard("Total Volume", "0.0 B", "#ffd600")
        self.card_total_volume.setToolTip("Total cumulative network volume transferred during this capture session.")
        
        self.card_total_packets = MetricCard("Total Packets", "0", "#ff9100")
        self.card_total_packets.setToolTip("Total count of network packets captured and parsed.")
        
        kpi_layout.addWidget(self.card_throughput)
        kpi_layout.addWidget(self.card_packet_rate)
        kpi_layout.addWidget(self.card_total_volume)
        kpi_layout.addWidget(self.card_total_packets)
        main_layout.addLayout(kpi_layout)
        
        # 2. Charts Row (Throughput, Packet Rate, Protocol Distribution)
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(8)
        
        # Throughput Plot
        self.throughput_plot = pg.PlotWidget(title="Bandwidth Throughput")
        self.throughput_plot.setToolTip(get_tooltip("Bandwidth"))
        self.throughput_plot.showGrid(x=True, y=True, alpha=0.25)
        self.throughput_plot.setLabel('left', 'Bytes / sec')
        self.throughput_plot.setLabel('bottom', 'Time (s)')
        self.throughput_plot.setXRange(-60, 0, padding=0.02)
        self.bytes_curve = self.throughput_plot.plot(
            pen=pg.mkPen('#00e5ff', width=2),
            fillLevel=0,
            brush=pg.mkBrush(0, 229, 255, 35)
        )
        charts_layout.addWidget(self.throughput_plot, stretch=3)
        
        # Packet Rate Plot
        self.packet_plot = pg.PlotWidget(title="Packet Rate")
        self.packet_plot.setToolTip(get_tooltip("Packet rate"))
        self.packet_plot.showGrid(x=True, y=True, alpha=0.25)
        self.packet_plot.setLabel('left', 'Packets / sec')
        self.packet_plot.setLabel('bottom', 'Time (s)')
        self.packet_plot.setXRange(-60, 0, padding=0.02)
        self.packets_curve = self.packet_plot.plot(
            pen=pg.mkPen('#00e676', width=2),
            fillLevel=0,
            brush=pg.mkBrush(0, 230, 118, 35)
        )
        charts_layout.addWidget(self.packet_plot, stretch=3)
        
        # Protocol Distribution Bar Chart
        self.proto_plot = pg.PlotWidget(title="Protocol Breakdown")
        self.proto_plot.setToolTip(get_tooltip("TCP"))
        self.proto_plot.showGrid(x=False, y=True, alpha=0.25)
        self.proto_plot.setLabel('left', 'Packets')
        proto_ax = self.proto_plot.getAxis('bottom')
        proto_ax.setTicks([[(i, name) for i, name in enumerate(self.proto_categories)]])
        
        self.proto_bars = pg.BarGraphItem(
            x=list(range(len(self.proto_categories))),
            height=[0] * len(self.proto_categories),
            width=0.6,
            brushes=[
                pg.mkColor('#448aff'), # TCP (blue)
                pg.mkColor('#00e676'), # UDP (green)
                pg.mkColor('#ffd600'), # ICMP (yellow)
                pg.mkColor('#ff9100'), # ARP (orange)
                pg.mkColor('#b0bec5')  # Other (gray)
            ]
        )
        self.proto_plot.addItem(self.proto_bars)
        charts_layout.addWidget(self.proto_plot, stretch=2)
        
        main_layout.addLayout(charts_layout, stretch=3)
        
        # 3. Bottom Row: Split between Top Talkers and Recommendations
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(8)

        # Left: Top Talkers Table
        talkers_frame = QFrame()
        talkers_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 6px; padding: 6px;")
        v_talkers = QVBoxLayout(talkers_frame)
        v_talkers.setContentsMargins(4, 4, 4, 4)
        v_talkers.setSpacing(4)

        lbl_tt = QLabel("Top Talkers (Cumulative Bandwidth)")
        lbl_tt.setStyleSheet("font-weight: bold; font-size: 12px; color: #d4d4d4;")
        v_talkers.addWidget(lbl_tt)
        
        self.talkers_table = QTableWidget(0, 4)
        self.talkers_table.setHorizontalHeaderLabels(["Rank", "IP Address", "Total Traffic", "% Share"])
        self.talkers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.talkers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.talkers_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.talkers_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.talkers_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.talkers_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.talkers_table.setStyleSheet("background-color: #1e1e24; color: #e0e0e0; border: none;")
        self.talkers_table.cellDoubleClicked.connect(self._on_talker_double_clicked)
        v_talkers.addWidget(self.talkers_table, 1)

        bottom_layout.addWidget(talkers_frame, stretch=3)

        # Right: Network Insights & Recommendations (Feature 6E)
        recs_frame = QFrame()
        recs_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 6px; padding: 6px;")
        v_recs = QVBoxLayout(recs_frame)
        v_recs.setContentsMargins(6, 4, 6, 4)
        v_recs.setSpacing(4)

        lbl_rec_title = QLabel("💡 Network Insights & Practical Recommendations")
        lbl_rec_title.setStyleSheet("font-weight: bold; font-size: 12px; color: #ffd600;")
        v_recs.addWidget(lbl_rec_title)

        self.lbl_recs_content = QLabel(
            "• Establishing baseline traffic patterns...\n"
            "• No severe anomalies or bandwidth bottlenecks detected.\n"
            "• Tip: Double-click any Top Talker IP to inspect its active flows in Network Connections."
        )
        self.lbl_recs_content.setWordWrap(True)
        self.lbl_recs_content.setStyleSheet("color: #d4d4d4; font-size: 11px; line-height: 1.4;")
        v_recs.addWidget(self.lbl_recs_content, 1)

        bottom_layout.addWidget(recs_frame, stretch=2)
        
        main_layout.addLayout(bottom_layout, stretch=2)

    def _on_talker_double_clicked(self, row: int, col: int):
        item = self.talkers_table.item(row, 1)
        if item:
            self.ip_clicked.emit(item.text().strip())

    def update_stats(self, stats: dict):
        """
        Receives stats dict emitted by CaptureEngine.
        Updates charts, KPI cards, top talkers, performance strip, and recommendations.
        """
        self.update_count += 1
        self.perf_monitor.record_gui_frame()

        bps = stats.get('bytes_per_sec', 0.0)
        pps = stats.get('packets_per_sec', 0.0)
        total_b = stats.get('total_bytes', 0)
        total_p = stats.get('total_packets', 0)
        
        # Update KPI Cards
        self.card_throughput.set_value(f"{format_bytes(bps)}/s")
        self.card_packet_rate.set_value(f"{pps:.0f} pkts/s")
        self.card_total_volume.set_value(format_bytes(total_b))
        self.card_total_packets.set_value(f"{total_p:,}")
        
        # Rolling Time-Series Data (-60s to 0s)
        self.bytes_data.append(bps)
        self.packets_data.append(pps)
        if len(self.bytes_data) > self.max_points:
            self.bytes_data.pop(0)
            self.packets_data.pop(0)
            
        x_axis = [i - self.max_points + 1 for i in range(len(self.bytes_data))]
        self.bytes_curve.setData(x_axis, self.bytes_data)
        self.packets_curve.setData(x_axis, self.packets_data)
        
        # Update Protocol Distribution Bar Chart
        proto_counts = stats.get('protocol_counts', {})
        heights = [proto_counts.get(p, 0) for p in self.proto_categories]
        self.proto_bars.setOpts(height=heights)
        
        # Update Top Talkers Table
        talkers = stats.get('top_talkers', [])
        total_talker_bytes = sum(b for _, b in talkers) or 1
        self.talkers_table.setRowCount(len(talkers))
        for idx, (ip, bytes_count) in enumerate(talkers):
            self.talkers_table.setItem(idx, 0, QTableWidgetItem(f"#{idx + 1}"))
            self.talkers_table.setItem(idx, 1, QTableWidgetItem(str(ip)))
            self.talkers_table.setItem(idx, 2, QTableWidgetItem(format_bytes(bytes_count)))
            pct = (bytes_count / total_talker_bytes) * 100
            self.talkers_table.setItem(idx, 3, QTableWidgetItem(f"{pct:.1f}%"))

        # Update Analyzer Performance Strip (Feature 1E)
        metrics = self.perf_monitor.get_metrics()
        self.lbl_perf_cpu.setText(f"CPU: {metrics['cpu_percent']}%")
        self.lbl_perf_mem.setText(f"RAM: {metrics['memory_mb']:.0f} MB")
        self.lbl_perf_q.setText(f"Queue: {metrics['queue_backlog']}")
        self.lbl_perf_lat.setText(f"Latency: {metrics['processing_latency_ms']:.1f}ms")
        self.lbl_perf_fps.setText(f"GUI: {metrics['gui_fps']:.0f} FPS")
        drops = metrics['queue_drops']
        self.lbl_perf_drops.setText(f"Drops: {drops}")
        self.lbl_perf_drops.setStyleSheet("color: #ff5252; font-weight: bold;" if drops > 0 else "color: #00e676; font-size: 11px;")

        # Periodic refresh of recommendations (every 3 stats updates)
        if self.update_count % 3 == 0:
            alerts = self.alert_manager.get_all_alerts_snapshot()
            recs = RecommendationsEngine.generate_recommendations(stats, alerts)
            if recs:
                rec_lines = [f"• <b>{r['title']}:</b> {r['recommendation']}" for r in recs[:3]]
                self.lbl_recs_content.setText("<br><br>".join(rec_lines))

    def reset_dashboard(self):
        """Resets all metrics, charts, and tables to initial blank state."""
        self.bytes_data = [0.0] * self.max_points
        self.packets_data = [0.0] * self.max_points
        x_axis = [i - self.max_points + 1 for i in range(self.max_points)]
        self.bytes_curve.setData(x_axis, self.bytes_data)
        self.packets_curve.setData(x_axis, self.packets_data)
        self.proto_bars.setOpts(height=[0] * len(self.proto_categories))
        self.talkers_table.setRowCount(0)
        self.card_throughput.set_value("0.0 B/s")
        self.card_packet_rate.set_value("0 pkts/s")
        self.card_total_volume.set_value("0.0 B")
        self.card_total_packets.set_value("0")
        self.lbl_recs_content.setText("• Session data cleared. Start capture to observe traffic.")
