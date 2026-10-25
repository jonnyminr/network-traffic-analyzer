import time
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                               QTableWidget, QTableWidgetItem, QHeaderView, QFrame)
from PySide6.QtCore import Qt, Signal
import pyqtgraph as pg

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
        
        # Initialize rolling data buffers with zeros
        self.bytes_data = [0.0] * self.max_points
        self.packets_data = [0.0] * self.max_points
        self.proto_categories = ['TCP', 'UDP', 'ICMP', 'ARP', 'Other']
        
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(4, 4, 4, 4)
        main_layout.setSpacing(10)
        
        # 1. KPI Cards Row
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(10)
        self.card_throughput = MetricCard("Current Bandwidth", "0.0 B/s", "#00e5ff")
        self.card_packet_rate = MetricCard("Packet Rate", "0 pkts/s", "#00e676")
        self.card_total_volume = MetricCard("Total Volume", "0.0 B", "#ffd600")
        self.card_total_packets = MetricCard("Total Packets", "0", "#ff9100")
        
        kpi_layout.addWidget(self.card_throughput)
        kpi_layout.addWidget(self.card_packet_rate)
        kpi_layout.addWidget(self.card_total_volume)
        kpi_layout.addWidget(self.card_total_packets)
        main_layout.addLayout(kpi_layout)
        
        # 2. Charts Row (Throughput, Packet Rate, Protocol Distribution)
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(10)
        
        # Throughput Plot
        self.throughput_plot = pg.PlotWidget(title="Bandwidth Throughput")
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
        
        # 3. Bottom Row: Top Talkers Table
        bottom_layout = QVBoxLayout()
        bottom_layout.setSpacing(4)
        label = QLabel("Top Talkers (Cumulative Bandwidth)")
        label.setStyleSheet("font-weight: bold; font-size: 13px; color: #d4d4d4;")
        bottom_layout.addWidget(label)
        
        self.talkers_table = QTableWidget(0, 4)
        self.talkers_table.setHorizontalHeaderLabels(["Rank", "IP Address", "Total Traffic", "% Share"])
        self.talkers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.talkers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.talkers_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.talkers_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.talkers_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.talkers_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.talkers_table.setMinimumHeight(140)
        self.talkers_table.cellDoubleClicked.connect(self._on_talker_double_clicked)
        bottom_layout.addWidget(self.talkers_table, stretch=1)
        
        main_layout.addLayout(bottom_layout, stretch=2)

    def _on_talker_double_clicked(self, row: int, col: int):
        item = self.talkers_table.item(row, 1)
        if item:
            self.ip_clicked.emit(item.text().strip())

    def update_stats(self, stats: dict):
        """
        Receives stats dict emitted by CaptureEngine / StatsAggregator.
        Updates charts, KPI cards, and the top talkers table.
        """
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
