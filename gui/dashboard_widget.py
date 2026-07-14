from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView
import pyqtgraph as pg
import collections

class DashboardWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
        # Data for plots
        self.time_data = []
        self.bytes_data = []
        self.packets_data = []
        self.max_points = 60 # 60 seconds of history on chart

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Top half: Charts
        charts_layout = QHBoxLayout()
        
        # Throughput Chart (pyqtgraph)
        self.throughput_plot = pg.PlotWidget(title="Throughput (Bytes/sec)")
        self.throughput_plot.setBackground('w')
        self.throughput_plot.showGrid(x=True, y=True)
        self.bytes_curve = self.throughput_plot.plot(pen=pg.mkPen('b', width=2))
        charts_layout.addWidget(self.throughput_plot)
        
        # Packet Rate Chart
        self.packet_plot = pg.PlotWidget(title="Packet Rate (Packets/sec)")
        self.packet_plot.setBackground('w')
        self.packet_plot.showGrid(x=True, y=True)
        self.packets_curve = self.packet_plot.plot(pen=pg.mkPen('r', width=2))
        charts_layout.addWidget(self.packet_plot)
        
        layout.addLayout(charts_layout)
        
        # Bottom half: Top talkers table
        bottom_layout = QVBoxLayout()
        label = QLabel("Top Talkers (By Bytes)")
        label.setStyleSheet("font-weight: bold; font-size: 14px;")
        bottom_layout.addWidget(label)
        
        self.talkers_table = QTableWidget(0, 2)
        self.talkers_table.setHorizontalHeaderLabels(["IP Address", "Bytes"])
        self.talkers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        bottom_layout.addWidget(self.talkers_table)
        
        layout.addLayout(bottom_layout)

    def update_stats(self, stats):
        """
        stats is a dict emitted by StatsAggregator
        """
        # Update charts
        self.time_data.append(stats['timestamp'])
        self.bytes_data.append(stats['bytes_per_sec'])
        self.packets_data.append(stats['packets_per_sec'])
        
        if len(self.time_data) > self.max_points:
            self.time_data.pop(0)
            self.bytes_data.pop(0)
            self.packets_data.pop(0)
            
        # We need relative time for X axis to look good, or just an index
        x_axis = list(range(len(self.bytes_data)))
        
        self.bytes_curve.setData(x_axis, self.bytes_data)
        self.packets_curve.setData(x_axis, self.packets_data)
        
        # Update Top Talkers
        self.talkers_table.setRowCount(0)
        for idx, (ip, bytes_count) in enumerate(stats['top_talkers']):
            self.talkers_table.insertRow(idx)
            self.talkers_table.setItem(idx, 0, QTableWidgetItem(str(ip)))
            self.talkers_table.setItem(idx, 1, QTableWidgetItem(str(bytes_count)))
