from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QProgressBar, QPushButton
)
from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor
import pyqtgraph as pg

from core.performance_monitor import PerformanceMonitor


class PerfMetricCard(QFrame):
    def __init__(self, title: str, initial_value: str = "-", color: str = "#00e5ff"):
        super().__init__()
        self.default_color = color
        self.setStyleSheet(f"""
            PerfMetricCard {{
                background-color: #25252c;
                border: 1px solid #363642;
                border-left: 4px solid {color};
                border-radius: 8px;
            }}
        """)
        v = QVBoxLayout(self)
        v.setContentsMargins(10, 8, 10, 8)
        v.setSpacing(2)

        self.lbl_t = QLabel(title.upper())
        self.lbl_t.setStyleSheet("color: #8e8e9f; font-size: 10px; font-weight: bold; letter-spacing: 0.5px;")
        v.addWidget(self.lbl_t)

        self.lbl_v = QLabel(initial_value)
        self.lbl_v.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
        v.addWidget(self.lbl_v)

        self.lbl_s = QLabel("")
        self.lbl_s.setStyleSheet("color: #707080; font-size: 10px;")
        v.addWidget(self.lbl_s)

    def set_value(self, val: str, subtext: str = "", color: str = None):
        self.lbl_v.setText(val)
        self.lbl_s.setText(subtext)
        if color:
            self.lbl_v.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")


class PerformanceMonitorWidget(QWidget):
    """
    Analyzer Performance Monitor Widget.
    Displays real-time process CPU, RAM memory, queue backlog,
    processing latency, packets/sec rate, and measured GUI FPS.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.monitor = PerformanceMonitor()

        self.history_cpu = []
        self.history_mem = []

        self.init_ui()

        # Update timer: 2 times per second (500ms)
        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self.update_metrics)
        self.timer.start()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header with Backend Drop Explanation
        head_frame = QFrame()
        head_frame.setStyleSheet("""
            QFrame {
                background-color: #1a1a24;
                border: 1px solid #2e2e40;
                border-radius: 6px;
                padding: 6px 12px;
            }
        """)
        h_box = QHBoxLayout(head_frame)
        h_box.setContentsMargins(4, 4, 4, 4)
        lbl_head = QLabel(
            "⚡ <b>Analyzer Runtime Performance:</b> Live instrumentation of process resource utilization, "
            "queue backlogs, and processing latencies. "
            "<br><span style='color:#a0a0b0; font-size:11px;'>Note: Internal queue drops are tracked in real-time. "
            "Kernel-level adapter drop statistics are managed directly by the Npcap/WinPcap Windows driver.</span>"
        )
        lbl_head.setWordWrap(True)
        lbl_head.setStyleSheet("color: #00e5ff; font-size: 12px;")
        h_box.addWidget(lbl_head)
        layout.addWidget(head_frame)

        # Metric Cards Row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(8)

        self.card_cpu = PerfMetricCard("CPU Usage", "0.0%", "#00e5ff")
        self.card_mem = PerfMetricCard("Memory (RSS)", "0.0 MB", "#00e676")
        self.card_pps = PerfMetricCard("Processing Rate", "0 pkts/s", "#ffd600")
        self.card_queue = PerfMetricCard("Queue Backlog", "0 pkts", "#448aff")
        self.card_latency = PerfMetricCard("Latency", "0.0 ms", "#b388ff")
        self.card_fps = PerfMetricCard("GUI Frame Rate", "0 FPS", "#00e5ff")
        self.card_drops = PerfMetricCard("Queue Drops", "0", "#ff5252")

        cards_layout.addWidget(self.card_cpu)
        cards_layout.addWidget(self.card_mem)
        cards_layout.addWidget(self.card_pps)
        cards_layout.addWidget(self.card_queue)
        cards_layout.addWidget(self.card_latency)
        cards_layout.addWidget(self.card_fps)
        cards_layout.addWidget(self.card_drops)
        layout.addLayout(cards_layout)

        # Performance Trends Plot
        self.perf_plot = pg.PlotWidget(title="CPU & Memory Utilization History")
        self.perf_plot.showGrid(x=True, y=True, alpha=0.25)
        self.perf_plot.setLabel('left', 'CPU (%) / Memory (MB)')
        self.perf_plot.setLabel('bottom', 'Time (Samples)')
        self.perf_plot.setYRange(0, 100, padding=0.05)
        self.curve_cpu = self.perf_plot.plot(pen=pg.mkPen('#00e5ff', width=2), name="CPU %")
        self.curve_mem = self.perf_plot.plot(pen=pg.mkPen('#00e676', width=2), name="Memory MB")
        layout.addWidget(self.perf_plot, 1)

    def update_metrics(self):
        metrics = self.monitor.get_metrics()

        cpu = metrics["cpu_percent"]
        mem = metrics["memory_mb"]
        pps = metrics["packets_per_sec"]
        backlog = metrics["queue_backlog"]
        drops = metrics["queue_drops"]
        lat = metrics["processing_latency_ms"]
        fps = metrics["gui_fps"]

        # Update cards
        self.card_cpu.set_value(f"{cpu:.1f}%", "Process CPU load", "#00e5ff" if cpu < 60 else "#ff5252")
        self.card_mem.set_value(f"{mem:.1f} MB", "Resident Set Size (RAM)", "#00e676" if mem < 500 else "#ffd600")
        self.card_pps.set_value(f"{pps:.0f} pkts/s", f"{metrics['total_packets_processed']:,} total")
        self.card_queue.set_value(f"{backlog:,} pkts", "Buffer queue depth", "#448aff" if backlog < 2000 else "#ff5252")
        self.card_latency.set_value(f"{lat:.2f} ms", "Arrival ➔ Parsed")
        self.card_fps.set_value(f"{fps:.1f} FPS", "GUI refresh cadence")
        self.card_drops.set_value(f"{drops:,}", "Queue overflow drops", "#00e676" if drops == 0 else "#ff5252")

        # Update history curves (keep last 60 samples)
        self.history_cpu.append(cpu)
        self.history_mem.append(mem)
        if len(self.history_cpu) > 60:
            self.history_cpu.pop(0)
            self.history_mem.pop(0)

        x_axis = list(range(len(self.history_cpu)))
        self.curve_cpu.setData(x_axis, self.history_cpu)
        self.curve_mem.setData(x_axis, self.history_mem)
