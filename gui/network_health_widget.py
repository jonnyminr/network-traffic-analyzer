import time
import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QProgressBar, QComboBox, QLineEdit, QTabWidget,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QCheckBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QBrush
import pyqtgraph as pg

from core.network_health import NetworkHealthTester
from core.incident_db import IncidentDatabase


class HealthMetricCard(QFrame):
    def __init__(self, title: str, initial_value: str = "-", color: str = "#00e5ff"):
        super().__init__()
        self.default_color = color
        self.setStyleSheet(f"""
            HealthMetricCard {{
                background-color: #25252c;
                border: 1px solid #363642;
                border-left: 4px solid {color};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        self.title_label = QLabel(title.upper())
        self.title_label.setStyleSheet("color: #8e8e9f; font-size: 11px; font-weight: bold; letter-spacing: 0.8px;")
        layout.addWidget(self.title_label)

        self.value_label = QLabel(initial_value)
        self.value_label.setStyleSheet(f"color: {self.default_color}; font-size: 18px; font-weight: bold;")
        layout.addWidget(self.value_label)

        self.sub_label = QLabel("")
        self.sub_label.setStyleSheet("color: #707080; font-size: 11px;")
        layout.addWidget(self.sub_label)

    def set_value(self, text: str, subtext: str = "", color: str = None):
        self.value_label.setText(text)
        self.sub_label.setText(subtext)
        use_color = color if color else self.default_color
        self.value_label.setStyleSheet(f"color: {use_color}; font-size: 18px; font-weight: bold;")


class NetworkHealthWidget(QWidget):
    """
    Dedicated Network Health monitoring and diagnostics interface.
    Features active ping/DNS/gateway tests, real-time metrics, historical trends,
    and plain-English connectivity guidance.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.db = IncidentDatabase()
        self.tester: NetworkHealthTester = None
        self.auto_timer = QTimer(self)
        self.auto_timer.timeout.connect(self.run_diagnostics)

        self.init_ui()
        self.load_history()

        # Run initial diagnostic 1 second after startup
        QTimer.singleShot(1000, self.run_diagnostics)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # 1. Top Informational Notice (Active test distinction)
        notice_frame = QFrame()
        notice_frame.setStyleSheet("""
            QFrame {
                background-color: #1a2233;
                border: 1px solid #283e66;
                border-radius: 6px;
                padding: 6px 12px;
            }
        """)
        h_note = QHBoxLayout(notice_frame)
        h_note.setContentsMargins(4, 4, 4, 4)
        lbl_note = QLabel(
            "ℹ️ <b>Active Connectivity Testing:</b> Network Health generates small, safe active test probes (DNS, gateway, and latency checks) "
            "to assess your internet and router connection quality. This is separate from passive packet capture."
        )
        lbl_note.setWordWrap(True)
        lbl_note.setStyleSheet("color: #82b1ff; font-size: 11px;")
        h_note.addWidget(lbl_note)
        main_layout.addWidget(notice_frame)

        # 2. Main Conclusion Banner
        self.banner = QFrame()
        self.banner.setStyleSheet("""
            QFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        b_layout = QHBoxLayout(self.banner)
        b_layout.setContentsMargins(8, 8, 8, 8)

        v_sum = QVBoxLayout()
        self.lbl_status_badge = QLabel("CONNECTIVITY DIAGNOSTICS")
        self.lbl_status_badge.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 16px;")
        self.lbl_summary = QLabel("Click 'Run Diagnostics' to test network connectivity.")
        self.lbl_summary.setStyleSheet("color: #e0e0e0; font-size: 13px; font-weight: 500;")
        self.lbl_last_tested = QLabel("Last tested: Never")
        self.lbl_last_tested.setStyleSheet("color: #888898; font-size: 11px;")

        v_sum.addWidget(self.lbl_status_badge)
        v_sum.addWidget(self.lbl_summary)
        v_sum.addWidget(self.lbl_last_tested)
        b_layout.addLayout(v_sum, 1)

        main_layout.addWidget(self.banner)

        # 3. KPI Cards Row
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(10)

        self.card_internet = HealthMetricCard("Internet Status", "Unknown", "#00e5ff")
        self.card_dns = HealthMetricCard("DNS Resolution", "Unknown", "#00e676")
        self.card_latency = HealthMetricCard("Latency (RTT)", "- ms", "#ffd600")
        self.card_loss = HealthMetricCard("Packet Loss", "- %", "#00e5ff")
        self.card_gateway = HealthMetricCard("Default Gateway", "Unknown", "#ff9100")
        self.card_iface = HealthMetricCard("Local Interface", "Unknown", "#8e8e9f")

        kpi_layout.addWidget(self.card_internet)
        kpi_layout.addWidget(self.card_dns)
        kpi_layout.addWidget(self.card_latency)
        kpi_layout.addWidget(self.card_loss)
        kpi_layout.addWidget(self.card_gateway)
        kpi_layout.addWidget(self.card_iface)

        main_layout.addLayout(kpi_layout)

        # 4. Diagnostic Controls Bar
        ctrl_frame = QFrame()
        ctrl_frame.setStyleSheet("background-color: #25252c; border: 1px solid #363642; border-radius: 6px; padding: 6px;")
        c_layout = QHBoxLayout(ctrl_frame)
        c_layout.setContentsMargins(6, 4, 6, 4)
        c_layout.setSpacing(8)

        c_layout.addWidget(QLabel("DNS Test Target:"))
        self.cmb_dns_target = QComboBox()
        self.cmb_dns_target.addItems(["google.com", "cloudflare.com", "quad9.net", "microsoft.com", "amazon.com"])
        self.cmb_dns_target.setEditable(True)
        self.cmb_dns_target.setStyleSheet("background: #1e1e24; color: #fff; padding: 4px 8px; border: 1px solid #363642; min-width: 140px;")
        c_layout.addWidget(self.cmb_dns_target)

        self.btn_run = QPushButton("▶ Run Diagnostics")
        self.btn_run.setStyleSheet("background-color: #00897b; color: white; font-weight: bold; padding: 6px 16px; border-radius: 4px;")
        self.btn_run.clicked.connect(self.run_diagnostics)
        c_layout.addWidget(self.btn_run)

        self.chk_auto = QCheckBox("Auto-test every 60s")
        self.chk_auto.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        self.chk_auto.toggled.connect(self._toggle_auto)
        c_layout.addWidget(self.chk_auto)

        c_layout.addStretch()

        self.lbl_progress_text = QLabel("Ready")
        self.lbl_progress_text.setStyleSheet("color: #888898; font-size: 11px;")
        c_layout.addWidget(self.lbl_progress_text)

        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 100)
        self.prog_bar.setValue(0)
        self.prog_bar.setFixedHeight(14)
        self.prog_bar.setFixedWidth(160)
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setStyleSheet("""
            QProgressBar { background-color: #1e1e24; border: 1px solid #363642; border-radius: 3px; }
            QProgressBar::chunk { background-color: #00e5ff; }
        """)
        c_layout.addWidget(self.prog_bar)

        main_layout.addWidget(ctrl_frame)

        # 5. Bottom Tabs: Historical Monitoring Charts & Test History Table
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #363642; background: #1e1e24; border-radius: 6px; }
            QTabBar::tab { background: #25252c; color: #a0a0b0; padding: 6px 14px; font-weight: bold; }
            QTabBar::tab:selected { background: #1e1e24; color: #00e5ff; border-top: 2px solid #00e5ff; }
        """)

        # Tab 1: Historical Charts
        chart_widget = QWidget()
        v_chart = QHBoxLayout(chart_widget)
        v_chart.setSpacing(10)
        v_chart.setContentsMargins(6, 6, 6, 6)

        # Latency Trend Plot
        self.latency_plot = pg.PlotWidget(title="Latency History (ms)")
        self.latency_plot.showGrid(x=True, y=True, alpha=0.25)
        self.latency_plot.setLabel('left', 'RTT (ms)')
        self.latency_plot.setLabel('bottom', 'Recent Tests')
        self.latency_curve = self.latency_plot.plot(
            pen=pg.mkPen('#ffd600', width=2),
            symbol='o',
            symbolBrush='#ffd600',
            symbolSize=6
        )
        v_chart.addWidget(self.latency_plot, 1)

        # Packet Loss Trend Plot
        self.loss_plot = pg.PlotWidget(title="Packet Loss History (%)")
        self.loss_plot.showGrid(x=True, y=True, alpha=0.25)
        self.loss_plot.setLabel('left', 'Loss %')
        self.loss_plot.setLabel('bottom', 'Recent Tests')
        self.loss_curve = self.loss_plot.plot(
            pen=pg.mkPen('#ff5252', width=2),
            symbol='s',
            symbolBrush='#ff5252',
            symbolSize=6
        )
        v_chart.addWidget(self.loss_plot, 1)

        self.tabs.addTab(chart_widget, "📈 Health Trends")

        # Tab 2: Test History Table
        history_widget = QWidget()
        v_hist = QVBoxLayout(history_widget)
        v_hist.setContentsMargins(6, 6, 6, 6)
        v_hist.setSpacing(6)

        self.tbl_history = QTableWidget()
        self.tbl_history.setColumnCount(7)
        self.tbl_history.setHorizontalHeaderLabels([
            "Timestamp", "Status", "Conclusion / Summary", "Latency", "Packet Loss", "DNS", "Gateway"
        ])
        self.tbl_history.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_history.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_history.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_history.setStyleSheet("background: #1e1e24; color: #fff; border: 1px solid #363642;")
        v_hist.addWidget(self.tbl_history)

        self.tabs.addTab(history_widget, "📋 Diagnostic History Log")

        main_layout.addWidget(self.tabs, 1)

    def _toggle_auto(self, checked: bool):
        if checked:
            self.auto_timer.start(60000) # every 60s
        else:
            self.auto_timer.stop()

    def run_diagnostics(self):
        if self.tester and self.tester.isRunning():
            return

        target_dns = self.cmb_dns_target.currentText().strip() or "google.com"
        self.btn_run.setEnabled(False)
        self.prog_bar.setValue(5)
        self.lbl_progress_text.setText("Starting diagnostics...")

        self.tester = NetworkHealthTester(target_dns=target_dns)
        self.tester.test_progress.connect(self._on_progress)
        self.tester.test_completed.connect(self._on_completed)
        self.tester.test_error.connect(self._on_error)
        self.tester.start()

    def _on_progress(self, desc: str, pct: int):
        self.lbl_progress_text.setText(desc)
        self.prog_bar.setValue(pct)

    def _on_completed(self, results: dict):
        self.btn_run.setEnabled(True)
        self.prog_bar.setValue(100)
        self.lbl_progress_text.setText("Completed")

        # Update Summary Banner
        status = results.get("status", "Healthy")
        summary = results.get("summary", "")
        now_str = datetime.datetime.fromtimestamp(results["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        self.lbl_last_tested.setText(f"Last tested: {now_str}")
        self.lbl_summary.setText(summary)

        if status == "Healthy":
            self.lbl_status_badge.setText("✅ INTERNET CONNECTION HEALTHY")
            self.lbl_status_badge.setStyleSheet("color: #00e676; font-weight: bold; font-size: 16px;")
            self.banner.setStyleSheet("QFrame { background-color: #1b2e23; border: 1px solid #2e7d32; border-radius: 8px; padding: 12px; }")
        elif status == "Degraded":
            self.lbl_status_badge.setText("⚠️ CONNECTION DEGRADED")
            self.lbl_status_badge.setStyleSheet("color: #ffd600; font-weight: bold; font-size: 16px;")
            self.banner.setStyleSheet("QFrame { background-color: #2b2816; border: 1px solid #f57f17; border-radius: 8px; padding: 12px; }")
        else:
            self.lbl_status_badge.setText("❌ NO INTERNET ACCESS DETECTED")
            self.lbl_status_badge.setStyleSheet("color: #ff5252; font-weight: bold; font-size: 16px;")
            self.banner.setStyleSheet("QFrame { background-color: #2e1a1a; border: 1px solid #c62828; border-radius: 8px; padding: 12px; }")

        # Update KPI Cards
        # 1. Internet
        self.card_internet.set_value(
            status,
            f"{results.get('latency_ms', 0)} ms avg",
            "#00e676" if status == "Healthy" else ("#ffd600" if status == "Degraded" else "#ff5252")
        )
        # 2. DNS
        dns_st = results.get("dns_status", "Unknown")
        dns_lat = results.get("dns_latency_ms", 0.0)
        self.card_dns.set_value(
            dns_st,
            f"{dns_lat} ms ({results.get('dns_resolved_ip', '')})",
            "#00e676" if dns_st == "Healthy" else ("#ffd600" if dns_st == "Slow" else "#ff5252")
        )
        # 3. Latency
        lat = results.get("latency_ms", 0.0)
        self.card_latency.set_value(f"{lat} ms", "Public DNS Anycast RTT", "#00e676" if lat < 100 else ("#ffd600" if lat < 250 else "#ff5252"))

        # 4. Packet Loss
        loss = results.get("packet_loss_pct", 0.0)
        self.card_loss.set_value(f"{loss}%", "Multi-probe loss", "#00e676" if loss == 0 else ("#ffd600" if loss < 20 else "#ff5252"))

        # 5. Gateway
        gw_st = results.get("gateway_status", "Unknown")
        gw_ip = results.get("gateway_ip", "Unknown")
        gw_lat = results.get("gateway_latency_ms", 0.0)
        self.card_gateway.set_value(
            gw_st,
            f"IP: {gw_ip} ({gw_lat} ms)",
            "#00e676" if gw_st == "Reachable" else "#ff5252"
        )

        # 6. Interface
        iface = results.get("interface_name", "Unknown")
        local_ip = results.get("local_ip", "Unknown")
        self.card_iface.set_value(local_ip, f"Interface: {iface}", "#00e5ff")

        # Reload history log & plots
        self.load_history()

    def _on_error(self, err_msg: str):
        self.btn_run.setEnabled(True)
        self.lbl_progress_text.setText("Error")
        self.lbl_status_badge.setText("⚠️ TEST FAILED")
        self.lbl_summary.setText(err_msg)

    def load_history(self):
        records = self.db.get_health_history(limit=40)
        if not records:
            return

        # Update History Table
        self.tbl_history.setRowCount(len(records))
        latencies = []
        losses = []

        for row, r in enumerate(records):
            dt = datetime.datetime.fromtimestamp(r["timestamp"]).strftime("%m-%d %H:%M:%S")
            self.tbl_history.setItem(row, 0, QTableWidgetItem(dt))

            st_item = QTableWidgetItem(r["status"])
            if r["status"] == "Healthy":
                st_item.setForeground(QBrush(QColor("#00e676")))
            elif r["status"] == "Degraded":
                st_item.setForeground(QBrush(QColor("#ffd600")))
            else:
                st_item.setForeground(QBrush(QColor("#ff5252")))
            self.tbl_history.setItem(row, 1, st_item)

            self.tbl_history.setItem(row, 2, QTableWidgetItem(r.get("summary", "")))
            self.tbl_history.setItem(row, 3, QTableWidgetItem(f"{r.get('latency_ms', 0)} ms"))
            self.tbl_history.setItem(row, 4, QTableWidgetItem(f"{r.get('packet_loss_pct', 0)}%"))
            self.tbl_history.setItem(row, 5, QTableWidgetItem(r.get("dns_status", "")))
            self.tbl_history.setItem(row, 6, QTableWidgetItem(r.get("gateway_status", "")))

            latencies.append(r.get("latency_ms", 0.0))
            losses.append(r.get("packet_loss_pct", 0.0))

        # Update plots (chronological order)
        latencies.reverse()
        losses.reverse()
        x_axis = list(range(len(latencies)))
        self.latency_curve.setData(x_axis, latencies)
        self.loss_curve.setData(x_axis, losses)
