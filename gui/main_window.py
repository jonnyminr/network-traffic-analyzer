import sys
import ctypes
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QSplitter, QToolBar, QStatusBar, QMessageBox, 
                               QFileDialog, QLabel, QTabWidget)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from scapy.all import conf

from core.capture_engine import CaptureEngine
from gui.dashboard_widget import DashboardWidget
from gui.packet_table_widget import PacketTableWidget
from gui.alerts_panel import AlertsPanel
from gui.settings_dialog import SettingsDialog
from gui.web_traffic_widget import WebTrafficWidget
from utils.interfaces import get_best_interface
from utils.exporter import export_to_pcap, export_stats_to_csv, export_alerts_to_csv
from utils.logger import logger

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Analyzer")
        self.resize(1340, 900)
        
        # State
        self.capture_engine = None
        self.current_bpf = ""
        self.stats_history = []
        
        # Determine the best active interface automatically on startup
        best_iface = get_best_interface()
        if best_iface:
            self.current_interface = best_iface['name']
            self.interface_display = best_iface['display_label']
        else:
            self.current_interface = "Any"
            self.interface_display = "Any"

        self.init_ui()
        self.check_environment()

    def check_environment(self):
        """Checks for Npcap and Administrator privileges and informs the user."""
        if sys.platform == 'win32':
            has_pcap = getattr(conf, 'use_pcap', False)
            if not has_pcap:
                QMessageBox.warning(
                    self,
                    "Npcap Required",
                    "Npcap / WinPcap was not detected on your Windows system.\n\n"
                    "Packet capture will fail without Npcap.\n"
                    "Please download and install Npcap from https://npcap.com/\n"
                    "Make sure to check 'Install Npcap in WinPcap API-compatible Mode'."
                )

    def init_ui(self):
        # Central Widget & Tab Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(6)

        # Main Navigation Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #363642;
                background-color: #1e1e24;
                border-radius: 6px;
            }
            QTabBar::tab {
                background: #25252c;
                color: #a0a0b0;
                padding: 8px 22px;
                font-weight: bold;
                font-size: 13px;
                border: 1px solid #363642;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background: #2b2b36;
                color: #00e5ff;
                border-top: 2px solid #00e5ff;
            }
            QTabBar::tab:hover {
                background: #2a2a34;
                color: #ffffff;
            }
        """)

        # -------------------------------------------------------------
        # Tab 1: Global Traffic Analyzer (Existing General Dashboard)
        # -------------------------------------------------------------
        global_widget = QWidget()
        global_layout = QVBoxLayout(global_widget)
        global_layout.setContentsMargins(6, 6, 6, 6)

        # Vertical Splitter: Top (Dashboard + Alerts) & Bottom (Packet Table)
        v_splitter = QSplitter(Qt.Vertical)
        
        # Top half: Dashboard (left) and Alerts (right)
        h_splitter = QSplitter(Qt.Horizontal)
        
        self.dashboard = DashboardWidget()
        h_splitter.addWidget(self.dashboard)
        
        self.alerts_panel = AlertsPanel()
        h_splitter.addWidget(self.alerts_panel)
        
        h_splitter.setSizes([880, 420])
        v_splitter.addWidget(h_splitter)
        
        # Bottom half: Raw Packet Table
        self.packet_table = PacketTableWidget()
        v_splitter.addWidget(self.packet_table)
        
        v_splitter.setSizes([460, 360])
        global_layout.addWidget(v_splitter)

        self.tabs.addTab(global_widget, "🌐 Global Network Traffic")

        # -------------------------------------------------------------
        # Tab 2: Web Traffic Analyzer (New Website Analysis Section)
        # -------------------------------------------------------------
        self.web_traffic_widget = WebTrafficWidget()
        self.tabs.addTab(self.web_traffic_widget, "🎯 Web Traffic Analyzer")

        main_layout.addWidget(self.tabs)

        # -----------------------------------------------------------
        # Main Toolbar (Global Capture & Actions)
        # -----------------------------------------------------------
        toolbar = QToolBar("Global Capture Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        self.start_action = QAction("▶ Start Global Capture", self)
        self.start_action.setToolTip("Start capturing all packets on the selected interface")
        self.start_action.triggered.connect(self.start_capture)
        toolbar.addAction(self.start_action)
        
        self.stop_action = QAction("⏹ Stop Global Capture", self)
        self.stop_action.setToolTip("Stop active global packet capture")
        self.stop_action.triggered.connect(self.stop_capture)
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)
        
        toolbar.addSeparator()
        
        settings_action = QAction("⚙ Capture Settings", self)
        settings_action.setToolTip("Select network interface and BPF filter for global capture")
        settings_action.triggered.connect(self.open_settings)
        toolbar.addAction(settings_action)
        
        clear_action = QAction("🗑 Clear Global Session", self)
        clear_action.setToolTip("Clear global charts, packet records, and alerts")
        clear_action.triggered.connect(self.clear_all_data)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        # Export Actions for Global Capture
        export_pcap_action = QAction("💾 Export PCAP", self)
        export_pcap_action.setToolTip("Export global raw packets to PCAP file")
        export_pcap_action.triggered.connect(self.export_pcap)
        toolbar.addAction(export_pcap_action)

        export_csv_action = QAction("📊 Export Stats CSV", self)
        export_csv_action.setToolTip("Export global traffic stats history to CSV")
        export_csv_action.triggered.connect(self.export_stats)
        toolbar.addAction(export_csv_action)

        export_alerts_action = QAction("🚨 Export Alerts CSV", self)
        export_alerts_action.setToolTip("Export global security alerts to CSV")
        export_alerts_action.triggered.connect(self.export_alerts)
        toolbar.addAction(export_alerts_action)

        toolbar.addSeparator()

        # Interface status display on toolbar
        self.toolbar_iface_label = QLabel(f"  Interface: <b>{self.current_interface}</b>  ")
        self.toolbar_iface_label.setStyleSheet("color: #00e5ff; font-size: 12px;")
        toolbar.addWidget(self.toolbar_iface_label)

        # -----------------------------------------------------------
        # Status Bar
        # -----------------------------------------------------------
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        filter_str = f" | Filter: '{self.current_bpf}'" if self.current_bpf else " | Filter: None (All Traffic)"
        self.status_bar.showMessage(f"Ready. Interface: {self.current_interface}{filter_str}")

        # Tab switch listener
        self.tabs.currentChanged.connect(self._on_tab_changed)

    def _on_tab_changed(self, index: int):
        if index == 0:
            filter_str = f" | Filter: '{self.current_bpf}'" if self.current_bpf else " | Filter: None"
            self.status_bar.showMessage(f"Global Traffic Analyzer — Interface: {self.current_interface}{filter_str}")
        else:
            self.status_bar.showMessage("Web Traffic Analyzer — Enter a URL to analyze website traffic in real-time.")

    def open_settings(self):
        dialog = SettingsDialog(self, self.current_interface, self.current_bpf)
        if dialog.exec():
            self.current_interface = dialog.selected_interface
            self.current_bpf = dialog.bpf_filter
            self.toolbar_iface_label.setText(f"  Interface: <b>{self.current_interface}</b>  ")
            
            filter_str = f" | Filter: '{self.current_bpf}'" if self.current_bpf else " | Filter: None (All Traffic)"
            self.status_bar.showMessage(f"Global interface set to {self.current_interface}{filter_str}")

    def start_capture(self):
        if self.capture_engine and self.capture_engine.isRunning():
            return
            
        self.capture_engine = CaptureEngine(self.current_interface, self.current_bpf)
        
        # Connect signals
        self.capture_engine.packet_captured.connect(self.packet_table.add_packet, Qt.QueuedConnection)
        self.capture_engine.stats_updated.connect(self.handle_stats, Qt.QueuedConnection)
        self.capture_engine.alerts_generated.connect(self.handle_alerts, Qt.QueuedConnection)
        self.capture_engine.capture_error.connect(self.handle_error, Qt.QueuedConnection)
        self.capture_engine.capture_stopped.connect(self.on_capture_stopped, Qt.QueuedConnection)
        
        self.capture_engine.start()
        
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        filter_info = f" [Filter: {self.current_bpf}]" if self.current_bpf else ""
        self.status_bar.showMessage(f"Capturing global traffic on {self.current_interface}{filter_info}...")
        logger.info("Global capture started via GUI.")

    def stop_capture(self):
        if self.capture_engine and self.capture_engine.isRunning():
            self.status_bar.showMessage("Stopping global capture...")
            self.capture_engine.stop()

    def on_capture_stopped(self):
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.status_bar.showMessage("Global capture stopped.")

    def handle_stats(self, stats: dict):
        self.stats_history.append(stats)
        self.dashboard.update_stats(stats)
        
        # Update status bar with live summary
        total_p = stats.get('total_packets', 0)
        pps = stats.get('packets_per_sec', 0.0)
        bps = stats.get('bytes_per_sec', 0.0)
        self.status_bar.showMessage(
            f"Global Capture on {self.current_interface} — Packets: {total_p:,} ({pps:.0f} pkts/s, {bps:.0f} B/s)"
        )

    def handle_alerts(self, alerts: list):
        for alert in alerts:
            self.alerts_panel.add_alert(alert)

    def handle_error(self, error_msg: str):
        QMessageBox.critical(self, "Capture Error", error_msg)
        self.on_capture_stopped()

    def clear_all_data(self):
        """Resets all dashboard stats, packet tables, and alerts."""
        self.stats_history.clear()
        self.dashboard.reset_dashboard()
        self.packet_table.clear_table()
        self.alerts_panel.clear_alerts()
        self.status_bar.showMessage("Global session data cleared.")

    def export_pcap(self):
        """Exports captured raw packets to a .pcap file."""
        if not self.capture_engine:
            QMessageBox.information(self, "Export PCAP", "No packets have been captured in this global session yet.")
            return

        raw_packets = self.capture_engine.get_raw_packets()
        if not raw_packets:
            QMessageBox.information(self, "Export PCAP", "No packets available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Captured Packets as PCAP", "global_capture.pcap", "PCAP Files (*.pcap *.cap)"
        )
        if file_path:
            success = export_to_pcap(file_path, raw_packets)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved {len(raw_packets)} packets to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save PCAP file. Check log for details.")

    def export_stats(self):
        """Exports statistics history to a CSV file."""
        if not self.stats_history:
            QMessageBox.information(self, "Export Stats", "No statistics records have been generated yet.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Traffic Statistics as CSV", "global_traffic_stats.csv", "CSV Files (*.csv)"
        )
        if file_path:
            success = export_stats_to_csv(file_path, self.stats_history)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved statistics to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save CSV file.")

    def export_alerts(self):
        """Exports security alerts to a CSV file."""
        alerts = self.alerts_panel.get_alerts()
        if not alerts:
            QMessageBox.information(self, "Export Alerts", "No security alerts have been generated yet.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Alerts as CSV", "global_security_alerts.csv", "CSV Files (*.csv)"
        )
        if file_path:
            success = export_alerts_to_csv(file_path, alerts)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved {len(alerts)} alerts to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save CSV file.")

    def closeEvent(self, event):
        # Stop global capture engine
        self.stop_capture()
        # Stop web traffic capture engine if running
        if hasattr(self, 'web_traffic_widget') and self.web_traffic_widget.web_engine:
            self.web_traffic_widget.stop_capture()
        super().closeEvent(event)
