import sys
import ctypes
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QToolBar, QStatusBar, QMessageBox, 
    QFileDialog, QLabel, QTabWidget, QPushButton,
    QStackedWidget, QComboBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from scapy.all import conf

from core.capture_engine import CaptureEngine
from core.connection_tracker import ConnectionTracker
from core.alert_manager import AlertManager
from core.incident_manager import IncidentManager
from core.incident_db import IncidentDatabase
from core.capture_profiles import DEFAULT_PROFILE

from gui.dashboard_widget import DashboardWidget
from gui.network_health_widget import NetworkHealthWidget
from gui.web_traffic_widget import WebTrafficWidget
from gui.packet_table_widget import PacketTableWidget
from gui.connection_explorer_widget import ConnectionExplorerWidget
from gui.dns_insights_widget import DNSInsightsWidget
from gui.alerts_panel import AlertsPanel
from gui.investigation_widget import InvestigationWidget
from gui.offline_analysis_widget import OfflineAnalysisWidget
from gui.settings_dialog import SettingsWidget
from gui.simple_mode_widget import SimpleModeWidget
from utils.interfaces import get_best_interface
from utils.exporter import export_to_pcap, export_stats_to_csv
from utils.logger import logger


class MainWindow(QMainWindow):
    """
    Main Application Window providing 10 cybersecurity and network analysis sections:
    1. Dashboard (KPIs, graphs, protocols, top talkers, performance, recommendations)
    2. Network Health (Active latency, DNS, gateway, packet loss diagnostics)
    3. Web Traffic (Target website domain monitor)
    4. Packet Inspector (Deep packet inspection, search, raw bytes)
    5. Network Connections (L4 flow tracking, device overview, topology)
    6. DNS Insights (Observable DNS transactions, domain analysis)
    7. Security Alerts (Intelligent deduplicated incidents, evidence modal)
    8. Investigations (Formal case studio, timeline, reports)
    9. Offline Analysis (Streaming PCAP analysis, zero-admin playback)
    10. Settings (Interface, profiles, refresh rates, performance)

    Also features seamless toggling between Simple Mode and Advanced Mode.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Analyzer — Cybersecurity & Health Studio")
        self.resize(1400, 930)
        self.setMinimumSize(1200, 800)

        self.db = IncidentDatabase()

        # State
        self.capture_engine = None
        self.current_bpf = ""
        self.stats_history = []
        self.current_profile = self.db.get_setting("capture_profile", DEFAULT_PROFILE)

        # Interface detection
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
        """Checks for Npcap and informs user if not detected."""
        if sys.platform == 'win32':
            has_pcap = getattr(conf, 'use_pcap', False)
            if not has_pcap:
                QMessageBox.warning(
                    self,
                    "Npcap Required for Live Capture",
                    "Npcap / WinPcap was not detected on your Windows system.\n\n"
                    "Live packet capture requires Npcap (https://npcap.com/).\n"
                    "Note: Offline PCAP Analysis and Network Health tests remain fully functional without Npcap."
                )

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(6)

        # -------------------------------------------------------------
        # Central View Stack: Index 0 = Advanced Mode, Index 1 = Simple Mode
        # -------------------------------------------------------------
        self.view_stack = QStackedWidget()
        main_layout.addWidget(self.view_stack)

        # -------------------------------------------------------------
        # 10 Dedicated Navigation Sections (Advanced Mode)
        # -------------------------------------------------------------
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
                padding: 8px 14px;
                font-weight: bold;
                font-size: 11px;
                border: 1px solid #363642;
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
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

        # 1. Dashboard
        self.dashboard = DashboardWidget()
        self.tabs.addTab(self.dashboard, "📊 Dashboard")

        # 2. Network Health
        self.network_health = NetworkHealthWidget()
        self.tabs.addTab(self.network_health, "🩺 Network Health")

        # 3. Web Traffic
        self.web_traffic_widget = WebTrafficWidget()
        self.tabs.addTab(self.web_traffic_widget, "🌐 Web Traffic")

        # 4. Packet Inspector
        self.packet_table = PacketTableWidget()
        self.tabs.addTab(self.packet_table, "📦 Packet Inspector")

        # 5. Network Connections
        self.connection_explorer = ConnectionExplorerWidget()
        self.tabs.addTab(self.connection_explorer, "🔗 Network Connections")

        # 6. DNS Insights
        self.dns_insights = DNSInsightsWidget()
        self.tabs.addTab(self.dns_insights, "🔍 DNS Insights")

        # 7. Security Alerts
        self.alerts_panel = AlertsPanel()
        self.tabs.addTab(self.alerts_panel, "🚨 Security Alerts")

        # 8. Investigations
        self.investigation_widget = InvestigationWidget()
        self.tabs.addTab(self.investigation_widget, "🛡 Investigations")

        # 9. Offline PCAP Analysis
        self.offline_analysis = OfflineAnalysisWidget()
        self.tabs.addTab(self.offline_analysis, "📁 Offline Analysis")

        # 10. Settings
        self.settings_widget = SettingsWidget(current_iface=self.current_interface, current_bpf=self.current_bpf)
        self.settings_widget.settings_applied.connect(self._on_settings_applied)
        self.tabs.addTab(self.settings_widget, "⚙ Settings")

        self.view_stack.addWidget(self.tabs) # Stack Index 0

        # Simple Mode Widget
        self.simple_mode = SimpleModeWidget()
        self.simple_mode.switch_to_advanced_requested.connect(self._toggle_to_advanced_mode)
        self.view_stack.addWidget(self.simple_mode) # Stack Index 1

        # -----------------------------------------------------------
        # Main Toolbar
        # -----------------------------------------------------------
        toolbar = QToolBar("Global Capture Toolbar")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.start_action = QAction("▶ Start Capture", self)
        self.start_action.setToolTip("Start capturing live packets on the selected interface")
        self.start_action.triggered.connect(self.start_capture)
        toolbar.addAction(self.start_action)

        self.stop_action = QAction("⏹ Stop Capture", self)
        self.stop_action.setToolTip("Stop active global packet capture")
        self.stop_action.triggered.connect(self.stop_capture)
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)

        toolbar.addSeparator()

        # Simple / Advanced Mode Selector (Feature 3C)
        toolbar.addWidget(QLabel(" View: "))
        self.cmb_mode = QComboBox()
        self.cmb_mode.addItem("Advanced Mode", "advanced")
        self.cmb_mode.addItem("Simple Mode", "simple")
        self.cmb_mode.setStyleSheet("background: #25252c; color: #00e5ff; font-weight: bold; padding: 4px; border: 1px solid #363642;")
        saved_mode = self.db.get_setting("ui_mode", "advanced")
        if saved_mode == "simple":
            self.cmb_mode.setCurrentIndex(1)
            self.view_stack.setCurrentIndex(1)
        else:
            self.cmb_mode.setCurrentIndex(0)
            self.view_stack.setCurrentIndex(0)
        self.cmb_mode.currentIndexChanged.connect(self._on_mode_changed)
        toolbar.addWidget(self.cmb_mode)

        toolbar.addSeparator()

        # Capture Profile Quick Selector (Feature 1F)
        toolbar.addWidget(QLabel(" Profile: "))
        self.cmb_profile = QComboBox()
        self.cmb_profile.addItems(["Balanced", "Lightweight", "Deep Analysis"])
        self.cmb_profile.setCurrentText(self.current_profile)
        self.cmb_profile.setStyleSheet("background: #25252c; color: #ffd600; padding: 4px; border: 1px solid #363642;")
        self.cmb_profile.currentTextChanged.connect(self._on_profile_toolbar_changed)
        toolbar.addWidget(self.cmb_profile)

        toolbar.addSeparator()

        settings_action = QAction("⚙ Settings", self)
        settings_action.setToolTip("Configure interface, filters, anomaly thresholds, and API keys")
        settings_action.triggered.connect(self.open_settings)
        toolbar.addAction(settings_action)

        clear_action = QAction("🗑 Clear Session", self)
        clear_action.setToolTip("Reset in-memory graphs, tables, and visible alerts")
        clear_action.triggered.connect(self.clear_all_data)
        toolbar.addAction(clear_action)

        toolbar.addSeparator()

        # Exporters
        export_pcap_action = QAction("💾 PCAP", self)
        export_pcap_action.setToolTip("Export raw captured packets to PCAP")
        export_pcap_action.triggered.connect(self.export_pcap)
        toolbar.addAction(export_pcap_action)

        export_csv_action = QAction("📊 Stats CSV", self)
        export_csv_action.setToolTip("Export traffic statistics history to CSV")
        export_csv_action.triggered.connect(self.export_stats)
        toolbar.addAction(export_csv_action)

        toolbar.addSeparator()

        # Status label
        self.toolbar_iface_label = QLabel(f"  Interface: <b>{self.current_interface}</b>  ")
        self.toolbar_iface_label.setStyleSheet("color: #00e5ff; font-size: 12px;")
        toolbar.addWidget(self.toolbar_iface_label)

        # -----------------------------------------------------------
        # Status Bar
        # -----------------------------------------------------------
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"Ready. Interface: {self.current_interface}")

        # Tab change listener
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # Wire cross-component integrations
        self._wire_component_signals()

    def _wire_component_signals(self):
        # 1. Top Talkers IP click -> Inspect IP in Network Connections (Tab 4)
        self.dashboard.ip_clicked.connect(self._on_top_talker_clicked)

        # 2. Connection Explorer -> Inspect Flow Packets in Packet Inspector (Tab 3)
        self.connection_explorer.inspect_flow_packets_requested.connect(self._on_inspect_flow_packets)

        # 3. Security Alerts -> Launch Investigation (Tab 7)
        self.alerts_panel.launch_investigation_requested.connect(self._on_launch_investigation_from_alert)

        # 4. Security Alerts -> Filter Connections (Tab 4)
        self.alerts_panel.filter_connections_requested.connect(self._on_filter_connections_from_alert)

        # 5. Security Alerts -> Inspect Packets (Tab 3)
        self.alerts_panel.inspect_packets_requested.connect(self._on_inspect_packets_from_alert)

        # 6. Investigation Widget -> Filter Connections (Tab 4)
        self.investigation_widget.filter_connections_requested.connect(self._on_filter_connections_from_alert)

    def _on_mode_changed(self, index: int):
        mode_val = self.cmb_mode.itemData(index) or ("simple" if index == 1 else "advanced")
        self.view_stack.setCurrentIndex(1 if mode_val == "simple" else 0)
        self.db.set_setting("ui_mode", mode_val)
        mode_label = "Simple Mode (Beginner friendly)" if mode_val == "simple" else "Advanced Cybersecurity Studio"
        self.status_bar.showMessage(f"Switched to {mode_label}. Capture remains active.")

    def _toggle_to_advanced_mode(self):
        self.cmb_mode.setCurrentIndex(0)
        self._on_mode_changed(0)

    def _on_profile_toolbar_changed(self, profile_name: str):
        self.current_profile = profile_name
        self.db.set_setting("capture_profile", profile_name)
        if self.capture_engine and self.capture_engine.isRunning():
            self.capture_engine.set_profile(profile_name)
        self.status_bar.showMessage(f"Capture profile set to: {profile_name}")

    def _on_top_talker_clicked(self, ip: str):
        self.view_stack.setCurrentIndex(0)
        self.tabs.setCurrentIndex(4) # Network Connections tab
        self.connection_explorer.filter_by_ip(ip)

    def _on_inspect_flow_packets(self, src_ip: str, dst_ip: str, sport: int, dport: int, proto: str):
        self.view_stack.setCurrentIndex(0)
        self.tabs.setCurrentIndex(3) # Packet Inspector tab
        self.packet_table.search_input.setText(src_ip)

    def _on_inspect_packets_from_alert(self, ip: str):
        self.view_stack.setCurrentIndex(0)
        self.tabs.setCurrentIndex(3) # Packet Inspector tab
        self.packet_table.search_input.setText(ip)

    def _on_launch_investigation_from_alert(self, alert_data: dict):
        self.view_stack.setCurrentIndex(0)
        self.tabs.setCurrentIndex(7) # Investigations tab
        self.investigation_widget.open_investigation_from_alert(alert_data)

    def _on_filter_connections_from_alert(self, src_ip: str, dst_ip: str):
        self.view_stack.setCurrentIndex(0)
        self.tabs.setCurrentIndex(4) # Network Connections tab
        target = src_ip if src_ip and src_ip not in ("Unknown", "Multiple") else dst_ip
        if target:
            self.connection_explorer.filter_by_ip(target)

    def _on_tab_changed(self, index: int):
        tab_names = [
            "Dashboard", "Network Health", "Web Traffic", "Packet Inspector",
            "Network Connections", "DNS Insights", "Security Alerts",
            "Investigations", "Offline Analysis", "Settings"
        ]
        name = tab_names[index] if index < len(tab_names) else "View"
        self.status_bar.showMessage(f"{name} active. Interface: {self.current_interface}")

    def open_settings(self):
        self.view_stack.setCurrentIndex(0)
        self.tabs.setCurrentIndex(9) # Settings tab

    def _on_settings_applied(self, iface: str, bpf: str, profile: str = "Balanced"):
        self.current_interface = iface
        self.current_bpf = bpf
        self.current_profile = profile
        self.cmb_profile.setCurrentText(profile)
        self.toolbar_iface_label.setText(f"  Interface: <b>{self.current_interface}</b>  ")
        filter_str = f" | Filter: '{self.current_bpf}'" if self.current_bpf else ""
        self.status_bar.showMessage(f"Configuration applied ({profile}). Interface: {self.current_interface}{filter_str}")

    def start_capture(self):
        if self.capture_engine and self.capture_engine.isRunning():
            return

        self.capture_engine = CaptureEngine(
            interface=self.current_interface,
            bpf_filter=self.current_bpf,
            profile_name=self.current_profile
        )

        # Connect signals (using both batched and individual handlers)
        self.capture_engine.packets_batch_captured.connect(self.packet_table.add_packet_batch, Qt.QueuedConnection)
        self.capture_engine.stats_updated.connect(self.handle_stats, Qt.QueuedConnection)
        self.capture_engine.stats_updated.connect(self.simple_mode.update_stats, Qt.QueuedConnection)
        self.capture_engine.alerts_generated.connect(self.handle_alerts, Qt.QueuedConnection)
        self.capture_engine.capture_error.connect(self.handle_error, Qt.QueuedConnection)
        self.capture_engine.capture_stopped.connect(self.on_capture_stopped, Qt.QueuedConnection)

        self.capture_engine.start()

        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.status_bar.showMessage(f"Capturing live traffic on {self.current_interface} (Profile: {self.current_profile})...")
        logger.info(f"Capture started ({self.current_profile}).")

    def stop_capture(self):
        if self.capture_engine and self.capture_engine.isRunning():
            self.status_bar.showMessage("Stopping capture...")
            self.capture_engine.stop()

    def on_capture_stopped(self):
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.status_bar.showMessage("Capture stopped.")

    def handle_stats(self, stats: dict):
        self.stats_history.append(stats)
        self.dashboard.update_stats(stats)

        total_p = stats.get('total_packets', 0)
        pps = stats.get('packets_per_sec', 0.0)
        bps = stats.get('bytes_per_sec', 0.0)
        self.status_bar.showMessage(
            f"Active on {self.current_interface} — Packets: {total_p:,} ({pps:.0f} pkts/s, {bps:.0f} B/s)"
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
        ConnectionTracker().clear()
        self.status_bar.showMessage("Session data cleared.")

    def export_pcap(self):
        if not self.capture_engine:
            QMessageBox.information(self, "Export PCAP", "No packets have been captured in this session yet.")
            return

        raw_packets = self.capture_engine.get_raw_packets()
        if not raw_packets:
            QMessageBox.information(self, "Export PCAP", "No packets available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Captured Packets as PCAP", "capture.pcap", "PCAP Files (*.pcap *.cap)"
        )
        if file_path:
            success = export_to_pcap(file_path, raw_packets)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved {len(raw_packets)} packets to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save PCAP file.")

    def export_stats(self):
        if not self.stats_history:
            QMessageBox.information(self, "Export Stats", "No statistics records generated yet.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Traffic Statistics as CSV", "traffic_stats.csv", "CSV Files (*.csv)"
        )
        if file_path:
            success = export_stats_to_csv(file_path, self.stats_history)
            if success:
                QMessageBox.information(self, "Export Succeeded", f"Saved statistics to:\n{file_path}")
            else:
                QMessageBox.critical(self, "Export Failed", "Failed to save CSV file.")

    def closeEvent(self, event):
        self.stop_capture()
        if hasattr(self, 'web_traffic_widget') and self.web_traffic_widget.web_engine:
            self.web_traffic_widget.stop_capture()
        if hasattr(self, 'offline_analysis') and self.offline_analysis.worker:
            self.offline_analysis.cancel_analysis()
        super().closeEvent(event)
