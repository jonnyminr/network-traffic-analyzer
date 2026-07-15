from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                               QSplitter, QToolBar, QStatusBar, QMessageBox)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction

from core.capture_engine import CaptureEngine
from gui.dashboard_widget import DashboardWidget
from gui.packet_table_widget import PacketTableWidget
from gui.alerts_panel import AlertsPanel
from gui.settings_dialog import SettingsDialog
from utils.logger import logger

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Analyzer")
        self.resize(1200, 800)
        
        # State
        self.capture_engine = None
        self.current_interface = "Any"
        self.current_bpf = ""

        self.init_ui()

    def init_ui(self):
        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Splitters for layout
        v_splitter = QSplitter(Qt.Vertical)
        
        # Top half: Dashboard and Alerts
        h_splitter = QSplitter(Qt.Horizontal)
        
        self.dashboard = DashboardWidget()
        h_splitter.addWidget(self.dashboard)
        
        self.alerts_panel = AlertsPanel()
        h_splitter.addWidget(self.alerts_panel)
        
        h_splitter.setSizes([800, 400])
        v_splitter.addWidget(h_splitter)
        
        # Bottom half: Packet Table
        self.packet_table = PacketTableWidget()
        v_splitter.addWidget(self.packet_table)
        
        v_splitter.setSizes([400, 400])
        main_layout.addWidget(v_splitter)

        # Toolbar
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        self.start_action = QAction("Start Capture", self)
        self.start_action.triggered.connect(self.start_capture)
        toolbar.addAction(self.start_action)
        
        self.stop_action = QAction("Stop Capture", self)
        self.stop_action.triggered.connect(self.stop_capture)
        self.stop_action.setEnabled(False)
        toolbar.addAction(self.stop_action)
        
        toolbar.addSeparator()
        
        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.open_settings)
        toolbar.addAction(settings_action)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready. Select an interface in Settings to begin.")

    def open_settings(self):
        dialog = SettingsDialog(self, self.current_interface, self.current_bpf)
        if dialog.exec():
            self.current_interface = dialog.selected_interface
            self.current_bpf = dialog.bpf_filter
            self.status_bar.showMessage(f"Interface set to {self.current_interface}. BPF: {self.current_bpf}")

    def start_capture(self):
        if self.capture_engine and self.capture_engine.isRunning():
            return
            
        self.capture_engine = CaptureEngine(self.current_interface, self.current_bpf)
        
        # Connect signals
        self.capture_engine.packet_captured.connect(self.packet_table.add_packet, Qt.QueuedConnection)
        self.capture_engine.stats_updated.connect(self.dashboard.update_stats, Qt.QueuedConnection)
        self.capture_engine.alerts_generated.connect(self.handle_alerts, Qt.QueuedConnection)
        self.capture_engine.capture_error.connect(self.handle_error, Qt.QueuedConnection)
        self.capture_engine.capture_stopped.connect(self.on_capture_stopped, Qt.QueuedConnection)
        
        self.capture_engine.start()
        
        self.start_action.setEnabled(False)
        self.stop_action.setEnabled(True)
        self.status_bar.showMessage(f"Capturing on {self.current_interface}...")
        logger.info("Capture started via GUI.")

    def stop_capture(self):
        if self.capture_engine and self.capture_engine.isRunning():
            self.capture_engine.stop()
            self.status_bar.showMessage("Stopping capture...")

    def on_capture_stopped(self):
        self.start_action.setEnabled(True)
        self.stop_action.setEnabled(False)
        self.status_bar.showMessage("Capture stopped.")

    def handle_alerts(self, alerts):
        for alert in alerts:
            self.alerts_panel.add_alert(alert)

    def handle_error(self, error_msg):
        QMessageBox.critical(self, "Capture Error", error_msg)
        self.on_capture_stopped()

    def closeEvent(self, event):
        self.stop_capture()
        super().closeEvent(event)
