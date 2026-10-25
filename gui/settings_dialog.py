import sys
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QLineEdit, QPushButton, QGroupBox, QTabWidget,
    QWidget, QSpinBox, QDoubleSpinBox, QFrame, QMessageBox
)
from PySide6.QtCore import Signal
from utils.interfaces import get_network_interfaces
from core.threat_intelligence import ThreatIntelManager
from core.incident_db import IncidentDatabase


class SettingsWidget(QWidget):
    """
    Comprehensive Configuration Panel with 4 functional tabs:
    1. Capture Interface & BPF Filters
    2. Anomaly Detection & Statistical Baselines
    3. Alert Grouping & Cooldowns
    4. Threat Intelligence API Keys & Privacy Controls
    """
    settings_applied = Signal(str, str) # Emits (selected_interface, bpf_filter)

    def __init__(self, parent=None, current_iface=None, current_bpf=""):
        super().__init__(parent)
        self.selected_interface = current_iface
        self.bpf_filter = current_bpf
        self.db = IncidentDatabase()
        self.intel_manager = ThreatIntelManager()

        self._init_ui()

    def set_current_state(self, current_iface: str, current_bpf: str):
        self.selected_interface = current_iface
        self.bpf_filter = current_bpf
        if hasattr(self, 'bpf_input'):
            self.bpf_input.setText(current_bpf)
        if hasattr(self, 'iface_combo'):
            idx = self.iface_combo.findData(current_iface)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(12)

        header_lbl = QLabel("⚙ System Configuration & Security Thresholds")
        header_lbl.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 16px;")
        main_layout.addWidget(header_lbl)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #363642; background: #25252c; border-radius: 6px; }
            QTabBar::tab { background: #1e1e24; color: #a0a0b0; padding: 6px 14px; margin-right: 2px; }
            QTabBar::tab:selected { background: #25252c; color: #00e5ff; font-weight: bold; border-top: 2px solid #00e5ff; }
        """)

        # -------------------------------------------------------------
        # TAB 1: Interface & BPF
        # -------------------------------------------------------------
        tab_iface = QWidget()
        v_iface = QVBoxLayout(tab_iface)
        v_iface.setSpacing(12)

        iface_group = QGroupBox("Network Capture Interface")
        iface_layout = QVBoxLayout(iface_group)
        self.iface_combo = QComboBox()
        if sys.platform != 'win32':
            self.iface_combo.addItem("Any (All interfaces)", userData="Any")

        detected_ifaces = get_network_interfaces()
        for item in detected_ifaces:
            self.iface_combo.addItem(item['display_label'], userData=item['name'])

        if self.selected_interface:
            idx = self.iface_combo.findData(self.selected_interface)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
            else:
                for i in range(self.iface_combo.count()):
                    if str(self.selected_interface).lower() in self.iface_combo.itemText(i).lower():
                        self.iface_combo.setCurrentIndex(i)
                        break

        iface_layout.addWidget(self.iface_combo)
        hint_label = QLabel("Tip: Select an [Active] interface associated with your primary IP address.")
        hint_label.setStyleSheet("color: #8e8e9f; font-size: 11px;")
        iface_layout.addWidget(hint_label)
        v_iface.addWidget(iface_group)

        # BPF Group
        bpf_group = QGroupBox("Berkeley Packet Filter (BPF)")
        bpf_layout = QVBoxLayout(bpf_group)
        h_pres = QHBoxLayout()
        h_pres.addWidget(QLabel("Preset:"))
        self.preset_combo = QComboBox()
        self.preset_combo.addItem("Select a preset...", "")
        self.preset_combo.addItem("All Traffic (No Filter)", "")
        self.preset_combo.addItem("Web Traffic (HTTP & HTTPS: port 80 or 443)", "port 80 or port 443")
        self.preset_combo.addItem("HTTPS Only (Port 443)", "port 443")
        self.preset_combo.addItem("TCP Only", "tcp")
        self.preset_combo.addItem("UDP Only", "udp")
        self.preset_combo.addItem("DNS Only (Port 53)", "port 53")
        self.preset_combo.addItem("ICMP / Ping", "icmp")
        self.preset_combo.currentIndexChanged.connect(self._on_preset_changed)
        h_pres.addWidget(self.preset_combo, 1)
        bpf_layout.addLayout(h_pres)

        self.bpf_input = QLineEdit()
        self.bpf_input.setPlaceholderText("e.g. port 443 or leave blank to capture all traffic")
        self.bpf_input.setText(self.bpf_filter)
        bpf_layout.addWidget(self.bpf_input)
        v_iface.addWidget(bpf_group)

        v_iface.addStretch()
        self.tabs.addTab(tab_iface, "🌐 Interface & BPF")

        # -------------------------------------------------------------
        # TAB 2: Anomaly Detection Thresholds
        # -------------------------------------------------------------
        tab_anomaly = QWidget()
        v_anom = QVBoxLayout(tab_anomaly)
        v_anom.setSpacing(12)

        anom_group = QGroupBox("Statistical & Rule Thresholds")
        v_ag = QVBoxLayout(anom_group)

        h_z = QHBoxLayout()
        h_z.addWidget(QLabel("Standard Z-Score Threshold (Bandwidth Spike):"))
        self.spin_z_score = QDoubleSpinBox()
        self.spin_z_score.setRange(2.0, 10.0)
        self.spin_z_score.setSingleStep(0.5)
        saved_z = float(self.db.get_setting("z_score_threshold", 3.5))
        self.spin_z_score.setValue(saved_z)
        h_z.addWidget(self.spin_z_score)
        v_ag.addLayout(h_z)

        h_ps = QHBoxLayout()
        h_ps.addWidget(QLabel("Port Scan Probing Threshold (Distinct Ports / Window):"))
        self.spin_port_scan = QSpinBox()
        self.spin_port_scan.setRange(5, 200)
        saved_ps = int(self.db.get_setting("port_scan_threshold", 25))
        self.spin_port_scan.setValue(saved_ps)
        h_ps.addWidget(self.spin_port_scan)
        v_ag.addLayout(h_ps)

        h_wu = QHBoxLayout()
        h_wu.addWidget(QLabel("Baseline Warm-up Window (Minimum Samples before Alerting):"))
        self.spin_warmup = QSpinBox()
        self.spin_warmup.setRange(5, 60)
        saved_wu = int(self.db.get_setting("warmup_samples", 12))
        self.spin_warmup.setValue(saved_wu)
        h_wu.addWidget(self.spin_warmup)
        v_ag.addLayout(h_wu)

        v_anom.addWidget(anom_group)

        lbl_anom_note = QLabel(
            "Note: Z-score uses robust variance damping. Events will not be classified as Critical "
            "solely on Z-score magnitude without sustaining duration or high occurrence frequency."
        )
        lbl_anom_note.setWordWrap(True)
        lbl_anom_note.setStyleSheet("color: #888898; font-size: 11px;")
        v_anom.addWidget(lbl_anom_note)
        v_anom.addStretch()
        self.tabs.addTab(tab_anomaly, "📈 Anomaly Thresholds")

        # -------------------------------------------------------------
        # TAB 3: Alert Grouping & Cooldowns
        # -------------------------------------------------------------
        tab_alerts = QWidget()
        v_al = QVBoxLayout(tab_alerts)
        v_al.setSpacing(12)

        al_group = QGroupBox("Deduplication & Cooldown Windows")
        v_alg = QVBoxLayout(al_group)

        h_cd = QHBoxLayout()
        h_cd.addWidget(QLabel("Alert Deduplication Window (Seconds):"))
        self.spin_cooldown = QSpinBox()
        self.spin_cooldown.setRange(5, 300)
        saved_cd = int(self.db.get_setting("cooldown_seconds", 60))
        self.spin_cooldown.setValue(saved_cd)
        h_cd.addWidget(self.spin_cooldown)
        v_alg.addLayout(h_cd)

        lbl_cd_help = QLabel(
            "Alerts with matching category and IP endpoints arriving within this window will "
            "be grouped together into the same ongoing event, updating occurrence counters."
        )
        lbl_cd_help.setWordWrap(True)
        lbl_cd_help.setStyleSheet("color: #888898; font-size: 11px;")
        v_alg.addWidget(lbl_cd_help)

        v_al.addWidget(al_group)
        v_al.addStretch()
        self.tabs.addTab(tab_alerts, "🚨 Alert Grouping")

        # -------------------------------------------------------------
        # TAB 4: Threat Intelligence & Privacy
        # -------------------------------------------------------------
        tab_threat = QWidget()
        v_ti = QVBoxLayout(tab_threat)
        v_ti.setSpacing(10)

        notice_p = QFrame()
        notice_p.setStyleSheet("background: #1c2038; border: 1px solid #283593; border-radius: 6px; padding: 8px;")
        v_np = QVBoxLayout(notice_p)
        lbl_pn = QLabel(
            "🔒 <b>Privacy Guarantee:</b> Threat intelligence lookups are on-demand. "
            "Private RFC 1918, loopback, and local subnet addresses are <b>strictly never sent</b> "
            "to external third-party APIs. API keys are stored locally in SQLite and never logged."
        )
        lbl_pn.setWordWrap(True)
        lbl_pn.setStyleSheet("color: #9fa8da; font-size: 11px;")
        v_np.addWidget(lbl_pn)
        v_ti.addWidget(notice_p)

        keys_group = QGroupBox("Optional Threat Intelligence API Credentials")
        v_kg = QVBoxLayout(keys_group)

        saved_keys = self.intel_manager.get_api_keys()

        v_kg.addWidget(QLabel("AbuseIPDB API Key (Optional):"))
        self.txt_abuseipdb = QLineEdit()
        self.txt_abuseipdb.setEchoMode(QLineEdit.Password)
        self.txt_abuseipdb.setPlaceholderText("Enter your AbuseIPDB v2 API key...")
        self.txt_abuseipdb.setText(saved_keys.get("abuseipdb", ""))
        v_kg.addWidget(self.txt_abuseipdb)

        v_kg.addWidget(QLabel("VirusTotal API Key (Optional):"))
        self.txt_virustotal = QLineEdit()
        self.txt_virustotal.setEchoMode(QLineEdit.Password)
        self.txt_virustotal.setPlaceholderText("Enter your VirusTotal v3 API key...")
        self.txt_virustotal.setText(saved_keys.get("virustotal", ""))
        v_kg.addWidget(self.txt_virustotal)

        lbl_free_hint = QLabel("ip-api.com geolocation and ASN lookups do not require an API key and work out of the box.")
        lbl_free_hint.setStyleSheet("color: #00e676; font-size: 11px;")
        v_kg.addWidget(lbl_free_hint)

        v_ti.addWidget(keys_group)
        v_ti.addStretch()
        self.tabs.addTab(tab_threat, "🛡 Threat Intelligence")

        main_layout.addWidget(self.tabs, 1)

        # Bottom Action Bar
        bottom_box = QHBoxLayout()
        self.btn_save = QPushButton("💾 Apply & Save Configuration")
        self.btn_save.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 8px 20px; border-radius: 4px;")
        self.btn_save.clicked.connect(self.save_settings)
        bottom_box.addStretch()
        bottom_box.addWidget(self.btn_save)

        main_layout.addLayout(bottom_box)

    def _on_preset_changed(self, index):
        if index > 0:
            val = self.preset_combo.itemData(index)
            self.bpf_input.setText(val)

    def save_settings(self):
        idx = self.iface_combo.currentIndex()
        if idx >= 0:
            self.selected_interface = self.iface_combo.itemData(idx)
        else:
            self.selected_interface = "Any"
        self.bpf_filter = self.bpf_input.text().strip()

        # Persist Anomaly Settings
        self.db.set_setting("z_score_threshold", self.spin_z_score.value())
        self.db.set_setting("port_scan_threshold", self.spin_port_scan.value())
        self.db.set_setting("warmup_samples", self.spin_warmup.value())

        # Persist Alert Grouping Settings
        self.db.set_setting("cooldown_seconds", self.spin_cooldown.value())

        # Persist API Keys
        self.intel_manager.set_api_keys(
            abuseipdb_key=self.txt_abuseipdb.text().strip(),
            virustotal_key=self.txt_virustotal.text().strip()
        )

        self.settings_applied.emit(self.selected_interface, self.bpf_filter)
        QMessageBox.information(self, "Settings Saved", "Configuration successfully saved and applied.")


class SettingsDialog(QDialog):
    """Modal wrapper around SettingsWidget."""
    def __init__(self, parent=None, current_iface=None, current_bpf=""):
        super().__init__(parent)
        self.setWindowTitle("Network Analyzer — Configuration Dialog")
        self.resize(600, 440)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.widget = SettingsWidget(self, current_iface, current_bpf)
        layout.addWidget(self.widget)
        self.widget.settings_applied.connect(self._on_applied)

    def _on_applied(self, iface: str, bpf: str):
        self.selected_interface = iface
        self.bpf_filter = bpf
        self.accept()
