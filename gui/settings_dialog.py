import sys
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, 
                               QLabel, QComboBox, QLineEdit, QPushButton, 
                               QDialogButtonBox, QGroupBox)
from utils.interfaces import get_network_interfaces

class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_iface=None, current_bpf=""):
        super().__init__(parent)
        self.setWindowTitle("Capture Settings")
        self.resize(550, 260)
        
        self.selected_interface = current_iface
        self.bpf_filter = current_bpf

        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(12)

        # 1. Network Interface Group
        iface_group = QGroupBox("Network Interface")
        iface_layout = QVBoxLayout(iface_group)
        
        self.iface_combo = QComboBox()
        
        # Populate interfaces using the intelligent detector
        if sys.platform != 'win32':
            self.iface_combo.addItem("Any (All interfaces)", userData="Any")

        detected_ifaces = get_network_interfaces()
        for item in detected_ifaces:
            self.iface_combo.addItem(item['display_label'], userData=item['name'])

        # Set currently selected iface
        if self.selected_interface:
            idx = self.iface_combo.findData(self.selected_interface)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)
            else:
                # Try matching by text
                for i in range(self.iface_combo.count()):
                    if str(self.selected_interface).lower() in self.iface_combo.itemText(i).lower():
                        self.iface_combo.setCurrentIndex(i)
                        break

        iface_layout.addWidget(self.iface_combo)
        
        hint_label = QLabel("Note: Select an [Active] interface with an IP address to capture live traffic.")
        hint_label.setStyleSheet("color: #8e8e9f; font-size: 11px;")
        iface_layout.addWidget(hint_label)
        
        main_layout.addWidget(iface_group)

        # 2. BPF Filter Group
        filter_group = QGroupBox("Berkeley Packet Filter (BPF)")
        filter_layout = QVBoxLayout(filter_group)
        
        preset_layout = QHBoxLayout()
        preset_label = QLabel("Quick Presets:")
        preset_label.setStyleSheet("font-size: 11px;")
        preset_layout.addWidget(preset_label)
        
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
        preset_layout.addWidget(self.preset_combo, stretch=1)
        filter_layout.addLayout(preset_layout)
        
        self.bpf_input = QLineEdit()
        self.bpf_input.setPlaceholderText("e.g. port 443 or leave blank to capture all traffic")
        self.bpf_input.setText(self.bpf_filter)
        filter_layout.addWidget(self.bpf_input)
        
        main_layout.addWidget(filter_group)

        # 3. Action Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        main_layout.addWidget(button_box)

    def _on_preset_changed(self, index):
        if index > 0:
            val = self.preset_combo.itemData(index)
            self.bpf_input.setText(val)

    def accept(self):
        idx = self.iface_combo.currentIndex()
        if idx >= 0:
            self.selected_interface = self.iface_combo.itemData(idx)
        else:
            self.selected_interface = "Any"
            
        self.bpf_filter = self.bpf_input.text().strip()
        super().accept()
