from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, 
                               QLabel, QComboBox, QLineEdit, QPushButton, QDialogButtonBox)
from scapy.all import conf

class SettingsDialog(QDialog):
    def __init__(self, parent=None, current_iface=None, current_bpf=""):
        super().__init__(parent)
        self.setWindowTitle("Capture Settings")
        self.resize(400, 150)
        
        self.selected_interface = current_iface
        self.bpf_filter = current_bpf

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Interface selection
        iface_layout = QHBoxLayout()
        iface_label = QLabel("Network Interface:")
        self.iface_combo = QComboBox()
        
        # Populate interfaces
        self.iface_combo.addItem("Any")
        
        # Try to get scapy interfaces
        try:
            for iface_name, iface_data in conf.ifaces.items():
                # On Windows, names might be UUIDs, description is better if available
                display_name = getattr(iface_data, 'description', iface_data.name)
                # Store the actual name to pass to sniff() as UserData
                self.iface_combo.addItem(f"{display_name} ({iface_data.name})", userData=iface_data.name)
        except Exception:
            pass # Fallback to empty if it fails

        # Set current iface
        if self.selected_interface:
            idx = self.iface_combo.findData(self.selected_interface)
            if idx >= 0:
                self.iface_combo.setCurrentIndex(idx)

        iface_layout.addWidget(iface_label)
        iface_layout.addWidget(self.iface_combo)
        layout.addLayout(iface_layout)

        # BPF Filter
        bpf_layout = QHBoxLayout()
        bpf_label = QLabel("BPF Filter:")
        self.bpf_input = QLineEdit()
        self.bpf_input.setPlaceholderText("e.g. tcp port 80")
        self.bpf_input.setText(self.bpf_filter)
        bpf_layout.addWidget(bpf_label)
        bpf_layout.addWidget(self.bpf_input)
        layout.addLayout(bpf_layout)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def accept(self):
        idx = self.iface_combo.currentIndex()
        if idx == 0:
            self.selected_interface = "Any"
        else:
            self.selected_interface = self.iface_combo.itemData(idx)
            
        self.bpf_filter = self.bpf_input.text().strip()
        super().accept()
