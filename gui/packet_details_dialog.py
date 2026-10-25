from datetime import datetime
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, 
                               QLabel, QPushButton, QGroupBox, QGridLayout, 
                               QTextEdit, QFrame)
from PySide6.QtCore import Qt

class PacketDetailsDialog(QDialog):
    """
    Modal dialog displaying safe, non-decrypted metadata for an inspected packet.
    """
    def __init__(self, parent=None, packet_data: dict = None):
        super().__init__(parent)
        self.setWindowTitle("Packet Metadata Inspection")
        self.resize(580, 520)
        self.packet_data = packet_data or {}
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Header Title
        title_label = QLabel("Packet Safe Metadata & Attribution")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #00e5ff;")
        layout.addWidget(title_label)

        # 1. Network & Transport Metadata Group
        meta_group = QGroupBox("Network && Transport Layer")
        meta_grid = QGridLayout(meta_group)
        meta_grid.setSpacing(8)

        ts = self.packet_data.get('timestamp', 0)
        try:
            dt_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        except Exception:
            dt_str = "N/A"

        items = [
            ("Timestamp:", dt_str, 0, 0),
            ("Packet Length:", f"{self.packet_data.get('size', 0)} bytes", 0, 2),
            ("Direction:", str(self.packet_data.get('direction', 'Unknown')), 1, 0),
            ("Protocol:", str(self.packet_data.get('protocol', 'Other')), 1, 2),
            ("Source IP:", str(self.packet_data.get('src_ip', '')), 2, 0),
            ("Destination IP:", str(self.packet_data.get('dst_ip', '')), 2, 2),
            ("Source Port:", str(self.packet_data.get('src_port') or 'N/A'), 3, 0),
            ("Destination Port:", str(self.packet_data.get('dst_port') or 'N/A'), 3, 2),
            ("TCP Flags:", str(self.packet_data.get('tcp_flags') or 'None'), 4, 0),
            ("Target Host:", str(self.packet_data.get('target_host') or 'N/A'), 4, 2)
        ]

        for label_text, val_text, row, col in items:
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color: #8e8e9f; font-weight: bold; font-size: 12px;")
            val = QLabel(val_text)
            val.setStyleSheet("color: #e0e0e0; font-size: 12px;")
            meta_grid.addWidget(lbl, row, col)
            meta_grid.addWidget(val, row, col + 1)

        layout.addWidget(meta_group)

        # 2. Attribution Analysis Group
        attr_group = QGroupBox("Website Attribution Details")
        attr_layout = QVBoxLayout(attr_group)

        attr_type = self.packet_data.get('attribution', 'Unknown')
        attr_label = QLabel(f"Attribution Type: <b style='color:#00e676;'>{attr_type}</b>")
        attr_layout.addWidget(attr_label)

        summary_text = self.packet_data.get('summary', 'No summary available.')
        summary_view = QTextEdit()
        summary_view.setReadOnly(True)
        summary_view.setPlainText(summary_text)
        summary_view.setMaximumHeight(70)
        summary_view.setStyleSheet("background-color: #1e1e24; border: 1px solid #363642; color: #d4d4d4;")
        attr_layout.addWidget(summary_view)

        layout.addWidget(attr_group)

        # 3. Privacy & Cryptographic Security Notice
        notice_frame = QFrame()
        notice_frame.setStyleSheet("""
            QFrame {
                background-color: #23232b;
                border-left: 4px solid #ffd600;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        notice_layout = QVBoxLayout(notice_frame)
        notice_title = QLabel("🔒 Payload Privacy & Cryptography Notice")
        notice_title.setStyleSheet("font-weight: bold; color: #ffd600; font-size: 11px;")
        notice_text = QLabel(
            "Application data payload is encrypted via TLS / HTTPS.\n"
            "In accordance with network security standards, encrypted payload contents and private credentials "
            "are not decrypted. Only transport headers, IP addresses, timing, ports, and unencrypted handshake "
            "metadata (e.g. SNI) are inspected."
        )
        notice_text.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        notice_text.setWordWrap(True)
        notice_layout.addWidget(notice_title)
        notice_layout.addWidget(notice_text)
        layout.addWidget(notice_frame)

        # Close button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setMinimumWidth(90)
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
