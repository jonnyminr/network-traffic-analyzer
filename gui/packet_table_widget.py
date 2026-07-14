from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtCore import Qt
from datetime import datetime

class PacketTableWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.max_rows = 1000
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Time", "Source IP", "Src Port", "Dest IP", "Dst Port", "Protocol", "Size"])
        self.table.setColumnCount(7)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        layout.addWidget(self.table)

    def add_packet(self, packet_data):
        row_position = self.table.rowCount()
        
        # Enforce max rows
        if row_position >= self.max_rows:
            self.table.removeRow(0)
            row_position = self.max_rows - 1
            
        self.table.insertRow(row_position)
        
        # Time
        dt = datetime.fromtimestamp(packet_data['timestamp']).strftime('%H:%M:%S.%f')[:-3]
        self.table.setItem(row_position, 0, QTableWidgetItem(dt))
        
        # Source IP
        self.table.setItem(row_position, 1, QTableWidgetItem(str(packet_data.get('src_ip', ''))))
        
        # Source Port
        sport = str(packet_data.get('src_port', '')) if packet_data.get('src_port') is not None else ''
        self.table.setItem(row_position, 2, QTableWidgetItem(sport))
        
        # Dest IP
        self.table.setItem(row_position, 3, QTableWidgetItem(str(packet_data.get('dst_ip', ''))))
        
        # Dest Port
        dport = str(packet_data.get('dst_port', '')) if packet_data.get('dst_port') is not None else ''
        self.table.setItem(row_position, 4, QTableWidgetItem(dport))
        
        # Protocol
        self.table.setItem(row_position, 5, QTableWidgetItem(str(packet_data.get('protocol', ''))))
        
        # Size
        self.table.setItem(row_position, 6, QTableWidgetItem(str(packet_data.get('size', ''))))
        
        # Scroll to bottom if user is at the bottom
        scrollbar = self.table.verticalScrollBar()
        if scrollbar.value() == scrollbar.maximum():
            self.table.scrollToBottom()
