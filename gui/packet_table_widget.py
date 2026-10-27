from collections import deque
from datetime import datetime
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                               QTableWidgetItem, QHeaderView, QLineEdit, 
                               QPushButton, QCheckBox, QLabel)
from PySide6.QtCore import Qt, QTimer

class PacketTableWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.max_rows = 1500
        self.packet_buffer = deque()
        self.row_packets = []
        
        self.init_ui()
        
        # Batch timer: flushes packet buffer to UI every 100ms (10 FPS)
        # This prevents UI freezing during high-throughput packet bursts
        self.batch_timer = QTimer(self)
        self.batch_timer.setInterval(100)
        self.batch_timer.timeout.connect(self._flush_batch)
        self.batch_timer.start()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 0)
        layout.setSpacing(6)
        
        # Control Bar: Search Filter & Controls
        ctrl_layout = QHBoxLayout()
        ctrl_layout.setSpacing(8)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter packets (IP, port, protocol)...")
        self.search_input.textChanged.connect(self._apply_filter)
        ctrl_layout.addWidget(self.search_input, stretch=3)
        
        self.autoscroll_check = QCheckBox("Auto-scroll")
        self.autoscroll_check.setChecked(True)
        ctrl_layout.addWidget(self.autoscroll_check)
        
        self.count_label = QLabel("Packets: 0")
        self.count_label.setStyleSheet("color: #8e8e9f; font-weight: bold;")
        ctrl_layout.addWidget(self.count_label)
        
        clear_btn = QPushButton("Clear Table")
        clear_btn.clicked.connect(self.clear_table)
        ctrl_layout.addWidget(clear_btn)
        
        layout.addLayout(ctrl_layout)
        
        # Table
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Src Port", "Dest IP", "Dst Port", "Protocol", "Size"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        
        layout.addWidget(self.table)

    def add_packet(self, packet_data: dict):
        """Enqueue packet for batch processing."""
        self.packet_buffer.append(packet_data)

    def _flush_batch(self):
        """Batch inserts queued packets into the table."""
        if not self.packet_buffer:
            return
            
        self.table.setUpdatesEnabled(False)
        current_filter = self.search_input.text().strip().lower()
        
        while self.packet_buffer:
            pkt = self.packet_buffer.popleft()
            row = self.table.rowCount()
            
            # Trim oldest rows if exceeding max_rows
            if row >= self.max_rows:
                self.table.removeRow(0)
                row = self.max_rows - 1
                
            self.table.insertRow(row)
            
            # Format time
            ts = pkt.get('timestamp', 0)
            try:
                dt_str = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]
            except Exception:
                dt_str = "00:00:00.000"
            self.table.setItem(row, 0, QTableWidgetItem(dt_str))
            
            src_ip = str(pkt.get('src_ip', ''))
            self.table.setItem(row, 1, QTableWidgetItem(src_ip))
            
            sport = str(pkt.get('src_port', '')) if pkt.get('src_port') is not None else ''
            self.table.setItem(row, 2, QTableWidgetItem(sport))
            
            dst_ip = str(pkt.get('dst_ip', ''))
            self.table.setItem(row, 3, QTableWidgetItem(dst_ip))
            
            dport = str(pkt.get('dst_port', '')) if pkt.get('dst_port') is not None else ''
            self.table.setItem(row, 4, QTableWidgetItem(dport))
            
            proto = str(pkt.get('protocol', ''))
            self.table.setItem(row, 5, QTableWidgetItem(proto))
            
            size = str(pkt.get('size', ''))
            self.table.setItem(row, 6, QTableWidgetItem(size))

            # Store reference to packet dict for double click inspection
            self.row_packets.append(pkt)
            if len(self.row_packets) > self.max_rows:
                self.row_packets.pop(0)
            
            # If a filter is currently active, apply visibility
            if current_filter:
                row_text = f"{src_ip} {sport} {dst_ip} {dport} {proto}".lower()
                self.table.setRowHidden(row, current_filter not in row_text)

        self.table.setUpdatesEnabled(True)
        self.count_label.setText(f"Packets: {self.table.rowCount():,}")
        
        if self.autoscroll_check.isChecked():
            self.table.scrollToBottom()

    def add_packet_batch(self, packets: list):
        """Enqueue an entire batch of packets."""
        self.packet_buffer.extend(packets)

    def _on_cell_double_clicked(self, row: int, col: int):
        from gui.packet_details_dialog import PacketDetailsDialog
        if 0 <= row < len(self.row_packets):
            pkt_dict = self.row_packets[row]
            dlg = PacketDetailsDialog(pkt_dict, parent=self)
            dlg.exec()

    def _apply_filter(self, filter_text: str):
        """Filters table rows based on search input."""
        query = filter_text.strip().lower()
        for row in range(self.table.rowCount()):
            if not query:
                self.table.setRowHidden(row, False)
            else:
                match = False
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item and query in item.text().lower():
                        match = True
                        break
                self.table.setRowHidden(row, not match)

    def clear_table(self):
        """Clears all packet rows and pending queue."""
        self.packet_buffer.clear()
        self.row_packets.clear()
        self.table.setRowCount(0)
        self.count_label.setText("Packets: 0")
