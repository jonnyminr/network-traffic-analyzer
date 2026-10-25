import time
import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QGridLayout,
    QFileDialog, QMessageBox, QFrame, QMenu, QAbstractItemView
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QBrush, QAction
from core.connection_tracker import ConnectionTracker
from gui.ip_threat_intel_dialog import IPThreatIntelDialog


def format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.2f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"


class ConnectionExplorerWidget(QWidget):
    """
    Dedicated Network Connection Explorer tab for inspecting, filtering,
    and correlating observed L4 network flows.
    """
    inspect_flow_packets_requested = Signal(str, str, int, int, str) # src_ip, dst_ip, sport, dport, proto

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tracker = ConnectionTracker()
        self.local_ip = "127.0.0.1"

        self._init_ui()

        # Update timer (every 1 second)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh_flows)
        self.timer.start(1000)

    def set_local_ip(self, ip: str):
        self.local_ip = ip
        self.tracker.set_local_ip(ip)

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(10)

        # 1. Top Summary Banner & Filter Bar
        filter_frame = QFrame()
        filter_frame.setObjectName("FilterFrame")
        filter_frame.setStyleSheet("""
            QFrame#FilterFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        f_layout = QHBoxLayout(filter_frame)
        f_layout.setContentsMargins(6, 6, 6, 6)
        f_layout.setSpacing(10)

        # Search box
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Search by IP address, port, or flow ID...")
        self.txt_search.setStyleSheet("background: #1e1e24; color: #fff; padding: 6px 10px; border: 1px solid #363642; border-radius: 4px;")
        self.txt_search.textChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.txt_search, 2)

        # Protocol Filter
        lbl_proto = QLabel("Protocol:")
        lbl_proto.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_proto)

        self.cmb_proto = QComboBox()
        self.cmb_proto.addItems(["All", "TCP", "UDP", "ICMP", "OTHER"])
        self.cmb_proto.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_proto.currentTextChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.cmb_proto)

        # Direction Filter
        lbl_dir = QLabel("Direction:")
        lbl_dir.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_dir)

        self.cmb_direction = QComboBox()
        self.cmb_direction.addItems(["All Directions", "Inbound", "Outbound"])
        self.cmb_direction.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_direction.currentTextChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.cmb_direction)

        # State Filter
        lbl_state = QLabel("State:")
        lbl_state.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_state)

        self.cmb_state = QComboBox()
        self.cmb_state.addItems(["All States", "Active / Established", "Closed / Reset", "Idle / Expired"])
        self.cmb_state.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_state.currentTextChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.cmb_state)

        # Export CSV Button
        self.btn_export = QPushButton("📥 Export CSV")
        self.btn_export.setStyleSheet("background: #363642; color: #00e5ff; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.btn_export.clicked.connect(self._export_csv)
        f_layout.addWidget(self.btn_export)

        main_layout.addWidget(filter_frame)

        # 2. Metric Counters Banner
        stats_layout = QHBoxLayout()
        self.card_total_flows = self._create_stat_card("Total Flows", "0", "#00e5ff")
        self.card_active_flows = self._create_stat_card("Active Flows", "0", "#00e676")
        self.card_total_bytes = self._create_stat_card("Total Volume", "0 B", "#ffd600")
        self.card_public_hosts = self._create_stat_card("Public Endpoints", "0", "#ff9100")

        stats_layout.addWidget(self.card_total_flows)
        stats_layout.addWidget(self.card_active_flows)
        stats_layout.addWidget(self.card_total_bytes)
        stats_layout.addWidget(self.card_public_hosts)
        main_layout.addLayout(stats_layout)

        # 3. Main Splitter: Flow Table (Top) and Flow Details (Bottom)
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #363642;
                height: 4px;
            }
        """)

        # Table Widget
        self.table = QTableWidget()
        self.table.setColumnCount(13)
        self.table.setHorizontalHeaderLabels([
            "Flow ID", "Source IP", "Src Port", "Destination IP", "Dst Port",
            "Proto", "State / Status", "Duration", "Packets",
            "Sent", "Recv", "Total Bytes", "Alerts"
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #1e1e24;
                alternate-background-color: #25252c;
                color: #e0e0e0;
                border: 1px solid #363642;
                border-radius: 6px;
                gridline-color: #2e2e38;
            }
            QHeaderView::section {
                background-color: #25252c;
                color: #00e5ff;
                padding: 6px;
                border: 1px solid #363642;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background-color: #2a3b5c;
                color: #ffffff;
            }
        """)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._on_flow_selected)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)

        splitter.addWidget(self.table)

        # 4. Detail Panel (Bottom)
        self.detail_panel = self._create_detail_panel()
        splitter.addWidget(self.detail_panel)
        splitter.setSizes([380, 220])

        main_layout.addWidget(splitter, 1)

    def _create_stat_card(self, title: str, val: str, color: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(f"""
            QFrame {{
                background-color: #25252c;
                border-left: 3px solid {color};
                border-radius: 6px;
                padding: 6px 12px;
            }}
        """)
        v = QVBoxLayout(frame)
        v.setContentsMargins(4, 4, 4, 4)
        v.setSpacing(2)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("color: #888898; font-size: 11px; font-weight: bold;")
        lbl_v = QLabel(val)
        lbl_v.setObjectName("ValueLabel")
        lbl_v.setStyleSheet(f"color: {color}; font-size: 16px; font-weight: bold;")
        v.addWidget(lbl_t)
        v.addWidget(lbl_v)
        return frame

    def _create_detail_panel(self) -> QGroupBox:
        group = QGroupBox("Selected Connection Details && Attribution")
        group.setStyleSheet("""
            QGroupBox {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                margin-top: 10px;
                font-weight: bold;
                color: #00e5ff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
        """)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(12, 16, 12, 12)
        layout.setSpacing(8)

        grid = QGridLayout()
        grid.setSpacing(8)

        self.lbl_det_endpoints = QLabel("No connection selected.")
        self.lbl_det_endpoints.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 13px;")
        grid.addWidget(self.lbl_det_endpoints, 0, 0, 1, 4)

        self.lbl_det_state = QLabel("--")
        self.lbl_det_timestamps = QLabel("--")
        self.lbl_det_packets = QLabel("--")
        self.lbl_det_bytes = QLabel("--")
        self.lbl_det_attribution = QLabel("--")

        def _k(t):
            l = QLabel(t)
            l.setStyleSheet("color: #888898; font-weight: bold;")
            return l

        grid.addWidget(_k("TCP/Flow State:"), 1, 0)
        grid.addWidget(self.lbl_det_state, 1, 1)
        grid.addWidget(_k("Timestamps:"), 1, 2)
        grid.addWidget(self.lbl_det_timestamps, 1, 3)

        grid.addWidget(_k("Packet Counts:"), 2, 0)
        grid.addWidget(self.lbl_det_packets, 2, 1)
        grid.addWidget(_k("Bandwidth Split:"), 2, 2)
        grid.addWidget(self.lbl_det_bytes, 2, 3)

        grid.addWidget(_k("Attribution / Evidence:"), 3, 0)
        grid.addWidget(self.lbl_det_attribution, 3, 1, 1, 3)

        layout.addLayout(grid)

        # Quick Actions Bar
        h_actions = QHBoxLayout()
        self.btn_threat_src = QPushButton("🛡 Threat Intel (Source IP)")
        self.btn_threat_src.setStyleSheet("background-color: #363642; color: #fff; padding: 5px 12px; border-radius: 4px;")
        self.btn_threat_src.clicked.connect(self._lookup_src_threat)
        h_actions.addWidget(self.btn_threat_src)

        self.btn_threat_dst = QPushButton("🛡 Threat Intel (Destination IP)")
        self.btn_threat_dst.setStyleSheet("background-color: #363642; color: #fff; padding: 5px 12px; border-radius: 4px;")
        self.btn_threat_dst.clicked.connect(self._lookup_dst_threat)
        h_actions.addWidget(self.btn_threat_dst)

        self.btn_filter_packets = QPushButton("🔍 Inspect Flow Packets")
        self.btn_filter_packets.setStyleSheet("background-color: #1e3a5f; color: #00e5ff; font-weight: bold; padding: 5px 12px; border-radius: 4px;")
        self.btn_filter_packets.clicked.connect(self._on_inspect_packets_clicked)
        h_actions.addWidget(self.btn_filter_packets)

        h_actions.addStretch()
        layout.addLayout(h_actions)

        return group

    def _refresh_flows(self):
        flows = self.tracker.get_all_flows_snapshot()

        # Update Stat Cards
        active_count = sum(1 for f in flows if "ESTABLISHED" in f["tcp_state"] or f["tcp_state"] == "ACTIVE" or "SYN" in f["tcp_state"])
        total_bytes = sum(f["total_bytes"] for f in flows)
        public_hosts = set()
        for f in flows:
            if f.get("src_is_public"):
                public_hosts.add(f["src_ip"])
            if f.get("dst_is_public"):
                public_hosts.add(f["dst_ip"])

        self.card_total_flows.findChild(QLabel, "ValueLabel").setText(str(len(flows)))
        self.card_active_flows.findChild(QLabel, "ValueLabel").setText(str(active_count))
        self.card_total_bytes.findChild(QLabel, "ValueLabel").setText(format_bytes(total_bytes))
        self.card_public_hosts.findChild(QLabel, "ValueLabel").setText(str(len(public_hosts)))

        # Filtering
        query = self.txt_search.text().strip().lower()
        proto_filter = self.cmb_proto.currentText().upper()
        dir_filter = self.cmb_direction.currentText()
        state_filter = self.cmb_state.currentText()

        filtered = []
        for f in flows:
            # Protocol match
            if proto_filter != "ALL" and f["protocol"] != proto_filter:
                continue

            # Direction match
            if dir_filter == "Inbound":
                if f["dst_ip"] != self.local_ip:
                    continue
            elif dir_filter == "Outbound":
                if f["src_ip"] != self.local_ip:
                    continue

            # State match
            st = f["tcp_state"]
            if state_filter == "Active / Established" and not ("ESTABLISHED" in st or st == "ACTIVE" or "SYN" in st):
                continue
            elif state_filter == "Closed / Reset" and not ("CLOSED" in st or "RESET" in st or "CLOSING" in st):
                continue
            elif state_filter == "Idle / Expired" and "IDLE" not in st:
                continue

            # Text query match
            if query:
                match_txt = (
                    query in f["flow_id"].lower() or
                    query in f["src_ip"].lower() or
                    query in f["dst_ip"].lower() or
                    query == str(f["src_port"]) or
                    query == str(f["dst_port"])
                )
                if not match_txt:
                    continue

            filtered.append(f)

        # Retain selected flow ID if any
        selected_flow_id = None
        current_row = self.table.currentRow()
        if current_row >= 0 and current_row < self.table.rowCount():
            item = self.table.item(current_row, 0)
            if item:
                selected_flow_id = item.text()

        # Sort filtered flows by last seen descending
        filtered.sort(key=lambda x: x["last_seen"], reverse=True)

        self.table.setRowCount(len(filtered))
        restore_row = -1

        for row, f in enumerate(filtered):
            if f["flow_id"] == selected_flow_id:
                restore_row = row

            self.table.setItem(row, 0, QTableWidgetItem(f["flow_id"]))

            # Source IP item with scope indicator
            src_str = f"{f['src_ip']}"
            if not f.get("src_is_public"):
                src_str += " 🔒 [Private]"
            item_src = QTableWidgetItem(src_str)
            if not f.get("src_is_public"):
                item_src.setForeground(QBrush(QColor("#81c784"))) # soft green
            self.table.setItem(row, 1, item_src)

            self.table.setItem(row, 2, QTableWidgetItem(str(f["src_port"] or "-")))

            # Destination IP item
            dst_str = f"{f['dst_ip']}"
            if not f.get("dst_is_public"):
                dst_str += " 🔒 [Private]"
            item_dst = QTableWidgetItem(dst_str)
            if not f.get("dst_is_public"):
                item_dst.setForeground(QBrush(QColor("#81c784")))
            self.table.setItem(row, 3, item_dst)

            self.table.setItem(row, 4, QTableWidgetItem(str(f["dst_port"] or "-")))
            self.table.setItem(row, 5, QTableWidgetItem(f["protocol"]))

            # State styling
            st_item = QTableWidgetItem(f["tcp_state"])
            if "ESTABLISHED" in f["tcp_state"] or f["tcp_state"] == "ACTIVE":
                st_item.setForeground(QBrush(QColor("#00e676")))
            elif "RESET" in f["tcp_state"]:
                st_item.setForeground(QBrush(QColor("#ff5252")))
            elif "SYN" in f["tcp_state"]:
                st_item.setForeground(QBrush(QColor("#ffd600")))
            elif "IDLE" in f["tcp_state"]:
                st_item.setForeground(QBrush(QColor("#808090")))
            self.table.setItem(row, 6, st_item)

            self.table.setItem(row, 7, QTableWidgetItem(f"{f['duration']:.1f}s"))
            self.table.setItem(row, 8, QTableWidgetItem(str(f["packets"])))
            self.table.setItem(row, 9, QTableWidgetItem(format_bytes(f["bytes_sent"])))
            self.table.setItem(row, 10, QTableWidgetItem(format_bytes(f["bytes_recv"])))
            self.table.setItem(row, 11, QTableWidgetItem(format_bytes(f["total_bytes"])))

            alert_item = QTableWidgetItem(str(f["related_alerts_count"]))
            if f["related_alerts_count"] > 0:
                alert_item.setForeground(QBrush(QColor("#ff5252")))
            self.table.setItem(row, 12, alert_item)

        if restore_row >= 0:
            self.table.selectRow(restore_row)

    def _on_flow_selected(self):
        row = self.table.currentRow()
        if row < 0 or row >= self.table.rowCount():
            return
        flow_id = self.table.item(row, 0).text()
        flow = self.tracker.get_flow_by_id(flow_id)
        if not flow:
            return

        self._active_flow = flow
        f_dict = flow.to_dict()

        self.lbl_det_endpoints.setText(
            f"<b>{flow.initiator_ip}:{flow.initiator_port}</b> ➔ <b>{flow.responder_ip}:{flow.responder_port}</b> "
            f"[{flow.protocol}] (Flow ID: {flow.flow_id})"
        )
        self.lbl_det_state.setText(f"{flow.tcp_state}")
        first_dt = datetime.datetime.fromtimestamp(flow.first_seen).strftime("%H:%M:%S")
        last_dt = datetime.datetime.fromtimestamp(flow.last_seen).strftime("%H:%M:%S")
        self.lbl_det_timestamps.setText(f"First: {first_dt} | Last: {last_dt} ({flow.duration:.1f}s)")
        self.lbl_det_packets.setText(f"Total: {flow.total_packets} (Sent: {flow.packets_sent}, Recv: {flow.packets_recv})")
        self.lbl_det_bytes.setText(
            f"Total: {format_bytes(flow.total_bytes)} | Out: {format_bytes(flow.bytes_sent)} | In: {format_bytes(flow.bytes_recv)}"
        )
        self.lbl_det_attribution.setText(
            f"{flow.attribution_type} | Src: {f_dict['src_scope']} | Dst: {f_dict['dst_scope']} | Alerts Linked: {len(flow.related_alerts)}"
        )

    def _lookup_src_threat(self):
        if hasattr(self, "_active_flow") and self._active_flow:
            dlg = IPThreatIntelDialog(self._active_flow.initiator_ip, parent=self)
            dlg.exec()

    def _lookup_dst_threat(self):
        if hasattr(self, "_active_flow") and self._active_flow:
            dlg = IPThreatIntelDialog(self._active_flow.responder_ip, parent=self)
            dlg.exec()

    def _on_inspect_packets_clicked(self):
        if hasattr(self, "_active_flow") and self._active_flow:
            f = self._active_flow
            self.inspect_flow_packets_requested.emit(
                f.initiator_ip, f.responder_ip, f.initiator_port, f.responder_port, f.protocol
            )

    def _show_context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        self.table.selectRow(row)
        flow_id = self.table.item(row, 0).text()
        flow = self.tracker.get_flow_by_id(flow_id)
        if not flow:
            return

        menu = QMenu(self)
        act_threat_src = menu.addAction(f"🛡 Check Threat Intel: {flow.initiator_ip}")
        act_threat_dst = menu.addAction(f"🛡 Check Threat Intel: {flow.responder_ip}")
        menu.addSeparator()
        act_inspect_pkts = menu.addAction("🔍 Inspect Packets for this Flow")
        act_filter_ip = menu.addAction(f"Filter flows for {flow.responder_ip}")

        action = menu.exec(self.table.viewport().mapToGlobal(pos))
        if action == act_threat_src:
            IPThreatIntelDialog(flow.initiator_ip, parent=self).exec()
        elif action == act_threat_dst:
            IPThreatIntelDialog(flow.responder_ip, parent=self).exec()
        elif action == act_inspect_pkts:
            self._on_inspect_packets_clicked()
        elif action == act_filter_ip:
            self.filter_by_ip(flow.responder_ip)

    def filter_by_ip(self, ip: str):
        """Top Talkers and external widgets call this to focus on an IP."""
        self.txt_search.setText(ip)

    def _export_csv(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export Observed Connections", "flows_export.csv", "CSV Files (*.csv)"
        )
        if filepath:
            success = self.tracker.export_to_csv(filepath)
            if success:
                QMessageBox.information(self, "Export Complete", f"Successfully exported connections to:\n{filepath}")
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export connections. Check logs.")
