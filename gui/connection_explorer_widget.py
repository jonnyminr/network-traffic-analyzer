import time
import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QGroupBox, QGridLayout,
    QFileDialog, QMessageBox, QFrame, QMenu, QAbstractItemView,
    QTabWidget
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QBrush, QAction
from core.connection_tracker import ConnectionTracker
from gui.ip_threat_intel_dialog import IPThreatIntelDialog
from gui.network_topology_widget import NetworkTopologyWidget


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
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        self.sub_tabs = QTabWidget()
        self.sub_tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #363642; background: #1e1e24; border-radius: 6px; }
            QTabBar::tab { background: #25252c; color: #a0a0b0; padding: 6px 14px; font-weight: bold; }
            QTabBar::tab:selected { background: #1e1e24; color: #00e5ff; border-top: 2px solid #00e5ff; }
        """)

        # -------------------------------------------------------------
        # SUB-TAB 1: L4 Connection Flows
        # -------------------------------------------------------------
        flows_tab = QWidget()
        v_flow_tab = QVBoxLayout(flows_tab)
        v_flow_tab.setContentsMargins(6, 6, 6, 6)
        v_flow_tab.setSpacing(8)

        # 1. Top Filter Bar
        filter_frame = QFrame()
        filter_frame.setObjectName("FilterFrame")
        filter_frame.setStyleSheet("""
            QFrame#FilterFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        f_layout = QHBoxLayout(filter_frame)
        f_layout.setContentsMargins(4, 4, 4, 4)
        f_layout.setSpacing(8)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Search by IP address, port, or flow ID...")
        self.txt_search.setStyleSheet("background: #1e1e24; color: #fff; padding: 6px 10px; border: 1px solid #363642; border-radius: 4px;")
        self.txt_search.textChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.txt_search, 2)

        lbl_proto = QLabel("Protocol:")
        lbl_proto.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_proto)

        self.cmb_proto = QComboBox()
        self.cmb_proto.addItems(["All", "TCP", "UDP", "ICMP", "OTHER"])
        self.cmb_proto.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_proto.currentTextChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.cmb_proto)

        lbl_dir = QLabel("Direction:")
        lbl_dir.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_dir)

        self.cmb_direction = QComboBox()
        self.cmb_direction.addItems(["All Directions", "Inbound", "Outbound"])
        self.cmb_direction.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_direction.currentTextChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.cmb_direction)

        lbl_state = QLabel("State:")
        lbl_state.setStyleSheet("color: #a0a0b0; font-weight: bold;")
        f_layout.addWidget(lbl_state)

        self.cmb_state = QComboBox()
        self.cmb_state.addItems(["All States", "Active / Established", "Closed / Reset", "Idle / Expired"])
        self.cmb_state.setStyleSheet("background: #1e1e24; color: #fff; padding: 5px; border: 1px solid #363642;")
        self.cmb_state.currentTextChanged.connect(self._refresh_flows)
        f_layout.addWidget(self.cmb_state)

        self.btn_export = QPushButton("📥 Export CSV")
        self.btn_export.setStyleSheet("background: #363642; color: #00e5ff; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.btn_export.clicked.connect(self._export_csv)
        f_layout.addWidget(self.btn_export)

        v_flow_tab.addWidget(filter_frame)

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
        v_flow_tab.addLayout(stats_layout)

        # 3. Main Splitter: Flow Table and Flow Details
        splitter = QSplitter(Qt.Vertical)
        splitter.setStyleSheet("QSplitter::handle { background-color: #363642; height: 4px; }")

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
        self.detail_panel = self._create_detail_panel()
        splitter.addWidget(self.detail_panel)
        splitter.setSizes([340, 200])

        v_flow_tab.addWidget(splitter, 1)
        self.sub_tabs.addTab(flows_tab, "🔗 L4 Connection Flows")

        # -------------------------------------------------------------
        # SUB-TAB 2: Device & Host Overview
        # -------------------------------------------------------------
        endpoints_tab = self._init_host_overview_tab()
        self.sub_tabs.addTab(endpoints_tab, "🖥️ Device & Host Overview")

        # -------------------------------------------------------------
        # SUB-TAB 3: Network Topology Map
        # -------------------------------------------------------------
        self.topology_widget = NetworkTopologyWidget()
        self.sub_tabs.addTab(self.topology_widget, "🌐 Network Topology Map")

        self.sub_tabs.currentChanged.connect(self._on_sub_tab_changed)
        main_layout.addWidget(self.sub_tabs, 1)

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

    def _init_host_overview_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        # Passive Capture Scope Notice
        notice_frame = QFrame()
        notice_frame.setStyleSheet("""
            QFrame {
                background-color: #1a2233;
                border: 1px solid #283e66;
                border-radius: 6px;
                padding: 6px 12px;
            }
        """)
        h_not = QHBoxLayout(notice_frame)
        h_not.setContentsMargins(4, 4, 4, 4)
        lbl_sc = QLabel(
            "ℹ️ <b>Passive Capture Scope:</b> The endpoints listed below represent network devices communicating with "
            "or visible to your computer's selected network interface. Passive packet capture does not discover devices "
            "communicating strictly through other router ports that do not broadcast or send packets to your interface."
        )
        lbl_sc.setWordWrap(True)
        lbl_sc.setStyleSheet("color: #82b1ff; font-size: 11px;")
        h_not.addWidget(lbl_sc)
        layout.addWidget(notice_frame)

        # Overview Cards
        h_cards = QHBoxLayout()
        self.card_ep_total = self._create_stat_card("Total Endpoints", "0", "#00e5ff")
        self.card_ep_lan = self._create_stat_card("Local LAN Hosts", "0", "#00e676")
        self.card_ep_wan = self._create_stat_card("External Servers", "0", "#448aff")
        self.card_ep_alerts = self._create_stat_card("Alerted Endpoints", "0", "#ff5252")

        h_cards.addWidget(self.card_ep_total)
        h_cards.addWidget(self.card_ep_lan)
        h_cards.addWidget(self.card_ep_wan)
        h_cards.addWidget(self.card_ep_alerts)
        layout.addLayout(h_cards)

        # Search bar
        h_search = QHBoxLayout()
        self.txt_ep_search = QLineEdit()
        self.txt_ep_search.setPlaceholderText("🔍 Filter endpoints by IP address or scope (e.g. 192.168, Public)...")
        self.txt_ep_search.setStyleSheet("background: #25252c; color: #fff; padding: 6px 10px; border: 1px solid #363642; border-radius: 4px;")
        self.txt_ep_search.textChanged.connect(self._refresh_endpoints)
        h_search.addWidget(self.txt_ep_search)
        layout.addLayout(h_search)

        # Endpoints Table
        self.tbl_endpoints = QTableWidget(0, 9)
        self.tbl_endpoints.setHorizontalHeaderLabels([
            "IP Address", "Scope / Classification", "First Observed", "Last Observed",
            "Sent (Tx)", "Recv (Rx)", "Total Traffic", "Observed Connections", "Associated Alerts"
        ])
        self.tbl_endpoints.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tbl_endpoints.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl_endpoints.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_endpoints.setStyleSheet("background: #1e1e24; color: #fff; border: 1px solid #363642;")
        self.tbl_endpoints.cellDoubleClicked.connect(self._on_endpoint_double_clicked)
        layout.addWidget(self.tbl_endpoints, 1)

        return widget

    def _on_sub_tab_changed(self, index: int):
        if index == 1:
            self._refresh_endpoints()
        elif index == 2 and hasattr(self, 'topology_widget'):
            self.topology_widget.refresh_topology()

    def _refresh_endpoints(self):
        if not hasattr(self, 'tbl_endpoints'):
            return

        endpoints = self.tracker.get_endpoints_overview()
        total_ep = len(endpoints)
        lan_count = sum(1 for e in endpoints if "192.168." in e["ip"] or "10." in e["ip"] or "172.16." in e["ip"])
        wan_count = total_ep - lan_count
        alert_count = sum(1 for e in endpoints if e["associated_alerts"] > 0)

        self.card_ep_total.findChild(QLabel, "ValueLabel").setText(str(total_ep))
        self.card_ep_lan.findChild(QLabel, "ValueLabel").setText(str(lan_count))
        self.card_ep_wan.findChild(QLabel, "ValueLabel").setText(str(wan_count))
        self.card_ep_alerts.findChild(QLabel, "ValueLabel").setText(str(alert_count))

        query = self.txt_ep_search.text().strip().lower()
        filtered = []
        for e in endpoints:
            if query and query not in e["ip"].lower() and query not in e["classification"].lower():
                continue
            filtered.append(e)

        self.tbl_endpoints.setRowCount(len(filtered))
        self._filtered_endpoints = filtered

        for row, e in enumerate(filtered):
            self.tbl_endpoints.setItem(row, 0, QTableWidgetItem(e["ip"]))

            scope_item = QTableWidgetItem(e["classification"])
            if e["is_public"]:
                scope_item.setForeground(QBrush(QColor("#448aff")))
            else:
                scope_item.setForeground(QBrush(QColor("#00e676")))
            self.tbl_endpoints.setItem(row, 1, scope_item)

            first_dt = datetime.datetime.fromtimestamp(e["first_seen"]).strftime("%H:%M:%S")
            last_dt = datetime.datetime.fromtimestamp(e["last_seen"]).strftime("%H:%M:%S")
            self.tbl_endpoints.setItem(row, 2, QTableWidgetItem(first_dt))
            self.tbl_endpoints.setItem(row, 3, QTableWidgetItem(last_dt))

            self.tbl_endpoints.setItem(row, 4, QTableWidgetItem(format_bytes(e["bytes_sent"])))
            self.tbl_endpoints.setItem(row, 5, QTableWidgetItem(format_bytes(e["bytes_recv"])))
            self.tbl_endpoints.setItem(row, 6, QTableWidgetItem(format_bytes(e["total_bytes"])))
            self.tbl_endpoints.setItem(row, 7, QTableWidgetItem(str(e["connection_count"])))

            al_item = QTableWidgetItem(str(e["associated_alerts"]))
            if e["associated_alerts"] > 0:
                al_item.setForeground(QBrush(QColor("#ff5252")))
            self.tbl_endpoints.setItem(row, 8, al_item)

    def _on_endpoint_double_clicked(self, row: int, col: int):
        if hasattr(self, '_filtered_endpoints') and row < len(self._filtered_endpoints):
            ip = self._filtered_endpoints[row]["ip"]
            # Switch to L4 flows tab and filter by this IP
            self.sub_tabs.setCurrentIndex(0)
            self.filter_by_ip(ip)
