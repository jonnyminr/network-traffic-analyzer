import math
from typing import Dict, Any, List
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsLineItem, QGraphicsTextItem, QGraphicsItem,
    QPushButton, QToolTip
)
from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QPen, QBrush, QColor, QFont, QPainter

from core.connection_tracker import ConnectionTracker


class NodeItem(QGraphicsEllipseItem):
    """Represents a network endpoint in the topology map."""
    def __init__(self, x: float, y: float, radius: float, ip: str, is_local: bool, is_alerted: bool, bytes_val: int):
        super().__init__(x - radius, y - radius, radius * 2, radius * 2)
        self.ip = ip
        self.is_local = is_local
        self.is_alerted = is_alerted
        self.bytes_val = bytes_val

        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)

        # Styling
        if is_local:
            self.setBrush(QBrush(QColor("#00e5ff"))) # Cyan
            self.setPen(QPen(QColor("#ffffff"), 2))
        elif is_alerted:
            self.setBrush(QBrush(QColor("#ff5252"))) # Red
            self.setPen(QPen(QColor("#ff8a80"), 2))
        elif "192.168." in ip or "10." in ip or "172.16." in ip:
            self.setBrush(QBrush(QColor("#00e676"))) # Green for LAN
            self.setPen(QPen(QColor("#b9f6ca"), 1.5))
        else:
            self.setBrush(QBrush(QColor("#448aff"))) # Blue for External
            self.setPen(QPen(QColor("#82b1ff"), 1.5))

    def hoverEnterEvent(self, event):
        mb = self.bytes_val / (1024 * 1024)
        kb = self.bytes_val / 1024
        vol_str = f"{mb:.2f} MB" if mb >= 1.0 else f"{kb:.1f} KB"
        role = "Local Host" if self.is_local else ("LAN Host" if "192.168." in self.ip else "Remote Public Endpoint")
        status = "⚠️ Has Security Alerts" if self.is_alerted else "Normal Traffic"
        tip = f"<b>{self.ip}</b> ({role})<br>Volume: {vol_str}<br>Status: {status}"
        QToolTip.showText(event.screenPos(), tip)
        super().hoverEnterEvent(event)


class NetworkTopologyWidget(QWidget):
    """
    Interactive Node-Link Network Topology Visualizer.
    Accurately maps observed network endpoints connected to the local host
    without fabricating physical hardware topology.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tracker = ConnectionTracker()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header bar
        head_layout = QHBoxLayout()
        lbl_title = QLabel("🌐 Observed Network Endpoint Topology")
        lbl_title.setStyleSheet("color: #00e5ff; font-weight: bold; font-size: 13px;")
        head_layout.addWidget(lbl_title)

        lbl_disclaimer = QLabel(
            "Note: Shows observed communication relationships on your local interface. "
            "Does not invent router physical wiring."
        )
        lbl_disclaimer.setStyleSheet("color: #888898; font-size: 11px;")
        head_layout.addWidget(lbl_disclaimer)

        head_layout.addStretch()

        btn_refresh = QPushButton("🔄 Refresh Topology")
        btn_refresh.setStyleSheet("background: #363642; color: #fff; padding: 4px 12px; border-radius: 4px;")
        btn_refresh.clicked.connect(self.refresh_topology)
        head_layout.addWidget(btn_refresh)
        layout.addLayout(head_layout)

        # Legend
        leg_layout = QHBoxLayout()
        leg_layout.setSpacing(14)
        self._add_legend_item(leg_layout, "#00e5ff", "Local Host (Center)")
        self._add_legend_item(leg_layout, "#00e676", "Local LAN / Gateway")
        self._add_legend_item(leg_layout, "#448aff", "External Web / Cloud Server")
        self._add_legend_item(leg_layout, "#ff5252", "Endpoint with Security Alerts")
        leg_layout.addStretch()
        layout.addLayout(leg_layout)

        # Graphics Scene & View
        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QBrush(QColor("#1e1e24")))

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setRenderHint(QPainter.TextAntialiasing)
        self.view.setStyleSheet("background-color: #1e1e24; border: 1px solid #363642; border-radius: 6px;")
        layout.addWidget(self.view, 1)

    def _add_legend_item(self, layout: QHBoxLayout, color: str, text: str):
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {color}; font-size: 14px;")
        lbl = QLabel(text)
        lbl.setStyleSheet("color: #a0a0b0; font-size: 11px;")
        layout.addWidget(dot)
        layout.addWidget(lbl)

    def refresh_topology(self):
        self.scene.clear()
        endpoints = self.tracker.get_endpoints_overview()
        flows = self.tracker.get_all_flows_snapshot()

        if not endpoints:
            txt = self.scene.addText("No active endpoints observed yet. Start capture to map connections.")
            txt.setDefaultTextColor(QColor("#888898"))
            txt.setFont(QFont("Segoe UI", 12))
            txt.setPos(50, 100)
            return

        cx, cy = 400.0, 300.0
        # 1. Place Local Host in Center
        local_ip = "Local Host"
        if endpoints:
            # Most active LAN endpoint is usually local host
            local_ep = next((e for e in endpoints if "192.168." in e["ip"] or "10." in e["ip"] or "127." in e["ip"]), endpoints[0])
            local_ip = local_ep["ip"]

        center_radius = 26.0
        center_node = NodeItem(cx, cy, center_radius, local_ip, is_local=True, is_alerted=False, bytes_val=0)
        self.scene.addItem(center_node)

        # Local Host Text Label
        lbl_center = self.scene.addText(f"{local_ip}\n[Local Host]")
        lbl_center.setDefaultTextColor(QColor("#00e5ff"))
        lbl_center.setFont(QFont("Segoe UI", 9, QFont.Bold))
        lbl_center.setPos(cx - 36, cy + center_radius + 4)

        # 2. Place Remote Endpoints Radially
        remote_endpoints = [e for e in endpoints if e["ip"] != local_ip][:24] # Limit to top 24 endpoints for clarity
        total_remotes = len(remote_endpoints)
        if total_remotes == 0:
            return

        angle_step = (2.0 * math.pi) / total_remotes
        base_radius = 210.0

        for i, ep in enumerate(remote_endpoints):
            angle = i * angle_step
            # Stagger radial distance slightly for neat visuals
            dist = base_radius + (35.0 if i % 2 == 1 else -20.0)
            nx = cx + dist * math.cos(angle)
            ny = cy + dist * math.sin(angle)

            # Node size based on relative traffic volume
            node_r = 14.0 if ep["total_bytes"] > 500000 else 10.0
            has_alert = ep.get("associated_alerts", 0) > 0

            # Line to center
            line_width = 2.5 if ep["total_bytes"] > 1000000 else (1.5 if ep["total_bytes"] > 100000 else 0.8)
            line_color = QColor(255, 82, 82, 160) if has_alert else QColor(0, 229, 255, 90)
            line = self.scene.addLine(cx, cy, nx, ny, QPen(line_color, line_width))
            line.setZValue(1)

            # Remote node item
            node = NodeItem(nx, ny, node_r, ep["ip"], is_local=False, is_alerted=has_alert, bytes_val=ep["total_bytes"])
            node.setZValue(2)
            self.scene.addItem(node)

            # Text label
            lbl = self.scene.addText(ep["ip"])
            lbl.setDefaultTextColor(QColor("#ff5252" if has_alert else "#e0e0e0"))
            lbl.setFont(QFont("Segoe UI", 8))
            lbl.setPos(nx - 24, ny + node_r + 2)
            lbl.setZValue(3)
