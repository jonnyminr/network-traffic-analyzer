from datetime import datetime
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                               QListWidget, QListWidgetItem, QLabel, QPushButton)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

class AlertsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.critical_count = 0
        self.warning_count = 0
        self.all_alerts = []
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)
        
        # Header bar
        header_layout = QHBoxLayout()
        header = QLabel("Security Alerts")
        header.setStyleSheet("font-weight: bold; font-size: 13px; color: #d4d4d4;")
        header_layout.addWidget(header)
        
        self.badge_label = QLabel("0 alerts")
        self.badge_label.setStyleSheet("color: #8e8e9f; font-size: 11px;")
        header_layout.addWidget(self.badge_label)
        
        header_layout.addStretch()
        
        clear_btn = QPushButton("Clear")
        clear_btn.setMaximumWidth(60)
        clear_btn.clicked.connect(self.clear_alerts)
        header_layout.addWidget(clear_btn)
        
        layout.addLayout(header_layout)
        
        self.alerts_list = QListWidget()
        self.alerts_list.setStyleSheet("""
            QListWidget {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 6px;
                padding: 4px;
            }
            QListWidget::item {
                padding: 4px;
                border-bottom: 1px solid #2e2e38;
            }
        """)
        layout.addWidget(self.alerts_list)

    def add_alert(self, alert_data: dict):
        """
        alert_data format: {'timestamp': float, 'severity': str, 'description': str}
        """
        self.all_alerts.append(alert_data)
        ts = alert_data.get('timestamp', 0)
        try:
            dt = datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        except Exception:
            dt = "00:00:00"
            
        severity = alert_data.get('severity', 'Info')
        desc = alert_data.get('description', '')
        
        if severity == 'Critical':
            self.critical_count += 1
            color = QColor('#ff5252')
        elif severity == 'Warning':
            self.warning_count += 1
            color = QColor('#ffb74d')
        else:
            color = QColor('#81d4fa')
            
        text = f"[{dt}] [{severity.upper()}] {desc}"
        item = QListWidgetItem(text)
        item.setForeground(color)
        
        self.alerts_list.insertItem(0, item) # Insert latest at top
        
        # Limit visible list to 150 items
        if self.alerts_list.count() > 150:
            self.alerts_list.takeItem(self.alerts_list.count() - 1)
            
        self.badge_label.setText(f"{self.critical_count} critical, {self.warning_count} warnings")

    def clear_alerts(self):
        """Clears all alerts."""
        self.alerts_list.clear()
        self.all_alerts.clear()
        self.critical_count = 0
        self.warning_count = 0
        self.badge_label.setText("0 alerts")

    def get_alerts(self):
        """Returns the list of stored alert records."""
        return self.all_alerts
