from PySide6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel
from PySide6.QtCore import Qt
from datetime import datetime

class AlertsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        header = QLabel("Security Alerts")
        header.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(header)
        
        self.alerts_list = QListWidget()
        layout.addWidget(self.alerts_list)

    def add_alert(self, alert_data):
        """
        alert_data should be a dict: {'timestamp': float, 'severity': str, 'description': str}
        """
        dt = datetime.fromtimestamp(alert_data['timestamp']).strftime('%H:%M:%S')
        severity = alert_data.get('severity', 'Info')
        desc = alert_data.get('description', '')
        
        text = f"[{dt}] [{severity}] {desc}"
        item = QListWidgetItem(text)
        
        if severity == 'Critical':
            item.setForeground(Qt.red)
        elif severity == 'Warning':
            item.setForeground(Qt.darkYellow)
            
        self.alerts_list.insertItem(0, item) # Insert at top
        
        # Keep only the last 100 alerts
        if self.alerts_list.count() > 100:
            self.alerts_list.takeItem(self.alerts_list.count() - 1)
