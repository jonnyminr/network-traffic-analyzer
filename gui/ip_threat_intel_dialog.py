import datetime
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QProgressBar, QGroupBox, QGridLayout, QTextBrowser,
    QTabWidget, QWidget, QFrame
)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from core.threat_intelligence import ThreatIntelWorker, classify_ip_address


class IPThreatIntelDialog(QDialog):
    """
    Rich modal for inspecting IP reputation, geolocation, ASN,
    and external threat intelligence with privacy protections.
    """
    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.worker = None

        self.setWindowTitle(f"Threat Intelligence & IP Reputation — {self.ip}")
        self.resize(720, 580)
        self.setMinimumSize(640, 500)

        self._init_ui()
        self._start_lookup(force_refresh=False)

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # 1. Header Box
        header_frame = QFrame()
        header_frame.setObjectName("HeaderFrame")
        header_frame.setStyleSheet("""
            QFrame#HeaderFrame {
                background-color: #25252c;
                border: 1px solid #363642;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        h_layout = QHBoxLayout(header_frame)
        h_layout.setContentsMargins(8, 8, 8, 8)

        v_titles = QVBoxLayout()
        self.lbl_title = QLabel(f"IP Target: <b style='color:#00e5ff; font-size:18px;'>{self.ip}</b>")
        self.lbl_title.setTextFormat(Qt.RichText)
        self.lbl_scope = QLabel("Classifying address...")
        self.lbl_scope.setStyleSheet("color: #a0a0b0; font-size: 12px;")
        v_titles.addWidget(self.lbl_title)
        v_titles.addWidget(self.lbl_scope)
        h_layout.addLayout(v_titles)

        h_layout.addStretch()

        # Score Gauge Box
        v_score = QVBoxLayout()
        v_score.setAlignment(Qt.AlignCenter)
        self.lbl_score_val = QLabel("--")
        self.lbl_score_val.setAlignment(Qt.AlignCenter)
        self.lbl_score_val.setStyleSheet("font-size: 24px; font-weight: bold; color: #00e5ff;")
        self.lbl_score_desc = QLabel("Threat Score")
        self.lbl_score_desc.setStyleSheet("color: #808090; font-size: 11px;")
        v_score.addWidget(self.lbl_score_val)
        v_score.addWidget(self.lbl_score_desc)
        h_layout.addLayout(v_score)

        layout.addWidget(header_frame)

        # 2. Loading / Status Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0) # indeterminate
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #1e1e24;
            }
            QProgressBar::chunk {
                background-color: #00e5ff;
            }
        """)
        layout.addWidget(self.progress_bar)

        # 3. Privacy & Safety Notice
        self.lbl_privacy = QLabel()
        self.lbl_privacy.setWordWrap(True)
        self.lbl_privacy.setStyleSheet("color: #7986cb; background: #1c2038; border: 1px solid #283593; border-radius: 6px; padding: 6px 10px; font-size: 11px;")
        self.lbl_privacy.setText("🛡 <b>Privacy Guard Active:</b> RFC 1918, loopback, and internal IPs are never sent to external services. Public lookups are on-demand only.")
        layout.addWidget(self.lbl_privacy)

        # 4. Details Grid in GroupBox
        details_group = QGroupBox("Enrichment && Geolocation")
        grid = QGridLayout(details_group)
        grid.setSpacing(10)
        grid.setContentsMargins(12, 14, 12, 12)

        self.lbl_country = QLabel("Loading...")
        self.lbl_city = QLabel("Loading...")
        self.lbl_asn = QLabel("Loading...")
        self.lbl_isp = QLabel("Loading...")
        self.lbl_cache = QLabel("Querying providers...")

        def _make_key(name):
            lbl = QLabel(name)
            lbl.setStyleSheet("color: #888898; font-weight: bold;")
            return lbl

        grid.addWidget(_make_key("Country:"), 0, 0)
        grid.addWidget(self.lbl_country, 0, 1)
        grid.addWidget(_make_key("City / Region:"), 0, 2)
        grid.addWidget(self.lbl_city, 0, 3)

        grid.addWidget(_make_key("ASN:"), 1, 0)
        grid.addWidget(self.lbl_asn, 1, 1)
        grid.addWidget(_make_key("ISP / Org:"), 1, 2)
        grid.addWidget(self.lbl_isp, 1, 3)

        grid.addWidget(_make_key("Cache / Time:"), 2, 0)
        grid.addWidget(self.lbl_cache, 2, 1, 1, 3)

        layout.addWidget(details_group)

        # 5. Tabbed Details: Providers Breakdown & Raw Data
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #363642; background: #25252c; border-radius: 6px; }
            QTabBar::tab { background: #1e1e24; color: #a0a0b0; padding: 6px 12px; margin-right: 2px; }
            QTabBar::tab:selected { background: #25252c; color: #00e5ff; font-weight: bold; border-top: 2px solid #00e5ff; }
        """)

        # Tab: Provider Messages
        self.txt_providers = QTextBrowser()
        self.txt_providers.setOpenExternalLinks(False)
        self.txt_providers.setStyleSheet("background: #1a1a20; color: #d0d0d8; border: none; font-family: monospace; font-size: 11px;")
        self.tab_widget.addTab(self.txt_providers, "Provider Responses")

        # Tab: External Investigation Shortcuts
        tab_links = QWidget()
        v_links = QVBoxLayout(tab_links)
        v_links.setSpacing(8)
        lbl_links_help = QLabel("Investigate this IP directly on trusted external threat platforms:")
        lbl_links_help.setStyleSheet("color: #a0a0b0; font-size: 12px;")
        v_links.addWidget(lbl_links_help)

        self.links_layout = QHBoxLayout()
        v_links.addLayout(self.links_layout)
        v_links.addStretch()
        self.tab_widget.addTab(tab_links, "External Portals")

        layout.addWidget(self.tab_widget, 1)

        # 6. Bottom Controls
        bottom_layout = QHBoxLayout()
        self.btn_refresh = QPushButton("🔄 Refresh Lookup")
        self.btn_refresh.setStyleSheet("background-color: #363642; color: white; padding: 6px 14px; border-radius: 4px;")
        self.btn_refresh.clicked.connect(lambda: self._start_lookup(force_refresh=True))
        bottom_layout.addWidget(self.btn_refresh)

        bottom_layout.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold; padding: 6px 18px; border-radius: 4px;")
        btn_close.clicked.connect(self.accept)
        bottom_layout.addWidget(btn_close)

        layout.addLayout(bottom_layout)

    def _start_lookup(self, force_refresh: bool = False):
        self.progress_bar.setVisible(True)
        self.btn_refresh.setEnabled(False)
        self.lbl_cache.setText("Querying intelligence providers...")

        # Immediate IP classification
        classification = classify_ip_address(self.ip)
        color = "#00e676" if not classification["is_public"] else "#00e5ff"
        self.lbl_scope.setText(f"<span style='color:{color}; font-weight:bold;'>[{classification['scope']}]</span> — {classification['description']}")

        self.worker = ThreatIntelWorker(self.ip, force_refresh=force_refresh, parent=self)
        self.worker.result_ready.connect(self._on_lookup_finished)
        self.worker.error_occurred.connect(self._on_lookup_error)
        self.worker.start()

    def _on_lookup_finished(self, data: dict):
        self.progress_bar.setVisible(False)
        self.btn_refresh.setEnabled(True)

        summary = data.get("summary", {})
        self.lbl_country.setText(summary.get("country", "Unknown"))
        self.lbl_city.setText(summary.get("city", "Unknown"))
        self.lbl_asn.setText(summary.get("asn", "Unknown"))
        self.lbl_isp.setText(summary.get("isp", "Unknown"))

        # Score & Severity Color
        score = summary.get("abuse_score", 0.0)
        self.lbl_score_val.setText(f"{score:.0f}/100" if score > 0 or data.get("classification", {}).get("is_public") else "0/100")
        if score >= 75:
            score_color = "#ff5252" # Red
        elif score >= 40:
            score_color = "#ff9100" # Orange
        elif score >= 15:
            score_color = "#ffd600" # Yellow
        else:
            score_color = "#00e676" # Green
        self.lbl_score_val.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {score_color};")

        # Cache indication
        if data.get("cached"):
            cached_dt = datetime.datetime.fromtimestamp(data.get("cached_at", 0)).strftime("%Y-%m-%d %H:%M:%S")
            self.lbl_cache.setText(f"Cached ({cached_dt}) — 24h retention")
        else:
            self.lbl_cache.setText("Live query completed successfully.")

        # Providers raw view
        prov_text = []
        for prov_name, prov_res in data.get("providers", {}).items():
            status = prov_res.get("status", "unknown")
            msg = prov_res.get("message", "")
            prov_text.append(f"=== {prov_name} [{status.upper()}] ===")
            if msg:
                prov_text.append(f"Note: {msg}")
            for k, v in prov_res.items():
                if k not in ("status", "message", "details"):
                    prov_text.append(f"  {k}: {v}")
            prov_text.append("")
        self.txt_providers.setText("\n".join(prov_text))

        # External Links
        # Clear existing buttons
        while self.links_layout.count():
            item = self.links_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        links = data.get("investigation_links", {})
        if links:
            for name, url in links.items():
                btn = QPushButton(f"🔗 {name}")
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #25252c;
                        color: #00e5ff;
                        border: 1px solid #363642;
                        padding: 8px 12px;
                        border-radius: 4px;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #363642;
                        border-color: #00e5ff;
                    }
                """)
                # Capture URL in closure
                btn.clicked.connect(lambda checked=False, target_url=url: QDesktopServices.openUrl(QUrl(target_url)))
                self.links_layout.addWidget(btn)
        else:
            lbl_nolinks = QLabel("No external links available for local/private IP.")
            lbl_nolinks.setStyleSheet("color: #707080;")
            self.links_layout.addWidget(lbl_nolinks)

    def _on_lookup_error(self, ip: str, error_msg: str):
        self.progress_bar.setVisible(False)
        self.btn_refresh.setEnabled(True)
        self.lbl_cache.setText(f"Lookup failed: {error_msg}")
        self.txt_providers.setText(f"Error querying threat intelligence for {ip}:\n{error_msg}")
