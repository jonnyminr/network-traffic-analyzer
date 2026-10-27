# Network Traffic Analyzer — Performance & Usability Cybersecurity Platform

A high-performance, beginner-friendly desktop network monitoring, traffic analysis, and cybersecurity platform built with **Python**, **PySide6**, **Scapy**, **pyqtgraph**, **scikit-learn**, and **SQLite**.

The application provides real-time layer-2 to layer-4 packet capture, rolling statistical baselines, machine learning anomaly detection, passive flow tracking, threat intelligence enrichment, an active network health diagnostic suite, offline PCAP replay, an interactive network topology map, and a dual-mode interface (Simple Mode for beginners and Advanced Mode for security analysts).

---

## 10 Integrated Navigation Sections

The application features a modern, responsive dark cybersecurity dashboard organized into ten dedicated sections:

1. **📊 Dashboard**: Global real-time overview featuring KPI metric cards (Bandwidth, Packet Rate, Volume, Total Packets), scrolling time-series bandwidth oscilloscope (-60s to 0s), live packet rate chart, protocol distribution bar chart, interactive Top Talkers table, Analyzer Performance status strip, and live evidence-based recommendations.
2. **🩺 Network Health**: Active diagnostic suite testing default gateway reachability, public Internet connectivity, DNS resolution latency, multi-probe ICMP/TCP round-trip time, and packet loss percentage with time-series trend history and plain-English diagnostic conclusions.
3. **🌐 Web Traffic**: Dedicated website traffic monitor allowing analysts to enter any target URL (e.g. `https://example.com`), resolve IPv4/IPv6 address pools, dynamically track CDN endpoints, monitor concurrent Ingress/Egress bandwidth, and verify TLS SNI.
4. **📦 Packet Inspector**: Batched deep packet inspection table with live search filters, protocol filtering, and double-click safe header metadata inspection.
5. **🔗 Network Connections**: Dedicated multi-tab connection station:
   - **L4 Flows**: Bi-directional flow table tracking passive TCP states (`SYN_SENT`, `ESTABLISHED`, `FIN_WAIT`, `RESET`), UDP timeout expiration, RFC 1918 vs. public host classification, duration, and one-click Threat Intelligence lookups.
   - **Device & Host Overview**: Aggregated inventory of all observed network endpoints, communication volume, connection counts, and passive capture scope disclaimers.
   - **Network Topology Map**: Interactive node-link visualization mapping the local host to observed remote endpoints with volume-weighted links and alert badges.
6. **🔍 DNS Insights**: Observable DNS transaction monitor extracting Query ID, client/server endpoints, query names, query types (A, AAAA, CNAME, MX, TXT, HTTPS), response codes (NOERROR, NXDOMAIN, SERVFAIL), latency, Shannon entropy DGA detection, and TLS handshake SNI extraction.
7. **🚨 Security Alerts**: Intelligent incident alert system with automated deduplication, grouping by category & IP within a configurable cooldown window, multi-factor severity scoring, detailed evidence modal, false-positive handling with justification notes, and persistent SQLite history.
8. **🛡 Investigations**: Case management studio enabling analysts to open formal investigations from alerts, navigate a unified chronological timeline, review correlated evidence (flows, packets, DNS, threat intel), log analyst notes, track audit trails, and generate printable HTML/PDF reports.
9. **📁 Offline Analysis**: Isolated PCAP/PCAPNG file inspector with streaming background playback, speed multiplier controls (Instant, 1x, 5x, 10x), protocol statistics, flow tracking, DNS insights, search filters, and CSV export without requiring administrative privileges.
10. **⚙ Settings**: Complete system configuration panel covering network interface selection, capture profiles (Lightweight, Balanced, Deep Analysis), GUI refresh rates (5–30 FPS), Berkeley Packet Filter (BPF) presets, anomaly detection thresholds, alert deduplication cooldowns, threat intelligence credentials, and a dedicated **Analyzer Performance** monitoring dashboard.

---

## Core Feature Capabilities

### FEATURE 1: Performance Optimization & Architecture
- **Decoupled Capture Pipeline**: Scapy's capture loop runs in an isolated thread whose sole task is enqueuing raw packet timestamps into a thread-safe, bounded queue (`queue.Queue(maxsize=20000)`). A dedicated worker thread dequeues and processes batches into parsed metadata, flows, DNS transactions, and rolling metrics.
- **Queue Drop Accounting**: If the queue fills under sustained high-speed traffic spikes, packets are safely dropped before Scapy buffers overflow, and actual queue drops are recorded and displayed in the performance instrumentation.
- **Controlled GUI Refresh**: The GUI thread never parses packets. pyqtgraph and table updates run on controlled timers (configurable 5–30 FPS; default 10 FPS). Batch updates (`add_packet_batch`) prevent UI micro-stutters.
- **Windowed Machine Learning**: Multivariate IsolationForest predictions do not run per-packet. Instead, traffic statistics are aggregated into a 10-second rolling feature vector and processed asynchronously, reducing CPU overhead by up to 95%.
- **Bounded Rolling Buffers & Flow Cleanup**: Ring buffers for time-series charts (-60s) and table packet capacity (500–10,000 depending on profile) prevent unbounded memory growth. Inactive TCP and UDP flows are periodically expired.
- **Analyzer Performance Monitor**: Real-time instrumentation tab and status bar displaying:
  - Process CPU usage percentage (via `psutil`).
  - Process RSS memory consumption in MB.
  - Packets processed per second (live throughput).
  - Processing latency per packet in milliseconds.
  - Queue backlog and queue drops.
  - Measured GUI update frames per second (FPS).
  - Kernel drop disclaimer explaining Windows Npcap buffer semantics.
- **Three Capture Profiles**:
  1. *Lightweight*: Bounded to 500 packets in memory, basic protocol statistics, zero ML anomaly overhead, ideal for low-spec machines.
  2. *Balanced*: Default profile with 2,000 packets retention, standard flow tracking, 10 FPS updates, and windowed ML anomaly detection.
  3. *Deep Analysis*: Retains up to 10,000 packets, full passive TCP state reconstruction, enhanced metadata tracking, and sensitive anomaly thresholds.

---

### FEATURE 2: Network Health Check
- **Active Diagnostic Suite**: Performs safe active connectivity checks completely separated from passive capture:
  - Network interface verification and local IP discovery.
  - Default gateway discovery (via routing tables) and round-trip ping.
  - Public Internet reachability (HTTP/HTTPS probes to Cloudflare `1.1.1.1` and Google `8.8.8.8`).
  - DNS resolution latency and failure detection.
  - Multi-probe packet loss percentage and jitter measurement.
- **Actionable Diagnostic Conclusions**: Translates raw probe measurements into clear conclusions:
  - *"Your internet connection appears healthy. Low latency and 0.0% packet loss."*
  - *"DNS resolution is failing. Check your DNS server configuration or network connection."*
  - *"High packet loss detected (X%). You may experience dropped calls or slow loading."*
- **Historical Health Monitoring**: Stores every health check test run in the local SQLite database (`logs/analyzer.db`) and renders a historical time-series graph of latency and packet loss trends over time.

---

### FEATURE 3: Simple Mode vs. Advanced Mode
- **Dual Interface Modes**: One-click toggle in the toolbar allows users to seamlessly switch between beginner-friendly and deep analyst views without interrupting active packet captures or resetting session counters.
- **Simple Mode**:
  - Educational, plain-English summary cards (*"Connection Status"*, *"Activity Level"*, *"Observed Endpoints"*, *"Security Status"*).
  - Categorized network usage buckets (*Web & Secure Browsing*, *Media & Gaming Streaming*, *System & Domain Services*, *Other*).
  - Friendly connection explanations translating technical flags into human concepts (*"Talking to 8 remote computers"*).
  - Direct next-step guidance for ordinary users.
- **Advanced Mode**:
  - Raw packet inspection table with hexadecimal and ASCII payloads.
  - Comprehensive L4 TCP flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
  - Rolling Z-scores and Median Absolute Deviation (MAD) metrics.
  - IsolationForest multidimensional anomaly scores and feature attributions.
- **Educational Tooltips**: Built-in definitions for technical terms (TCP, UDP, DNS, Z-score, Anomaly, Port Scanning, Bandwidth, Ingress/Egress) accessible on hover.
- **Persistent Preferences**: Mode selection and capture profile choices are saved in SQLite and restored across restarts.

---

### FEATURE 4: Improved Alert Investigation & False-Positive Handling
- **Alert Grouping & Deduplication**: Repeated anomalies matching the same category and endpoint IP within a 60-second window are consolidated into a single alert record with an incrementing counter (`occurrences`) and updated `last_seen` timestamp.
- **Rich Alert Evidence Bundle**: Double-clicking an alert opens the comprehensive Alert Details modal:
  - Detection method and statistical anomaly score.
  - Measured rate vs. calculated historical baseline.
  - Specific source and destination endpoints.
  - Correlated packet timestamps and related network connections.
- **False-Positive Management**: Analysts can mark any alert as a false positive and record a justification reason (e.g., *"Scheduled nightly backup sync"*). Decisions are stored in the SQLite `false_positives` table for audit trails and tuning.
- **Incident History & Case Escalation**: One-click escalation creates a formal case in the Investigations studio with an interactive chronological timeline and printable HTML/PDF report.

---

### FEATURE 5: Offline PCAP Analysis
- **Zero-Admin PCAP/PCAPNG Playback**: Analyze captured network files (`.pcap`, `.pcapng`) on any computer without needing administrator or root privileges.
- **Incremental Streaming (`PcapReader`)**: Large PCAP files are read packet-by-packet via Scapy's streaming generator rather than loaded entirely into memory, preventing Out-Of-Memory crashes.
- **Playback Controls**:
  - Replay speed selector: Instant (maximum throughput), 1x (real-time pacing), 5x, or 10x.
  - Pause and Resume buttons.
  - Live progress bar and packet counter.
- **Session Isolation**: Offline analysis maintains independent state structures. Inspecting an offline PCAP does not overwrite or corrupt active live-capture sessions.
- **Offline Analytics**: Computes protocol breakdowns, top talkers, connection flows, DNS insights, and exports results to CSV.

---

### FEATURE 6: Practical Network Monitoring
- **Device & Host Overview**:
  - Aggregates all seen IP endpoints into an inventory table displaying IP classification (RFC 1918 Private LAN vs Public WAN), first seen, last seen, bytes sent/received, active flows, and associated security alerts.
  - **Passive Capture Disclaimer**: Prominently informs users that passive packet capture only observes traffic transmitted to or through the local machine's interface, avoiding misconceptions about full router visibility.
- **Traffic Usage & Direction Breakdown**:
  - Accurately tracks inbound vs. outbound traffic splits based on local interface IP resolution.
  - Flags traffic with unknown direction when ambiguous rather than guessing.
- **Interactive Network Topology Visualization**:
  - Node-link graph mapping the local workstation as the central node connected to observed external servers and internal peers.
  - Link thickness dynamically scales with transfer volume.
  - Nodes with triggered security alerts are highlighted with amber/red status rings.
- **Evidence-Based Recommendations Engine**:
  - Analyzes live traffic patterns and produces actionable, non-alarmist recommendations (e.g., advising on dominant bandwidth consumers, port probing events, or gateway packet loss).

---

## Technical & Cryptographic Limitations

- **Passive Capture Scope**: In standard switched Ethernet and Wi-Fi networks, passive capture only sees packets addressed to, originating from, or broadcasted to the local network adapter (unless connected via a SPAN port, network TAP, or promiscuous hub).
- **Kernel Buffer Drops (Npcap on Windows)**: Scapy captures packets via the Windows Npcap driver. When the kernel buffer overflows during burst traffic, drops occur inside Npcap's driver memory. Because the Python Scapy wrapper does not consistently expose the low-level WinPcap `pcap_stats` API across all driver versions, application-level queue drops are measured directly and kernel drops are clearly noted when unavailable.
- **Payload Encryption**: All HTTPS and TLS traffic payloads (passwords, URL paths, POST bodies, response HTML) are cryptographically encrypted. The application inspects only packet headers, timing, endpoints, lengths, and unencrypted handshake indicators (SNI).
- **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT)**: If the host OS or web browser routes DNS queries through DoH (e.g. Cloudflare 1.1.1.1 or Google 8.8.8.8 over HTTPS), queries appear as standard HTTPS encrypted traffic and cannot be parsed on UDP port 53.
- **Active vs. Passive Health Tests**: Network Health tests generate active network traffic (DNS queries and TCP/ICMP ping probes). In contrast, the Dashboard and Packet Inspector rely strictly on passive capture.

---

## Prerequisites

### 1. Python
- Python 3.10 to 3.14 on Windows, Linux, or macOS.

### 2. Npcap Driver (Windows)
Live packet capture at Layer 2 requires Npcap on Windows:
1. Download the Npcap installer from **[https://npcap.com/](https://npcap.com/)**.
2. **Critical Step**: During installation, check the box:
   - `☑ Install Npcap in WinPcap API-compatible Mode`
3. If Npcap is installed with Administrator-only restrictions, launch PowerShell / IDE as Administrator.
*(Note: Offline PCAP Analysis does not require Npcap or Administrator privileges).*

---

## PowerShell Installation & Launch Instructions

Open **Windows PowerShell** (Run as Administrator for live capture):

```powershell
# 1. Navigate to the project directory
cd d:\network-traffic-analyzer

# 2. Install required dependencies
py -m pip install -r requirements.txt

# 3. Verify automated test suite (all 12 unit/integration tests)
py -m unittest discover -s tests -p "test_*.py"
# or using pytest:
py -m pytest tests/

# 4. Launch the application
py main.py
```

*(If multiple Python versions are installed, you can specify `py -3.14 main.py`).*

---

## Automated Test Suite

The project includes an end-to-end automated test suite covering all features:

```powershell
py -m unittest discover -s tests -p "test_*.py"
```

**Test Coverage Summary:**
- `tests/test_advanced_features.py`:
  - `test_feature_1_alert_manager_and_deduplication`: Alert generation, deduplication, occurrence counter, status updates, SQLite persistence.
  - `test_feature_2_connection_tracker`: Bi-directional flow hashing, TCP state inference, UDP timeout expiration, CSV export.
  - `test_feature_3_smarter_anomaly_detection`: Rolling baselines, zero-variance Z-score protection, robust MAD, port scan heuristics.
  - `test_feature_4_threat_intelligence_privacy`: RFC 1918 / loopback privacy interception, public IP classification.
  - `test_feature_5_dns_and_encrypted_traffic`: Shannon entropy DGA detection, synthetic DNS parsing, latency tracking.
  - `test_feature_6_investigation_mode`: Case creation, automatic evidence correlation, timeline generation, HTML report generation.
- `tests/test_performance_and_usability_upgrade.py`:
  - `test_feature_1_capture_profiles_and_performance_monitor`: Capture profiles configuration, CPU/memory metric recording, queue drop accounting, GUI FPS tracking.
  - `test_feature_2_network_health_diagnostics`: Gateway/interface discovery, multi-probe latency and packet loss logic, SQLite test history persistence.
  - `test_feature_3_simple_mode_and_tooltips`: Educational tooltips dictionary verification, UI mode persistence in SQLite settings.
  - `test_feature_4_improved_alert_investigation_and_false_positives`: Evidence bundle retrieval, false-positive classification with justification notes.
  - `test_feature_5_offline_pcap_streaming_analysis`: Streaming PCAP replay using `PcapReader`, speed multiplier, session isolation, protocol aggregation.
  - `test_feature_6_practical_network_monitoring_and_recommendations`: Device & host endpoint aggregation, flow expiration, evidence-based recommendations engine.

---

## Project Structure

```
network-traffic-analyzer/
├── core/
│   ├── capture_engine.py          # Decoupled Scapy capture thread + batch worker pipeline
│   ├── capture_profiles.py        # Feature 1: Lightweight, Balanced, & Deep Analysis profiles
│   ├── performance_monitor.py     # Feature 1: Live CPU, memory, PPS, latency, queue backlog instrumentation
│   ├── network_health.py          # Feature 2: Active gateway, DNS, latency, and packet loss diagnostics
│   ├── connection_tracker.py      # Feature 6: Flow tracking, endpoint inventory, & inactive flow expiration
│   ├── dns_monitor.py             # Feature 5: DNS query/response parser, DGA entropy, & TLS SNI extractor
│   ├── anomaly_detector.py        # Feature 1 & 3: Windowed ML IsolationForest, Z-Score, robust MAD
│   ├── alert_manager.py           # Feature 4: Alert deduplication, evidence bundling, & false-positive handling
│   ├── recommendations_engine.py  # Feature 6: Non-alarmist, evidence-based network recommendations
│   ├── pcap_analyzer.py           # Feature 5: Background streaming PCAP/PCAPNG replay worker
│   ├── threat_intelligence.py     # RFC 1918 Privacy Guard, ip-api / AbuseIPDB / VirusTotal providers
│   ├── incident_manager.py        # Incident case management, timeline correlation, & HTML reporting
│   ├── incident_db.py             # Thread-safe SQLite database (WAL mode) with health & FP tables
│   ├── packet_parser.py           # Protocol & header extractor (IPv4, IPv6, TCP flags, UDP, ICMP, ARP)
│   ├── stats_aggregator.py        # Rolling window rates, top talkers, & protocol distribution
│   └── web_traffic_monitor.py     # Target website traffic monitor (DNS resolution, SNI, bandwidth)
├── gui/
│   ├── main_window.py             # 10 navigation tabs, toolbar Mode toggle (Simple/Advanced), Profile selector
│   ├── simple_mode_widget.py      # Feature 3: Beginner-friendly overview, usage buckets, & plain-English cards
│   ├── network_health_widget.py   # Feature 2: Diagnostic controls, KPI cards, trend charts, & test log
│   ├── offline_analysis_widget.py # Feature 5: Offline PCAP station, speed controls, progress bar, & flows
│   ├── performance_monitor_widget.py # Feature 1: Live performance instrumentation dashboard
│   ├── network_topology_widget.py # Feature 6: Interactive node-link network visualization
│   ├── tooltips_helper.py         # Feature 3: Centralized educational definitions and tooltips
│   ├── dashboard_widget.py        # Section 1: KPI cards, oscilloscope, performance strip, recommendations
│   ├── packet_table_widget.py     # Section 4: Batched raw packet inspector table with search
│   ├── connection_explorer_widget.py # Section 5: L4 Flows, Device & Host Overview, and Topology subtabs
│   ├── web_traffic_widget.py      # Section 3: Target website traffic analyzer dashboard
│   ├── dns_insights_widget.py     # Section 6: Live DNS transactions table, top domains, & encrypted hints
│   ├── alerts_panel.py            # Section 7: Grouped security alerts table, evidence viewer, & actions
│   ├── alert_details_dialog.py    # Feature 4: Alert evidence dialog with false-positive classification
│   ├── investigation_widget.py    # Section 8: Incident investigation studio, timeline, & case reports
│   ├── ip_threat_intel_dialog.py  # Geolocation, ASN, and reputation modal dialog
│   ├── settings_dialog.py         # Section 10: Profile selector, GUI refresh sliders, and BPF configuration
│   └── packet_details_dialog.py   # Safe packet metadata inspection modal
├── utils/
│   ├── interfaces.py              # Cross-platform interface discovery, scoring, and resolution
│   ├── exporter.py                # PCAP, stats, alerts, and connection flows CSV export utilities
│   └── logger.py                  # Rotating logger for console and logs/app.log
├── tests/
│   ├── test_advanced_features.py  # Unit and integration test suite for advanced features
│   └── test_performance_and_usability_upgrade.py # Test suite for all 6 performance/usability features
├── logs/
│   ├── analyzer.db                # SQLite database (alerts, occurrences, false positives, health history)
│   └── app.log                    # Execution log file
├── main.py                        # Desktop application entry point with dark Fusion styling
├── requirements.txt               # Package dependencies (scapy, PySide6, pyqtgraph, scikit-learn, psutil, etc.)
└── README.md                      # Complete architecture, user guide, and operational instructions
```
