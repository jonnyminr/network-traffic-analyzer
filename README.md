# Network Traffic Analyzer — Advanced Cybersecurity & Threat Intelligence Studio

A professional desktop cybersecurity monitoring, network traffic analysis, and incident investigation platform built with **Python**, **PySide6**, **Scapy**, **pyqtgraph**, and **scikit-learn**.

The application provides real-time layer-2 to layer-4 packet capture, rolling statistical baselines, machine learning anomaly detection, passive flow tracking, threat intelligence enrichment, and a comprehensive incident investigation workflow.

---

## 8 Integrated Navigation Sections

The application features a modern, responsive dark cybersecurity dashboard divided into eight dedicated sections:

1. **📊 Dashboard**: Global real-time overview featuring KPI metric cards (Bandwidth, Packet Rate, Volume, Total Packets), scrolling time-series bandwidth oscilloscope (-60s to 0s), live packet rate chart, protocol distribution bar chart, and interactive Top Talkers table.
2. **📦 Packet Inspector**: Batched 10-FPS deep packet inspection table with live search filters, protocol filtering, and double-click safe header metadata inspection.
3. **🔗 Network Connections**: Dedicated L4 connection explorer aggregating packets into bi-directional flows, tracking passive TCP states (`SYN_SENT`, `ESTABLISHED`, `FIN_WAIT`, `RESET`), UDP timeout expiration, RFC 1918 vs. public host classification, duration, volume splits, and one-click Threat Intelligence lookups.
4. **🌐 Web Traffic**: Dedicated website traffic monitor allowing analysts to enter any target URL (e.g. `https://example.com`), resolve IPv4/IPv6 address pools, dynamically track CDN endpoints, monitor concurrent Ingress/Egress bandwidth, and verify TLS SNI.
5. **🔍 DNS Insights**: Observable DNS transaction monitor extracting Query ID, client/server endpoints, query names, query types (A, AAAA, CNAME, MX, TXT, HTTPS), response codes (NOERROR, NXDOMAIN, SERVFAIL), latency, Shannon entropy DGA detection, and TLS handshake SNI extraction.
6. **🚨 Security Alerts**: Intelligent incident alert system with automated deduplication, grouping by category & IP within a configurable cooldown window, multi-factor severity scoring, detailed evidence modal, and persistent SQLite history.
7. **🛡 Investigations**: Case management studio enabling analysts to open formal investigations from alerts, navigate a unified chronological timeline, review correlated evidence (flows, packets, DNS, threat intel), log analyst notes, track audit trails, and generate printable HTML/PDF reports.
8. **⚙ Settings**: Complete system configuration panel covering network interface selection, Berkeley Packet Filter (BPF) presets, anomaly detection baselines/thresholds, alert deduplication cooldowns, and optional Threat Intelligence API credentials.

---

## The Six Core Feature Upgrades

### FEATURE 1: Smart Security Alerts
- **Rich Incident Metadata**: Every alert includes a unique alert ID (`ALT-YYYYMMDD-XXXX`), title, category, multi-factor severity (Informational, Low, Medium, High, Critical), detection method, source/destination IPs and ports, current rate vs baseline rate, anomaly score, first/last seen timestamps, occurrence counter, status workflow (`New`, `Investigating`, `Resolved`, `False Positive`), short explanation, and actionable investigation guidance.
- **Intelligent Deduplication**: Groups repeated alerts with matching category and IP endpoints occurring within a configurable cooldown window (default 60s). Increments the occurrence counter and updates the last-seen timestamp rather than flooding the analyst with duplicate alerts.
- **Multi-Factor Severity Assignment**: Evaluates anomaly magnitude, sustained duration, repeated occurrences, and affected endpoints. Avoids classifying an event as Critical solely because its Z-score is high.
- **Detailed Evidence Dialog**: Double-clicking an alert opens a detailed modal displaying detection evidence, baseline comparisons, historical occurrences, analyst notes, and one-click actions to check Threat Intelligence or launch an investigation.
- **Persistent SQLite Storage**: Incidents are saved across application sessions in `logs/analyzer.db` (WAL mode). Clearing the visible UI table does not erase historical database records.

---

### FEATURE 2: Network Connection Explorer
- **Bi-directional Flow Tracking**: Canonical flow hashing maps incoming and outgoing packets between two endpoints into a single unified flow.
- **Passive TCP State Machine**: Infers connection lifecycle states (`SYN_SENT`, `SYN_RCVD`, `ESTABLISHED`, `CLOSING (FIN-WAIT)`, `CLOSED (Bi-FIN)`, `RESET (Closed)`) from observed TCP flags without claiming access to internal OS socket tables.
- **UDP Session Tracking**: Maintains UDP flows with an inactivity timeout (default 30s) transitioning idle flows to `IDLE / EXPIRED`.
- **Private vs Public Classification**: Evaluates IP addresses using RFC 1918 and loopback definitions. Identifies local LAN hosts (`🔒 [Private]`) vs public Internet endpoints.
- **Interactive Exploration**: Filter by search text, transport protocol (TCP, UDP, ICMP, OTHER), direction (Inbound, Outbound), or state (Active, Closed, Idle). Export connection flows to CSV.

---

### FEATURE 3: Smarter Anomaly Detection
- **Rolling Traffic Baselines**: Maintains rolling statistics (mean $\mu$, standard deviation $\sigma$, median, Median Absolute Deviation [MAD], 95th percentile, min/max, EWMA) for bandwidth, packet rates, and outbound transmission.
- **Mathematically Correct Z-Score & Robust MAD**:
  - Standard Z-score: $Z = (x - \mu) / \sigma$ with zero-variance protection ($\sigma > 10^{-4}$).
  - Robust MAD: $Z_{mad} = 0.6745 \times (x - \text{median}) / \text{MAD}$ when variance is zero or outliers are extreme.
- **Multi-Dimensional IsolationForest**: Analyzes multivariate traffic features (bytes/sec, packets/sec, average packet size, unique destination ports, unique destination IPs, SYN ratio, and outbound ratio). Features are normalized, and model decisions include explainable top-deviating feature attribution.
- **Attack Heuristics & False-Positive Gating**:
  - Port scan detection (probing $>25$ distinct ports within a measurement window).
  - High SYN-to-ACK disparity (possible SYN flood or connection retries).
  - Outbound transmission surges.
  - Baseline warm-up period (first 12 samples suppressed) preventing startup false positives.

---

### FEATURE 4: IP Reputation & Threat Intelligence
- **Modular Provider Architecture**: Extensible provider interface (`BaseThreatIntelProvider`) supporting:
  - **ip-api.com**: Free geolocation, ASN, ISP, and organization lookup out of the box (requires no API key).
  - **AbuseIPDB**: Abuse confidence score, total reports, and last reported date.
  - **VirusTotal**: Antivirus engine detection ratios (malicious, suspicious, harmless).
- **Strict Privacy Controls**:
  - RFC 1918 private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), and multicast addresses are **strictly intercepted by the Privacy Guard and never sent to external APIs**.
  - Public lookups are on-demand or explicitly user-initiated.
- **Local SQLite Caching**: External lookup results are cached locally in `logs/analyzer.db` with a 24-hour TTL to respect provider rate limits and ensure offline speed.
- **Direct External Portal Shortcuts**: Clickable buttons opening trusted investigation portals in the default web browser (VirusTotal, AbuseIPDB, Shodan, Cisco Talos, IPinfo).

---

### FEATURE 5: DNS & Encrypted Traffic Insights
- **Passive DNS Transaction Monitor**: Captures unencrypted DNS traffic (port 53), correlates queries with responses via Query ID (QID), and measures resolution latency in milliseconds.
- **Supported Records**: Common query types (A, AAAA, CNAME, MX, TXT, HTTPS, PTR, SRV) and response codes (NOERROR, NXDOMAIN, SERVFAIL, REFUSED).
- **DNS Behavioral Anomaly Detection**:
  - **NXDOMAIN Bursts**: Flags hosts receiving $\ge 8$ NXDOMAIN responses in 10 seconds.
  - **High Domain Entropy (DGA / Tunneling)**: Calculates Shannon entropy of subdomain labels. Flags labels with length $\ge 12$ and entropy $> 3.8$.
  - **Query Flooding**: Flags single-client query bursts ($\ge 30$ queries in 5s) or repeated domain flooding.
- **Encrypted Traffic Disclosures**:
  - Safely extracts Server Name Indication (SNI) from unencrypted TLS Client Hello packets on port 443.
  - Identifies UDP port 443 traffic as "QUIC-like (UDP 443)".
  - Honestly discloses cryptographic boundaries: ordinary packet sniffing cannot decrypt DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), or HTTPS application payloads.

---

### FEATURE 6: Incident Investigation Mode
- **Incident Case Workflow**: Open an investigation directly from any security alert or create a case manually (`INV-YYYYMMDD-XXXX`).
- **Automatic Evidence Correlation**: Correlates related flows from `ConnectionTracker`, DNS queries from `DNSMonitor`, and cached threat intelligence within the incident time window.
- **Chronological Timeline**: Unified timeline capturing alert generation, flow start/end timestamps, observed DNS queries, status changes, and analyst notes.
- **Audit Trail & Analyst Notes**: Analysts can log timestamped findings, mark status transitions (`Open` ➔ `Investigating` ➔ `Resolved` ➔ `Closed`), and document root-cause justifications.
- **Printable HTML & JSON Reports**: Generates a formatted executive and technical HTML incident report with dark styling and print-friendly CSS for PDF export.

---

## Technical & Cryptographic Limitations

- **Payload Encryption**: All HTTPS and TLS traffic payloads (passwords, URLs paths, POST data, response HTML) are cryptographically encrypted. The application inspects only packet headers, timing, endpoints, lengths, and unencrypted handshake indicators (SNI).
- **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT)**: If the host OS or web browser routes DNS queries through DoH (e.g. Cloudflare 1.1.1.1 or Google 8.8.8.8 over HTTPS), queries appear as standard HTTPS encrypted traffic and cannot be parsed on UDP port 53.
- **Passive vs. Active Socket State**: Passive packet sniffing infers TCP states based on observed wire flags (SYN, ACK, FIN, RST). It does not query OS kernel socket tables (`netstat`). Packet drops or out-of-order captures may affect state inference.
- **Shared CDN Infrastructure**: Many public websites share IP addresses on multi-tenant CDNs (Cloudflare, Fastly, Akamai). Threat intelligence and reverse DNS for CDN IPs reflect the CDN provider rather than a specific tenant.

---

## Prerequisites

### 1. Python
- Python 3.10 to 3.14 on Windows, Linux, or macOS.

### 2. Npcap Driver (Windows)
Packet capture at Layer 2 requires Npcap on Windows:
1. Download the Npcap installer from **[https://npcap.com/](https://npcap.com/)**.
2. **Critical Step**: During installation, check the box:
   - `☑ Install Npcap in WinPcap API-compatible Mode`
3. If Npcap is installed with Administrator-only restrictions, launch PowerShell / IDE as Administrator.

---

## PowerShell Installation & Launch Instructions

Open **Windows PowerShell** as **Administrator**:

```powershell
# 1. Navigate to the project directory
cd d:\network-traffic-analyzer

# 2. Install required dependencies
py -m pip install -r requirements.txt

# 3. Verify test suite passes
py -m unittest tests/test_advanced_features.py

# 4. Launch the application
py main.py
```

---

## Configuring Optional Threat Intelligence API Keys

Threat intelligence enrichment via **ip-api.com** (geolocation, ASN, ISP) works immediately without requiring an API key.

If you have API keys for **AbuseIPDB** or **VirusTotal**, you can configure them in either of two ways:

### Option A: In the Application GUI (Recommended)
1. Open the application.
2. Navigate to the **⚙ Settings** tab.
3. Switch to the **🛡 Threat Intelligence** tab.
4. Enter your **AbuseIPDB API Key** and/or **VirusTotal API Key**.
5. Click **💾 Apply & Save Configuration**. Keys are persisted locally in SQLite (`logs/analyzer.db`) and are never written to source control or sent over the wire.

### Option B: Environment Variables
Set the environment variables before starting the application:
```powershell
$env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key_here"
$env:VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
py main.py
```

---

## Test Results

The automated test suite verifies all six feature modules:

```powershell
py -m unittest tests/test_advanced_features.py
```

**Results:**
- `test_feature_1_alert_manager_and_deduplication`: PASSED (Alert creation, deduplication by category & IPs, occurrence counting, status updates, SQLite persistence).
- `test_feature_2_connection_tracker`: PASSED (Bi-directional flow mapping, TCP flag state inference, UDP timeout tracking, CSV export).
- `test_feature_3_smarter_anomaly_detection`: PASSED (Rolling baselines, zero-variance Z-score handling, robust MAD, warm-up period gating, port scan detection).
- `test_feature_4_threat_intelligence_privacy`: PASSED (RFC 1918 / loopback privacy interception, public IP classification, live ip-api lookup).
- `test_feature_5_dns_and_encrypted_traffic`: PASSED (Shannon entropy calculation, synthetic DNS query/response parsing, latency measurement).
- `test_feature_6_investigation_mode`: PASSED (Case creation, automated flow correlation, timeline event generation, HTML report generation).

---

## Project Structure

```
network-traffic-analyzer/
├── core/
│   ├── capture_engine.py          # Unified Scapy packet sniffer thread feeding all analytics
│   ├── connection_tracker.py      # Feature 2: Bi-directional flow aggregator & passive TCP state engine
│   ├── dns_monitor.py             # Feature 5: DNS query/response parser, DGA entropy, & TLS SNI extractor
│   ├── anomaly_detector.py        # Feature 3: Rolling baselines, Z-Score, robust MAD, & IsolationForest ML
│   ├── alert_manager.py           # Feature 1: Central alert coordinator, deduplication, & severity engine
│   ├── threat_intelligence.py     # Feature 4: IP classification, Privacy Guard, ip-api/AbuseIPDB/VT
│   ├── incident_manager.py        # Feature 6: Incident case manager, correlation, & HTML report generator
│   ├── incident_db.py             # Thread-safe SQLite storage engine (WAL mode)
│   ├── packet_parser.py           # Protocol & header extractor (IPv4, IPv6, TCP flags, UDP, ICMP, ARP)
│   ├── stats_aggregator.py        # Rolling window rates, top talkers, & multi-dimensional metrics
│   └── web_traffic_monitor.py     # Web traffic analyzer engine (domain resolution, SNI, ingress/egress)
├── gui/
│   ├── main_window.py             # Main PySide6 window with 8 cybersecurity navigation sections
│   ├── dashboard_widget.py        # Section 1: KPI cards, throughput oscilloscope, packet rate, protocols
│   ├── packet_table_widget.py     # Section 2: Batched raw packet inspector table with search
│   ├── connection_explorer_widget.py # Section 3: Connection flow table, filters, & details drawer
│   ├── web_traffic_widget.py      # Section 4: Target website traffic analyzer dashboard
│   ├── dns_insights_widget.py     # Section 5: Live DNS transactions table, top domains, & encrypted hints
│   ├── alerts_panel.py            # Section 6: Security alerts table, deduplication counter, & actions
│   ├── alert_details_dialog.py    # Evidence-based alert investigation dialog modal
│   ├── investigation_widget.py    # Section 7: Incident investigation studio, timeline, & case reports
│   ├── ip_threat_intel_dialog.py  # Modal dialog displaying geolocation, ASN, and reputation scores
│   ├── settings_dialog.py         # Section 8: Embedded settings tab & configuration dialog
│   └── packet_details_dialog.py   # Safe packet metadata inspection modal
├── utils/
│   ├── interfaces.py              # Cross-platform interface discovery, scoring, and resolution
│   ├── exporter.py                # PCAP, stats, alerts, and connection flows CSV export utilities
│   └── logger.py                  # Rotating logger for console and logs/app.log
├── tests/
│   └── test_advanced_features.py  # Automated unit and integration test suite
├── logs/
│   ├── analyzer.db                # SQLite database storing alerts, occurrences, investigations, and cache
│   └── app.log                    # Execution log file
├── main.py                        # Desktop application entry point with Fusion dark theme
├── requirements.txt               # Package dependencies (scapy, PySide6, pyqtgraph, scikit-learn, pandas, requests)
└── README.md                      # Comprehensive user guide and architecture documentation
```
