# Network Traffic Analyzer

A modern, cross-platform desktop application built with Python, PySide6, Scapy, and pyqtgraph that captures live network packets, visualizes real-time network throughput and protocol distribution on an interactive dashboard, and detects anomalous traffic patterns using rule-based algorithms, statistical Z-scores, and Machine Learning (IsolationForest).

The application features two dedicated operational modes:
1. **🌐 Global Network Traffic Analyzer**: General-purpose whole-network packet sniffing, throughput charts, protocol breakdown, and threat detection across all local adapters.
2. **🎯 Web Traffic Analyzer**: Real-time website-specific traffic analysis allowing users to input a target URL (e.g. `https://example.com`), resolve its IP addresses (IPv4 & IPv6), inspect bi-directional ingress/egress flows, track active connection endpoints, and detect website-specific traffic anomalies.

---

## Key Features

### 🌐 Global Traffic Analyzer
- **Intelligent Interface Auto-Detection**:
  - Automatically identifies and selects your active internet-connected adapter (Wi-Fi, Ethernet) on startup, avoiding disconnected virtual adapters and Windows WAN Miniports.
  - Displays IPv4 addresses, active status badges (`[Active]`), and MAC addresses in interface settings.
- **Real-Time Interactive Dashboard**:
  - **KPI Metrics**: Real-time display of Current Bandwidth (B/s, KB/s, MB/s), Packet Rate (pkts/s), Total Session Volume, and Total Packets.
  - **Live Throughput Chart**: High-performance scrolling time-series oscilloscope (-60s to 0s) showing bandwidth over time with smooth glowing gradients.
  - **Packet Rate Chart**: Live packets-per-second monitoring with automatic range scaling.
  - **Protocol Distribution Bar Chart**: Live breakdown of traffic protocols (TCP, UDP, ICMP, ARP, and Other).
  - **Top Talkers Table**: Cumulative bandwidth ranking identifying the highest traffic IP addresses, human-readable byte formatting, and percentage share.
- **High-Throughput Raw Packet Table**:
  - Batched UI rendering (10 FPS) preventing GUI freezes during high-volume network bursts.
  - Live search filter (filter by IP, port, or protocol), auto-scroll toggle, and packet counter.
- **Multi-Layer Anomaly Detection**:
  - Port scan detection, statistical Z-score volume spikes, and unsupervised IsolationForest ML detection.
- **Session Exports**:
  - Export raw packets to Wireshark `.pcap`, traffic history to `.csv`, and alerts to `.csv`.

---

### 🎯 Web Traffic Analyzer (New)
- **Target URL Input & Validation**:
  - Accepts HTTP and HTTPS URLs (e.g., `https://example.com`, `http://example.com`, `https://www.wikipedia.org`).
  - Normalizes hostnames and rejects malformed inputs or unsupported schemes (`ftp://`, `ssh://`, etc.).
- **Dual-Stack DNS Resolution & CDN Tracking**:
  - Resolves both IPv4 and IPv6 addresses via system DNS.
  - Identifies multi-IP and CDN architectures.
  - Dynamically updates the website's IP pool when live DNS A/AAAA queries or responses are observed on the wire.
- **Website-Specific Packet Filtering & Attribution**:
  - Filters packets involving resolved IPs across standard web ports (HTTPS 443, HTTP 80, QUIC/HTTP-3 443) and custom ports.
  - Inspects DNS queries and responses specifically matching the target domain.
  - Extracts TLS Server Name Indication (SNI) from ClientHello packets to provide verified domain attribution.
  - Clearly labels packet attribution:
    - **`Verified SNI`**: Exact domain confirmed from unencrypted TLS ClientHello handshake.
    - **`DNS Activity`**: Domain query or answer matching the target host.
    - **`IP Match (CDN/Shared)`**: Matched via resolved IP addresses.
- **Directional Traffic Metrics (Incoming vs Outgoing)**:
  - Automatically identifies local machine IP vs remote web server IP.
  - Displays real-time **Incoming (Download ⬇)** and **Outgoing (Upload ⬆)** bandwidth and byte/packet counters.
- **Live Bandwidth Chart (Dual Curves)**:
  - Real-time pyqtgraph oscilloscope displaying concurrent **Incoming Bandwidth** (cyan) and **Outgoing Bandwidth** (orange) over the last 60 seconds.
- **Protocol Breakdown Bar Chart**:
  - Real-time packet distribution categorized into `HTTPS`, `HTTP`, `QUIC`, `DNS`, `TCP`, `UDP`, `ICMP`, and `Other`.
- **Observed Connection Tracker**:
  - Live flow table tracking: Remote Endpoint (`IP:Port`), Protocol, TCP State (`SYN_SENT`, `SYN_RECV`, `ESTABLISHED`, `FIN_WAIT`, `RESET`, `ACTIVE`), Ingress/Egress packet and volume counts, Attribution type, and Last Seen timestamp.
- **Safe Packet Inspection Dialog**:
  - Double-click any packet row to inspect safe network and transport headers (IP addresses, ports, TTL, sequence numbers, TCP flags, window size, TLS SNI, and DNS records).
- **Website Anomaly Detection**:
  - Flags throughput spikes (Z-score > 3.0), repeated SYN retransmissions / connection timeouts, and unusual destination ports.
- **Dedicated Export Suite**:
  - Export website-matched packets to `.pcap`.
  - Export website traffic statistics to `.csv`.
  - Export connection summaries to `.csv`.
  - Export website anomaly incident logs to `.csv`.

---

## Important Technical & Cryptographic Limitations

- **Encrypted HTTPS Payloads**: All TLS / HTTPS application data (URLs paths, query strings, headers, cookies, POST bodies, and credentials) is cryptographically encrypted. The application inspects only packet headers, timing, lengths, IP addresses, and unencrypted handshake indicators (SNI). It does not decrypt or tamper with encrypted ciphertext.
- **Shared CDN / Cloud IPs**: Many modern websites share IP addresses on CDNs (Cloudflare, Akamai, CloudFront, Fastly). When traffic is matched by IP address, packets from other websites hosted on the same IP cluster may be captured. The application explicitly labels these as `IP Match (CDN/Shared)` rather than verified website traffic.
- **Connection Reuse**: Modern web browsers reuse established TCP/TLS connections via HTTP/2 and HTTP/3 connection pooling. If the target website was already open before starting capture, the initial DNS lookup and TLS handshake may have completed earlier.
- **QUIC / HTTP/3**: Modern web browsers frequently use QUIC over UDP port 443. The application tracks QUIC alongside TCP HTTPS.
- **Encrypted DNS (DoH/DoT)**: If your browser or OS uses DNS-over-HTTPS (e.g. 1.1.1.1 or 8.8.8.8 over port 443), DNS lookups are encrypted inside HTTPS packets and will appear as HTTPS traffic rather than plaintext port 53 packets.

---

## Prerequisites

### 1. Python
- Python 3.10 or higher.

### 2. Packet Capture Driver
Because packet sniffing operates at the data-link layer:

- **Windows**:
  - You **must** install **[Npcap](https://npcap.com/)** (or Wireshark, which includes Npcap).
  - **Important Installation Option**: During Npcap setup, make sure to check:
    - `☑ Install Npcap in WinPcap API-compatible Mode`
  - If Npcap is installed with Administrator-only restrictions, launch your terminal / IDE with Administrator privileges.
- **Linux**:
  - Install `libpcap` and `tcpdump`:
    ```bash
    sudo apt update && sudo apt install -y libpcap-dev tcpdump
    ```
- **macOS**:
  - Install `libpcap`:
    ```bash
    brew install libpcap
    ```

---

## Installation & Setup

1. **Clone or navigate to the repository**:
   ```bash
   cd network-traffic-analyzer
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(or `py -m pip install -r requirements.txt` on Windows)*

---

## Running the Application

Because raw packet capture requires low-level network adapter access:

### Windows:
Open **Command Prompt** or **PowerShell** as **Administrator**, then run:
```bash
python main.py
```
*(or `py main.py`)*

### Linux / macOS:
Run with `sudo` privileges:
```bash
sudo python main.py
```

---

## How to Use Web Traffic Analyzer

1. Launch the application.
2. Click the **🎯 Web Traffic Analyzer** tab at the top of the window.
3. Enter a website URL (e.g. `https://www.wikipedia.org` or `https://example.com`).
4. Select your active network adapter from the **Interface** dropdown (auto-selected by default).
5. (Optional) Choose a capture duration limit (e.g. `30 seconds`, `60 seconds`, or `No Limit`).
6. Click **▶ Capture Traffic**.
7. Open a web browser or run an HTTP request to the target website.
8. Watch real-time incoming/outgoing bandwidth curves, protocol distribution bars, connection flows, and packet records populate live.
9. Double-click any packet row to inspect safe metadata in the **Packet Inspection** dialog.
10. Click **⏹ Stop Capture** when finished, then use the export buttons (`💾 PCAP`, `📊 Stats CSV`, `🔗 Conns CSV`, `🚨 Alerts CSV`) to save data to disk.

---

## Troubleshooting

### Q1: "Sniffing and sending packets is not available at layer 2: winpcap is not installed"
- **Cause**: Npcap is either not installed on Windows or was installed without the WinPcap-compatible mode option enabled.
- **Solution**:
  1. Download the latest installer from [https://npcap.com/](https://npcap.com/).
  2. Run the installer and check the box: `Install Npcap in WinPcap API-compatible Mode`.
  3. Restart the application.

### Q2: 0 packets captured on Web Traffic
- **Cause 1 - Connection already established**: If the website was already open in your browser before starting capture, refresh the webpage in your browser (Ctrl+F5) to generate new network traffic.
- **Cause 2 - Wrong Network Interface**: Ensure the selected interface in the dropdown shows `[Active]` with your computer's local IP address.
- **Cause 3 - DNS resolution failed**: Verify that your computer has internet access and can resolve the domain.

---

## Project Structure

```
network-traffic-analyzer/
├── core/
│   ├── capture_engine.py       # Global capture thread using Scapy AsyncSniffer
│   ├── web_traffic_monitor.py  # Web target normalization, DNS resolver, SNI parser, flow tracker, WebCaptureEngine
│   ├── packet_parser.py        # Parser for IPv4, IPv6, TCP, UDP, ICMP, and ARP packets
│   ├── stats_aggregator.py     # Global rolling window rates and cumulative session statistics
│   └── anomaly_detector.py     # Global rule-based, Z-score, and IsolationForest anomaly detector
├── gui/
│   ├── main_window.py          # Main application window with tab navigation (Global & Web Traffic)
│   ├── web_traffic_widget.py   # Complete Web Traffic Analyzer dashboard, charts, connections, and table
│   ├── packet_details_dialog.py# Modal safe packet metadata viewer with cryptography disclaimer
│   ├── dashboard_widget.py     # Global KPI metric cards, throughput chart, packet rate chart, and protocol chart
│   ├── packet_table_widget.py  # Global batched raw packet inspector with dynamic search filter
│   ├── alerts_panel.py         # Global security incident alert feed
│   └── settings_dialog.py      # Interface selector with active IP labeling and BPF presets
├── utils/
│   ├── interfaces.py           # Cross-platform interface discovery, scoring, and resolution
│   ├── exporter.py             # PCAP, stats, alerts, and connections CSV export utilities
│   └── logger.py               # Unified logging setup for console and logs/app.log
├── logs/
│   └── app.log                 # Persistent execution log
├── main.py                     # Application entry point with custom Fusion dark palette
├── requirements.txt            # Python package dependencies
└── README.md                   # Documentation and user guide
```
