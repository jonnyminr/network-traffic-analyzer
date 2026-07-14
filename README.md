# Network Traffic Analyzer

A cross-platform desktop application that captures live network packets, displays real-time traffic statistics on a dashboard, and detects/alerts on anomalous traffic patterns.

## Features
- Real-time packet capture using Scapy
- Live throughput and protocol distribution dashboard (PySide6 & pyqtgraph)
- Detailed, filterable raw packet inspection table
- Anomaly detection (Z-score, rule-based, and IsolationForest integration)

## Prerequisites
- Python 3.10+
- **Windows**: [Npcap](https://npcap.com/) or WinPcap must be installed. Wireshark installs this by default.
- **Linux/macOS**: `tcpdump` or `libpcap` installed.

## Setup
1. Clone or download this repository.
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application
Because the application needs to capture network packets in promiscuous mode or on specific interfaces, **you must run it with elevated privileges**:

- **Windows**: Open an Administrator Command Prompt or PowerShell, then run:
  ```bash
  python main.py
  ```
- **Linux/macOS**:
  ```bash
  sudo python main.py
  ```

If you launch without appropriate privileges, the application may start but will likely fail to capture any traffic or list your network interfaces properly.
