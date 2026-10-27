from typing import Dict

EXPLANATIONS: Dict[str, str] = {
    "TCP": (
        "<b>Transmission Control Protocol (TCP):</b> A reliable, connection-oriented protocol. "
        "It uses a three-way handshake (SYN, SYN-ACK, ACK) and verifies every packet is received in order."
    ),
    "UDP": (
        "<b>User Datagram Protocol (UDP):</b> A lightweight, connectionless protocol designed for speed. "
        "Commonly used for real-time traffic like DNS queries, online gaming, and video streaming."
    ),
    "DNS": (
        "<b>Domain Name System (DNS):</b> The Internet's phonebook that translates human-friendly domain names "
        "(like google.com) into numerical IP addresses (like 142.250.190.46)."
    ),
    "Z-score": (
        "<b>Statistical Z-Score:</b> Measures how many standard deviations a metric (such as current bandwidth) "
        "is above or below its normal baseline. A Z-score > 3.0 indicates a statistically significant surge."
    ),
    "Anomaly": (
        "<b>Traffic Anomaly:</b> A deviation from established rolling patterns. "
        "Note: An anomaly is a mathematical observation, not necessarily a cyberattack."
    ),
    "Port scanning": (
        "<b>Port Scanning:</b> When a single device systematically sends probes to many different port numbers "
        "on target systems to discover open services or security vulnerabilities."
    ),
    "Packet rate": (
        "<b>Packet Rate (pkts/s):</b> The frequency of individual network data units arriving per second. "
        "Sudden spikes with small packet sizes can suggest scanning or heartbeat ping floods."
    ),
    "Bandwidth": (
        "<b>Bandwidth / Throughput:</b> The rate of digital data transmission, measured in bytes per second (B/s, KB/s, MB/s)."
    ),
    "Source IP": (
        "<b>Source IP Address:</b> The origin numerical network address identifying where the packet was sent from."
    ),
    "Destination IP": (
        "<b>Destination IP Address:</b> The recipient numerical network address identifying where the packet is destined."
    ),
    "IsolationForest": (
        "<b>IsolationForest Machine Learning:</b> An unsupervised machine learning algorithm from scikit-learn "
        "that isolates multivariate anomalies by randomly partitioning multidimensional traffic features."
    ),
    "Passive Capture": (
        "<b>Passive Packet Capture:</b> Silently observes network packets that reach your computer's network interface "
        "without transmitting any probe signals or disrupting network traffic."
    )
}

def get_tooltip(term: str) -> str:
    """Returns formatted tooltip explanation for a term."""
    return EXPLANATIONS.get(term, f"<b>{term}</b>: Network communication metric.")
