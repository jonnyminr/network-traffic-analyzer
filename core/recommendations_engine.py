import time
from typing import Dict, Any, List

class RecommendationsEngine:
    """
    Generates practical, evidence-based network troubleshooting recommendations
    and actionable observations without fabricating data or mislabeling statistical
    deviations as confirmed cyberattacks.
    """
    @staticmethod
    def generate_recommendations(stats: dict, alerts: list, health_status: dict = None) -> List[Dict[str, str]]:
        recs = []

        total_bytes = stats.get("total_bytes", 0)
        bps = stats.get("bytes_per_sec", 0.0)
        talkers = stats.get("top_talkers", [])
        outbound_bytes = stats.get("outbound_bytes", 0)
        inbound_bytes = stats.get("inbound_bytes", 0)

        # 1. Top Talker Dominance Recommendation
        if talkers and total_bytes > 500000:
            top_ip, top_b = talkers[0]
            share = (top_b / max(1, total_bytes)) * 100.0
            if share >= 60.0:
                recs.append({
                    "category": "Bandwidth Usage",
                    "severity": "Informational",
                    "title": "Single Host Dominating Traffic",
                    "observation": f"Host {top_ip} accounts for {share:.1f}% of total session volume ({top_b / (1024*1024):.1f} MB).",
                    "recommendation": f"Check if host {top_ip} is running a large file transfer, operating system update, or video stream."
                })

        # 2. Asymmetric Outbound Traffic Recommendation
        if outbound_bytes > 2000000 and outbound_bytes > (inbound_bytes * 4):
            recs.append({
                "category": "Traffic Flow",
                "severity": "Notice",
                "title": "Substantial Outbound Upload Activity",
                "observation": f"Outbound transmission ({outbound_bytes / (1024*1024):.1f} MB) significantly exceeds inbound reception ({inbound_bytes / (1024*1024):.1f} MB).",
                "recommendation": "Review active connections to verify if cloud backups, video uploads, or file sharing are currently scheduled."
            })

        # 3. Port Scanning / Probing Heuristic Recommendation
        for a in alerts:
            if a.get("category") == "Port Scanning":
                src = a.get("src_ip", "Unknown")
                recs.append({
                    "category": "Scanning Activity",
                    "severity": "Warning",
                    "title": "Multiple Port Probes Observed",
                    "observation": f"Host {src} generated connection attempts to numerous distinct destination ports.",
                    "recommendation": f"Inspect local firewall rules for {src}. Verify if vulnerability scanners or local discovery tools are running."
                })
                break

        # 4. Repeated Connection Retries / SYN Flood Recommendation
        for a in alerts:
            if a.get("category") == "Repeated Connection Attempts":
                recs.append({
                    "category": "Connectivity Retries",
                    "severity": "Notice",
                    "title": "Unanswered TCP Handshakes",
                    "observation": "Observed multiple TCP SYN connection attempts without corresponding ACK acknowledgments.",
                    "recommendation": "Check Connection Explorer for SYN_SENT states. The target service may be offline, firewalled, or rejecting connections."
                })
                break

        # 5. Network Health Diagnostic Findings
        if health_status:
            status = health_status.get("status", "")
            if status == "Degraded":
                if health_status.get("packet_loss_pct", 0) > 15:
                    recs.append({
                        "category": "Network Quality",
                        "severity": "Warning",
                        "title": "High Network Packet Loss",
                        "observation": f"Active diagnostics detected {health_status.get('packet_loss_pct')}% packet loss.",
                        "recommendation": "Check physical Ethernet cable, Wi-Fi signal strength, or restart the local network router."
                    })
                if health_status.get("dns_status") == "Failing":
                    recs.append({
                        "category": "DNS Troubleshooting",
                        "severity": "Warning",
                        "title": "DNS Domain Resolution Failed",
                        "observation": "Domain name resolution queries to public resolvers failed during connectivity tests.",
                        "recommendation": "Verify your computer's DNS configuration (e.g. switch to 1.1.1.1 or 8.8.8.8) or inspect router DNS settings."
                    })

        # Default healthy fallback
        if not recs:
            recs.append({
                "category": "General Network Health",
                "severity": "Normal",
                "title": "Traffic Profile Is Normal",
                "observation": "Captured network traffic shows balanced protocol distributions and no severe anomalies.",
                "recommendation": "Continue standard network monitoring. You can configure custom BPF filters or capture profiles in Settings."
            })

        return recs
