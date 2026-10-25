import time
import math
import csv
import threading
from collections import Counter, deque
from typing import Dict, List, Optional, Tuple, Any
from utils.logger import logger

# DNS Query Types mapping
DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    43: "DS",
    48: "DNSKEY",
    65: "HTTPS",
    255: "ANY"
}

# DNS RCODEs mapping
DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    9: "NOTAUTH",
    10: "NOTZONE"
}


def calculate_entropy(s: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def parse_tls_sni(payload: bytes) -> Optional[str]:
    """
    Safely extracts Server Name Indication (SNI) from TLS Client Hello without external dependencies.
    """
    try:
        if len(payload) < 43:
            return None
        # Byte 0: Content Type (22 = Handshake)
        if payload[0] != 22:
            return None
        # Byte 5: Handshake Type (1 = Client Hello)
        if payload[5] != 1:
            return None

        # Session ID length
        pos = 43
        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        # Cipher suites length
        if pos + 2 > len(payload):
            return None
        cipher_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cipher_len

        # Compression methods length
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len

        # Extensions length
        if pos + 2 > len(payload):
            return None
        ext_total_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2

        ext_end = pos + ext_total_len
        while pos + 4 <= min(ext_end, len(payload)):
            ext_type = int.from_bytes(payload[pos:pos+2], 'big')
            ext_len = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0: # SNI extension
                if pos + 5 <= len(payload):
                    # Server name list length (2) + name type (1) + name length (2)
                    sni_len = int.from_bytes(payload[pos+3:pos+5], 'big')
                    sni_bytes = payload[pos+5:pos+5+sni_len]
                    return sni_bytes.decode('utf-8', errors='ignore')
            pos += ext_len
    except Exception:
        pass
    return None


class DNSTransaction:
    """Represents an observable DNS query and its matched response."""
    def __init__(self, tx_id: str, query_id: int, client_ip: str, client_port: int,
                 server_ip: str, server_port: int, qname: str, qtype: str, timestamp: float):
        self.tx_id = tx_id
        self.query_id = query_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.qname = qname
        self.qtype = qtype
        self.req_time = timestamp
        self.resp_time: Optional[float] = None
        self.duration_ms: Optional[float] = None
        self.rcode = "Pending"
        self.answers: List[str] = []
        self.is_anomalous = False
        self.anomaly_reason = ""

    def complete_response(self, rcode_str: str, answers: List[str], resp_time: float):
        self.resp_time = resp_time
        self.duration_ms = max(0.1, (resp_time - self.req_time) * 1000.0)
        self.rcode = rcode_str
        self.answers = answers

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "query_id": self.query_id,
            "client_endpoint": f"{self.client_ip}:{self.client_port}",
            "server_endpoint": f"{self.server_ip}:{self.server_port}",
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "qname": self.qname,
            "qtype": self.qtype,
            "rcode": self.rcode,
            "duration_ms": round(self.duration_ms, 2) if self.duration_ms is not None else -1.0,
            "answers": ", ".join(self.answers) if self.answers else ("None" if self.rcode != "Pending" else "..."),
            "timestamp": self.req_time,
            "is_anomalous": self.is_anomalous,
            "anomaly_reason": self.anomaly_reason
        }


class DNSMonitor:
    """
    Monitors, parses, and correlates DNS queries/responses and encrypted traffic hints (TLS/QUIC).
    Detects DNS tunneling, query floods, and NXDOMAIN bursts.
    """
    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls, max_history: int = 5000):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super(DNSMonitor, cls).__new__(cls)
                cls._instance._init_monitor(max_history)
            return cls._instance

    def _init_monitor(self, max_history: int):
        self.max_history = max_history
        self.lock = threading.Lock()
        self.transactions: deque = deque(maxlen=max_history)
        self.pending_queries: Dict[Tuple, DNSTransaction] = {} # Key: (client_ip, client_port, server_ip, query_id)
        self.anomaly_alerts: deque = deque(maxlen=200)

        # Anomaly tracking windows
        self.nxdomain_history: Dict[str, deque] = {} # client_ip -> deque of timestamps
        self.query_rate_history: Dict[str, deque] = {} # client_ip -> deque of timestamps
        self.domain_frequency: Dict[str, deque] = {} # qname -> deque of timestamps

        logger.info(f"Initialized DNSMonitor (capacity={max_history})")

    def process_packet(self, pkt: Dict[str, Any], raw_packet=None) -> Optional[Dict[str, Any]]:
        """
        Parses Scapy packet for DNS and TLS metadata.
        Returns DNS transaction dict or TLS metadata dict if applicable.
        """
        if raw_packet is None:
            return None

        # 1. Check for DNS layer
        try:
            from scapy.layers.dns import DNS, DNSQR, DNSRR
            if raw_packet.haslayer(DNS):
                return self._handle_dns_packet(raw_packet, pkt)
        except Exception as e:
            logger.debug(f"DNS parsing error: {e}")

        # 2. Check for TLS Handshake on TCP
        try:
            from scapy.layers.inet import TCP
            if raw_packet.haslayer(TCP):
                tcp = raw_packet[TCP]
                sport = tcp.sport
                dport = tcp.dport
                if dport == 443 or sport == 443 or dport in (8443, 9443):
                    payload = bytes(tcp.payload)
                    if payload:
                        sni = parse_tls_sni(payload)
                        if sni:
                            return {
                                "type": "TLS_METADATA",
                                "protocol": "TLS-associated",
                                "sni": sni,
                                "src_ip": pkt.get("src_ip"),
                                "dst_ip": pkt.get("dst_ip"),
                                "src_port": sport,
                                "dst_port": dport,
                                "timestamp": pkt.get("timestamp", time.time()),
                                "note": "Observable SNI extracted from unencrypted TLS Client Hello. Traffic payload is encrypted."
                            }
        except Exception:
            pass

        return None

    def _handle_dns_packet(self, raw_packet, pkt_meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        dns = raw_packet[DNS]
        timestamp = pkt_meta.get("timestamp", time.time())
        src_ip = pkt_meta.get("src_ip", "")
        dst_ip = pkt_meta.get("dst_ip", "")
        src_port = pkt_meta.get("src_port", 0)
        dst_port = pkt_meta.get("dst_port", 0)

        # Handle Query (qr == 0)
        if dns.qr == 0:
            if not dns.qd:
                return None
            qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if hasattr(dns.qd, 'qname') else "Unknown"
            qtype_num = dns.qd.qtype if hasattr(dns.qd, 'qtype') else 1
            qtype = DNS_QTYPES.get(qtype_num, f"TYPE{qtype_num}")

            tx_id = f"DNS-{len(self.transactions) + 1:06d}"
            tx = DNSTransaction(
                tx_id=tx_id,
                query_id=dns.id,
                client_ip=src_ip,
                client_port=src_port,
                server_ip=dst_ip,
                server_port=dst_port,
                qname=qname,
                qtype=qtype,
                timestamp=timestamp
            )

            # Check query anomalies immediately
            self._check_query_anomalies(tx)

            with self.lock:
                key = (src_ip, src_port, dst_ip, dns.id)
                self.pending_queries[key] = tx
                self.transactions.append(tx)

            return tx.to_dict()

        # Handle Response (qr == 1)
        elif dns.qr == 1:
            rcode_num = dns.rcode
            rcode_str = DNS_RCODES.get(rcode_num, f"RCODE{rcode_num}")
            answers = []

            # Extract answers safely
            if dns.an:
                curr = dns.an
                while curr:
                    try:
                        if hasattr(curr, 'rdata'):
                            rdata = curr.rdata
                            if isinstance(rdata, bytes):
                                answers.append(rdata.decode('utf-8', errors='ignore'))
                            else:
                                answers.append(str(rdata))
                    except Exception:
                        pass
                    curr = curr.payload if hasattr(curr, 'payload') and curr.payload else None

            with self.lock:
                # Key matching response endpoints: client was original src
                key = (dst_ip, dst_port, src_ip, dns.id)
                tx = self.pending_queries.pop(key, None)
                if tx:
                    tx.complete_response(rcode_str, answers, timestamp)
                    self._check_response_anomalies(tx)
                    return tx.to_dict()
                else:
                    # Unmatched response (e.g. query captured before sniffer started)
                    qname = "Unknown"
                    qtype = "A"
                    if dns.qd:
                        qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        qtype = DNS_QTYPES.get(dns.qd.qtype, "A")

                    tx_id = f"DNS-{len(self.transactions) + 1:06d}"
                    orphan_tx = DNSTransaction(
                        tx_id=tx_id,
                        query_id=dns.id,
                        client_ip=dst_ip,
                        client_port=dst_port,
                        server_ip=src_ip,
                        server_port=src_port,
                        qname=qname,
                        qtype=qtype,
                        timestamp=timestamp
                    )
                    orphan_tx.complete_response(rcode_str, answers, timestamp)
                    self.transactions.append(orphan_tx)
                    return orphan_tx.to_dict()

    def _check_query_anomalies(self, tx: DNSTransaction):
        now = tx.req_time
        client = tx.client_ip
        domain = tx.qname

        # 1. Query rate spike check (>30 queries in 5s)
        if client not in self.query_rate_history:
            self.query_rate_history[client] = deque()
        q_window = self.query_rate_history[client]
        q_window.append(now)
        while q_window and now - q_window[0] > 5.0:
            q_window.popleft()

        if len(q_window) >= 30:
            tx.is_anomalous = True
            tx.anomaly_reason = f"High DNS query rate burst ({len(q_window)} queries in 5s)"
            self._record_alert("DNS Query Flood", tx.anomaly_reason, client, domain)

        # 2. Domain entropy / Suspicious DGA check
        # Take the leftmost subdomain label
        parts = domain.split('.')
        if len(parts) >= 2:
            subdomain = parts[0]
            if len(subdomain) >= 12:
                entropy = calculate_entropy(subdomain)
                if entropy > 3.8:
                    tx.is_anomalous = True
                    tx.anomaly_reason = f"High domain entropy ({entropy:.2f}) on '{subdomain}' (Potential DGA/Tunneling Heuristic)"
                    self._record_alert("High Domain Entropy (DGA / Tunneling Heuristic)", tx.anomaly_reason, client, domain)

        # 3. Repeated Domain Flooding (>25 queries to same domain in 10s)
        if domain not in self.domain_frequency:
            self.domain_frequency[domain] = deque()
        d_window = self.domain_frequency[domain]
        d_window.append(now)
        while d_window and now - d_window[0] > 10.0:
            d_window.popleft()

        if len(d_window) >= 25:
            tx.is_anomalous = True
            tx.anomaly_reason = f"Repeated domain flooding ({len(d_window)} requests to '{domain}' in 10s)"
            self._record_alert("Repeated Domain Flooding", tx.anomaly_reason, client, domain)

    def _check_response_anomalies(self, tx: DNSTransaction):
        now = tx.resp_time or tx.req_time
        client = tx.client_ip

        # NXDOMAIN Burst check (>=8 NXDOMAINs in 10s)
        if tx.rcode == "NXDOMAIN":
            if client not in self.nxdomain_history:
                self.nxdomain_history[client] = deque()
            nx_window = self.nxdomain_history[client]
            nx_window.append(now)
            while nx_window and now - nx_window[0] > 10.0:
                nx_window.popleft()

            if len(nx_window) >= 8:
                tx.is_anomalous = True
                tx.anomaly_reason = f"Burst of {len(nx_window)} NXDOMAIN failures in 10s"
                self._record_alert("NXDOMAIN Failure Burst", tx.anomaly_reason, client, tx.qname)

    def _record_alert(self, title: str, reason: str, client_ip: str, domain: str):
        now = time.time()
        alert = {
            "title": title,
            "reason": reason,
            "client_ip": client_ip,
            "domain": domain,
            "timestamp": now
        }
        with self.lock:
            self.anomaly_alerts.append(alert)

        # Forward to central AlertManager
        try:
            from core.alert_manager import AlertManager
            AlertManager().process_raw_alert({
                "category": "DNS Anomaly",
                "title": title,
                "detection_method": "DNS Heuristic / Entropy",
                "src_ip": client_ip,
                "dst_ip": domain,
                "anomaly_score": 5.0,
                "current_rate": reason,
                "baseline_rate": "Normal DNS traffic",
                "explanation": reason,
                "recommended_action": "Inspect domain query history and client software. Investigate whether suspicious DGA, tunneling, or flood queries are originating from this host.",
                "timestamp": now
            })
        except Exception:
            pass

    def get_transactions_snapshot(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [tx.to_dict() for tx in reversed(self.transactions)]

    def get_top_domains(self, limit: int = 15) -> List[Tuple[str, int]]:
        with self.lock:
            counts = Counter(tx.qname for tx in self.transactions if tx.qname and tx.qname != "Unknown")
            return counts.most_common(limit)

    def get_qtype_distribution(self) -> Dict[str, int]:
        with self.lock:
            return dict(Counter(tx.qtype for tx in self.transactions))

    def get_rcode_distribution(self) -> Dict[str, int]:
        with self.lock:
            return dict(Counter(tx.rcode for tx in self.transactions))

    def get_dns_alerts(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(reversed(self.anomaly_alerts))

    def clear(self):
        with self.lock:
            self.transactions.clear()
            self.pending_queries.clear()
            self.anomaly_alerts.clear()
            self.nxdomain_history.clear()
            self.query_rate_history.clear()
            self.domain_frequency.clear()

    def export_to_csv(self, filepath: str) -> bool:
        txs = self.get_transactions_snapshot()
        if not txs:
            return False
        try:
            fieldnames = [
                "tx_id", "timestamp", "client_endpoint", "server_endpoint",
                "qname", "qtype", "rcode", "duration_ms", "answers",
                "is_anomalous", "anomaly_reason"
            ]
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for row in txs:
                    writer.writerow(row)
            return True
        except Exception as e:
            logger.error(f"Failed to export DNS log to CSV: {e}")
            return False
