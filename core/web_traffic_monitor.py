import time
import socket
import urllib.parse
import re
import collections
from typing import Dict, Any, List, Optional, Set, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from PySide6.QtCore import QThread, Signal
from scapy.all import conf, AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

from core.packet_parser import parse_packet
from utils.interfaces import resolve_scapy_interface, get_network_interfaces
from utils.logger import logger

def normalize_website_url(raw_url: str) -> Tuple[str, str]:
    """
    Validates and normalizes user-entered website URL.
    Returns (normalized_url, hostname).
    Raises ValueError with descriptive reason if invalid.
    """
    if not raw_url or not raw_url.strip():
        raise ValueError("Please enter a website URL.")

    url = raw_url.strip()

    # Prepend https:// if no scheme is provided
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url = 'https://' + url

    parsed = urllib.parse.urlparse(url)

    if parsed.scheme.lower() not in ('http', 'https'):
        raise ValueError(f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS URLs are supported.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: Could not extract a valid domain or hostname.")

    hostname = hostname.lower().strip('.')

    # Basic hostname validation
    if not re.match(r'^[a-z0-9]([a-z0-9\-\.]{0,253}[a-z0-9])?$', hostname):
        raise ValueError(f"Invalid hostname format: '{hostname}'")

    return url, hostname

def extract_tls_sni(raw_packet) -> Optional[str]:
    """
    Extracts the Server Name Indication (SNI) hostname from a TLS ClientHello packet.
    Operates directly on the raw TCP payload for high speed without heavy layer dependencies.
    """
    try:
        if not (raw_packet.haslayer(TCP) and raw_packet.haslayer(Raw)):
            return None
            
        payload = bytes(raw_packet[Raw].load)
        if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
            
        # Handshake Type 1 = ClientHello
        if payload[5] != 0x01:
            return None

        # Skip Session ID
        offset = 43
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Skip Cipher Suites
        if offset + 2 > len(payload):
            return None
        cipher_suites_len = int.from_bytes(payload[offset:offset+2], 'big')
        offset += 2 + cipher_suites_len

        # Skip Compression Methods
        if offset + 1 > len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(payload):
            return None
        ext_total_len = int.from_bytes(payload[offset:offset+2], 'big')
        offset += 2
        ext_end = min(offset + ext_total_len, len(payload))

        while offset + 4 <= ext_end:
            ext_type = int.from_bytes(payload[offset:offset+2], 'big')
            ext_len = int.from_bytes(payload[offset+2:offset+4], 'big')
            offset += 4
            if ext_type == 0: # Extension: Server Name Indication (SNI)
                if offset + 5 <= ext_end:
                    name_type = payload[offset+2]
                    name_len = int.from_bytes(payload[offset+3:offset+5], 'big')
                    if name_type == 0 and offset + 5 + name_len <= ext_end:
                        sni_bytes = payload[offset+5 : offset+5+name_len]
                        return sni_bytes.decode('utf-8', errors='ignore').lower().strip('.')
            offset += ext_len
    except Exception:
        pass
    return None

class WebTarget:
    """
    Encapsulates the target website, DNS resolution, and attribution matching.
    """
    def __init__(self, raw_url: str):
        self.raw_url, self.hostname = normalize_website_url(raw_url)
        # Extract base domain (e.g. 'wikipedia.org' from 'www.wikipedia.org')
        parts = self.hostname.split('.')
        self.base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else self.hostname

        self.resolved_ipv4: Set[str] = set()
        self.resolved_ipv6: Set[str] = set()
        self.all_ips: Set[str] = set()
        self.dns_resolved_at: float = 0.0
        self.last_error: Optional[str] = None

    def resolve_dns(self) -> Dict[str, Any]:
        """Resolves target hostname via DNS for both IPv4 and IPv6."""
        ipv4_found = set()
        ipv6_found = set()
        self.last_error = None

        try:
            # Query getaddrinfo for both AF_INET and AF_INET6
            infos = socket.getaddrinfo(self.hostname, None)
            for info in infos:
                family = info[0]
                ip_addr = info[4][0]
                if family == socket.AF_INET:
                    ipv4_found.add(ip_addr)
                elif family == socket.AF_INET6:
                    ipv6_found.add(ip_addr)
        except socket.gaierror as e:
            self.last_error = f"DNS resolution failed for '{self.hostname}': {e.strerror}"
            logger.warning(self.last_error)
        except Exception as e:
            self.last_error = f"DNS resolution error: {str(e)}"
            logger.error(self.last_error)

        if ipv4_found or ipv6_found:
            self.resolved_ipv4.update(ipv4_found)
            self.resolved_ipv6.update(ipv6_found)
            self.all_ips = self.resolved_ipv4.union(self.resolved_ipv6)
            self.dns_resolved_at = time.time()

        return {
            'hostname': self.hostname,
            'base_domain': self.base_domain,
            'ipv4': sorted(self.resolved_ipv4),
            'ipv6': sorted(self.resolved_ipv6),
            'all_ips': sorted(self.all_ips),
            'error': self.last_error,
            'resolved_at': self.dns_resolved_at
        }

    def add_dynamic_ip(self, ip: str):
        """Dynamically registers an IP discovered via live DNS response or verified SNI."""
        if not ip:
            return
        if ':' in ip:
            self.resolved_ipv6.add(ip)
        else:
            self.resolved_ipv4.add(ip)
        self.all_ips.add(ip)

    def matches_packet(self, parsed_pkt: dict, raw_pkt=None) -> Tuple[bool, str, str]:
        """
        Determines whether a packet is associated with this website.
        Returns: (is_match, attribution_label, summary_desc)
        """
        src_ip = parsed_pkt.get('src_ip', '')
        dst_ip = parsed_pkt.get('dst_ip', '')
        src_port = parsed_pkt.get('src_port')
        dst_port = parsed_pkt.get('dst_port')
        proto = parsed_pkt.get('protocol', '')

        # 1. Check for DNS Traffic (port 53) matching target domain
        if (src_port == 53 or dst_port == 53) and raw_pkt is not None:
            if raw_pkt.haslayer(DNS):
                try:
                    dns = raw_pkt[DNS]
                    # Check query name
                    qname = ""
                    if dns.qd and hasattr(dns.qd, 'qname'):
                        qname = dns.qd.qname.decode('utf-8', errors='ignore').lower().strip('.')

                    if self.hostname in qname or self.base_domain in qname:
                        # Inspect answer records if present to dynamically learn CDN IPs
                        if dns.an:
                            cur_an = dns.an
                            while cur_an:
                                if hasattr(cur_an, 'rdata') and cur_an.rdata:
                                    rdata_str = str(cur_an.rdata).strip()
                                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', rdata_str) or ':' in rdata_str:
                                        self.add_dynamic_ip(rdata_str)
                                cur_an = getattr(cur_an, 'payload', None)
                        summary = f"DNS Query/Response for {qname or self.hostname}"
                        return True, "DNS Activity", summary
                except Exception:
                    pass

        # 2. Check for TLS SNI Match on TCP ClientHello
        if proto == 'TCP' and raw_pkt is not None:
            sni = extract_tls_sni(raw_pkt)
            if sni:
                if sni == self.hostname or sni.endswith('.' + self.base_domain):
                    # Add remote IP to target IPs if not present
                    if dst_ip and dst_ip not in self.all_ips:
                        self.add_dynamic_ip(dst_ip)
                    summary = f"TLS ClientHello SNI: {sni}"
                    return True, "Verified SNI", summary

        # 3. Check for Direct IP Match (src or dst in resolved IPs)
        if src_ip in self.all_ips or dst_ip in self.all_ips:
            # Determine application description
            if dst_port == 443 or src_port == 443:
                app_desc = "HTTPS [Encrypted TLS Payload]" if proto == 'TCP' else "QUIC / HTTP3 [Encrypted]"
            elif dst_port == 80 or src_port == 80:
                app_desc = "HTTP Cleartext"
            elif dst_port == 53 or src_port == 53:
                app_desc = "DNS"
            else:
                port_num = dst_port or src_port or 0
                app_desc = f"{proto} Port {port_num}"

            # TCP flags string if present
            flags_str = parsed_pkt.get('tcp_flags', '')
            flag_info = f" Flags: [{flags_str}]" if flags_str else ""
            summary = f"{app_desc}{flag_info} (IP-Matched via {self.hostname})"
            return True, "IP Match (CDN/Shared)", summary

        return False, "", ""

class WebConnectionTracker:
    """
    Tracks and aggregates bidirectional flows/connections associated with the target website.
    """
    def __init__(self):
        self.lock_conns = collections.defaultdict(dict)
        self.connections: Dict[str, Dict[str, Any]] = {}

    def get_flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> str:
        p1 = f"{src_ip}:{src_port}"
        p2 = f"{dst_ip}:{dst_port}"
        if p1 <= p2:
            return f"{proto}:{p1}<->{p2}"
        else:
            return f"{proto}:{p2}<->{p1}"

    def update_flow(self, parsed_pkt: dict, direction: str, attribution: str):
        src_ip = parsed_pkt.get('src_ip', '')
        dst_ip = parsed_pkt.get('dst_ip', '')
        src_port = parsed_pkt.get('src_port') or 0
        dst_port = parsed_pkt.get('dst_port') or 0
        proto = parsed_pkt.get('protocol', 'Other')
        size = parsed_pkt.get('size', 0)
        ts = parsed_pkt.get('timestamp', time.time())
        flags = parsed_pkt.get('tcp_flags', '')

        key = self.get_flow_key(src_ip, src_port, dst_ip, dst_port, proto)

        if key not in self.connections:
            # Classify application protocol
            if proto == 'TCP' and (src_port == 443 or dst_port == 443):
                app_proto = "HTTPS (TLS)"
            elif proto == 'UDP' and (src_port == 443 or dst_port == 443):
                app_proto = "QUIC (HTTP/3)"
            elif src_port == 80 or dst_port == 80:
                app_proto = "HTTP"
            elif src_port == 53 or dst_port == 53:
                app_proto = "DNS"
            else:
                app_proto = proto

            # Determine local vs remote endpoint accurately
            # Local endpoint is our computer; remote endpoint is the website server
            local_ip = parsed_pkt.get('local_ip', '')
            if src_ip == local_ip or ("Outgoing" in direction and dst_ip != local_ip):
                local_ep = f"{src_ip}:{src_port}"
                remote_ep = f"{dst_ip}:{dst_port}"
                remote_port = dst_port
            else:
                local_ep = f"{dst_ip}:{dst_port}"
                remote_ep = f"{src_ip}:{src_port}"
                remote_port = src_port

            self.connections[key] = {
                'key': key,
                'local_endpoint': local_ep,
                'remote_endpoint': remote_ep,
                'remote_port': remote_port,
                'protocol': proto,
                'app_proto': app_proto,
                'start_time': ts,
                'last_seen': ts,
                'bytes_in': 0,
                'bytes_out': 0,
                'packets_in': 0,
                'packets_out': 0,
                'total_bytes': 0,
                'total_packets': 0,
                'state': 'ESTABLISHED' if proto == 'TCP' else 'ACTIVE',
                'attribution': attribution
            }

        conn = self.connections[key]
        conn['last_seen'] = ts
        conn['total_packets'] += 1
        conn['total_bytes'] += size

        if "Incoming" in direction:
            conn['bytes_in'] += size
            conn['packets_in'] += 1
        else:
            conn['bytes_out'] += size
            conn['packets_out'] += 1

        # Track TCP States
        if proto == 'TCP' and flags:
            if 'S' in flags and 'A' not in flags:
                conn['state'] = 'SYN_SENT'
            elif 'S' in flags and 'A' in flags:
                conn['state'] = 'SYN_RECV'
            elif 'F' in flags:
                conn['state'] = 'FIN_WAIT'
            elif 'R' in flags:
                conn['state'] = 'RESET'
            elif 'A' in flags and conn['state'] in ('SYN_SENT', 'SYN_RECV'):
                conn['state'] = 'ESTABLISHED'

        # Upgrade attribution if verified SNI seen
        if attribution == "Verified SNI":
            conn['attribution'] = "Verified SNI"

    def get_connection_list(self) -> List[Dict[str, Any]]:
        """Returns list of tracked connections sorted by most recently active."""
        sorted_conns = sorted(self.connections.values(), key=lambda c: c['last_seen'], reverse=True)
        return sorted_conns

    def get_active_count(self) -> int:
        now = time.time()
        # Consider connections active if packets seen in last 30s and state not CLOSED/RESET
        return sum(1 for c in self.connections.values() if now - c['last_seen'] < 30.0 and c['state'] not in ('RESET', 'CLOSED'))

    def clear(self):
        self.connections.clear()

class WebStatsAggregator:
    """
    Aggregates real-time website traffic metrics (incoming/outgoing rates, protocols, totals).
    """
    def __init__(self):
        self.conn_tracker = WebConnectionTracker()
        self.reset_all()

    def reset_all(self):
        self.session_start = time.time()
        self.total_bytes = 0
        self.total_packets = 0
        self.total_incoming_bytes = 0
        self.total_outgoing_bytes = 0
        self.total_incoming_packets = 0
        self.total_outgoing_packets = 0
        
        self.protocol_counts = collections.defaultdict(int)
        self.conn_tracker.clear()
        
        self.history: List[Dict[str, Any]] = []
        self.reset_current_window()

    def reset_current_window(self):
        self.window_start = time.time()
        self.window_in_bytes = 0
        self.window_out_bytes = 0
        self.window_in_packets = 0
        self.window_out_packets = 0

    def add_packet(self, parsed_pkt: dict, direction: str, attribution: str):
        size = parsed_pkt.get('size', 0)
        proto = parsed_pkt.get('protocol', 'Other')
        src_port = parsed_pkt.get('src_port') or 0
        dst_port = parsed_pkt.get('dst_port') or 0

        # Update cumulative counters
        self.total_packets += 1
        self.total_bytes += size

        if direction == "Incoming":
            self.total_incoming_bytes += size
            self.total_incoming_packets += 1
            self.window_in_bytes += size
            self.window_in_packets += 1
        else:
            self.total_outgoing_bytes += size
            self.total_outgoing_packets += 1
            self.window_out_bytes += size
            self.window_out_packets += 1

        # Protocol Breakdown Strategy
        if proto == 'TCP' and (src_port == 443 or dst_port == 443):
            cat = "HTTPS"
        elif proto == 'UDP' and (src_port == 443 or dst_port == 443):
            cat = "QUIC"
        elif src_port == 80 or dst_port == 80:
            cat = "HTTP"
        elif src_port == 53 or dst_port == 53:
            cat = "DNS"
        elif proto == 'ICMP':
            cat = "ICMP"
        elif proto == 'TCP':
            cat = "TCP"
        elif proto == 'UDP':
            cat = "UDP"
        else:
            cat = "Other"

        self.protocol_counts[cat] += 1
        self.conn_tracker.update_flow(parsed_pkt, direction, attribution)

    def get_and_reset_stats(self) -> Dict[str, Any]:
        now = time.time()
        duration = now - self.window_start
        if duration <= 0:
            duration = 1.0

        in_bps = self.window_in_bytes / duration
        out_bps = self.window_out_bytes / duration
        in_pps = self.window_in_packets / duration
        out_pps = self.window_out_packets / duration

        active_conns = self.conn_tracker.get_active_count()
        conn_list = self.conn_tracker.get_connection_list()

        stats = {
            'timestamp': now,
            'duration': duration,
            'session_duration': now - self.session_start,
            'incoming_bytes_per_sec': in_bps,
            'outgoing_bytes_per_sec': out_bps,
            'total_bytes_per_sec': in_bps + out_bps,
            'incoming_packets_per_sec': in_pps,
            'outgoing_packets_per_sec': out_pps,
            'total_packets_per_sec': in_pps + out_pps,
            'total_bytes': self.total_bytes,
            'total_packets': self.total_packets,
            'total_incoming_bytes': self.total_incoming_bytes,
            'total_outgoing_bytes': self.total_outgoing_bytes,
            'total_incoming_packets': self.total_incoming_packets,
            'total_outgoing_packets': self.total_outgoing_packets,
            'protocol_counts': dict(self.protocol_counts),
            'active_connections': active_conns,
            'connection_list': conn_list
        }

        self.history.append(stats)
        if len(self.history) > 60:
            self.history.pop(0)

        self.reset_current_window()
        return stats

class WebTrafficAnomalyDetector:
    """
    Website-specific anomaly detection using rule checks, Z-score baseline, and IsolationForest.
    Distinguishes statistical anomalies from confirmed security threats.
    """
    def __init__(self):
        self.baseline_window_size = 30
        self.history: List[Dict[str, Any]] = []
        self.ml_model: Optional[IsolationForest] = None
        self.is_model_trained = False
        self.training_features: List[List[float]] = []
        self.min_samples_to_train = 20

    def process_stats(self, stats: Dict[str, Any], target_hostname: str) -> List[Dict[str, Any]]:
        alerts = []
        now = time.time()
        in_bps = stats.get('incoming_bytes_per_sec', 0.0)
        out_bps = stats.get('outgoing_bytes_per_sec', 0.0)
        tot_bps = in_bps + out_bps
        in_pps = stats.get('incoming_packets_per_sec', 0.0)
        out_pps = stats.get('outgoing_packets_per_sec', 0.0)
        tot_pps = in_pps + out_pps
        active_conns = stats.get('active_connections', 0)

        has_spike = False

        # 1. Statistical Z-Score Analysis on Bandwidth
        if len(self.history) >= 10:
            past_rates = [s['total_bytes_per_sec'] for s in self.history[-self.baseline_window_size:]]
            mean_rate = float(np.mean(past_rates))
            std_rate = float(np.std(past_rates))
            
            # Require minimum meaningful baseline traffic (> 10 KB/s) before flagging spikes
            if std_rate > 2048.0 and mean_rate > 5120.0:
                z_score = (tot_bps - mean_rate) / std_rate
                if z_score > 3.0:
                    has_spike = True
                    alerts.append({
                        'timestamp': now,
                        'severity': 'Warning',
                        'type': 'Statistical Anomaly (Throughput Spike)',
                        'description': (
                            f"Traffic spike for {target_hostname}: Z-Score {z_score:.2f} "
                            f"(Current: {tot_bps / 1024.0:.1f} KB/s, Baseline Mean: {mean_rate / 1024.0:.1f} KB/s). "
                            f"Note: This is a statistical volume change, not necessarily malicious."
                        )
                    })

        # 2. Rule Check: Repeated SYN attempts without establishment
        conns = stats.get('connection_list', [])
        syn_stuck_count = sum(1 for c in conns if c.get('state') == 'SYN_SENT' and c.get('packets_out', 0) > 3 and c.get('packets_in', 0) == 0)
        if syn_stuck_count >= 2:
            alerts.append({
                'timestamp': now,
                'severity': 'Critical',
                'type': 'Connection Failure / Timeout',
                'description': (
                    f"Repeated SYN retransmissions to {target_hostname}: {syn_stuck_count} connection(s) "
                    f"timed out without response from remote endpoint (possible server block, firewall drop, or down server)."
                )
            })

        # 3. Rule Check: Unusual Destination Ports
        for c in conns[:10]:
            remote_port = c.get('remote_port', 0)
            if remote_port not in (443, 80, 53, 8443, 8080) and remote_port > 0:
                alerts.append({
                    'timestamp': now,
                    'severity': 'Warning',
                    'type': 'Unusual Port Activity',
                    'description': (
                        f"Traffic to non-standard remote port {remote_port} on {c.get('remote_endpoint')} "
                        f"for {target_hostname}."
                    )
                })
                break

        # 4. Machine Learning (IsolationForest)
        features = [float(in_bps), float(out_bps), float(in_pps), float(out_pps), float(active_conns)]
        self.training_features.append(features)
        if len(self.training_features) > 100:
            self.training_features.pop(0)

        if len(self.training_features) >= self.min_samples_to_train:
            if not self.is_model_trained or len(self.training_features) % 15 == 0:
                try:
                    X = np.array(self.training_features)
                    if np.any(np.std(X, axis=0) > 0):
                        self.ml_model = IsolationForest(contamination=0.05, random_state=42)
                        self.ml_model.fit(X)
                        self.is_model_trained = True
                except Exception:
                    pass

            if self.is_model_trained and self.ml_model is not None and not has_spike:
                try:
                    sample = np.array([features])
                    pred = self.ml_model.predict(sample)
                    if pred[0] == -1:
                        alerts.append({
                            'timestamp': now,
                            'severity': 'Warning',
                            'type': 'Machine Learning Anomaly (IsolationForest)',
                            'description': (
                                f"Unusual traffic pattern detected for {target_hostname}: "
                                f"In: {in_bps/1024:.1f} KB/s, Out: {out_bps/1024:.1f} KB/s, "
                                f"Conns: {active_conns}. Signature deviates from learned baseline."
                            )
                        })
                except Exception:
                    pass

        self.history.append(stats)
        if len(self.history) > self.baseline_window_size:
            self.history.pop(0)

        return alerts

class WebCaptureEngine(QThread):
    """
    Dedicated QThread that captures packets specifically matched to the entered website.
    Runs asynchronously without blocking the GUI.
    """
    packet_captured = Signal(dict)
    stats_updated = Signal(dict)
    alerts_generated = Signal(list)
    dns_resolved = Signal(dict)
    status_changed = Signal(str)
    capture_error = Signal(str)
    capture_stopped = Signal()

    def __init__(self, target_url: str, interface: Any = None, max_duration_seconds: int = 0):
        super().__init__()
        self.target_url = target_url
        self.interface = interface
        self.max_duration = max_duration_seconds # 0 = unlimited
        
        self.is_running = False
        self.web_target = WebTarget(target_url)
        self.stats_aggregator = WebStatsAggregator()
        self.anomaly_detector = WebTrafficAnomalyDetector()
        
        # Buffer of raw Scapy packets for PCAP export
        self.raw_packet_buffer = collections.deque(maxlen=3000)
        self.local_ip = "127.0.0.1"
        self.start_time = 0.0

    def run(self):
        self.is_running = True
        self.status_changed.emit("Resolving Domain")
        logger.info(f"Resolving domain for Web Traffic capture: {self.web_target.hostname}")

        # 1. Resolve DNS
        dns_info = self.web_target.resolve_dns()
        self.dns_resolved.emit(dns_info)

        if not self.web_target.all_ips and dns_info.get('error'):
            msg = f"DNS Resolution Failed: {dns_info['error']}"
            logger.error(msg)
            self.capture_error.emit(msg)
            self.is_running = False
            self.status_changed.emit("Error")
            self.capture_stopped.emit()
            return

        # 2. Resolve Interface & determine local IP
        resolved_iface = resolve_scapy_interface(self.interface)
        if hasattr(resolved_iface, 'ip') and resolved_iface.ip:
            self.local_ip = str(resolved_iface.ip)
        else:
            # Fallback to local probe
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.local_ip = s.getsockname()[0]
                s.close()
            except Exception:
                self.local_ip = "127.0.0.1"

        iface_name = getattr(resolved_iface, 'name', str(resolved_iface))
        logger.info(f"Starting Web Traffic capture on iface: {iface_name} (Local IP: {self.local_ip}, Target: {self.web_target.hostname})")

        self.status_changed.emit("Capturing")
        self.start_time = time.time()
        self.stats_aggregator.reset_all()

        sniffer = None
        try:
            # We sniff broadly on the interface and filter in Python so we can also capture
            # DNS queries and TLS SNI for target domain dynamically even on multi-IP CDNs
            sniffer = AsyncSniffer(
                iface=resolved_iface,
                filter=None, # Software filtering against WebTarget
                prn=self.process_raw_packet,
                store=False,
                promisc=False
            )
            sniffer.start()

            last_dns_refresh = time.time()

            while self.is_running:
                # Sleep in 100ms slices for responsiveness
                for _ in range(10):
                    if not self.is_running:
                        break
                    time.sleep(0.1)

                if not self.is_running:
                    break

                # Periodic DNS re-resolution every 30s to detect CDN changes
                if time.time() - last_dns_refresh > 30.0:
                    last_dns_refresh = time.time()
                    new_dns = self.web_target.resolve_dns()
                    self.dns_resolved.emit(new_dns)

                # Emit stats every second
                self._emit_stats()

                # Check max duration
                if self.max_duration > 0 and (time.time() - self.start_time) >= self.max_duration:
                    logger.info(f"Max capture duration ({self.max_duration}s) reached.")
                    self.is_running = False
                    break

        except PermissionError:
            msg = "Permission denied: Web packet capture requires Administrator privileges on Windows."
            logger.error(msg)
            self.capture_error.emit(msg)
        except RuntimeError as e:
            err_str = str(e)
            if "winpcap" in err_str.lower() or "npcap" in err_str.lower():
                msg = "Npcap / WinPcap driver not accessible. Please install Npcap with WinPcap compatibility."
            else:
                msg = f"Capture runtime error: {err_str}"
            logger.error(msg)
            self.capture_error.emit(msg)
        except Exception as e:
            msg = f"Capture error: {str(e)}"
            logger.error(msg)
            self.capture_error.emit(msg)
        finally:
            if sniffer is not None:
                try:
                    sniffer.stop()
                    sniffer.join(timeout=1.0)
                except Exception:
                    pass
            self.is_running = False
            self.status_changed.emit("Stopped")
            self.capture_stopped.emit()
            logger.info("Web Traffic capture stopped.")

    def process_raw_packet(self, raw_pkt):
        if not self.is_running:
            return

        parsed = parse_packet(raw_pkt)
        if not parsed:
            return

        # Check TCP flags if TCP
        if raw_pkt.haslayer(TCP):
            parsed['tcp_flags'] = str(raw_pkt[TCP].flags)
        else:
            parsed['tcp_flags'] = ''

        # Match against WebTarget
        is_match, attribution, summary = self.web_target.matches_packet(parsed, raw_pkt)
        if not is_match:
            return

        # Determine traffic direction relative to local machine
        src_ip = parsed.get('src_ip', '')
        dst_ip = parsed.get('dst_ip', '')
        if src_ip == self.local_ip:
            direction = "Outgoing ⬆"
        elif dst_ip == self.local_ip:
            direction = "Incoming ⬇"
        elif src_ip in self.web_target.all_ips:
            direction = "Incoming ⬇"
        elif dst_ip in self.web_target.all_ips:
            direction = "Outgoing ⬆"
        else:
            direction = "Internal"

        parsed['direction'] = direction
        parsed['attribution'] = attribution
        parsed['summary'] = summary
        parsed['target_host'] = self.web_target.hostname
        parsed['local_ip'] = self.local_ip

        # Keep raw packet in buffer for PCAP export
        self.raw_packet_buffer.append(raw_pkt)

        # Emit to UI table
        self.packet_captured.emit(parsed)

        # Update stats
        self.stats_aggregator.add_packet(parsed, direction, attribution)

    def _emit_stats(self):
        stats = self.stats_aggregator.get_and_reset_stats()
        self.stats_updated.emit(stats)

        # Check for anomalies
        alerts = self.anomaly_detector.process_stats(stats, self.web_target.hostname)
        if alerts:
            self.alerts_generated.emit(alerts)

    def get_raw_packets(self) -> List[Any]:
        return list(self.raw_packet_buffer)

    def stop(self):
        logger.info("Stop requested for Web Traffic capture.")
        self.is_running = False
        self.wait(2000)
