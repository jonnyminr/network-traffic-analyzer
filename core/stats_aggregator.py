import collections
import time
from typing import Dict, Any, List
import threading

class StatsAggregator:
    def __init__(self):
        self.lock = threading.Lock()
        
        # Cumulative lifetime session metrics
        self.total_packets = 0
        self.total_bytes = 0
        self.session_start = time.time()
        self.cumulative_protocols = collections.defaultdict(int)
        self.cumulative_ip_bytes = collections.defaultdict(int)
        
        # Current window metrics
        self.reset_current_window()
        # History for rolling baselines (e.g. for anomaly detection)
        self.history: List[Dict[str, Any]] = []

    def reset_current_window(self):
        self.current_window_start = time.time()
        self.window_packet_count = 0
        self.window_byte_count = 0
        self.window_protocol_counts = collections.defaultdict(int)
        self.window_ip_bytes = collections.defaultdict(int)
        # For port scan detection (source IP -> set of dest ports)
        self.window_ip_ports = collections.defaultdict(set)
        self.window_dst_ips = set()
        self.window_dst_ports = set()
        self.window_tcp_syns = 0
        self.window_tcp_acks = 0
        self.window_inbound_bytes = 0
        self.window_outbound_bytes = 0

    def set_local_ip(self, ip: str):
        self.local_ip = ip

    def reset_all(self):
        """Resets all session and window statistics."""
        with self.lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.session_start = time.time()
            self.cumulative_protocols.clear()
            self.cumulative_ip_bytes.clear()
            self.history.clear()
            self.reset_current_window()

    def add_packet(self, parsed_packet: Dict[str, Any]):
        with self.lock:
            pkt_size = parsed_packet.get('size', 0)
            proto = parsed_packet.get('protocol', 'Other')
            src_ip = parsed_packet.get('src_ip', '')
            dst_ip = parsed_packet.get('dst_ip', '')
            dst_port = parsed_packet.get('dst_port')
            flags = str(parsed_packet.get('flags', '')).upper()
            
            # Update cumulative metrics
            self.total_packets += 1
            self.total_bytes += pkt_size
            self.cumulative_protocols[proto] += 1
            if src_ip:
                self.cumulative_ip_bytes[src_ip] += pkt_size
            if dst_ip:
                self.cumulative_ip_bytes[dst_ip] += pkt_size

            # Update window metrics
            self.window_packet_count += 1
            self.window_byte_count += pkt_size
            self.window_protocol_counts[proto] += 1
            
            if src_ip:
                self.window_ip_bytes[src_ip] += pkt_size
            if dst_ip:
                self.window_ip_bytes[dst_ip] += pkt_size
                self.window_dst_ips.add(dst_ip)
            
            if dst_port is not None:
                self.window_dst_ports.add(dst_port)
                if src_ip:
                    self.window_ip_ports[src_ip].add(dst_port)

            # TCP flags
            if 'S' in flags:
                self.window_tcp_syns += 1
            if 'A' in flags:
                self.window_tcp_acks += 1

            # Inbound / Outbound classification
            if hasattr(self, 'local_ip') and self.local_ip:
                if src_ip == self.local_ip:
                    self.window_outbound_bytes += pkt_size
                elif dst_ip == self.local_ip:
                    self.window_inbound_bytes += pkt_size

    def get_and_reset_stats(self) -> Dict[str, Any]:
        """
        Returns stats for the current window along with cumulative session totals,
        and starts a new measurement window.
        """
        with self.lock:
            now = time.time()
            duration = now - self.current_window_start
            if duration <= 0:
                duration = 1.0

            # Calculate top talkers (top 5 by cumulative bytes, fallback to window)
            top_talkers_src = self.cumulative_ip_bytes if self.cumulative_ip_bytes else self.window_ip_bytes
            top_talkers = sorted(top_talkers_src.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Port scan detection: IPs hitting > 10 distinct destination ports in the current window
            port_scan_candidates = {
                ip: len(ports) 
                for ip, ports in self.window_ip_ports.items() 
                if len(ports) > 10
            }

            stats = {
                'timestamp': now,
                'duration': duration,
                'packets_per_sec': self.window_packet_count / duration,
                'bytes_per_sec': self.window_byte_count / duration,
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'session_duration': now - self.session_start,
                'protocol_counts': dict(self.cumulative_protocols),
                'window_protocol_counts': dict(self.window_protocol_counts),
                'top_talkers': top_talkers,
                'port_scan_candidates': port_scan_candidates,
                'unique_src_ips': len(self.window_ip_ports),
                'unique_dst_ips': len(self.window_dst_ips),
                'unique_dst_ports': len(self.window_dst_ports),
                'tcp_syn_count': self.window_tcp_syns,
                'tcp_ack_count': self.window_tcp_acks,
                'outbound_bytes': self.window_outbound_bytes,
                'inbound_bytes': self.window_inbound_bytes,
                'outbound_rate': self.window_outbound_bytes / duration,
                'inbound_rate': self.window_inbound_bytes / duration
            }
            
            # Keep recent history for ML/Anomaly detection (last 60 windows)
            self.history.append(stats)
            if len(self.history) > 60:
                self.history.pop(0)

            self.reset_current_window()
            return stats
