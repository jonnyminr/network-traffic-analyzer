import collections
import time
from typing import Dict, Any, List
import threading

class StatsAggregator:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset_current_window()
        # History for rolling baselines
        self.history: List[Dict[str, Any]] = []

    def reset_current_window(self):
        self.current_window_start = time.time()
        self.packet_count = 0
        self.byte_count = 0
        self.protocol_counts = collections.defaultdict(int)
        self.ip_bytes = collections.defaultdict(int)
        # For port scan detection (source IP -> set of dest ports)
        self.ip_ports = collections.defaultdict(set)

    def add_packet(self, parsed_packet: Dict[str, Any]):
        with self.lock:
            self.packet_count += 1
            self.byte_count += parsed_packet['size']
            self.protocol_counts[parsed_packet['protocol']] += 1
            
            src_ip = parsed_packet['src_ip']
            dst_ip = parsed_packet['dst_ip']
            
            self.ip_bytes[src_ip] += parsed_packet['size']
            self.ip_bytes[dst_ip] += parsed_packet['size']
            
            if parsed_packet['dst_port'] is not None:
                self.ip_ports[src_ip].add(parsed_packet['dst_port'])

    def get_and_reset_stats(self) -> Dict[str, Any]:
        """
        Returns the stats for the current window and starts a new window.
        """
        with self.lock:
            now = time.time()
            duration = now - self.current_window_start
            # Avoid division by zero
            if duration <= 0:
                duration = 1.0

            # Calculate top talkers (top 5 by bytes)
            top_talkers = sorted(self.ip_bytes.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Calculate distinct port counts per IP
            port_scan_candidates = {ip: len(ports) for ip, ports in self.ip_ports.items() if len(ports) > 10}

            stats = {
                'timestamp': now,
                'duration': duration,
                'packets_per_sec': self.packet_count / duration,
                'bytes_per_sec': self.byte_count / duration,
                'protocol_counts': dict(self.protocol_counts),
                'top_talkers': top_talkers,
                'port_scan_candidates': port_scan_candidates,
                'unique_src_ips': len(self.ip_ports)
            }
            
            # Keep recent history for ML/Anomaly detection (last 60 windows)
            self.history.append(stats)
            if len(self.history) > 60:
                self.history.pop(0)

            self.reset_current_window()
            return stats
