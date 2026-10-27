import os
import time
from typing import Dict, Any, List, Optional
from PySide6.QtCore import QThread, Signal
from scapy.all import PcapReader, Packet

from core.packet_parser import parse_packet
from core.stats_aggregator import StatsAggregator
from core.anomaly_detector import AnomalyDetector
from utils.logger import logger


class OfflineStatsAggregator(StatsAggregator):
    """Isolated StatsAggregator instance for offline PCAP files."""
    pass


class PcapAnalysisWorker(QThread):
    """
    Streaming Offline PCAP/PCAPNG Analyzer QThread.
    Reads packets incrementally via PcapReader to avoid exhausting memory.
    Maintains isolated session state without touching live capture singletons.
    Does NOT require administrator privileges.
    """
    analysis_started = Signal(dict)
    progress_updated = Signal(int, int, float) # (current_packet, total_estimate, percent)
    packet_processed = Signal(dict)
    batch_processed = Signal(list)
    stats_updated = Signal(dict)
    alerts_generated = Signal(list)
    analysis_completed = Signal(dict)
    analysis_error = Signal(str)

    def __init__(self, file_path: str, speed_multiplier: float = 0.0):
        super().__init__()
        self.file_path = file_path
        # 0.0 = Instant (as fast as possible), 1.0 = 1x real-time replay, 5.0 = 5x speed
        self.speed_multiplier = speed_multiplier
        
        self.is_running = True
        self.is_paused = False
        
        # Dedicated isolated aggregators
        self.stats = OfflineStatsAggregator()
        self.anomaly_detector = AnomalyDetector()
        
        self.parsed_packets: List[Dict[str, Any]] = []
        self.isolated_alerts: List[Dict[str, Any]] = []
        self.isolated_flows: Dict[tuple, dict] = {}
        self.dns_queries: List[Dict[str, Any]] = []

    def pause(self):
        self.is_paused = True

    def resume(self):
        self.is_paused = False

    def cancel(self):
        self.is_running = False

    def set_speed(self, speed: float):
        self.speed_multiplier = max(0.0, speed)

    def run(self):
        if not os.path.exists(self.file_path):
            self.analysis_error.emit(f"File not found: {self.file_path}")
            return

        file_size = os.path.getsize(self.file_path)
        file_name = os.path.basename(self.file_path)

        metadata = {
            "file_name": file_name,
            "file_path": self.file_path,
            "file_size": file_size,
            "file_size_formatted": f"{file_size / (1024 * 1024):.2f} MB",
            "start_time": time.time(),
            "first_packet_time": 0.0,
            "last_packet_time": 0.0,
            "total_packets": 0,
            "protocol_counts": {}
        }
        self.analysis_started.emit(metadata)

        # Estimate packet count based on typical average packet size ~500 bytes
        estimated_total_pkts = max(100, int(file_size / 500))

        pkt_count = 0
        batch_size = 50
        current_batch = []
        last_progress_emit = time.time()
        last_stats_emit = time.time()
        prev_pkt_ts = None

        first_ts = None
        last_ts = None

        reader = None
        try:
            reader = PcapReader(self.file_path)
            for raw_pkt in reader:
                if not self.is_running:
                    break

                while self.is_paused and self.is_running:
                    time.sleep(0.1)

                pkt_count += 1
                pkt_time = float(getattr(raw_pkt, 'time', time.time()))

                if first_ts is None:
                    first_ts = pkt_time
                last_ts = pkt_time

                # Optional replay pacing if speed_multiplier > 0
                if self.speed_multiplier > 0.0 and prev_pkt_ts is not None:
                    delta_sim = pkt_time - prev_pkt_ts
                    if 0 < delta_sim < 5.0: # Cap at 5s to avoid huge pauses
                        sleep_time = delta_sim / self.speed_multiplier
                        time.sleep(min(0.2, sleep_time))
                prev_pkt_ts = pkt_time

                # Parse packet
                parsed = parse_packet(raw_pkt)
                if parsed:
                    parsed["packet_num"] = pkt_count
                    current_batch.append(parsed)
                    self.stats.add_packet(parsed)

                    # Track isolated flow
                    src = parsed.get("src_ip", "")
                    dst = parsed.get("dst_ip", "")
                    sport = parsed.get("src_port") or 0
                    dport = parsed.get("dst_port") or 0
                    proto = parsed.get("protocol", "OTHER")

                    if src and dst:
                        ep1 = (src, sport)
                        ep2 = (dst, dport)
                        flow_key = (ep1, ep2, proto) if ep1 <= ep2 else (ep2, ep1, proto)
                        if flow_key not in self.isolated_flows:
                            self.isolated_flows[flow_key] = {
                                "flow_id": f"OFFLINE-FLOW-{len(self.isolated_flows) + 1:05d}",
                                "src_ip": src,
                                "dst_ip": dst,
                                "src_port": sport,
                                "dst_port": dport,
                                "protocol": proto,
                                "first_seen": pkt_time,
                                "last_seen": pkt_time,
                                "packets": 0,
                                "total_bytes": 0
                            }
                        f = self.isolated_flows[flow_key]
                        f["last_seen"] = pkt_time
                        f["packets"] += 1
                        f["total_bytes"] += parsed.get("size", 0)

                    # Track DNS queries if visible
                    if dport == 53 or sport == 53:
                        if raw_pkt.haslayer('DNS') and raw_pkt.haslayer('DNSQR'):
                            try:
                                qname = raw_pkt['DNSQR'].qname.decode('utf-8', errors='ignore').rstrip('.')
                                self.dns_queries.append({
                                    "timestamp": pkt_time,
                                    "query": qname,
                                    "client_ip": src
                                })
                            except Exception:
                                pass

                # Emit batch every batch_size or 150ms
                now = time.time()
                if len(current_batch) >= batch_size or (now - last_progress_emit) >= 0.15:
                    self.batch_processed.emit(list(current_batch))
                    current_batch.clear()

                    # Progress calculation
                    pct = min(99.0, (pkt_count / estimated_total_pkts) * 100.0) if estimated_total_pkts else 50.0
                    self.progress_updated.emit(pkt_count, estimated_total_pkts, pct)
                    last_progress_emit = now

                # Emit stats snapshot
                if (now - last_stats_emit) >= 1.0:
                    current_stats = self.stats.get_and_reset_stats()
                    self.stats_updated.emit(current_stats)
                    # Check for anomalies
                    alerts = self.anomaly_detector.process_stats(current_stats)
                    if alerts:
                        self.isolated_alerts.extend(alerts)
                        self.alerts_generated.emit(alerts)
                    last_stats_emit = now

            # Flush remaining batch
            if current_batch:
                self.batch_processed.emit(list(current_batch))
                current_batch.clear()

            # Final stats & completion
            final_stats = self.stats.get_and_reset_stats()
            self.stats_updated.emit(final_stats)

            duration_sec = (last_ts - first_ts) if (first_ts and last_ts) else 0.0
            summary = {
                "file_name": file_name,
                "file_size": file_size,
                "total_packets": pkt_count,
                "capture_duration_seconds": round(duration_sec, 2),
                "first_packet_time": first_ts or 0.0,
                "last_packet_time": last_ts or 0.0,
                "protocol_counts": dict(self.stats.cumulative_protocols),
                "total_bytes": self.stats.total_bytes,
                "unique_flows_count": len(self.isolated_flows),
                "dns_queries_count": len(self.dns_queries),
                "alerts_count": len(self.isolated_alerts)
            }
            self.progress_updated.emit(pkt_count, pkt_count, 100.0)
            self.analysis_completed.emit(summary)
            logger.info(f"Offline PCAP analysis completed for {file_name}: {pkt_count} packets processed.")

        except Exception as e:
            logger.error(f"Error parsing PCAP file {self.file_path}: {e}")
            self.analysis_error.emit(f"Failed to parse PCAP file: {str(e)}")
        finally:
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass
            self.is_running = False
