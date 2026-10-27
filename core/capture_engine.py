import time
import queue
import collections
from typing import Dict, Any, List, Optional
from PySide6.QtCore import QThread, Signal
from scapy.all import conf, AsyncSniffer

from core.packet_parser import parse_packet
from core.stats_aggregator import StatsAggregator
from core.anomaly_detector import AnomalyDetector
from core.connection_tracker import ConnectionTracker
from core.dns_monitor import DNSMonitor
from core.alert_manager import AlertManager
from core.capture_profiles import get_profile, CaptureProfile
from core.performance_monitor import PerformanceMonitor
from utils.interfaces import resolve_scapy_interface
from utils.logger import logger


class CaptureEngine(QThread):
    """
    High-Performance Asynchronous Packet Capture Engine.
    Decouples raw packet capture (AsyncSniffer) from parsing, aggregations,
    anomaly detection, and GUI signal emissions using a bounded thread-safe queue.
    """
    # Signals to communicate with GUI
    packet_captured = Signal(dict)
    packets_batch_captured = Signal(list)
    stats_updated = Signal(dict)
    alerts_generated = Signal(list)
    capture_error = Signal(str)
    capture_stopped = Signal()

    def __init__(self, interface: Any = None, bpf_filter: str = "", profile_name: str = "Balanced"):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter.strip() if bpf_filter else ""
        self.profile: CaptureProfile = get_profile(profile_name)
        
        self.is_running = False
        self.stats_aggregator = StatsAggregator()
        self.anomaly_detector = AnomalyDetector()
        self.perf_monitor = PerformanceMonitor()
        
        # Bounded packet queue separating capture thread from processing thread
        self.packet_queue = queue.Queue(maxsize=20000)
        
        # Bounded buffer of raw packets for PCAP export (configured per profile)
        self.raw_packet_buffer = collections.deque(maxlen=self.profile.raw_buffer_size)
        
        self.last_stats_emit = time.time()
        self.last_batch_emit = time.time()
        self.stats_interval = self.profile.stats_interval

    def set_profile(self, profile_name: str):
        self.profile = get_profile(profile_name)
        self.stats_interval = self.profile.stats_interval
        # Resize raw packet buffer if needed
        current_pkts = list(self.raw_packet_buffer)
        self.raw_packet_buffer = collections.deque(
            current_pkts[-self.profile.raw_buffer_size:], 
            maxlen=self.profile.raw_buffer_size
        )
        logger.info(f"Capture profile set to '{self.profile.name}' (buffer={self.profile.raw_buffer_size})")

    def run(self):
        self.is_running = True
        self.stats_aggregator.reset_all()
        self.perf_monitor.reset()
        
        # Resolve the interface
        resolved_iface = resolve_scapy_interface(self.interface)
        iface_name = getattr(resolved_iface, 'name', str(resolved_iface))
        logger.info(
            f"Starting capture on interface: {iface_name} "
            f"(Profile: {self.profile.name}, Filter: '{self.bpf_filter}')"
        )
        
        sniffer = None
        try:
            sniffer = AsyncSniffer(
                iface=resolved_iface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._enqueue_packet,
                store=False, # Don't accumulate packets unbounded in Scapy
                promisc=False
            )
            sniffer.start()
            
            # Processing loop runs on this QThread
            pending_batch = []
            self.last_batch_emit = time.time()
            self.last_stats_emit = time.time()

            while self.is_running:
                now = time.time()
                
                # Update queue backlog size
                q_size = self.packet_queue.qsize()
                self.perf_monitor.update_queue_status(q_size)

                # Drain packets from the bounded queue
                drained_count = 0
                max_drain_per_iter = 100 # Batch size
                
                while drained_count < max_drain_per_iter:
                    try:
                        arrival_time, raw_packet = self.packet_queue.get_nowait()
                    except queue.Empty:
                        break
                    
                    drained_count += 1
                    proc_latency_ms = (time.time() - arrival_time) * 1000.0
                    self.perf_monitor.record_packet_processed(proc_latency_ms)

                    # Store in rolling buffer for PCAP export
                    self.raw_packet_buffer.append(raw_packet)

                    # Parse packet
                    parsed = parse_packet(raw_packet)
                    if parsed:
                        pending_batch.append(parsed)
                        self.stats_aggregator.add_packet(parsed)

                        # Deep analysis tracking (skipped in Lightweight profile)
                        if self.profile.deep_inspection:
                            try:
                                ConnectionTracker().process_packet(parsed, raw_packet)
                            except Exception:
                                pass
                            try:
                                DNSMonitor().process_packet(parsed, raw_packet)
                            except Exception:
                                pass

                # Emit batched packets to GUI at controlled interval (e.g. 100ms)
                batch_elapsed = (now - self.last_batch_emit) * 1000.0
                if pending_batch and (batch_elapsed >= self.profile.packet_table_batch_ms or len(pending_batch) >= 100):
                    # Emit batch signal (for optimized listeners)
                    self.packets_batch_captured.emit(list(pending_batch))
                    # Also emit single signal for legacy compatibility
                    for p in pending_batch:
                        self.packet_captured.emit(p)
                    pending_batch.clear()
                    self.last_batch_emit = now

                # Periodic stats aggregation and anomaly detection
                if (now - self.last_stats_emit) >= self.stats_interval:
                    self._emit_stats()
                    self.last_stats_emit = now

                # Small sleep when queue is empty to avoid 100% CPU busy loop
                if drained_count == 0:
                    time.sleep(0.02)

            # Flush remaining batch before stopping
            if pending_batch:
                self.packets_batch_captured.emit(list(pending_batch))
                for p in pending_batch:
                    self.packet_captured.emit(p)
                pending_batch.clear()

        except PermissionError:
            msg = (
                "Permission denied: Packet capture requires Administrator privileges on Windows "
                "(or sudo/root on Linux). Please run the application as Administrator."
            )
            logger.error(msg)
            self.capture_error.emit(msg)
        except RuntimeError as e:
            err_str = str(e)
            if "winpcap" in err_str.lower() or "npcap" in err_str.lower():
                msg = (
                    "Capture error: Npcap / WinPcap is not installed or not accessible.\n\n"
                    "Please install Npcap from https://npcap.com/ and ensure 'WinPcap API-compatible Mode' "
                    "is checked during installation."
                )
            else:
                msg = f"Capture runtime error: {err_str}"
            logger.error(msg)
            self.capture_error.emit(msg)
        except Exception as e:
            err_str = str(e)
            if "can't parse filter" in err_str or "syntax error" in err_str:
                msg = f"BPF Filter Syntax Error: '{self.bpf_filter}' is not a valid filter."
            else:
                msg = f"Capture error: {err_str}"
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
            self.capture_stopped.emit()
            logger.info("Capture stopped cleanly.")

    def _enqueue_packet(self, raw_packet):
        """Called by Scapy's capture thread. Must execute as fast as possible."""
        if not self.is_running:
            return
        try:
            self.packet_queue.put_nowait((time.time(), raw_packet))
        except queue.Full:
            self.perf_monitor.record_queue_drop()

    def process_packet(self, raw_packet):
        """Backward compatibility for direct testing."""
        self._enqueue_packet(raw_packet)

    def _emit_stats(self):
        stats = self.stats_aggregator.get_and_reset_stats()
        self.stats_updated.emit(stats)
        
        # Pass stats to anomaly detector (ML enabled check)
        if self.profile.ml_enabled:
            alerts = self.anomaly_detector.process_stats(stats)
        else:
            # Rule-based only without ML overhead
            alerts = self.anomaly_detector.process_stats_lightweight(stats) if hasattr(self.anomaly_detector, 'process_stats_lightweight') else self.anomaly_detector.process_stats(stats)
            
        if alerts:
            mgr = AlertManager()
            for a in alerts:
                try:
                    mgr.process_raw_alert(a)
                except Exception:
                    pass
            self.alerts_generated.emit(alerts)

    def get_raw_packets(self) -> List[Any]:
        """Returns a snapshot of recently captured raw Scapy packets."""
        return list(self.raw_packet_buffer)

    def stop(self):
        logger.info("Stop capture requested.")
        self.is_running = False
        self.wait(2000)
