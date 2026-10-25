import time
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
from utils.interfaces import resolve_scapy_interface
from utils.logger import logger

class CaptureEngine(QThread):
    # Signals to communicate with the GUI
    packet_captured = Signal(dict)
    stats_updated = Signal(dict)
    alerts_generated = Signal(list)
    capture_error = Signal(str)
    capture_stopped = Signal()

    def __init__(self, interface: Any = None, bpf_filter: str = ""):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter.strip() if bpf_filter else ""
        
        self.is_running = False
        self.stats_aggregator = StatsAggregator()
        self.anomaly_detector = AnomalyDetector()
        
        # Keep a rolling buffer of raw packets for PCAP export (up to 2,000 recent packets)
        self.raw_packet_buffer = collections.deque(maxlen=2000)
        
        self.last_stats_emit = time.time()
        self.stats_interval = 1.0 # Emit stats every second

    def run(self):
        self.is_running = True
        self.stats_aggregator.reset_all()
        
        # Resolve the interface using robust platform resolution
        resolved_iface = resolve_scapy_interface(self.interface)
        iface_name = getattr(resolved_iface, 'name', str(resolved_iface))
        logger.info(f"Starting capture on interface: {iface_name} (Filter: '{self.bpf_filter}')")
        
        sniffer = None
        try:
            sniffer = AsyncSniffer(
                iface=resolved_iface,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self.process_packet,
                store=False, # Don't accumulate all packets unbounded in memory
                promisc=False # Promiscuous mode often fails on Windows Wi-Fi
            )
            sniffer.start()
            
            while self.is_running:
                # Sleep in short slices for instantaneous stop responsiveness
                sleep_steps = max(1, int(self.stats_interval / 0.1))
                for _ in range(sleep_steps):
                    if not self.is_running:
                        break
                    time.sleep(0.1)
                
                if self.is_running:
                    self._emit_stats()

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
            logger.info("Capture stopped.")

    def process_packet(self, raw_packet):
        if not self.is_running:
            return

        # Store raw packet for PCAP export
        self.raw_packet_buffer.append(raw_packet)

        # Parse the packet
        parsed = parse_packet(raw_packet)
        if parsed:
            # Emit raw parsed packet for UI table
            self.packet_captured.emit(parsed)
            # Update stats
            self.stats_aggregator.add_packet(parsed)
            # Update connection flow tracker
            try:
                ConnectionTracker().process_packet(parsed, raw_packet)
            except Exception:
                pass
            # Update DNS monitor
            try:
                DNSMonitor().process_packet(parsed, raw_packet)
            except Exception:
                pass

    def _emit_stats(self):
        stats = self.stats_aggregator.get_and_reset_stats()
        self.stats_updated.emit(stats)
        
        # Pass stats to anomaly detector
        alerts = self.anomaly_detector.process_stats(stats)
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
        self.wait(2000) # Wait up to 2 seconds for thread to finish safely
