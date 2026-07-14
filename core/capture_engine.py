import time
from typing import Dict, Any, List
from PySide6.QtCore import QThread, Signal
from scapy.all import sniff, conf

from core.packet_parser import parse_packet
from core.stats_aggregator import StatsAggregator
from core.anomaly_detector import AnomalyDetector
from utils.logger import logger

class CaptureEngine(QThread):
    # Signals to communicate with the GUI
    packet_captured = Signal(dict)
    stats_updated = Signal(dict)
    alerts_generated = Signal(list)
    capture_error = Signal(str)
    capture_stopped = Signal()

    def __init__(self, interface: str = None, bpf_filter: str = ""):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        
        self.is_running = False
        self.stats_aggregator = StatsAggregator()
        self.anomaly_detector = AnomalyDetector()
        
        self.last_stats_emit = time.time()
        self.stats_interval = 1.0 # Emit stats every second

    def run(self):
        self.is_running = True
        logger.info(f"Starting capture on interface: {self.interface} with filter: '{self.bpf_filter}'")
        
        try:
            # We use a custom stop_filter to cleanly exit the sniff loop
            sniff(
                iface=self.interface if self.interface != "Any" else None,
                filter=self.bpf_filter,
                prn=self.process_packet,
                stop_filter=lambda p: not self.is_running,
                store=False # Don't keep packets in memory (prevents OOM)
            )
        except PermissionError:
            msg = "Permission denied. Please run the application with Administrator/root privileges."
            logger.error(msg)
            self.capture_error.emit(msg)
        except Exception as e:
            msg = f"Capture error: {str(e)}"
            logger.error(msg)
            self.capture_error.emit(msg)
        finally:
            self.is_running = False
            self.capture_stopped.emit()
            logger.info("Capture stopped.")

    def process_packet(self, raw_packet):
        if not self.is_running:
            return

        # Parse the packet
        parsed = parse_packet(raw_packet)
        if parsed:
            # Emit raw parsed packet for the UI table
            self.packet_captured.emit(parsed)
            
            # Update stats
            self.stats_aggregator.add_packet(parsed)

        # Check if we should emit stats (once per second)
        now = time.time()
        if now - self.last_stats_emit >= self.stats_interval:
            stats = self.stats_aggregator.get_and_reset_stats()
            self.stats_updated.emit(stats)
            
            # Pass stats to anomaly detector
            alerts = self.anomaly_detector.process_stats(stats)
            if alerts:
                self.alerts_generated.emit(alerts)
                
            self.last_stats_emit = now

    def stop(self):
        logger.info("Stop capture requested.")
        self.is_running = False
        self.wait() # Wait for thread to finish safely
