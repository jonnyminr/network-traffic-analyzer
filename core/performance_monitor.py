import time
import os
import psutil
from typing import Dict, Any

class PerformanceMonitor:
    """
    Measures and tracks real runtime performance metrics of the Analyzer:
    - Process CPU % and System CPU %
    - Resident Set Size (RSS) Memory usage in MB
    - Packets processed per second
    - Queue backlog and queue overflow drops
    - Processing latency (elapsed time from arrival to parsing)
    - GUI frame-rate (measured FPS)
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(PerformanceMonitor, cls).__new__(cls)
            cls._instance._init_monitor()
        return cls._instance

    def _init_monitor(self):
        self.process = psutil.Process(os.getpid())
        # Prime cpu_percent
        try:
            self.process.cpu_percent(interval=None)
        except Exception:
            pass

        self.packets_processed_count = 0
        self.last_packet_count_snapshot = 0
        self.last_rate_calc_time = time.time()
        self.packets_per_sec = 0.0

        self.queue_backlog = 0
        self.queue_drops = 0
        self.processing_latency_ms = 0.0

        # Frame rate tracking
        self.gui_frame_times = []
        self.gui_fps = 0.0

    def record_packet_processed(self, latency_ms: float = 0.0):
        self.packets_processed_count += 1
        if latency_ms > 0:
            # Exponential rolling average of processing latency
            if self.processing_latency_ms == 0.0:
                self.processing_latency_ms = latency_ms
            else:
                self.processing_latency_ms = 0.9 * self.processing_latency_ms + 0.1 * latency_ms

    def record_queue_drop(self):
        self.queue_drops += 1

    def update_queue_status(self, backlog_size: int):
        self.queue_backlog = backlog_size

    def record_gui_frame(self):
        now = time.time()
        self.gui_frame_times.append(now)
        # Keep timestamps within the last 1.0 second
        cutoff = now - 1.0
        while self.gui_frame_times and self.gui_frame_times[0] < cutoff:
            self.gui_frame_times.pop(0)
        self.gui_fps = float(len(self.gui_frame_times))

    def get_metrics(self) -> Dict[str, Any]:
        now = time.time()
        dt = now - self.last_rate_calc_time
        if dt >= 0.5:
            delta_pkts = self.packets_processed_count - self.last_packet_count_snapshot
            self.packets_per_sec = max(0.0, delta_pkts / dt)
            self.last_packet_count_snapshot = self.packets_processed_count
            self.last_rate_calc_time = now

        # Memory usage
        try:
            mem_info = self.process.memory_info()
            mem_mb = mem_info.rss / (1024.0 * 1024.0)
        except Exception:
            mem_mb = 0.0

        # CPU usage
        try:
            cpu_pct = self.process.cpu_percent(interval=None)
        except Exception:
            cpu_pct = 0.0

        return {
            "timestamp": now,
            "cpu_percent": round(cpu_pct, 1),
            "memory_mb": round(mem_mb, 1),
            "packets_per_sec": round(self.packets_per_sec, 1),
            "total_packets_processed": self.packets_processed_count,
            "queue_backlog": self.queue_backlog,
            "queue_drops": self.queue_drops,
            "processing_latency_ms": round(self.processing_latency_ms, 2),
            "gui_fps": round(self.gui_fps, 1),
            "backend_drops_available": False,
            "backend_drop_note": "Scapy AsyncSniffer on Windows relies on Npcap/WinPcap kernel buffer. "
                                 "Internal queue drops are accurately tracked above. Kernel-level buffer drops "
                                 "are handled directly by the Npcap driver."
        }

    def reset(self):
        self.packets_processed_count = 0
        self.last_packet_count_snapshot = 0
        self.last_rate_calc_time = time.time()
        self.packets_per_sec = 0.0
        self.queue_backlog = 0
        self.queue_drops = 0
        self.processing_latency_ms = 0.0
        self.gui_frame_times.clear()
        self.gui_fps = 0.0
