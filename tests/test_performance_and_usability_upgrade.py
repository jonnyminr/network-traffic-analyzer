import os
import time
import tempfile
import unittest
import pytest
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap

from core.capture_profiles import get_profile, PROFILES
from core.performance_monitor import PerformanceMonitor
from core.network_health import get_default_gateway_and_iface, NetworkHealthTester
from core.recommendations_engine import RecommendationsEngine
from core.alert_manager import AlertManager, SecurityAlert
from core.connection_tracker import ConnectionTracker
from core.incident_db import IncidentDatabase
from core.pcap_analyzer import PcapAnalysisWorker
from gui.tooltips_helper import get_tooltip


class TestPerformanceAndUsabilityUpgrade(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = IncidentDatabase()

    @classmethod
    def setup_class(cls):
        cls.db = IncidentDatabase()

    def test_feature_1_capture_profiles_and_performance_monitor(self):
        # 1. Test profiles
        p_light = get_profile("Lightweight")
        assert p_light.name == "Lightweight"
        assert p_light.raw_buffer_size == 500
        assert not p_light.ml_enabled

        p_bal = get_profile("Balanced")
        assert p_bal.name == "Balanced"
        assert p_bal.raw_buffer_size == 2000
        assert p_bal.ml_enabled

        p_deep = get_profile("Deep Analysis")
        assert p_deep.name == "Deep Analysis"
        assert p_deep.raw_buffer_size == 10000

        # 2. Test PerformanceMonitor
        monitor = PerformanceMonitor()
        monitor.reset()
        monitor.record_packet_processed(latency_ms=1.5)
        monitor.record_packet_processed(latency_ms=2.0)
        monitor.record_queue_drop()
        monitor.update_queue_status(backlog_size=42)
        monitor.record_gui_frame()

        metrics = monitor.get_metrics()
        assert metrics["total_packets_processed"] == 2
        assert metrics["queue_drops"] == 1
        assert metrics["queue_backlog"] == 42
        assert metrics["memory_mb"] > 0
        assert "backend_drop_note" in metrics
        assert metrics["backend_drops_available"] is False

    def test_feature_2_network_health_diagnostics(self):
        # 1. Interface and Gateway resolution
        gw_info = get_default_gateway_and_iface()
        assert isinstance(gw_info, dict)
        assert "gateway_ip" in gw_info
        assert "local_ip" in gw_info

        # 2. Diagnostic tester evaluation logic
        tester = NetworkHealthTester(target_dns="google.com")
        
        # Test socket ping helper
        ok, rtt = tester._socket_ping("1.1.1.1", port=53, timeout_sec=1.5)
        # Note: If no internet in test environment, ok will be False, but function should not raise exception
        assert isinstance(ok, bool)
        assert isinstance(rtt, float)

        # 3. Test saving and retrieving health check history
        fake_result = {
            "timestamp": time.time(),
            "status": "Healthy",
            "summary": "Your internet connection appears healthy.",
            "latency_ms": 24.5,
            "packet_loss_pct": 0.0,
            "dns_status": "Healthy",
            "dns_latency_ms": 15.2,
            "gateway_status": "Reachable",
            "interface_name": "Wi-Fi",
            "details": {"test": True}
        }
        saved = self.db.save_health_check(fake_result)
        assert saved is True

        history = self.db.get_health_history(limit=5)
        assert len(history) >= 1
        assert history[0]["status"] in ("Healthy", "Degraded", "Disconnected")

    def test_feature_3_simple_mode_and_tooltips(self):
        # 1. Tooltips
        tip_tcp = get_tooltip("TCP")
        assert "Transmission Control Protocol" in tip_tcp
        tip_z = get_tooltip("Z-score")
        assert "standard deviations" in tip_z
        tip_anom = get_tooltip("Anomaly")
        assert "deviation" in tip_anom.lower()

        # 2. Mode persistence
        self.db.set_setting("ui_mode", "simple")
        assert self.db.get_setting("ui_mode") == "simple"
        self.db.set_setting("ui_mode", "advanced")
        assert self.db.get_setting("ui_mode") == "advanced"

    def test_feature_4_improved_alert_investigation_and_false_positives(self):
        mgr = AlertManager()
        
        # 1. Raise alert
        raw = {
            "category": "Bandwidth Spike",
            "title": "Unusual Bandwidth Surge",
            "detection_method": "Robust MAD Score",
            "src_ip": "192.168.1.105",
            "dst_ip": "142.250.190.46",
            "anomaly_score": 5.2,
            "current_rate": "850 KB/s",
            "baseline_rate": "120 KB/s",
            "explanation": "Sudden volume surge observed.",
            "recommended_action": "Check active flows."
        }
        alert_id = mgr.process_raw_alert(raw)
        assert alert_id.startswith("ALT-")

        # 2. Fetch alert evidence bundle
        evidence = mgr.get_alert_evidence(alert_id)
        assert "alert" in evidence
        assert "time_range" in evidence
        assert evidence["alert"]["alert_id"] == alert_id

        # 3. Mark as false positive with reason
        success = mgr.mark_false_positive(alert_id, reason="Authorized backup routine scheduled at 7 PM")
        assert success is True

        fp_records = self.db.get_false_positives()
        assert len(fp_records) >= 1
        matched = next((f for f in fp_records if f["alert_id"] == alert_id), None)
        assert matched is not None
        assert "Authorized backup" in matched["reason"]

    def test_feature_5_offline_pcap_streaming_analysis(self, tmp_path=None):
        if tmp_path is not None:
            pcap_file = str(tmp_path / "test_capture.pcap")
            self._run_offline_pcap_test(pcap_file)
        else:
            with tempfile.TemporaryDirectory() as td:
                pcap_file = os.path.join(td, "test_capture.pcap")
                self._run_offline_pcap_test(pcap_file)

    def _run_offline_pcap_test(self, pcap_file):
        # 1. Create a synthetic test PCAP file
        packets = []
        now = time.time()
        for i in range(25):
            pkt = Ether() / IP(src=f"192.168.1.{10 + i}", dst="8.8.8.8") / UDP(sport=50000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
            pkt.time = now + (i * 0.1)
            packets.append(pkt)
        wrpcap(pcap_file, packets)

        # 2. Run PcapAnalysisWorker synchronously for testing
        worker = PcapAnalysisWorker(pcap_file, speed_multiplier=0.0)
        
        received_batches = []
        completed_summary = {}

        def on_batch(b):
            received_batches.extend(b)

        def on_completed(s):
            completed_summary.update(s)

        worker.batch_processed.connect(on_batch)
        worker.analysis_completed.connect(on_completed)

        worker.run()

        assert len(received_batches) == 25
        assert completed_summary["total_packets"] == 25
        assert completed_summary["dns_queries_count"] == 25
        assert completed_summary["unique_flows_count"] >= 1
        assert "UDP" in completed_summary["protocol_counts"]

    def test_feature_6_practical_network_monitoring_and_recommendations(self):
        tracker = ConnectionTracker()
        tracker.clear()

        # Simulate flow packet
        pkt = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.55",
            "dst_ip": "93.184.216.34",
            "src_port": 49152,
            "dst_port": 443,
            "protocol": "TCP",
            "length": 1400,
            "flags": "SA"
        }
        tracker.process_packet(pkt)

        # 1. Device and Host Overview
        endpoints = tracker.get_endpoints_overview()
        assert len(endpoints) == 2
        ips = [e["ip"] for e in endpoints]
        assert "192.168.1.55" in ips
        assert "93.184.216.34" in ips

        # 2. Flow expiration
        expired = tracker.expire_inactive_flows(timeout_seconds=0.0)
        assert expired == 1
        assert len(tracker.flows) == 0

        # 3. Recommendations Engine
        fake_stats = {
            "total_bytes": 1000000,
            "bytes_per_sec": 50000.0,
            "top_talkers": [("192.168.1.55", 850000)],
            "outbound_bytes": 800000,
            "inbound_bytes": 50000
        }
        fake_alerts = [{
            "category": "Port Scanning",
            "src_ip": "192.168.1.200"
        }]
        fake_health = {
            "status": "Degraded",
            "packet_loss_pct": 25.0,
            "dns_status": "Failing"
        }

        recs = RecommendationsEngine.generate_recommendations(fake_stats, fake_alerts, fake_health)
        assert len(recs) >= 3
        titles = [r["title"] for r in recs]
        assert any("Dominating" in t for t in titles)
        assert any("Port Probes" in t for t in titles)
        assert any("Loss" in t or "DNS" in t for t in titles)
