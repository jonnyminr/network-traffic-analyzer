import os
import sys
import time
import json
import unittest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from core.incident_db import IncidentDatabase
from core.threat_intelligence import classify_ip_address, ThreatIntelManager
from core.connection_tracker import ConnectionTracker
from core.dns_monitor import DNSMonitor, calculate_entropy, parse_tls_sni
from core.anomaly_detector import AnomalyDetector, RollingBaseline, calculate_mad
from core.alert_manager import AlertManager
from core.incident_manager import IncidentManager


class TestAdvancedCybersecurityUpgrade(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = IncidentDatabase("logs/test_analyzer.db")

    def test_feature_1_alert_manager_and_deduplication(self):
        """Verify Alert creation, deduplication, grouping, and persistence."""
        mgr = AlertManager()
        mgr.set_cooldown_window(60.0)

        raw_alert = {
            "category": "Bandwidth Spike",
            "title": "Unusual Bandwidth Spike",
            "detection_method": "Z-Score",
            "src_ip": "192.168.1.50",
            "dst_ip": "104.244.42.1",
            "anomaly_score": 4.5,
            "current_rate": "45.2 KB/s",
            "baseline_rate": "3.1 KB/s",
            "explanation": "Traffic surge observed.",
            "recommended_action": "Check connections."
        }

        # First alert emission
        alert_id_1 = mgr.process_raw_alert(raw_alert)
        self.assertIsNotNone(alert_id_1)
        alert_1 = mgr.get_alert_by_id(alert_id_1)
        self.assertEqual(alert_1["occurrences"], 1)
        self.assertEqual(alert_1["severity"], "Medium")

        # Second alert within cooldown window -> should deduplicate and increment occurrences
        alert_id_2 = mgr.process_raw_alert(raw_alert)
        self.assertEqual(alert_id_1, alert_id_2, "Should deduplicate to same alert ID")
        alert_updated = mgr.get_alert_by_id(alert_id_1)
        self.assertEqual(alert_updated["occurrences"], 2)

        # Status update workflow
        success = mgr.update_alert_status(alert_id_1, "Investigating", "Analyst reviewing")
        self.assertTrue(success)
        self.assertEqual(mgr.get_alert_by_id(alert_id_1)["status"], "Investigating")

        # Persistence check: verify record exists in DB
        occurrences = self.db.get_alert_occurrences(alert_id_1)
        self.assertGreaterEqual(len(occurrences), 2)

    def test_feature_2_connection_tracker(self):
        """Verify bi-directional flow tracking, TCP state inference, and UDP timeout."""
        tracker = ConnectionTracker()
        tracker.clear()

        # Inbound packet: External -> Local
        p1 = {
            "src_ip": "142.250.190.46", "dst_ip": "192.168.1.10",
            "src_port": 443, "dst_port": 51234, "protocol": "TCP",
            "length": 1500, "flags": "SA", "timestamp": time.time()
        }
        # Outbound packet: Local -> External
        p2 = {
            "src_ip": "192.168.1.10", "dst_ip": "142.250.190.46",
            "src_port": 51234, "dst_port": 443, "protocol": "TCP",
            "length": 80, "flags": "A", "timestamp": time.time() + 0.05
        }

        flow1 = tracker.process_packet(p1)
        flow2 = tracker.process_packet(p2)

        self.assertIsNotNone(flow1)
        self.assertIsNotNone(flow2)
        self.assertEqual(flow1.flow_id, flow2.flow_id, "Both directional packets must map to the same flow")
        self.assertEqual(flow1.total_packets, 2)
        self.assertEqual(flow1.total_bytes, 1580)

        # Verify state
        snapshot = tracker.get_all_flows_snapshot()
        self.assertEqual(len(snapshot), 1)
        self.assertTrue(snapshot[0]["dst_is_public"] or snapshot[0]["src_is_public"])

        # Test CSV export
        export_path = "logs/test_flows.csv"
        exp_success = tracker.export_to_csv(export_path)
        self.assertTrue(exp_success)
        self.assertTrue(os.path.exists(export_path))
        if os.path.exists(export_path):
            os.remove(export_path)

    def test_feature_3_smarter_anomaly_detection(self):
        """Verify rolling statistical baseline, Z-Score, robust MAD, and IsolationForest."""
        baseline = RollingBaseline(window_size=30)
        # Feed stable values
        for _ in range(15):
            baseline.update(100.0)

        stats = baseline.get_stats()
        self.assertAlmostEqual(stats["mean"], 100.0, delta=1.0)
        self.assertAlmostEqual(stats["std"], 0.0, delta=0.01)

        # Z-score test with zero variance handling
        z_normal, method = baseline.compute_z_score(100.0)
        self.assertEqual(z_normal, 0.0)

        # Spike detection
        z_spike, _ = baseline.compute_z_score(500.0)
        self.assertGreater(z_spike, 3.0)

        # Full AnomalyDetector test
        detector = AnomalyDetector()
        detector.set_thresholds(z_score=3.0, port_scan=15, warmup=5)

        # Warm-up phase should not alert
        alerts_warmup = detector.process_stats({
            "timestamp": time.time(),
            "bytes_per_sec": 1000.0,
            "packets_per_sec": 10.0,
            "port_scan_candidates": {}
        })
        self.assertEqual(len(alerts_warmup), 0)

        # Port scan alert
        alerts_scan = detector.process_stats({
            "timestamp": time.time(),
            "bytes_per_sec": 1000.0,
            "packets_per_sec": 10.0,
            "port_scan_candidates": {"192.168.1.99": 35}
        })
        self.assertGreaterEqual(len(alerts_scan), 1)
        self.assertEqual(alerts_scan[0]["category"], "Port Scanning")

    def test_feature_4_threat_intelligence_privacy(self):
        """Verify privacy guarantees for RFC1918 addresses and modular lookups."""
        c_priv = classify_ip_address("10.0.0.5")
        self.assertFalse(c_priv["is_public"])
        self.assertIn("Private", c_priv["scope"])

        c_loop = classify_ip_address("127.0.0.1")
        self.assertFalse(c_loop["is_public"])

        c_pub = classify_ip_address("8.8.8.8")
        self.assertTrue(c_pub["is_public"])

        manager = ThreatIntelManager()
        # Private lookup must be intercepted by Privacy Guard
        priv_res = manager.lookup_ip("192.168.1.1")
        self.assertIn("Privacy Guard", priv_res["providers"])
        self.assertEqual(priv_res["summary"]["country"], "Local / Private")

    def test_feature_5_dns_and_encrypted_traffic(self):
        """Verify DNS transaction parsing, Shannon entropy calculation, and TLS SNI."""
        monitor = DNSMonitor()
        monitor.clear()

        # Shannon entropy test
        low_ent = calculate_entropy("google")
        high_ent = calculate_entropy("x8q921mv9a710bkz")
        self.assertGreater(high_ent, low_ent)
        self.assertGreater(high_ent, 3.5)

        # Synthetic Scapy DNS Query
        scapy_dns_query = IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=43210, dport=53)/DNS(
            id=0x1234, qr=0, qd=DNSQR(qname="test.example.com")
        )
        meta_query = {
            "timestamp": time.time(), "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8", "src_port": 43210, "dst_port": 53
        }
        res_q = monitor.process_packet(meta_query, scapy_dns_query)
        self.assertIsNotNone(res_q)
        self.assertEqual(res_q["qname"], "test.example.com")
        self.assertEqual(res_q["rcode"], "Pending")

        # Synthetic Scapy DNS Response
        scapy_dns_resp = IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=43210)/DNS(
            id=0x1234, qr=1, rcode=0, qd=DNSQR(qname="test.example.com"),
            an=DNSRR(rrname="test.example.com", rdata="93.184.216.34")
        )
        meta_resp = {
            "timestamp": time.time() + 0.02, "src_ip": "8.8.8.8",
            "dst_ip": "192.168.1.100", "src_port": 53, "dst_port": 43210
        }
        res_r = monitor.process_packet(meta_resp, scapy_dns_resp)
        self.assertIsNotNone(res_r)
        self.assertEqual(res_r["rcode"], "NOERROR")
        self.assertIn("93.184.216.34", res_r["answers"])
        self.assertGreater(res_r["duration_ms"], 0)

    def test_feature_6_investigation_mode(self):
        """Verify Investigation creation, correlation, timeline, and report generation."""
        inv_mgr = IncidentManager()

        test_alert = {
            "alert_id": "ALT-TEST-001",
            "title": "Suspected Port Scan Activity",
            "severity": "High",
            "category": "Port Scanning",
            "detection_method": "Rule-Based",
            "src_ip": "192.168.1.200",
            "dst_ip": "192.168.1.1",
            "current_rate": "42 ports probed",
            "baseline_rate": "<10 ports",
            "anomaly_score": 42.0,
            "explanation": "Targeted port scan from host 192.168.1.200.",
            "first_seen": time.time()
        }

        inv = inv_mgr.create_investigation(
            title="Security Investigation - Host 192.168.1.200",
            initial_alert=test_alert
        )
        inv_id = inv["investigation_id"]
        self.assertTrue(inv_id.startswith("INV-"))

        # Add analyst note
        inv_mgr.add_analyst_note(inv_id, "Host confirmed to be internal security scanner.")

        # Update status
        inv_mgr.update_status(inv_id, "Resolved", "Authorized vulnerability scan confirmed.")

        updated_inv = inv_mgr.get_investigation(inv_id)
        self.assertEqual(updated_inv["status"], "Resolved")
        self.assertIn("internal security scanner", updated_inv["analyst_notes"])

        # Timeline verification
        timeline = updated_inv["timeline"]
        self.assertGreaterEqual(len(timeline), 3)

        # Generate HTML report
        html_report = inv_mgr.generate_html_report(inv_id)
        self.assertIn("Cybersecurity Incident Investigation Report", html_report)
        self.assertIn(inv_id, html_report)
        self.assertIn("Authorized vulnerability scan", html_report)


if __name__ == "__main__":
    unittest.main()
