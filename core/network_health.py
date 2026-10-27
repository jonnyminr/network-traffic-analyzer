import time
import socket
import subprocess
import sys
import re
from typing import Dict, Any, List, Optional
from PySide6.QtCore import QThread, Signal
from scapy.all import conf
from utils.logger import logger
from core.incident_db import IncidentDatabase


def get_default_gateway_and_iface() -> Dict[str, str]:
    """Retrieves default gateway IP, local IP, and interface name."""
    info = {
        "gateway_ip": "Unknown",
        "local_ip": "127.0.0.1",
        "iface_name": "Unknown",
        "mac_address": "Unknown"
    }

    # 1. Try Scapy's route table
    try:
        route = conf.route.route("0.0.0.0")
        if route and len(route) >= 3:
            gw = route[2]
            if gw and gw != "0.0.0.0":
                info["gateway_ip"] = str(gw)
            if hasattr(route[0], 'ip') and route[0].ip:
                info["local_ip"] = str(route[0].ip)
            if hasattr(route[0], 'name'):
                info["iface_name"] = str(route[0].name)
            if hasattr(route[0], 'mac'):
                info["mac_address"] = str(route[0].mac)
    except Exception as e:
        logger.debug(f"Scapy route lookup error: {e}")

    # 2. Windows fallback using netsh / ipconfig / socket connect
    if info["gateway_ip"] == "Unknown" and sys.platform == 'win32':
        try:
            output = subprocess.check_output("ipconfig", text=True, stderr=subprocess.DEVNULL)
            gw_matches = re.findall(r"Default Gateway[ .]*: ([\d\.]+)", output)
            if gw_matches:
                for gw in gw_matches:
                    if gw and gw != "0.0.0.0":
                        info["gateway_ip"] = gw
                        break
            ip_matches = re.findall(r"IPv4 Address[ .]*: ([\d\.]+)", output)
            if ip_matches:
                info["local_ip"] = ip_matches[0]
        except Exception:
            pass

    # 3. Fallback for local IP via dummy UDP connection
    if info["local_ip"] == "127.0.0.1":
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info["local_ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    return info


class NetworkHealthTester(QThread):
    """
    Background worker thread performing non-disruptive, active network diagnostics:
    1. Local network interface validation
    2. Default gateway reachability and RTT
    3. DNS resolution and lookup latency (target configurable)
    4. Multi-probe internet connectivity and packet loss measurement
    5. Evidence-based health conclusions
    """
    test_started = Signal()
    test_progress = Signal(str, int) # (step_description, percentage)
    test_completed = Signal(dict)
    test_error = Signal(str)

    def __init__(self, target_dns: str = "google.com", custom_host: str = ""):
        super().__init__()
        self.target_dns = target_dns.strip() if target_dns else "google.com"
        self.custom_host = custom_host.strip()
        self.is_running = True

    def run(self):
        self.test_started.emit()
        logger.info(f"Starting Network Health diagnostic check (DNS Target: {self.target_dns})")
        
        results: Dict[str, Any] = {
            "timestamp": time.time(),
            "status": "Healthy",
            "summary": "Diagnostics in progress...",
            "latency_ms": 0.0,
            "packet_loss_pct": 0.0,
            "dns_status": "Unknown",
            "dns_latency_ms": 0.0,
            "dns_resolved_ip": "",
            "gateway_status": "Unknown",
            "gateway_latency_ms": 0.0,
            "interface_name": "",
            "local_ip": "",
            "gateway_ip": "",
            "details": {}
        }

        try:
            # -------------------------------------------------------------
            # STEP 1: Interface Information & Status
            # -------------------------------------------------------------
            self.test_progress.emit("Inspecting network interface...", 15)
            iface_info = get_default_gateway_and_iface()
            results["interface_name"] = iface_info["iface_name"]
            results["local_ip"] = iface_info["local_ip"]
            results["gateway_ip"] = iface_info["gateway_ip"]
            results["details"]["mac_address"] = iface_info["mac_address"]

            if results["local_ip"] in ("127.0.0.1", "", "0.0.0.0"):
                results["status"] = "Disconnected"
                results["summary"] = "No active network interface with a valid local IP address detected."
                self._finalize(results)
                return

            # -------------------------------------------------------------
            # STEP 2: Gateway Reachability Test
            # -------------------------------------------------------------
            self.test_progress.emit("Testing default gateway reachability...", 35)
            gw_ip = results["gateway_ip"]
            gw_reachable = False
            gw_latency = 0.0

            if gw_ip and gw_ip != "Unknown":
                gw_reachable, gw_latency = self._probe_host(gw_ip, port=53, fallback_ping=True)
                if gw_reachable:
                    results["gateway_status"] = "Reachable"
                    results["gateway_latency_ms"] = gw_latency
                else:
                    results["gateway_status"] = "Unreachable"
            else:
                results["gateway_status"] = "Not Configured"

            # -------------------------------------------------------------
            # STEP 3: DNS Resolution Test
            # -------------------------------------------------------------
            self.test_progress.emit(f"Testing DNS resolution for {self.target_dns}...", 60)
            dns_start = time.time()
            dns_ok = False
            dns_error_msg = ""
            try:
                # Perform DNS resolve
                ip_addr = socket.gethostbyname(self.target_dns)
                dns_latency = (time.time() - dns_start) * 1000.0
                dns_ok = True
                results["dns_status"] = "Healthy" if dns_latency < 250.0 else "Slow"
                results["dns_latency_ms"] = round(dns_latency, 1)
                results["dns_resolved_ip"] = ip_addr
            except socket.gaierror as e:
                dns_ok = False
                dns_error_msg = str(e)
                results["dns_status"] = "Failing"
            except Exception as e:
                dns_ok = False
                dns_error_msg = str(e)
                results["dns_status"] = "Failing"

            results["details"]["dns_error"] = dns_error_msg

            # -------------------------------------------------------------
            # STEP 4: Internet Latency & Packet Loss Multi-Probe
            # -------------------------------------------------------------
            self.test_progress.emit("Measuring internet latency and packet loss...", 85)
            # Use reliable, high-availability public DNS Anycast endpoints for safe connectivity test
            probe_targets = [("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53)]
            successful_latencies = []
            total_probes = 6

            for i in range(total_probes):
                target_ip, port = probe_targets[i % len(probe_targets)]
                success, rtt = self._socket_ping(target_ip, port, timeout_sec=1.2)
                if success:
                    successful_latencies.append(rtt)
                time.sleep(0.08)

            lost_probes = total_probes - len(successful_latencies)
            loss_pct = round((lost_probes / total_probes) * 100.0, 1)
            avg_latency = round(sum(successful_latencies) / len(successful_latencies), 1) if successful_latencies else 0.0

            results["packet_loss_pct"] = loss_pct
            results["latency_ms"] = avg_latency
            results["details"]["successful_probes"] = len(successful_latencies)
            results["details"]["total_probes"] = total_probes

            # -------------------------------------------------------------
            # STEP 5: Evidence-Based Health Conclusion
            # -------------------------------------------------------------
            self.test_progress.emit("Analyzing diagnostic evidence...", 95)
            
            if len(successful_latencies) == 0 and not dns_ok and results["gateway_status"] == "Unreachable":
                results["status"] = "Disconnected"
                results["summary"] = "Local network connection is disconnected. Default gateway is unreachable."
            elif len(successful_latencies) == 0 and not dns_ok and results["gateway_status"] == "Reachable":
                results["status"] = "Disconnected"
                results["summary"] = "Connected to local router/gateway, but Internet access is unavailable."
            elif not dns_ok and len(successful_latencies) > 0:
                results["status"] = "Degraded"
                results["summary"] = "DNS resolution is failing. Check your DNS configuration or network connection."
            elif loss_pct >= 40.0:
                results["status"] = "Degraded"
                results["summary"] = f"High packet loss detected ({loss_pct}%). Your connection is experiencing significant disruption."
            elif avg_latency >= 300.0:
                results["status"] = "Degraded"
                results["summary"] = f"Internet connection active but experiencing high latency ({avg_latency} ms)."
            elif results["dns_status"] == "Slow":
                results["status"] = "Degraded"
                results["summary"] = f"DNS resolution is slow ({results['dns_latency_ms']} ms). Web browsing responsiveness may be delayed."
            else:
                results["status"] = "Healthy"
                results["summary"] = "Your internet connection appears healthy."

            self._finalize(results)

        except Exception as e:
            logger.error(f"Health test failed: {e}")
            self.test_error.emit(f"Health diagnostic error: {str(e)}")

    def _socket_ping(self, host: str, port: int = 53, timeout_sec: float = 1.0) -> (bool, float):
        """Measures TCP socket handshake time to an endpoint."""
        start = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_sec)
            s.connect((host, port))
            s.close()
            rtt = (time.time() - start) * 1000.0
            return True, rtt
        except Exception:
            return False, 0.0

    def _probe_host(self, host: str, port: int = 53, fallback_ping: bool = True) -> (bool, float):
        # 1. Quick TCP socket probe
        ok, rtt = self._socket_ping(host, port, timeout_sec=0.8)
        if ok:
            return True, rtt

        # 2. Ping probe via OS ping command (1 echo probe, 1000ms timeout)
        if fallback_ping:
            start = time.time()
            try:
                cmd = ["ping", "-n", "1", "-w", "1000", host] if sys.platform == 'win32' else ["ping", "-c", "1", "-W", "1", host]
                res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
                if res.returncode == 0:
                    rtt = (time.time() - start) * 1000.0
                    return True, round(rtt, 1)
            except Exception:
                pass

        return False, 0.0

    def _finalize(self, results: Dict[str, Any]):
        # Save to SQLite history
        IncidentDatabase().save_health_check(results)
        self.test_progress.emit("Complete", 100)
        self.test_completed.emit(results)
