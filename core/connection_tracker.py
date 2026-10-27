import time
import threading
import ipaddress
import csv
from typing import Dict, List, Optional, Tuple, Any
from utils.logger import logger
from core.threat_intelligence import classify_ip_address


class NetworkFlow:
    """
    Represents a bidirectional network communication flow between two endpoints.
    Tracks packet counts, bytes sent/received, timestamps, and passive TCP states.
    """
    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, timestamp: float):
        self.flow_id = flow_id
        # Initiator endpoints (first packet seen)
        self.initiator_ip = src_ip
        self.initiator_port = src_port
        self.responder_ip = dst_ip
        self.responder_port = dst_port
        self.protocol = protocol.upper()

        self.first_seen = timestamp
        self.last_seen = timestamp

        self.packets_sent = 0
        self.bytes_sent = 0
        self.packets_recv = 0
        self.bytes_recv = 0

        # TCP tracking flags
        self.syn_seen_init = False
        self.syn_seen_resp = False
        self.fin_seen_init = False
        self.fin_seen_resp = False
        self.rst_seen = False
        self.tcp_state = "ESTABLISHED (Inferred)" if self.protocol == "TCP" else "ACTIVE"

        # Evidence & Attribution
        self.attribution_type = "Passive L4 Flow Inference"
        self.related_alerts = set()
        self.packet_indices = [] # recent packet identifiers or timestamps

        # Classification
        self.src_classification = classify_ip_address(self.initiator_ip)
        self.dst_classification = classify_ip_address(self.responder_ip)

    @property
    def total_packets(self) -> int:
        return self.packets_sent + self.packets_recv

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def update_with_packet(self, pkt: Dict[str, Any], raw_packet=None):
        timestamp = pkt.get("timestamp", time.time())
        length = pkt.get("length", 0)
        flags = str(pkt.get("flags", "")).upper()
        self.last_seen = timestamp

        # Direction detection based on initiator
        is_initiator = (pkt.get("src_ip") == self.initiator_ip and pkt.get("src_port") == self.initiator_port)
        if is_initiator:
            self.packets_sent += 1
            self.bytes_sent += length
        else:
            self.packets_recv += 1
            self.bytes_recv += length

        # Keep bounded list of packet timestamps/summaries (up to 50 per flow)
        if len(self.packet_indices) < 50:
            self.packet_indices.append({
                "timestamp": timestamp,
                "length": length,
                "src_ip": pkt.get("src_ip"),
                "dst_ip": pkt.get("dst_ip"),
                "src_port": pkt.get("src_port"),
                "dst_port": pkt.get("dst_port"),
                "flags": flags,
                "info": pkt.get("info", "")
            })

        # TCP Flag & Passive State Inference
        if self.protocol == "TCP":
            if "R" in flags:
                self.rst_seen = True
                self.tcp_state = "RESET (Closed)"
            elif "F" in flags:
                if is_initiator:
                    self.fin_seen_init = True
                else:
                    self.fin_seen_resp = True

                if self.fin_seen_init and self.fin_seen_resp:
                    self.tcp_state = "CLOSED (Bi-FIN)"
                else:
                    self.tcp_state = "CLOSING (FIN-WAIT)"
            elif "S" in flags:
                if "A" in flags:
                    self.syn_seen_resp = True
                    self.tcp_state = "SYN_RCVD"
                else:
                    self.syn_seen_init = True
                    self.tcp_state = "SYN_SENT"
            elif "A" in flags and not self.fin_seen_init and not self.fin_seen_resp and not self.rst_seen:
                if self.syn_seen_init and self.syn_seen_resp:
                    self.tcp_state = "ESTABLISHED"
                elif self.tcp_state not in ("ESTABLISHED", "SYN_SENT"):
                    self.tcp_state = "ESTABLISHED (Inferred)"

    def check_udp_timeout(self, current_time: float, timeout_seconds: float = 30.0):
        if self.protocol == "UDP":
            if current_time - self.last_seen > timeout_seconds:
                self.tcp_state = "IDLE / EXPIRED"
            else:
                self.tcp_state = "ACTIVE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.initiator_ip,
            "dst_ip": self.responder_ip,
            "src_port": self.initiator_port,
            "dst_port": self.responder_port,
            "protocol": self.protocol,
            "tcp_state": self.tcp_state,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "packets": self.total_packets,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "total_bytes": self.total_bytes,
            "related_alerts_count": len(self.related_alerts),
            "attribution_type": self.attribution_type,
            "src_is_public": self.src_classification.get("is_public", False),
            "dst_is_public": self.dst_classification.get("is_public", False),
            "src_scope": self.src_classification.get("scope", "Unknown"),
            "dst_scope": self.dst_classification.get("scope", "Unknown"),
        }


class ConnectionTracker:
    """
    Aggregates captured packets into bidirectional network flows.
    Provides filtering, sorting, export, and IP connection history.
    """
    _instance = None
    _singleton_lock = threading.Lock()

    def __new__(cls, max_flows: int = 20000, udp_timeout: float = 30.0):
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super(ConnectionTracker, cls).__new__(cls)
                cls._instance._init_tracker(max_flows, udp_timeout)
            return cls._instance

    def _init_tracker(self, max_flows: int, udp_timeout: float):
        self.max_flows = max_flows
        self.udp_timeout = udp_timeout
        self.flows: Dict[Tuple, NetworkFlow] = {}
        self.lock = threading.Lock()
        self.local_ip: Optional[str] = None
        logger.info(f"Initialized ConnectionTracker (capacity={max_flows}, udp_timeout={udp_timeout}s)")

    def set_local_ip(self, ip: str):
        self.local_ip = ip

    def _make_canonical_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple:
        """
        Produces an order-independent flow key so packets in both directions map to the same flow.
        """
        ep1 = (src_ip, src_port or 0)
        ep2 = (dst_ip, dst_port or 0)
        if ep1 <= ep2:
            return (ep1, ep2, proto.upper())
        else:
            return (ep2, ep1, proto.upper())

    def process_packet(self, pkt: Dict[str, Any], raw_packet=None) -> Optional[NetworkFlow]:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        proto = pkt.get("protocol", "OTHER")

        # Skip non-IP traffic
        if not src_ip or not dst_ip or src_ip == "Unknown" or dst_ip == "Unknown":
            return None

        src_port = pkt.get("src_port") or 0
        dst_port = pkt.get("dst_port") or 0
        timestamp = pkt.get("timestamp", time.time())

        key = self._make_canonical_key(src_ip, dst_ip, src_port, dst_port, proto)

        with self.lock:
            if key in self.flows:
                flow = self.flows[key]
                flow.update_with_packet(pkt, raw_packet)
                return flow
            else:
                # Flow cleanup if limit reached
                if len(self.flows) >= self.max_flows:
                    self._prune_oldest_flows(prune_count=1000)

                flow_id = f"FLOW-{len(self.flows) + 1:06d}"
                flow = NetworkFlow(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    timestamp=timestamp
                )
                flow.update_with_packet(pkt, raw_packet)
                self.flows[key] = flow
                return flow

    def _prune_oldest_flows(self, prune_count: int = 1000):
        # Sort by last seen and remove oldest closed/idle flows first
        sorted_keys = sorted(self.flows.keys(), key=lambda k: self.flows[k].last_seen)
        for k in sorted_keys[:prune_count]:
            self.flows.pop(k, None)

    def attach_alert_to_flow(self, alert_id: str, src_ip: str, dst_ip: str, src_port: int = None, dst_port: int = None):
        """Associates a security alert with relevant active flows."""
        with self.lock:
            for flow in self.flows.values():
                match_endpoints = (
                    (flow.initiator_ip == src_ip and flow.responder_ip == dst_ip) or
                    (flow.initiator_ip == dst_ip and flow.responder_ip == src_ip)
                )
                if match_endpoints:
                    if src_port and dst_port:
                        if (flow.initiator_port == src_port and flow.responder_port == dst_port) or \
                           (flow.initiator_port == dst_port and flow.responder_port == src_port):
                            flow.related_alerts.add(alert_id)
                    else:
                        flow.related_alerts.add(alert_id)

    def get_all_flows_snapshot(self) -> List[Dict[str, Any]]:
        """Returns a thread-safe snapshot of all flows formatted for GUI display."""
        now = time.time()
        with self.lock:
            snapshot = []
            for flow in self.flows.values():
                flow.check_udp_timeout(now, self.udp_timeout)
                snapshot.append(flow.to_dict())
            return snapshot

    def get_flow_by_id(self, flow_id: str) -> Optional[NetworkFlow]:
        with self.lock:
            for flow in self.flows.values():
                if flow.flow_id == flow_id:
                    return flow
        return None

    def get_flows_for_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Returns all flows involving a specific IP address."""
        now = time.time()
        with self.lock:
            matches = []
            for flow in self.flows.values():
                if flow.initiator_ip == ip or flow.responder_ip == ip:
                    flow.check_udp_timeout(now, self.udp_timeout)
                    matches.append(flow.to_dict())
            return sorted(matches, key=lambda f: f["last_seen"], reverse=True)

    def expire_inactive_flows(self, timeout_seconds: float = 300.0) -> int:
        """Prunes flows that have been inactive longer than timeout_seconds."""
        now = time.time()
        expired_keys = []
        with self.lock:
            for k, flow in self.flows.items():
                if (now - flow.last_seen) > timeout_seconds:
                    expired_keys.append(k)
            for k in expired_keys:
                self.flows.pop(k, None)
        return len(expired_keys)

    def get_endpoints_overview(self) -> List[Dict[str, Any]]:
        """
        Aggregates flow information by observed IP endpoint for Device & Host Overview.
        Provides: IP address, Internal/External classification, First/Last seen,
        Bytes transferred (Tx/Rx), Packet count, Observed connections, Associated alerts.
        """
        endpoints = {}
        with self.lock:
            for flow in self.flows.values():
                src = flow.initiator_ip
                if src not in endpoints:
                    endpoints[src] = {
                        "ip": src,
                        "classification": flow.src_classification.get("scope", "External"),
                        "is_public": flow.src_classification.get("is_public", True),
                        "first_seen": flow.first_seen,
                        "last_seen": flow.last_seen,
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "total_bytes": 0,
                        "packets": 0,
                        "connection_count": 0,
                        "associated_alerts": 0
                    }
                e = endpoints[src]
                e["first_seen"] = min(e["first_seen"], flow.first_seen)
                e["last_seen"] = max(e["last_seen"], flow.last_seen)
                e["bytes_sent"] += flow.bytes_sent
                e["bytes_recv"] += flow.bytes_recv
                e["total_bytes"] += flow.total_bytes
                e["packets"] += flow.total_packets
                e["connection_count"] += 1
                e["associated_alerts"] += len(flow.related_alerts)

                dst = flow.responder_ip
                if dst not in endpoints:
                    endpoints[dst] = {
                        "ip": dst,
                        "classification": flow.dst_classification.get("scope", "External"),
                        "is_public": flow.dst_classification.get("is_public", True),
                        "first_seen": flow.first_seen,
                        "last_seen": flow.last_seen,
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "total_bytes": 0,
                        "packets": 0,
                        "connection_count": 0,
                        "associated_alerts": 0
                    }
                e2 = endpoints[dst]
                e2["first_seen"] = min(e2["first_seen"], flow.first_seen)
                e2["last_seen"] = max(e2["last_seen"], flow.last_seen)
                e2["bytes_sent"] += flow.bytes_recv
                e2["bytes_recv"] += flow.bytes_sent
                e2["total_bytes"] += flow.total_bytes
                e2["packets"] += flow.total_packets
                e2["connection_count"] += 1
                e2["associated_alerts"] += len(flow.related_alerts)

        return sorted(endpoints.values(), key=lambda x: x["total_bytes"], reverse=True)

    def clear(self):
        with self.lock:
            self.flows.clear()

    def export_to_csv(self, filepath: str) -> bool:
        """Exports all current flow snapshots to CSV."""
        flows_data = self.get_all_flows_snapshot()
        if not flows_data:
            return False
        try:
            fieldnames = [
                "flow_id", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "tcp_state", "first_seen", "last_seen",
                "duration", "packets", "packets_sent", "packets_recv",
                "bytes_sent", "bytes_recv", "total_bytes", "related_alerts_count",
                "attribution_type", "src_scope", "dst_scope"
            ]
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for row in flows_data:
                    writer.writerow(row)
            return True
        except Exception as e:
            logger.error(f"Failed to export flows to CSV {filepath}: {e}")
            return False
