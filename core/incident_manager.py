import time
import json
import uuid
import datetime
from typing import Dict, List, Optional, Any
from utils.logger import logger
from core.incident_db import IncidentDatabase
from core.connection_tracker import ConnectionTracker
from core.dns_monitor import DNSMonitor
from core.alert_manager import AlertManager


class IncidentManager:
    """
    Orchestrates Incident Investigations, correlating security alerts with
    observed network flows, DNS activity, threat intelligence, and analyst notes.
    """
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(IncidentManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if getattr(self, '_initialized', False):
            return
        self._initialized = True
        self.db = IncidentDatabase()
        self.tracker = ConnectionTracker()
        self.dns_monitor = DNSMonitor()
        self.alert_manager = AlertManager()
        logger.info("Initialized IncidentManager")

    def create_investigation(
        self,
        title: str,
        description: str = "",
        initial_alert: Dict[str, Any] = None,
        severity: str = "Medium"
    ) -> Dict[str, Any]:
        """
        Creates a new investigation and automatically correlates evidence.
        """
        now = time.time()
        date_str = time.strftime("%Y%m%d", time.localtime(now))
        inv_id = f"INV-{date_str}-{str(uuid.uuid4())[:6].upper()}"

        alert_ids = []
        involved_ips = set()
        related_conns = []

        if initial_alert:
            alert_id = initial_alert.get("alert_id")
            if alert_id:
                alert_ids.append(alert_id)
            severity = initial_alert.get("severity", severity)
            if not title:
                title = f"Investigation into {initial_alert.get('title', 'Security Alert')} ({alert_id})"

            src_ip = initial_alert.get("src_ip")
            dst_ip = initial_alert.get("dst_ip")
            if src_ip and src_ip not in ("Unknown", "Multiple"):
                involved_ips.add(src_ip)
            if dst_ip and dst_ip not in ("Unknown", "Multiple", "Network", "Local/Target"):
                involved_ips.add(dst_ip)

        inv_record = {
            "investigation_id": inv_id,
            "title": title or f"Investigation {inv_id}",
            "status": "Open",
            "severity": severity,
            "created_at": now,
            "updated_at": now,
            "description": description or (f"Triggered by alert: {initial_alert.get('title')}" if initial_alert else "Manual investigation initiated."),
            "resolution": "",
            "analyst_notes": "",
            "alert_ids_json": json.dumps(alert_ids),
            "involved_ips_json": json.dumps(list(involved_ips)),
            "related_conn_ids_json": json.dumps(related_conns)
        }

        self.db.save_investigation(inv_record)

        # Record initial timeline event
        self.db.add_timeline_event(
            inv_id=inv_id,
            timestamp=now,
            event_type="INVESTIGATION_OPENED",
            title="Investigation Created",
            description=f"Investigation opened with status 'Open' (Severity: {severity}).",
            evidence_ref=inv_id
        )

        if initial_alert:
            self.db.add_timeline_event(
                inv_id=inv_id,
                timestamp=initial_alert.get("first_seen", now),
                event_type="ALERT_CORRELATED",
                title=f"Alert Linked: {initial_alert.get('title')}",
                description=initial_alert.get("explanation", ""),
                evidence_ref=initial_alert.get("alert_id", "")
            )

        # Run automatic correlation
        self._correlate_evidence(inv_id, list(involved_ips), initial_alert)

        return self.get_investigation(inv_id)

    def _correlate_evidence(self, inv_id: str, ips: List[str], alert: Optional[Dict[str, Any]]):
        """Correlates flows, DNS, and threat intel with explicit association rationale."""
        if not ips:
            return

        correlated_conn_ids = []

        # 1. Match network flows
        for ip in ips:
            flows = self.tracker.get_flows_for_ip(ip)
            for f in flows[:15]:
                flow_id = f.get("flow_id")
                if flow_id and flow_id not in correlated_conn_ids:
                    correlated_conn_ids.append(flow_id)
                    self.db.add_timeline_event(
                        inv_id=inv_id,
                        timestamp=f.get("first_seen", time.time()),
                        event_type="FLOW_OBSERVED",
                        title=f"Observed Flow: {f.get('src_ip')}:{f.get('src_port')} ➔ {f.get('dst_ip')}:{f.get('dst_port')}",
                        description=f"Protocol {f.get('protocol')}, State: {f.get('tcp_state')}, Volume: {f.get('total_bytes')} bytes across {f.get('packets')} packets.",
                        evidence_ref=flow_id
                    )

        # 2. Match DNS queries
        dns_txs = self.dns_monitor.get_transactions_snapshot()
        matched_dns_count = 0
        for tx in dns_txs:
            matches_ip = any(ip in tx.get("client_endpoint", "") or ip in tx.get("answers", "") for ip in ips)
            if matches_ip and matched_dns_count < 10:
                matched_dns_count += 1
                self.db.add_timeline_event(
                    inv_id=inv_id,
                    timestamp=tx.get("timestamp", time.time()),
                    event_type="DNS_QUERY",
                    title=f"DNS Lookup: {tx.get('qname')} ({tx.get('qtype')})",
                    description=f"Response: {tx.get('rcode')}, Resolved IPs: {tx.get('answers')}",
                    evidence_ref=tx.get("tx_id", "")
                )

        # Update correlated conn IDs in DB
        inv = self.db.get_investigation(inv_id)
        if inv:
            existing_conns = json.loads(inv.get("related_conn_ids_json") or "[]")
            all_conns = list(set(existing_conns + correlated_conn_ids))
            inv["related_conn_ids_json"] = json.dumps(all_conns)
            self.db.save_investigation(inv)

    def add_analyst_note(self, inv_id: str, note_text: str):
        now = time.time()
        inv = self.db.get_investigation(inv_id)
        if not inv:
            return

        dt_str = datetime.datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{dt_str}] {note_text}\n"
        existing = inv.get("analyst_notes") or ""
        inv["analyst_notes"] = existing + entry
        inv["updated_at"] = now
        self.db.save_investigation(inv)

        self.db.add_timeline_event(
            inv_id=inv_id,
            timestamp=now,
            event_type="ANALYST_NOTE",
            title="Analyst Note Added",
            description=note_text,
            evidence_ref="Note"
        )

    def update_status(self, inv_id: str, new_status: str, resolution_note: str = ""):
        now = time.time()
        inv = self.db.get_investigation(inv_id)
        if not inv:
            return

        old_status = inv.get("status", "Open")
        inv["status"] = new_status
        inv["updated_at"] = now
        if resolution_note:
            inv["resolution"] = resolution_note
        self.db.save_investigation(inv)

        self.db.add_timeline_event(
            inv_id=inv_id,
            timestamp=now,
            event_type="STATUS_CHANGED",
            title=f"Status Changed: {old_status} ➔ {new_status}",
            description=resolution_note or f"Investigation status transitioned to {new_status}.",
            evidence_ref=new_status
        )

    def get_investigation(self, inv_id: str) -> Optional[Dict[str, Any]]:
        inv = self.db.get_investigation(inv_id)
        if not inv:
            return None
        inv["alert_ids"] = json.loads(inv.get("alert_ids_json") or "[]")
        inv["involved_ips"] = json.loads(inv.get("involved_ips_json") or "[]")
        inv["related_conn_ids"] = json.loads(inv.get("related_conn_ids_json") or "[]")
        inv["timeline"] = self.db.get_investigation_timeline(inv_id)
        return inv

    def get_all_investigations(self) -> List[Dict[str, Any]]:
        raw = self.db.get_all_investigations()
        for r in raw:
            r["alert_ids"] = json.loads(r.get("alert_ids_json") or "[]")
            r["involved_ips"] = json.loads(r.get("involved_ips_json") or "[]")
            r["related_conn_ids"] = json.loads(r.get("related_conn_ids_json") or "[]")
        return raw

    def generate_html_report(self, inv_id: str) -> str:
        """Generates a comprehensive printable HTML investigation report."""
        inv = self.get_investigation(inv_id)
        if not inv:
            return "<html><body><h1>Investigation not found</h1></body></html>"

        created_str = datetime.datetime.fromtimestamp(inv["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        updated_str = datetime.datetime.fromtimestamp(inv["updated_at"]).strftime("%Y-%m-%d %H:%M:%S")

        timeline_rows = ""
        for t in inv["timeline"]:
            t_dt = datetime.datetime.fromtimestamp(t["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            timeline_rows += f"""
            <tr>
                <td style="white-space:nowrap; padding:8px; border-bottom:1px solid #333; color:#a0a0b0;">{t_dt}</td>
                <td style="padding:8px; border-bottom:1px solid #333; font-weight:bold; color:#00e5ff;">{t['event_type']}</td>
                <td style="padding:8px; border-bottom:1px solid #333; color:#fff;">{t['title']}<br><span style="color:#aaa; font-size:11px;">{t['description']}</span></td>
                <td style="padding:8px; border-bottom:1px solid #333; color:#ffd600;">{t.get('evidence_ref', '')}</td>
            </tr>
            """

        alerts_html = ""
        for aid in inv["alert_ids"]:
            a = self.alert_manager.get_alert_by_id(aid)
            if a:
                alerts_html += f"""
                <div style="background:#25252c; border-left:4px solid #ff5252; padding:10px; margin-bottom:8px; border-radius:4px;">
                    <b>{a['title']}</b> ({a['alert_id']}) — <span style="color:#ff9100;">{a['severity']}</span><br>
                    <span>Detection: {a['detection_method']} | Category: {a['category']}</span><br>
                    <span>Rate: {a['current_rate']} vs Baseline: {a['baseline_rate']} (Score: {a['anomaly_score']})</span><br>
                    <span style="color:#bbb; font-size:11px;">{a['explanation']}</span>
                </div>
                """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Incident Investigation Report — {inv['investigation_id']}</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    background-color: #1a1a20;
                    color: #e0e0e0;
                    margin: 20px;
                    line-height: 1.5;
                }}
                .header {{
                    background: #25252c;
                    padding: 20px;
                    border-radius: 8px;
                    border: 1px solid #363642;
                    margin-bottom: 20px;
                }}
                h1 {{ color: #00e5ff; margin-top: 0; }}
                h2 {{ color: #00e5ff; border-bottom: 1px solid #363642; padding-bottom: 6px; margin-top: 24px; }}
                .badge {{
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }}
                .badge-open {{ background: #b71c1c; color: white; }}
                .badge-investigating {{ background: #f57f17; color: white; }}
                .badge-resolved {{ background: #2e7d32; color: white; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th {{ background: #25252c; color: #00e5ff; text-align: left; padding: 8px; border-bottom: 2px solid #363642; }}
                .notice {{
                    background: #1c2038;
                    border: 1px solid #283593;
                    border-radius: 6px;
                    padding: 12px;
                    font-size: 11px;
                    color: #9fa8da;
                    margin-top: 30px;
                }}
                @media print {{
                    body {{ background: #fff; color: #000; }}
                    .header, th {{ background: #f0f0f0 !important; color: #000 !important; }}
                    h1, h2 {{ color: #000 !important; }}
                    td {{ border-bottom: 1px solid #ccc !important; color: #000 !important; }}
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Cybersecurity Incident Investigation Report</h1>
                <p><b>Investigation ID:</b> {inv['investigation_id']} | <b>Title:</b> {inv['title']}</p>
                <p>
                    <b>Status:</b> <span class="badge badge-{inv['status'].lower()}">{inv['status']}</span> |
                    <b>Severity:</b> {inv['severity']} |
                    <b>Created:</b> {created_str} |
                    <b>Last Updated:</b> {updated_str}
                </p>
                <p><b>Description:</b> {inv['description']}</p>
            </div>

            <h2>1. Associated Security Incidents & Alerts</h2>
            {alerts_html if alerts_html else "<p>No alerts linked.</p>"}

            <h2>2. Chronological Investigation Timeline</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Details</th>
                        <th>Evidence Ref</th>
                    </tr>
                </thead>
                <tbody>
                    {timeline_rows}
                </tbody>
            </table>

            <h2>3. Analyst Assessment & Resolution</h2>
            <div style="background:#25252c; padding:12px; border-radius:6px; border:1px solid #363642;">
                <p><b>Final Resolution:</b> {inv['resolution'] or "Pending resolution."}</p>
                <p><b>Analyst Notes:</b><br><pre style="white-space:pre-wrap; font-family:monospace; color:#ccc;">{inv['analyst_notes'] or "No notes logged."}</pre></p>
            </div>

            <div class="notice">
                <b>Evidence Integrity & Technical Limitations Notice:</b><br>
                This incident report aggregates passively observed L4 flows, standard DNS transactions, and statistical anomaly scores.
                Encrypted payloads (TLS/HTTPS, DoH) were not decrypted. Detections and anomaly scores reflect statistical observations rather than definitive proof of malicious attack.
            </div>
        </body>
        </html>
        """
        return html
