import csv
import json
from scapy.all import wrpcap
from typing import List, Dict, Any
import os

from utils.logger import logger

def export_to_pcap(filename: str, packets: List[Any]) -> bool:
    """
    Export raw scapy packets to a .pcap file.
    """
    if not packets:
        logger.warning("No raw packets captured to export.")
        return False

    try:
        wrpcap(filename, packets)
        logger.info(f"Successfully exported {len(packets)} packets to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export to pcap: {e}")
        return False

def export_stats_to_csv(filename: str, stats: List[Dict[str, Any]]) -> bool:
    """
    Export statistics history to a CSV file.
    Serializes nested lists/dicts to strings for clean CSV output.
    """
    if not stats:
        logger.warning("No stats to export.")
        return False

    try:
        keys = list(stats[0].keys())
        # Prepare flat rows
        sanitized_rows = []
        for row in stats:
            sanitized = {}
            for k, v in row.items():
                if isinstance(v, (dict, list, set)):
                    sanitized[k] = json.dumps(v, default=str)
                else:
                    sanitized[k] = v
            sanitized_rows.append(sanitized)

        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(sanitized_rows)
        logger.info(f"Successfully exported {len(sanitized_rows)} stat entries to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export stats to CSV: {e}")
        return False

def export_alerts_to_csv(filename: str, alerts: List[Dict[str, Any]]) -> bool:
    """
    Export alerts to a CSV file.
    """
    if not alerts:
        logger.warning("No alerts to export.")
        return False

    try:
        keys = list(alerts[0].keys())
        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(alerts)
        logger.info(f"Successfully exported {len(alerts)} alerts to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export alerts to CSV: {e}")
        return False

def export_connections_to_csv(filename: str, connections: List[Dict[str, Any]]) -> bool:
    """
    Export website connection summary to a CSV file.
    """
    if not connections:
        logger.warning("No connection summaries to export.")
        return False

    try:
        keys = list(connections[0].keys())
        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(connections)
        logger.info(f"Successfully exported {len(connections)} connections to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export connections to CSV: {e}")
        return False
