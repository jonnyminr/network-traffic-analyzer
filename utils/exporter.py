import csv
from scapy.all import wrpcap
from typing import List, Dict, Any
import os

from utils.logger import logger

def export_to_pcap(filename: str, packets: List[Any]):
    """
    Export raw scapy packets to a .pcap file.
    """
    try:
        wrpcap(filename, packets)
        logger.info(f"Successfully exported {len(packets)} packets to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export to pcap: {e}")
        return False

def export_stats_to_csv(filename: str, stats: List[Dict[str, Any]]):
    """
    Export statistics to a CSV file.
    """
    if not stats:
        logger.warning("No stats to export.")
        return False

    try:
        keys = stats[0].keys()
        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(stats)
        logger.info(f"Successfully exported stats to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export stats to CSV: {e}")
        return False

def export_alerts_to_csv(filename: str, alerts: List[Dict[str, Any]]):
    """
    Export alerts to a CSV file.
    """
    if not alerts:
        logger.warning("No alerts to export.")
        return False

    try:
        keys = alerts[0].keys()
        with open(filename, 'w', newline='', encoding='utf-8') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(alerts)
        logger.info(f"Successfully exported alerts to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export alerts to CSV: {e}")
        return False
