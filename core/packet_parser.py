import time
from typing import Dict, Any, Optional
from scapy.all import Packet, IP, TCP, UDP, ICMP

def parse_packet(packet: Packet) -> Optional[Dict[str, Any]]:
    """
    Extract protocol, src/dst IP+port, size, and timestamp from a Scapy packet.
    """
    try:
        # We only care about IP packets for this basic analyzer
        if IP in packet:
            ip_layer = packet[IP]
            
            # Basic info
            parsed = {
                'timestamp': time.time(), # scapy packet.time is a float, but we can also use time.time()
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'size': len(packet),
                'protocol': 'Other',
                'src_port': None,
                'dst_port': None
            }
            
            # Timestamp from scapy
            if hasattr(packet, 'time'):
                parsed['timestamp'] = float(packet.time)

            # Protocol and Ports
            if TCP in packet:
                parsed['protocol'] = 'TCP'
                parsed['src_port'] = packet[TCP].sport
                parsed['dst_port'] = packet[TCP].dport
            elif UDP in packet:
                parsed['protocol'] = 'UDP'
                parsed['src_port'] = packet[UDP].sport
                parsed['dst_port'] = packet[UDP].dport
            elif ICMP in packet:
                parsed['protocol'] = 'ICMP'
                
            return parsed
    except Exception as e:
        # Silently drop unparseable packets or log them if debugging
        pass
    
    return None
