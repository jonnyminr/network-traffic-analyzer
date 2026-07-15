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
                'timestamp': float(packet.time) if hasattr(packet, 'time') else time.time(),
                'src_ip': str(ip_layer.src),
                'dst_ip': str(ip_layer.dst),
                'size': int(len(packet)),
                'protocol': 'Other',
                'src_port': None,
                'dst_port': None
            }
            
            # Protocol and Ports
            if TCP in packet:
                parsed['protocol'] = 'TCP'
                parsed['src_port'] = int(packet[TCP].sport)
                parsed['dst_port'] = int(packet[TCP].dport)
            elif UDP in packet:
                parsed['protocol'] = 'UDP'
                parsed['src_port'] = int(packet[UDP].sport)
                parsed['dst_port'] = int(packet[UDP].dport)
            elif ICMP in packet:
                parsed['protocol'] = 'ICMP'
                
            return parsed
    except Exception as e:
        # Silently drop unparseable packets or log them if debugging
        pass
    
    return None
