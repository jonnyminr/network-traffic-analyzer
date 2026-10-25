import time
from typing import Dict, Any, Optional
from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP, ARP

def parse_packet(packet: Packet) -> Optional[Dict[str, Any]]:
    """
    Extract protocol, src/dst IP+port, size, and timestamp from a Scapy packet.
    Supports IPv4, IPv6, and ARP packets.
    """
    try:
        # Determine timestamp
        if hasattr(packet, 'time') and packet.time is not None:
            ts = float(packet.time)
        else:
            ts = time.time()

        size = int(len(packet))

        # 1. IP & IPv6 Packets
        if IP in packet or IPv6 in packet:
            ip_layer = packet[IP] if IP in packet else packet[IPv6]
            
            parsed = {
                'timestamp': ts,
                'src_ip': str(ip_layer.src),
                'dst_ip': str(ip_layer.dst),
                'size': size,
                'protocol': 'Other',
                'src_port': None,
                'dst_port': None
            }
            
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
            elif packet.haslayer('ICMPv6EchoRequest') or packet.haslayer('ICMPv6EchoReply'):
                parsed['protocol'] = 'ICMP'
                
            return parsed

        # 2. ARP Packets (very common on LAN)
        elif ARP in packet:
            return {
                'timestamp': ts,
                'src_ip': str(packet[ARP].psrc),
                'dst_ip': str(packet[ARP].pdst),
                'size': size,
                'protocol': 'ARP',
                'src_port': None,
                'dst_port': None
            }

    except Exception:
        # Silently drop unparseable packets
        pass
    
    return None
