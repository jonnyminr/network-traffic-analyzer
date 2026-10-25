import sys
from typing import List, Dict, Any, Optional
from scapy.all import conf

def get_network_interfaces() -> List[Dict[str, Any]]:
    """
    Returns a sorted list of network interfaces available on the system.
    Active, internet-connected interfaces (with valid IP addresses) are prioritized
    at the top of the list, while disconnected virtual adapters and WAN Miniports
    are deprioritized.
    """
    interfaces = []
    default_iface = getattr(conf, 'iface', None)

    try:
        ifaces_dict = conf.ifaces
    except Exception:
        ifaces_dict = {}

    for key, iface in ifaces_dict.items():
        name = getattr(iface, 'name', '') or str(key)
        desc = getattr(iface, 'description', '') or name
        ip = getattr(iface, 'ip', '') or ''
        mac = getattr(iface, 'mac', '') or ''
        
        is_loopback = (
            'loopback' in desc.lower() or 
            'loopback' in name.lower() or 
            ip == '127.0.0.1' or 
            name.lower() in ('lo', 'lo0')
        )
        is_miniport = 'miniport' in desc.lower() or 'miniport' in name.lower()
        has_real_ip = bool(
            ip and 
            ip != '0.0.0.0' and 
            not ip.startswith('169.254.') and 
            not is_loopback
        )
        
        # Calculate suitability score
        score = 0
        if has_real_ip:
            score += 100
        if iface == default_iface:
            score += 50
        if is_loopback:
            score -= 20
        if is_miniport:
            score -= 60
            
        display_label = f"{name} - {desc}"
        if ip:
            display_label += f" ({ip})"
        if has_real_ip:
            display_label += " [Active]"

        interfaces.append({
            'key': key,
            'name': name,
            'description': desc,
            'ip': ip,
            'mac': mac,
            'is_active': has_real_ip,
            'is_loopback': is_loopback,
            'is_miniport': is_miniport,
            'score': score,
            'display_label': display_label,
            'iface_obj': iface
        })
        
    interfaces.sort(key=lambda x: x['score'], reverse=True)
    return interfaces

def get_best_interface() -> Optional[Dict[str, Any]]:
    """
    Returns the most suitable active network interface to capture packets on.
    """
    ifaces = get_network_interfaces()
    if ifaces:
        return ifaces[0]
    return None

def resolve_scapy_interface(target: Any) -> Any:
    """
    Resolves any interface representation (NetworkInterface object, interface name,
    GUID key, or description) into a Scapy-compatible interface object or pcap name.
    
    On Windows:
      If target is None or 'Any', it automatically resolves to the best active interface
      because libpcap on Windows does not support listening on all interfaces at once.
    """
    # 1. Already a Scapy interface object
    if target is not None and hasattr(target, 'name') and hasattr(target, 'network_name'):
        return target

    # 2. On Windows, 'Any' or empty target cannot be sniffed directly at Layer 2
    if not target or str(target).strip().lower() in ('any', 'none'):
        if sys.platform == 'win32':
            best = get_best_interface()
            if best and best.get('iface_obj'):
                return best['iface_obj']
            return getattr(conf, 'iface', None)
        else:
            return None # On Linux/macOS, None or 'any' sniffs on all interfaces

    target_str = str(target).strip()

    # 3. Match against conf.ifaces
    try:
        for key, iface in conf.ifaces.items():
            if (str(key) == target_str or 
                getattr(iface, 'name', '') == target_str or 
                getattr(iface, 'description', '') == target_str or
                getattr(iface, 'network_name', '') == target_str):
                return iface
    except Exception:
        pass

    # 4. Fallback to conf.iface
    default_iface = getattr(conf, 'iface', None)
    return default_iface if default_iface is not None else target_str
