"""
feature_extractor.py - Convert Raw Packets to NSL-KDD Feature Vectors
=======================================================================
This module extracts 41 features from captured network packets/connections
to match the NSL-KDD dataset format for ML classification.

The NSL-KDD features are grouped into:
1. Basic features (1-9): Derived from packet headers
2. Content features (10-22): Derived from payload content
3. Time-based traffic features (23-31): Computed over a 2-second window
4. Host-based traffic features (32-41): Computed over recent connections

Since real-time packet capture cannot perfectly replicate all 41 features
(some require deep packet inspection or connection-level aggregation),
this module approximates them as closely as possible.

Author: University of Botswana - Final Year Project
"""

import time
import collections
from scapy.all import IP, TCP, UDP, ICMP


# ============================================================================
# NSL-KDD Service Port Mapping
# ============================================================================
SERVICE_MAP = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    37: 'time', 42: 'name', 43: 'whois', 53: 'domain_u', 66: 'sql_net',
    69: 'tftp_u', 70: 'gopher', 79: 'finger', 80: 'http', 109: 'pop_2',
    110: 'pop_3', 111: 'sunrpc', 113: 'auth', 119: 'nntp', 123: 'ntp_u',
    139: 'netbios_ns', 143: 'imap4', 161: 'snmp', 179: 'bgp',
    389: 'ldap', 443: 'http_443s', 512: 'exec', 513: 'login', 514: 'shell',
    515: 'printer', 520: 'efs', 530: 'courier', 540: 'uucp', 543: 'klogin',
    544: 'kshell', 993: 'imap4', 995: 'pop_3', 1080: 'socks',
    1433: 'sql_net', 1521: 'sql_net', 2049: 'nfs', 3306: 'sql_net',
    5432: 'sql_net', 6667: 'IRC', 8080: 'http',
}

# NSL-KDD TCP Flag Mapping
FLAG_MAP = {
    'S': 'S0',       # SYN only (connection attempt, no response)
    'SA': 'S1',      # SYN-ACK (connection established from source)
    'SF': 'SF',      # Normal establishment and termination
    'R': 'REJ',      # Connection rejected
    'RA': 'RSTO',    # Connection reset by originator
    'FA': 'S2',      # FIN-ACK (established, originator closing)
    'PA': 'SF',      # Push-ACK (data transfer, treat as normal)
}


class ConnectionTracker:
    """
    Tracks recent network connections to compute time-based and host-based
    traffic features (features 23-41 in the NSL-KDD format).
    Uses sliding windows to maintain statistics over recent connections.
    """

    def __init__(self, time_window=2.0, host_window=100):
        """
        Args:
            time_window (float): Seconds for time-based feature computation.
            host_window (int): Number of recent connections for host-based features.
        """
        self.time_window = time_window
        self.host_window = host_window
        self.connections = collections.deque(maxlen=5000)  # Recent connections

    def add_connection(self, conn_info):
        """Add a connection record with timestamp."""
        conn_info['timestamp'] = time.time()
        self.connections.append(conn_info)

    def _get_time_window_connections(self, current_time):
        """Get connections within the time window."""
        cutoff = current_time - self.time_window
        return [c for c in self.connections if c['timestamp'] >= cutoff]

    def _get_host_window_connections(self):
        """Get the last N connections for host-based features."""
        return list(self.connections)[-self.host_window:]

    def compute_time_features(self, dst_ip, dst_port, service, protocol):
        """
        Compute time-based traffic features (features 23-31).
        These are based on connections in the last 2-second window.

        Returns:
            dict: Time-based features.
        """
        now = time.time()
        recent = self._get_time_window_connections(now)

        if not recent:
            return {
                'count': 0, 'srv_count': 0,
                'serror_rate': 0.0, 'srv_serror_rate': 0.0,
                'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
                'same_srv_rate': 0.0, 'diff_srv_rate': 0.0,
                'srv_diff_host_rate': 0.0,
            }

        # Count connections to same destination
        same_dst = [c for c in recent if c.get('dst_ip') == dst_ip]
        count = len(same_dst)

        # Count connections to same service
        same_srv = [c for c in recent if c.get('service') == service]
        srv_count = len(same_srv)

        # Error rates
        if count > 0:
            serror_rate = sum(1 for c in same_dst if c.get('flag', '') in ['S0', 'S1', 'S2', 'S3']) / count
            rerror_rate = sum(1 for c in same_dst if c.get('flag', '') == 'REJ') / count
            same_srv_count = sum(1 for c in same_dst if c.get('service') == service)
            same_srv_rate = same_srv_count / count
            diff_srv_rate = 1.0 - same_srv_rate
        else:
            serror_rate = rerror_rate = same_srv_rate = diff_srv_rate = 0.0

        if srv_count > 0:
            srv_serror_rate = sum(1 for c in same_srv if c.get('flag', '') in ['S0', 'S1', 'S2', 'S3']) / srv_count
            srv_rerror_rate = sum(1 for c in same_srv if c.get('flag', '') == 'REJ') / srv_count
            diff_hosts = len(set(c.get('dst_ip') for c in same_srv))
            srv_diff_host_rate = diff_hosts / srv_count if srv_count > 0 else 0.0
        else:
            srv_serror_rate = srv_rerror_rate = srv_diff_host_rate = 0.0

        return {
            'count': count,
            'srv_count': srv_count,
            'serror_rate': round(serror_rate, 2),
            'srv_serror_rate': round(srv_serror_rate, 2),
            'rerror_rate': round(rerror_rate, 2),
            'srv_rerror_rate': round(srv_rerror_rate, 2),
            'same_srv_rate': round(same_srv_rate, 2),
            'diff_srv_rate': round(diff_srv_rate, 2),
            'srv_diff_host_rate': round(srv_diff_host_rate, 2),
        }

    def compute_host_features(self, dst_ip, dst_port, service):
        """
        Compute host-based traffic features (features 32-41).
        These are based on the last 100 connections.

        Returns:
            dict: Host-based features.
        """
        recent = self._get_host_window_connections()

        if not recent:
            return {
                'dst_host_count': 0, 'dst_host_srv_count': 0,
                'dst_host_same_srv_rate': 0.0, 'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0, 'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0,
            }

        # Connections to same destination host
        same_host = [c for c in recent if c.get('dst_ip') == dst_ip]
        dst_host_count = len(same_host)

        # Connections to same destination host and service
        same_host_srv = [c for c in same_host if c.get('service') == service]
        dst_host_srv_count = len(same_host_srv)

        if dst_host_count > 0:
            dst_host_same_srv_rate = dst_host_srv_count / dst_host_count
            diff_services = len(set(c.get('service') for c in same_host))
            dst_host_diff_srv_rate = (diff_services - 1) / dst_host_count if dst_host_count > 1 else 0.0
            same_port = sum(1 for c in same_host if c.get('dst_port') == dst_port)
            dst_host_same_src_port_rate = same_port / dst_host_count
            dst_host_serror_rate = sum(1 for c in same_host if c.get('flag', '') in ['S0', 'S1', 'S2', 'S3']) / dst_host_count
            dst_host_rerror_rate = sum(1 for c in same_host if c.get('flag', '') == 'REJ') / dst_host_count
        else:
            dst_host_same_srv_rate = dst_host_diff_srv_rate = 0.0
            dst_host_same_src_port_rate = dst_host_serror_rate = dst_host_rerror_rate = 0.0

        if dst_host_srv_count > 0:
            diff_hosts = len(set(c.get('src_ip') for c in same_host_srv))
            dst_host_srv_diff_host_rate = diff_hosts / dst_host_srv_count
            dst_host_srv_serror_rate = sum(1 for c in same_host_srv if c.get('flag', '') in ['S0', 'S1', 'S2', 'S3']) / dst_host_srv_count
            dst_host_srv_rerror_rate = sum(1 for c in same_host_srv if c.get('flag', '') == 'REJ') / dst_host_srv_count
        else:
            dst_host_srv_diff_host_rate = dst_host_srv_serror_rate = dst_host_srv_rerror_rate = 0.0

        return {
            'dst_host_count': min(dst_host_count, 255),
            'dst_host_srv_count': min(dst_host_srv_count, 255),
            'dst_host_same_srv_rate': round(dst_host_same_srv_rate, 2),
            'dst_host_diff_srv_rate': round(dst_host_diff_srv_rate, 2),
            'dst_host_same_src_port_rate': round(dst_host_same_src_port_rate, 2),
            'dst_host_srv_diff_host_rate': round(dst_host_srv_diff_host_rate, 2),
            'dst_host_serror_rate': round(dst_host_serror_rate, 2),
            'dst_host_srv_serror_rate': round(dst_host_srv_serror_rate, 2),
            'dst_host_rerror_rate': round(dst_host_rerror_rate, 2),
            'dst_host_srv_rerror_rate': round(dst_host_srv_rerror_rate, 2),
        }


def get_tcp_flags(packet):
    """
    Extract TCP flags from a packet and map to NSL-KDD flag format.

    Args:
        packet: Scapy packet with TCP layer.

    Returns:
        str: NSL-KDD flag string (e.g., 'SF', 'S0', 'REJ').
    """
    if not packet.haslayer(TCP):
        return 'SF'  # Default for non-TCP

    flags = packet[TCP].flags
    flag_str = str(flags)

    # Map common flag combinations
    if 'S' in flag_str and 'A' not in flag_str and 'F' not in flag_str:
        return 'S0'   # SYN only
    elif 'R' in flag_str:
        return 'REJ' if 'A' not in flag_str else 'RSTO'
    elif 'S' in flag_str and 'A' in flag_str:
        return 'S1'
    elif 'F' in flag_str:
        return 'SF'   # FIN seen, assume normal close
    else:
        return 'SF'   # Default to normal


def get_service(packet):
    """
    Determine the network service based on destination port.

    Args:
        packet: Scapy packet with IP layer.

    Returns:
        str: Service name matching NSL-KDD format.
    """
    if packet.haslayer(TCP):
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        port = packet[UDP].dport
    else:
        return 'other'

    return SERVICE_MAP.get(port, 'other')


def get_protocol(packet):
    """
    Determine the protocol type from a packet.

    Args:
        packet: Scapy packet.

    Returns:
        str: Protocol string ('tcp', 'udp', or 'icmp').
    """
    if packet.haslayer(TCP):
        return 'tcp'
    elif packet.haslayer(UDP):
        return 'udp'
    elif packet.haslayer(ICMP):
        return 'icmp'
    return 'tcp'  # Default


def extract_features(packet, connection_tracker):
    """
    Extract all 41 NSL-KDD features from a captured network packet.

    This function converts a raw Scapy packet into a feature vector matching
    the NSL-KDD dataset format for ML classification.

    Args:
        packet: Scapy packet (must have IP layer).
        connection_tracker: ConnectionTracker instance for traffic statistics.

    Returns:
        dict: Dictionary with 41 features plus metadata (src_ip, dst_ip, dst_port)
              matching the NSL-KDD column names, or None if packet cannot be processed.
    """
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    # Determine protocol, service, and flag
    protocol = get_protocol(packet)
    service = get_service(packet)
    flag = get_tcp_flags(packet)

    # Get ports
    src_port = 0
    dst_port = 0
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ========================================================================
    # Basic Features (1-9)
    # ========================================================================
    duration = 0  # Single packet, duration is 0

    src_bytes = len(packet)  # Bytes from source to destination
    dst_bytes = 0  # Cannot determine from single packet

    land = 1 if src_ip == dst_ip and src_port == dst_port else 0
    wrong_fragment = ip_layer.frag if hasattr(ip_layer, 'frag') else 0
    urgent = packet[TCP].urgptr if packet.haslayer(TCP) and packet[TCP].urgptr else 0

    # ========================================================================
    # Content Features (10-22)
    # These require deep packet inspection; approximate with defaults
    # ========================================================================
    hot = 0
    num_failed_logins = 0
    logged_in = 1 if flag == 'SF' else 0
    num_compromised = 0
    root_shell = 0
    su_attempted = 0
    num_root = 0
    num_file_creations = 0
    num_shells = 0
    num_access_files = 0
    num_outbound_cmds = 0
    is_host_login = 0
    is_guest_login = 0

    # ========================================================================
    # Time-based Traffic Features (23-31)
    # ========================================================================
    time_features = connection_tracker.compute_time_features(
        dst_ip, dst_port, service, protocol
    )

    # ========================================================================
    # Host-based Traffic Features (32-41)
    # ========================================================================
    host_features = connection_tracker.compute_host_features(
        dst_ip, dst_port, service
    )

    # Record this connection for future feature computation
    conn_info = {
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'service': service,
        'flag': flag,
    }
    connection_tracker.add_connection(conn_info)

    # ========================================================================
    # Assemble the 41-feature vector
    # ========================================================================
    features = {
        # Basic features (1-9)
        'duration': duration,
        'protocol_type': protocol,
        'service': service,
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': land,
        'wrong_fragment': wrong_fragment,
        'urgent': urgent,

        # Content features (10-22)
        'hot': hot,
        'num_failed_logins': num_failed_logins,
        'logged_in': logged_in,
        'num_compromised': num_compromised,
        'root_shell': root_shell,
        'su_attempted': su_attempted,
        'num_root': num_root,
        'num_file_creations': num_file_creations,
        'num_shells': num_shells,
        'num_access_files': num_access_files,
        'num_outbound_cmds': num_outbound_cmds,
        'is_host_login': is_host_login,
        'is_guest_login': is_guest_login,

        # Time-based features (23-31)
        **time_features,

        # Host-based features (32-41)
        **host_features,
    }

    # Add metadata (not part of the 41 features, used for alert display)
    features['_src_ip'] = src_ip
    features['_dst_ip'] = dst_ip
    features['_dst_port'] = dst_port
    features['_src_port'] = src_port
    features['_protocol'] = protocol

    return features
