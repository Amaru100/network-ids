"""
nids_agent.py - NIDS Standalone Agent
=======================================
Self-contained agent that can be installed on any machine in the network.
Captures packets, classifies them using ML, and reports to the central NIDS server.

Works on both Windows and Linux.

Usage:
    Windows (Admin CMD):  python nids_agent.py --agent-name LAB-PC-01
    Linux (root):         sudo python3 nids_agent.py --agent-name LAB-PC-01

The --api-url is pre-configured but can be overridden.

Author: University of Botswana - Final Year Project
"""

import os
import sys
import time
import signal
import socket
import platform
import argparse
import logging
import threading
import requests
from scapy.all import sniff, get_if_list

# Local imports (same directory)
from feature_extractor import extract_features, ConnectionTracker
from classifier import TrafficClassifier

# ============================================================
# CONFIGURATION — Change this to your backend URL
# ============================================================
DEFAULT_API_URL = 'https://backend-three-rho-54.vercel.app'
# ============================================================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('NIDS-Agent')

# Global flag for graceful shutdown
running = True


def signal_handler(sig, frame):
    """Handle Ctrl+C for graceful shutdown."""
    global running
    logger.info("\n[!] Shutdown signal received. Stopping agent...")
    running = False


def _get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return 'unknown'


def _heartbeat_loop(api_url, agent_name):
    """Send periodic heartbeats to the central NIDS server."""
    payload = {
        'agent_name': agent_name,
        'hostname': socket.gethostname(),
        'ip_address': _get_local_ip(),
        'os_info': f"{platform.system()} {platform.release()}",
    }

    while running:
        try:
            response = requests.post(
                f"{api_url}/api/agents",
                json=payload,
                timeout=10
            )
            if response.status_code in [200, 201]:
                logger.debug(f"Heartbeat sent for {agent_name}")
            else:
                logger.warning(f"Heartbeat failed: HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Heartbeat error: {e}")

        time.sleep(30)


# Ports that are normal network noise — not attacks
NOISE_PORTS = {5353, 1900, 5355, 3702, 138, 137, 547, 546}  # mDNS, SSDP, LLMNR, WS-Discovery, NetBIOS, DHCPv6

# Common service ports — outbound traffic to these is normal web browsing, not intrusion
WEB_PORTS = {80, 443, 8080, 8443, 53}  # HTTP, HTTPS, DNS

# Cache the local IP so we only look it up once
_local_ip_cache = [None]


def _is_noise(packet):
    """Check if packet is benign network noise that should be skipped."""
    from scapy.all import IP, TCP, UDP
    if not packet.haslayer(IP):
        return True

    src = packet[IP].src
    dst = packet[IP].dst

    # Multicast (224.x.x.x — 239.x.x.x) and broadcast (x.x.x.255)
    if dst.startswith('224.') or dst.startswith('239.') or dst.endswith('.255'):
        return True

    # Common discovery ports (UDP)
    if packet.haslayer(UDP):
        if packet[UDP].dport in NOISE_PORTS or packet[UDP].sport in NOISE_PORTS:
            return True
        # DNS traffic
        if packet[UDP].dport == 53 or packet[UDP].sport == 53:
            return True

    # Get local IP
    if _local_ip_cache[0] is None:
        _local_ip_cache[0] = _get_local_ip()
    local_ip = _local_ip_cache[0]

    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        sport = packet[TCP].sport

        # Outbound web traffic — local machine browsing the internet (not an intrusion)
        if src == local_ip and dport in WEB_PORTS:
            return True

        # Responses from external servers to local machine on ephemeral ports
        # (these are replies to your web requests, not attacks)
        if dst == local_ip and sport in WEB_PORTS:
            return True

    return False


def create_packet_handler(classifier, connection_tracker, log_all=False):
    """Create a packet processing callback."""
    packet_count = [0]
    skipped = [0]

    def handle_packet(packet):
        if not running:
            return

        # Skip known benign traffic
        if _is_noise(packet):
            skipped[0] += 1
            return

        packet_count[0] += 1

        features = extract_features(packet, connection_tracker)
        if features is None:
            return

        result = classifier.classify(features)
        if result is None:
            return

        if result['category'] != 'Normal':
            classifier.send_alert(result)

            severity_icons = {'high': '!!!', 'medium': '!! ', 'low': '!  '}
            icon = severity_icons.get(result['severity'], '   ')
            logger.warning(
                f"[{icon}] {result['category']:>6} | {result['attack_type']:<30} | "
                f"{result['src_ip']:>15} -> {result['dst_ip']:>15}:{result['dst_port']:<5} | "
                f"Confidence: {result['confidence']:>6.2f}%"
            )
        else:
            # Send Normal traffic count to backend (so dashboard counter updates)
            classifier.send_normal(result)
            if log_all:
                logger.info(
                    f"[   ] Normal | "
                    f"{result['src_ip']:>15} -> {result['dst_ip']:>15}:{result['dst_port']:<5} | "
                    f"Confidence: {result['confidence']:>6.2f}%"
                )

        if packet_count[0] % 100 == 0:
            stats = classifier.get_stats()
            logger.info(
                f"--- Stats: {stats['total_classified']} classified | "
                f"{skipped[0]} noise skipped | "
                f"{stats['normal_count']} normal | "
                f"{stats['attack_count']} attacks ({stats['attack_percentage']}%) | "
                f"{stats['alerts_sent']} alerts sent ---"
            )

    return handle_packet


def check_privileges():
    """Check for root/admin privileges."""
    if platform.system() == 'Windows':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.error("This script requires Administrator privileges.")
                logger.error("Right-click CMD/PowerShell and select 'Run as Administrator'.")
                sys.exit(1)
        except Exception:
            pass
    else:
        if os.geteuid() != 0:
            logger.error("This script requires root privileges.")
            logger.error("Run with: sudo python3 nids_agent.py")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='NIDS Agent - Network Intrusion Detection System'
    )
    parser.add_argument(
        '--agent-name',
        default=socket.gethostname(),
        help='Name for this agent (default: system hostname)'
    )
    parser.add_argument(
        '--api-url',
        default=DEFAULT_API_URL,
        help=f'Central NIDS server URL (default: {DEFAULT_API_URL})'
    )
    parser.add_argument(
        '-i', '--interface',
        default=None,
        help='Network interface to capture on (default: all)'
    )
    parser.add_argument(
        '--log-all',
        action='store_true',
        help='Log all traffic including normal'
    )
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )

    args = parser.parse_args()

    if args.list_interfaces:
        print("\nAvailable network interfaces:")
        print("-" * 40)
        for iface in get_if_list():
            print(f"  - {iface}")
        print()
        return

    # Banner
    print("=" * 60)
    print("  NIDS AGENT — Network Intrusion Detection System")
    print("  University of Botswana - Final Year Project")
    print("=" * 60)
    print(f"  Agent Name : {args.agent_name}")
    print(f"  Server URL : {args.api_url}")
    print(f"  Machine IP : {_get_local_ip()}")
    print(f"  OS         : {platform.system()} {platform.release()}")
    print("=" * 60)
    print()

    # Check privileges
    check_privileges()

    # Model directory is in the same folder as this script
    agent_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = os.path.join(agent_dir, 'model')

    # Verify model files
    required_files = ['best_model.pkl', 'scaler.pkl', 'label_encoder.pkl', 'feature_names.pkl']
    for f in required_files:
        path = os.path.join(model_dir, f)
        if not os.path.exists(path):
            logger.error(f"Missing model file: {path}")
            logger.error("The model/ folder must be in the same directory as this script.")
            sys.exit(1)

    # Initialise
    logger.info("Loading ML model...")
    connection_tracker = ConnectionTracker()
    classifier = TrafficClassifier(
        model_dir=model_dir,
        api_url=args.api_url,
        agent_name=args.agent_name
    )

    # Start heartbeat
    logger.info(f"Connecting to server: {args.api_url}")
    heartbeat_thread = threading.Thread(
        target=_heartbeat_loop,
        args=(args.api_url, args.agent_name),
        daemon=True
    )
    heartbeat_thread.start()
    logger.info("Heartbeat started (every 30 seconds)")

    # Signal handler
    signal.signal(signal.SIGINT, signal_handler)
    if platform.system() != 'Windows':
        signal.signal(signal.SIGTERM, signal_handler)

    # Start capture
    iface = args.interface
    if iface:
        logger.info(f"Capturing on interface: {iface}")
    else:
        logger.info("Capturing on all interfaces")

    logger.info("Monitoring started. Press Ctrl+C to stop.")
    print()

    handler = create_packet_handler(
        classifier=classifier,
        connection_tracker=connection_tracker,
        log_all=args.log_all
    )

    try:
        sniff(
            iface=iface,
            prn=handler,
            store=False,
            stop_filter=lambda p: not running,
        )
    except PermissionError:
        logger.error("Permission denied. Run as admin/root.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Capture error: {e}")
        sys.exit(1)

    # Final stats
    print()
    stats = classifier.get_stats()
    print("=" * 60)
    print("SESSION SUMMARY")
    print("=" * 60)
    print(f"  Packets classified: {stats['total_classified']}")
    print(f"  Normal traffic:     {stats['normal_count']}")
    print(f"  Attacks detected:   {stats['attack_count']} ({stats['attack_percentage']}%)")
    print(f"  Alerts sent:        {stats['alerts_sent']}")
    print(f"  Errors:             {stats['errors']}")
    print("=" * 60)


if __name__ == '__main__':
    main()
