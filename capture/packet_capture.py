"""
packet_capture.py - Real-Time Network Packet Capture and Classification
=========================================================================
This is the main entry point for the NIDS packet capture system.
It uses Scapy to sniff network traffic on the host machine, extracts
features from each packet, classifies them using the trained ML model,
and sends alerts to the backend API for attack detections.

Usage:
    sudo python3 packet_capture.py                     # Capture on default interface
    sudo python3 packet_capture.py -i eth0             # Specify interface
    sudo python3 packet_capture.py --api-url http://localhost:3001  # Specify backend URL
    sudo python3 packet_capture.py --log-all            # Log all traffic (not just attacks)

Requirements:
    - Must run with root/admin privileges (for raw packet capture)
    - Trained ML model must exist in ml/model/
    - Backend API should be running (optional, will log to console if not)

Author: University of Botswana - Final Year Project
"""

import os
import sys
import time
import signal
import argparse
import logging
from scapy.all import sniff, get_if_list, conf

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from capture.feature_extractor import extract_features, ConnectionTracker
from capture.classifier import TrafficClassifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('NIDS-Capture')

# Global flag for graceful shutdown
running = True


def signal_handler(sig, frame):
    """Handle Ctrl+C for graceful shutdown."""
    global running
    logger.info("\n[!] Shutdown signal received. Stopping capture...")
    running = False


def create_packet_handler(classifier, connection_tracker, log_all=False):
    """
    Create a packet processing callback function.

    Args:
        classifier: TrafficClassifier instance.
        connection_tracker: ConnectionTracker instance.
        log_all (bool): If True, log all traffic including normal.

    Returns:
        callable: Packet handler function for Scapy's sniff().
    """
    packet_count = [0]  # Use list for mutable closure

    def handle_packet(packet):
        """Process a single captured packet."""
        if not running:
            return

        packet_count[0] += 1

        # Extract features from packet
        features = extract_features(packet, connection_tracker)
        if features is None:
            return  # Skip non-IP packets

        # Classify the traffic
        result = classifier.classify(features)
        if result is None:
            return

        # Log based on classification
        if result['category'] != 'Normal':
            # Attack detected - send alert
            classifier.send_alert(result)

            # Print to console
            severity_icons = {'high': '!!!', 'medium': '!! ', 'low': '!  '}
            icon = severity_icons.get(result['severity'], '   ')
            logger.warning(
                f"[{icon}] {result['category']:>6} | {result['attack_type']:<30} | "
                f"{result['src_ip']:>15} -> {result['dst_ip']:>15}:{result['dst_port']:<5} | "
                f"Confidence: {result['confidence']:>6.2f}% | "
                f"Time: {result['classification_time_ms']:.2f}ms"
            )
        elif log_all:
            logger.info(
                f"[   ] Normal | "
                f"{result['src_ip']:>15} -> {result['dst_ip']:>15}:{result['dst_port']:<5} | "
                f"Confidence: {result['confidence']:>6.2f}%"
            )

        # Print periodic statistics
        if packet_count[0] % 100 == 0:
            stats = classifier.get_stats()
            logger.info(
                f"--- Stats: {stats['total_classified']} classified | "
                f"{stats['normal_count']} normal | "
                f"{stats['attack_count']} attacks ({stats['attack_percentage']}%) | "
                f"{stats['alerts_sent']} alerts sent ---"
            )

    return handle_packet


def list_interfaces():
    """Print available network interfaces."""
    print("\nAvailable network interfaces:")
    print("-" * 40)
    for iface in get_if_list():
        print(f"  - {iface}")
    print()


def main():
    """Main entry point for the NIDS packet capture system."""
    parser = argparse.ArgumentParser(
        description='NIDS - Network Intrusion Detection System (Packet Capture)'
    )
    parser.add_argument(
        '-i', '--interface',
        default=None,
        help='Network interface to capture on (default: all interfaces)'
    )
    parser.add_argument(
        '--api-url',
        default=os.environ.get('NIDS_API_URL', None),
        help='Backend API URL (default: from NIDS_API_URL env var, or log-only mode)'
    )
    parser.add_argument(
        '--log-all',
        action='store_true',
        help='Log all traffic including normal (default: attacks only)'
    )
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    parser.add_argument(
        '--model-dir',
        default=os.path.join(project_root, 'ml', 'model'),
        help='Path to the ML model directory'
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    # Print banner
    print("=" * 60)
    print("  NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
    print("  University of Botswana - Final Year Project")
    print("=" * 60)
    print()

    # Check for root privileges
    if os.geteuid() != 0:
        logger.error("This script requires root privileges for packet capture.")
        logger.error("Run with: sudo python3 packet_capture.py")
        sys.exit(1)

    # Verify model files exist
    required_files = ['best_model.pkl', 'scaler.pkl', 'label_encoder.pkl', 'feature_names.pkl']
    for f in required_files:
        path = os.path.join(args.model_dir, f)
        if not os.path.exists(path):
            logger.error(f"Missing model file: {path}")
            logger.error("Run 'python3 ml/train_model.py' first to train the model.")
            sys.exit(1)

    # Initialise components
    logger.info("Initialising NIDS components...")

    connection_tracker = ConnectionTracker()
    classifier = TrafficClassifier(
        model_dir=args.model_dir,
        api_url=args.api_url
    )

    if args.api_url:
        logger.info(f"Backend API: {args.api_url}")
    else:
        logger.info("No API URL set - running in log-only mode")
        logger.info("Set NIDS_API_URL env var or use --api-url to send alerts to backend")

    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Determine capture interface
    iface = args.interface
    if iface:
        logger.info(f"Capturing on interface: {iface}")
    else:
        logger.info("Capturing on all interfaces")

    logger.info("Starting packet capture... (Press Ctrl+C to stop)")
    print()

    # Create packet handler
    handler = create_packet_handler(
        classifier=classifier,
        connection_tracker=connection_tracker,
        log_all=args.log_all
    )

    # Start packet capture
    try:
        sniff(
            iface=iface,
            prn=handler,
            store=False,     # Don't store packets in memory
            stop_filter=lambda p: not running,
        )
    except PermissionError:
        logger.error("Permission denied. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Capture error: {e}")
        sys.exit(1)

    # Print final statistics
    print()
    stats = classifier.get_stats()
    print("=" * 60)
    print("CAPTURE SESSION SUMMARY")
    print("=" * 60)
    print(f"  Total packets classified: {stats['total_classified']}")
    print(f"  Normal traffic:           {stats['normal_count']}")
    print(f"  Attacks detected:         {stats['attack_count']} ({stats['attack_percentage']}%)")
    print(f"  Alerts sent to API:       {stats['alerts_sent']}")
    print(f"  Classification errors:    {stats['errors']}")
    print("=" * 60)


if __name__ == '__main__':
    main()
