# Packet Sniffer using Scapy
# This script captures network packets and prints their details to the console
# It requires root privileges on Linux/Mac or Administrator rights on Windows

import os
import sys
from datetime import datetime

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    from scapy.all import sniff, conf
    from scapy.layers.inet import IP, TCP, UDP

    # Check for permissions
    if os.name == 'nt': # Windows
        
        conf.use_pcap = True
        print("[INFO] Running on Windows. Ensure Npcap is installed and you run this script as Administrator.")
    elif os.geteuid() != 0: # Linux/Mac
        print("[ERROR] This script needs root privileges on Linux/Mac.")
        print("[INFO] Please run using 'sudo python3 simple_sniffer.py'")
        # Exit if not root, as sniffing won't work

except ImportError:
    print("[ERROR] Scapy library not found. Please install it:")
    print("  pip install scapy")
    sys.exit(1)
except OSError as e:
    if "Operation not permitted" in str(e) or os.name != 'nt' and os.geteuid() != 0:
        print("[ERROR] Permission denied. Run as root (Linux/Mac) or Administrator (Windows).")
    else:
        print(f"[ERROR] An OS error occurred: {e}")
    sys.exit(1)

def process_packet(packet):
    """This function is called for every packet captured."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto # Protocol number

        src_port = "*"
        dst_port = "*"

        # Check for TCP
        if proto == 6 and TCP in packet:
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol_name = "TCP"
        # Check for UDP
        elif proto == 17 and UDP in packet:
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol_name = "UDP"
        # Check for ICMP
        elif proto == 1:
            protocol_name = "ICMP"
        # Other protocols
        else:
            protocol_name = f"Other({proto})"

        print(f"[{timestamp}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} Protocol: {protocol_name}")


print("[INFO] Starting packet sniffer...")
print("[INFO] Press Ctrl+C to stop.")

try:
    sniff(prn=process_packet, store=0, iface=None)
except Exception as e:
    print(f"\n[ERROR] An error occurred during sniffing: {e}")
    if os.name == 'nt':
        print("[INFO] On Windows, ensure Npcap is installed and running, and the script has Administrator rights.")
    elif os.geteuid() != 0:
        print("[INFO] On Linux/Mac, ensure you are running with 'sudo'.")
finally:
    print("\n[INFO] Sniffer stopped.")

