import sys
import os
import json
import time
import pickle
import numpy as np
import csv
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
from collections import defaultdict
from threading import Timer
import signal
import warnings

# Suppress sklearn warnings about feature names
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ddos_detector.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'scaler.pkl')
CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')

# Default values
DEFAULT_INTERFACE = 'Ethernet'
DEFAULT_THRESHOLD = 2000
WINDOW_SIZE = 5        

FEATURE_NAMES = ['pps', 'syn_count', 'udp_count', 'icmp_count']

packet_data = [] 
ml_model = None
scaler = None
start_time = time.time()

is_capture_mode = False
capture_filename = None
capture_writer = None
capture_file = None

sniff_interface = DEFAULT_INTERFACE
alert_threshold_pps = DEFAULT_THRESHOLD

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

def load_ml_assets():
    global ml_model, scaler
    try:
        with open(MODEL_PATH, 'rb') as f:
            ml_model = pickle.load(f)
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
    except Exception as e:
        print(f"CRITICAL ERROR: Error loading ML assets. Did you run train_model.py? Error: {e}", file=sys.stderr)
        sys.exit(1)

def close_capture_file():
    global capture_file
    if capture_file:
        capture_file.close()
        print(f"Capture finished and file saved: {capture_filename}", file=sys.stderr)

def packet_callback(packet):
    global packet_data
    
    row = {'time': time.time(), 'syn': 0, 'udp': 0, 'icmp': 0}
    
    if IP in packet:
        if TCP in packet:
            if packet[TCP].flags == 'S': 
                row['syn'] = 1
        elif UDP in packet:
            row['udp'] = 1
        elif ICMP in packet:
            row['icmp'] = 1
            
    packet_data.append(row)


def aggregate_and_analyze():
    global packet_data, start_time, capture_writer, capture_filename

    end_time = time.time()
    duration = end_time - start_time
    
    current_window_data = [p for p in packet_data if p['time'] > start_time]

    if duration > 0 and current_window_data:
        
        total_packets = len(current_window_data)
        pps = total_packets / duration
        
        syn_count = sum(p['syn'] for p in current_window_data)
        udp_count = sum(p['udp'] for p in current_window_data)
        icmp_count = sum(p['icmp'] for p in current_window_data)
        
        feature_vector = [pps, syn_count, udp_count, icmp_count]

        if is_capture_mode and capture_writer:
            
            row_data = {
                'pps': feature_vector[0],
                'syn_count': feature_vector[1],
                'udp_count': feature_vector[2],
                'icmp_count': feature_vector[3],
                'Label': 'BENIGN' 
            }
            try:
                capture_writer.writerow(row_data)
                print(f"Captured: {pps:.2f} pps (Total rows: {len(packet_data)})", file=sys.stderr)
            except Exception as e:
                print(f"Error writing capture data: {e}", file=sys.stderr)
                close_capture_file()
                sys.exit(1)

        elif not is_capture_mode:
            X_test = np.array([feature_vector])
            
            X_scaled = scaler.transform(X_test)
            
            prediction = ml_model.predict(X_scaled)[0]
            
            is_attack = (prediction != 0) or (pps > alert_threshold_pps)

            alert = {
                "timestamp": time.strftime("%H:%M:%S"),
                "pps": f"{pps:.2f}",
                "status": "ATTACK DETECTED" if is_attack else "Normal",
                "reason": "ML Model Classified as Attack" if prediction != 0 else "High PPS Heuristic",
                "action": "Check active connections."
            }
            
            print(json.dumps(alert))
            sys.stdout.flush()
        
        packet_data = [] 
        start_time = time.time()
        
    from threading import Timer
    Timer(WINDOW_SIZE, aggregate_and_analyze).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DDoS Detector Sniffer')
    parser.add_argument('mode', nargs='?', choices=['capture', 'detect'], default='detect', help='Mode: capture or detect')
    parser.add_argument('filename', nargs='?', help='Output filename for capture mode')
    parser.add_argument('--interface', help='Network interface to sniff on')
    parser.add_argument('--threshold', type=int, help='PPS threshold for alerts')
    
    args = parser.parse_args()
    
    config = load_config()
    sniff_interface = args.interface or config.get('sniff_interface', DEFAULT_INTERFACE)
    alert_threshold_pps = args.threshold or config.get('pps_threshold', DEFAULT_THRESHOLD)

    if args.mode == 'capture':
        is_capture_mode = True
        if not args.filename:
            print("Usage: python backend/sniffer_ml.py capture <output_filename.csv>", file=sys.stderr)
            sys.exit(1)
        
        capture_filename = args.filename
        
        try:
            capture_file = open(capture_filename, 'w', newline='')
            fieldnames = ['pps', 'syn_count', 'udp_count', 'icmp_count', 'Label']
            capture_writer = csv.DictWriter(capture_file, fieldnames=fieldnames)
            capture_writer.writeheader()
            print(f"Entering CAPTURE MODE. Saving features to: {capture_filename}", file=sys.stderr)
            
            signal.signal(signal.SIGINT, lambda s, f: (close_capture_file(), sys.exit(0)))
            
        except Exception as e:
            print(f"Error opening capture file: {e}", file=sys.stderr)
            sys.exit(1)
            
    else:
        load_ml_assets()
        print(f"Starting Sniffer on {sniff_interface} with PPS Threshold: {alert_threshold_pps}", file=sys.stderr)

    # Start command listener thread
    import threading
    def command_listener():
        global alert_threshold_pps
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                data = json.loads(line)
                if data.get('command') == 'update_threshold':
                    new_threshold = int(data.get('value'))
                    alert_threshold_pps = new_threshold
                    print(f"Threshold updated to: {alert_threshold_pps}", file=sys.stderr)
            except ValueError:
                continue
            except Exception as e:
                print(f"Command listener error: {e}", file=sys.stderr)

    listener_thread = threading.Thread(target=command_listener, daemon=True)
    listener_thread.start()

    aggregate_and_analyze()
    
    print("Sniffer started. Waiting for packets...", file=sys.stderr)
    try:
        sniff(iface=sniff_interface, prn=packet_callback, store=0)
    except Exception as e:
        print(f"Sniffer failed. Run as root/admin. Error: {e}", file=sys.stderr)
        close_capture_file()
        sys.exit(1)
