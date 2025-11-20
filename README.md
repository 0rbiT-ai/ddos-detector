# DDoS Detector & Mitigation System

A real-time DDoS detection system using Electron for the frontend and Python (Scikit-learn) for the backend. It captures network traffic, analyzes it using a Random Forest model, and detects potential DDoS attacks based on packet patterns and PPS (Packets Per Second) thresholds.

## Features
- **Real-time Packet Sniffing**: Captures TCP/UDP/ICMP packets.
- **ML-based Detection**: Uses a trained Random Forest classifier.
- **Heuristic Detection**: Alerts on high PPS spikes.
- **Attack Simulation**: Built-in traffic generator to simulate SYN floods.
- **Dynamic Configuration**: Update PPS threshold in real-time without restarting.
- **Configurable**: Select network interface, target IP, and thresholds via UI.

## Prerequisites

### 1. Install Node.js
Ensure you have Node.js installed (v16+ recommended).

### 2. Install Python & Dependencies
Ensure you have Python 3.x installed.
Install the required Python libraries:
```bash
pip install -r requirements.txt
```

### 3. Install Npcap (Windows Only)
For packet sniffing to work on Windows, you **MUST** install [Npcap](https://npcap.com/#download).
- During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.

## Installation

1. Clone the repository.
2. Install Electron dependencies:
```bash
npm install
```

## Usage

### Running the Application
**IMPORTANT**: You must run the application as **Administrator** (Windows) or **Root** (Linux/macOS) because packet sniffing requires raw socket access.

```bash
# Open PowerShell or Command Prompt as Administrator
npm start
```

### Using the Dashboard
1. **Select Interface**: Choose the network interface you want to monitor (e.g., Wi-Fi or Ethernet).
2. **Set Threshold**: Adjust the PPS Threshold (default 2000) for alerts. **Note**: You can change this value dynamically while the system is running!
3. **Start System**: Click "Start System" to begin monitoring.
4. **Simulate Attack**:
    - Enter a Target IP (e.g., your local IP or 127.0.0.1).
    - Set Packet Count.
    - Click "Simulate Attack" to generate traffic and see if the system detects it.

## Troubleshooting
- **Sniffer Error**: If you see "Sniffer failed", ensure you installed Npcap and are running as Administrator.
- **No Interfaces**: If the dropdown is empty, check your network connection.
