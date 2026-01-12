# Personal Network Traffic Sniffer

A lightweight, pure-Python packet sniffer that monitors your own outbound internet traffic with geolocation, hostname resolution, and detailed protocol information.

**Important**: This tool is designed **exclusively for monitoring your own device's network traffic** on networks you own or have explicit permission to analyze.  


## Features

- Automatically detects the correct network interface (avoids VirtualBox/VMware adapters)
- Captures and parses IP, TCP, UDP, and ICMP packets
- Shows real-time information:
  - Source → Destination IP
  - Resolved hostname (reverse DNS)
  - Approximate geolocation + ISP (via ip-api.com)
  - Protocol, ports, sequence/ack numbers (TCP), type/code (ICMP)
- Smart geolocation:
  - Rate-limited (1 request every 2 seconds)
  - Caches results for repeated destinations
  - Only queries public IPs
- Saves all captured packets to a timestamped log file
- Easy to run with command-line options (`--count`, `--logfile`)
- Works on Windows (requires admin privileges)

## Requirements

- Python 3.8+
- Windows (tested on Windows 11)
- Administrator privileges (CMD/Powershell) (needed for raw sockets + promiscuous mode)

### Python packages
bash
pip install requests

#### How to Run

**Always run as Administrator** (right-click PowerShell/CMD → "Run as administrator").

First, open PowerShell or Command Prompt and navigate to the folder containing the script (resulting log file is automatically saved to this folder):

powershell
cd C:\Users\YourUsername\Documents\Python    ← change to your actual path

- Example 1. Capture 500 packets, custom log file
python psniffer.py --count 500 --logfile steam_activity.log

- Example 2. Run forever (until Ctrl+C), default log file
python psniffer.py

- Example 3. Short test (good for first run)
python psniffer.py --count 100 --logfile quick_test.log
