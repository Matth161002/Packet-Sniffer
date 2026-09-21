# Packet-Sniffer

**A Python network packet sniffer that has evolved into a small network security monitoring application.**

The project captures IPv4 traffic, parses TCP, UDP and ICMP packets, analyses traffic patterns and displays the results through a desktop GUI.

The main goal is to make network traffic easier to understand and provide basic indicators of potentially unusual activity.

## Features

- IPv4 packet capture using raw sockets
- TCP, UDP and ICMP packet parsing
- Live desktop monitoring interface
- Traffic statistics
- Basic security event detection
- Possible port-scan detection
- High-traffic detection
- Reverse DNS lookups
- Optional IP geolocation
- Background network lookups
- Automated tests
- Packet validation and error handling

## GUI

The application currently provides three main views:

- **Packets** - live captured traffic with repeated traffic grouped together
- **Security Events** - potentially unusual activity detected during capture
- **Statistics** - basic information about the traffic being observed

The capture can be started, stopped and cleared without restarting the application.

## Security Events

The current detection system looks for simple patterns that may be worth investigating, including:

- High traffic volume
- Possible port scanning activity
- Connections to selected unusual destination ports

These detections are indicators rather than proof of malicious activity. The detection system is still fairly basic and will be expanded as the project develops.

## Installation

Clone the repository and install the required dependencies:

<<<<<<< HEAD
=======
```powershell
>>>>>>> 4eb2de3 (docs: improve project README)
git clone <repository-url>
cd Packet-Sniffer
pip install -r requirements.txt
```

Raw packet capture on Windows requires administrator privileges.

## Usage

Start the desktop application with:

```powershell
python security_gui.py
```

The original command-line sniffer can also be run directly:

```powershell
python Packet_Sniffer.py --count 30
```

## Testing

Tests are written using `pytest`.

Run the test suite with:

```powershell
python -m pytest
```

## Project Structure

```text
Packet-Sniffer/
├── Packet_Sniffer.py
├── packet_capture.py
├── network_lookup.py
├── traffic_analysis.py
├── security_gui.py
└── tests/
    ├── test_packet_parser.py
    └── test_traffic_analysis.py
```

## Development

The project is still being developed.

The next major step is **network flow aggregation**, moving the application away from treating every packet as a separate item and towards displaying complete network connections and flows.

Planned areas include:

- Network flow tracking
- Improved traffic detection
- TCP connection analysis
- Filtering and investigation
- Exporting captured data
- Better traffic visualisation

## Responsible Use

Packet-Sniffer is intended for use on networks and systems that you own or have permission to monitor.

See [SECURITY.md](SECURITY.md) for further information.

## Licence

<<<<<<< HEAD
MIT License.
=======
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
>>>>>>> 4eb2de3 (docs: improve project README)
