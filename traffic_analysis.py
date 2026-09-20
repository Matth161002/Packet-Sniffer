import time
from collections import Counter, defaultdict, deque


class TrafficAnalyzer:
    """Analyse captured traffic and identify potentially unusual behaviour."""

    HIGH_TRAFFIC_THRESHOLD = 20
    HIGH_TRAFFIC_WINDOW = 10

    PORT_SCAN_THRESHOLD = 5
    PORT_SCAN_WINDOW = 10

    UNUSUAL_PORTS = {
        21,
        23,
        25,
        110,
        135,
        139,
        445,
        1433,
        3389,
        5900
    }

    def __init__(self):
        """Initialise traffic statistics and detection state."""
        self.total_packets = 0

        self.protocol_counts = Counter()
        self.destination_counts = Counter()
        self.port_counts = Counter()

        self.destination_history = defaultdict(deque)
        self.port_history = defaultdict(deque)

        self.reported_high_traffic = set()
        self.reported_port_scans = set()
        self.reported_unusual_ports = set()

    def analyse_packet(self, packet):
        """Analyse a packet and return any security events it generates."""
        self.total_packets += 1

        destination_ip = packet["destination_ip"]
        protocol = packet["protocol"]

        self.protocol_counts[protocol] += 1
        self.destination_counts[destination_ip] += 1

        current_time = time.time()

        self.destination_history[destination_ip].append(
            current_time
        )

        self._remove_old_entries(
            self.destination_history[destination_ip],
            current_time,
            self.HIGH_TRAFFIC_WINDOW
        )

        events = []

        high_traffic_event = self._check_high_traffic(
            destination_ip
        )

        if high_traffic_event:
            events.append(high_traffic_event)

        transport = packet["transport"]

        if transport:
            destination_port = transport.get("destination_port")

            if destination_port is not None:
                self.port_counts[destination_port] += 1

                self.port_history[destination_ip].append(
                    (
                        current_time,
                        destination_port
                    )
                )

                self._remove_old_port_entries(
                    destination_ip,
                    current_time
                )

                unusual_port_event = self._check_unusual_port(
                    destination_ip,
                    destination_port
                )

                if unusual_port_event:
                    events.append(unusual_port_event)

                port_scan_event = self._check_port_scan(
                    destination_ip
                )

                if port_scan_event:
                    events.append(port_scan_event)

        return events

    def _check_high_traffic(self, destination_ip):
        """Detect a high volume of packets to one destination."""
        packet_times = self.destination_history[destination_ip]

        if len(packet_times) < self.HIGH_TRAFFIC_THRESHOLD:
            return None

        if destination_ip in self.reported_high_traffic:
            return None

        self.reported_high_traffic.add(destination_ip)

        return {
            "type": "HIGH_TRAFFIC",
            "severity": "WARNING",
            "message": (
                f"High traffic volume detected for "
                f"{destination_ip}: "
                f"{len(packet_times)} packets in "
                f"{self.HIGH_TRAFFIC_WINDOW} seconds"
            )
        }

    def _check_port_scan(self, destination_ip):
        """Detect multiple destination ports contacted on one host."""
        history = self.port_history[destination_ip]

        unique_ports = {
            destination_port
            for _, destination_port in history
        }

        if len(unique_ports) < self.PORT_SCAN_THRESHOLD:
            return None

        if destination_ip in self.reported_port_scans:
            return None

        self.reported_port_scans.add(destination_ip)

        ports = sorted(unique_ports)

        return {
            "type": "POSSIBLE_PORT_SCAN",
            "severity": "WARNING",
            "message": (
                f"Possible port scanning activity against "
                f"{destination_ip}. "
                f"{len(ports)} different destination ports "
                f"were contacted within "
                f"{self.PORT_SCAN_WINDOW} seconds: "
                f"{ports}"
            )
        }

    def _check_unusual_port(self, destination_ip, destination_port):
        """Detect connections to ports commonly associated with legacy or administrative services."""
        port_key = (
            destination_ip,
            destination_port
        )

        if destination_port not in self.UNUSUAL_PORTS:
            return None

        if port_key in self.reported_unusual_ports:
            return None

        self.reported_unusual_ports.add(port_key)

        return {
            "type": "UNUSUAL_PORT",
            "severity": "INFO",
            "message": (
                f"Connection to destination port "
                f"{destination_port} on {destination_ip}. "
                f"This port is commonly associated with "
                f"legacy or administrative services."
            )
        }

    def _remove_old_entries(
        self,
        history,
        current_time,
        window
    ):
        """Remove timestamps outside the specified time window."""
        while history:
            if current_time - history[0] <= window:
                break

            history.popleft()

    def _remove_old_port_entries(
        self,
        destination_ip,
        current_time
    ):
        """Remove port observations outside the scan detection window."""
        history = self.port_history[destination_ip]

        while history:
            timestamp, _ = history[0]

            if current_time - timestamp <= self.PORT_SCAN_WINDOW:
                break

            history.popleft()

    def get_statistics(self):
        """Return a snapshot of the collected traffic statistics."""
        return {
            "total_packets": self.total_packets,
            "protocol_counts": dict(self.protocol_counts),
            "destination_counts": dict(self.destination_counts),
            "port_counts": dict(self.port_counts)
        }