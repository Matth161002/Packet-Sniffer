from dataclasses import dataclass
import time


@dataclass
class NetworkFlow:
    """Represent a bidirectional network flow."""

    protocol: int
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def duration(self):
        """Return the elapsed time between the first and last packet."""
        return max(
            0.0,
            self.last_seen - self.first_seen
        )

    def update(self, packet, timestamp, packet_length):
        """Add a packet to the flow."""
        is_forward = (
            packet["source_ip"] == self.source_ip
            and packet["destination_ip"] == self.destination_ip
        )

        self.packet_count += 1
        self.byte_count += packet_length

        if is_forward:
            self.forward_packets += 1
        else:
            self.reverse_packets += 1

        if self.first_seen == 0.0:
            self.first_seen = timestamp

        self.last_seen = timestamp

    def to_dict(self):
        """Return the flow as a serialisable dictionary."""
        return {
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "forward_packets": self.forward_packets,
            "reverse_packets": self.reverse_packets,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration
        }


class FlowAggregator:
    """Group packets into bidirectional network flows."""

    def __init__(self):
        """Initialise the flow collection."""
        self.flows = {}

    @staticmethod
    def _get_endpoint(packet, source=True):
        """Return an endpoint consisting of IP address and port."""
        ip_key = "source_ip" if source else "destination_ip"
        ip_address = packet[ip_key]

        transport = packet.get("transport")

        if transport and transport.get("type") in {"TCP", "UDP"}:
            port_key = (
                "source_port"
                if source
                else "destination_port"
            )

            port = transport.get(port_key)

        else:
            port = None

        return ip_address, port

    @classmethod
    def _get_flow_key(cls, packet):
        """Create a direction-independent key for a packet."""
        source_endpoint = cls._get_endpoint(
            packet,
            source=True
        )

        destination_endpoint = cls._get_endpoint(
            packet,
            source=False
        )

        endpoints = tuple(
            sorted(
                (
                    source_endpoint,
                    destination_endpoint
                )
            )
        )

        return (
            packet["protocol"],
            endpoints
        )

    def update(self, packet, timestamp=None):
        """Add a packet to its flow and return the updated flow."""
        if timestamp is None:
            timestamp = time.time()

        packet_length = packet.get(
            "packet_length",
            0
        )

        key = self._get_flow_key(
            packet
        )

        flow = self.flows.get(key)

        if flow is None:
            flow = NetworkFlow(
                protocol=packet["protocol"],
                source_ip=packet["source_ip"],
                destination_ip=packet["destination_ip"],
                source_port=self._get_endpoint(
                    packet,
                    source=True
                )[1],
                destination_port=self._get_endpoint(
                    packet,
                    source=False
                )[1]
            )

            self.flows[key] = flow

        flow.update(
            packet,
            timestamp,
            packet_length
        )

        return flow

    def get_flows(self):
        """Return flows ordered by most recently observed traffic."""
        return sorted(
            self.flows.values(),
            key=lambda flow: flow.last_seen,
            reverse=True
        )

    def get_statistics(self):
        """Return summary statistics for the aggregated flows."""
        flows = list(
            self.flows.values()
        )

        return {
            "total_flows": len(flows),
            "total_packets": sum(
                flow.packet_count
                for flow in flows
            ),
            "total_bytes": sum(
                flow.byte_count
                for flow in flows
            )
        }

    def reset(self):
        """Remove all tracked flows."""
        self.flows.clear()
