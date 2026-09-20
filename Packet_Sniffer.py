import socket
import os
import struct
import time
import argparse
import ipaddress

from network_lookup import NetworkLookupWorker
from traffic_analysis import TrafficAnalyzer


protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}


def parse_ip_header(data):
    """Parse and validate the IPv4 header."""
    if len(data) < 20:
        raise ValueError("Packet is too short to contain an IPv4 header")

    version = data[0] >> 4

    if version != 4:
        raise ValueError("Packet is not IPv4")

    ihl = data[0] & 0x0F
    iph_length = ihl * 4

    if ihl < 5:
        raise ValueError("Invalid IPv4 header length")

    if len(data) < iph_length:
        raise ValueError("Packet is shorter than the IPv4 header length")

    iph = struct.unpack(
        "!BBHHHBBH4s4s",
        data[:20]
    )

    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])
    ttl = iph[5]

    return iph_length, protocol, src_addr, dst_addr, ttl


def parse_tcp_header(data):
    """Parse and validate the TCP header."""
    if len(data) < 20:
        raise ValueError("Packet is too short to contain a TCP header")

    tcph = struct.unpack(
        "!HHLLBBHHH",
        data[:20]
    )

    src_port = tcph[0]
    dst_port = tcph[1]
    sequence = tcph[2]
    acknowledgment = tcph[3]

    tcp_header_length = (tcph[4] >> 4) * 4

    if tcp_header_length < 20:
        raise ValueError("Invalid TCP header length")

    if len(data) < tcp_header_length:
        raise ValueError("Packet is shorter than the TCP header length")

    return (
        src_port,
        dst_port,
        sequence,
        acknowledgment,
        tcp_header_length
    )


def parse_udp_header(data):
    """Parse and validate the UDP header."""
    if len(data) < 8:
        raise ValueError("Packet is too short to contain a UDP header")

    udph = struct.unpack(
        "!HHHH",
        data[:8]
    )

    src_port = udph[0]
    dst_port = udph[1]
    length = udph[2]
    checksum = udph[3]

    if length < 8:
        raise ValueError("Invalid UDP length")

    if len(data) < length:
        raise ValueError("Packet is shorter than the UDP length")

    return src_port, dst_port, length, checksum


def parse_icmp_header(data):
    """Parse and validate the ICMP header."""
    if len(data) < 4:
        raise ValueError("Packet is too short to contain an ICMP header")

    icmph = struct.unpack(
        "!BBH",
        data[:4]
    )

    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]

    return icmp_type, code, checksum


def parse_packet(raw_data):
    """Parse an IPv4 packet and its transport-layer header."""
    if not raw_data:
        raise ValueError("Packet is empty")

    (
        iph_length,
        protocol,
        src_addr,
        dst_addr,
        ttl
    ) = parse_ip_header(raw_data)

    packet = {
        "ip_header_length": iph_length,
        "protocol": protocol,
        "source_ip": src_addr,
        "destination_ip": dst_addr,
        "ttl": ttl,
        "transport": None
    }

    transport_data = raw_data[iph_length:]

    if protocol == 6:
        (
            src_port,
            dst_port,
            sequence,
            acknowledgment,
            tcp_header_length
        ) = parse_tcp_header(transport_data)

        packet["transport"] = {
            "type": "TCP",
            "source_port": src_port,
            "destination_port": dst_port,
            "sequence": sequence,
            "acknowledgment": acknowledgment,
            "header_length": tcp_header_length
        }

    elif protocol == 17:
        (
            src_port,
            dst_port,
            length,
            checksum
        ) = parse_udp_header(transport_data)

        packet["transport"] = {
            "type": "UDP",
            "source_port": src_port,
            "destination_port": dst_port,
            "length": length,
            "checksum": checksum
        }

    elif protocol == 1:
        (
            icmp_type,
            code,
            checksum
        ) = parse_icmp_header(transport_data)

        packet["transport"] = {
            "type": "ICMP",
            "type_code": icmp_type,
            "code": code,
            "checksum": checksum
        }

    return packet


def is_public_ip(ip):
    """Determine whether an IP address is publicly routable."""
    try:
        address = ipaddress.ip_address(ip)

        return not (
            address.is_private
            or address.is_loopback
            or address.is_multicast
            or address.is_reserved
        )

    except ValueError:
        return False


def get_active_ipv4():
    """Determine the host's active IPv4 address."""
    test_addresses = [
        ("8.8.8.8", 80),
        ("1.1.1.1", 53),
        ("208.67.222.222", 53),
        ("google.com", 80)
    ]

    for address, port in test_addresses:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        try:
            sock.settimeout(2)
            sock.connect((address, port))

            local_ip = sock.getsockname()[0]

            if local_ip and not local_ip.startswith("127."):
                return local_ip

        except OSError:
            continue

        finally:
            sock.close()

    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        if local_ip and not local_ip.startswith("127."):
            return local_ip

    except socket.gaierror:
        pass

    return "Unknown"


def handle_lookup_result(future):
    """Display network metadata when a background lookup finishes."""
    try:
        result = future.result()

        if result is None:
            return

        ip = result["ip"]
        hostname = result["hostname"]
        geolocation = result["geolocation"]

        print(
            f"Lookup result for {ip}: "
            f"Hostname={hostname or 'Unknown'}, "
            f"Location={geolocation}"
        )

    except Exception as e:
        print(f"Network lookup error: {e}")


def display_security_event(event):
    """Display a security event generated by the traffic analyser."""
    severity = event["severity"]
    message = event["message"]

    print(
        f"[{severity}] {message}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Capture and analyse IPv4 network traffic."
    )

    parser.add_argument(
        "--logfile",
        default="sniffer_log.txt",
        help="Path to the packet log file."
    )

    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture. Use 0 for unlimited capture."
    )

    args = parser.parse_args()

    lookup_worker = NetworkLookupWorker()
    traffic_analyzer = TrafficAnalyzer()

    packet_count = 0

    try:
        active_ip = get_active_ipv4()

        print(f"Active IPv4 address: {active_ip}")

        with open(
            args.logfile,
            "a",
            encoding="utf-8"
        ) as logfile:

            # Create a raw socket for IPv4 packet capture.
            sniffer = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP
            )

            sniffer.bind((active_ip, 0))

            sniffer.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_HDRINCL,
                1
            )

            # Windows requires promiscuous mode to receive all local traffic.
            if os.name == "nt":
                sniffer.ioctl(
                    socket.SIO_RCVALL,
                    socket.RCVALL_ON
                )

            sniffer.settimeout(0.3)

            try:
                while (
                    args.count == 0
                    or packet_count < args.count
                ):

                    try:
                        raw_data, _ = sniffer.recvfrom(65535)

                    except socket.timeout:
                        continue

                    try:
                        packet = parse_packet(raw_data)

                    except (ValueError, struct.error) as e:
                        print(f"Skipping malformed packet: {e}")
                        continue

                    src_addr = packet["source_ip"]
                    dst_addr = packet["destination_ip"]

                    if not is_public_ip(dst_addr):
                        continue

                    protocol = packet["protocol"]

                    protocol_name = protocol_map.get(
                        protocol,
                        f"Unknown ({protocol})"
                    )

                    timestamp = time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

                    packet_count += 1

                    # Analyse the packet locally before displaying it.
                    security_events = traffic_analyzer.analyse_packet(
                        packet
                    )

                    for event in security_events:
                        display_security_event(event)

                        logfile.write(
                            f"[{timestamp}] "
                            f"[{event['severity']}] "
                            f"{event['message']}\n"
                        )

                    # Submit metadata lookups without blocking packet capture.
                    lookup_future, is_new_lookup = lookup_worker.submit(
                        dst_addr
                    )

                    if is_new_lookup:
                        lookup_future.add_done_callback(
                            handle_lookup_result
                        )

                    output = (
                        f"[{timestamp}] "
                        f"Packet #{packet_count}: "
                        f"{src_addr} -> {dst_addr} "
                        f"Protocol={protocol_name} "
                        f"TTL={packet['ttl']}"
                    )

                    print(output)
                    logfile.write(output + "\n")

                    transport = packet["transport"]

                    if transport:

                        if transport["type"] == "TCP":
                            tcp_output = (
                                f"  TCP: "
                                f"{transport['source_port']} -> "
                                f"{transport['destination_port']} "
                                f"Seq={transport['sequence']} "
                                f"Ack={transport['acknowledgment']} "
                                f"Header Length={transport['header_length']}"
                            )

                            print(tcp_output)
                            logfile.write(tcp_output + "\n")

                        elif transport["type"] == "UDP":
                            udp_output = (
                                f"  UDP: "
                                f"{transport['source_port']} -> "
                                f"{transport['destination_port']} "
                                f"Length={transport['length']} "
                                f"Checksum={transport['checksum']}"
                            )

                            print(udp_output)
                            logfile.write(udp_output + "\n")

                        elif transport["type"] == "ICMP":
                            icmp_output = (
                                f"  ICMP: "
                                f"Type={transport['type_code']} "
                                f"Code={transport['code']} "
                                f"Checksum={transport['checksum']}"
                            )

                            print(icmp_output)
                            logfile.write(icmp_output + "\n")

                    logfile.flush()

            except KeyboardInterrupt:
                print("\nStopping packet capture...")

            finally:
                # Disable promiscuous mode before closing the socket.
                if os.name == "nt":
                    try:
                        sniffer.ioctl(
                            socket.SIO_RCVALL,
                            socket.RCVALL_OFF
                        )
                    except OSError:
                        pass

                sniffer.close()

    finally:
        # Wait for outstanding metadata lookups before shutting down.
        lookup_worker.shutdown()

    statistics = traffic_analyzer.get_statistics()

    print("\nTraffic summary:")
    print(f"Total packets: {statistics['total_packets']}")

    print("\nProtocols:")

    for protocol, count in statistics["protocol_counts"].items():
        protocol_name = protocol_map.get(
            protocol,
            f"Unknown ({protocol})"
        )

        print(
            f"  {protocol_name}: {count}"
        )

    print("\nTop destinations:")

    for destination, count in sorted(
        statistics["destination_counts"].items(),
        key=lambda item: item[1],
        reverse=True
    )[:10]:

        print(
            f"  {destination}: {count}"
        )

    print("\nTop destination ports:")

    for port, count in sorted(
        statistics["port_counts"].items(),
        key=lambda item: item[1],
        reverse=True
    )[:10]:

        print(
            f"  {port}: {count}"
        )

    print(f"\nCaptured {packet_count} packets.")
    print(f"Log saved to {args.logfile}")


if __name__ == "__main__":
    main()