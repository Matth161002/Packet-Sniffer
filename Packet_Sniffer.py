import socket
import os
import struct
import time
import argparse
import ipaddress

from network_lookup import get_hostname, get_geolocation

# Mapping protocol numbers to protocol names
protocol_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}


# Function to parse IP header from raw packet data
def parse_ip_header(data):
    if len(data) < 20:
        raise ValueError("Packet is too short to contain an IPv4 header")

    ip_header = data[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    if version != 4:
        raise ValueError(f"Unsupported IP version: {version}")

    if ihl < 5:
        raise ValueError("Invalid IPv4 header length")

    iph_length = ihl * 4

    if len(data) < iph_length:
        raise ValueError("Packet is shorter than the IPv4 header length")

    ttl = iph[5]
    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])

    return iph_length, protocol, src_addr, dst_addr, ttl


# Function to parse TCP header
def parse_tcp_header(data):
    if len(data) < 20:
        raise ValueError("Packet is too short to contain a TCP header")

    tcp_header = data[0:20]
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)

    src_port = tcph[0]
    dst_port = tcph[1]
    sequence = tcph[2]
    acknowledgment = tcph[3]
    offset_reserved = tcph[4]

    tcp_header_length = (offset_reserved >> 4) * 4

    if tcp_header_length < 20:
        raise ValueError("Invalid TCP header length")

    if len(data) < tcp_header_length:
        raise ValueError("Packet is shorter than the TCP header length")

    return src_port, dst_port, sequence, acknowledgment, tcp_header_length


# Function to parse UDP header
def parse_udp_header(data):
    if len(data) < 8:
        raise ValueError("Packet is too short to contain a UDP header")

    udp_header = data[0:8]
    udph = struct.unpack('!HHHH', udp_header)

    src_port = udph[0]
    dst_port = udph[1]
    length = udph[2]
    checksum = udph[3]

    if length < 8:
        raise ValueError("Invalid UDP length")

    if len(data) < length:
        raise ValueError("Packet is shorter than the UDP length")

    return src_port, dst_port, length, checksum


# Function to parse ICMP header
def parse_icmp_header(data):
    if len(data) < 4:
        raise ValueError("Packet is too short to contain an ICMP header")

    icmph = struct.unpack('!BBH', data[0:4])

    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]

    return icmp_type, code, checksum


# Function to parse a complete packet and its transport-layer header
def parse_packet(raw_data):
    if not raw_data:
        raise ValueError("Received an empty packet")

    iph_length, protocol_num, src_addr, dst_addr, ttl = parse_ip_header(raw_data)

    packet = {
        "ip_header_length": iph_length,
        "protocol": protocol_num,
        "source_ip": src_addr,
        "destination_ip": dst_addr,
        "ttl": ttl,
        "transport": None
    }

    if protocol_num == 6:  # TCP
        tcp_start = iph_length
        tcp_data = raw_data[tcp_start:]

        src_port, dst_port, sequence, acknowledgment, tcp_header_length = parse_tcp_header(tcp_data)

        packet["transport"] = {
            "source_port": src_port,
            "destination_port": dst_port,
            "sequence": sequence,
            "acknowledgment": acknowledgment,
            "header_length": tcp_header_length
        }

    elif protocol_num == 17:  # UDP
        udp_start = iph_length
        udp_data = raw_data[udp_start:]

        src_port, dst_port, length, checksum = parse_udp_header(udp_data)

        packet["transport"] = {
            "source_port": src_port,
            "destination_port": dst_port,
            "length": length,
            "checksum": checksum
        }

    elif protocol_num == 1:  # ICMP
        icmp_start = iph_length
        icmp_data = raw_data[icmp_start:]

        icmp_type, code, checksum = parse_icmp_header(icmp_data)

        packet["transport"] = {
            "type": icmp_type,
            "code": code,
            "checksum": checksum
        }

    return packet



# Function to check if an IP is public (to avoid local network spam)
def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        )
    except ValueError:
        return False


# Function to automatically detect the active network interface IP
def get_active_ipv4():
    """Try to detect the real local IP used for outbound internet traffic"""
    print("Detecting active network interface IP...")

    destinations = [
        ("8.8.8.8", 80),
        ("1.1.1.1", 53),
        ("208.67.222.222", 53),
        ("google.com", 80)
    ]

    for dest, port in destinations:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)
            s.connect((dest, port))
            detected_ip = s.getsockname()[0]
            s.close()

            if (
                detected_ip.startswith("127.")
                or detected_ip.startswith("169.254.")
                or detected_ip.startswith("192.168.56.")
            ):
                print(f"  Skipped likely virtual IP: {detected_ip}")
                continue

            print(f"  Success! Using detected IP: {detected_ip}")
            return detected_ip

        except Exception as e:
            print(f"  Failed to test {dest}:{port} → {str(e)}")
            continue

    fallback = socket.gethostbyname(socket.gethostname())
    print(f"  All detection attempts failed. Falling back to: {fallback}")
    return fallback


# Parse command-line arguments (logfile name and packet count)
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Python Packet Sniffer with Geolocation"
    )
    parser.add_argument(
        '--logfile',
        type=str,
        default="sniffer_log.txt",
        help="Log file name (default: sniffer_log.txt)"
    )
    parser.add_argument(
        '--count',
        type=int,
        default=0,
        help="Number of packets to capture (0 = infinite)"
    )
    return parser.parse_args()


def main():
    global last_geo_time, geo_cache

    # Parse CLI arguments
    args = parse_arguments()

    # Open logfile with line buffering for more reliable writes on Windows
    logfile = open(args.logfile, "a", buffering=1)

    # Get local IP address
    host = get_active_ipv4()

    # Create raw socket for packet sniffing
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Windows-specific: enable promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"Listening on {host}...\n")
    print(f"Logging to {args.logfile}\n")

    packet_counter = 0

    try:
        while True:
            # Receive raw packet data
            sniffer.settimeout(0.3)

            try:
                raw_data, addr = sniffer.recvfrom(65565)
            except socket.timeout:
                continue

            # Parse the captured packet
            try:
                packet = parse_packet(raw_data)
            except ValueError as e:
                print(f"Skipping malformed packet: {e}")
                continue
            except struct.error as e:
                print(f"Skipping malformed packet: {e}")
                continue

            protocol_num = packet["protocol"]
            src_addr = packet["source_ip"]
            dst_addr = packet["destination_ip"]
            ttl = packet["ttl"]

            # Optional: skip non-public IPs
            if not is_public_ip(dst_addr):
                continue

            # Hostname resolution
            dst_hostname = get_hostname(dst_addr)
            dst_geo = get_geolocation(dst_addr)

            # Build display string with IP, hostname, and geo info
            if dst_hostname:
                dst_display = f"{dst_addr} ({dst_hostname}) [{dst_geo}]"
            else:
                dst_display = f"{dst_addr} [{dst_geo}]"

            # Build IP packet log entry
            output = (
                f"[{time.ctime()}] IP Packet: {src_addr} -> {dst_display} "
                f"| Protocol: {protocol_map.get(protocol_num, protocol_num)} "
                f"| TTL: {ttl}"
            )

            # Print and log IP packet info
            print(output)
            logfile.write(output + "\n")
            logfile.flush()

            # Display TCP information
            if protocol_num == 6:
                transport = packet["transport"]

                tcp_output = (
                    f"TCP Segment: {src_addr}:{transport['source_port']} "
                    f"-> {dst_addr}:{transport['destination_port']} "
                    f"| Seq: {transport['sequence']} "
                    f"Ack: {transport['acknowledgment']}"
                )

                print(tcp_output)
                logfile.write(tcp_output + "\n")
                logfile.flush()

            # Display UDP information
            elif protocol_num == 17:
                transport = packet["transport"]

                udp_output = (
                    f"UDP Segment: {src_addr}:{transport['source_port']} "
                    f"-> {dst_addr}:{transport['destination_port']} "
                    f"| Length: {transport['length']}"
                )

                print(udp_output)
                logfile.write(udp_output + "\n")
                logfile.flush()

            # Display ICMP information
            elif protocol_num == 1:
                transport = packet["transport"]

                icmp_output = (
                    f"ICMP Packet: {src_addr} -> {dst_addr} "
                    f"| Type: {transport['type']} "
                    f"Code: {transport['code']}"
                )

                print(icmp_output)
                logfile.write(icmp_output + "\n")
                logfile.flush()

            packet_counter += 1

            # Stop capturing if packet count limit is reached
            if args.count > 0 and packet_counter >= args.count:
                print(f"\nReached {args.count} packets. Stopping.")
                break

    except KeyboardInterrupt:
        print("\nUser interrupted.")

    finally:
        # Clean up: disable promiscuous mode on Windows and close logfile
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        logfile.flush()
        logfile.close()
        print(f"Sniffer stopped. Log saved to {args.logfile}")


# Entry point
if __name__ == "__main__":
    main()