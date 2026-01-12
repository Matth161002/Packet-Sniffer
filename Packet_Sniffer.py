import socket
import os
import struct
import time
import argparse
import requests
import ipaddress

# Global variables for geolocation rate limiting and caching
last_geo_time = 0.0
geo_cache = {} # Cache: IP → geo string
# Mapping protocol numbers to protocol names
protocol_map = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}


# Function to parse IP header from raw packet data
def parse_ip_header(data):
    ip_header = data[0:20]  # IP header is always the first 20 bytes
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4  # High 4 bits are version
    ihl = version_ihl & 0xF     # Low 4 bits are Internet Header Length
    iph_length = ihl * 4        # Calculate actual header length in bytes

    ttl = iph[5]
    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])  # Convert 4-byte IP to string
    dst_addr = socket.inet_ntoa(iph[9])

    return iph_length, protocol, src_addr, dst_addr, ttl

# Function to parse TCP header (only called for TCP packets)
def parse_tcp_header(data):
    tcp_header = data[0:20]  # TCP header is at least 20 bytes
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)

    src_port = tcph[0]
    dst_port = tcph[1]
    sequence = tcph[2]
    acknowledgment = tcph[3]
    offset_reserved = tcph[4]
    tcp_header_length = (offset_reserved >> 4) * 4  # Header length in bytes

    return src_port, dst_port, sequence, acknowledgment, tcp_header_length

# Function to parse UDP header (only called for UDP packets)
def parse_udp_header(data):
    udp_header = data[0:8]
    udph = struct.unpack('!HHHH', udp_header)

    src_port = udph[0]
    dst_port = udph[1]
    length = udph[2]
    checksum = udph[3]

    return src_port, dst_port, length, checksum

# Function to parse ICMP header (only called for ICMP packets)
def parse_icmp_header(data):
    icmph = struct.unpack('!BBH', data[0:4])
    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]

    return icmp_type, code, checksum

# Function to resolve IP address to hostname
def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]  # Fixed: spcket → socket
        return hostname
    except socket.herror:
        return None # No reverse DNS record
    except socket.gaierror:
        return None # Invalid IP or DNS issue
    except Exception as e:
        print(f"Hostname lookup error for {ip}: {e}") # Optional: log error
        return None

# Function to resolve Geolocation using ip-api.com
def geolocate_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,org,query", timeout=5)
        if response.status_code == 200:
            data = response.json()
            country = data.get('country', '')
            city = data.get('city', '')
            org = data.get('org', '')
            return f"{city}, {country} ({org})"
        else:
            return "Geo lookup failed"
    except requests.RequestException:
        return "Geo lookup error"

# Function to check if an IP is public (avoid local network spam)
def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved)
    except ValueError:
        return False

# Function to automatically detect the active network interface IP
def get_active_ipv4():
    """Try to detect the real local IP used for outbound internet traffic"""
    print("Detecting active network interface IP...")

    destinations = [
        ("8.8.8.8", 80), # Google DNS
        ("1.1.1.1", 53), # Cloudflare DNS
        ("208.67.222.222", 53), # OpenDNS
        ("google.com", 80) # Forces real DNS resolution
    ]

    for dest, port in destinations:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0) # Short timeout to avoid hanging
            s.connect((dest, port))
            detected_ip = s.getsockname()[0]
            s.close()

            # Skip known bad/private/virtual ranges
            if (detected_ip.startswith("127.") or
                detected_ip.startswith("169.254.") or
                detected_ip.startswith("192.168.56.")):
                print(f"  Skipped Likely virtual IP: {detected_ip}")
                continue

            print(f"  Success! Using detected IP: {detected_ip}")
            return detected_ip
        except Exception as e:
            print(f"  Failed to test {dest}:{port} → {str(e)}")
            continue

    # Fallback method if all tests fail
    fallback = socket.gethostbyname(socket.gethostname())
    print(f"  All detection attempts failed. Falling back to: {fallback}")
    return fallback

# Parse command-line arguments (logfile name and packet count)
def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced Python Packet Sniffer with Geolocation")
    parser.add_argument('--logfile', type=str, default="sniffer_log.txt", help="Log file name (default: sniffer_log.txt)")
    parser.add_argument('--count', type=int, default=0, help="Number of packets to capture (0 = infinite)")
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
    sniffer.bind((host, 0))  # Bind to local interface
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers in received packets

    # Windows-specific: enable promiscuous mode
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"Listening on {host}...\n")
    print(f"Logging to {args.logfile}\n")

    packet_counter = 0

    try:
        while True:
            # Receive raw packet data
            sniffer.settimeout(0.3) # wake up every ~300 ms
            try:
               raw_data, addr = sniffer.recvfrom(65565)
            except socket.timeout:
               continue # go back to while loop

            # Parse IP header
            iph_length, protocol_num, src_addr, dst_addr, ttl = parse_ip_header(raw_data)

            # Optional: skip non-public IPs
            if not is_public_ip(dst_addr):
                continue

            # Hostname resolution
            dst_hostname = resolve_hostname(dst_addr)

            # Geolocation resolution with rate limiting + caching
            if dst_addr in geo_cache:
                dst_geo = geo_cache[dst_addr]
            else:
                current_time = time.time()
                if current_time - last_geo_time >= 2.0: # Max 1 lookup every 2 seconds
                    dst_geo = geolocate_ip(dst_addr)
                    geo_cache[dst_addr] = dst_geo
                    last_geo_time = current_time
                else:
                    dst_geo = "Geo rate-limited"

            # Build display string with IP, hostname, and geo info
            if dst_hostname:
                dst_display = f"{dst_addr} ({dst_hostname}) [{dst_geo}]"
            else:
                dst_display = f"{dst_addr} [{dst_geo}]"

            # Build IP packet log entry
            output = f"[{time.ctime()}] IP Packet: {src_addr} -> {dst_display} | Protocol: {protocol_map.get(protocol_num, protocol_num)} | TTL: {ttl}"

            # Print and log IP packet info
            print(output)
            logfile.write(output + "\n")
            logfile.flush() # Force write to disk

            # If it's a TCP packet, parse TCP header too
            if protocol_num == 6:  # TCP
                tcp_start = iph_length  # TCP header starts after IP header
                tcp_data = raw_data[tcp_start:tcp_start+20]

                src_port, dst_port, sequence, acknowledgment, tcp_header_length = parse_tcp_header(tcp_data)

                tcp_output = f"TCP Segment: {src_addr}:{src_port} -> {dst_addr}:{dst_port} | Seq: {sequence} Ack: {acknowledgment}"

                print(tcp_output)
                logfile.write(tcp_output + "\n")
                logfile.flush() # Force write to disk

            # If it's a UDP packet, parse UDP header too
            elif protocol_num == 17:  # UDP
                udp_start = iph_length
                udp_data = raw_data[udp_start:udp_start+8]
                src_port, dst_port, length, checksum = parse_udp_header(udp_data)

                udp_output = f"UDP Segment: {src_addr}:{src_port} -> {dst_addr}:{dst_port} | Length: {length}"
                print(udp_output)
                logfile.write(udp_output + "\n")
                logfile.flush() # Force write to disk

            # If it's an ICMP packet, parse ICMP header too
            elif protocol_num == 1:  # ICMP
                icmp_start = iph_length
                icmp_data = raw_data[icmp_start:icmp_start+4]
                icmp_type, code, checksum = parse_icmp_header(icmp_data)

                icmp_output = f"ICMP Packet: {src_addr} -> {dst_addr} | Type: {icmp_type} Code: {code}"
                print(icmp_output)
                logfile.write(icmp_output + "\n")
                logfile.flush() # Force write to disk

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
