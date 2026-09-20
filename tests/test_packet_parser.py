import struct
import socket

import pytest

from Packet_Sniffer import (
    parse_ip_header,
    parse_tcp_header,
    parse_udp_header,
    parse_icmp_header,
    parse_packet
)


# Build a minimal IPv4 header for use in the parser tests.
# The header contains the fields required by parse_ip_header().
def create_ipv4_header(protocol, source_ip, destination_ip, ihl=5):
    version_ihl = (4 << 4) | ihl

    return struct.pack(
        '!BBHHHBBH4s4s',
        version_ihl,
        0,
        40,
        0,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip)
    )


# Build a minimal TCP header containing known test values.
# Using fixed values makes it possible to verify that each field
# is extracted correctly by the parser.
def create_tcp_header(source_port, destination_port):
    return struct.pack(
        '!HHLLBBHHH',
        source_port,
        destination_port,
        12345,
        67890,
        5 << 4,
        0,
        8192,
        0,
        0
    )


# Build a minimal UDP header with the minimum valid UDP length of 8 bytes.
def create_udp_header(source_port, destination_port):
    return struct.pack(
        '!HHHH',
        source_port,
        destination_port,
        8,
        0
    )


# Build a minimal ICMP header representing an ICMP Echo Request.
def create_icmp_header():
    return struct.pack(
        '!BBH',
        8,
        0,
        0
    )


# Test that the IPv4 parser correctly extracts the header length,
# protocol number, source and destination addresses, and TTL.
def test_parse_ip_header():
    packet = create_ipv4_header(
        6,
        '192.168.1.10',
        '8.8.8.8'
    )

    result = parse_ip_header(packet)

    assert result == (
        20,
        6,
        '192.168.1.10',
        '8.8.8.8',
        64
    )


# Test that the TCP parser correctly extracts ports, sequence number,
# acknowledgement number, and TCP header length.
def test_parse_tcp_header():
    header = create_tcp_header(50000, 443)

    result = parse_tcp_header(header)

    assert result == (
        50000,
        443,
        12345,
        67890,
        20
    )


# Test that the UDP parser correctly extracts the ports, length,
# and checksum from a valid UDP header.
def test_parse_udp_header():
    header = create_udp_header(50000, 53)

    result = parse_udp_header(header)

    assert result == (
        50000,
        53,
        8,
        0
    )


# Test that the ICMP parser correctly extracts the message type,
# code, and checksum.
def test_parse_icmp_header():
    header = create_icmp_header()

    result = parse_icmp_header(header)

    assert result == (
        8,
        0,
        0
    )


# Test complete TCP packet parsing by combining an IPv4 header
# with a TCP header and checking the resulting packet structure.
def test_parse_tcp_packet():
    ip_header = create_ipv4_header(
        6,
        '192.168.1.10',
        '8.8.8.8'
    )

    tcp_header = create_tcp_header(50000, 443)

    packet = parse_packet(ip_header + tcp_header)

    assert packet["source_ip"] == '192.168.1.10'
    assert packet["destination_ip"] == '8.8.8.8'
    assert packet["protocol"] == 6
    assert packet["ttl"] == 64

    assert packet["transport"]["source_port"] == 50000
    assert packet["transport"]["destination_port"] == 443
    assert packet["transport"]["sequence"] == 12345
    assert packet["transport"]["acknowledgment"] == 67890
    assert packet["transport"]["header_length"] == 20


# Test complete UDP packet parsing by combining an IPv4 header
# with a UDP header and checking the resulting packet structure.
def test_parse_udp_packet():
    ip_header = create_ipv4_header(
        17,
        '192.168.1.10',
        '8.8.8.8'
    )

    udp_header = create_udp_header(50000, 53)

    packet = parse_packet(ip_header + udp_header)

    assert packet["source_ip"] == '192.168.1.10'
    assert packet["destination_ip"] == '8.8.8.8'
    assert packet["protocol"] == 17

    assert packet["transport"]["source_port"] == 50000
    assert packet["transport"]["destination_port"] == 53
    assert packet["transport"]["length"] == 8
    assert packet["transport"]["checksum"] == 0


# Test complete ICMP packet parsing by combining an IPv4 header
# with an ICMP header and checking the resulting packet structure.
def test_parse_icmp_packet():
    ip_header = create_ipv4_header(
        1,
        '192.168.1.10',
        '8.8.8.8'
    )

    icmp_header = create_icmp_header()

    packet = parse_packet(ip_header + icmp_header)

    assert packet["source_ip"] == '192.168.1.10'
    assert packet["destination_ip"] == '8.8.8.8'
    assert packet["protocol"] == 1

    assert packet["transport"]["type"] == 8
    assert packet["transport"]["code"] == 0
    assert packet["transport"]["checksum"] == 0


# Verify that an empty packet is rejected rather than being passed
# to the header parsers.
def test_reject_empty_packet():
    with pytest.raises(ValueError):
        parse_packet(b'')


# Verify that packets shorter than the minimum IPv4 header size
# are rejected safely.
def test_reject_short_ip_header():
    with pytest.raises(ValueError):
        parse_packet(b'\x45' + b'\x00' * 10)


# Verify that packets using an unsupported IP version are rejected.
def test_reject_invalid_ip_version():
    invalid_header = create_ipv4_header(
        6,
        '192.168.1.10',
        '8.8.8.8'
    )

    # Change the version field from IPv4 to an invalid version.
    invalid_header = bytes([0x65]) + invalid_header[1:]

    with pytest.raises(ValueError):
        parse_packet(invalid_header)


# Verify that a truncated TCP header is rejected instead of causing
# an unpacking error to terminate the application.
def test_reject_short_tcp_header():
    ip_header = create_ipv4_header(
        6,
        '192.168.1.10',
        '8.8.8.8'
    )

    with pytest.raises(ValueError):
        parse_packet(ip_header + b'\x00' * 10)


# Verify that a truncated UDP header is rejected safely.
def test_reject_short_udp_header():
    ip_header = create_ipv4_header(
        17,
        '192.168.1.10',
        '8.8.8.8'
    )

    with pytest.raises(ValueError):
        parse_packet(ip_header + b'\x00' * 4)


# Verify that a truncated ICMP header is rejected safely.
def test_reject_short_icmp_header():
    ip_header = create_ipv4_header(
        1,
        '192.168.1.10',
        '8.8.8.8'
    )

    with pytest.raises(ValueError):
        parse_packet(ip_header + b'\x00' * 2)