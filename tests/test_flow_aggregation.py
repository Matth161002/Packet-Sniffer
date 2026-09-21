from flow_aggregation import FlowAggregator


def create_tcp_packet(
    source_ip="192.168.56.101",
    destination_ip="192.168.56.1",
    source_port=50000,
    destination_port=443,
    packet_length=100
):
    """Create a parsed TCP packet for flow tests."""
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": 6,
        "ttl": 64,
        "packet_length": packet_length,
        "transport": {
            "type": "TCP",
            "source_port": source_port,
            "destination_port": destination_port,
            "sequence": 1,
            "acknowledgment": 1,
            "header_length": 20
        }
    }


def create_icmp_packet(
    source_ip="192.168.56.101",
    destination_ip="192.168.56.1",
    packet_length=84
):
    """Create a parsed ICMP packet for flow tests."""
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": 1,
        "ttl": 64,
        "packet_length": packet_length,
        "transport": {
            "type": "ICMP",
            "type_code": 8,
            "code": 0,
            "checksum": 0
        }
    }


def test_reverse_tcp_packets_share_one_flow():
    """Verify that both directions of a TCP exchange form one flow."""
    aggregator = FlowAggregator()

    aggregator.update(
        create_tcp_packet(),
        timestamp=100.0
    )

    aggregator.update(
        create_tcp_packet(
            source_ip="192.168.56.1",
            destination_ip="192.168.56.101",
            source_port=443,
            destination_port=50000,
            packet_length=120
        ),
        timestamp=101.5
    )

    flows = aggregator.get_flows()

    assert len(flows) == 1

    flow = flows[0]

    assert flow.packet_count == 2
    assert flow.byte_count == 220
    assert flow.forward_packets == 1
    assert flow.reverse_packets == 1
    assert flow.duration == 1.5


def test_different_tcp_connections_form_separate_flows():
    """Verify that different TCP ports produce separate flows."""
    aggregator = FlowAggregator()

    aggregator.update(
        create_tcp_packet(
            source_port=50000,
            destination_port=443
        )
    )

    aggregator.update(
        create_tcp_packet(
            source_port=50001,
            destination_port=443
        )
    )

    assert len(aggregator.get_flows()) == 2


def test_icmp_request_and_reply_share_one_flow():
    """Verify that ICMP request and reply traffic forms one flow."""
    aggregator = FlowAggregator()

    aggregator.update(
        create_icmp_packet(),
        timestamp=200.0
    )

    aggregator.update(
        create_icmp_packet(
            source_ip="192.168.56.1",
            destination_ip="192.168.56.101"
        ),
        timestamp=200.25
    )

    flows = aggregator.get_flows()

    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert flows[0].forward_packets == 1
    assert flows[0].reverse_packets == 1
    assert flows[0].duration == 0.25


def test_flow_statistics_are_correct():
    """Verify aggregate flow statistics."""
    aggregator = FlowAggregator()

    aggregator.update(
        create_tcp_packet(
            packet_length=150
        )
    )

    aggregator.update(
        create_tcp_packet(
            source_port=50001,
            packet_length=200
        )
    )

    statistics = aggregator.get_statistics()

    assert statistics["total_flows"] == 2
    assert statistics["total_packets"] == 2
    assert statistics["total_bytes"] == 350


def test_reset_removes_all_flows():
    """Verify that resetting the aggregator removes tracked flows."""
    aggregator = FlowAggregator()

    aggregator.update(
        create_tcp_packet()
    )

    aggregator.reset()

    assert aggregator.get_flows() == []
    assert aggregator.get_statistics()["total_flows"] == 0
