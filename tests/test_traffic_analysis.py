from traffic_analysis import TrafficAnalyzer


def create_tcp_packet(
    destination_ip="8.8.8.8",
    destination_port=443
):
    """Create a minimal parsed TCP packet for testing."""
    return {
        "source_ip": "192.168.1.100",
        "destination_ip": destination_ip,
        "protocol": 6,
        "ttl": 64,
        "transport": {
            "type": "TCP",
            "source_port": 50000,
            "destination_port": destination_port,
            "sequence": 1,
            "acknowledgment": 1,
            "header_length": 20
        }
    }


def test_packet_statistics_are_recorded():
    """Verify that packet statistics are updated."""
    analyzer = TrafficAnalyzer()

    analyzer.analyse_packet(
        create_tcp_packet()
    )

    statistics = analyzer.get_statistics()

    assert statistics["total_packets"] == 1
    assert statistics["protocol_counts"][6] == 1
    assert statistics["destination_counts"]["8.8.8.8"] == 1
    assert statistics["port_counts"][443] == 1


def test_high_traffic_detection():
    """Verify that high packet volume generates an alert."""
    analyzer = TrafficAnalyzer()

    events = []

    for _ in range(analyzer.HIGH_TRAFFIC_THRESHOLD):
        events.extend(
            analyzer.analyse_packet(
                create_tcp_packet()
            )
        )

    high_traffic_events = [
        event
        for event in events
        if event["type"] == "HIGH_TRAFFIC"
    ]

    assert len(high_traffic_events) == 1
    assert high_traffic_events[0]["severity"] == "WARNING"


def test_high_traffic_alert_is_not_repeated():
    """Verify that the same high traffic alert is only generated once."""
    analyzer = TrafficAnalyzer()

    events = []

    for _ in range(analyzer.HIGH_TRAFFIC_THRESHOLD + 5):
        events.extend(
            analyzer.analyse_packet(
                create_tcp_packet()
            )
        )

    high_traffic_events = [
        event
        for event in events
        if event["type"] == "HIGH_TRAFFIC"
    ]

    assert len(high_traffic_events) == 1


def test_port_scan_detection():
    """Verify that multiple destination ports generate an alert."""
    analyzer = TrafficAnalyzer()

    events = []

    for port in range(
        10000,
        10000 + analyzer.PORT_SCAN_THRESHOLD
    ):
        events.extend(
            analyzer.analyse_packet(
                create_tcp_packet(
                    destination_port=port
                )
            )
        )

    scan_events = [
        event
        for event in events
        if event["type"] == "POSSIBLE_PORT_SCAN"
    ]

    assert len(scan_events) == 1
    assert scan_events[0]["severity"] == "WARNING"


def test_port_scan_alert_is_not_repeated():
    """Verify that the same port scan alert is only generated once."""
    analyzer = TrafficAnalyzer()

    events = []

    for port in range(
        10000,
        10000 + analyzer.PORT_SCAN_THRESHOLD + 3
    ):
        events.extend(
            analyzer.analyse_packet(
                create_tcp_packet(
                    destination_port=port
                )
            )
        )

    scan_events = [
        event
        for event in events
        if event["type"] == "POSSIBLE_PORT_SCAN"
    ]

    assert len(scan_events) == 1


def test_unusual_port_detection():
    """Verify that an unusual destination port generates an alert."""
    analyzer = TrafficAnalyzer()

    events = analyzer.analyse_packet(
        create_tcp_packet(
            destination_port=3389
        )
    )

    unusual_port_events = [
        event
        for event in events
        if event["type"] == "UNUSUAL_PORT"
    ]

    assert len(unusual_port_events) == 1
    assert unusual_port_events[0]["severity"] == "INFO"


def test_unusual_port_alert_is_not_repeated():
    """Verify that the same unusual port alert is only generated once."""
    analyzer = TrafficAnalyzer()

    events = []

    for _ in range(5):
        events.extend(
            analyzer.analyse_packet(
                create_tcp_packet(
                    destination_port=3389
                )
            )
        )

    unusual_port_events = [
        event
        for event in events
        if event["type"] == "UNUSUAL_PORT"
    ]

    assert len(unusual_port_events) == 1


def test_normal_port_does_not_generate_unusual_port_alert():
    """Verify that a common HTTPS port is not flagged as unusual."""
    analyzer = TrafficAnalyzer()

    events = analyzer.analyse_packet(
        create_tcp_packet(
            destination_port=443
        )
    )

    unusual_port_events = [
        event
        for event in events
        if event["type"] == "UNUSUAL_PORT"
    ]

    assert len(unusual_port_events) == 0