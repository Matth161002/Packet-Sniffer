import queue
import tkinter as tk

from datetime import datetime
from tkinter import ttk, messagebox

from Packet_Sniffer import (
    parse_packet,
    get_active_ipv4,
    protocol_map
)

from flow_aggregation import FlowAggregator
from network_lookup import NetworkLookupWorker
from packet_capture import PacketCapture
from traffic_analysis import TrafficAnalyzer


class SecurityGUI:
    """Desktop interface for network traffic capture and analysis."""

    def __init__(self, root):
        """Initialise the application."""
        self.root = root
        self.root.title("Packet-Sniffer Security Monitor")
        self.root.geometry("1350x800")
        self.root.minsize(1000, 650)

        self.event_queue = queue.Queue()

        self.capture_session = 0

        self.packet_count = 0
        self.alert_count = 0

        self.analyzer = TrafficAnalyzer()
        self.flow_aggregator = FlowAggregator()
        self.lookup_worker = NetworkLookupWorker()

        self.capture = PacketCapture(
            parse_packet,
            self.handle_packet,
            ignored_ips=self.lookup_worker.lookup_service_ips
        )

        self.current_group = None
        self.current_group_row = None
        self.current_group_start = None
        self.current_group_end = None

        self.flow_rows = {}

        self.build_interface()

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_application
        )

        self.root.after(
            100,
            self.process_events
        )

    def build_interface(self):
        """Build the graphical interface."""
        header = ttk.Frame(
            self.root,
            padding=10
        )

        header.pack(
            fill=tk.X
        )

        title = ttk.Label(
            header,
            text="Packet-Sniffer Security Monitor",
            font=("Segoe UI", 18, "bold")
        )

        title.pack(
            side=tk.LEFT
        )

        self.clear_button = ttk.Button(
            header,
            text="Clear Capture",
            command=self.clear_capture
        )

        self.clear_button.pack(
            side=tk.RIGHT
        )

        self.stop_button = ttk.Button(
            header,
            text="Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED
        )

        self.stop_button.pack(
            side=tk.RIGHT,
            padx=5
        )

        self.start_button = ttk.Button(
            header,
            text="Start Capture",
            command=self.start_capture
        )

        self.start_button.pack(
            side=tk.RIGHT
        )

        status_frame = ttk.Frame(
            self.root,
            padding=(10, 0, 10, 10)
        )

        status_frame.pack(
            fill=tk.X
        )

        self.status_label = ttk.Label(
            status_frame,
            text="Status: Stopped"
        )

        self.status_label.pack(
            side=tk.LEFT
        )

        self.packet_label = ttk.Label(
            status_frame,
            text="Packets: 0"
        )

        self.packet_label.pack(
            side=tk.LEFT,
            padx=25
        )

        self.alert_label = ttk.Label(
            status_frame,
            text="Security events: 0"
        )

        self.alert_label.pack(
            side=tk.LEFT
        )

        self.flow_label = ttk.Label(
            status_frame,
            text="Flows: 0"
        )

        self.flow_label.pack(
            side=tk.LEFT,
            padx=25
        )

        self.notebook = ttk.Notebook(
            self.root
        )

        self.notebook.pack(
            fill=tk.BOTH,
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        self.build_packets_tab()
        self.build_flows_tab()
        self.build_events_tab()
        self.build_statistics_tab()

    def build_packets_tab(self):
        """Create the packet table."""
        frame = ttk.Frame(
            self.notebook,
            padding=5
        )

        self.notebook.add(
            frame,
            text="Packets"
        )

        columns = (
            "packets",
            "source",
            "destination",
            "protocol",
            "source_port",
            "destination_port",
            "ttl",
            "hostname",
            "location"
        )

        self.packet_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "packets": "Packets",
            "source": "Source",
            "destination": "Destination",
            "protocol": "Protocol",
            "source_port": "Source Port",
            "destination_port": "Destination Port",
            "ttl": "TTL",
            "hostname": "Hostname",
            "location": "Location"
        }

        widths = {
            "packets": 80,
            "source": 130,
            "destination": 130,
            "protocol": 80,
            "source_port": 90,
            "destination_port": 110,
            "ttl": 50,
            "hostname": 250,
            "location": 220
        }

        for column in columns:
            self.packet_tree.heading(
                column,
                text=headings[column]
            )

            self.packet_tree.column(
                column,
                width=widths[column],
                anchor=tk.W
            )

        vertical_scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.VERTICAL,
            command=self.packet_tree.yview
        )

        horizontal_scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.HORIZONTAL,
            command=self.packet_tree.xview
        )

        self.packet_tree.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set
        )

        self.packet_tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal_scrollbar.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

    def build_flows_tab(self):
        """Create the network flow table."""
        frame = ttk.Frame(
            self.notebook,
            padding=5
        )

        self.notebook.add(
            frame,
            text="Flows"
        )

        columns = (
            "source",
            "destination",
            "protocol",
            "ports",
            "packets",
            "bytes",
            "duration",
            "direction"
        )

        self.flow_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "source": "Source",
            "destination": "Destination",
            "protocol": "Protocol",
            "ports": "Ports",
            "packets": "Packets",
            "bytes": "Bytes",
            "duration": "Duration",
            "direction": "Packets by Direction"
        }

        widths = {
            "source": 180,
            "destination": 180,
            "protocol": 90,
            "ports": 150,
            "packets": 80,
            "bytes": 100,
            "duration": 100,
            "direction": 180
        }

        for column in columns:
            self.flow_tree.heading(
                column,
                text=headings[column]
            )

            self.flow_tree.column(
                column,
                width=widths[column],
                anchor=tk.W
            )

        scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.VERTICAL,
            command=self.flow_tree.yview
        )

        self.flow_tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.flow_tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        scrollbar.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

    def build_events_tab(self):
        """Create the security event table."""
        frame = ttk.Frame(
            self.notebook,
            padding=5
        )

        self.notebook.add(
            frame,
            text="Security Events"
        )

        columns = (
            "time",
            "severity",
            "type",
            "message"
        )

        self.event_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "time": "Time",
            "severity": "Severity",
            "type": "Event",
            "message": "Description"
        }

        widths = {
            "time": 150,
            "severity": 100,
            "type": 180,
            "message": 700
        }

        for column in columns:
            self.event_tree.heading(
                column,
                text=headings[column]
            )

            self.event_tree.column(
                column,
                width=widths[column],
                anchor=tk.W
            )

        scrollbar = ttk.Scrollbar(
            frame,
            orient=tk.VERTICAL,
            command=self.event_tree.yview
        )

        self.event_tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.event_tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        scrollbar.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

    def build_statistics_tab(self):
        """Create the traffic statistics display."""
        frame = ttk.Frame(
            self.notebook,
            padding=20
        )

        self.notebook.add(
            frame,
            text="Statistics"
        )

        self.statistics_text = tk.Text(
            frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Consolas", 11)
        )

        self.statistics_text.pack(
            fill=tk.BOTH,
            expand=True
        )

    def start_capture(self):
        """Start network packet capture."""
        if self.capture.running:
            return

        try:
            active_ip = get_active_ipv4()

            if active_ip == "Unknown":
                messagebox.showerror(
                    "Packet Capture",
                    "Unable to determine the active IPv4 address."
                )

                return

            self.capture_session += 1

            self.analyzer = TrafficAnalyzer()
            self.flow_aggregator = FlowAggregator()

            self.packet_count = 0
            self.alert_count = 0

            self.current_group = None
            self.current_group_row = None
            self.current_group_start = None
            self.current_group_end = None

            self.flow_rows.clear()

            self.packet_tree.delete(
                *self.packet_tree.get_children()
            )

            self.flow_tree.delete(
                *self.flow_tree.get_children()
            )

            self.event_tree.delete(
                *self.event_tree.get_children()
            )

            self.update_statistics()

            self.capture.start(
                active_ip,
                session_id=self.capture_session
            )

            self.status_label.config(
                text=f"Status: Capturing on {active_ip}"
            )

            self.start_button.config(
                state=tk.DISABLED
            )

            self.stop_button.config(
                state=tk.NORMAL
            )

        except Exception as error:
            messagebox.showerror(
                "Packet Capture",
                str(error)
            )

    def stop_capture(self):
        """Stop network packet capture."""
        self.capture.stop()

        self.status_label.config(
            text="Status: Stopped"
        )

        self.start_button.config(
            state=tk.NORMAL
        )

        self.stop_button.config(
            state=tk.DISABLED
        )

    def clear_capture(self):
        """Stop capture and completely reset the current session."""
        self.capture_session += 1

        self.capture.stop()

        self.packet_count = 0
        self.alert_count = 0

        self.analyzer = TrafficAnalyzer()
        self.flow_aggregator = FlowAggregator()

        self.current_group = None
        self.current_group_row = None
        self.current_group_start = None
        self.current_group_end = None

        self.flow_rows.clear()

        self.packet_tree.delete(
            *self.packet_tree.get_children()
        )

        self.flow_tree.delete(
            *self.flow_tree.get_children()
        )

        self.event_tree.delete(
            *self.event_tree.get_children()
        )

        self.packet_label.config(
            text="Packets: 0"
        )

        self.alert_label.config(
            text="Security events: 0"
        )

        self.flow_label.config(
            text="Flows: 0"
        )

        self.status_label.config(
            text="Status: Stopped"
        )

        self.start_button.config(
            state=tk.NORMAL
        )

        self.stop_button.config(
            state=tk.DISABLED
        )

        self.update_statistics()

    def handle_packet(self, packet, error, session_id):
        """Place a capture result onto the GUI event queue."""
        self.event_queue.put(
            (
                "packet",
                packet,
                error,
                session_id
            )
        )

    def process_events(self):
        """Process background events on the GUI thread."""
        try:
            while True:
                event = self.event_queue.get_nowait()

                if event[0] == "packet":
                    self.process_capture_event(
                        event[1],
                        event[2],
                        event[3]
                    )

                elif event[0] == "lookup":
                    self.process_lookup_event(
                        event[1],
                        event[2],
                        event[3]
                    )

        except queue.Empty:
            pass

        self.root.after(
            100,
            self.process_events
        )

    def process_capture_event(
        self,
        packet,
        error,
        session_id
    ):
        """Handle a captured packet or capture error."""
        if session_id != self.capture_session:
            return

        if error:
            self.status_label.config(
                text=f"Status: {error}"
            )

            self.capture.stop()

            self.start_button.config(
                state=tk.NORMAL
            )

            self.stop_button.config(
                state=tk.DISABLED
            )

            return

        if packet is None:
            return

        self.process_packet(
            packet
        )

    def process_packet(self, packet):
        """Analyse and display a captured packet."""
        self.packet_count += 1

        security_events = self.analyzer.analyse_packet(
            packet
        )

        for event in security_events:
            self.display_security_event(
                event
            )

        flow = self.flow_aggregator.update(
            packet
        )

        self.update_flow_row(
            flow
        )

        transport = packet["transport"]

        source_port = ""
        destination_port = ""

        if transport:
            source_port = transport.get(
                "source_port",
                ""
            )

            destination_port = transport.get(
                "destination_port",
                ""
            )

        protocol_name = protocol_map.get(
            packet["protocol"],
            f"Unknown ({packet['protocol']})"
        )

        group_key = (
            packet["source_ip"],
            packet["destination_ip"],
            protocol_name,
            source_port,
            destination_port,
            packet["ttl"]
        )

        if (
            self.current_group == group_key
            and self.current_group_row is not None
            and self.packet_tree.exists(
                self.current_group_row
            )
        ):
            self.current_group_end = self.packet_count

            packet_range = self.format_packet_range(
                self.current_group_start,
                self.current_group_end
            )

            current_values = self.packet_tree.item(
                self.current_group_row,
                "values"
            )

            updated_values = list(
                current_values
            )

            updated_values[0] = packet_range

            self.packet_tree.item(
                self.current_group_row,
                values=updated_values
            )

        else:
            self.current_group = group_key
            self.current_group_start = self.packet_count
            self.current_group_end = self.packet_count

            item_id = self.packet_tree.insert(
                "",
                tk.END,
                values=(
                    str(self.packet_count),
                    packet["source_ip"],
                    packet["destination_ip"],
                    protocol_name,
                    source_port,
                    destination_port,
                    packet["ttl"],
                    "Looking up...",
                    "Looking up..."
                )
            )

            self.current_group_row = item_id

            future, _ = self.lookup_worker.submit(
                packet["destination_ip"]
            )

            future.add_done_callback(
                lambda completed_future,
                row=item_id,
                session_id=self.capture_session:
                self.queue_lookup_result(
                    completed_future,
                    row,
                    session_id
                )
            )

        self.packet_label.config(
            text=f"Packets: {self.packet_count}"
        )

        self.flow_label.config(
            text=(
                f"Flows: "
                f"{self.flow_aggregator.get_statistics()['total_flows']}"
            )
        )

        self.update_statistics()

    def update_flow_row(self, flow):
        """Insert or update a flow in the flow table."""
        flow_key = (
            flow.protocol,
            flow.source_ip,
            flow.destination_ip,
            flow.source_port,
            flow.destination_port
        )

        values = (
            flow.source_ip,
            flow.destination_ip,
            protocol_map.get(
                flow.protocol,
                f"Unknown ({flow.protocol})"
            ),
            self.format_ports(
                flow.source_port,
                flow.destination_port
            ),
            flow.packet_count,
            self.format_bytes(
                flow.byte_count
            ),
            self.format_duration(
                flow.duration
            ),
            (
                f"{flow.forward_packets} forward / "
                f"{flow.reverse_packets} reverse"
            )
        )

        row_id = self.flow_rows.get(
            flow_key
        )

        if row_id and self.flow_tree.exists(
            row_id
        ):
            self.flow_tree.item(
                row_id,
                values=values
            )

        else:
            row_id = self.flow_tree.insert(
                "",
                tk.END,
                values=values
            )

            self.flow_rows[flow_key] = row_id

        self.flow_tree.move(
            row_id,
            "",
            0
        )

    @staticmethod
    def format_ports(source_port, destination_port):
        """Format a pair of transport ports."""
        if (
            source_port is None
            or destination_port is None
        ):
            return "-"

        return f"{source_port} -> {destination_port}"

    @staticmethod
    def format_bytes(byte_count):
        """Format a byte count for display."""
        if byte_count < 1024:
            return f"{byte_count} B"

        if byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.1f} KB"

        return f"{byte_count / (1024 * 1024):.1f} MB"

    @staticmethod
    def format_duration(duration):
        """Format a flow duration for display."""
        if duration < 1:
            return f"{duration * 1000:.0f} ms"

        return f"{duration:.2f} s"

    @staticmethod
    def format_packet_range(start, end):
        """Format a packet number range."""
        if start == end:
            return str(start)

        return f"{start}-{end}"

    def queue_lookup_result(
        self,
        future,
        item_id,
        session_id
    ):
        """Queue completed lookup data for the GUI thread."""
        try:
            result = future.result()

        except Exception:
            result = None

        if result:
            self.event_queue.put(
                (
                    "lookup",
                    result,
                    item_id,
                    session_id
                )
            )

    def process_lookup_event(
        self,
        result,
        item_id,
        session_id
    ):
        """Update a packet row with network metadata."""
        if session_id != self.capture_session:
            return

        if not self.packet_tree.exists(
            item_id
        ):
            return

        values = self.packet_tree.item(
            item_id,
            "values"
        )

        if not values:
            return

        updated_values = list(
            values
        )

        updated_values[7] = (
            result["hostname"]
            or "Unknown"
        )

        updated_values[8] = (
            result["geolocation"]
            or "Unknown"
        )

        self.packet_tree.item(
            item_id,
            values=updated_values
        )

    def display_security_event(self, event):
        """Display a traffic-analysis security event."""
        self.alert_count += 1

        self.event_tree.insert(
            "",
            tk.END,
            values=(
                self.current_time(),
                event["severity"],
                event["type"],
                event["message"]
            )
        )

        self.alert_label.config(
            text=f"Security events: {self.alert_count}"
        )

    def update_statistics(self):
        """Refresh the traffic statistics display."""
        statistics = self.analyzer.get_statistics()
        flow_statistics = self.flow_aggregator.get_statistics()

        lines = [
            "TRAFFIC SUMMARY",
            "",
            f"Total packets: {statistics['total_packets']}",
            f"Total flows: {flow_statistics['total_flows']}",
            f"Total bytes: {self.format_bytes(flow_statistics['total_bytes'])}",
            "",
            "PROTOCOLS",
            ""
        ]

        for protocol, count in sorted(
            statistics["protocol_counts"].items()
        ):
            protocol_name = protocol_map.get(
                protocol,
                f"Unknown ({protocol})"
            )

            lines.append(
                f"{protocol_name}: {count}"
            )

        lines.extend(
            [
                "",
                "TOP DESTINATIONS",
                ""
            ]
        )

        destinations = sorted(
            statistics["destination_counts"].items(),
            key=lambda item: item[1],
            reverse=True
        )

        for destination, count in destinations[:10]:
            lines.append(
                f"{destination}: {count}"
            )

        lines.extend(
            [
                "",
                "TOP DESTINATION PORTS",
                ""
            ]
        )

        ports = sorted(
            statistics["port_counts"].items(),
            key=lambda item: item[1],
            reverse=True
        )

        for port, count in ports[:10]:
            lines.append(
                f"{port}: {count}"
            )

        self.statistics_text.config(
            state=tk.NORMAL
        )

        self.statistics_text.delete(
            "1.0",
            tk.END
        )

        self.statistics_text.insert(
            tk.END,
            "\n".join(lines)
        )

        self.statistics_text.config(
            state=tk.DISABLED
        )

    @staticmethod
    def current_time():
        """Return the current local time."""
        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def close_application(self):
        """Stop capture and background workers before closing."""
        self.capture_session += 1
        self.capture.stop()
        self.lookup_worker.shutdown()
        self.root.destroy()


def main():
    """Launch the Packet-Sniffer desktop application."""
    root = tk.Tk()

    SecurityGUI(
        root
    )

    root.mainloop()


if __name__ == "__main__":
    main()
