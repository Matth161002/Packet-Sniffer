import ipaddress
import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor

import requests


geo_cache = {}
hostname_cache = {}

last_geo_time = 0.0
geo_lock = threading.Lock()


def resolve_hostname(ip):
    """Resolve an IP address to a hostname using reverse DNS."""
    with geo_lock:
        if ip in hostname_cache:
            return hostname_cache[ip]

    try:
        hostname = socket.gethostbyaddr(ip)[0]

    except socket.herror:
        hostname = None

    except socket.gaierror:
        hostname = None

    except Exception as error:
        print(
            f"Hostname lookup error for {ip}: {error}"
        )

        hostname = None

    with geo_lock:
        hostname_cache[ip] = hostname

    return hostname


def geolocate_ip(ip):
    """Look up the approximate location and organisation of an IP address."""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,city,org,query",
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()

            country = data.get(
                "country",
                ""
            )

            city = data.get(
                "city",
                ""
            )

            org = data.get(
                "org",
                ""
            )

            return f"{city}, {country} ({org})"

        return "Geo lookup failed"

    except requests.RequestException:
        return "Geo lookup error"


def get_hostname(ip):
    """Return cached hostname data or perform a reverse DNS lookup."""
    return resolve_hostname(ip)


def get_geolocation(ip):
    """Return cached geolocation data or perform a rate-limited lookup."""
    global last_geo_time

    try:
        address = ipaddress.ip_address(ip)

        if not address.is_global:
            return "Local/private network"

    except ValueError:
        return "Unknown"

    with geo_lock:
        if ip in geo_cache:
            return geo_cache[ip]

        current_time = time.time()

        if current_time - last_geo_time < 2.0:
            return "Geo rate-limited"

        last_geo_time = current_time

    location = geolocate_ip(ip)

    with geo_lock:
        geo_cache[ip] = location

    return location


def get_lookup_service_ips():
    """Return IP addresses currently associated with the geolocation API."""
    try:
        addresses = socket.gethostbyname_ex(
            "ip-api.com"
        )[2]

        return set(addresses)

    except socket.gaierror:
        return set()


class NetworkLookupWorker:
    """Run network metadata lookups outside the packet capture loop."""

    def __init__(self, max_workers=4):
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers
        )

        self.in_flight = {}
        self.completed = {}

        self.in_flight_lock = threading.Lock()

        # The packet capture application uses this set to prevent
        # its own geolocation API traffic from appearing as monitored traffic.
        self.lookup_service_ips = get_lookup_service_ips()

    def submit(self, ip):
        """Return a lookup future while preventing duplicate work."""
        with self.in_flight_lock:

            if ip in self.completed:
                return self.completed[ip], False

            if ip in self.in_flight:
                return self.in_flight[ip], False

            future = self.executor.submit(
                self._lookup,
                ip
            )

            self.in_flight[ip] = future

            future.add_done_callback(
                lambda completed_future, address=ip:
                self._store_result(
                    address,
                    completed_future
                )
            )

            return future, True

    def _store_result(self, ip, future):
        """Store a completed lookup and remove it from the active collection."""
        try:
            result = future.result()

        except Exception:
            result = None

        with self.in_flight_lock:
            self.in_flight.pop(
                ip,
                None
            )

            if result is not None:
                self.completed[ip] = future

    def _lookup(self, ip):
        """Perform hostname and geolocation lookups for an IP address."""
        hostname = get_hostname(ip)
        geolocation = get_geolocation(ip)

        return {
            "ip": ip,
            "hostname": hostname,
            "geolocation": geolocation
        }

    def shutdown(self):
        """Stop lookup workers and wait for active lookups to finish."""
        self.executor.shutdown(
            wait=True
        )