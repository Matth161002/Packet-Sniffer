import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor

import requests


geo_cache = {}
last_geo_time = 0.0
geo_lock = threading.Lock()


def resolve_hostname(ip):
    """Resolve an IP address to a hostname using reverse DNS."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    except socket.gaierror:
        return None
    except Exception as e:
        print(f"Hostname lookup error for {ip}: {e}")
        return None


def geolocate_ip(ip):
    """Look up the approximate location and organisation of an IP address."""
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,city,org,query",
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()
            country = data.get("country", "")
            city = data.get("city", "")
            org = data.get("org", "")

            return f"{city}, {country} ({org})"

        return "Geo lookup failed"

    except requests.RequestException:
        return "Geo lookup error"


def get_hostname(ip):
    """Return the hostname associated with an IP address."""
    return resolve_hostname(ip)


def get_geolocation(ip):
    """Return cached geolocation data or perform a rate-limited lookup."""
    global last_geo_time

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


class NetworkLookupWorker:
    """Run network metadata lookups outside the packet capture loop."""

    def __init__(self, max_workers=4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.in_flight = {}
        self.in_flight_lock = threading.Lock()

    def submit(self, ip):
        """Submit a lookup unless one is already running for the IP."""
        with self.in_flight_lock:
            if ip in self.in_flight:
                return self.in_flight[ip], False

            future = self.executor.submit(self._lookup, ip)
            self.in_flight[ip] = future

            future.add_done_callback(
                lambda completed_future, address=ip:
                self._remove_in_flight(address)
        )

        return future, True

    def _remove_in_flight(self, ip):
        """Remove a completed lookup from the in-flight collection."""
        with self.in_flight_lock:
            self.in_flight.pop(ip, None)

    def _lookup(self, ip):
        """Perform all metadata lookups for an IP address."""
        hostname = get_hostname(ip)
        geolocation = get_geolocation(ip)

        return {
            "ip": ip,
            "hostname": hostname,
            "geolocation": geolocation
        }

    def shutdown(self):
        """Stop the worker threads and wait for active lookups to finish."""
        self.executor.shutdown(wait=True)