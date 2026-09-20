import socket
import time

import requests


# Store previously resolved IP addresses to avoid repeating
# geolocation requests for the same destination.
geo_cache = {}

# Track the time of the most recent geolocation request so that
# external API requests are not made too frequently.
last_geo_time = 0.0


def resolve_hostname(ip):
    """Resolve an IP address to a hostname using reverse DNS."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
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
            country = data.get('country', '')
            city = data.get('city', '')
            org = data.get('org', '')

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

    if ip in geo_cache:
        return geo_cache[ip]

    current_time = time.time()

    if current_time - last_geo_time >= 2.0:
        location = geolocate_ip(ip)
        geo_cache[ip] = location
        last_geo_time = current_time
        return location

    return "Geo rate-limited"