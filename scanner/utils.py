import re
from urllib.parse import urlparse


def sanitize_target(target: str) -> str:
    """
    Cleans target input by stripping protocols, ports, and paths.
    Converts 'https://sub.example.com:8080/test' -> 'sub.example.com'.
    """
    target = target.strip()

    # If scheme is present, parse with urlparse
    if "://" in target:
        parsed = urlparse(target)
        hostname = parsed.hostname or parsed.netloc
    else:
        # If no scheme, handle path stripping manually
        hostname = target.split("/")[0].split(":")[0]

    hostname = hostname.strip().lower()
    return hostname


def is_valid_target(target: str) -> bool:
    """
    Validates if the target string is a valid IPv4 address or domain name.
    """
    # Check IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, target):
        octets = target.split(".")
        return all(0 <= int(octet) <= 255 for octet in octets)

    # Check Domain / FQDN
    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(domain_pattern, target))
