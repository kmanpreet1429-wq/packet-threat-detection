from collections import defaultdict
from time import time


# Store destination ports observed from each source IP
port_activity = defaultdict(list)

# Store ICMP packet timestamps from each source IP
icmp_activity = defaultdict(list)


def detect_port_scan(
    source_ip,
    destination_ports,
    threshold=10
):
    """
    Basic port scan rule.

    Returns True if the source IP has contacted
    at least 'threshold' unique destination ports.
    """

    unique_ports = len(set(destination_ports))

    return unique_ports >= threshold


def detect_icmp_flood(
    icmp_count,
    threshold=20
):
    """
    Basic ICMP flood rule.

    Returns True if the ICMP count reaches
    the configured threshold.
    """

    return icmp_count >= threshold


def assign_severity(threat_type):

    if threat_type == "ICMP Flood":
        return "HIGH"

    elif threat_type == "Port Scan":
        return "MEDIUM"

    else:
        return "LOW"