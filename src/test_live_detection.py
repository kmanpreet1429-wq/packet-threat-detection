from datetime import datetime

from rules import (
    detect_port_scan,
    detect_icmp_flood,
    assign_severity
)

from database import (
    create_database,
    save_alert,
    get_recent_alerts
)


# Initialize database
create_database()


# Simulate suspicious activity
source_ip = "192.168.1.99"

destination_ports = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443, 8080
]

icmp_count = 25

print("Starting threat detection test...\n")


# Port scan detection
if detect_port_scan(source_ip, destination_ports):

    severity = assign_severity("Port Scan")

    save_alert(
        "Port Scan",
        source_ip,
        severity,
        datetime.now().isoformat()
    )

    print("Port Scan detected!")
    print("Source IP:", source_ip)
    print("Severity:", severity)

else:
    print("Port Scan not detected.")


print("-" * 40)


# ICMP flood detection
if detect_icmp_flood(icmp_count):

    severity = assign_severity("ICMP Flood")

    save_alert(
        "ICMP Flood",
        source_ip,
        severity,
        datetime.now().isoformat()
    )

    print("ICMP Flood detected!")
    print("Simulated ICMP count:", icmp_count)
    print("Severity:", severity)

else:
    print("ICMP Flood not detected.")


print("-" * 40)


# Verify alerts in the database
print("\nRecent alerts saved in database:")

for alert in get_recent_alerts():
    print(alert)

print("\nThreat detection test finished.")