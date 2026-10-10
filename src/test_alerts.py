from datetime import datetime

from database import create_database, save_alert, get_recent_alerts

# Initialize database
create_database()

# Simulate a port scan alert
save_alert(
    "Port Scan",
    "192.168.1.10",
    "MEDIUM",
    datetime.now().isoformat()
)

print("Test alert saved to database!")

# Verify saved alert
alerts = get_recent_alerts()

if alerts:
    print("\nRecent alerts:")
    for alert in alerts:
        print(alert)
else:
    print("No alerts found!")