import sqlite3

DATABASE_NAME = "packets.db"


def create_database():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            packet_size INTEGER,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_type TEXT,
            source_ip TEXT,
            severity TEXT,
            timestamp TEXT
        )
    """)

    connection.commit()
    connection.close()

def save_packet(source_ip, destination_ip, protocol,
                source_port, destination_port, packet_size, timestamp):

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO packets
        (source_ip, destination_ip, protocol, source_port,
         destination_port, packet_size, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size,
        str(timestamp)
    ))

    connection.commit()
    connection.close()

def save_alert(threat_type, source_ip, severity, timestamp):

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts
        (threat_type, source_ip, severity, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        threat_type,
        source_ip,
        severity,
        str(timestamp)
    ))

    connection.commit()
    connection.close()

def get_recent_alerts(limit=10):

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT threat_type, source_ip, severity, timestamp
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    alerts = cursor.fetchall()

    connection.close()

    return alerts