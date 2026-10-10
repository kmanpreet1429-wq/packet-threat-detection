import queue
import threading
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from datetime import datetime

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

from rules import (
    detect_port_scan,
    detect_icmp_flood,
    assign_severity
)

from database import (
    create_database,
    save_packet,
    save_alert,
    get_recent_alerts
)


# ---------------- LOGGING SETUP ----------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        RotatingFileHandler(
            "packet_detector.log",
            maxBytes=1_000_000,
            backupCount=3
        ),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# ---------------- DATABASE SETUP ----------------

create_database()


# ---------------- PACKET QUEUE ----------------

packet_queue = queue.Queue(maxsize=1000)


# ---------------- STATISTICS ----------------

stats = {
    "total": 0,
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}

port_activity = defaultdict(set)
icmp_activity = defaultdict(int)


# ---------------- PACKET PRODUCER ----------------

def packet_producer(packet):
    """Add captured packets to the processing queue."""

    try:
        packet_queue.put_nowait(packet)

    except queue.Full:
        logger.warning("Packet queue full. Packet dropped.")


# ---------------- PACKET CONSUMER ----------------

def packet_consumer():
    """Process queued packets and save them to SQLite."""

    while True:
        packet = packet_queue.get()

        try:
            # None tells the consumer to stop
            if packet is None:
                return

            # Process IPv4 packets only
            if not packet.haslayer(IP):
                continue

            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            packet_size = len(packet)
            timestamp = datetime.now().isoformat()

            source_port = None
            destination_port = None

            if packet.haslayer(TCP):
                protocol = "TCP"
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport

    # Count only TCP SYN packets for port scan detection
                tcp_flags = packet[TCP].flags

                if (tcp_flags & 0x02) and not (tcp_flags & 0x10):
                    port_activity[source_ip].add(destination_port)

            elif packet.haslayer(UDP):
                protocol = "UDP"
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                icmp_activity[source_ip] += 1

            else:
                protocol = "Other"

            stats["total"] += 1
            stats[protocol] += 1

            save_packet(
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                packet_size,
                timestamp
            )

            print(
                f"Packet #{stats['total']} | "
                f"{source_ip} -> {destination_ip} | "
                f"{protocol} | {packet_size} bytes"
            )

        except Exception:
            logger.exception("Packet processing failed")

        finally:
            packet_queue.task_done()


# ---------------- THREAT DETECTION ----------------

def detect_threats():
    """Check captured traffic and save alerts."""

    for source_ip, ports in port_activity.items():

        if detect_port_scan(source_ip, ports):
            severity = assign_severity("Port Scan")

            save_alert(
                "Port Scan",
                source_ip,
                severity,
                datetime.now().isoformat()
            )

            logger.warning(
                "Port Scan detected | Source: %s | Severity: %s",
                source_ip,
                severity
            )

    for source_ip, count in icmp_activity.items():

        if detect_icmp_flood(count):
            severity = assign_severity("ICMP Flood")

            save_alert(
                "ICMP Flood",
                source_ip,
                severity,
                datetime.now().isoformat()
            )

            logger.warning(
                "ICMP Flood detected | Source: %s | Severity: %s",
                source_ip,
                severity
            )


# ---------------- MAIN FUNCTION ----------------

def main():

    logger.info("Packet Threat Detector started")

    consumer_thread = threading.Thread(
        target=packet_consumer,
        daemon=False
    )
    consumer_thread.start()

    sniffer = AsyncSniffer(
        prn=packet_producer,
        store=False
    )

    print("Starting packet capture for 60 seconds...")
    print("Press Ctrl+C to stop early.")

    try:
        sniffer.start()
        logger.info("Packet capture started")

        # Wait for the capture to finish, but allow Ctrl+C
        sniffer_thread = sniffer.thread

        if sniffer_thread is not None:
            sniffer_thread.join(timeout=60)

    except KeyboardInterrupt:
        print("\nCapture interrupted by user.", flush=True)
        logger.info("Capture interrupted by user")

    except Exception:
        logger.exception("Packet capture failed")

    finally:
        # Stop capture if it is still running
        try:
            if sniffer.running:
                sniffer.stop()
        except Exception:
            logger.exception("Error while stopping capture")

        # Wait until capture has actually stopped
        try:
            if sniffer.thread is not None:
                sniffer.thread.join(timeout=5)
        except Exception:
            logger.exception("Error while waiting for capture thread")

        # Process queued packets before stopping consumer
        packet_queue.join()

        # Stop consumer cleanly
        packet_queue.put(None)
        packet_queue.join()
        consumer_thread.join()

    # ---------------- DETECT THREATS ----------------

    detect_threats()

    # ---------------- FINAL SUMMARY ----------------

    print("\n========== CAPTURE SUMMARY ==========")

    print("Total IPv4 packets processed:", stats["total"])
    print("TCP packets:", stats["TCP"])
    print("UDP packets:", stats["UDP"])
    print("ICMP packets:", stats["ICMP"])
    print("Other packets:", stats["Other"])

    print("\nRecent alerts:")

    for alert in get_recent_alerts():
        print(alert)

    logger.info(
        "Capture finished. Total IPv4 packets processed: %s",
        stats["total"]
    )

    print("\nPacket capture finished.")


# ---------------- PROGRAM ENTRY POINT ----------------

if __name__ == "__main__":
    main()