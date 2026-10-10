<<<<<<< HEAD
# 🛡️ Python Packet Threat Detector

A Python-based network monitoring project that captures packets, identifies common network protocols, detects basic suspicious activity, and stores packet information and alerts in an SQLite database.

## Features

- Network packet capture using Scapy.
- Identification of TCP, UDP, ICMP, and IP traffic.
- Basic port scan detection.
- Basic ICMP flood detection.
- Threat severity classification: HIGH, MEDIUM, and LOW.
- SQLite database for storing packets and alerts.
- Streamlit dashboard for viewing packet statistics and alerts.
- Automatic dashboard refresh.
- Logging and error-handling tests.
- Rule-based detection tests.

## Technologies Used

- Python
- Scapy
- SQLite
- Streamlit
- Pandas
- Plotly
- Python Logging
- Threading and Queues

## Project Structure

```text
packet_threat_detector/
├── captures/
├── src/
│   ├── dashboard.py
│   ├── database.py
│   ├── main.py
│   ├── main_backup.py
│   ├── rules.py
│   ├── test_alerts.py
│   ├── test_database_error.py
│   ├── test_error_handling.py
│   ├── test_live_detection.py
│   └── test_rules.py
├── venv/
├── .gitignore
├── packets.db
├── packet_detector.log
├── requirements.txt
└── README.md
=======
# packet-threat-detection
Python-based network packet monitoring and basic threat detection dashboard.
>>>>>>> 06fc720c7a085519cd0da835e5e5ce7cbebdc72f
