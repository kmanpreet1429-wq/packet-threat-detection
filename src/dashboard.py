import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="Packet Threat Detector",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- AUTO REFRESH ----------------

st_autorefresh(
    interval=5000,
    key="packet_dashboard_refresh"
)

# ---------------- DASHBOARD TITLE ----------------

st.title("🛡️ Packet Threat Detector")
st.caption("Live Network Monitoring & Threat Detection Dashboard")

# ---------------- DATABASE CONNECTION ----------------

connection = sqlite3.connect("packets.db")

try:
    # Total packets
    total_packets = pd.read_sql_query(
        "SELECT COUNT(*) AS count FROM packets",
        connection
    )["count"][0]

    # Count HIGH severity alerts
    high_alerts = pd.read_sql_query(
        "SELECT COUNT(*) AS count FROM alerts WHERE severity = 'HIGH'",
        connection
    )["count"][0]

# Count MEDIUM severity alerts
    medium_alerts = pd.read_sql_query(
        "SELECT COUNT(*) AS count FROM alerts WHERE severity = 'MEDIUM'",
        connection
    )["count"][0]

    # Total alerts
    total_alerts = pd.read_sql_query(
        "SELECT COUNT(*) AS count FROM alerts",
        connection
    )["count"][0]
    # Count alerts by severity
    severity_counts = pd.read_sql_query(
        """
        SELECT severity, COUNT(*) AS count
        FROM alerts
        GROUP BY severity
        """,
        connection
    )

    severity_map = dict(
        zip(severity_counts["severity"], severity_counts["count"])
    )

    high_alerts = severity_map.get("HIGH", 0)
    medium_alerts = severity_map.get("MEDIUM", 0)
    low_alerts = severity_map.get("LOW", 0)
    # Packet activity
    packets = pd.read_sql_query(
        """
        SELECT timestamp
        FROM packets
        ORDER BY id
        """,
        connection
    )

    # Protocol distribution
    protocol_data = pd.read_sql_query(
        """
        SELECT protocol, COUNT(*) AS count
        FROM packets
        GROUP BY protocol
        """,
        connection
    )

    # Recent alerts
    alerts = pd.read_sql_query(
        """
        SELECT threat_type, source_ip, severity, timestamp
        FROM alerts
        ORDER BY id DESC
        LIMIT 10
        """,
        connection
    )

finally:
    connection.close()

# ---------------- METRICS ----------------


col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("📦 Total Packets", int(total_packets))

with col2:
    st.metric("🚨 Total Alerts", int(total_alerts))

with col3:
    st.metric("🔴 High Severity", int(high_alerts))

with col4:
    st.metric("🟠 Medium Severity", int(medium_alerts))

with col5:
    st.metric("🟢 Low Severity", int(low_alerts))
# ---------------- PACKET ACTIVITY GRAPH ----------------

st.subheader("📈 Packet Activity Over Time")

if not packets.empty:
    # Database timestamps are ISO-format strings.
    packets["timestamp"] = pd.to_datetime(
        packets["timestamp"],
        errors="coerce"
    )

    packets = packets.dropna(subset=["timestamp"])

    if not packets.empty:
        packets["packet_count"] = range(1, len(packets) + 1)

        fig = px.line(
            packets,
            x="timestamp",
            y="packet_count",
            title="Cumulative Packets Processed",
            labels={
                "timestamp": "Time",
                "packet_count": "Packets Processed"
            }
        )

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No valid packet timestamps available.")
else:
    st.info("No packet data available.")

st.divider()

# ---------------- PROTOCOL DISTRIBUTION ----------------

st.subheader("🌐 Protocol Distribution")

if not protocol_data.empty:
    fig_pie = px.pie(
        protocol_data,
        names="protocol",
        values="count",
        title="Packets by Protocol",
        hole=0.35
    )

    st.plotly_chart(fig_pie, use_container_width=True)
else:
    st.info("No protocol data available.")

st.divider()

# ---------------- RECENT ALERTS ----------------

st.subheader("🚨 Recent Security Alerts")
# Filter alerts by severity
severity_options = ["ALL", "HIGH", "MEDIUM", "LOW"]

selected_severity = st.selectbox(
    "Filter alerts by severity",
    severity_options
)

if selected_severity != "ALL":
    alerts = alerts[
        alerts["severity"] == selected_severity
    ]

if not alerts.empty:
    st.dataframe(
        alerts,
        use_container_width=True,
        hide_index=True
    )
else:
    st.success("No alerts found.")

# ---------------- FOOTER ----------------

st.caption("Dashboard refreshes automatically every 5 seconds.")