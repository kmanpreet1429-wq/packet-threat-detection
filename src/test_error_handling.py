import logging

logging.basicConfig(
    filename="packet_detector.log",
    level=logging.ERROR,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

try:
    connection = None
    connection.execute("SELECT 1")

except Exception:
    logging.exception("Test error handled successfully")
    print("Error Handling Test: PASS")