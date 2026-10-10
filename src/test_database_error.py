import sqlite3
import logging
import os

logging.basicConfig(
    level=logging.ERROR,
    format="%(levelname)s | %(message)s"
)

test_database = "test_error_temp.db"

try:
    # Create a temporary database
    connection = sqlite3.connect(test_database)
    cursor = connection.cursor()

    # Create a test table
    cursor.execute(
        "CREATE TABLE test_table (id INTEGER PRIMARY KEY)"
    )

    connection.commit()
    connection.close()

    # Reopen and deliberately trigger a SQL error
    connection = sqlite3.connect(test_database)
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT * FROM missing_table")

    except sqlite3.Error:
        logging.exception("Database error handled successfully")
        print("Database Error Handling Test: PASS")

    finally:
        connection.close()

except sqlite3.Error:
    logging.exception("Database setup failed")
    print("Database setup failed.")

finally:
    # Remove only the temporary test database
    if os.path.exists(test_database):
        os.remove(test_database)
        print("Temporary test database cleaned up.")