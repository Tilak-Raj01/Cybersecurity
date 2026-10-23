import sqlite3
import time


class IncidentLogger:
    def __init__(self, db_path=":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.create_table()

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            rule_id TEXT,
            severity TEXT,
            src_ip TEXT,
            message TEXT
        );
        """
        self.conn.execute(query)
        self.conn.commit()

    def log_event(self, rule_id, severity, src_ip, message):
        query = """
            INSERT INTO security_events
                (timestamp, rule_id, severity, src_ip, message)
            VALUES (?, ?, ?, ?, ?)
        """
        self.conn.execute(
            query,
            (time.time(), rule_id, severity, src_ip, message),
        )
        self.conn.commit()

    def fetch_recent(self, limit=10):
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit < 0:
            raise ValueError("limit must be non-negative")

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        return cursor.fetchall()


def display_events_table(events):
    """Formats and prints the list of security event tuples as a clean CLI table."""
    if not events:
        print("No events found in database.")
        return

    headers = ["ID", "Timestamp", "Rule ID", "Severity", "Source IP", "Message"]
    col_widths = [5, 20, 15, 10, 16, 45]

    def format_row(row):
        values = list(row)
        if len(values) > 1 and isinstance(values[1], (int, float)):
            values[1] = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(values[1])
            )
        return " | ".join(
            f"{str(value):<{width}}" for value, width in zip(values, col_widths)
        )

    print(format_row(headers))
    print("-+-".join("-" * width for width in col_widths))
    for event in events:
        print(format_row(event))
