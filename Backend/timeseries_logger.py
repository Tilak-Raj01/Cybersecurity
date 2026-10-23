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
        query = "INSERT INTO security_events (timestamp, rule_id, severity, src_ip, message) VALUES (?, ?, ?, ?, ?)"
        self.conn.execute(query, (time.time(), rule_id, severity, src_ip, message))
        self.conn.commit()

    def fetch_recent(self, limit=10):
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")
        if limit < 0:
            raise ValueError("limit must be non-negative")

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,))
        return cursor.fetchall()
