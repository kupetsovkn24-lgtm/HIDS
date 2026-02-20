# File: core/database.py

from logging import log
import sqlite3
import datetime
import json
from typing import List

from core.anomaly import AnomalyEvent
from core.config import DB_PATH

class DatabaseManager:
    """
    Manages all SQLite database operations for anomaly storage.
    """
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        with self._get_connection() as conn:
            self._create_table(conn)

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _create_table(self, conn: sqlite3.Connection):
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                severity INTEGER NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                details TEXT NOT NULL
            );
        """)

    def add_anomaly(self, event: AnomalyEvent):
        """Inserts a single AnomalyEvent into the database."""
        details_json = json.dumps(event.details)

        sql = """
            INSERT INTO events (timestamp, severity, category, description, details)
            VALUES (?, ?, ?, ?, ?)
        """
        try:
            with self._get_connection() as conn:
                conn.execute(sql, (
                    event.timestamp,
                    event.severity,
                    event.category,
                    event.description,
                    details_json
                ))
        except sqlite3.Error as e:
            print(f"DB write error: {e}")

    def get_anomalies(self, days: int) -> List[AnomalyEvent]:
        """Returns all anomalies from the last N days."""
        anomalies = []
        try:
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
            sql = "SELECT * FROM events WHERE timestamp >= ? ORDER BY timestamp DESC"

            with self._get_connection() as conn:
                cursor = conn.execute(sql, (cutoff_date,))
                rows = cursor.fetchall()

            for row in rows:
                anomalies.append(
                    AnomalyEvent(
                        timestamp=datetime.datetime.fromisoformat(row['timestamp']),
                        severity=row['severity'],
                        category=row['category'],
                        description=row['description'],
                        details=json.loads(row['details'])
                    )
                )
        except (sqlite3.Error, json.JSONDecodeError) as e:
            print(f"DB read error: {e}")
        return anomalies

    def get_pending_review_files(self) -> list:
        """
        Returns a unique list of files with status 'pending_review' or 'not_found'.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT DISTINCT details
                    FROM events
                    WHERE details LIKE '%"baseline_status": "pending_review"%'
                       OR details LIKE '%"baseline_status": "not_found"%'
                """)
                rows = cursor.fetchall()

            unique_files = {}
            for row in rows:
                try:
                    details = json.loads(row['details'])
                    sha256 = details.get("sha256")

                    if sha256 and sha256 != "N/A" and sha256 not in unique_files:
                        unique_files[sha256] = {
                            "sha256": sha256,
                            "path": details.get("executable_path", "N/A"),
                            "name": details.get("name", details.get("key_name", "N/A"))
                        }
                except (json.JSONDecodeError, TypeError):
                    continue

            return list(unique_files.values())

        except sqlite3.Error as e:
            print(f"Triage file retrieval error: {e}")
            return []

    def prune_old_data(self, days: int):
        """Deletes all records older than N days."""
        try:
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
            sql = "DELETE FROM events WHERE timestamp < ?"

            with self._get_connection() as conn:
                conn.execute(sql, (cutoff_date,))
            print(f" [DB Manager] Pruned records older than {days} days.")
        except sqlite3.Error as e:
            print(f"DB prune error: {e}")


if __name__ == "__main__":
    print("Starting database manager...")
    db_manager = DatabaseManager()

    print("Adding test anomaly...")
    test_event = AnomalyEvent(
        severity=1,
        category="Test",
        description="Read/prune verification",
        details={"status": "running"}
    )
    db_manager.add_anomaly(test_event)
    print("Test anomaly added.")

    print("\nPruning data older than 7 days...")
    db_manager.prune_old_data(days=7)

    print("\nFetching data from the last 7 days:")
    recent_anomalies = db_manager.get_anomalies(days=7)

    if not recent_anomalies:
        print("Error: could not read back the test anomaly.")
    else:
        print(f"Found {len(recent_anomalies)} anomalies:")
        for anomaly in recent_anomalies:
            print(f"  - {anomaly}")