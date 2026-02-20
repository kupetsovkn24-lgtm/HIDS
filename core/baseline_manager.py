# File: core/baseline_manager.py

import sqlite3
import logging
from typing import Optional
from .config import PROJECT_ROOT
from pathlib import Path

log = logging.getLogger(__name__)

DB_NAME = "baseline.db"
BASELINE_DB_PATH = PROJECT_ROOT / "data" / DB_NAME


class BaselineManager:
    """
    Manages access to 'baseline.db'.
    Provides methods for querying the trust status of executables.
    """
    def __init__(self, db_path: Path = BASELINE_DB_PATH):
        self.db_path = db_path
        self._conn = None

        if not self.db_path.exists():
            log.error(f"Baseline database '{self.db_path}' not found!")
            log.error("Please run the baseline creation script first.")
        else:
            try:
                # Read-only connection via URI to prevent accidental modifications
                db_uri = f'file:{self.db_path}?mode=ro'
                self._conn = sqlite3.connect(db_uri, uri=True, check_same_thread=False)
                log.info("Connected to baseline.db (read-only)")
            except sqlite3.OperationalError as e:
                log.error(f"Failed to open baseline.db (read-only): {e}")
                log.error("Check file permissions or whether the database is locked.")
            except sqlite3.Error as e:
                log.error(f"General baseline.db connection error: {e}")

    def get_executable_status(self, sha256: Optional[str]) -> Optional[str]:
        """
        Returns the trust status ('auto_trusted', 'pending_review', etc.)
        of an executable based on its SHA256 hash.
        Returns None if not found or connection unavailable.
        """
        if not self._conn or not sha256:
            return None

        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT status FROM executables WHERE sha256 = ?", (sha256,))
            row = cursor.fetchone()
            return row[0] if row else None
        except sqlite3.Error as e:
            log.error(f"baseline.db query error (get_executable_status for {sha256[:10]}...): {e}")
            return None

    def __del__(self):
        if self._conn:
            self._conn.close()
            log.info("baseline.db connection closed")

    def set_executable_status(self, sha256: str, new_status: str) -> bool:
        """
        Sets a new status for a file in baseline.db.
        Opens a temporary read-write connection.
        """
        if not sha256 or not new_status:
            return False

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE executables SET status = ? WHERE sha256 = ?",
                (new_status, sha256)
            )
            conn.commit()
            conn.close()
            log.info(f"Status for {sha256[:10]}... updated to '{new_status}'")
            return True

        except sqlite3.Error as e:
            log.error(f"Failed to update status in baseline.db: {e}")
            return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    print("="*50)
    print("Testing BaselineManager...")
    manager = BaselineManager()

    if manager._conn:
        print(f"Connected to: {manager.db_path}")

        # Replace with a real hash from your baseline.db
        # 1. Open baseline.db with "DB Browser for SQLite"
        # 2. Go to Browse Data -> executables table
        # 3. Copy a SHA256 value (e.g., for python.exe or cmd.exe)
        test_hash_exists = "0b899508777d7ed5159e2a99a5eff60c54d0724493df3d630525b837fa43aa51"

        if test_hash_exists != "PASTE_A_REAL_SHA256_FROM_YOUR_DB_HERE":
            status_exists = manager.get_executable_status(test_hash_exists)
            if status_exists:
                print(f"Status for known hash {test_hash_exists[:10]}...: {status_exists}")
            else:
                print(f"Known hash {test_hash_exists[:10]}... NOT FOUND in DB (is it correct?).")
        else:
            print("\nWARNING: Please edit 'test_hash_exists' in baseline_manager.py with a real SHA256 from your DB.")

        non_existent_hash = "a" * 64
        status_none = manager.get_executable_status(non_existent_hash)
        print(f"Status for non-existent hash aaaaaa...: {status_none} (expected None)")
    else:
        print("\n--- TEST SKIPPED: Could not connect to database. ---")
        print(f"Ensure '{BASELINE_DB_PATH}' exists and is a valid SQLite file.")

    print("="*50)