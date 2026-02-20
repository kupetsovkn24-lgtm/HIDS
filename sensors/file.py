import os
import datetime
import logging
from typing import List
from sensors.base import BaseSensor
from core.anomaly import AnomalyEvent

from core.baseline_manager import BaselineManager
from core.utils import get_sha256, TRUSTED_STATUSES
from core.config import SUSPICIOUS_PATHS, FILESYSTEM_SUSPICIOUS_EXTENSIONS

log = logging.getLogger(__name__)

# Only flag files created/modified within this window
MONITOR_WINDOW_MINUTES = 20

class FileSensor(BaseSensor):
    """
    Scans the filesystem for recently created untrusted files.
    Paths and suspicious extensions are driven by config.json (v2.1).
    """

    def __init__(self, baseline: BaselineManager):
        self.baseline = baseline
        self.window = datetime.timedelta(minutes=MONITOR_WINDOW_MINUTES)
        self.watch_dirs = SUSPICIOUS_PATHS
        self.watch_exts = FILESYSTEM_SUSPICIOUS_EXTENSIONS

        log.info(f" [FileSensor] v2.1 init. Watching {len(self.watch_dirs)} paths.")
        log.info(f" [FileSensor] Suspicious extensions: {self.watch_exts}")

    def scan(self) -> List[AnomalyEvent]:
        anomalies = []
        now = datetime.datetime.now()

        for dir_path in self.watch_dirs:
            normalized_dir = os.path.normpath(os.path.expandvars(dir_path))

            if not os.path.exists(normalized_dir):
                log.debug(f" [FileSensor] Path not found (expected): {normalized_dir}")
                continue

            try:
                for entry in os.scandir(normalized_dir):
                    if not entry.is_file():
                        continue

                    try:
                        file_ext = os.path.splitext(entry.name)[1].lower()

                        if file_ext in self.watch_exts:
                            stats = entry.stat()
                            ctime = datetime.datetime.fromtimestamp(stats.st_ctime)
                            file_age = now - ctime

                            if file_age < self.window:
                                file_path = entry.path
                                sha256 = get_sha256(file_path)

                                status = "unknown"
                                if sha256 and self.baseline:
                                    status = self.baseline.get_executable_status(sha256) or "not_found"

                                if status in TRUSTED_STATUSES:
                                    log.debug(f" [FileSensor] New but trusted file: {entry.name}")
                                    continue

                                severity = 7 if status == "pending_review" else 8

                                anomalies.append(AnomalyEvent(
                                    severity=severity,
                                    category="File",
                                    description=f"New {'unknown' if status == 'not_found' else 'untrusted'} file in '{normalized_dir}'",
                                    details={
                                        "file_name": entry.name,
                                        "full_path": file_path,
                                        "extension": file_ext,
                                        "created_at": ctime.isoformat(),
                                        "sha256": sha256 or "N/A",
                                        "baseline_status": status
                                    }
                                ))
                    except FileNotFoundError:
                        continue  # File was deleted during scan
                    except OSError as e:
                        log.warning(f" [FileSensor] Access error on {entry.path}: {e}")

            except OSError as e:
                log.error(f" [FileSensor] Cannot access directory {normalized_dir}: {e}")

        return anomalies


if __name__ == "__main__":
    pass