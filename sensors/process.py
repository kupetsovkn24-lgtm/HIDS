# File: sensors/process.py (VERSION 2 - WITH BASELINE.DB INTEGRATION)

# --- HACK FOR TESTING ---
if __name__ == "__main__":
    import sys, os
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append(project_root)
# --- END HACK ---

import psutil
import logging # Use logging
from typing import List, Set # Set is no longer needed for __init__
from sensors.base import BaseSensor
from core.anomaly import AnomalyEvent
from core.config import SUSPICIOUS_PATHS
# --- NEW IMPORTS ---
from core.baseline_manager import BaselineManager # Our baseline DB manager
from core.utils import get_sha256, parse_command_path, TRUSTED_STATUSES, normalize_path # Utilities

log = logging.getLogger(__name__)


class ProcessSensor(BaseSensor):
    """
    Process sensor v2.
    Integrates with baseline.db for trust verification.
    """

    # --- UPDATED __init__ ---
    def __init__(self, baseline: BaselineManager):
        """ Accepts the BaselineManager. """
        self.baseline = baseline

    # --- HEAVILY UPDATED scan method ---
    def scan(self) -> List[AnomalyEvent]:
        anomalies = []
        reported_pids = set() # Avoid duplicate alerts for the same PID

        # Request necessary attributes including 'exe' and 'cmdline'
        attrs = ['pid', 'name', 'username', 'exe', 'cmdline']
        for proc in psutil.process_iter(attrs):
            try:
                # --- Get Process Info ---
                proc_info = proc.info
                proc_pid = proc_info['pid']
                proc_name = proc_info['name']
                proc_path = normalize_path(proc_info['exe']) # Normalize path
                proc_cmdline = proc_info['cmdline'] or [] # Ensure it's a list

                # --- Baseline Integration ---
                sha256 = None
                status = "unknown" # Default status

                if proc_path:
                    # 1. Get hash
                    sha256 = get_sha256(proc_path)
                    # 2. Query baseline DB
                    if sha256 and self.baseline:
                        status = self.baseline.get_executable_status(sha256) or "not_found"

                # --- NEW FILTERING LOGIC ---
                # IGNORE process if its status is trusted
                if status in TRUSTED_STATUSES:
                    continue # This is a trusted executable, skip further checks

                # --- Anomaly Detection Logic (Now applied ONLY to untrusted/unknown) ---

                suspicious_path_found = None
                reason = ""

                # Check 1: Suspicious executable path
                if proc_path:
                    for s_path in SUSPICIOUS_PATHS:
                        # Use startswith for normalized paths
                        if proc_path.startswith(normalize_path(s_path)):
                            suspicious_path_found = s_path
                            reason = f"Executable path starts with suspicious folder: '{s_path}'."
                            break

                # Check 2: Suspicious path in command line arguments
                if not suspicious_path_found and proc_cmdline:
                    cmd_line_str = " ".join(proc_cmdline)
                    for s_path in SUSPICIOUS_PATHS:
                        # Check if normalized suspicious path is in the command line string
                        if normalize_path(s_path) in cmd_line_str.lower():
                            suspicious_path_found = s_path
                            reason = f"Suspicious path '{s_path}' found in command line arguments."
                            break

                # Create anomaly if a suspicious path was found for a non-trusted process
                if suspicious_path_found and proc_pid not in reported_pids:
                    severity = 7 if status == "pending_review" else 8 # Higher for unknown
                    anomalies.append(AnomalyEvent(
                        severity=severity,
                        category="Process",
                        description=f"{'Untrusted' if status != 'not_found' else 'Unknown'} process '{proc_name}' linked to suspicious path.",
                        details={
                            "pid": proc_pid,
                            "name": proc_name,
                            "path": proc_path or "N/A",
                            "sha256": sha256 or "N/A",
                            "baseline_status": status,
                            "cmdline": " ".join(proc_cmdline),
                            "reason": reason
                        }
                    ))
                    reported_pids.add(proc_pid)

                # Check 3: Masquerading (old logic, now only applied to non-trusted)
                # Check for svch0st or non-system taskmgr
                is_masquerading = 'svch0st' in proc_name.lower() or \
                                  ('taskmgr' in proc_name.lower() and proc_path and \
                                   not proc_path.startswith(normalize_path('C:\\Windows\\System32')))

                if is_masquerading and proc_pid not in reported_pids:
                    severity = 9 # Masquerading is high severity
                    anomalies.append(AnomalyEvent(
                        severity=severity,
                        category="Process",
                        description=f"Potential Masquerading: Untrusted/Unknown process named '{proc_name}'.",
                        details={
                            "pid": proc_pid,
                            "name": proc_name,
                            "path": proc_path or "N/A",
                            "sha256": sha256 or "N/A",
                            "baseline_status": status
                        }
                    ))
                    reported_pids.add(proc_pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue # Ignore processes we can't access
            except Exception as e:
                # Log unexpected errors but continue scanning other processes
                log.error(f"[ProcessSensor] Unexpected error processing PID {proc_info.get('pid', 'N/A')}: {e}")

        return anomalies

# --- Test Block (Updated) ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
    print("="*50)
    print("Testing Process Sensor v2 (with Baseline DB)...")

    # Import and initialize BaselineManager for the test
    from core.baseline_manager import BaselineManager
    baseline_manager = BaselineManager()

    if not baseline_manager._conn:
        print("\n!!! ERROR: Failed to connect to baseline.db. Cannot run test. !!!")
    else:
        process_sensor = ProcessSensor(baseline=baseline_manager)
        found_anomalies = process_sensor.scan()

        if not found_anomalies:
            print("\n--- RESULT: No untrusted/unknown process anomalies found ---")
        else:
            print(f"\n--- RESULT: FOUND {len(found_anomalies)} UNTRUSTED/UNKNOWN PROCESS ANOMALIES ---")
            for anomaly in found_anomalies:
                print(anomaly)
                print(f"  Details: {anomaly.details}\n")
    print("="*50)