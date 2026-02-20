# File: sensors/task.py
# --- HACK FOR TESTING ---
if __name__ == "__main__":
    import sys, os
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append(project_root)
# --- END HACK ---

import subprocess
import re
import logging
from typing import List
from .base import BaseSensor
from core.anomaly import AnomalyEvent
from core.config import TRUSTED_AUTHORS, TASK_SUSPICIOUS_KEYWORDS
from core.baseline_manager import BaselineManager
from core.utils import get_sha256, parse_command_path, TRUSTED_STATUSES

log = logging.getLogger(__name__)


class TaskSensor(BaseSensor):
    """
    Task Scheduler sensor v2.
    Integrates with baseline.db for trust verification.
    """
    def __init__(self, baseline: BaselineManager):
        self.baseline = baseline

    def scan(self) -> List[AnomalyEvent]:
        anomalies = []
        reported_tasks = set()

        try:
            cmd = ["schtasks", "/QUERY", "/FO", "LIST", "/V"]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding='cp866', errors='ignore')

            if result.returncode != 0:
                log.error(f" [TaskSensor] Error executing schtasks: {result.stderr}")
                return []

            output = result.stdout
            tasks = output.split("HostName:")

            for task_data in tasks[1:]:
                task_name_match = re.search(r"TaskName:\s+(.*?)\r", task_data)
                task_run_match = re.search(r"Task To Run:\s+(.*?)\r", task_data)
                task_author_match = re.search(r"Run As User:\s+(.*?)\r", task_data)

                if not task_name_match or not task_run_match:
                    continue

                task_name = task_name_match.group(1).strip()
                command = task_run_match.group(1).strip()
                task_author = task_author_match.group(1).strip() if task_author_match else "Unknown"

                # Skip tasks from trusted authors
                is_trusted_author = any(author.lower() in task_author.lower() for author in TRUSTED_AUTHORS)
                if is_trusted_author:
                    continue

                exe_path = parse_command_path(command)
                sha256 = None
                status = "unknown"

                if exe_path:
                    sha256 = get_sha256(exe_path)
                    if sha256 and self.baseline:
                        status = self.baseline.get_executable_status(sha256) or "not_found"
                else:
                    status = "pending_review"

                if status not in TRUSTED_STATUSES and task_name not in reported_tasks:
                    severity = 7 if status == "pending_review" else 8
                    description = f"{'Untrusted' if status != 'not_found' else 'Unknown'} scheduled task found: {task_name}"

                    anomalies.append(AnomalyEvent(
                        severity=severity,
                        category="Task",
                        description=description,
                        details={
                            "task_name": task_name,
                            "author": task_author,
                            "command": command,
                            "executable_path": exe_path or "N/A",
                            "sha256": sha256 or "N/A",
                            "baseline_status": status
                        }
                    ))
                    reported_tasks.add(task_name)

                    if any(keyword.lower() in command.lower() for keyword in TASK_SUSPICIOUS_KEYWORDS):
                        anomalies.append(AnomalyEvent(
                            severity=max(severity, 8),
                            category="Task",
                            description=f"Suspicious keyword in untrusted/unknown task '{task_name}'.",
                            details={
                                "task_name": task_name, "author": task_author, "command": command,
                                "executable_path": exe_path or "N/A", "sha256": sha256 or "N/A",
                                "baseline_status": status, "suspicious_keyword": True
                            }
                        ))

        except FileNotFoundError:
            log.error(" [TaskSensor] Error: schtasks.exe not found in PATH.")
        except Exception as e:
            log.error(f" [TaskSensor] Critical error during scan: {e}")

        return anomalies


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
    print("="*50)
    print("Testing Task Sensor v2 (with Baseline DB)...")

    from core.baseline_manager import BaselineManager
    baseline_manager = BaselineManager()

    if not baseline_manager._conn:
        print("\n!!! ERROR: Failed to connect to baseline.db. Cannot run test effectively. !!!")
    else:
        sensor = TaskSensor(baseline=baseline_manager)
        found_anomalies = sensor.scan()

        if not found_anomalies:
            print("\n--- RESULT: No untrusted/unknown scheduled tasks found ---")
        else:
            print(f"\n--- RESULT: FOUND {len(found_anomalies)} UNTRUSTED/UNKNOWN TASK ANOMALIES ---")
            for anomaly in found_anomalies:
                print(anomaly)
                print(f"  Details: {anomaly.details}\n")
                print("="*50)