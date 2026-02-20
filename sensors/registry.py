# File: sensors/registry.py v2.1

# --- HACK FOR TESTING ---
if __name__ == "__main__":
    import sys, os
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append(project_root)
# --- END HACK ---

import winreg
import logging
from typing import List
from sensors.base import BaseSensor
from core.anomaly import AnomalyEvent
from core.baseline_manager import BaselineManager
from core.config import REG_AUTORUN_PATHS
from core.utils import get_sha256, parse_command_path, TRUSTED_STATUSES

log = logging.getLogger(__name__)


class RegistrySensor(BaseSensor):
    """
    Registry autorun sensor v2.1.
    Integrated with baseline.db for trust verification.
    """

    def __init__(self, baseline: BaselineManager):
        self.baseline = baseline

    def scan(self) -> List[AnomalyEvent]:
        anomalies = []

        for hkey, path in REG_AUTORUN_PATHS:
            try:
                with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, command_value, reg_type = winreg.EnumValue(key, i)
                            i += 1

                            # Skip non-string registry types (REG_DWORD, REG_BINARY, etc.)
                            if reg_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                                continue

                            command = str(command_value)

                            exe_path = parse_command_path(command)

                            # Skip entries without a resolvable .exe path (settings, numeric values, etc.)
                            if not exe_path:
                                continue

                            sha256 = get_sha256(exe_path)

                            if sha256 and self.baseline:
                                status = self.baseline.get_executable_status(sha256) or "not_found"
                            else:
                                # Path found but hash unavailable (e.g., file locked)
                                status = "pending_review"

                            if status not in TRUSTED_STATUSES:
                                severity = 7 if status == "pending_review" else 8

                                event = AnomalyEvent(
                                    severity=severity,
                                    category="Registry",
                                    description=f"Untrusted autorun entry: {name}",
                                    details={
                                        "key_name": name,
                                        "command": command,
                                        "executable_path": exe_path or "N/A",
                                        "sha256": sha256 or "N/A",
                                        "baseline_status": status,
                                        "registry_path": f"{hkey_to_string(hkey)}\\{path}"
                                    }
                                )
                                anomalies.append(event)

                        except OSError:
                            break  # No more values
            except FileNotFoundError:
                pass  # Registry key doesn't exist on this system
            except Exception as e:
                log.error(f" [RegistrySensor] Error reading {path}: {e}")

        return anomalies


def hkey_to_string(hkey_obj) -> str:
    """Converts a winreg HKEY object to a human-readable string."""
    if hkey_obj == winreg.HKEY_LOCAL_MACHINE: return "HKLM"
    if hkey_obj == winreg.HKEY_CURRENT_USER: return "HKCU"
    if hkey_obj == winreg.HKEY_CLASSES_ROOT: return "HKCR"
    if hkey_obj == winreg.HKEY_USERS: return "HKU"
    return str(hkey_obj)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    print("="*50)
    print("Testing Registry Sensor v2.1 (with Baseline DB)...")
    print("Note: HKLM requires admin rights.")

    from core.baseline_manager import BaselineManager
    baseline_manager = BaselineManager()

    if not baseline_manager._conn:
        print("\n!!! ERROR: Could not connect to baseline.db. Test cannot run. !!!")
    else:
        registry_sensor = RegistrySensor(baseline=baseline_manager)
        found_anomalies = registry_sensor.scan()

        if not found_anomalies:
            print("\n--- RESULT: No untrusted autorun entries found ---")
        else:
            print(f"\n--- RESULT: FOUND {len(found_anomalies)} UNTRUSTED ENTRIES ---")
            for anomaly in found_anomalies:
                print(anomaly)
                print(f"  Details: {anomaly.details}\n")