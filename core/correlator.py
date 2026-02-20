# File: core/correlator.py

import re
import collections
import logging
from typing import List, Dict, Set, Tuple
from core.anomaly import AnomalyEvent
from core.utils import TRUSTED_STATUSES

log = logging.getLogger(__name__)

# --- Algorithm 1: "Suspicious Parent" settings ---
OFFICE_PROCS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELL_PROCS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}
EXPECTED_PARENTS = {
    "svchost.exe": "services.exe",
}

# --- Algorithm 2: LOLBAS settings ---
LOLBAS_PATTERNS = {
    "certutil.exe": [
        r"-urlcache.*http",  # File download
        r"-encode",          # Data encoding (possible exfiltration)
    ],
    "bitsadmin.exe": [
        r"/transfer",        # File upload/download
        r"/create",
    ],
    "regsvr32.exe": [
        r"/i:http",          # Execute scriptlet from URL
        r"/i:ftp",
    ],
    "rundll32.exe": [
        r"javascript:",      # JavaScript execution
        r"shell32.dll.*control_rundll",
    ],
    "mshta.exe": [
        r"http:",            # Execute HTA from URL
        r"vbscript:",        # VBScript execution
    ],
}

class AnomalyCorrelator:
    """
    The system "brain". Implements prioritization, Suspicious Parent,
    LOLBAS, and First Seen correlation algorithms.
    """

    def __init__(self):
        # Cache for unique correlated events per session: key = tuple of key fields
        self.correlated_events_cache: Set[Tuple] = set()

    def correlate_and_prioritize(self, events: List[AnomalyEvent]) -> List[AnomalyEvent]:
        """Main entry point: runs correlation then sorts by severity."""

        correlated_anomalies = self._run_correlation_algorithms(events)
        all_events = events + correlated_anomalies

        final_prioritized_list = sorted(
            all_events,
            key=lambda event: event.severity,
            reverse=True
        )

        self.correlated_events_cache.clear()
        return final_prioritized_list

    def _run_correlation_algorithms(self, events: List[AnomalyEvent]) -> List[AnomalyEvent]:
        """Runs all correlation algorithms and returns newly generated anomalies."""
        new_anomalies = []

        events_by_category: Dict[str, List[AnomalyEvent]] = collections.defaultdict(list)
        for e in events:
            events_by_category[e.category].append(e)

        new_anomalies.extend(self._correlate_suspicious_parent(events_by_category.get("Process", [])))
        new_anomalies.extend(self._correlate_lolbas_usage(events_by_category.get("Process", [])))
        new_anomalies.extend(self._correlate_first_seen(events))

        return new_anomalies

    def _correlate_suspicious_parent(self, process_events: List[AnomalyEvent]) -> List[AnomalyEvent]:
        """Detects anomalous parent-child process relationships."""
        new_anomalies = []
        for event in process_events:
            pid = event.details.get("pid")
            child_name = event.details.get("name", "").lower()
            parent_name = event.details.get("parent_name", "").lower()

            if not pid or not child_name or not parent_name or parent_name == "n/a":
                continue

            correlation_key = ("SuspiciousParent", pid, parent_name, child_name)
            if correlation_key in self.correlated_events_cache:
                continue

            is_suspicious = False
            reason = ""

            # Rule 1: Office app spawned a shell
            if parent_name in OFFICE_PROCS and child_name in SHELL_PROCS:
                is_suspicious = True
                reason = f"Office application '{parent_name}' launched a shell '{child_name}'."

            # Rule 2: System process has unexpected parent
            elif child_name in EXPECTED_PARENTS and parent_name != EXPECTED_PARENTS[child_name]:
                is_suspicious = True
                reason = f"System process '{child_name}' has unexpected parent '{parent_name}' (expected '{EXPECTED_PARENTS[child_name]}')."

            if is_suspicious:
                new_event = AnomalyEvent(
                    severity=9,
                    category="Correlated",
                    description=f"CORRELATION: Suspicious process launch '{child_name}' by parent '{parent_name}'.",
                    details={**event.details, "correlation_reason": reason}
                )
                new_anomalies.append(new_event)
                self.correlated_events_cache.add(correlation_key)

        return new_anomalies

    def _correlate_lolbas_usage(self, process_events: List[AnomalyEvent]) -> List[AnomalyEvent]:
        """Detects suspicious use of legitimate Windows utilities (LOLBAS)."""
        new_anomalies = []
        for event in process_events:
            pid = event.details.get("pid")
            proc_name = event.details.get("name", "").lower()
            cmdline = event.details.get("cmdline", "")

            if not pid or not proc_name or not cmdline:
                continue

            if proc_name in LOLBAS_PATTERNS:
                for pattern in LOLBAS_PATTERNS[proc_name]:
                    if re.search(pattern, cmdline, re.IGNORECASE):

                        correlation_key = ("LOLBAS", pid, proc_name, pattern)
                        if correlation_key in self.correlated_events_cache:
                            continue

                        reason = f"LOLBAS tool '{proc_name}' used with suspicious pattern: '{pattern}'."
                        new_event = AnomalyEvent(
                            severity=8,
                            category="Correlated",
                            description=f"CORRELATION: Suspicious use of system utility '{proc_name}'.",
                            details={**event.details, "correlation_reason": reason}
                        )
                        new_anomalies.append(new_event)
                        self.correlated_events_cache.add(correlation_key)
                        break  # One pattern match per process is enough

        return new_anomalies

    def _correlate_first_seen(self, all_events: List[AnomalyEvent]) -> List[AnomalyEvent]:
        """Elevates priority for anomalies involving objects not found in baseline."""
        new_anomalies = []
        for event in all_events:
            baseline_status = event.details.get("baseline_status")
            sha256 = event.details.get("sha256")

            if baseline_status == "not_found" and sha256:

                correlation_key = ("FirstSeen", sha256)
                if correlation_key in self.correlated_events_cache:
                    continue

                obj_type = "executable"
                if event.category == "Registry":
                    obj_type = "registry entry"
                elif event.category == "Task":
                    obj_type = "scheduled task"
                elif event.category == "File":
                    obj_type = "file"

                reason = f"Executable/Object with SHA256 '{sha256[:10]}...' not found in baseline database."

                original_name = event.details.get('process_name', event.details.get('name', event.details.get('file_name', 'N/A')))

                new_event = AnomalyEvent(
                    severity=max(8, event.severity + 2),
                    category="Correlated",
                    description=f"CORRELATION: First-seen {obj_type} '{original_name}'.",
                    details={
                        **event.details,
                        "correlation_reason": reason,
                        "original_category": event.category,
                        "original_description": event.description
                    }
                )
                new_anomalies.append(new_event)
                self.correlated_events_cache.add(correlation_key)

        return new_anomalies