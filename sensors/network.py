# File: sensors/network.py
# --- HACK FOR TESTING ---
if __name__ == "__main__":
    import sys, os
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append(project_root)
# --- END HACK ---

import ctypes
import math
import collections
import psutil
import logging
import subprocess
import os
import time
import socket
import ipaddress
import geoip2.database
from typing import List, Set, Dict, Optional
from sensors.base import BaseSensor
from core.anomaly import AnomalyEvent

from core.config import (
    EXTRA_TRUSTED_DOMAIN_SUFFIXES,
    TRUSTED_EXACT_DOMAINS,
    SUSPICIOUS_PORTS,
    SUSPICIOUS_TLDS,
    SCAN_DURATION_SEC,
    TSHARK_PATH,
    NETWORK_INTERFACE,
    GEOIP_DB_PATH,
    TRUSTED_IPS,
    PROCESS_TRUSTED_PORTS,
    STRICT_PORT_MODE,
    DGA_ENTROPY_THRESHOLD,
    DNS_TUNNEL_LENGTH_THRESHOLD
)

from core.baseline_manager import BaselineManager
from core.utils import get_sha256, normalize_path, TRUSTED_STATUSES


def is_admin() -> bool:
    try: return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except AttributeError: return False

IS_ADMIN = is_admin()
log = logging.getLogger(__name__)

def load_geoip_reader():
    if not GEOIP_DB_PATH.exists():
        return None
    try: return geoip2.database.Reader(GEOIP_DB_PATH)
    except Exception as e: log.error(f"Failed to load GeoIP: {e}"); return None

def shannon_entropy(s: str) -> float:
    if not s: return 0
    entropy = 0; counts = collections.Counter(s); length = float(len(s))
    for count in counts.values():
        freq = count / length
        if freq > 0: entropy -= freq * math.log(freq, 2)
    return entropy


class NetworkSensor(BaseSensor):
    """
    Hybrid network sensor v5.
    Uses context-aware port whitelists and improved DNS filters.
    """
    def __init__(self, baseline: BaselineManager):
        self.baseline = baseline
        self.tshark_found = os.path.exists(TSHARK_PATH)

        if NETWORK_INTERFACE:
            self.interface = NETWORK_INTERFACE
            log.info(f"[NS] Using forced interface: {self.interface}")
        else:
            self.interface = self._find_active_interface()
            if self.interface:
                log.info(f"[NS] Auto-detected interface: {self.interface}")
            else:
                log.warning("[NS] Could not detect network interface.")

        self.geoip_reader = load_geoip_reader()

        # Safe mode: falls back to psutil-only if no admin, tshark or interface
        self.safe_mode = not (IS_ADMIN and self.tshark_found and self.interface)

        log_msg = f"[NetworkSensor] Init V5. Baseline: {'Loaded' if baseline._conn else 'Failed'}, "
        log_msg += f"Mode: {'SAFE' if self.safe_mode else 'ADVANCED'}, Interface: {self.interface}, GeoIP: {'Ready' if self.geoip_reader else 'Not Found'}"
        log.info(log_msg)

    def _find_active_interface(self) -> str | None:
        try:
            stats = psutil.net_if_stats(); addrs = psutil.net_if_addrs(); best = None
            for iface, iface_stats in stats.items():
                if (iface_stats.isup and iface_stats.speed > 0 and iface not in ("Loopback", "lo") and iface in addrs):
                    for addr in addrs[iface]:
                        if addr.family == socket.AF_INET:
                            if "Ethernet" in iface or "Wi-Fi" in iface: return iface
                            if not best: best = iface
            return best
        except Exception as e: log.warning(f"Interface lookup error: {e}"); return None

    def scan(self) -> List[AnomalyEvent]:
        anomalies = []
        try: anomalies.extend(self._scan_psutil_connections())
        except Exception as e: log.error(f"[NS] psutil scan error: {e}")

        if not self.safe_mode:
            try: anomalies.extend(self._scan_dns_with_tshark())
            except Exception as e: log.error(f"[NS] tshark scan error: {e}")
        return anomalies

    def _scan_psutil_connections(self) -> List[AnomalyEvent]:
        anomalies = []
        seen_pids = {}

        try: conns = psutil.net_connections(kind='inet')
        except psutil.AccessDenied: log.warning("psutil conn access denied."); return []

        for conn in conns:
            if conn.status != 'ESTABLISHED' or not conn.raddr or not conn.pid: continue

            r_ip = conn.raddr.ip
            r_port = conn.raddr.port
            pid_info = self._get_pid_info_with_baseline(conn.pid, seen_pids)

            # Filtering logic: trusted process + allowed port -> skip
            if pid_info['status'] in TRUSTED_STATUSES:
                proc_name_lower = pid_info['name'].lower()

                if proc_name_lower in PROCESS_TRUSTED_PORTS:
                    if r_port in PROCESS_TRUSTED_PORTS[proc_name_lower]:
                        continue
                    # Port is unusual for this trusted process -> analyze further

                elif STRICT_PORT_MODE:
                    # In strict mode, even trusted processes are checked
                    pass

                else:
                    # Non-strict: any trusted process is allowed
                    continue

            # Analyze untrusted / unknown / trusted-on-odd-port connections
            try:
                ip_obj = ipaddress.ip_address(r_ip)
                if ip_obj.is_global and r_ip not in TRUSTED_IPS:
                    country = "Unknown"
                    if self.geoip_reader:
                        try: country = self.geoip_reader.country(r_ip).country.iso_code
                        except geoip2.errors.AddressNotFoundError: country = "N/A"

                    severity = 4
                    reason = "Direct IP connection (process pending review)"

                    if pid_info['status'] not in TRUSTED_STATUSES and pid_info['status'] != 'pending_review':
                        severity = 7
                        reason = "Direct IP connection (process unknown/not in baseline)"
                    elif pid_info['status'] in TRUSTED_STATUSES and pid_info['name'].lower() in PROCESS_TRUSTED_PORTS and r_port not in PROCESS_TRUSTED_PORTS[pid_info['name'].lower()]:
                        severity = 6
                        reason = f"Trusted process '{pid_info['name']}' on non-standard port {r_port}"

                    anomalies.append(AnomalyEvent(
                        severity=severity, category="Network",
                        description=f"{'Unknown/Untrusted' if severity >= 7 else 'Review Needed'} process '{pid_info['name']}' connected to IP.",
                        details={
                            "pid": pid_info['pid'], "process_name": pid_info['name'],
                            "parent_name": pid_info['parent_name'], "sha256": pid_info['sha256'],
                            "baseline_status": pid_info['status'] or "Not Found",
                            "remote_ip": r_ip, "remote_port": r_port, "geo_country": country,
                            "reason": reason
                        }
                    ))
            except ValueError: pass  # Not a valid IP

        return anomalies

    def _get_pid_info_with_baseline(self, pid: int, cache: dict) -> dict:
        if pid in cache: return cache[pid]
        info = {"pid": pid, "name": "N/A", "ppid": 0, "parent_name": "N/A", "exe_path": None, "sha256": None, "status": None}
        if pid is None or pid == 0: info["name"] = "System/Unknown"; info["parent_name"] = "System"; cache[pid] = info; return info
        try:
            proc = psutil.Process(pid); proc_dict = proc.as_dict(attrs=['name', 'ppid', 'exe'])
            info["name"] = proc_dict.get('name', 'N/A'); info["ppid"] = proc_dict.get('ppid'); info["exe_path"] = normalize_path(proc_dict.get('exe', ''))
            if info["ppid"]:
                try: info["parent_name"] = psutil.Process(info["ppid"]).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied): info["parent_name"] = "AccessDenied/Gone"
            else: info["parent_name"] = "System"
            if info["exe_path"]: info["sha256"] = get_sha256(info["exe_path"])
            if info["sha256"] and self.baseline: info["status"] = self.baseline.get_executable_status(info["sha256"])
        except (psutil.NoSuchProcess, psutil.AccessDenied): info["name"] = "AccessDenied/Gone"
        except Exception as e: log.error(f"PID info error {pid}: {e}")
        cache[pid] = info; return info

    def _scan_dns_with_tshark(self) -> List[AnomalyEvent]:
        anomalies = []
        if not self.interface: log.warning("DNS scan skipped: no interface."); return []

        command = [TSHARK_PATH, "-i", self.interface, "-a", f"duration:{SCAN_DURATION_SEC}", "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name", "-e", "dns.cname"]
        log.info(f" [NS] Starting tshark for {SCAN_DURATION_SEC}s on {self.interface}...")
        try: result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=SCAN_DURATION_SEC + 5)
        except (subprocess.TimeoutExpired, Exception) as e: log.error(f"[NS] tshark error: {e}"); return []
        if result.returncode != 0: log.error(f" [NS] tshark stderr: {result.stderr}"); return []

        unique_domains = set()
        for line in result.stdout.strip().splitlines():
            if line.strip():
                parts = line.strip().split('\t')
                if len(parts) >= 1 and parts[0]:
                    unique_domains.add(tuple(parts))

        log.info(f" [NS] tshark finished. Found {len(unique_domains)} unique DNS queries.")

        for item in unique_domains:
            domain = item[0]; cname = item[1] if len(item) > 1 and item[1] else None

            if not domain or domain == "." or domain.endswith(".local"): continue
            if domain in TRUSTED_EXACT_DOMAINS: continue
            if any(domain.endswith(trusted) for trusted in EXTRA_TRUSTED_DOMAIN_SUFFIXES): continue

            if len(domain) > DNS_TUNNEL_LENGTH_THRESHOLD:
                anomalies.append(AnomalyEvent(severity=9, category="Network", description=f"Very long DNS query (Tunneling?): {domain[:50]}...", details={"domain": domain, "length": len(domain)}))

            entropy = shannon_entropy(domain)
            if entropy > DGA_ENTROPY_THRESHOLD:
                anomalies.append(AnomalyEvent(severity=9, category="Network", description=f"High DNS query entropy (DGA?): {domain}", details={"domain": domain, "entropy": round(entropy, 2)}))

            if cname:
                if any(cname.endswith(trusted) for trusted in EXTRA_TRUSTED_DOMAIN_SUFFIXES): continue
                tld_found = next((tld for tld in SUSPICIOUS_TLDS if cname.endswith(tld)), None)
                if tld_found:
                    anomalies.append(AnomalyEvent(severity=7, category="Network", description=f"Domain '{domain}' CNAME redirects to suspicious host.", details={"domain": domain, "cname_redirect": cname, "reason": f"CNAME TLD ({tld_found})"}))

        return anomalies


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
    print("="*50); print("Testing Network Sensor V5..."); print(f"Admin: {IS_ADMIN}")

    from core.baseline_manager import BaselineManager
    baseline_manager = BaselineManager()
    if not baseline_manager._conn: print("\n!!! WARNING: Baseline DB connection failed. Psutil results might be noisy. !!!")

    network_sensor = NetworkSensor(baseline=baseline_manager)

    print("\n--- [Test Psutil (Baseline Integrated)] ---")
    psutil_anomalies = network_sensor._scan_psutil_connections()
    if not psutil_anomalies: print("No psutil anomalies found.")
    else: print(f"Found {len(psutil_anomalies)} psutil anomalies:"); [print(f"  - Sev:{a.severity} {a.description} | {a.details}") for a in psutil_anomalies]

    print("\n--- [Test TShark (Improved Filters)] ---")
    if network_sensor.safe_mode: print("Skipped: tshark unavailable.")
    else:
        print(f"!!! Starting {SCAN_DURATION_SEC}s tshark scan. Run `ping dga.xyz` etc. in another terminal !!!\n"); time.sleep(3)
        tshark_anomalies = network_sensor._scan_dns_with_tshark()
        if not tshark_anomalies: print("No tshark anomalies found.")
        else: print(f"Found {len(tshark_anomalies)} tshark anomalies:"); [print(f"  - Sev:{a.severity} {a.description} | {a.details}") for a in tshark_anomalies]
    print("="*50)