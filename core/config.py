import json
import winreg
import sys
from pathlib import Path

# --- Paths & Constants ---

# PROJECT_ROOT resolves to the HIDS_Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DB_PATH = PROJECT_ROOT / "data" / "anomalies.db"
GEOIP_DB_PATH = PROJECT_ROOT / "data" / "GeoLite2-Country.mmdb"
CONFIG_FILE_PATH = PROJECT_ROOT / "config" / "config.json"
CONFIG_SCHEMA_PATH = PROJECT_ROOT / "config" / "schema.json"

# Maps JSON string keys to winreg constants
WINREG_HIVES = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS
}

# --- Load config ---
try:
    with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

except FileNotFoundError:
    print(f"ERROR: Config file '{CONFIG_FILE_PATH}' not found. Using empty defaults.", file=sys.stderr)
    config_data = {}
except json.JSONDecodeError:
    print(f"ERROR: Config file '{CONFIG_FILE_PATH}' contains invalid JSON.", file=sys.stderr)
    sys.exit(1)

# --- Parse config sections ---

_paths = config_data.get('paths', {})
TSHARK_PATH = _paths.get('tshark', r"C:\Program Files\Wireshark\tshark.exe")

_settings = config_data.get('settings', {})
NETWORK_INTERFACE = _settings.get('network_interface', "Wi-Fi")
DAYS_TO_KEEP = int(_settings.get('days_to_keep_logs', 7))
SCAN_DURATION_SEC = int(_settings.get('scan_duration_sec', 10))
STRICT_PORT_MODE = bool(_settings.get('strict_mode_process_ports', True))

_whitelists = config_data.get('whitelists', {})
TRUSTED_IPS = set(_whitelists.get('trusted_ips', []))
EXTRA_TRUSTED_DOMAIN_SUFFIXES = set(_whitelists.get('trusted_domain_suffixes', []))
TRUSTED_EXACT_DOMAINS = set(_whitelists.get('trusted_exact_domains', []))
TRUSTED_AUTHORS = set(_whitelists.get('trusted_authors', []))
PROCESS_TRUSTED_PORTS = {
    process.lower(): set(ports)
    for process, ports in _whitelists.get('process_trusted_ports', {}).items()
}

_blacklists = config_data.get('blacklists', {})
SUSPICIOUS_PATHS = _blacklists.get('suspicious_paths', [])
SUSPICIOUS_PORTS = set(_blacklists.get('suspicious_ports', []))
SUSPICIOUS_TLDS = set(_blacklists.get('suspicious_tlds', []))

_registry = config_data.get('registry', {})
REG_AUTORUN_PATHS = []
all_autorun_paths = _registry.get('autorun_paths', []) + _registry.get('autorun_extended_paths', [])

for hive_str, path in all_autorun_paths:
    hive_const = WINREG_HIVES.get(hive_str)
    if hive_const:
        REG_AUTORUN_PATHS.append((hive_const, path))
    else:
        print(f"Config error: unknown registry hive key '{hive_str}'", file=sys.stderr)

_filesystem = config_data.get('filesystem', {})
FILESYSTEM_SUSPICIOUS_EXTENSIONS = set(_filesystem.get('suspicious_extensions', []))
FILESYSTEM_IGNORE_EXTENSIONS = set(_filesystem.get('ignore_extensions', []))

_net_detect = config_data.get('network_detection', {})
DGA_ENTROPY_THRESHOLD = float(_net_detect.get('dga_entropy_threshold', 4.0))
DNS_TUNNEL_LENGTH_THRESHOLD = int(_net_detect.get('dns_tunnel_length_threshold', 60))

_tasks = config_data.get('tasks', {})
TASK_SUSPICIOUS_KEYWORDS = _tasks.get('suspicious_task_keywords', [])

_rules = config_data.get('correlation_rules', {})

_susp_parent = _rules.get('suspicious_parent', {})
CORR_OFFICE_PROCS = set(_susp_parent.get('office_procs', []))
CORR_SHELL_PROCS = set(_susp_parent.get('shell_procs', []))
CORR_EXPECTED_PARENTS = _susp_parent.get('expected_parents', {})

CORR_LOLBAS_PATTERNS = _rules.get('lolbas_patterns', {})

from sensors import ProcessSensor, NetworkSensor, RegistrySensor, FileSensor, TaskSensor
SENSOR_MAP = {
    "Process": ProcessSensor,
    "Network": NetworkSensor,
    "Registry": RegistrySensor,
    "File": FileSensor,
    "Task": TaskSensor
}