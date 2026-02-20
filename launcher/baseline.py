# File: launcher/baseline.py
print("[DEBUG] Baseline builder script started...")

import os, sys, sqlite3, hashlib, subprocess, winreg, psutil, re, socket, ctypes, shutil
from datetime import datetime
from typing import Optional, Tuple
import logging

# -----------------------
# Configuration
# -----------------------
DB_NAME = "baseline.db"
BACKUP_NAME = "baseline.db.bak"

TRUSTED_PUBLISHERS = {
    "Microsoft Corporation", "Intel Corporation", "NVIDIA Corporation",
    "Lenovo", "Google LLC", "Mozilla Corporation", "Realtek", "Adobe Systems"
}

SYSTEM_PATHS = (
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
)

REG_AUTORUN_PATHS = [
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

# -----------------------
# Logging
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("BaselineBuilder")

# -----------------------
# Utilities
# -----------------------
def is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def normalize_path(path: str) -> str:
    return os.path.normpath(path).lower() if path else ""

def get_sha256(file_path: str) -> Optional[str]:
    if not file_path or not os.path.exists(file_path):
        return None
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, PermissionError):
        return None

_SIG_CACHE = {}

def run_powershell_signature_check(file_path: str, timeout: int = 5) -> Tuple[str, str]:
    """
    Gets the Authenticode signature status and publisher using PowerShell.
    Returns (Status, Publisher).
    """
    normalized_path = normalize_path(file_path)
    if normalized_path in _SIG_CACHE:
        return _SIG_CACHE[normalized_path]

    if not os.path.exists(normalized_path):
        _SIG_CACHE[normalized_path] = ("NotFound", "N/A")
        return _SIG_CACHE[normalized_path]

    ps_cmd = (
        r"$sig = Get-AuthenticodeSignature -FilePath '{0}' -ErrorAction SilentlyContinue; "
        r"if ($sig) {{ "
        r"  $status = $sig.Status.ToString(); "
        r"  $publisher = 'N/A'; "
        r"  if ($sig.SignerCertificate) {{ "
        r"    $subject = $sig.SignerCertificate.Subject; "
        r"    $org = ($subject -split ',') | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ -like 'O=*' }} | Select-Object -First 1; "
        r"    $cn = ($subject -split ',') | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ -like 'CN=*' }} | Select-Object -First 1; "
        r"    if ($org) {{ $publisher = $org -replace '^O=' }} "
        r"    elseif ($cn) {{ $publisher = $cn -replace '^CN=' }} "
        r"    else {{ $publisher = 'UnknownSubjectFormat' }}; "
        r"  }} else {{ $publisher = 'NoCertificate'; }}; "
        r"  Write-Output ('{{0}};{{1}}' -f $status, ($publisher -replace '\"','')); "
        r"}} else {{ 'NotSigned;N/A' }}"
    ).format(normalized_path.replace("'", "''"))

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=timeout, encoding='utf-8', errors='ignore'
        )

        out = result.stdout.strip()

        if result.returncode == 0 and out:
            parts = out.split(";", 1)
            status = parts[0].strip()
            pub = parts[1].strip().replace('"', '') if len(parts) > 1 else "N/A"
            if pub.upper() == "N/A" or not pub:
                pub = "N/A"
            res = (status, pub)
        elif result.returncode != 0:
            log.warning(f"SigCheck PS Error for '{os.path.basename(normalized_path)}': {result.stderr.strip()[:100]}")
            res = ("Error", "PSError")
        else:
            res = ("Error", "NoOutput")

    except subprocess.TimeoutExpired:
        res = ("Error", "Timeout")
        log.warning(f"SigCheck timed out for '{os.path.basename(normalized_path)}'")
    except Exception as e:
        res = ("Error", "PyExcp")
        log.error(f"SigCheck Python error for '{os.path.basename(normalized_path)}': {e}")

    _SIG_CACHE[normalized_path] = res
    return res


def determine_status(publisher: str, path: str, sig_status: str) -> str:
    """Determines the trust status based on signature and publisher."""
    trusted_pub = any(pub.lower() in (publisher or "").lower() for pub in TRUSTED_PUBLISHERS)
    trusted_path = any(normalize_path(path).startswith(normalize_path(p)) for p in SYSTEM_PATHS)

    if sig_status == "Valid" and trusted_pub and trusted_path:
        return "auto_trusted"
    elif sig_status == "Valid" and trusted_pub:
        return "trusted_signature"
    elif sig_status == "NotSigned":
        return "not_signed"
    else:
        return "pending_review"


_CMD_EXE_REGEX = re.compile(r'["\']?([A-Za-z]:\\(?:["\'\s]|\\\s?)+?\.exe)["\']?', re.IGNORECASE)

def parse_command_path(command: str) -> str:
    """
    Extracts the path to an .exe file from a command string.
    Handles environment variables and quoted paths.
    """
    if not command:
        return ""
    try:
        expanded = os.path.expandvars(command)
    except Exception:
        expanded = command

    # 1. Try regex match
    m = _CMD_EXE_REGEX.search(expanded)
    if m:
        p = m.group(1)
        if os.path.exists(p):
            return normalize_path(p)

    # 2. Handle rundll32 specifically
    if re.search(r'\brundll32\b', expanded, re.IGNORECASE):
        sys_path = os.path.expandvars(r"%SystemRoot%\System32\rundll32.exe")
        if os.path.exists(sys_path):
            return normalize_path(sys_path)

    # 3. Try treating the whole command as a simple path
    if os.path.exists(expanded) and os.path.isfile(expanded) and expanded.lower().endswith(".exe"):
        return normalize_path(expanded)

    return ""


# -----------------------
# Database
# -----------------------
def create_or_backup_db():
    if os.path.exists(DB_NAME):
        shutil.copy2(DB_NAME, BACKUP_NAME)
        log.info(f"[Backup] Created {BACKUP_NAME}")
    conn = sqlite3.connect(DB_NAME, timeout=30)
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS executables (
        sha256 TEXT PRIMARY KEY,
        path TEXT,
        publisher TEXT,
        status TEXT,
        first_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS autoruns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hive TEXT, key_path TEXT, value_name TEXT,
        command TEXT, exe_sha256 TEXT, status TEXT, first_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS network_listeners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        port INTEGER,
        protocol TEXT,
        path TEXT,
        exe_sha256 TEXT,
        status TEXT,
        first_seen TEXT,
        notes TEXT,
        FOREIGN KEY (exe_sha256) REFERENCES executables(sha256)
    );
""")
    conn.commit()
    return conn

def upsert_executable(cur, sha256, path, publisher, status):
    path = normalize_path(path)
    cur.execute("SELECT status FROM executables WHERE sha256=?", (sha256,))
    row = cur.fetchone()
    if not row:
        cur.execute(
            "INSERT INTO executables (sha256, path, publisher, status, first_seen) VALUES (?, ?, ?, ?, ?)",
            (sha256, path, publisher, status, datetime.utcnow().isoformat())
        )
        log.info(f"[NEW] Added executable: {path} ({publisher}) → {status}")
    else:
        existing = row[0]
        priority = {"pending_review": 0, "not_signed": 1, "trusted_signature": 2, "auto_trusted": 3}
        if priority.get(status, 0) > priority.get(existing, 0):
            cur.execute("UPDATE executables SET status=? WHERE sha256=?", (status, sha256))
            log.info(f"[UPDATE] Status upgraded for {path} → {status}")

# -----------------------
# Scanners
# -----------------------
def scan_processes(conn):
    cur = conn.cursor()
    seen = set()
    for proc in psutil.process_iter(["exe"]):
        try:
            exe = proc.info.get("exe")
            if not exe: continue
            exe = normalize_path(exe)
            if exe in seen: continue
            seen.add(exe)
            sha = get_sha256(exe)
            if not sha: continue
            sig, pub = run_powershell_signature_check(exe)
            status = determine_status(pub, exe, sig)
            upsert_executable(cur, sha, exe, pub, status)
        except Exception:
            continue
    conn.commit()
    log.info(f"[OK] Processes scanned: {len(seen)}")

def scan_autoruns(conn):
    cur = conn.cursor()
    total = 0
    for hive, key_path in REG_AUTORUN_PATHS:
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        val, cmd, _ = winreg.EnumValue(key, i)
                        i += 1
                        exe = parse_command_path(cmd)
                        sha = get_sha256(exe) if exe else None
                        status = "pending_review"
                        pub, sig = "N/A", "N/A"
                        if sha:
                            sig, pub = run_powershell_signature_check(exe)
                            status = determine_status(pub, exe, sig)
                            upsert_executable(cur, sha, exe, pub, status)
                        cur.execute(
                            "INSERT INTO autoruns (hive,key_path,value_name,command,exe_sha256,status,first_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (str(hive), key_path, val, cmd, sha, status, datetime.utcnow().isoformat())
                        )
                        total += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
    conn.commit()
    log.info(f"[OK] Autoruns scanned: {total}")

def scan_listeners(conn):
    cur = conn.cursor()
    log.info("[*] Scanning network listeners (IPv4 + IPv6)...")
    conns = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        log.error(f"Failed to enumerate listeners: {e}")

    count = 0
    for c in conns:
        try:
            if c.status != psutil.CONN_LISTEN or not c.pid:
                continue

            port = c.laddr.port
            proc = psutil.Process(c.pid)
            exe = normalize_path(proc.exe())
            process_name = proc.name()
            sha = get_sha256(exe)

            if not sha:
                continue

            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            sig, pub = run_powershell_signature_check(exe)
            status = determine_status(pub, exe, sig)
            upsert_executable(cur, sha, exe, pub, status)

            cur.execute(
                "INSERT INTO network_listeners (port, protocol, path, exe_sha256, status, first_seen, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (port, proto, exe, sha, status, datetime.utcnow().isoformat(), process_name)
            )
            count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            log.warning(f"Error processing listener on port {c.laddr.port if c.laddr else 'N/A'}: {e}")
            continue

    conn.commit()
    log.info(f"[OK] Network listeners scanned: {count} entries added/updated.")

# -----------------------
# Main
# -----------------------
def main():
    if os.name != "nt":
        log.error("Windows only.")
        return
    if not is_windows_admin():
        log.error("Please run as Administrator.")
        return

    conn = create_or_backup_db()
    try:
        scan_processes(conn)
        scan_autoruns(conn)
        scan_listeners(conn)
    finally:
        conn.close()
    log.info("✅ Baseline completed. Check baseline.db for results.")

# -----------------------
# Entry point
# -----------------------
if __name__ == "__main__":
    main()
