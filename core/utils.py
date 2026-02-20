# File: core/utils.py

import os
import re
import hashlib
from typing import Optional

# SHA256 cache to avoid repeated hashing of the same file
_SHA256_CACHE = {}

def normalize_path(path: str) -> str:
    """Normalizes a path to lowercase with OS-standard separators."""
    if not path:
        return ""
    try:
        return os.path.normpath(path).lower()
    except ValueError:
        return path.lower().replace('/', '\\')

def get_sha256(file_path: str) -> Optional[str]:
    """Computes SHA256 hash of a file, with caching."""
    if not file_path:
        return None

    normalized_path = normalize_path(file_path)

    if normalized_path in _SHA256_CACHE:
        return _SHA256_CACHE[normalized_path]

    if not os.path.exists(normalized_path):
        _SHA256_CACHE[normalized_path] = None
        return None

    h = hashlib.sha256()
    try:
        with open(normalized_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        result = h.hexdigest()
    except (IOError, PermissionError):
        result = None

    _SHA256_CACHE[normalized_path] = result
    return result

# Statuses considered "trusted" in baseline.db lookups
TRUSTED_STATUSES = {"auto_trusted", "trusted_signature"}

# Regex to extract .exe paths from command strings
_CMD_EXE_REGEX = re.compile(r'["\']?([A-Za-z]:\\(?:["\'\s]|\\\s?)+?\.exe)["\']?', re.IGNORECASE)

def parse_command_path(command: str) -> str:
    """
    Extracts the path to an .exe file from a command string (e.g., registry autorun value).
    Handles environment variables, quoted paths, and rundll32.
    """
    if not command:
        return ""
    try:
        expanded = os.path.expandvars(command)
    except Exception:
        expanded = command

    expanded_cleaned = expanded.strip()

    # 1. Quoted path: "C:\Program Files\App\app.exe" /arg
    if expanded_cleaned.startswith('"'):
        end_quote_index = expanded_cleaned.find('"', 1)
        if end_quote_index != -1:
            potential_path = expanded_cleaned[1:end_quote_index]
            if potential_path.lower().endswith(".exe") and os.path.exists(potential_path):
                return normalize_path(potential_path)

    # 2. Unquoted path: C:\Windows\system32\svchost.exe -k LocalService
    potential_path = expanded_cleaned.split(" ")[0].split(",")[0]
    if potential_path.lower().endswith(".exe") and os.path.exists(potential_path):
        return normalize_path(potential_path)

    # 3. rundll32 fallback
    if re.search(r'\brundll32\b', expanded, re.IGNORECASE):
        sys_path = os.path.expandvars(r"%SystemRoot%\System32\rundll32.exe")
        if os.path.exists(sys_path):
            return normalize_path(sys_path)

    return ""