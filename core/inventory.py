import psutil
import sys

CURRENT_WHITELIST = {
    "chrome.exe",
    "telegram.exe",
    "signal.exe",
    "code.exe",
    "vmware.exe",
    "VBoxService.exe",
    "python.exe"
}

def list_unique_processes():
    """
    Collects all unique running process names and compares them against
    the current whitelist. Useful for expanding the trusted process list.
    """
    unique_processes = set()

    for proc in psutil.process_iter(['name']):
        try:
            unique_processes.add(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    sorted_processes = sorted(list(unique_processes), key=str.lower)

    new_processes = []
    whitelisted_processes = []

    for proc_name in sorted_processes:
        if proc_name in CURRENT_WHITELIST:
            whitelisted_processes.append(proc_name)
        else:
            new_processes.append(proc_name)

    print("="*50)
    print(f"NEW PROCESSES (not in whitelist): {len(new_processes)}")
    print("="*50)
    for proc_name in new_processes:
        print(f'    "{proc_name}",')

    print("\n" + "="*50)
    print(f"KNOWN PROCESSES (already in whitelist): {len(whitelisted_processes)}")
    print("="*50)
    for proc_name in whitelisted_processes:
        print(f"    {proc_name}")

    print("\n" + "="*50)
    print("Tip: Add processes you know and trust to 'trusted_processes' in whitelist.json.")

if __name__ == "__main__":
    if not hasattr(sys, 'prefix'):
        print("Error: Looks like you are not in a virtual environment (.venv).")
        print("Please activate it: .\\.venv\\Scripts\\Activate")
    else:
        list_unique_processes()