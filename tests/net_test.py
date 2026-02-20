import requests
import time
import random
import sys

URL = "https://rozetka.com.ua"
REQUESTS_COUNT = 30
TIMEOUT = 10
MIN_SLEEP = 5.0
MAX_SLEEP = 15.0

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NotepadTest/1.0"
}

def main():
    session = requests.Session()
    session.headers.update(HEADERS)
    print(f"--- [TEST] Slow 'Notepad' started. Running for ~{REQUESTS_COUNT * (MIN_SLEEP+MAX_SLEEP)/2 :.0f} seconds ---")

    for i in range(1, REQUESTS_COUNT + 1):
        try:
            print(f"[{i}/{REQUESTS_COUNT}] Connecting to {URL} ...")
            resp = session.get(URL, timeout=TIMEOUT)
            print(f"    Response code: {resp.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"    Error: {e}")

        if i != REQUESTS_COUNT:
            sleep_for = random.uniform(MIN_SLEEP, MAX_SLEEP)
            print(f"    Sleeping {sleep_for:.2f}s...")
            time.sleep(sleep_for)

    print("Done.")
    time.sleep(1.0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)