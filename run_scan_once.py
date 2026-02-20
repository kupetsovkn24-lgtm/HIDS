# File: run_scan_once.py
# Intended to be run via Windows Task Scheduler.
# Headless: no GUI, performs one full scan cycle and logs to file.

import sys
import os
import logging

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager
from core.config import DAYS_TO_KEEP, DB_PATH, SENSOR_MAP
from core.correlator import AnomalyCorrelator
from core.baseline_manager import BaselineManager
from sensors import ProcessSensor, NetworkSensor, RegistrySensor, FileSensor, TaskSensor

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "scanner_run.log")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    filemode='a',
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)
log = logging.getLogger("HIDS_Worker")

def run_scan_headless():
    """
    Headless scanner entry point.
    Logs to file; no GUI output.
    """
    try:
        log.info("="*40)
        log.info("Starting HIDS scanner (with Baseline DB)...")
        log.info("="*40)

        db = DatabaseManager(DB_PATH)
        baseline_db = BaselineManager()
        correlator = AnomalyCorrelator()

        if not baseline_db._conn:
            log.error("ERROR: Failed to load baseline.db!")

        log.info(f"Pruning anomalies older than {DAYS_TO_KEEP} days...")
        db.prune_old_data(days=DAYS_TO_KEEP)

        log.info("[Scanner] Initializing sensors...")

        active_sensor_names = list(SENSOR_MAP.keys())

        all_sensors = []
        for name in active_sensor_names:
            if name in SENSOR_MAP:
                try:
                    all_sensors.append(SENSOR_MAP[name](baseline=baseline_db))
                except Exception as e:
                    log.error(f"ERROR initializing sensor {name}: {e}")

        log.info(f"Loaded {len(all_sensors)} active sensors.")

        all_raw_events = []
        for sensor in all_sensors:
            sensor_name = sensor.__class__.__name__
            log.info(f"--- Running {sensor_name} ---")
            try:
                events = sensor.scan()
                log.info(f"--- {sensor_name} done. Found: {len(events)} ---")
                all_raw_events.extend(events)
            except Exception as e:
                log.error(f"!!! CRITICAL ERROR in {sensor_name}: {e} !!!")

        log.info(f"\n[Scanner] Scan complete. Total raw events: {len(all_raw_events)}")

        log.info("[Scanner] Running correlator...")
        final_prioritized_list = correlator.correlate_and_prioritize(all_raw_events)
        newly_correlated = len(final_prioritized_list) - len(all_raw_events)
        log.info(f"[Scanner] Correlator done. Generated {newly_correlated} correlated anomalies.")

        if final_prioritized_list:
            log.info(f"[Scanner] Writing {len(final_prioritized_list)} anomalies to anomaly.db...")
            for anomaly in final_prioritized_list:
                db.add_anomaly(anomaly)
        else:
            log.info("[Scanner] No anomalies to write. System is clean.")

        log.info("="*40)
        log.info("Scan finished.")
        log.info("="*40)

    except Exception as e:
        log.error(f"!!! CRITICAL SCANNER ERROR: {e} !!!")

if __name__ == "__main__":
    print(f"Starting headless HIDS scan... Log will be written to {LOG_FILE}")
    run_scan_headless()
    print("Headless scan complete.")