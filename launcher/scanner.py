# File: launcher/scanner.py
import time
import logging

from core.database import DatabaseManager
from core.config import DAYS_TO_KEEP
from core.correlator import AnomalyCorrelator
from core.baseline_manager import BaselineManager

from sensors.process import ProcessSensor
from sensors.network import NetworkSensor
from sensors.registry import RegistrySensor
from sensors.file import FileSensor
from sensors.task import TaskSensor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

def main():
    """
    Standalone scanner entry point (legacy, without Streamlit).
    """
    log.info("="*40)
    log.info("Starting HIDS scanner (with Baseline DB)...")
    log.info("="*40)

    db = DatabaseManager()
    baseline_db = BaselineManager()
    correlator = AnomalyCorrelator()

    if not baseline_db._conn:
        log.error("Failed to load baseline.db! Many HIDS features will be unavailable.")

    db.prune_old_data(days=DAYS_TO_KEEP)

    log.info("[Scanner] Initializing sensors...")
    all_sensors = [
        ProcessSensor(baseline=baseline_db),
        NetworkSensor(baseline=baseline_db),
        RegistrySensor(baseline=baseline_db),
        FileSensor(baseline=baseline_db),  # TODO: ensure FileSensor accepts baseline
        TaskSensor(baseline=baseline_db)
    ]
    log.info(f"Loaded {len(all_sensors)} sensors.")

    log.info("\n[Scanner] Starting scan...")
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
    log.info(f"[Scanner] Total anomalies to write (sorted): {len(final_prioritized_list)}")

    if final_prioritized_list:
        log.info(f"[Scanner] Writing {len(final_prioritized_list)} anomalies to anomaly.db...")
        for anomaly in final_prioritized_list:
            db.add_anomaly(anomaly)

        log.info("\n--- TOP-3 ANOMALIES ---")
        for event in final_prioritized_list[:3]:
            log.warning(f"  [Sev: {event.severity} | {event.category}] {event.description}")
        log.info("----------------------------------\n")

    else:
        log.info("[Scanner] No anomalies to write. System is clean.")

    log.info("="*40)
    log.info("Scan finished.")
    log.info("="*40)


if __name__ == "__main__":
    main()