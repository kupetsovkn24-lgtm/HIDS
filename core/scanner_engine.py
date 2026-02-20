# File: core/scanner_engine.py

import logging
from core.database import DatabaseManager
from core.config import DAYS_TO_KEEP, SENSOR_MAP, DB_PATH
from core.correlator import AnomalyCorrelator
from core.baseline_manager import BaselineManager

from sensors import ProcessSensor, NetworkSensor, RegistrySensor, FileSensor, TaskSensor

log = logging.getLogger(__name__)


def run_scan_generator(active_sensor_names: list):
    """
    Runs a full scan cycle and yields log messages in real time.
    Designed to be consumed by the Streamlit dashboard.
    """
    try:
        yield "="*40
        yield "Starting HIDS scanner (with Baseline DB)..."
        yield "="*40

        db = DatabaseManager(DB_PATH)
        baseline_db = BaselineManager()
        correlator = AnomalyCorrelator()

        if not baseline_db._conn:
            yield "ERROR: Failed to load baseline.db!"

        yield f"Pruning anomalies older than {DAYS_TO_KEEP} days..."
        db.prune_old_data(days=DAYS_TO_KEEP)

        yield "[Scanner] Initializing sensors..."

        all_sensors = []
        for name in active_sensor_names:
            if name in SENSOR_MAP:
                try:
                    sensor_class = SENSOR_MAP[name]
                    all_sensors.append(sensor_class(baseline=baseline_db))
                except Exception as e:
                    yield f"ERROR initializing sensor {name}: {e}"

        yield f"Loaded {len(all_sensors)} active sensors."

        all_raw_events = []
        for sensor in all_sensors:
            sensor_name = sensor.__class__.__name__
            yield f"--- Running {sensor_name} ---"
            try:
                events = sensor.scan()
                yield f"--- {sensor_name} done. Found: {len(events)} ---"
                all_raw_events.extend(events)
            except Exception as e:
                yield f"!!! CRITICAL ERROR in {sensor_name}: {e} !!!"

        yield f"\n[Scanner] Scan complete. Total raw events collected: {len(all_raw_events)}"

        yield "[Scanner] Running correlator (correlation & prioritization)..."
        final_prioritized_list = correlator.correlate_and_prioritize(all_raw_events)
        newly_correlated = len(final_prioritized_list) - len(all_raw_events)
        yield f"[Scanner] Correlator done. Generated {newly_correlated} correlated anomalies."

        if final_prioritized_list:
            yield f"[Scanner] Writing {len(final_prioritized_list)} anomalies to anomaly.db..."
            for anomaly in final_prioritized_list:
                db.add_anomaly(anomaly)
        else:
            yield "[Scanner] No anomalies to write. System is clean."

        yield "="*40
        yield "Scan finished."
        yield "="*40

    except Exception as e:
        yield f"!!! CRITICAL SCANNER ERROR: {e} !!!"