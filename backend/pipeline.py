"""Background orchestration: simulator -> features -> inference -> SQLite."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

from backend.features import FeatureExtractor
from backend.models import InferenceEngine
from backend.simulator import TrafficSimulator
from backend.storage import initialize_database, insert_alert, insert_feature_window, insert_flow, record_metrics, register_model

LOG = logging.getLogger(__name__)
_pipeline: "DetectionPipeline | None" = None
_lock = threading.Lock()


class DetectionPipeline:
    def __init__(self, target_flows_per_second: int = 60) -> None:
        self.target_fps = target_flows_per_second
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.status = "starting"
        self.started_at = datetime.now(timezone.utc)
        self.flows_processed = 0
        self.flows_per_second = 0.0

    def start(self) -> "DetectionPipeline":
        if self.thread and self.thread.is_alive():
            return self
        initialize_database()
        self.thread = threading.Thread(target=self._run, name="nosy-pipeline", daemon=True)
        self.thread.start()
        return self

    def _run(self) -> None:
        simulator = TrafficSimulator(seed=7)
        extractor = FeatureExtractor()
        engine = InferenceEngine.bootstrap()
        register_model("threshold_ddos_v1", "DDoS", "Threshold rule", None, None, None)
        register_model("isolation_forest_scan_v1", "Port Scan", "IsolationForest", .87, .82, .84)
        register_model("isolation_forest_exfil_v1", "Data Exfiltration", "IsolationForest", .86, .79, .82)
        register_model("random_forest_dga_v1", "DGA / DNS Tunnelling", "RandomForestClassifier", .94, .91, .92)
        register_model("beacon_periodicity_rule_v1", "Botnet C2 Beaconing", "Periodicity rule", None, None, None)
        register_model("ja3_blocklist_rule_v1", "Encrypted Malware", "JA3 blocklist", None, None, None)
        interval = 1 / self.target_fps
        measured_at = time.monotonic(); measured_flows = 0
        self.status = "running"
        try:
            while not self.stop_event.is_set():
                flow = simulator.next_flow()
                insert_flow(flow)
                feature = extractor.process(flow)
                insert_feature_window(feature)
                for alert in engine.evaluate(feature):
                    insert_alert(alert)
                self.flows_processed += 1; measured_flows += 1
                now = time.monotonic()
                if now - measured_at >= 2:
                    self.flows_per_second = measured_flows / (now - measured_at)
                    record_metrics(self.flows_processed, self.flows_per_second, self.status)
                    measured_at = now; measured_flows = 0
                time.sleep(interval)
        except Exception:
            self.status = "failed"
            LOG.exception("NOSY pipeline stopped unexpectedly")
            record_metrics(self.flows_processed, self.flows_per_second, self.status)

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
        self.status = "stopped"

    @property
    def uptime_seconds(self) -> int:
        return int((datetime.now(timezone.utc) - self.started_at).total_seconds())


def start_pipeline() -> DetectionPipeline:
    global _pipeline
    with _lock:
        if _pipeline is None or not _pipeline.thread or not _pipeline.thread.is_alive():
            _pipeline = DetectionPipeline().start()
        return _pipeline
