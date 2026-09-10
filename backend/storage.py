"""SQLite access layer. The only persistence boundary used by the pipeline."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pandas as pd

from backend.constants import DB_PATH, KNOWN_BAD_JA3, REFERENCE_WORDS
from backend.schema_models import Alert, FeatureWindow, Flow


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection(db_path: Path = DB_PATH) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize_database(db_path: Path = DB_PATH) -> None:
    schema = (Path(__file__).parent / "schema.sql").read_text(encoding="utf-8")
    with connection(db_path) as conn:
        conn.executescript(schema)
        conn.executemany(
            "INSERT OR IGNORE INTO ja3_blocklist(ja3_hash, malware_family) VALUES (?, ?)",
            KNOWN_BAD_JA3.items(),
        )
        conn.executemany(
            "INSERT OR IGNORE INTO dga_reference_words(word, freq) VALUES (?, ?)",
            [(word, 1) for word in REFERENCE_WORDS],
        )


def insert_flow(flow: Flow, db_path: Path = DB_PATH) -> None:
    columns = ", ".join(flow.to_row())
    placeholders = ", ".join(f":{key}" for key in flow.to_row())
    with connection(db_path) as conn:
        conn.execute(f"INSERT INTO flows ({columns}) VALUES ({placeholders})", flow.to_row())


def insert_feature_window(feature: FeatureWindow, db_path: Path = DB_PATH) -> None:
    row = feature.to_row()
    columns = ", ".join(row)
    placeholders = ", ".join(f":{key}" for key in row)
    with connection(db_path) as conn:
        conn.execute(f"INSERT INTO feature_windows ({columns}) VALUES ({placeholders})", row)


def insert_alert(alert: Alert, db_path: Path = DB_PATH) -> None:
    with connection(db_path) as conn:
        previous = conn.execute("SELECT alert_hash FROM alerts ORDER BY timestamp DESC LIMIT 1").fetchone()
        alert.with_hash(previous[0] if previous else None)
        row = alert.to_row()
        columns = ", ".join(row)
        placeholders = ", ".join(f":{key}" for key in row)
        conn.execute(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", row)


def record_metrics(flows_processed: int, flows_per_sec: float, status: str, db_path: Path = DB_PATH) -> None:
    with connection(db_path) as conn:
        conn.execute(
            "INSERT INTO pipeline_metrics(recorded_at, flows_processed, flows_per_sec, pipeline_status) VALUES (?, ?, ?, ?)",
            (_now(), flows_processed, flows_per_sec, status),
        )


def register_model(model_id: str, threat_class: str, model_type: str, precision: float | None, recall: float | None, f1: float | None, db_path: Path = DB_PATH) -> None:
    with connection(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO models_registry VALUES (?, ?, ?, ?, ?, ?, ?)",
            (model_id, threat_class, model_type, precision, recall, f1, _now()),
        )


def query_dataframe(query: str, params: tuple = (), db_path: Path = DB_PATH) -> pd.DataFrame:
    with connection(db_path) as conn:
        return pd.read_sql_query(query, conn, params=params)
