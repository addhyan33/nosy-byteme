PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS flows (
  flow_id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  src_port INTEGER NOT NULL,
  dst_port INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  packet_count INTEGER NOT NULL,
  syn_count INTEGER NOT NULL,
  ack_count INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  bytes_in INTEGER NOT NULL,
  dns_query TEXT,
  dns_record_type TEXT,
  ja3_fingerprint TEXT,
  is_synthetic INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_flows_time ON flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_src_time ON flows(src_ip, timestamp);

CREATE TABLE IF NOT EXISTS feature_windows (
  window_id TEXT PRIMARY KEY,
  entity_key TEXT NOT NULL,
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  flow_id TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  flow_count INTEGER NOT NULL,
  src_ip_entropy REAL NOT NULL,
  syn_ack_ratio REAL NOT NULL,
  packets_per_sec REAL NOT NULL,
  distinct_dst_ports INTEGER NOT NULL,
  distinct_dst_hosts INTEGER NOT NULL,
  iat_mean_ms REAL NOT NULL,
  iat_variance_ms REAL NOT NULL,
  dns_domain_entropy REAL,
  dns_dictionary_score REAL,
  dns_length INTEGER,
  bytes_out_in_ratio REAL NOT NULL,
  total_bytes_out INTEGER NOT NULL,
  ja3_match TEXT,
  FOREIGN KEY(flow_id) REFERENCES flows(flow_id)
);
CREATE INDEX IF NOT EXISTS idx_windows_time ON feature_windows(window_end);

CREATE TABLE IF NOT EXISTS models_registry (
  model_id TEXT PRIMARY KEY,
  threat_class TEXT NOT NULL,
  model_type TEXT NOT NULL,
  precision_score REAL,
  recall_score REAL,
  f1_score REAL,
  trained_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  alert_id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  flow_id TEXT,
  window_id TEXT,
  threat_class TEXT NOT NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
  severity TEXT NOT NULL,
  model_used TEXT NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  acknowledged INTEGER NOT NULL DEFAULT 0,
  prev_alert_hash TEXT,
  alert_hash TEXT,
  evidence_json TEXT NOT NULL,
  FOREIGN KEY(flow_id) REFERENCES flows(flow_id),
  FOREIGN KEY(window_id) REFERENCES feature_windows(window_id),
  FOREIGN KEY(model_used) REFERENCES models_registry(model_id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS pipeline_metrics (
  metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
  recorded_at TEXT NOT NULL,
  flows_processed INTEGER NOT NULL,
  flows_per_sec REAL NOT NULL,
  pipeline_status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metrics_time ON pipeline_metrics(recorded_at DESC);

CREATE TABLE IF NOT EXISTS ja3_blocklist (
  ja3_hash TEXT PRIMARY KEY,
  malware_family TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dga_reference_words (
  word TEXT PRIMARY KEY,
  freq INTEGER NOT NULL
);
