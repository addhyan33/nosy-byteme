"""Local ML and explainable rule evaluation for six passive threat classes."""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from backend.schema_models import Alert, FeatureWindow, ThreatClass


def _dga_vector(entropy: float, length: int, overlap: float, txt_like: float = 0.0) -> list[float]:
    return [entropy, length, overlap, txt_like]


@dataclass
class InferenceEngine:
    anomaly_model: IsolationForest
    dga_model: RandomForestClassifier

    @classmethod
    def bootstrap(cls, seed: int = 42) -> "InferenceEngine":
        """Train compact deterministic demo models on baseline synthetic metadata once per process."""
        rng = np.random.default_rng(seed)
        normal = np.column_stack((
            rng.normal(1.2, 0.25, 900),   # SYN:ACK ratio
            rng.normal(40, 18, 900),      # packets/sec
            rng.normal(4, 1.5, 900),      # distinct ports
            rng.normal(1.2, 0.35, 900),   # bytes out/in
            rng.normal(15_000, 4_000, 900),
        ))
        anomaly = IsolationForest(contamination=0.04, random_state=seed, n_estimators=120).fit(normal)
        benign = np.column_stack((rng.normal(2.5, 0.35, 500), rng.normal(13, 3, 500), rng.normal(.75, .2, 500), rng.binomial(1, .08, 500)))
        malicious = np.column_stack((rng.normal(4.1, 0.25, 500), rng.normal(27, 5, 500), rng.normal(.03, .04, 500), rng.binomial(1, .55, 500)))
        X = np.vstack((benign, malicious)); y = np.array([0] * len(benign) + [1] * len(malicious))
        dga = RandomForestClassifier(n_estimators=160, min_samples_leaf=2, random_state=seed, class_weight="balanced").fit(X, y)
        return cls(anomaly, dga)

    def _alert(self, feature: FeatureWindow, threat: ThreatClass, confidence: float, model: str, evidence: dict) -> Alert:
        confidence = round(min(max(confidence, 0.01), 0.99), 3)
        return Alert(
            flow_id=feature.flow_id,
            window_id=feature.window_id,
            threat_class=threat,
            confidence=confidence,
            severity=Alert.severity_from_confidence(confidence),
            model_used=model,
            src_ip=feature.src_ip,
            dst_ip=feature.dst_ip,
            evidence=evidence,
        )

    def evaluate(self, feature: FeatureWindow) -> list[Alert]:
        """Return evidence-backed alerts; no raw packet payload is used."""
        alerts: list[Alert] = []
        # DDoS: many source IPs hit one destination, with SYNs exceeding ACKs.
        if feature.flow_count >= 24 and feature.syn_ack_ratio >= 7 and feature.src_ip_entropy >= 4.3:
            confidence = min(.99, .58 + feature.syn_ack_ratio / 28 + feature.flow_count / 200)
            alerts.append(self._alert(feature, ThreatClass.DDOS, confidence, "threshold_ddos_v1", {
                "flows_to_destination_5s": feature.flow_count, "syn_ack_ratio": round(feature.syn_ack_ratio, 2),
                "source_ip_entropy": round(feature.src_ip_entropy, 2), "window_seconds": 5,
            }))
        # Fan-out is a directly explainable scan signal; Isolation Forest adds a second signal.
        vector = np.array([[feature.syn_ack_ratio, feature.packets_per_sec, feature.distinct_dst_ports, feature.bytes_out_in_ratio, feature.total_bytes_out]])
        anomalous = self.anomaly_model.predict(vector)[0] == -1
        if feature.distinct_dst_ports >= 18 and feature.distinct_dst_hosts >= 10:
            confidence = min(.98, .66 + feature.distinct_dst_ports / 150 + (.08 if anomalous else 0))
            alerts.append(self._alert(feature, ThreatClass.PORT_SCAN, confidence, "isolation_forest_scan_v1", {
                "distinct_destination_ports_5s": feature.distinct_dst_ports, "distinct_destination_hosts_5s": feature.distinct_dst_hosts,
                "anomaly_model_agrees": bool(anomalous), "syn_ack_ratio": round(feature.syn_ack_ratio, 2),
            }))
        if feature.bytes_out_in_ratio >= 40 and feature.total_bytes_out >= 500_000:
            confidence = min(.98, .7 + min(feature.bytes_out_in_ratio, 150) / 500 + (.08 if anomalous else 0))
            alerts.append(self._alert(feature, ThreatClass.EXFILTRATION, confidence, "isolation_forest_exfil_v1", {
                "bytes_out_in_ratio": round(feature.bytes_out_in_ratio, 2), "bytes_out_5s": feature.total_bytes_out,
                "anomaly_model_agrees": bool(anomalous),
            }))
        if feature.iat_mean_ms > 0 and feature.iat_variance_ms <= 5 and feature.iat_mean_ms >= 800:
            alerts.append(self._alert(feature, ThreatClass.BEACONING, .82, "beacon_periodicity_rule_v1", {
                "mean_interarrival_ms": round(feature.iat_mean_ms, 1), "interarrival_variance_ms": round(feature.iat_variance_ms, 2),
                "pair": feature.entity_key, "observation_window_seconds": 30,
            }))
        if feature.dns_domain_entropy is not None:
            vector = _dga_vector(feature.dns_domain_entropy, feature.dns_length or 0, feature.dns_dictionary_score or 0, 1.0 if feature.dns_length and feature.dns_length > 20 else 0.0)
            probability = float(self.dga_model.predict_proba([vector])[0][1])
            if probability >= .76:
                alerts.append(self._alert(feature, ThreatClass.DGA, probability, "random_forest_dga_v1", {
                    "domain_entropy": round(feature.dns_domain_entropy, 3), "query_length": feature.dns_length,
                    "dictionary_overlap": round(feature.dns_dictionary_score or 0, 3), "classifier_probability": round(probability, 3),
                }))
        if feature.ja3_match:
            alerts.append(self._alert(feature, ThreatClass.ENCRYPTED_MALWARE, .96, "ja3_blocklist_rule_v1", {
                "malware_family_reference": feature.ja3_match, "inspection_scope": "TLS handshake metadata only; no payload decryption",
            }))
        return alerts
