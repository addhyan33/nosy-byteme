"""Typed in-memory contracts shared across every NOSY component."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ThreatClass(str, Enum):
    DDOS = "DDoS"
    BEACONING = "Botnet C2 Beaconing"
    DGA = "DGA / DNS Tunnelling"
    ENCRYPTED_MALWARE = "Encrypted Malware"
    PORT_SCAN = "Port Scan"
    EXFILTRATION = "Data Exfiltration"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RowModel(BaseModel):
    def to_row(self) -> dict[str, Any]:
        result = self.model_dump(mode="json")
        for key, value in list(result.items()):
            if isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, Enum):
                result[key] = value.value
        return result


class Flow(RowModel):
    flow_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=1, le=65535)
    dst_port: int = Field(ge=1, le=65535)
    protocol: str
    duration_ms: int = Field(ge=0)
    packet_count: int = Field(ge=0)
    syn_count: int = Field(ge=0)
    ack_count: int = Field(ge=0)
    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)
    dns_query: str | None = None
    dns_record_type: str | None = None
    ja3_fingerprint: str | None = None
    is_synthetic: bool = True

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        value = value.upper()
        if value not in {"TCP", "UDP", "ICMP", "QUIC"}:
            raise ValueError("protocol must be TCP, UDP, ICMP, or QUIC")
        return value


class FeatureWindow(RowModel):
    window_id: str = Field(default_factory=lambda: str(uuid4()))
    entity_key: str
    window_start: datetime
    window_end: datetime
    flow_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    flow_count: int = Field(ge=0)
    src_ip_entropy: float = Field(ge=0)
    syn_ack_ratio: float = Field(ge=0)
    packets_per_sec: float = Field(ge=0)
    distinct_dst_ports: int = Field(ge=0)
    distinct_dst_hosts: int = Field(ge=0)
    iat_mean_ms: float = Field(ge=0)
    iat_variance_ms: float = Field(ge=0)
    dns_domain_entropy: float | None = None
    dns_dictionary_score: float | None = None
    dns_length: int | None = None
    bytes_out_in_ratio: float = Field(ge=0)
    total_bytes_out: int = Field(ge=0)
    ja3_match: str | None = None


class Alert(RowModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    flow_id: str | None = None
    window_id: str | None = None
    threat_class: ThreatClass
    confidence: float = Field(ge=0, le=1)
    severity: Severity
    model_used: str
    src_ip: str | None = None
    dst_ip: str | None = None
    acknowledged: bool = False
    prev_alert_hash: str | None = None
    alert_hash: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def severity_from_confidence(confidence: float) -> Severity:
        if confidence >= 0.92:
            return Severity.CRITICAL
        if confidence >= 0.78:
            return Severity.HIGH
        if confidence >= 0.60:
            return Severity.MEDIUM
        return Severity.LOW

    def to_row(self) -> dict[str, Any]:
        result = super().to_row()
        evidence = result.pop("evidence")
        result["evidence_json"] = json.dumps(evidence, sort_keys=True, default=str)
        return result

    def with_hash(self, previous_hash: str | None) -> "Alert":
        self.prev_alert_hash = previous_hash
        material = f"{previous_hash or ''}|{self.timestamp.isoformat()}|{self.alert_id}|{self.evidence}"
        self.alert_hash = hashlib.sha256(material.encode()).hexdigest()
        return self
