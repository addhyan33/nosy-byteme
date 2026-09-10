"""Synthetic-only traffic producer. It never opens a socket or sends a packet."""
from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone

from backend.constants import KNOWN_BAD_JA3, REFERENCE_WORDS
from backend.schema_models import Flow


class TrafficSimulator:
    """Creates bounded normal flows plus clearly labelled, scheduled attack patterns."""

    def __init__(self, seed: int | None = None) -> None:
        self.random = random.Random(seed)
        self.clock = datetime.now(timezone.utc)
        self.tick = 0
        self.attack_kind: str | None = None
        self.attack_remaining = 0
        self.attack_src = self._private_ip()
        self.attack_dst = self._private_ip(prefix="172.20")

    def _private_ip(self, prefix: str = "10") -> str:
        if prefix == "10":
            return f"10.{self.random.randrange(1, 255)}.{self.random.randrange(1, 255)}.{self.random.randrange(2, 254)}"
        return f"172.20.{self.random.randrange(1, 255)}.{self.random.randrange(2, 254)}"

    def _normal_domain(self) -> str:
        labels = self.random.sample(sorted(REFERENCE_WORDS), k=2)
        return f"{labels[0]}.{labels[1]}.internal"

    def _flow(self, **overrides: object) -> Flow:
        self.clock += timedelta(milliseconds=100)
        base: dict[str, object] = {
            "timestamp": self.clock,
            "src_ip": self._private_ip(),
            "dst_ip": self._private_ip(prefix="172.20"),
            "src_port": self.random.randrange(1024, 65535),
            "dst_port": self.random.choice([53, 80, 443, 445, 3389, 8080]),
            "protocol": "TCP",
            "duration_ms": self.random.randrange(20, 950),
            "packet_count": self.random.randrange(3, 24),
            "syn_count": 1,
            "ack_count": self.random.randrange(1, 10),
            "bytes_out": self.random.randrange(300, 9_000),
            "bytes_in": self.random.randrange(300, 18_000),
        }
        base.update(overrides)
        return Flow(**base)

    def _start_attack(self) -> None:
        self.attack_kind = self.random.choice(["ddos", "scan", "beacon", "dga", "malware", "exfil"])
        self.attack_remaining = {"ddos": 55, "scan": 45, "beacon": 72, "dga": 16, "malware": 10, "exfil": 10}[self.attack_kind]
        self.attack_src = self._private_ip()
        self.attack_dst = self._private_ip(prefix="172.20")

    def next_flow(self) -> Flow:
        self.tick += 1
        # Normal background traffic predominates; attacks are injected about every 8 simulated seconds.
        if not self.attack_kind and self.tick % 80 == 0:
            self._start_attack()
        if not self.attack_kind:
            dns = self._normal_domain() if self.random.random() < 0.15 else None
            return self._flow(protocol="UDP" if dns else "TCP", dst_port=53 if dns else self.random.choice([80, 443]), dns_query=dns, dns_record_type="A" if dns else None)

        kind = self.attack_kind
        self.attack_remaining -= 1
        if self.attack_remaining <= 0:
            self.attack_kind = None

        if kind == "ddos":
            return self._flow(src_ip=self._private_ip(), dst_ip=self.attack_dst, dst_port=443, protocol="TCP", duration_ms=15, packet_count=2, syn_count=2, ack_count=0, bytes_out=120, bytes_in=0)
        if kind == "scan":
            return self._flow(src_ip=self.attack_src, dst_ip=self._private_ip(prefix="172.20"), dst_port=1024 + (self.tick * 97) % 54_000, protocol="TCP", duration_ms=12, packet_count=1, syn_count=1, ack_count=0, bytes_out=64, bytes_in=0)
        if kind == "beacon":
            # Repeated pair with a fixed simulated 1.2-second interval.
            if self.tick % 12 == 0:
                return self._flow(src_ip=self.attack_src, dst_ip=self.attack_dst, dst_port=443, protocol="TCP", duration_ms=90, packet_count=6, bytes_out=420, bytes_in=720)
            return self._flow()
        if kind == "dga":
            label = "".join(self.random.choice(string.ascii_lowercase + string.digits) for _ in range(24))
            return self._flow(src_ip=self.attack_src, dst_port=53, protocol="UDP", dns_query=f"{label}.com", dns_record_type=self.random.choice(["TXT", "NULL", "A"]), bytes_out=850, bytes_in=70)
        if kind == "malware":
            ja3 = self.random.choice(list(KNOWN_BAD_JA3))
            return self._flow(src_ip=self.attack_src, dst_ip=self.attack_dst, dst_port=443, protocol="TCP", ja3_fingerprint=ja3, bytes_out=1_200, bytes_in=1_700)
        # exfiltration
        return self._flow(src_ip=self.attack_src, dst_ip=self.attack_dst, dst_port=443, protocol="TCP", duration_ms=2_800, packet_count=160, bytes_out=1_500_000, bytes_in=700)
