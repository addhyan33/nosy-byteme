"""Rolling, passive metadata feature extraction. No payload inspection or decryption."""
from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from datetime import timedelta

from backend.constants import KNOWN_BAD_JA3, REFERENCE_WORDS
from backend.schema_models import FeatureWindow, Flow


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def distribution_entropy(values: list[str]) -> float:
    """Shannon entropy of a categorical distribution, used for source-IP diversity."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def dictionary_overlap(domain: str | None) -> float:
    if not domain:
        return 0.0
    labels = [label for label in domain.lower().split(".") if label]
    return sum(any(word in label for word in REFERENCE_WORDS) for label in labels) / max(len(labels), 1)


class FeatureExtractor:
    def __init__(self, window_seconds: int = 5, long_window_seconds: int = 30) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.long_window = timedelta(seconds=long_window_seconds)
        self.by_destination: dict[str, deque[Flow]] = defaultdict(deque)
        self.by_source: dict[str, deque[Flow]] = defaultdict(deque)
        self.by_pair: dict[str, deque[Flow]] = defaultdict(deque)

    @staticmethod
    def _trim(flows: deque[Flow], newest: Flow, duration: timedelta) -> None:
        cutoff = newest.timestamp - duration
        while flows and flows[0].timestamp < cutoff:
            flows.popleft()

    def process(self, flow: Flow) -> FeatureWindow:
        destination = self.by_destination[flow.dst_ip]
        source = self.by_source[flow.src_ip]
        pair_key = f"{flow.src_ip}→{flow.dst_ip}"
        pair = self.by_pair[pair_key]
        destination.append(flow); source.append(flow); pair.append(flow)
        self._trim(destination, flow, self.window)
        self._trim(source, flow, self.window)
        self._trim(pair, flow, self.long_window)

        source_ips = [item.src_ip for item in destination]
        syns = sum(item.syn_count for item in destination)
        acks = sum(item.ack_count for item in destination)
        elapsed = max((destination[-1].timestamp - destination[0].timestamp).total_seconds(), 0.1)
        pair_times = [item.timestamp.timestamp() * 1000 for item in pair]
        intervals = [pair_times[i] - pair_times[i - 1] for i in range(1, len(pair_times))]
        iat_mean = sum(intervals) / len(intervals) if intervals else 0.0
        iat_variance = sum((x - iat_mean) ** 2 for x in intervals) / len(intervals) if intervals else 0.0
        domain_label = (flow.dns_query or "").split(".")[0]
        ratio = flow.bytes_out / max(flow.bytes_in, 1)
        return FeatureWindow(
            entity_key=pair_key,
            window_start=destination[0].timestamp,
            window_end=flow.timestamp,
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            flow_count=len(destination),
            src_ip_entropy=distribution_entropy(source_ips),
            syn_ack_ratio=syns / max(acks, 1),
            packets_per_sec=sum(item.packet_count for item in destination) / elapsed,
            distinct_dst_ports=len({item.dst_port for item in source}),
            distinct_dst_hosts=len({item.dst_ip for item in source}),
            iat_mean_ms=iat_mean,
            iat_variance_ms=iat_variance,
            dns_domain_entropy=shannon_entropy(domain_label) if flow.dns_query else None,
            dns_dictionary_score=dictionary_overlap(flow.dns_query) if flow.dns_query else None,
            dns_length=len(flow.dns_query) if flow.dns_query else None,
            bytes_out_in_ratio=ratio,
            total_bytes_out=sum(item.bytes_out for item in source),
            ja3_match=KNOWN_BAD_JA3.get(flow.ja3_fingerprint or ""),
        )
