from datetime import datetime, timezone

from backend.models import InferenceEngine
from backend.schema_models import FeatureWindow


def test_known_bad_ja3_creates_explainable_alert():
    feature = FeatureWindow(entity_key="10.0.0.5→172.20.0.8", window_start=datetime.now(timezone.utc), window_end=datetime.now(timezone.utc), src_ip="10.0.0.5", dst_ip="172.20.0.8", flow_count=1, src_ip_entropy=0, syn_ack_ratio=1, packets_per_sec=10, distinct_dst_ports=1, distinct_dst_hosts=1, iat_mean_ms=0, iat_variance_ms=0, bytes_out_in_ratio=1, total_bytes_out=1000, ja3_match="TrickBot")
    alerts = InferenceEngine.bootstrap().evaluate(feature)
    assert any(alert.threat_class.value == "Encrypted Malware" for alert in alerts)
    assert all(alert.evidence for alert in alerts)
