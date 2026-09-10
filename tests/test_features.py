from datetime import datetime, timezone

from backend.features import FeatureExtractor, dictionary_overlap, distribution_entropy, shannon_entropy
from backend.schema_models import Flow


def flow(**changes):
    fields = dict(src_ip="10.0.0.4", dst_ip="172.20.1.8", src_port=49152, dst_port=443, protocol="TCP", duration_ms=10, packet_count=1, syn_count=1, ack_count=1, bytes_out=100, bytes_in=100, timestamp=datetime.now(timezone.utc))
    fields.update(changes)
    return Flow(**fields)


def test_entropy_has_expected_shape():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
    assert distribution_entropy(["a", "a", "b", "b"]) == 1
    assert dictionary_overlap("api.service.internal") > 0


def test_feature_extractor_keeps_flow_context():
    extractor = FeatureExtractor()
    result = extractor.process(flow(dns_query="abc123xyz.net", dns_record_type="A"))
    assert result.flow_count == 1
    assert result.dns_domain_entropy is not None
    assert result.entity_key == "10.0.0.4→172.20.1.8"
