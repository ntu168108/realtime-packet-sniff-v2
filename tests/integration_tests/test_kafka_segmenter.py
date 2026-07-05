from integration.kafka_segmenter import KafkaPcapSegmenter
from integration.pcap_segment import parse_segment

class FakeProducer:
    def __init__(self): self.sent = []
    def send(self, topic, key=None, value=None):
        self.sent.append((topic, key, value))
    def flush(self):
        pass

def test_flush_on_size():
    p = FakeProducer()
    seg = KafkaPcapSegmenter(p, "t", "ens33", segment_seconds=9999, segment_max_bytes=50,
                             id_factory=lambda: "ID1")
    seg.add_packet(1, 0, b"x" * 30)
    assert p.sent == []                      # chưa đủ size
    seg.add_packet(2, 0, b"y" * 30)          # vượt 50 → flush
    assert len(p.sent) == 1
    topic, key, value = p.sent[0]
    assert topic == "t"
    assert key == b"ens33"
    meta, pcap_bytes = parse_segment(value)
    assert meta["segment_id"] == "ID1"
    assert meta["n_pkts"] == 2
    assert meta["interface"] == "ens33"

def test_flush_on_time():
    p = FakeProducer()
    t = [1000.0]
    seg = KafkaPcapSegmenter(p, "t", "ens33", segment_seconds=60, segment_max_bytes=1 << 30,
                             clock=lambda: t[0], id_factory=lambda: "ID2")
    seg.add_packet(1, 0, b"a")
    t[0] = 1061.0
    seg.add_packet(2, 0, b"b")               # quá 60s → flush segment cũ trước khi thêm
    assert len(p.sent) == 1

def test_flush_empty_returns_none():
    p = FakeProducer()
    seg = KafkaPcapSegmenter(p, "t", "ens33", id_factory=lambda: "ID3")
    assert seg.flush() is None
    assert p.sent == []
