"""KafkaPcapSegmenter: gom packet thành segment, publish blob pcap lên Kafka."""
import time
import uuid

from .pcap_segment import build_segment


class KafkaPcapSegmenter:
    """Buffer packets, flush khi quá segment_seconds hoặc segment_max_bytes."""

    def __init__(
        self,
        producer,
        topic,
        interface,
        segment_seconds=60,
        segment_max_bytes=64 << 20,
        clock=time.time,
        id_factory=lambda: uuid.uuid4().hex,
    ):
        self.producer = producer
        self.topic = topic
        self.interface = interface
        self.segment_seconds = segment_seconds
        self.segment_max_bytes = segment_max_bytes
        self.clock = clock
        self.id_factory = id_factory
        self._pkts = []
        self._bytes = 0
        self._t_start = None

    def add_packet(self, ts_sec, ts_usec, data):
        now = self.clock()
        if self._t_start is not None and (now - self._t_start) >= self.segment_seconds:
            self.flush()
        if self._t_start is None:
            self._t_start = now
        self._pkts.append((ts_sec, ts_usec, data))
        self._bytes += len(data)
        if self._bytes >= self.segment_max_bytes:
            self.flush()

    def flush(self):
        if not self._pkts:
            return None
        sid = self.id_factory()
        meta = {
            "segment_id": sid,
            "interface": self.interface,
            "n_pkts": len(self._pkts),
            "t_start": self._pkts[0][0],
            "t_end": self._pkts[-1][0],
        }
        blob = build_segment(self._pkts, meta)
        self.producer.send(self.topic, key=self.interface.encode(), value=blob)
        self._pkts = []
        self._bytes = 0
        self._t_start = None
        return sid
