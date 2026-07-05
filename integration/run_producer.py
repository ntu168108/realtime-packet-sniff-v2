"""Entrypoint: capture trên NIC → KafkaPcapSegmenter → Kafka.

Dùng core.capture.CaptureEngine (đã có sẵn từ SNIFF). Callback API thực tế:
- CaptureEngine(interface=..., bpf_filter=..., on_packet_filtered=...)
- on_packet_filtered nhận PacketInfo(ts_sec, ts_usec, data, ...)
"""
import logging
import signal
import sys
import time

from kafka import KafkaProducer

from .config import load_config
from .kafka_segmenter import KafkaPcapSegmenter


def _make_producer(bootstrap, max_segment_bytes):
    return KafkaProducer(
        bootstrap_servers=bootstrap,
        max_request_size=max_segment_bytes + (1 << 20),
        linger_ms=200,
        acks=1,
    )


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )
    cfg = load_config()
    producer = _make_producer(
        cfg["kafka"]["bootstrap"], cfg["kafka"]["segment_max_bytes"]
    )
    seg = KafkaPcapSegmenter(
        producer,
        cfg["kafka"]["topic"],
        cfg["capture"]["interface"],
        segment_seconds=cfg["kafka"]["segment_seconds"],
        segment_max_bytes=cfg["kafka"]["segment_max_bytes"],
    )

    def on_pkt(pi):
        seg.add_packet(pi.ts_sec, pi.ts_usec, pi.data)

    # Late import: tránh scapy nạp khi chỉ cần config.
    from core.capture import CaptureEngine

    engine = CaptureEngine(
        interface=cfg["capture"]["interface"],
        bpf_filter=cfg["capture"]["bpf"],
        on_packet_filtered=on_pkt,
    )

    last_segment_id = "-"
    n_segments = 0
    n_pkts = 0
    t_last_hb = time.monotonic()
    hb_every_sec = 60.0
    seg_logger = logging.getLogger("producer")

    def _emit_heartbeat(force: bool = False) -> None:
        nonlocal t_last_hb, n_segments, n_pkts
        now_mono = time.monotonic()
        if not force and (now_mono - t_last_hb) < hb_every_sec:
            return
        seg_logger.info(
            "heartbeat segments_published=%d pkts_buffered=%d last_segment=%s uptime_sec=%.1f",
            n_segments, n_pkts, last_segment_id, now_mono,
        )
        t_last_hb = now_mono

    # Patch segmenter to log structured flush events.
    original_flush = seg.flush
    def logged_flush():
        nonlocal last_segment_id, n_segments
        sid = original_flush()
        if sid is not None:
            n_segments += 1
            last_segment_id = sid
            seg_logger.info("[segment=%s] published segment to Kafka topic=%s",
                            sid, seg.topic)
            _emit_heartbeat(force=True)
        return sid
    seg.flush = logged_flush  # type: ignore[assignment]

    def shutdown(*_):
        seg_logger.info("producer: shutdown signal")
        try:
            engine.stop()
        except Exception as exc:
            logging.error("engine.stop: %s", exc)
        try:
            sid = seg.flush()
            if sid:
                seg_logger.info("[segment=%s] flushed final segment", sid)
        except Exception as exc:
            logging.error("seg.flush: %s", exc)
        try:
            producer.flush(timeout=5)
            producer.close(timeout=5)
        except Exception as exc:
            logging.error("producer.close: %s", exc)
        _emit_heartbeat(force=True)
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    seg_logger.info(
        "producer starting | interface=%s topic=%s segment_seconds=%d max_bytes=%d",
        cfg["capture"]["interface"], cfg["kafka"]["topic"],
        cfg["kafka"]["segment_seconds"], cfg["kafka"]["segment_max_bytes"],
    )

    engine.start()
    # Sniffer chạy trong background; main thread chờ signal.
    signal.pause()


if __name__ == "__main__":
    main()