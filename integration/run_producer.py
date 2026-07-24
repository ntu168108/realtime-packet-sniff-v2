"""Entrypoint: capture trên NIC → KafkaPcapSegmenter → Kafka.

Dùng core.capture.CaptureEngine (đã có sẵn từ SNIFF). Callback API thực tế:
- CaptureEngine(interface=..., bpf_filter=..., on_packet_filtered=...)
- on_packet_filtered nhận PacketInfo(ts_sec, ts_usec, data, ...)
"""
import logging
import signal
import sys
import threading
import time

from .config import load_config
from .dos_guard import DosGuard
from .kafka_segmenter import KafkaPcapSegmenter


def _ipv4_dst(data):
    """Trích 4 byte IP đích từ khung Ethernet thô. Trả None nếu không phải IPv4.

    Cực rẻ (chỉ đọc vài byte, không cấp phát) — an toàn cho hot path. Chỉ hỗ trợ
    Ethernet II + tùy chọn 1 tag 802.1Q; các loại khác trả None (bỏ qua per-dst).
    """
    n = len(data)
    if n < 34:
        return None
    etype = (data[12] << 8) | data[13]
    off = 14
    if etype == 0x8100:  # 802.1Q VLAN
        if n < 38:
            return None
        etype = (data[16] << 8) | data[17]
        off = 18
    if etype != 0x0800:  # not IPv4
        return None
    if n < off + 20:
        return None
    return bytes(data[off + 16:off + 20])


def _fmt_ip(b):
    """bytes(4) -> 'a.b.c.d' cho log; chấp nhận None."""
    if not b or len(b) != 4:
        return "-"
    return ".".join(str(x) for x in b)


def _make_producer(bootstrap, max_segment_bytes):
    # Late import: giữ module import được (vd để test helper thuần) khi chưa cài
    # kafka-python; khớp pattern late-import scapy đã dùng bên dưới.
    from kafka import KafkaProducer
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
        segment_max_packets=cfg["kafka"].get("segment_max_packets", 100_000),
    )

    # Tự bảo vệ chống DoS: cắt tải theo backpressure (NIC-agnostic) + pps, và
    # cắt CÓ CHỌN LỌC theo đích victim (giữ traffic hợp lệ).
    _cap = cfg["capture"]
    guard = DosGuard(
        trigger_pps=_cap.get("dos_trigger_pps", 50_000),
        clear_pps=_cap.get("dos_clear_pps", 15_000),
        target_pps=_cap.get("dos_target_pps", 10_000),
        max_drop=_cap.get("dos_max_drop", 200),
        backpressure=_cap.get("dos_backpressure", True),
        queue_high_ratio=_cap.get("dos_queue_high_ratio", 0.5),
        queue_low_ratio=_cap.get("dos_queue_low_ratio", 0.2),
        victim_share=_cap.get("dos_victim_share", 0.5),
        victim_min_pps=_cap.get("dos_victim_min_pps", 1_000),
    )

    def on_pkt(pi):
        # Fast path: khi KHÔNG bị DoS, không phân tích đích (dst=None) → không tốn gì.
        # Khi đang bị DoS, trích đích để cắt tải CÓ CHỌN LỌC (giữ traffic hợp lệ).
        dst = _ipv4_dst(pi.data) if guard.dos_active else None
        if not guard.should_keep(pi.stt, dst):
            return
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

    # --- Bộ ghi PCAP bằng chứng qua dumpcap (chống mất gói khi tải cao) ---
    # Nhánh Scapy -> RingBuffer -> dispatcher Python có thể drop trong burst
    # (đo thực tế: mất 60% gói ở POST 100MB). dumpcap (C, libpcap trực tiếp,
    # kernel buffer lớn) ghi file bằng chứng gần như không drop. Tùy chọn, hỏng
    # thì bỏ qua để KHÔNG chặn producer.
    evidence = None
    if cfg["capture"].get("evidence_dumpcap", True):
        try:
            from core.native_writer import DumpcapWriter
            _out = cfg["capture"].get("output", {}) or {}
            evidence = DumpcapWriter(
                interface=cfg["capture"]["interface"],
                out_dir=_out.get("base_dir", "/var/lib/sniff-web/sniff_data"),
                buffer_mb=int(cfg["capture"].get("evidence_buffer_mb", 512)),
                ring_seconds=int(_out.get("rotate_interval", 3600)),
                ring_filesize_kb=int(_out.get("max_file_size", 1073741824)) // 1024,
                snaplen=int(cfg["capture"].get("snaplen", 0) or 0),
                bpf_filter=cfg["capture"].get("bpf", ""),
            )
            evidence.start()
            seg_logger.info("evidence dumpcap writer started -> %s", evidence.out_dir)
        except Exception as exc:  # noqa: BLE001
            seg_logger.warning(
                "evidence dumpcap writer KHÔNG chạy được (bỏ qua, không chặn producer): %s",
                exc,
            )
            evidence = None

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
        if evidence is not None:
            try:
                evidence.stop()
            except Exception as exc:
                logging.error("evidence.stop: %s", exc)
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

    # Luồng nền 1Hz: đọc pps (CaptureEngine đã tính sẵn) → cập nhật DosGuard.
    # Khi phát hiện flood, log cảnh báo kèm top-talkers để biết ai đang đánh.
    def _dos_guard_loop():
        was_active = False
        while engine.is_running:
            try:
                st = engine.get_status()
                pps = st.get("pps", 0.0)
                active = guard.update(
                    pps,
                    kernel_drops=st.get("dropped", 0),
                    queue_drops=st.get("queue_dropped", 0),
                    qsize=st.get("queue_size", 0),
                    qcap=st.get("queue_capacity", 0),
                )
                if active:
                    top = engine.get_top_conversations(5)
                    ev = evidence.drop_stats() if evidence is not None else {}
                    seg_logger.warning(
                        "DoS SUSPECTED pps=%.0f giu_1/%d bp_level=%d victim=%s "
                        "top_talkers=%s evidence_drop=%s",
                        pps, guard.sample_every, guard._bp_level,
                        _fmt_ip(guard._hot_victim), top, ev,
                    )
                elif was_active:
                    seg_logger.info("DoS cleared pps=%.0f, thu day lai (1/1)", pps)
                was_active = active
            except Exception as exc:
                # Nâng từ debug lên warning kèm traceback: một exception ở đây
                # (vd race condition trong DosGuard._update_hot_victim, đã vá
                # nhưng để phòng lỗi tương tự trong tương lai) trước đây bị
                # nuốt âm thầm ở mức debug -- production log thường chạy ở
                # INFO trở lên nên không ai biết guard đã crash 1 vòng cập
                # nhật, ngay lúc hệ thống cần dữ liệu DoS chính xác nhất.
                logging.warning("dos_guard_loop: %s", exc, exc_info=True)
            time.sleep(1.0)

    threading.Thread(target=_dos_guard_loop, daemon=True, name="dos-guard").start()

    # Sniffer chạy trong background; main thread chờ signal.
    signal.pause()


if __name__ == "__main__":
    main()