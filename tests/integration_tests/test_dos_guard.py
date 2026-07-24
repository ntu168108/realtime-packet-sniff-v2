# -*- coding: utf-8 -*-
"""Unit tests for DosGuard adaptive backpressure + per-destination shedding."""
from integration.dos_guard import DosGuard


def _fresh(**kw):
    # Small thresholds so tests are explicit; pps path effectively off unless asked.
    return DosGuard(trigger_pps=50_000, clear_pps=15_000, target_pps=10_000, **kw)


def test_backward_compat_update_pps_only():
    """update(pps) with no backpressure kwargs still shed on a pps flood."""
    g = _fresh()
    g.update(200_000)  # pps flood, no drop/queue info
    assert g.dos_active is True
    assert g.sample_every >= 2  # ~ round(200k/10k)=20, clamped to max_drop


def test_no_shed_on_quiet_traffic():
    g = _fresh()
    g.update(2_000, kernel_drops=0, queue_drops=0, qsize=0, qcap=65536)
    assert g.dos_active is False
    assert g.sample_every == 1


def test_backpressure_escalates_on_queue_drops_even_when_pps_looks_normal():
    """The whole point: pps below trigger, but the pipeline is dropping ->
    shed anyway. NIC-agnostic survival signal."""
    g = _fresh()
    # pps 'normal' for a fast link, but queue drops are climbing each second.
    g.update(5_000, queue_drops=100, qsize=40_000, qcap=65536)
    g.update(5_000, queue_drops=500, qsize=50_000, qcap=65536)
    assert g.sample_every >= 2
    assert g.dos_active is True


def test_backpressure_escalates_on_queue_fill():
    g = _fresh()
    g.update(5_000, qsize=60_000, qcap=65536)  # ~0.92 fill >= high ratio 0.5
    assert g.sample_every >= 2


def test_backpressure_backs_off_on_relief():
    g = _fresh()
    # Ramp up under pressure.
    for d in (100, 300, 700, 1500):
        g.update(5_000, queue_drops=d, qsize=60_000, qcap=65536)
    hot = g.sample_every
    assert hot >= 4
    # Relief: low fill, no new drops. Additive backoff each second.
    last = hot
    for _ in range(hot + 2):
        g.update(2_000, queue_drops=1500, qsize=1_000, qcap=65536)
        assert g.sample_every <= last
        last = g.sample_every
    assert g.sample_every == 1
    assert g.dos_active is False


def test_pps_and_backpressure_take_the_more_aggressive():
    g = _fresh()
    # pps path alone -> ~ round(30k/10k)=3.
    g.update(30_000)
    pps_only = g.sample_every
    # Now add heavy backpressure; sample_every must be >= pps_only.
    for d in (200, 600, 1400, 3000):
        g.update(30_000, queue_drops=d, qsize=64_000, qcap=65536)
    assert g.sample_every >= pps_only


# ---- Task 2: per-destination surgical shedding ----

def test_should_keep_backward_compat_no_dst():
    """should_keep(seq) without dst behaves as a pure 1/N sampler."""
    g = _fresh()
    g.sample_every = 4
    kept = [s for s in range(20) if g.should_keep(s)]
    assert kept == [0, 4, 8, 12, 16]


def test_hot_victim_identified_on_concentration():
    g = _fresh(victim_share=0.5, victim_min_pps=100)
    victim = bytes([192, 168, 1, 10])
    other = bytes([192, 168, 1, 20])
    # 900 packets to victim, 100 to other -> 90% share, >100 pps.
    for i in range(900):
        g.should_keep(i, victim)
    for i in range(100):
        g.should_keep(i, other)
    g.update(0)  # 1 Hz tick: identify victim from the accumulated window
    assert g._hot_victim == victim
    assert g._victim_sample_every >= 2


def test_surgical_keeps_other_destinations_full():
    """With a hot victim + global shedding, non-victim traffic is kept 1/1."""
    g = _fresh(victim_share=0.5, victim_min_pps=100)
    victim = bytes([10, 0, 0, 9])
    other = bytes([10, 0, 0, 5])
    for i in range(800):
        g.should_keep(i, victim)
    for i in range(50):
        g.should_keep(i, other)
    g.update(0)
    assert g._hot_victim == victim
    # Non-victim: every packet kept.
    assert all(g.should_keep(s, other) for s in range(50))
    # Victim: sampled (not all kept).
    victim_kept = sum(g.should_keep(s, victim) for s in range(100))
    assert victim_kept < 100


def test_no_victim_when_spread_traffic():
    """Broadly spread traffic -> no single hot victim -> global sampling only."""
    g = _fresh(victim_share=0.6, victim_min_pps=10)
    for i in range(1000):
        dst = bytes([10, 0, 0, i % 50])  # 50 distinct dsts, even spread
        g.should_keep(i, dst)
    g.update(0)
    assert g._hot_victim is None


def test_dst_counter_memory_is_bounded():
    """Spoofed-destination flood must not grow the counter without bound."""
    g = _fresh()
    for i in range(20_000):
        g.should_keep(i, bytes([10, (i >> 8) & 255, i & 255, 0]))
    assert len(g._dst_counts) <= g._dst_cap


# ---- Task 4: _ipv4_dst frame parser (in run_producer) ----

def test_ipv4_dst_parses_standard_ethernet_frame():
    from integration.run_producer import _ipv4_dst
    # 12B MACs + ethertype 0x0800 + IP header; dst IP at IP-offset 16..20.
    eth = bytes(12) + bytes([0x08, 0x00])
    ip = bytearray(20)
    ip[16:20] = bytes([192, 168, 101, 135])  # dst
    frame = eth + bytes(ip) + b"payload"
    assert _ipv4_dst(frame) == bytes([192, 168, 101, 135])


def test_ipv4_dst_returns_none_for_non_ipv4():
    from integration.run_producer import _ipv4_dst
    arp = bytes(12) + bytes([0x08, 0x06]) + bytes(40)  # ARP ethertype
    assert _ipv4_dst(arp) is None
    assert _ipv4_dst(b"\x00" * 10) is None  # too short


def test_ipv4_dst_handles_vlan_tag():
    from integration.run_producer import _ipv4_dst
    # 802.1Q: ethertype 0x8100, 2B tag, then real ethertype 0x0800.
    eth = bytes(12) + bytes([0x81, 0x00]) + bytes([0x00, 0x64]) + bytes([0x08, 0x00])
    ip = bytearray(20)
    ip[16:20] = bytes([10, 0, 0, 9])
    frame = eth + bytes(ip)
    assert _ipv4_dst(frame) == bytes([10, 0, 0, 9])


def test_no_race_between_capture_thread_and_monitor_thread():
    """Regression test cho race condition thật đã tái tạo bằng thực nghiệm:

    should_keep(dst=...) (gọi từ luồng bắt gói qua _note_dst) và
    update()->_update_hot_victim() (gọi từ luồng giám sát 1Hz) cùng thao tác
    trên self._dst_counts. Bản vá cũ lặp trực tiếp trên dict đang sống rồi
    reset ở cuối -> nếu luồng bắt gói ghi thêm key mới đúng lúc luồng giám
    sát đang giữa vòng lặp .items(), Python ném
    `RuntimeError: dictionary changed size during iteration`.

    Test này ép mở rộng cửa sổ race bằng sys.setswitchinterval() cực thấp
    (kỹ thuật stress-test chuẩn cho race condition dưới GIL, không tạo lỗi
    giả) để lỗi hiếm gặp này biểu hiện đáng tin cậy trong CI thay vì chỉ
    thỉnh thoảng xuất hiện khi vận hành thật.
    """
    import sys
    import threading
    import time

    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        g = _fresh(backpressure=True, victim_share=0.5, victim_min_pps=1_000)
        g.dos_active = True
        errors = []
        stop = threading.Event()

        def capture_thread(idx):
            i = 0
            try:
                while not stop.is_set():
                    dst = f"10.{idx}.{(i >> 8) & 255}.{i & 255}".encode()
                    g.should_keep(i, dst=dst)
                    i += 1
            except Exception as e:  # noqa: BLE001
                errors.append((f"capture_thread_{idx}", repr(e)))

        def monitor_thread():
            try:
                while not stop.is_set():
                    g.update(80_000, kernel_drops=0, queue_drops=0,
                              qsize=40_000, qcap=65_536)
            except Exception as e:  # noqa: BLE001
                errors.append(("monitor_thread", repr(e)))

        threads = [threading.Thread(target=capture_thread, args=(i,))
                   for i in range(6)]
        mt = threading.Thread(target=monitor_thread)
        for t in threads:
            t.start()
        mt.start()
        time.sleep(3.0)
        stop.set()
        for t in threads:
            t.join(timeout=2)
        mt.join(timeout=2)

        assert errors == [], f"Race condition reproduced: {errors}"
    finally:
        sys.setswitchinterval(old_interval)
