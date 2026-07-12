# DosGuard Adaptive Backpressure + Per-Destination Shedding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the producer's DoS self-protection (`DosGuard`) NIC-agnostic by triggering load-shedding on actual pipeline backpressure (kernel/queue drops + queue fill) instead of an absolute `pps` threshold, and make it surgical by shedding only the concentrated-victim's traffic while keeping other destinations at full fidelity.

**Architecture:** `DosGuard` already runs as a 1 Hz control loop in `integration/run_producer.py` and exposes `should_keep(seq)` on the capture hot path. We extend it with (A1) a backpressure feedback controller (AIMD on a `sample_every` valve driven by `CaptureEngine.get_status()` drop/queue metrics that already exist) and (A3) per-destination accounting that identifies a concentrated flood victim and scopes shedding to that victim. The absolute-`pps` path is retained as an optional secondary signal; the effective `sample_every` is `max(backpressure, pps)`. No ClickHouse schema, sink, Kafka, or classifier code changes.

**Tech Stack:** Python 3.12 (deploy box) / 3.11 (dev), pandas 2.x, numpy 2.x, pytest 9, PyYAML. Pure-stdlib for the guard itself (no new dependencies).

## Global Constraints

- **Backward-compatible public API.** `run_producer.py` calls `guard.update(pps)` and `guard.should_keep(pi.stt)` positionally today; both must keep working unchanged. New parameters are keyword-only with safe defaults.
- **No new runtime dependencies.** `DosGuard` stays pure-stdlib (no numpy/pandas import in `dos_guard.py`).
- **Hot path stays cheap.** Per-destination accounting must add ZERO cost when not under attack: `on_pkt` only parses the destination IP and feeds per-dst counts when `guard.dos_active` is already `True`.
- **Do not touch** ClickHouse schema/DDL, `integration/schema.py`, `integration/clickhouse_sink.py`, the classifier (`unified_classifier.py`), or Kafka wire format.
- **Numpy-version safety:** no `np.char.*` (already burned once on NumPy ≥ 2.0). Not applicable here since the guard is pure stdlib, but keep it that way.
- **Config keys are additive** with defaults in `integration/config.py::_DEFAULTS["capture"]`; existing `config.yaml` on the box has no `dos_*` keys, so defaults must reproduce today's behavior when backpressure signals are absent (all-zero) — i.e. `sample_every` from pps path only.
- **Ship target:** push to `github.com/ntu168108/realtime-packet-sniff-v2`, merge to `main`, redeploy on box `tu@192.168.100.158` (`~/realtime-packet-sniff-v2`, systemd unit `sniff-producer`), verify.

---

## File Structure

- `integration/dos_guard.py` — **modify.** All guard logic: backpressure controller (A1), per-dst accounting + hot-victim identification (A3), extended `update()` / `should_keep()` / `stats()`. Single responsibility: the shed-decision state machine. Pure stdlib.
- `integration/config.py` — **modify.** Add `dos_backpressure`, `dos_queue_high_ratio`, `dos_queue_low_ratio`, `dos_victim_share`, `dos_victim_min_pps`, `dos_max_drop` to `_DEFAULTS["capture"]`.
- `config.yaml.example` — **modify.** Document the new tunables under `capture:`.
- `integration/run_producer.py` — **modify.** Add `_ipv4_dst()` + `_fmt_ip()` helpers; extend `on_pkt` to feed destination when `guard.dos_active`; extend `_dos_guard_loop` to pass backpressure metrics from `get_status()` and read new config.
- `tests/integration_tests/test_dos_guard.py` — **create.** Unit tests for the guard state machine (backward-compat, backpressure escalate/backoff, pps/backpressure max, per-dst victim, surgical keep, memory cap) and for `_ipv4_dst`.
- `docs/operations/architecture.md` — **modify.** New "Adaptive DoS self-protection" subsection.
- `docs/operations/deployment.vi.md` — **modify.** Extend the tuning table (section 11.3) with the new keys.
- `CHANGELOG.md` — **modify.** New `[Unreleased]` block.

---

### Task 1: DosGuard — backpressure feedback controller (A1)

**Files:**
- Modify: `integration/dos_guard.py`
- Test: `tests/integration_tests/test_dos_guard.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `DosGuard.__init__(self, trigger_pps=50_000, clear_pps=15_000, target_pps=10_000, max_drop=200, *, backpressure=True, queue_high_ratio=0.5, queue_low_ratio=0.2, victim_share=0.5, victim_min_pps=1_000)` — victim params are consumed in Task 2.
  - `DosGuard.update(self, pps, *, kernel_drops=0, queue_drops=0, qsize=0, qcap=0) -> bool` — returns `dos_active`.
  - Public attrs read by later tasks / producer: `sample_every: int`, `dos_active: bool`, `last_pps: float`.

- [ ] **Step 1: Write the failing tests**

Create `tests/integration_tests/test_dos_guard.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration_tests/test_dos_guard.py -q`
Expected: FAIL — `update()` currently rejects the `kernel_drops`/`queue_drops`/`qsize`/`qcap` keyword args (`TypeError: update() got an unexpected keyword argument`).

- [ ] **Step 3: Rewrite `DosGuard.__init__` and `update()`**

Replace the `__init__` body and the entire `update()` method in `integration/dos_guard.py`. Keep the module docstring; keep `should_keep()`/`stats()` for now (Task 2 rewrites them). New code:

```python
    def __init__(
        self,
        trigger_pps: float = 50_000,
        clear_pps: float = 15_000,
        target_pps: float = 10_000,
        max_drop: int = 200,
        *,
        backpressure: bool = True,
        queue_high_ratio: float = 0.5,
        queue_low_ratio: float = 0.2,
        victim_share: float = 0.5,
        victim_min_pps: float = 1_000,
    ):
        if not (clear_pps <= trigger_pps):
            raise ValueError("clear_pps phải <= trigger_pps (hysteresis)")
        if not (0.0 <= queue_low_ratio <= queue_high_ratio <= 1.0):
            raise ValueError("cần 0 <= queue_low_ratio <= queue_high_ratio <= 1")
        self.trigger_pps = float(trigger_pps)
        self.clear_pps = float(clear_pps)
        self.target_pps = max(1.0, float(target_pps))
        self.max_drop = max(1, int(max_drop))

        # A1 — backpressure controller
        self.backpressure = bool(backpressure)
        self.queue_high_ratio = float(queue_high_ratio)
        self.queue_low_ratio = float(queue_low_ratio)
        self._bp_level: int = 1
        self._prev_kernel_drops: int = 0
        self._prev_queue_drops: int = 0

        # A3 — per-destination (used in Task 2)
        self.victim_share = float(victim_share)
        self.victim_min_pps = float(victim_min_pps)
        self._dst_counts: dict = {}
        self._dst_cap: int = 4096
        self._hot_victim = None
        self._victim_sample_every: int = 1

        # Shared / public
        self.sample_every: int = 1     # 1 = giữ mọi gói; N = chỉ giữ 1/N
        self.dos_active: bool = False
        self.last_pps: float = 0.0

    def update(
        self,
        pps: float,
        *,
        kernel_drops: int = 0,
        queue_drops: int = 0,
        qsize: int = 0,
        qcap: int = 0,
    ) -> bool:
        """Cập nhật trạng thái ~1 lần/giây. Trả về True nếu đang cắt tải.

        Hai bộ phát hiện chạy song song, lấy mức CẮT TẢI mạnh hơn:
          * pps tuyệt đối (giữ để tương thích ngược / mạng nhỏ đã hiệu chỉnh).
          * backpressure (NIC-agnostic): khi kernel/queue bắt đầu DROP hoặc hàng
            đợi đầy quá high-watermark → pipeline đang hụt hơi → cắt tải theo AIMD
            (nhân đôi khi còn áp lực, trừ dần khi hết) — không phụ thuộc tốc độ NIC.
        """
        self.last_pps = pps

        # --- backpressure controller (AIMD) ---
        d_kernel = max(0, int(kernel_drops) - self._prev_kernel_drops)
        d_queue = max(0, int(queue_drops) - self._prev_queue_drops)
        self._prev_kernel_drops = int(kernel_drops)
        self._prev_queue_drops = int(queue_drops)
        fill = (qsize / qcap) if qcap and qcap > 0 else 0.0
        under_pressure = self.backpressure and (
            d_kernel > 0 or d_queue > 0 or fill >= self.queue_high_ratio
        )
        relieved = fill <= self.queue_low_ratio and d_kernel == 0 and d_queue == 0
        if under_pressure:
            self._bp_level = min(self.max_drop, max(2, self._bp_level * 2))
        elif relieved:
            self._bp_level = max(1, self._bp_level - 1)
        # else: hold (mid-band hysteresis, tránh dao động)

        # --- pps detector (legacy / small-LAN) ---
        if pps >= self.trigger_pps:
            self._pps_active = True
        elif pps <= self.clear_pps:
            self._pps_active = False
        pps_level = 1
        if getattr(self, "_pps_active", False) and pps > self.target_pps:
            pps_level = min(self.max_drop, max(2, round(pps / self.target_pps)))

        # --- combine: the more aggressive valve wins ---
        self.sample_every = max(self._bp_level, pps_level)

        # A3 hot-victim identification runs here (implemented in Task 2).
        self._update_hot_victim(pps)

        self.dos_active = (
            self.sample_every > 1
            or getattr(self, "_pps_active", False)
            or self._hot_victim is not None
        )
        return self.dos_active

    def _update_hot_victim(self, pps: float) -> None:
        """Placeholder — Task 2 replaces this with per-destination logic."""
        self._hot_victim = None
        self._victim_sample_every = 1
        self._dst_counts = {}
```

> NOTE: `_pps_active` is created lazily; the two `getattr(..., "_pps_active", False)` guards make the first call safe without adding it to `__init__` (kept minimal to reduce diff). It is acceptable to instead initialize `self._pps_active = False` in `__init__` — do whichever the reviewer prefers, but be consistent.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration_tests/test_dos_guard.py -q`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add integration/dos_guard.py tests/integration_tests/test_dos_guard.py
git commit -m "feat(dosguard): backpressure-driven load shedding (NIC-agnostic)"
```

---

### Task 2: DosGuard — per-destination surgical shedding (A3)

**Files:**
- Modify: `integration/dos_guard.py`
- Test: `tests/integration_tests/test_dos_guard.py`

**Interfaces:**
- Consumes: `DosGuard` from Task 1 (`sample_every`, `dos_active`, `victim_share`, `victim_min_pps`, `_dst_counts`, `_dst_cap`, `_hot_victim`, `_victim_sample_every`, `_update_hot_victim`).
- Produces:
  - `DosGuard.should_keep(self, seq: int, dst=None) -> bool` — `dst` is an opaque hashable key (4-byte `bytes` from the producer) or `None`. Counts `dst` and applies victim-scoped sampling.
  - `DosGuard._update_hot_victim(self, pps)` — real implementation.
  - `DosGuard.stats(self) -> dict` — adds `bp_level`, `hot_victim`, `victim_sample_every`.

- [ ] **Step 1: Write the failing tests (append to `test_dos_guard.py`)**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration_tests/test_dos_guard.py -q`
Expected: FAIL — current `should_keep(self, seq)` takes no `dst` arg (`TypeError`), and `_update_hot_victim` is the placeholder that never sets a victim.

- [ ] **Step 3: Replace `should_keep`, `_update_hot_victim`, and `stats`**

In `integration/dos_guard.py`, replace the placeholder `_update_hot_victim` and the existing `should_keep`/`stats` with:

```python
    def _note_dst(self, dst) -> None:
        """Đếm 1 gói theo đích cho cửa sổ 1 giây. Chặn phình bộ nhớ khi bị
        flood spoofed-DESTINATION bằng trần số key (bỏ qua key mới khi đầy —
        các đích 'nóng' đã có mặt vẫn được đếm tiếp)."""
        c = self._dst_counts
        if dst in c:
            c[dst] += 1
        elif len(c) < self._dst_cap:
            c[dst] = 1
        # else: counter đầy -> bỏ qua đích mới (đủ để nhận diện đích nóng đã thấy)

    def should_keep(self, seq: int, dst=None) -> bool:
        """Quyết định giữ (True) / bỏ (False) một gói. Cực rẻ, gọi mỗi gói.

        Args:
            seq: số thứ tự tăng dần của gói (PacketInfo.stt).
            dst: khoá đích (bytes IPv4) để cắt tải CÓ CHỌN LỌC, hoặc None để
                 dùng tỉ lệ cắt tải toàn cục. Producer chỉ truyền dst khi
                 `dos_active` (fast path bình thường: dst=None, không tốn gì).
        """
        if dst is not None:
            self._note_dst(dst)
            if self._hot_victim is not None:
                # Chỉ cắt tải luồng đổ vào ĐÍCH NÓNG; đích khác giữ nguyên 1/1.
                n = self._victim_sample_every if dst == self._hot_victim else 1
                return n == 1 or (seq % n == 0)
        n = self.sample_every
        return n == 1 or (seq % n == 0)

    def _update_hot_victim(self, pps: float) -> None:
        """Từ cửa sổ đếm 1 giây, xác định 'đích nóng' (victim) nếu lưu lượng dồn
        tập trung: đích chiếm >= victim_share tổng gói VÀ vượt victim_min_pps.
        Đặt tỉ lệ cắt tải riêng cho victim để kéo tốc độ tới nó về ~target_pps.
        Reset cửa sổ đếm sau mỗi lần gọi."""
        self._hot_victim = None
        self._victim_sample_every = 1
        counts = self._dst_counts
        total = 0
        top_dst = None
        top_n = 0
        for k, v in counts.items():
            total += v
            if v > top_n:
                top_n, top_dst = v, k
        if (
            self.victim_share > 0.0
            and total > 0
            and top_dst is not None
            and (top_n / total) >= self.victim_share
            and top_n >= self.victim_min_pps
        ):
            self._hot_victim = top_dst
            self._victim_sample_every = min(
                self.max_drop, max(2, round(top_n / self.target_pps))
            )
        self._dst_counts = {}

    def stats(self) -> dict:
        """Ảnh chụp trạng thái để log/giám sát."""
        return {
            "dos_active": self.dos_active,
            "sample_every": self.sample_every,
            "bp_level": self._bp_level,
            "last_pps": round(self.last_pps, 1),
            "keep_ratio": round(1.0 / self.sample_every, 4),
            "hot_victim": self._hot_victim,
            "victim_sample_every": self._victim_sample_every,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/integration_tests/test_dos_guard.py -q`
Expected: PASS (11 tests total).

- [ ] **Step 5: Commit**

```bash
git add integration/dos_guard.py tests/integration_tests/test_dos_guard.py
git commit -m "feat(dosguard): per-destination surgical shedding (spare legit traffic)"
```

---

### Task 3: Config — new tunables, defaults, and documented example

**Files:**
- Modify: `integration/config.py:24-32` (the `capture` block of `_DEFAULTS`)
- Modify: `config.yaml.example` (the `capture:` block, starting line 5)
- Test: `tests/integration_tests/test_config.py` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: config keys under `cfg["capture"]`: `dos_backpressure` (bool), `dos_queue_high_ratio` (float), `dos_queue_low_ratio` (float), `dos_victim_share` (float), `dos_victim_min_pps` (float), `dos_max_drop` (int). Consumed by Task 4.

- [ ] **Step 1: Write the failing test (append to `tests/integration_tests/test_config.py`)**

```python
def test_capture_defaults_include_adaptive_dos_keys():
    from integration.config import load_config
    cfg = load_config(path="/nonexistent-so-defaults-only.yaml")
    cap = cfg["capture"]
    assert cap["dos_backpressure"] is True
    assert cap["dos_queue_high_ratio"] == 0.5
    assert cap["dos_queue_low_ratio"] == 0.2
    assert cap["dos_victim_share"] == 0.5
    assert cap["dos_victim_min_pps"] == 1_000
    assert cap["dos_max_drop"] == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/integration_tests/test_config.py::test_capture_defaults_include_adaptive_dos_keys -q`
Expected: FAIL with `KeyError: 'dos_backpressure'`.

- [ ] **Step 3: Add the defaults**

In `integration/config.py`, replace the `"capture"` dict in `_DEFAULTS` with:

```python
    "capture": {
        "interface": "ens33",
        "bpf": "not port 22",
        "keep_local_pcap": False,
        # --- Tự bảo vệ chống DoS (DosGuard) ---
        # Cơ chế pps tuyệt đối (nhỏ/lab; con số tuyệt đối, KHÔNG co giãn theo NIC).
        "dos_trigger_pps": 50_000,   # vượt mức này → bật chế độ cắt tải (DoS)
        "dos_clear_pps": 15_000,     # xuống dưới mức này → tắt (hysteresis)
        "dos_target_pps": 10_000,    # mức gói/giây CHẤP NHẬN thu khi bị DoS
        # Cơ chế backpressure (NIC-agnostic): cắt tải khi pipeline THỰC SỰ hụt
        # hơi (kernel/queue drop, hàng đợi đầy) — đúng cho mọi tốc độ NIC.
        "dos_backpressure": True,
        "dos_queue_high_ratio": 0.5,  # hàng đợi đầy >= mức này → tăng cắt tải
        "dos_queue_low_ratio": 0.2,   # hàng đợi <= mức này + hết drop → giảm dần
        # Cắt tải CÓ CHỌN LỌC theo đích: chỉ hạ luồng đổ vào victim tập trung,
        # giữ nguyên traffic hợp lệ tới đích khác. Đặt dos_victim_share=0 để tắt.
        "dos_victim_share": 0.5,      # 1 đích chiếm >= tỉ lệ này → coi là victim
        "dos_victim_min_pps": 1_000,  # và vượt mức pps này (tránh báo nhầm lúc nhàn)
        "dos_max_drop": 200,          # trần tỉ lệ bỏ gói (giữ tối thiểu 1/200)
    },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/integration_tests/test_config.py::test_capture_defaults_include_adaptive_dos_keys -q`
Expected: PASS.

- [ ] **Step 5: Document the keys in `config.yaml.example`**

In `config.yaml.example`, inside the `capture:` block (after the `snaplen` line ~15), add:

```yaml
  # --- DoS self-protection (DosGuard) ---
  # pps tuyệt đối — chỉ hợp mạng nhỏ/lab (KHÔNG co giãn theo NIC 10G/100G):
  dos_trigger_pps: 50000
  dos_clear_pps: 15000
  dos_target_pps: 10000
  # backpressure (NIC-agnostic, KHUYẾN NGHỊ bật): cắt tải theo drop/queue thật:
  dos_backpressure: true
  dos_queue_high_ratio: 0.5
  dos_queue_low_ratio: 0.2
  # cắt tải chọn lọc theo đích (giữ traffic hợp lệ); 0 = tắt:
  dos_victim_share: 0.5
  dos_victim_min_pps: 1000
  dos_max_drop: 200
```

- [ ] **Step 6: Commit**

```bash
git add integration/config.py config.yaml.example tests/integration_tests/test_config.py
git commit -m "feat(config): adaptive DoS-guard tunables (backpressure + per-dst)"
```

---

### Task 4: Producer wiring — feed destination + backpressure metrics

**Files:**
- Modify: `integration/run_producer.py` (guard construction ~48-52, `on_pkt` ~54-58, `_dos_guard_loop` ~167-185; add module-level helpers)
- Test: `tests/integration_tests/test_dos_guard.py` (append `_ipv4_dst` tests)

**Interfaces:**
- Consumes: `DosGuard(update/should_keep/dos_active)` from Tasks 1-2; config keys from Task 3; `engine.get_status()` keys `pps`, `dropped`, `queue_dropped`, `queue_size`, `queue_capacity` (verified present in `core/capture.py:625-641`).
- Produces: module-level `_ipv4_dst(data: bytes) -> bytes | None` and `_fmt_ip(b) -> str` in `run_producer.py`.

- [ ] **Step 1: Write the failing tests (append to `test_dos_guard.py`)**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/integration_tests/test_dos_guard.py -q -k ipv4_dst`
Expected: FAIL — `_ipv4_dst` does not exist yet (`ImportError`/`AttributeError`).

- [ ] **Step 3: Add the helpers to `run_producer.py`**

Near the top of `integration/run_producer.py` (after imports, module scope), add:

```python
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
```

- [ ] **Step 4: Run helper tests to verify they pass**

Run: `python -m pytest tests/integration_tests/test_dos_guard.py -q -k ipv4_dst`
Expected: PASS (3 tests).

- [ ] **Step 5: Wire config + on_pkt + guard loop**

In `integration/run_producer.py`:

(a) Replace the `guard = DosGuard(...)` construction (~48-52) with:

```python
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
```

(b) Replace `on_pkt` (~54-58) with:

```python
    def on_pkt(pi):
        # Fast path: khi KHÔNG bị DoS, không phân tích đích (dst=None) → không tốn gì.
        # Khi đang bị DoS, trích đích để cắt tải CÓ CHỌN LỌC (giữ traffic hợp lệ).
        dst = _ipv4_dst(pi.data) if guard.dos_active else None
        if not guard.should_keep(pi.stt, dst):
            return
        seg.add_packet(pi.ts_sec, pi.ts_usec, pi.data)
```

(c) Replace the body of `_dos_guard_loop` (~167-185) with:

```python
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
                logging.debug("dos_guard_loop: %s", exc)
            time.sleep(1.0)
```

- [ ] **Step 6: Run the full guard/producer test module + a syntax check**

Run:
```bash
python -m pytest tests/integration_tests/test_dos_guard.py -q
python -m py_compile integration/run_producer.py integration/dos_guard.py integration/config.py
```
Expected: tests PASS (14 total), `py_compile` prints nothing (exit 0).

- [ ] **Step 7: Commit**

```bash
git add integration/run_producer.py tests/integration_tests/test_dos_guard.py
git commit -m "feat(producer): feed backpressure metrics + per-dst to DosGuard"
```

---

### Task 5: Documentation

**Files:**
- Modify: `docs/operations/architecture.md` (DoS-protection area)
- Modify: `docs/operations/deployment.vi.md` (section 11.3 tuning table)
- Modify: `CHANGELOG.md` (top, new `[Unreleased]` block)

**Interfaces:** none (docs only).

- [ ] **Step 1: Add an architecture subsection**

In `docs/operations/architecture.md`, after the "Classification: one label per flow" subsection added earlier (search for `### Classification: one label per flow`), insert:

```markdown
### Adaptive DoS self-protection (producer)

`integration/dos_guard.py` (`DosGuard`) is the capture-side load valve. It runs
as a 1 Hz control loop in `run_producer.py` and decides, per packet, whether to
keep or drop (`should_keep`). Three signals drive it:

1. **Backpressure (default, NIC-agnostic)** — escalates shedding (AIMD on
   `sample_every`) when the pipeline actually falls behind: kernel/queue drops
   climb or the ring buffer fills past `dos_queue_high_ratio`. Because it reacts
   to saturation rather than an absolute packet rate, it scales to any NIC speed.
2. **Absolute pps (legacy)** — the original `dos_trigger_pps` threshold, kept for
   small/lab LANs. The effective sample rate is `max(backpressure, pps)`.
3. **Per-destination concentration** — once shedding is active, the guard finds a
   "hot victim" (a single destination taking ≥ `dos_victim_share` of packets and
   over `dos_victim_min_pps`) and sheds only that destination's flood, keeping
   traffic to every other destination at full fidelity. Destination is parsed
   from the raw frame only while `dos_active` (zero cost in normal operation).

The ring buffer has a hard ceiling and drops-newest when full, so the host can
never OOM from the queue regardless of guard tuning; the guard's job is to shed
*early and selectively* so a flood costs CPU/quality, not a crash. The consumer's
`EC_MAX_PKTS_PER_SEGMENT` circuit breaker is the last-resort backstop.

**Scaling note:** full-packet capture via this Python/Scapy path is not intended
for sustained 10G/100G line rate. At those speeds add kernel-level sampling
(`PACKET_FANOUT`/XDP) or move to flow telemetry (sFlow/NetFlow/IPFIX); the
adaptive guard here keeps the box alive but cannot manufacture capture headroom.
```

- [ ] **Step 2: Extend the deployment tuning table**

In `docs/operations/deployment.vi.md`, section **11.3** (search for `### 11.3 Hiệu chỉnh`), add these rows to the env/config table (they are set in `config.yaml` under `capture:`):

```markdown
| `dos_backpressure` | `true` | Bật cắt tải theo backpressure (drop/queue thật) — NIC-agnostic, KHUYẾN NGHỊ để `true`. Với NIC 10G/100G đây là cơ chế chính; ngưỡng pps tuyệt đối gần như vô dụng ở tốc độ đó. |
| `dos_queue_high_ratio` | `0.5` | Hàng đợi đầy ≥ tỉ lệ này → tăng cắt tải. Hạ xuống để phản ứng sớm hơn. |
| `dos_queue_low_ratio` | `0.2` | Hàng đợi ≤ tỉ lệ này + hết drop → giảm cắt tải dần, rồi trở lại 1/1. |
| `dos_victim_share` | `0.5` | 1 đích chiếm ≥ tỉ lệ này tổng gói → coi là victim, chỉ cắt luồng tới nó, giữ traffic hợp lệ khác. Đặt `0` để tắt cắt-tải-chọn-lọc. |
| `dos_victim_min_pps` | `1000` | Ngưỡng pps tối thiểu của 1 đích để bị coi là victim (tránh báo nhầm lúc mạng nhàn). |
| `dos_max_drop` | `200` | Trần tỉ lệ bỏ gói (giữ tối thiểu 1/200) — dù flood cực lớn vẫn còn mẫu để phân loại. |
```

Also append, right below that table:

```markdown
> **NIC nhanh (10G/100G):** `dos_backpressure` để `true` và **bỏ qua** việc chỉnh
> `dos_trigger_pps` (ngưỡng tuyệt đối không co giãn theo NIC). Guard sẽ tự cắt tải
> khi thực sự hụt hơi. Nếu vẫn drop nhiều ở kernel, vấn đề là TRẦN BẮT GÓI của
> tầng Python/Scapy — cần kernel sampling (PACKET_FANOUT/XDP) hoặc flow telemetry
> (sFlow/IPFIX), không phải chỉnh guard.
```

- [ ] **Step 3: Add the CHANGELOG block**

At the top of `CHANGELOG.md` (right under the `All notable changes...` line), insert:

```markdown
## [Unreleased] - feat/dosguard-adaptive-backpressure

### Added
- **DosGuard backpressure mode (NIC-agnostic self-protection).** The capture-side
  load valve now sheds based on real pipeline saturation — kernel/queue drops and
  ring-buffer fill from `CaptureEngine.get_status()` — via an AIMD controller,
  instead of relying only on an absolute `pps` threshold that mis-scales on
  10G/100G links. Effective sampling is `max(backpressure, pps)`; the pps path is
  retained for small/lab LANs. Config: `dos_backpressure`, `dos_queue_high_ratio`,
  `dos_queue_low_ratio`.
- **Per-destination surgical shedding.** While shedding is active, the guard
  identifies a concentrated flood victim (≥ `dos_victim_share` of packets and
  over `dos_victim_min_pps`) and sheds only that destination's traffic, keeping
  every other destination at full fidelity — so a flood aimed at one host no
  longer forces uniform sampling of legitimate traffic. Destination is parsed from
  the raw frame only while `dos_active` (zero added cost in normal operation).
  Config: `dos_victim_share`, `dos_victim_min_pps`, `dos_max_drop`.

### Notes
- `DosGuard.update()` and `should_keep()` remain backward compatible
  (`update(pps)` / `should_keep(seq)` still valid); new inputs are keyword-only /
  optional. No ClickHouse schema, sink, Kafka, or classifier changes.
- Full-packet capture on this Python/Scapy path is not intended for sustained
  10G/100G; see `docs/operations/architecture.md` (Adaptive DoS self-protection).
```

- [ ] **Step 4: Commit**

```bash
git add docs/operations/architecture.md docs/operations/deployment.vi.md CHANGELOG.md
git commit -m "docs: document adaptive DoS-guard (backpressure + per-dst) + tuning"
```

---

### Task 6: Ship — verify, push, PR, merge, redeploy, confirm

**Files:** none (release engineering). This task must be executed by an operator who has: the local repo clone at the working directory, GitHub push auth for `ntu168108/realtime-packet-sniff-v2`, and SSH key access to `tu@192.168.100.158` (key `~/.ssh/id_sniff`).

**Interfaces:** consumes all prior tasks (a clean working tree with the 5 feature commits on a fresh branch).

- [ ] **Step 1: Full regression run (local)**

Run:
```bash
python -m pytest tests/integration_tests/test_dos_guard.py tests/integration_tests/test_config.py \
  tests/integration_tests/test_clickhouse_sink.py tests/integration_tests/test_schema.py -q
cd Extraction-and-classification && python -m pytest MODULE_PHANLOAI/tests/test_unified_classifier.py -q && cd ..
```
Expected: all PASS. (The 5 pre-existing `test_wrapper_end_to_end.py` CWD-path failures are unrelated and out of scope — do not "fix" them here.)

- [ ] **Step 2: Create the branch and confirm no secret is committed**

```bash
git checkout -b feat/dosguard-adaptive-backpressure
grep -rn "ghp_" --include="*.py" --include="*.md" --include="*.yaml" . | grep -v ".git/" || echo "clean"
git log --oneline -6
```
Expected: `clean`; six commits listed (5 feature + this branch base is the 5 commits from Tasks 1-5).

- [ ] **Step 3: Push the branch**

```bash
git push -u origin feat/dosguard-adaptive-backpressure
```
Expected: branch created on origin; a PR-create URL is printed.

- [ ] **Step 4: Open a PR** (Python + GitHub API; token supplied out-of-band as `$GH_TOKEN`, never written to a file)

```bash
python - <<'PY'
import json, os, urllib.request
tok = os.environ["GH_TOKEN"]
body = ("Make DosGuard NIC-agnostic: shed on real backpressure (kernel/queue "
        "drops + ring fill, AIMD) instead of an absolute pps threshold, and shed "
        "only the concentrated victim's traffic while sparing legitimate flows. "
        "Backward-compatible API; no schema/sink/classifier changes. "
        "Tests: tests/integration_tests/test_dos_guard.py (14 cases).\n\n"
        "See docs/operations/architecture.md 'Adaptive DoS self-protection' and "
        "deployment.vi.md 11.3.\n\n🤖 Generated with Claude Code")
data = json.dumps({"title": "feat: adaptive DoS-guard (backpressure + per-destination shedding)",
                   "head": "feat/dosguard-adaptive-backpressure", "base": "main",
                   "body": body}).encode()
req = urllib.request.Request(
    "https://api.github.com/repos/ntu168108/realtime-packet-sniff-v2/pulls",
    data=data, method="POST",
    headers={"Authorization": "token " + tok, "Accept": "application/vnd.github+json",
             "User-Agent": "claude"})
r = json.load(urllib.request.urlopen(req))
print("PR #%d: %s" % (r["number"], r["html_url"]))
PY
```
Expected: prints `PR #NN: https://github.com/...`.

- [ ] **Step 5: Merge the PR (squash)**

```bash
python - <<'PY'
import json, os, urllib.request
tok = os.environ["GH_TOKEN"]; pr = os.environ["PR_NUMBER"]
data = json.dumps({"merge_method": "squash"}).encode()
req = urllib.request.Request(
    "https://api.github.com/repos/ntu168108/realtime-packet-sniff-v2/pulls/%s/merge" % pr,
    data=data, method="PUT",
    headers={"Authorization": "token " + tok, "Accept": "application/vnd.github+json",
             "User-Agent": "claude"})
print("merged:", json.load(urllib.request.urlopen(req)).get("merged"))
PY
```
Expected: `merged: True`.

- [ ] **Step 6: Redeploy on the box**

```bash
ssh -i ~/.ssh/id_sniff tu@192.168.100.158 \
  "cd ~/realtime-packet-sniff-v2 && git checkout -- sniff-web/web/package-lock.json 2>/dev/null; \
   git fetch origin -q && git pull origin main 2>&1 | tail -4 && \
   git log --oneline -1 && \
   echo 1 | sudo -S -p '' systemctl restart sniff-producer && sleep 3 && \
   echo 1 | sudo -S -p '' systemctl is-active sniff-producer"
```
Expected: pull succeeds; HEAD is the squashed merge commit; `sniff-producer` prints `active`.

- [ ] **Step 7: Verify the guard loads and its config is live**

```bash
ssh -i ~/.ssh/id_sniff tu@192.168.100.158 \
  "cd ~/realtime-packet-sniff-v2 && .venv/bin/python -c \
   'from integration.dos_guard import DosGuard; g=DosGuard(); \
    g.update(5000, queue_drops=500, qsize=60000, qcap=65536); \
    print(\"sample_every=\",g.sample_every,\"active=\",g.dos_active,\"stats=\",g.stats())'"
```
Expected: `sample_every= 2 active= True stats= {...'bp_level': 2...}` — proves backpressure escalation runs in the box's Python 3.12 / numpy 2.x environment.

- [ ] **Step 8: Confirm the producer is capturing normally (no false shedding at idle)**

```bash
ssh -i ~/.ssh/id_sniff tu@192.168.100.158 \
  "echo 1 | sudo -S -p '' journalctl -u sniff-producer -n 30 --no-pager | grep -E 'DoS SUSPECTED|DoS cleared|heartbeat' | tail -5; \
   echo '--- expect: NO \"DoS SUSPECTED\" line while the network is idle ---'"
```
Expected: recent heartbeat lines, and **no** `DoS SUSPECTED` while traffic is normal (confirms the backpressure valve is not firing on benign load). If `DoS SUSPECTED` appears at idle, raise `dos_queue_high_ratio` / lower sensitivity per section 11.3 and restart.

---

## Self-Review

**1. Spec coverage** — Option 1 = A1 (backpressure) + A3 (per-destination), backward compatible, config-driven, plus full ship (docs + code → repo). Mapping:
- A1 backpressure controller → Task 1. ✅
- A3 per-destination surgical shedding → Task 2. ✅
- Config tunables + example → Task 3. ✅
- Producer wiring (feed metrics + dst, zero idle cost) → Task 4. ✅
- Docs (architecture + deployment tuning + CHANGELOG) → Task 5. ✅
- Push/PR/merge/redeploy/verify on the same repo + box → Task 6. ✅
- "Đầy đủ từ doc tới code" → Tasks 1-4 (code) + Task 5 (docs) + Task 6 (ship). ✅

**2. Placeholder scan** — every code step contains complete code; every command has expected output; no "TBD"/"handle edge cases"/"similar to Task N". ✅

**3. Type consistency** — `sample_every:int`, `dos_active:bool`, `_bp_level:int`, `_hot_victim:bytes|None`, `_victim_sample_every:int`, `_dst_counts:dict`, `_dst_cap:int` are defined in Task 1's `__init__` and used verbatim in Tasks 2/4. `update(pps, *, kernel_drops, queue_drops, qsize, qcap)` (Task 1) is called with exactly those kwargs in Task 4. `should_keep(seq, dst=None)` (Task 2) called as `should_keep(pi.stt, dst)` in Task 4. `_ipv4_dst(data)->bytes|None` / `_fmt_ip(b)->str` (Task 4) used in `on_pkt` and the log line. `get_status()` keys (`pps`, `dropped`, `queue_dropped`, `queue_size`, `queue_capacity`) match `core/capture.py:625-641`. Config keys defined in Task 3 match those read in Task 4's `guard = DosGuard(...)`. ✅

**Known out-of-scope (documented, not fixed):** the 5 pre-existing `test_wrapper_end_to_end.py` CWD-relative fixture failures; and true 10G/100G capture headroom (kernel-bypass / flow telemetry) — Task 5 documents this as the boundary of what the guard can do.
