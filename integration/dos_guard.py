"""DosGuard: tự bảo vệ chống DoS ở tầng thu.

Bài toán: khi bị flood (SYN/UDP/ICMP), producer nhồi hàng trăm nghìn gói mỗi
segment → consumer chạy Argus/Zeek/pandas trên khối dữ liệu khổng lồ → cạn RAM
→ OOM killer làm sập cả host. Phát hiện DoS ở cuối pipeline (dos_classifier) là
QUÁ TRỄ vì máy đã sập trước khi kịp phân loại.

Giải pháp: phát hiện flood ngay tại tầng capture bằng `pps` (đã được
CaptureEngine tính sẵn mỗi giây, không đụng hot path), rồi CẮT TẢI bằng cách
chỉ giữ lại 1/N gói (lấy mẫu). Một IDS không cần từng gói của trận flood để
kết luận đó là flood — một mẫu đại diện là đủ để dos_classifier gắn nhãn.

Cách dùng (xem integration/run_producer.py):

    guard = DosGuard(trigger_pps=50_000, clear_pps=15_000, target_pps=10_000)

    def on_pkt(pi):
        if not guard.should_keep(pi.stt):
            return                       # bỏ gói flood — KHÔNG thu thập
        seg.add_packet(pi.ts_sec, pi.ts_usec, pi.data)

    # luồng nền 1Hz cập nhật guard từ pps
    while True:
        guard.update(engine.get_status()["pps"])
        time.sleep(1)
"""


class DosGuard:
    """Phát hiện flood bằng pps và cắt tải bằng lấy mẫu 1/N.

    Trạng thái được cập nhật ở tần suất thấp (1Hz) qua `update(pps)`; quyết
    định giữ/bỏ mỗi gói ở hot path qua `should_keep(seq)` chỉ tốn 1 phép chia
    dư — không lock, an toàn đọc đồng thời dưới GIL.
    """

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
        """
        Args:
            trigger_pps: pps vượt mức này → coi là đang bị DoS, bật cắt tải.
            clear_pps:   pps xuống dưới mức này → coi là hết DoS (hysteresis,
                         nên đặt < trigger_pps để tránh bật/tắt liên tục).
            target_pps:  mức gói/giây ta CHẤP NHẬN thu khi bị DoS; tỉ lệ mẫu
                         được tính để kéo lưu lượng thu về xấp xỉ mức này.
            max_drop:    trần tỉ lệ bỏ gói (giữ tối thiểu 1/max_drop) để dù
                         flood cực lớn vẫn còn mẫu cho phân loại.
        """
        if not (clear_pps <= trigger_pps):
            raise ValueError("clear_pps phải <= trigger_pps (hysteresis)")
        if not (0.0 <= queue_low_ratio <= queue_high_ratio <= 1.0):
            raise ValueError("cần 0 <= queue_low_ratio <= queue_high_ratio <= 1")
        self.trigger_pps = float(trigger_pps)
        self.clear_pps = float(clear_pps)
        self.target_pps = max(1.0, float(target_pps))
        self.max_drop = max(1, int(max_drop))

        # A1 — backpressure controller (NIC-agnostic)
        self.backpressure = bool(backpressure)
        self.queue_high_ratio = float(queue_high_ratio)
        self.queue_low_ratio = float(queue_low_ratio)
        self._bp_level: int = 1
        self._prev_kernel_drops: int = 0
        self._prev_queue_drops: int = 0
        self._pps_active: bool = False

        # A3 — per-destination surgical shedding (dùng ở Task 2)
        self.victim_share = float(victim_share)
        self.victim_min_pps = float(victim_min_pps)
        self._dst_counts: dict = {}
        self._dst_cap: int = 4096
        self._hot_victim = None
        self._victim_sample_every: int = 1

        # Chung / công khai
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
        # else: giữ nguyên (mid-band hysteresis, tránh dao động)

        # --- pps detector (legacy / mạng nhỏ) ---
        if pps >= self.trigger_pps:
            self._pps_active = True
        elif pps <= self.clear_pps:
            self._pps_active = False
        pps_level = 1
        if self._pps_active and pps > self.target_pps:
            pps_level = min(self.max_drop, max(2, round(pps / self.target_pps)))

        # --- gộp: van cắt tải mạnh hơn thắng ---
        self.sample_every = max(self._bp_level, pps_level)

        # A3 — xác định "đích nóng" (Task 2 hiện thực đầy đủ)
        self._update_hot_victim(pps)

        self.dos_active = (
            self.sample_every > 1
            or self._pps_active
            or self._hot_victim is not None
        )
        return self.dos_active

    def _update_hot_victim(self, pps: float) -> None:
        """Placeholder — Task 2 thay bằng logic per-destination thật."""
        self._hot_victim = None
        self._victim_sample_every = 1
        self._dst_counts = {}

    def should_keep(self, seq: int) -> bool:
        """Quyết định giữ gói (True) hay bỏ (False). Cực rẻ, gọi mỗi gói.

        Args:
            seq: số thứ tự tăng dần của gói (PacketInfo.stt).
        """
        n = self.sample_every
        return n == 1 or (seq % n == 0)

    def stats(self) -> dict:
        """Ảnh chụp trạng thái để log/giám sát."""
        return {
            "dos_active": self.dos_active,
            "sample_every": self.sample_every,
            "last_pps": round(self.last_pps, 1),
            "keep_ratio": round(1.0 / self.sample_every, 4),
        }
