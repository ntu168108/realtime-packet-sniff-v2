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
        self.trigger_pps = float(trigger_pps)
        self.clear_pps = float(clear_pps)
        self.target_pps = max(1.0, float(target_pps))
        self.max_drop = max(1, int(max_drop))

        self.sample_every: int = 1     # 1 = giữ mọi gói; N = chỉ giữ 1/N
        self.dos_active: bool = False
        self.last_pps: float = 0.0

    def update(self, pps: float) -> bool:
        """Cập nhật trạng thái từ pps hiện tại. Gọi ~1 lần/giây.

        Returns:
            True nếu đang trong chế độ DoS (đang cắt tải), ngược lại False.
        """
        self.last_pps = pps
        if pps >= self.trigger_pps:
            self.dos_active = True
        elif pps <= self.clear_pps:
            self.dos_active = False

        if self.dos_active and pps > self.target_pps:
            # Ví dụ pps=200k, target=10k → sample_every=20 → giữ 1/20 (~10k pps).
            self.sample_every = min(self.max_drop,
                                    max(2, round(pps / self.target_pps)))
        else:
            self.sample_every = 1
        return self.dos_active

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
