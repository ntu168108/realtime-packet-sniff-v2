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

import threading


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
        # FIX (race #2): khoá bảo vệ _dst_counts giữa luồng bắt gói (_note_dst)
        # và luồng giám sát 1Hz (_update_hot_victim). Bản vá trước chỉ hoán đổi
        # tham chiếu và cho rằng thao tác nguyên tử dưới GIL là đủ — KHÔNG đủ,
        # xem ghi chú ở _note_dst(). Vùng khoá được giữ CỰC NGẮN (chỉ 1 phép
        # tăng counter, hoặc 1 phép hoán đổi) nên không nằm trên đường đi tốn
        # kém; vòng lặp tổng hợp chạy NGOÀI khoá.
        self._counts_lock = threading.Lock()
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

    def _note_dst(self, dst) -> None:
        """Đếm 1 gói theo đích cho cửa sổ 1 giây. Chặn phình bộ nhớ khi bị flood
        spoofed-DESTINATION bằng trần số key (bỏ qua key mới khi đầy — các đích
        'nóng' đã có mặt vẫn được đếm tiếp).

        FIX (race #2): phải đọc self._dst_counts và ghi vào nó TRONG cùng một
        vùng khoá. Bản vá trước để nguyên đoạn này không khoá, dựa vào lập luận
        "hoán đổi tham chiếu ở _update_hot_victim là nguyên tử dưới GIL nên
        luồng bắt gói sẽ ghi vào dict mới". Lập luận đó SAI: luồng này copy tham
        chiếu vào biến local TRƯỚC khi ghi, nên nếu monitor hoán đổi đúng giữa
        hai bước thì phép ghi vẫn rơi vào dict CŨ — chính dict monitor đang lặp
        → `RuntimeError: dictionary changed size during iteration`. Cửa sổ race
        này hẹp và phụ thuộc bytecode: CI tái tạo được trên Python 3.10 nhưng
        KHÔNG trên 3.12 (xem test_no_race_between_capture_thread_and_monitor_thread).
        """
        with self._counts_lock:
            c = self._dst_counts
            if dst in c:
                c[dst] += 1
            elif len(c) < self._dst_cap:
                c[dst] = 1
            # else: counter đầy -> bỏ qua đích mới (đủ để nhận diện đích nóng đã thấy)

    def _update_hot_victim(self, pps: float) -> None:
        """Từ cửa sổ đếm 1 giây, xác định 'đích nóng' (victim) nếu lưu lượng dồn
        tập trung: đích chiếm >= victim_share tổng gói VÀ vượt victim_min_pps.
        Đặt tỉ lệ cắt tải riêng cho victim để kéo tốc độ tới nó về ~target_pps.
        Reset cửa sổ đếm sau mỗi lần gọi."""
        self._hot_victim = None
        self._victim_sample_every = 1
        # Hoán đổi dict RA khỏi self._dst_counts rồi lặp trên bản đã tách, thay
        # vì lặp trực tiếp trên self._dst_counts (đang bị luồng bắt gói mutate)
        # — lặp trực tiếp ném `RuntimeError: dictionary changed size during
        # iteration`.
        #
        # FIX (race #2): phép hoán đổi phải nằm TRONG khoá. Chỉ hoán đổi tham
        # chiếu (như bản vá trước) là KHÔNG đủ: _note_dst() copy tham chiếu vào
        # biến local trước khi ghi, nên một writer đã vào giữa hai bước đó sẽ ghi
        # vào dict cũ trong lúc ta đang lặp nó. Khoá ở đây đảm bảo: khi lệnh
        # dưới trả về, mọi writer hoặc đã ghi xong (dưới khoá) hoặc sẽ lấy khoá
        # SAU và nhìn thấy dict mới — không ai còn giữ đường ghi vào `counts`.
        # Nhờ vậy vòng lặp tổng hợp bên dưới chạy NGOÀI khoá vẫn an toàn, giữ
        # thời gian giữ khoá ở mức tối thiểu.
        with self._counts_lock:
            counts, self._dst_counts = self._dst_counts, {}
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

    def should_keep(self, seq: int, dst=None) -> bool:
        """Quyết định giữ (True) / bỏ (False) một gói. Cực rẻ, gọi mỗi gói.

        Args:
            seq: số thứ tự tăng dần của gói (PacketInfo.stt).
            dst: khoá đích (bytes IPv4) để cắt tải CÓ CHỌN LỌC, hoặc None để dùng
                 tỉ lệ cắt tải toàn cục. Producer chỉ truyền dst khi `dos_active`
                 (fast path bình thường: dst=None, không tốn gì).
        """
        if dst is not None:
            self._note_dst(dst)
            if self._hot_victim is not None:
                # Chỉ cắt tải luồng đổ vào ĐÍCH NÓNG; đích khác giữ nguyên 1/1.
                n = self._victim_sample_every if dst == self._hot_victim else 1
                return n == 1 or (seq % n == 0)
        n = self.sample_every
        return n == 1 or (seq % n == 0)

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
