"""
Lock-free-ish ring buffer cho packet capture
- Sử dụng collections.deque với maxlen (ring buffer C-level)
- Thread-safe put_nowait/get_nowait nhờ GIL
- Drop-oldest strategy khi đầy
- Drop tracking
- Batch get cho UI consumers

NOTE: Python GIL đảm bảo các thao tác append/popleft của deque là atomic ở C-level,
do đó đây là "lock-free" trong thực tế dù deque không hoàn toàn SPSC.
"""

import collections
import threading
import time
from typing import List, Optional, Deque, Any


class RingBuffer:
    """
    Ring buffer thread-safe với drop-oldest semantics.
    Producer (capture thread) gọi put_nowait() liên tục.
    Consumer (UI) gọi get_batch() hoặc get_nowait().

    Dùng collections.deque(maxlen=N) làm backing store.
    - append() và popleft() ở deque là atomic trong CPython (GIL)
    - Khi đầy, append() tự động evict phần tử cũ nhất ở C-level
    - Không cần lock cho hot path put/get

    Trade-off: thêm một counter dropped sử dụng threading.Lock nhẹ
    (rất ít tranh chấp vì chỉ increment 1 biến).
    """

    __slots__ = (
        "_maxlen",
        "_deque",
        "_lock",
        "_dropped",
        "_put_total",
        "_get_total",
    )

    def __init__(self, maxlen: int = 65536):
        """
        Args:
            maxlen: Số phần tử tối đa (khi đầy sẽ evict cũ nhất)
        """
        if maxlen <= 0:
            raise ValueError("maxlen must be > 0")
        self._maxlen = maxlen
        self._deque: Deque[Any] = collections.deque(maxlen=maxlen)
        # Lock nhẹ chỉ để bảo vệ các counter; deque ops không cần
        self._lock = threading.Lock()
        self._dropped: int = 0
        self._put_total: int = 0
        self._get_total: int = 0

    def put_nowait(self, item: Any) -> bool:
        """
        Đẩy item vào buffer. Nếu đầy thì evict cũ nhất.
        Returns True nếu thành công (không tính evict là fail).

        Thread-safe: append() ở deque là atomic dưới GIL.
        Counter increment dưới lock nhẹ - contention thấp.
        """
        dq = self._deque
        # Trước khi append kiểm tra để biết có drop hay không
        was_full = len(dq) == self._maxlen
        dq.append(item)
        with self._lock:
            self._put_total += 1
            if was_full:
                self._dropped += 1
        return True

    def get_nowait(self) -> Optional[Any]:
        """
        Lấy 1 phần tử. Trả về None nếu rỗng.

        Thread-safe dưới GIL.
        """
        try:
            item = self._deque.popleft()
        except IndexError:
            return None
        with self._lock:
            self._get_total += 1
        return item

    def get_batch(self, max_items: int = 64, timeout: float = 0.0) -> List[Any]:
        """
        Lấy nhiều phần tử cùng lúc - tối ưu cho UI consumer.
        Nếu timeout > 0, block cho đến khi có ít nhất 1 item hoặc timeout.

        Returns list (có thể rỗng).
        """
        dq = self._deque
        if timeout > 0:
            # Polling wait - tránh condvar overhead
            deadline = time.monotonic() + timeout
            while not dq:
                if time.monotonic() >= deadline:
                    return []
                time.sleep(0.001)  # 1ms backoff

        batch: List[Any] = []
        # popleft trong loop là atomic ở mỗi step dưới GIL
        for _ in range(max_items):
            try:
                item = dq.popleft()
            except IndexError:
                break
            batch.append(item)

        if batch:
            with self._lock:
                self._get_total += len(batch)
        return batch

    def clear(self) -> int:
        """Xoá toàn bộ buffer. Trả về số phần tử đã xoá."""
        dq = self._deque
        count = len(dq)
        dq.clear()
        return count

    def qsize(self) -> int:
        """Số phần tử hiện tại (approx - dùng cho monitoring)."""
        return len(self._deque)

    def maxlen(self) -> int:
        """Dung lượng tối đa."""
        return self._maxlen

    @property
    def dropped(self) -> int:
        """Tổng số drop từ lúc tạo buffer."""
        with self._lock:
            return self._dropped

    @property
    def put_total(self) -> int:
        """Tổng số put từ lúc tạo buffer."""
        with self._lock:
            return self._put_total

    @property
    def get_total(self) -> int:
        """Tổng số get từ lúc tạo buffer."""
        with self._lock:
            return self._get_total

    def __len__(self) -> int:
        return len(self._deque)

    def __bool__(self) -> bool:
        return bool(self._deque)


class BoundedRingBuffer(RingBuffer):
    """
    Ring buffer có TRẦN CỨNG với semantics *drop-newest* (back-pressure).

    Khác `RingBuffer` (drop-oldest, đè phần tử cũ nhất khi đầy):
    khi đã đầy, `BoundedRingBuffer` TỪ CHỐI item mới — `put_nowait()` trả về
    False và tăng bộ đếm `dropped`, KHÔNG đè dữ liệu cũ.

    Dùng khi ta muốn báo hiệu áp lực ngược cho producer (ví dụ: đang bị DoS
    flood → cắt tải ngay ở đầu vào) thay vì âm thầm mất gói cũ. Vẫn atomic
    dưới GIL ở hot path; lock chỉ bảo vệ counter.

    NOTE (lịch sử): `core.capture` import class này từ trước nhưng nó chưa
    từng được định nghĩa → mọi lần nạp `core.capture` sẽ ImportError. Định
    nghĩa ở đây vừa vá lỗi import vừa cung cấp chiến lược drop-newest tùy chọn.
    """

    def put_nowait(self, item: Any) -> bool:
        dq = self._deque
        if len(dq) >= self._maxlen:
            # Đầy → từ chối item mới (drop-newest), đếm drop.
            with self._lock:
                self._put_total += 1
                self._dropped += 1
            return False
        dq.append(item)
        with self._lock:
            self._put_total += 1
        return True
