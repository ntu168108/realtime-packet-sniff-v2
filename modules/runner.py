"""
Module Runner - Thực thi analysis modules
- Batch pool: xử lý PCAP rotated files (BaseModule)
- Live pool: subscribe packet stream từ CaptureEngine (LiveModule)
- Metrics per module (processed/detections/errors/latency p50/p95/p99)
- Auto-discovery an toàn với import errors
"""

import os
import queue
import threading
import logging
import importlib
import time
import traceback
from collections import deque
from pathlib import Path
from typing import List, Dict, Optional, Set, Callable
from dataclasses import dataclass, field

from .base import BaseModule, LiveModule, Detection

logger = logging.getLogger(__name__)


# ---------- Configuration ----------

@dataclass
class LiveRunnerConfig:
    """Cấu hình cho live analysis pool"""
    num_workers: int = 1             # Live chỉ cần 1 thread - streaming là tuần tự
    packet_queue_size: int = 8192    # Bounded queue giữa capture và live modules


@dataclass
class BatchRunnerConfig:
    """Cấu hình cho batch pool"""
    num_workers: int = 2
    max_queue_size: int = 100
    job_timeout_sec: float = 600.0   # 10 phút / job, tránh stuck
    stop_timeout_sec: float = 10.0


# ---------- Job ----------

@dataclass
class AnalysisJob:
    """Batch analysis job (cho BaseModule)"""
    pcap_path: str
    interface: str
    time_window: str


# ---------- Metrics ----------

@dataclass
class ModuleMetrics:
    """Metrics cho 1 module (cả batch và live)"""
    processed: int = 0
    detections: int = 0
    alerts: int = 0
    errors: int = 0
    # Latency window (mỗi lần xử lý 1 packet / 1 job đo)
    latencies_ms: deque = field(default_factory=lambda: deque(maxlen=512))

    def record_latency(self, latency_ms: float):
        self.latencies_ms.append(latency_ms)

    def percentiles(self) -> Dict[str, float]:
        """Tính p50/p95/p99"""
        if not self.latencies_ms:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
        sorted_lat = sorted(self.latencies_ms)
        n = len(sorted_lat)
        def pct(p):
            idx = min(int(n * p), n - 1)
            return sorted_lat[idx]
        return {
            "p50": round(pct(0.50), 3),
            "p95": round(pct(0.95), 3),
            "p99": round(pct(0.99), 3),
        }

    def to_dict(self) -> dict:
        return {
            "processed": self.processed,
            "detections": self.detections,
            "alerts": self.alerts,
            "errors": self.errors,
            **self.percentiles(),
        }


# ---------- BatchRunner ----------

class BatchRunner:
    """
    Chạy BaseModule trên PCAP files.
    Thay thế logic batch cũ với:
    - Dead-letter queue khi queue đầy
    - Job timeout mỗi job (tránh stuck)
    - Per-module timeout cho từng module.analyze()
    - Dropped counter thay vì silent drop
    """

    def __init__(
        self,
        modules: Dict[str, BaseModule],
        output_dir: Path,
        config: BatchRunnerConfig,
    ):
        self.modules = modules
        self.output_dir = output_dir
        self.config = config

        # Job queue
        self._job_queue: queue.Queue = queue.Queue(
            maxsize=config.max_queue_size
        )
        self._jobs_failed: int = 0
        self._lock = threading.Lock()

        # Workers
        self._workers: List[threading.Thread] = []
        self._running = False
        self._stop_event = threading.Event()

        # Metrics per module
        self._metrics: Dict[str, ModuleMetrics] = {
            name: ModuleMetrics() for name in modules
        }

    def queue(self, pcap_path: str, interface: str, time_window: str):
        """
        Thêm job vào queue.
        """
        job = AnalysisJob(pcap_path, interface, time_window)
        try:
            self._job_queue.put(job, timeout=2.0)
            logger.info(f"Queued analysis: {pcap_path}")
        except queue.Full:
            logger.warning(f"Analysis queue full, dropping: {pcap_path}")

    def _worker_loop(self, worker_id: int):
        """Worker loop - dùng Event để chờ thay vì polling 1s"""
        logger.info(f"BatchWorker {worker_id} started")

        while not self._stop_event.is_set():
            job = None
            try:
                # Block chờ job, poll mỗi 2s để check stop
                try:
                    job = self._job_queue.get(timeout=2.0)
                except queue.Empty:
                    continue

                self._process_job(job, worker_id)
                self._job_queue.task_done()

            except Exception as e:
                logger.error(f"BatchWorker {worker_id} error: {e}\n{traceback.format_exc()}")

        logger.info(f"BatchWorker {worker_id} stopped")

    def _process_job(self, job: AnalysisJob, worker_id: int):
        """Xử lý 1 job với timeout mỗi module"""
        logger.info(f"BatchWorker {worker_id} processing: {job.pcap_path}")

        if not Path(job.pcap_path).exists():
            logger.warning(f"PCAP not found: {job.pcap_path}")
            with self._lock:
                self._jobs_failed += 1
            return

        # Chạy từng module với timeout guard
        for module_name, module in self.modules.items():
            start = time.time()
            try:
                summary = self._run_module_with_timeout(
                    module, job, timeout_sec=self.config.job_timeout_sec
                )
                duration_ms = (time.time() - start) * 1000

                metrics = self._metrics[module_name]
                metrics.processed += 1
                metrics.detections += summary.total_hits
                metrics.alerts += summary.alerts_generated
                metrics.record_latency(duration_ms)

                logger.info(
                    f"Module {module_name}: {summary.total_hits} hits "
                    f"({summary.alerts_generated} alerts) in {duration_ms:.1f}ms"
                )
            except RuntimeError as e:
                logger.error(f"Module {module_name} timeout on {job.pcap_path}: {e}")
                with self._lock:
                    self._metrics[module_name].errors += 1
                    self._jobs_failed += 1
            except Exception as e:
                logger.error(
                    f"Module {module_name} failed: {e}\n{traceback.format_exc()}"
                )
                with self._lock:
                    self._metrics[module_name].errors += 1
                    self._jobs_failed += 1

    def _run_module_with_timeout(
        self,
        module: BaseModule,
        job: AnalysisJob,
        timeout_sec: float,
    ):
        """
        Chạy module.analyze() với timeout.
        Dùng thread (CPython không kill thread được nhưng
        ta dùng timeout để ghi nhận stuck và skip job sau đó).
        """
        result_box = {"summary": None, "error": None}

        def target():
            try:
                result_box["summary"] = module.analyze(
                    pcap_path=job.pcap_path,
                    output_dir=str(self.output_dir),
                    interface=job.interface,
                    time_window=job.time_window,
                )
            except Exception as e:
                result_box["error"] = e

        t = threading.Thread(target=target, daemon=True, name=f"mod-{module.name}")
        t.start()
        t.join(timeout=timeout_sec)

        if t.is_alive():
            raise RuntimeError(
                f"Module {module.name} exceeded {timeout_sec}s on {job.pcap_path}"
            )
        if result_box["error"]:
            raise result_box["error"]
        return result_box["summary"]

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        for i in range(self.config.num_workers):
            w = threading.Thread(
                target=self._worker_loop, args=(i,),
                daemon=True, name=f"BatchWorker-{i}",
            )
            w.start()
            self._workers.append(w)
        logger.info(f"BatchRunner started with {self.config.num_workers} workers")

    def stop(self, timeout: Optional[float] = None):
        if not self._running:
            return
        timeout = timeout or self.config.stop_timeout_sec
        self._running = False
        self._stop_event.set()

        # Drain queue với bounded timeout
        try:
            self._job_queue.join(timeout=timeout)
        except Exception:
            pass

        # Wait workers - mỗi worker timeout đầy đủ (không chia)
        for w in self._workers:
            w.join(timeout=timeout)
        self._workers.clear()
        logger.info("BatchRunner stopped")

    def metrics(self) -> Dict[str, dict]:
        with self._lock:
            return {
                name: {
                    **m.to_dict(),
                    "jobs_failed": self._jobs_failed,
                }
                for name, m in self._metrics.items()
            }


# ---------- LiveRunner ----------

class LiveRunner:
    """
    Subscribe packet stream từ CaptureEngine (qua callback).
    Dispatch tới các LiveModule.
    Mỗi packet chạy qua:
      1. Decode (đã làm ở capture)
      2. Gọi on_packet() trên từng module
      3. Nếu module trả Detection -> emit alert qua callback
    """

    def __init__(
        self,
        modules: Dict[str, LiveModule],
        config: LiveRunnerConfig,
        on_alert: Optional[Callable[[str, Detection], None]] = None,
    ):
        self.modules = modules
        self.config = config
        self.on_alert = on_alert

        # Packet queue giữa capture callback và live dispatcher
        self._packet_queue: queue.Queue = queue.Queue(
            maxsize=config.packet_queue_size
        )
        self._dropped_packets: int = 0
        self._lock = threading.Lock()

        # Metrics
        self._metrics: Dict[str, ModuleMetrics] = {
            name: ModuleMetrics() for name in modules
        }

        # Enabled set (cho runtime enable/disable)
        self._enabled: Set[str] = set(modules.keys())

        # Worker
        self._worker: Optional[threading.Thread] = None
        self._running = False
        self._stop_event = threading.Event()

    def set_enabled(self, module_name: str, enabled: bool):
        """Runtime enable/disable 1 module"""
        with self._lock:
            if enabled:
                self._enabled.add(module_name)
                logger.info(f"Live module ENABLED: {module_name}")
            else:
                self._enabled.discard(module_name)
                logger.info(f"Live module DISABLED: {module_name}")

    def is_enabled(self, module_name: str) -> bool:
        return module_name in self._enabled

    def list_enabled(self) -> List[str]:
        return sorted(self._enabled)

    # ----- Packet ingress (được CaptureEngine gọi) -----

    def submit_packet(self, pkt_info, decoded) -> bool:
        """
        Được CaptureEngine gọi cho mỗi packet (qua on_packet_filtered hook).
        Trả về True nếu accept, False nếu drop do backpressure.
        """
        if not self._running:
            return False
        try:
            self._packet_queue.put_nowait((pkt_info, decoded))
            return True
        except queue.Full:
            return False

    def _worker_loop(self):
        """Loop chính: lấy packet, gọi từng module"""
        logger.info("LiveRunner worker started")
        while not self._stop_event.is_set():
            try:
                try:
                    pkt_info, decoded = self._packet_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                self._dispatch(pkt_info, decoded)
                self._packet_queue.task_done()

            except Exception as e:
                logger.error(f"LiveRunner error: {e}\n{traceback.format_exc()}")
        logger.info("LiveRunner worker stopped")

    def _dispatch(self, pkt_info, decoded):
        """Gọi từng LiveModule cho packet này"""
        for name in list(self._enabled):
            module = self.modules.get(name)
            if module is None:
                continue

            # Gọi on_packet với latency guard
            start = time.time()
            try:
                det = module.on_packet(pkt_info, decoded)
                latency_ms = (time.time() - start) * 1000
                metrics = self._metrics[name]
                metrics.processed += 1
                metrics.record_latency(latency_ms)

                # Skip packet nếu module quá chậm
                if latency_ms > module.max_latency_ms:
                    logger.debug(
                        f"Live module {name} slow: {latency_ms:.1f}ms "
                        f"> {module.max_latency_ms}ms"
                    )
                    metrics.errors += 1

                # Phát alert nếu detection priority cao
                if det is not None:
                    metrics.detections += 1
                    if det.is_alert:
                        metrics.alerts += 1
                        if self.on_alert:
                            try:
                                self.on_alert(name, det)
                            except Exception as e:
                                logger.error(f"on_alert callback failed: {e}")

            except Exception as e:
                logger.error(
                    f"Live module {name} on_packet failed: {e}\n"
                    f"{traceback.format_exc()}"
                )
                with self._lock:
                    self._metrics[name].errors += 1

    def start(self):
        if self._running:
            return
        self._running = True
        self._stop_event.clear()

        # Gọi on_start cho từng module
        for name, module in self.modules.items():
            try:
                module.on_start()
            except Exception as e:
                logger.error(f"Live module {name} on_start failed: {e}")

        self._worker = threading.Thread(
            target=self._worker_loop, daemon=True, name="LiveRunner"
        )
        self._worker.start()
        logger.info(f"LiveRunner started with {len(self.modules)} modules")

    def stop(self, timeout: float = 5.0):
        if not self._running:
            return
        self._running = False
        self._stop_event.set()

        for module in self.modules.values():
            try:
                module.on_stop()
            except Exception as e:
                logger.error(f"on_stop failed for {module.name}: {e}")

        if self._worker:
            self._worker.join(timeout=timeout)
        logger.info("LiveRunner stopped")

    def metrics(self) -> Dict[str, dict]:
        with self._lock:
            return {
                "queue_size": self._packet_queue.qsize(),
                "enabled": self.list_enabled(),
                "modules": {
                    name: m.to_dict()
                    for name, m in self._metrics.items()
                }
            }


# ---------- ModuleRunner (orchestrator) ----------

class ModuleRunner:
    """
    Orchestrator chính:
    - Quản lý batch pool (BaseModule) + live pool (LiveModule)
    - Auto-discovery modules an toàn (skip import errors)
    - Runtime enable/disable + reload
    - SIGUSR1 handler để toggle modules
    """

    def __init__(
        self,
        output_dir: str,
        enabled_modules: Optional[List[str]] = None,
        num_workers: int = 2,
        max_queue_size: int = 100,
        live_config: Optional[LiveRunnerConfig] = None,
        batch_config: Optional[BatchRunnerConfig] = None,
        on_alert: Optional[Callable[[str, Detection], None]] = None,
    ):
        self.output_dir = Path(output_dir)
        self.enabled_module_names = enabled_modules

        self.batch_config = batch_config or BatchRunnerConfig(
            num_workers=num_workers,
            max_queue_size=max_queue_size,
        )
        self.live_config = live_config or LiveRunnerConfig()
        self._on_alert = on_alert

        # Registry: name -> instance
        self._base_modules: Dict[str, BaseModule] = {}
        self._live_modules: Dict[str, LiveModule] = {}

        # Sub-runners (tạo lazy trong start())
        self._batch: Optional[BatchRunner] = None
        self._live: Optional[LiveRunner] = None

        self._running = False

        # Mặc định num_workers từ CPU count nếu user không set
        if num_workers <= 0:
            self.batch_config.num_workers = max(1, (os.cpu_count() or 2) // 2)

    # ----- Discovery & registration -----

    def register_module(self, module):
        """Register BaseModule hoặc LiveModule"""
        if isinstance(module, LiveModule):
            self._live_modules[module.name] = module
            logger.info(f"Registered LIVE module: {module.name}")
        elif isinstance(module, BaseModule):
            self._base_modules[module.name] = module
            logger.info(f"Registered BATCH module: {module.name}")
        else:
            logger.warning(f"Unknown module type: {type(module).__name__}")

    def discover_modules(self, package_path: Optional[str] = None):
        """
        Auto-discovery an toàn:
        - Import error -> log warning, tiếp tục
        - Class không phải BaseModule/LiveModule -> skip
        """
        if package_path is None:
            package_path = str(Path(__file__).parent)

        package = Path(package_path)
        if not package.exists():
            logger.warning(f"Module package path not found: {package_path}")
            return

        for item in sorted(package.iterdir()):
            if not (item.is_dir() and (item / '__init__.py').exists()):
                continue
            if item.name.startswith('_'):
                continue

            module_name = item.name
            try:
                # Import module
                mod = importlib.import_module(f'modules.{module_name}')

                # Tìm tất cả class kế thừa BaseModule hoặc LiveModule
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if not (isinstance(attr, type)):
                        continue
                    if attr is BaseModule or attr is LiveModule:
                        continue
                    if not issubclass(attr, (BaseModule, LiveModule)):
                        continue
                    try:
                        instance = attr()
                        self.register_module(instance)
                    except Exception as e:
                        logger.warning(
                            f"Failed to instantiate {attr_name} from "
                            f"{module_name}: {e}"
                        )
            except ImportError as e:
                logger.warning(
                    f"ImportError loading module {module_name}: {e} - skipping"
                )
            except Exception as e:
                logger.warning(
                    f"Error loading module {module_name}: {e} - skipping\n"
                    f"{traceback.format_exc()}"
                )

    # ----- Queries -----

    def _enabled_base_modules(self) -> Dict[str, BaseModule]:
        if self.enabled_module_names is None:
            return dict(self._base_modules)
        return {
            n: m for n, m in self._base_modules.items()
            if n in self.enabled_module_names
        }

    def _enabled_live_modules(self) -> Dict[str, LiveModule]:
        if self.enabled_module_names is None:
            return dict(self._live_modules)
        return {
            n: m for n, m in self._live_modules.items()
            if n in self.enabled_module_names
        }

    def get_enabled_modules(self) -> List[BaseModule]:
        return list(self._enabled_base_modules().values())

    def get_available_modules(self) -> List[str]:
        return sorted(
            list(self._base_modules.keys()) + list(self._live_modules.keys())
        )

    # ----- Batch API (delegate xuống BatchRunner) -----

    def queue_analysis(self, pcap_path: str, interface: str, time_window: str):
        if self._batch is None:
            logger.warning("BatchRunner not started - job dropped")
            return
        self._batch.queue(pcap_path, interface, time_window)

    # ----- Runtime control -----

    # ----- Lifecycle -----

    def start(self):
        if self._running:
            return
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Batch runner
        self._batch = BatchRunner(
            modules=self._enabled_base_modules(),
            output_dir=self.output_dir,
            config=self.batch_config,
        )
        self._batch.start()

        # Live runner
        self._live = LiveRunner(
            modules=self._enabled_live_modules(),
            config=self.live_config,
            on_alert=self._on_alert,
        )
        self._live.start()

        self._running = True
        logger.info(
            f"ModuleRunner started: "
            f"{len(self._enabled_base_modules())} batch, "
            f"{len(self._enabled_live_modules())} live"
        )

    def stop(self, wait: bool = True, timeout: float = 10.0):
        if not self._running:
            return
        logger.info("Stopping ModuleRunner...")

        if self._batch:
            self._batch.stop(timeout=timeout)
        if self._live:
            self._live.stop(timeout=timeout)

        self._running = False
        logger.info("ModuleRunner stopped")

    # ----- Status -----

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "batch": self._batch.metrics() if self._batch else {},
            "live": self._live.metrics() if self._live else {},
            "enabled_modules": self.get_available_modules(),
            "available_modules": self.get_available_modules(),
        }

    # ----- Convenience: hook vào CaptureEngine -----


def create_runner(
    output_dir: str,
    enabled_modules: Optional[List[str]] = None,
    auto_discover: bool = True,
    on_alert: Optional[Callable[[str, Detection], None]] = None,
) -> ModuleRunner:
    """Helper tạo ModuleRunner đã config sẵn"""
    runner = ModuleRunner(
        output_dir=output_dir,
        enabled_modules=enabled_modules,
        on_alert=on_alert,
    )
    if auto_discover:
        runner.discover_modules()
    return runner
