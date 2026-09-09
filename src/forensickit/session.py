from __future__ import annotations

"""Threaded analysis-session controller shared by terminal front ends.

The forensic engine remains synchronous and deterministic.  This adapter runs
one engine instance on a worker thread, exposes bounded progress events, and
provides cooperative cancellation/retry without letting a UI mutate evidence.
"""

from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Callable, Protocol

from .config import ForensicKitConfig
from .engine import AnalysisEngine
from .models import AnalysisMode, AnalysisResult, utc_now


class SessionStatus(str, Enum):
    WAITING = "waiting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    evidence: tuple[Path, ...]
    workspace_base: Path
    mode: AnalysisMode = AnalysisMode.TRIAGE
    execute: bool | None = None
    config: ForensicKitConfig | None = None

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("at least one evidence path is required")


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    status: SessionStatus
    started_at: str | None
    ended_at: str | None
    workspace: str | None
    error: str | None
    attempt: int
    event_count: int


class _Engine(Protocol):
    def analyze_many(
        self,
        evidence_items: tuple[Path, ...],
        workspace_base: Path,
        *,
        mode: AnalysisMode,
        execute: bool | None,
    ) -> AnalysisResult: ...


EngineFactory = Callable[
    [ForensicKitConfig, Callable[[dict[str, object]], None], Event],
    _Engine,
]


def _default_engine_factory(
    config: ForensicKitConfig,
    progress: Callable[[dict[str, object]], None],
    cancel_event: Event,
) -> AnalysisEngine:
    return AnalysisEngine(config, progress=progress, cancel_event=cancel_event)


class AnalysisSession:
    """Own one asynchronous analysis attempt at a time."""

    def __init__(
        self,
        *,
        engine_factory: EngineFactory = _default_engine_factory,
        max_progress_events: int = 10_000,
    ) -> None:
        if max_progress_events <= 0:
            raise ValueError("max_progress_events must be positive")
        self._engine_factory = engine_factory
        self._events: deque[dict[str, object]] = deque(maxlen=max_progress_events)
        self._lock = Lock()
        self._cancel_event = Event()
        self._thread: Thread | None = None
        self._request: AnalysisRequest | None = None
        self._result: AnalysisResult | None = None
        self._status = SessionStatus.WAITING
        self._started_at: str | None = None
        self._ended_at: str | None = None
        self._workspace: str | None = None
        self._error: str | None = None
        self._attempt = 0
        self._event_count = 0

    def start(self, request: AnalysisRequest) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("an analysis session is already running")
            self._request = request
            self._result = None
            self._status = SessionStatus.RUNNING
            self._started_at = utc_now()
            self._ended_at = None
            self._workspace = None
            self._error = None
            self._attempt += 1
            self._cancel_event = Event()
            self._events.clear()
            self._event_count = 0
            attempt = self._attempt
            self._append_event_locked({
                "event": "session_started",
                "status": SessionStatus.RUNNING.value,
                "attempt": attempt,
                "timestamp": self._started_at,
            })
            self._thread = Thread(
                target=self._run,
                args=(request, attempt, self._cancel_event),
                name=f"forensickit-analysis-{attempt}",
                daemon=True,
            )
            self._thread.start()

    def retry(self) -> None:
        with self._lock:
            request = self._request
            running = self._thread is not None and self._thread.is_alive()
        if running:
            raise RuntimeError("cannot retry while analysis is running")
        if request is None:
            raise RuntimeError("there is no previous analysis request to retry")
        self.start(request)

    def cancel(self) -> bool:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                return False
            self._cancel_event.set()
            self._append_event_locked({
                "event": "cancellation_requested",
                "status": SessionStatus.RUNNING.value,
                "attempt": self._attempt,
                "timestamp": utc_now(),
            })
            return True

    def wait(self, timeout: float | None = None) -> bool:
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def snapshot(self) -> SessionSnapshot:
        with self._lock:
            return SessionSnapshot(
                status=self._status,
                started_at=self._started_at,
                ended_at=self._ended_at,
                workspace=self._workspace,
                error=self._error,
                attempt=self._attempt,
                event_count=self._event_count,
            )

    @property
    def result(self) -> AnalysisResult | None:
        with self._lock:
            return self._result

    def drain_events(self, maximum: int = 1_000) -> list[dict[str, object]]:
        if maximum <= 0:
            return []
        with self._lock:
            output = [self._events.popleft() for _ in range(min(maximum, len(self._events)))]
        return output

    def _progress(self, event: dict[str, object]) -> None:
        copied = dict(event)
        copied.setdefault("timestamp", utc_now())
        with self._lock:
            if copied.get("event") == "case_created" and isinstance(copied.get("workspace"), str):
                self._workspace = str(copied["workspace"])
            self._append_event_locked(copied)

    def _append_event_locked(self, event: dict[str, object]) -> None:
        self._events.append(event)
        self._event_count += 1

    def _run(self, request: AnalysisRequest, attempt: int, cancel_event: Event) -> None:
        try:
            engine = self._engine_factory(
                request.config or ForensicKitConfig(), self._progress, cancel_event,
            )
            result = engine.analyze_many(
                request.evidence,
                request.workspace_base,
                mode=request.mode,
                execute=request.execute,
            )
        except BaseException as exc:
            # KeyboardInterrupt/SystemExit raised inside the worker must not
            # silently strand the UI in a running state.
            ended_at = utc_now()
            with self._lock:
                if attempt != self._attempt:
                    return
                canceled = cancel_event.is_set()
                self._status = SessionStatus.CANCELED if canceled else SessionStatus.FAILED
                self._error = None if canceled else f"{type(exc).__name__}: {exc}"[:4_000]
                self._ended_at = ended_at
                self._append_event_locked({
                    "event": "session_finished",
                    "status": self._status.value,
                    "error": self._error,
                    "attempt": attempt,
                    "timestamp": ended_at,
                })
            return
        ended_at = utc_now()
        with self._lock:
            if attempt != self._attempt:
                return
            self._result = result
            self._workspace = result.case.workspace
            self._status = SessionStatus.CANCELED if cancel_event.is_set() else SessionStatus.COMPLETED
            self._ended_at = ended_at
            self._append_event_locked({
                "event": "session_finished",
                "status": self._status.value,
                "workspace": self._workspace,
                "attempt": attempt,
                "timestamp": ended_at,
            })


__all__ = [
    "AnalysisRequest", "AnalysisSession", "SessionSnapshot", "SessionStatus",
]
