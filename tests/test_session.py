from __future__ import annotations

from pathlib import Path
from threading import Event

from forensickit.config import ForensicKitConfig
from forensickit.engine import AnalysisEngine
from forensickit.models import AnalysisMode
from forensickit.session import AnalysisRequest, AnalysisSession, SessionStatus


def test_analysis_session_streams_real_progress_and_result(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"prefix FLAG{SESSION_PROGRESS} suffix")
    session = AnalysisSession()

    session.start(AnalysisRequest(
        evidence=(evidence,), workspace_base=tmp_path / "cases",
        mode=AnalysisMode.TRIAGE, execute=False,
    ))

    assert session.wait(20)
    snapshot = session.snapshot()
    events = session.drain_events()
    assert snapshot.status is SessionStatus.COMPLETED
    assert snapshot.workspace is not None
    assert session.result is not None
    assert any(item.value == "FLAG{SESSION_PROGRESS}" for item in session.result.flags)
    assert [item["event"] for item in events][0] == "session_started"
    assert any(item["event"] == "case_created" for item in events)
    assert any(item["event"] == "artifact_started" for item in events)
    assert events[-1]["event"] == "session_finished"


def test_analysis_session_cancel_is_cooperative_and_terminal(tmp_path: Path) -> None:
    entered = Event()

    class BlockingEngine:
        def __init__(self, cancel_event: Event) -> None:
            self.cancel_event = cancel_event

        def analyze_many(self, evidence_items, workspace_base, *, mode, execute):
            entered.set()
            assert self.cancel_event.wait(5)
            raise RuntimeError("worker stopped after cancellation")

    def factory(config, progress, cancel_event):
        return BlockingEngine(cancel_event)

    evidence = tmp_path / "cancel.bin"
    evidence.write_bytes(b"data")
    session = AnalysisSession(engine_factory=factory)
    session.start(AnalysisRequest((evidence,), tmp_path / "cases"))
    assert entered.wait(2)
    assert session.cancel() is True
    assert session.wait(5)
    assert session.snapshot().status is SessionStatus.CANCELED
    assert session.snapshot().error is None
    assert any(item["event"] == "cancellation_requested" for item in session.drain_events())


def test_failed_analysis_session_can_retry_same_request(tmp_path: Path) -> None:
    attempts = 0

    class FailingEngine:
        def analyze_many(self, evidence_items, workspace_base, *, mode, execute):
            raise ValueError("synthetic first-attempt failure")

    def factory(config: ForensicKitConfig, progress, cancel_event):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return FailingEngine()
        return AnalysisEngine(config, progress=progress, cancel_event=cancel_event)

    evidence = tmp_path / "retry.bin"
    evidence.write_bytes(b"FLAG{RETRY_WORKED}")
    session = AnalysisSession(engine_factory=factory)
    session.start(AnalysisRequest((evidence,), tmp_path / "cases", execute=False))
    assert session.wait(5)
    assert session.snapshot().status is SessionStatus.FAILED
    assert "synthetic first-attempt failure" in str(session.snapshot().error)

    session.retry()
    assert session.wait(20)
    assert session.snapshot().status is SessionStatus.COMPLETED
    assert session.snapshot().attempt == 2
    assert session.result is not None
    assert any(item.value == "FLAG{RETRY_WORKED}" for item in session.result.flags)
