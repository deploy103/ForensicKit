from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


def new_id() -> str:
    return uuid4().hex


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class AnalysisMode(str, Enum):
    TRIAGE = "triage"
    AUTO = "auto"
    DEEP = "deep"
    PLAN = "plan"


class ToolRunStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


@dataclass(slots=True)
class Case:
    id: str
    name: str
    created_at: str
    workspace: str
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Classification:
    artifact_type: str
    confidence: float
    reason: str
    source: str = "classification_engine"


@dataclass(slots=True)
class Artifact:
    id: str
    case_id: str
    path: str
    logical_name: str
    sha256: str
    size: int
    parent_id: str | None = None
    mime: str | None = None
    magic: str | None = None
    artifact_type: str = "unknown"
    classifications: list[Classification] = field(default_factory=list)
    depth: int = 0
    created_by_tool_run_id: str | None = None
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class Observation:
    artifact_id: str
    key: str
    value: Any
    source: str
    confidence: float = 1.0
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class Finding:
    artifact_id: str
    title: str
    category: str
    severity: str
    confidence: float
    explanation: str
    source: str
    supporting_evidence: list[str] = field(default_factory=list)
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class ToolRun:
    artifact_id: str
    tool: str
    command_argv: list[str]
    timeout: float
    status: ToolRunStatus = ToolRunStatus.PLANNED
    id: str = field(default_factory=new_id)
    started_at: str | None = None
    ended_at: str | None = None
    exit_code: int | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    generated_files: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class FlagCandidate:
    artifact_id: str
    value: str
    transform_chain: list[str]
    source: str
    location: str | None
    confidence: float
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class AnalysisError:
    """A non-fatal analysis error retained for reproducible case reporting."""

    message: str
    source: str
    artifact_id: str | None = None
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class ToolPlanItem:
    tool: str
    artifact_id: str
    reasons: list[str]
    mode: AnalysisMode
    priority: int
    command_mode: str = "default"
    parameters: dict[str, str] = field(default_factory=dict)
    command_argv: list[str] = field(default_factory=list)
    available: bool = False
    executable: str | None = None
    timeout: float = 60.0
    cost: str = "medium"


@dataclass(slots=True)
class AnalysisResult:
    case: Case
    root_artifact: Artifact
    artifacts: list[Artifact] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    plans: list[ToolPlanItem] = field(default_factory=list)
    tool_runs: list[ToolRun] = field(default_factory=list)
    flags: list[FlagCandidate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
