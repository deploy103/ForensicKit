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
    CANCELED = "canceled"


class VerificationStatus(str, Enum):
    """Whether recorded evidence currently verifies a hypothesis."""

    SUPPORTED = "supported"
    UNVERIFIED = "unverified"


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
    source_path: str | None = None
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
class Hypothesis:
    """A testable explanation linked one-to-one with a persisted finding."""

    artifact_id: str
    finding_id: str
    statement: str
    rationale: str
    source: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class Verification:
    """The explicit method and evidence used to evaluate one hypothesis."""

    artifact_id: str
    finding_id: str
    hypothesis_id: str
    method: str
    status: VerificationStatus
    conclusion: str
    source: str
    evidence: list[str] = field(default_factory=list)
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
    encoding: str = "utf-8"
    context: str | None = None
    source_kind: str = "evidence"
    origin_path: str | None = None
    discovered_path: str | None = None
    offset: int | None = None
    locations: list[dict[str, Any]] = field(default_factory=list)
    status: str = "candidate"
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class SearchHit:
    """A non-flag exact, keyword, or explicitly enabled regex match."""

    artifact_id: str
    value: str
    query: str
    match_type: str
    source: str
    location: str | None
    encoding: str
    transform_chain: list[str]
    context: str | None = None
    source_kind: str = "evidence"
    origin_path: str | None = None
    discovered_path: str | None = None
    offset: int | None = None
    locations: list[dict[str, Any]] = field(default_factory=list)
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
    evidence_confidence: float = 1.0
    expected_value: int = 50
    cpu_cost: int = 1
    estimated_ram_bytes: int = 0
    expected_outputs: list[str] = field(default_factory=list)
    supported_platforms: list[str] = field(default_factory=list)
    dependency_hints: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)


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
    search_hits: list[SearchHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
