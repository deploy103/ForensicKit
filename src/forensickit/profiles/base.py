from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from ..models import AnalysisMode, Artifact, Finding, Observation


def _normalize_mode(mode: AnalysisMode | str) -> AnalysisMode:
    if isinstance(mode, AnalysisMode):
        return mode
    return AnalysisMode(str(mode).lower())


@dataclass(frozen=True, slots=True)
class ToolRecommendation:
    """A profile/rule recommendation independent from registry and runner state."""

    tool: str
    allowed_modes: frozenset[AnalysisMode]
    reason: str
    priority: int = 50
    command_mode: str = "default"
    parameters: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        tool = self.tool.strip().lower()
        reason = self.reason.strip()
        if not tool:
            raise ValueError("recommendation tool must not be empty")
        if not reason:
            raise ValueError("recommendation reason must not be empty")
        modes = frozenset(_normalize_mode(mode) for mode in self.allowed_modes)
        if not modes:
            raise ValueError("recommendation must allow at least one mode")
        if AnalysisMode.TRIAGE in modes or AnalysisMode.PLAN in modes:
            raise ValueError("allowed_modes only accepts auto/deep execution modes")
        if isinstance(self.priority, bool) or not isinstance(self.priority, int):
            raise ValueError("recommendation priority must be an integer")
        command_mode = self.command_mode.strip().lower()
        if not command_mode or not command_mode.replace("_", "").replace("-", "").isalnum():
            raise ValueError("recommendation command_mode must be a simple non-empty identifier")
        parameters = {str(key): str(value) for key, value in self.parameters.items()}
        if any(not key.replace("_", "").isalnum() or "\x00" in value for key, value in parameters.items()):
            raise ValueError("recommendation parameters must use identifier keys and NUL-free values")
        object.__setattr__(self, "tool", tool)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "allowed_modes", modes)
        object.__setattr__(self, "command_mode", command_mode)
        object.__setattr__(self, "parameters", parameters)

    def allows(self, mode: AnalysisMode | str) -> bool:
        normalized = _normalize_mode(mode)
        if normalized is AnalysisMode.PLAN:
            # Plan mode displays every recommendation without executing it.
            return True
        return normalized in self.allowed_modes


@dataclass(slots=True)
class ProfileContext:
    artifact: Artifact
    observations: tuple[Observation, ...]
    _index: dict[str, tuple[Any, ...]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        indexed: dict[str, list[Any]] = {}
        for observation in self.observations:
            if observation.artifact_id != self.artifact.id:
                continue
            indexed.setdefault(observation.key, []).append(observation.value)
        self._index = {key: tuple(values) for key, values in indexed.items()}

    def values(self, *keys: str) -> tuple[Any, ...]:
        values: list[Any] = []
        for key in keys:
            values.extend(self._index.get(key, ()))
        return tuple(values)

    def exists(self, *keys: str) -> bool:
        return any(key in self._index for key in keys)

    def truthy(self, *keys: str) -> bool:
        return any(_truthy(value) for value in self.values(*keys))

    def number(self, *keys: str) -> float | None:
        for value in self.values(*keys):
            if isinstance(value, bool):
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return None

    @property
    def artifact_types(self) -> frozenset[str]:
        values = {self.artifact.artifact_type.lower()}
        values.update(item.artifact_type.lower() for item in self.artifact.classifications)
        for observed in self.values("artifact.type", "artifact.profile", "artifact.profiles"):
            if isinstance(observed, str):
                values.add(observed.lower())
            elif isinstance(observed, (list, tuple, set, frozenset)):
                values.update(str(item).lower() for item in observed if item)
        return frozenset(value for value in values if value)

    @property
    def format(self) -> str | None:
        for value in self.values(
            "artifact.format", "triage.detected_header_format", "file.format", "format"
        ):
            if isinstance(value, str) and value.strip():
                return value.strip().lower().lstrip(".")
        for candidate in self.artifact_types:
            if candidate not in {"unknown", "generic", "image", "archive", "memory", "disk"}:
                return candidate
        mime = (self.artifact.mime or "").lower()
        mime_formats = {
            "image/png": "png",
            "image/jpeg": "jpeg",
            "image/gif": "gif",
            "image/bmp": "bmp",
            "application/zip": "zip",
            "application/x-7z-compressed": "7z",
            "application/vnd.tcpdump.pcap": "pcap",
        }
        return mime_formats.get(mime)

    def format_is(self, *formats: str) -> bool:
        current = self.format
        return current is not None and current in {value.lower().lstrip(".") for value in formats}

    def classified_as(self, *artifact_types: str) -> bool:
        wanted = {value.lower() for value in artifact_types}
        return bool(self.artifact_types & wanted)


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "none", "null"}
    return bool(value)


@dataclass(slots=True)
class ProfileResult:
    profile: str
    matched: bool
    reasons: list[str] = field(default_factory=list)
    recommendations: list[ToolRecommendation] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@runtime_checkable
class Profile(Protocol):
    name: str
    priority: int

    def evaluate(self, context: ProfileContext) -> ProfileResult:
        """Observe context and return a deterministic plan without running tools."""


class BaseProfile:
    name = "base"
    priority = 0

    def evaluate(self, context: ProfileContext) -> ProfileResult:
        reasons = self.match_reasons(context)
        if not reasons:
            return ProfileResult(profile=self.name, matched=False)
        result = self.analyze(context)
        result.profile = self.name
        result.matched = True
        result.reasons = list(dict.fromkeys([*reasons, *result.reasons]))
        return result

    def match_reasons(self, context: ProfileContext) -> list[str]:
        raise NotImplementedError

    def analyze(self, context: ProfileContext) -> ProfileResult:
        return ProfileResult(profile=self.name, matched=True)

    def recommendation(
        self,
        tool: str,
        modes: Iterable[AnalysisMode | str],
        reason: str,
        priority: int,
        *,
        command_mode: str = "default",
        parameters: Mapping[str, str] | None = None,
    ) -> ToolRecommendation:
        return ToolRecommendation(
            tool, frozenset(_normalize_mode(mode) for mode in modes), reason, priority,
            command_mode=command_mode, parameters=parameters or {},
        )

    def finding(
        self,
        context: ProfileContext,
        *,
        title: str,
        category: str,
        confidence: float,
        explanation: str,
        evidence: Iterable[str],
        severity: str = "medium",
    ) -> Finding:
        return Finding(
            artifact_id=context.artifact.id,
            title=title,
            category=category,
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            explanation=explanation,
            source=f"profile:{self.name}",
            supporting_evidence=list(dict.fromkeys(evidence)),
        )

    def observation(self, context: ProfileContext, key: str, value: Any, confidence: float = 1.0) -> Observation:
        return Observation(
            artifact_id=context.artifact.id, key=key, value=value,
            source=f"profile:{self.name}", confidence=max(0.0, min(1.0, confidence)),
        )
