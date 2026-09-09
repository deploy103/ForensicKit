from __future__ import annotations

from collections import defaultdict
import sys
from typing import Iterable

from .models import AnalysisMode, Artifact, ToolPlanItem, ToolRunStatus
from .profiles.base import ToolRecommendation
from .tools.registry import ToolRegistry
from .workspace import CaseWorkspace


_COST_PENALTY = {"low": 0, "medium": 10, "high": 30}
_SIZE_STEP = 128 * 1024 * 1024


class ToolPlanner:
    """Turns evidence-backed recommendations into executable, deduplicated plans."""

    def __init__(self, workspace: CaseWorkspace, registry: ToolRegistry) -> None:
        self.workspace = workspace
        self.registry = registry

    def plan(
        self,
        artifact: Artifact,
        recommendations: Iterable[ToolRecommendation],
        mode: AnalysisMode,
    ) -> list[ToolPlanItem]:
        merged: dict[tuple[str, str, tuple[tuple[str, str], ...]], list[ToolRecommendation]] = defaultdict(list)
        for recommendation in recommendations:
            if recommendation.allows(mode):
                key = (
                    recommendation.tool,
                    recommendation.command_mode,
                    tuple(sorted(recommendation.parameters.items())),
                )
                merged[key].append(recommendation)

        previous_runs = self.workspace.database.tool_runs(artifact.id)
        previous = {
            run.tool
            for run in previous_runs
            if run.status is ToolRunStatus.COMPLETED and run.exit_code == 0
        }
        previous_findings = self.workspace.database.findings(artifact.id)
        previous_observations = self.workspace.database.observations(artifact.id)
        limits = self.workspace.case.configuration.get("limits", {})
        if not isinstance(limits, dict):
            limits = {}
        cpu_budget = _positive_int(limits.get("planner_cpu_units"), 2)
        configured_ram_budget = _positive_int(
            limits.get("planner_max_ram_bytes"), 6 * 1024 * 1024 * 1024
        )
        runner_ram_limit = _positive_int(
            limits.get("tool_max_memory_bytes"), configured_ram_budget
        )
        ram_budget = min(configured_ram_budget, runner_ram_limit)
        evidence = self.workspace.resolve_stored_path(artifact.path)
        plans: list[ToolPlanItem] = []
        for (tool_name, requested_mode, parameter_items), tool_recommendations in merged.items():
            parameters = dict(parameter_items)
            if tool_name in previous and not parameters:
                continue
            reasons = list(dict.fromkeys(item.reason for item in tool_recommendations))
            priority = max(item.priority for item in tool_recommendations)
            try:
                definition = self.registry.get(tool_name)
            except KeyError:
                plans.append(
                    ToolPlanItem(
                        tool=tool_name,
                        artifact_id=artifact.id,
                        reasons=reasons + ["tool is not defined in the registry"],
                        mode=mode,
                        priority=priority,
                        command_mode=requested_mode,
                        parameters=parameters,
                        available=False,
                    )
                )
                continue

            evidence_confidence = _evidence_confidence(
                artifact, definition.profiles, definition.accepts
            )
            if definition.accepts and not _accepts_artifact(definition.accepts, artifact):
                plans.append(
                    ToolPlanItem(
                        tool=definition.name,
                        artifact_id=artifact.id,
                        reasons=reasons + [
                            f"tool accepts {', '.join(definition.accepts)} but confirmed artifact format is incompatible"
                        ],
                        mode=mode,
                        priority=priority - _COST_PENALTY.get(definition.cost, 10),
                        command_mode=requested_mode,
                        parameters=parameters,
                        available=False,
                        timeout=definition.timeout,
                        cost=definition.cost,
                        evidence_confidence=evidence_confidence,
                        expected_value=definition.expected_value,
                        cpu_cost=definition.cpu_cost,
                        estimated_ram_bytes=definition.estimated_ram_bytes,
                        expected_outputs=list(definition.expected_outputs),
                        supported_platforms=list(definition.supported_platforms),
                        dependency_hints=list(definition.dependency_hints),
                        prerequisites=list(definition.prerequisites),
                    )
                )
                continue

            policy_reasons: list[str] = []
            current_platform = _current_platform()
            if current_platform not in definition.supported_platforms:
                policy_reasons.append(
                    f"current platform {current_platform!r} is not supported; supported platforms: "
                    + ", ".join(definition.supported_platforms)
                )
            if artifact.size < definition.min_artifact_size:
                policy_reasons.append(
                    f"artifact size {artifact.size} is below tool minimum {definition.min_artifact_size} bytes"
                )
            if definition.max_artifact_size is not None and artifact.size > definition.max_artifact_size:
                policy_reasons.append(
                    f"artifact size {artifact.size} exceeds tool maximum {definition.max_artifact_size} bytes"
                )
            if evidence_confidence < definition.minimum_confidence:
                policy_reasons.append(
                    f"evidence confidence {evidence_confidence:.2f} is below tool minimum "
                    f"{definition.minimum_confidence:.2f}"
                )
            if definition.cpu_cost > cpu_budget:
                policy_reasons.append(
                    f"estimated CPU cost {definition.cpu_cost} exceeds planner budget {cpu_budget}"
                )
            if definition.estimated_ram_bytes > ram_budget:
                policy_reasons.append(
                    f"estimated RAM {definition.estimated_ram_bytes} exceeds planner budget {ram_budget} bytes"
                )
            unmet = _unmet_prerequisites(
                definition.prerequisites, previous_runs, previous_findings, previous_observations
            )
            if unmet:
                policy_reasons.append("unmet prerequisites: " + ", ".join(unmet))

            executable = self.registry.resolve_executable(definition)
            if requested_mode != "default" and requested_mode in definition.command_templates:
                run_mode = requested_mode
            elif mode is AnalysisMode.DEEP and "deep" in definition.command_templates:
                run_mode = "deep"
            else:
                run_mode = "default"
            output_directory = self.workspace.path("artifacts", artifact.id, tool_name)
            command: list[str] = []
            if executable:
                try:
                    command = self.registry.build_command(
                        definition,
                        evidence,
                        mode=run_mode,
                        output_directory=output_directory,
                        executable=executable,
                        template_values=parameters,
                    )
                except (OSError, ValueError) as exc:
                    reasons.append(f"command could not be built: {exc}")
                    executable = None
            size_penalty = _artifact_size_penalty(artifact.size, definition.cost)
            if size_penalty:
                reasons.append(
                    f"artifact size {artifact.size} bytes and {definition.cost} cost reduce priority "
                    f"by {size_penalty}"
                )
            score = (
                priority
                - _COST_PENALTY.get(definition.cost, 10)
                - size_penalty
                - round((1.0 - evidence_confidence) * 10)
                + round((definition.expected_value - 50) / 5)
            )
            plans.append(
                ToolPlanItem(
                    tool=definition.name,
                    artifact_id=artifact.id,
                    reasons=[*reasons, *policy_reasons],
                    mode=mode,
                    priority=score,
                    command_mode=run_mode,
                    parameters=parameters,
                    command_argv=command,
                    available=executable is not None and not policy_reasons,
                    executable=executable,
                    timeout=definition.timeout,
                    cost=definition.cost,
                    evidence_confidence=evidence_confidence,
                    expected_value=definition.expected_value,
                    cpu_cost=definition.cpu_cost,
                    estimated_ram_bytes=definition.estimated_ram_bytes,
                    expected_outputs=list(definition.expected_outputs),
                    supported_platforms=list(definition.supported_platforms),
                    dependency_hints=list(definition.dependency_hints),
                    prerequisites=list(definition.prerequisites),
                )
            )
        return sorted(plans, key=lambda item: (-item.priority, item.tool))


__all__ = ["ToolPlanner"]


def _accepts_artifact(accepted: tuple[str, ...], artifact: Artifact) -> bool:
    """Reject only a positively identified incompatible format.

    Registry ``accepts`` is a safety guard, not an extension-based classifier:
    unknown evidence remains eligible for profile-driven tools, while a known
    JPEG will never receive a PNG-only invocation.
    """
    known: set[str] = {artifact.artifact_type.lower()}
    known.update(item.artifact_type.lower() for item in artifact.classifications)
    mime_map = {
        "image/png": "png", "image/jpeg": "jpeg", "image/gif": "gif", "image/bmp": "bmp",
        "application/pdf": "pdf", "application/zip": "zip", "application/vnd.sqlite3": "sqlite",
    }
    if artifact.mime:
        known.add(mime_map.get(artifact.mime.lower(), artifact.mime.lower()))
    magic = (artifact.magic or "").lower()
    for token, format_name in (
        ("png", "png"), ("jpeg", "jpeg"), ("gif", "gif"), ("bmp", "bmp"),
        ("pdf", "pdf"), ("zip", "zip"), ("elf", "elf"), ("android apk", "apk"),
    ):
        if token in magic:
            known.add(format_name)
    confirmed = known - {"unknown", "unknown_binary", "generic", "image", "archive", "text"}
    if not confirmed:
        return True
    wanted = {item.lower().lstrip(".") for item in accepted}
    return bool(confirmed & wanted)


def _current_platform() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith(("win32", "cygwin", "msys")):
        return "windows"
    return sys.platform.lower()


def _positive_int(value: object, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else default


def _evidence_confidence(
    artifact: Artifact, profiles: tuple[str, ...], accepted: tuple[str, ...]
) -> float:
    relevant = {item.lower() for item in (*profiles, *accepted)}
    matching = [
        item.confidence for item in artifact.classifications
        if not relevant or item.artifact_type.lower() in relevant
    ]
    if not matching:
        matching = [item.confidence for item in artifact.classifications]
    if matching:
        return max(0.0, min(1.0, max(matching)))
    if artifact.artifact_type.lower() not in {"", "unknown", "unknown_binary", "generic"}:
        return 0.8
    if artifact.mime or artifact.magic:
        return 0.7
    return 0.5


def _artifact_size_penalty(size: int, cost: str) -> int:
    """Bound predictable priority erosion for expensive multi-pass tools."""
    if size <= _SIZE_STEP:
        return 0
    steps = min(8, max(1, (size - 1) // _SIZE_STEP))
    multiplier = {"low": 1, "medium": 2, "high": 3}.get(cost, 2)
    return int(steps) * multiplier


def _unmet_prerequisites(prerequisites, runs, findings, observations) -> list[str]:
    successful_tools = {
        run.tool.casefold() for run in runs
        if run.status is ToolRunStatus.COMPLETED and run.exit_code == 0
    }
    finding_terms = {
        value.casefold()
        for finding in findings
        for value in (finding.id, finding.title, finding.category, finding.source)
    }
    observation_keys = {item.key.casefold() for item in observations}
    unmet: list[str] = []
    for prerequisite in prerequisites:
        kind, separator, value = prerequisite.partition(":")
        target = value.strip().casefold()
        if not separator or not target:
            unmet.append(prerequisite)
        elif kind.casefold() == "tool" and target not in successful_tools:
            unmet.append(prerequisite)
        elif kind.casefold() == "finding" and target not in finding_terms:
            unmet.append(prerequisite)
        elif kind.casefold() == "observation" and target not in observation_keys:
            unmet.append(prerequisite)
        elif kind.casefold() not in {"tool", "finding", "observation"}:
            unmet.append(prerequisite)
    return unmet
