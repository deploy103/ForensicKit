from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable

from .models import AnalysisMode, Artifact, ToolPlanItem, ToolRunStatus
from .profiles.base import ToolRecommendation
from .tools.registry import ToolRegistry
from .workspace import CaseWorkspace


_COST_PENALTY = {"low": 0, "medium": 10, "high": 30}


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

        previous = {
            run.tool
            for run in self.workspace.database.tool_runs(artifact.id)
            if run.status is ToolRunStatus.COMPLETED and run.exit_code == 0
        }
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
                    )
                )
                continue

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
            plans.append(
                ToolPlanItem(
                    tool=definition.name,
                    artifact_id=artifact.id,
                    reasons=reasons,
                    mode=mode,
                    priority=priority - _COST_PENALTY.get(definition.cost, 10),
                    command_mode=run_mode,
                    parameters=parameters,
                    command_argv=command,
                    available=executable is not None,
                    executable=executable,
                    timeout=definition.timeout,
                    cost=definition.cost,
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
