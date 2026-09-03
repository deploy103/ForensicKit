from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .models import Artifact


@dataclass(frozen=True, slots=True)
class LineageNode:
    artifact_id: str
    logical_name: str
    artifact_type: str
    parent_id: str | None


class ArtifactGraph:
    """Read-only, cycle-safe view over persisted artifact parent relationships."""

    def __init__(self, artifacts: Iterable[Artifact]) -> None:
        self.nodes = {artifact.id: artifact for artifact in artifacts}
        self.children: dict[str | None, list[str]] = defaultdict(list)
        for artifact in self.nodes.values():
            if artifact.parent_id is None or artifact.parent_id in self.nodes:
                self.children[artifact.parent_id].append(artifact.id)
        for values in self.children.values():
            values.sort(key=lambda artifact_id: (self.nodes[artifact_id].depth, self.nodes[artifact_id].logical_name, artifact_id))

    def lineage(self, artifact_id: str) -> list[LineageNode]:
        result: list[LineageNode] = []
        visited: set[str] = set()
        current = self.nodes.get(artifact_id)
        while current is not None and current.id not in visited:
            visited.add(current.id)
            result.append(LineageNode(current.id, current.logical_name, current.artifact_type, current.parent_id))
            current = self.nodes.get(current.parent_id) if current.parent_id else None
        return list(reversed(result))

    def as_tree(self) -> list[str]:
        lines: list[str] = []
        roots = self.children.get(None, [])
        for root_index, root_id in enumerate(roots):
            self._render(root_id, "", root_index == len(roots) - 1, lines, set())
        return lines

    def as_mapping(self) -> dict[str | None, list[str]]:
        return {parent: list(children) for parent, children in self.children.items()}

    def _render(self, artifact_id: str, prefix: str, last: bool, lines: list[str], visited: set[str]) -> None:
        artifact = self.nodes[artifact_id]
        connector = "└─ " if last else "├─ "
        lines.append(f"{prefix}{connector}{artifact.logical_name} [{artifact.artifact_type}] ({artifact.id[:8]})")
        if artifact_id in visited:
            lines.append(f"{prefix}   └─ cycle prevented")
            return
        descendants = self.children.get(artifact_id, [])
        next_prefix = prefix + ("   " if last else "│  ")
        next_visited = visited | {artifact_id}
        for index, child_id in enumerate(descendants):
            self._render(child_id, next_prefix, index == len(descendants) - 1, lines, next_visited)
