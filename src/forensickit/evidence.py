from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .models import Artifact, new_id
from .workspace import CaseWorkspace, safe_name


class EvidenceError(ValueError):
    pass


class EvidenceManager:
    """Preserves source evidence and registers immutable workspace copies."""

    def __init__(self, workspace: CaseWorkspace) -> None:
        self.workspace = workspace

    def ingest(self, source: Path) -> Artifact:
        source = source.expanduser().resolve(strict=True)
        if not source.is_file():
            raise EvidenceError(f"evidence is not a regular file: {source}")

        staging = self.workspace.path("evidence", f".ingest-{new_id()}.tmp")
        digest = hashlib.sha256()
        size = 0
        try:
            with source.open("rb") as reader, staging.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    digest.update(chunk)
                    writer.write(chunk)
                    size += len(chunk)
                writer.flush()
                os.fsync(writer.fileno())

            sha256 = digest.hexdigest()
            existing = self.workspace.database.artifact_by_hash(self.workspace.case.id, sha256)
            if existing:
                staging.unlink(missing_ok=True)
                return existing

            destination = self.workspace.path(
                "evidence", f"{sha256[:16]}_{safe_name(source.name)}"
            )
            staging.replace(destination)
            destination.chmod(0o444)
            artifact = Artifact(
                id=new_id(),
                case_id=self.workspace.case.id,
                path=self.workspace.relative(destination),
                logical_name=source.name,
                sha256=sha256,
                size=size,
            )
            self.workspace.database.add_artifact(artifact)
            return artifact
        except BaseException:
            staging.unlink(missing_ok=True)
            raise
