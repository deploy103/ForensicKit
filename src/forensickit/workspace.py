from __future__ import annotations

import re
from pathlib import Path

from .config import ForensicKitConfig
from .models import Case, new_id, utc_now
from .storage import CaseDatabase


WORKSPACE_DIRECTORIES = ("evidence", "artifacts", "extracted", "outputs", "logs", "cache", "reports")


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned[:100] or "case"


class CaseWorkspace:
    def __init__(self, root: Path, case: Case, database: CaseDatabase) -> None:
        self.root = root.resolve()
        self.case = case
        self.database = database

    @classmethod
    def create(
        cls,
        base_directory: Path,
        name: str,
        config: ForensicKitConfig | None = None,
    ) -> "CaseWorkspace":
        config = config or ForensicKitConfig()
        case_id = new_id()
        timestamp = utc_now().replace(":", "").replace("+00:00", "Z").replace("-", "")
        root = (base_directory / f"{safe_name(name)}-{timestamp}-{case_id[:8]}").resolve()
        root.mkdir(parents=True, exist_ok=False)
        for directory in WORKSPACE_DIRECTORIES:
            (root / directory).mkdir()
        database = CaseDatabase(root / "case.db")
        case = Case(
            id=case_id,
            name=name,
            created_at=utc_now(),
            workspace=str(root),
            configuration=config.as_dict(),
        )
        database.add_case(case)
        return cls(root, case, database)

    @classmethod
    def open(cls, root: Path) -> "CaseWorkspace":
        resolved = root.resolve()
        database = CaseDatabase(resolved / "case.db")
        return cls(resolved, database.get_case(), database)

    def path(self, category: str, *parts: str) -> Path:
        if category not in WORKSPACE_DIRECTORIES:
            raise ValueError(f"unknown workspace category: {category}")
        target = (self.root / category).joinpath(*parts).resolve()
        if self.root not in target.parents:
            raise ValueError("workspace path escapes case root")
        return target

    def relative(self, path: Path) -> str:
        return str(path.resolve().relative_to(self.root))

    def resolve_stored_path(self, stored_path: str) -> Path:
        path = (self.root / stored_path).resolve()
        if self.root not in path.parents:
            raise ValueError("stored path escapes case root")
        return path

    def close(self) -> None:
        self.database.close()

    def __enter__(self) -> "CaseWorkspace":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
