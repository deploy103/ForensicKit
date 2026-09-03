from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from threading import RLock
from typing import Any, Iterable

from .models import (
    Artifact,
    AnalysisError,
    Case,
    Classification,
    Finding,
    FlagCandidate,
    Observation,
    ToolRun,
    ToolRunStatus,
)


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
    workspace TEXT NOT NULL, configuration_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
    parent_id TEXT REFERENCES artifacts(id), path TEXT NOT NULL,
    logical_name TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
    mime TEXT, magic TEXT, artifact_type TEXT NOT NULL,
    classifications_json TEXT NOT NULL, depth INTEGER NOT NULL,
    created_by_tool_run_id TEXT, created_at TEXT NOT NULL,
    UNIQUE(case_id, sha256)
);
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    key TEXT NOT NULL, value_json TEXT NOT NULL, source TEXT NOT NULL,
    confidence REAL NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_artifact_key ON observations(artifact_id, key);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    title TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
    confidence REAL NOT NULL, explanation TEXT NOT NULL, source TEXT NOT NULL,
    supporting_evidence_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_runs (
    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    tool TEXT NOT NULL, command_argv_json TEXT NOT NULL, timeout REAL NOT NULL,
    status TEXT NOT NULL, started_at TEXT, ended_at TEXT, exit_code INTEGER,
    stdout_path TEXT, stderr_path TEXT, generated_files_json TEXT NOT NULL,
    error TEXT
);
CREATE TABLE IF NOT EXISTS flag_candidates (
    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    value TEXT NOT NULL, transform_chain_json TEXT NOT NULL, source TEXT NOT NULL,
    location TEXT, confidence REAL NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(artifact_id, value, source, location)
);
CREATE TABLE IF NOT EXISTS analysis_errors (
    id TEXT PRIMARY KEY, artifact_id TEXT REFERENCES artifacts(id),
    message TEXT NOT NULL, source TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_errors_artifact ON analysis_errors(artifact_id, created_at);
"""


class CaseDatabase:
    """Small explicit SQLite repository; all forensic entities remain inspectable."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = RLock()
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        with self.connection:
            self.connection.executescript(SCHEMA)

    def close(self) -> None:
        self.connection.close()

    def add_case(self, case: Case) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?)",
                (case.id, case.name, case.created_at, case.workspace, json.dumps(case.configuration)),
            )

    def get_case(self) -> Case:
        row = self.connection.execute("SELECT * FROM cases ORDER BY created_at LIMIT 1").fetchone()
        if row is None:
            raise LookupError("workspace has no case record")
        return Case(row["id"], row["name"], row["created_at"], row["workspace"], json.loads(row["configuration_json"]))

    def add_artifact(self, artifact: Artifact) -> None:
        classifications = [asdict(item) for item in artifact.classifications]
        with self._lock, self.connection:
            self.connection.execute(
                """INSERT INTO artifacts
                (id, case_id, parent_id, path, logical_name, sha256, size, mime, magic,
                 artifact_type, classifications_json, depth, created_by_tool_run_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    artifact.id, artifact.case_id, artifact.parent_id, artifact.path,
                    artifact.logical_name, artifact.sha256, artifact.size, artifact.mime,
                    artifact.magic, artifact.artifact_type, json.dumps(classifications),
                    artifact.depth, artifact.created_by_tool_run_id, artifact.created_at,
                ),
            )

    def update_artifact_identification(self, artifact: Artifact) -> None:
        classifications = [asdict(item) for item in artifact.classifications]
        with self._lock, self.connection:
            self.connection.execute(
                """UPDATE artifacts SET mime=?, magic=?, artifact_type=?, classifications_json=?
                   WHERE id=?""",
                (artifact.mime, artifact.magic, artifact.artifact_type, json.dumps(classifications), artifact.id),
            )

    def artifact_by_hash(self, case_id: str, sha256: str) -> Artifact | None:
        row = self.connection.execute(
            "SELECT * FROM artifacts WHERE case_id=? AND sha256=?", (case_id, sha256)
        ).fetchone()
        return self._artifact(row) if row else None

    def artifacts(self) -> list[Artifact]:
        rows = self.connection.execute("SELECT * FROM artifacts ORDER BY depth, created_at").fetchall()
        return [self._artifact(row) for row in rows]

    def add_observations(self, observations: Iterable[Observation]) -> None:
        rows = [
            (o.id, o.artifact_id, o.key, json.dumps(o.value), o.source, o.confidence, o.created_at)
            for o in observations
        ]
        with self._lock, self.connection:
            self.connection.executemany("INSERT OR IGNORE INTO observations VALUES (?, ?, ?, ?, ?, ?, ?)", rows)

    def observations(self, artifact_id: str | None = None) -> list[Observation]:
        query = "SELECT * FROM observations"
        args: tuple[str, ...] = ()
        if artifact_id:
            query += " WHERE artifact_id=?"
            args = (artifact_id,)
        query += " ORDER BY created_at"
        return [
            Observation(
                id=row["id"], artifact_id=row["artifact_id"], key=row["key"],
                value=json.loads(row["value_json"]), source=row["source"],
                confidence=row["confidence"], created_at=row["created_at"],
            )
            for row in self.connection.execute(query, args).fetchall()
        ]

    def add_findings(self, findings: Iterable[Finding]) -> None:
        rows = [
            (f.id, f.artifact_id, f.title, f.category, f.severity, f.confidence,
             f.explanation, f.source, json.dumps(f.supporting_evidence), f.created_at)
            for f in findings
        ]
        with self._lock, self.connection:
            self.connection.executemany("INSERT OR IGNORE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)

    def findings(self, artifact_id: str | None = None) -> list[Finding]:
        query, args = "SELECT * FROM findings", ()
        if artifact_id:
            query, args = query + " WHERE artifact_id=?", (artifact_id,)
        return [
            Finding(
                id=r["id"], artifact_id=r["artifact_id"], title=r["title"], category=r["category"],
                severity=r["severity"], confidence=r["confidence"], explanation=r["explanation"],
                source=r["source"], supporting_evidence=json.loads(r["supporting_evidence_json"]),
                created_at=r["created_at"],
            ) for r in self.connection.execute(query + " ORDER BY created_at", args).fetchall()
        ]

    def add_tool_run(self, run: ToolRun) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO tool_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                self._tool_run_values(run),
            )

    def update_tool_run(self, run: ToolRun) -> None:
        values = self._tool_run_values(run)
        with self._lock, self.connection:
            self.connection.execute(
                """UPDATE tool_runs SET artifact_id=?, tool=?, command_argv_json=?, timeout=?,
                   status=?, started_at=?, ended_at=?, exit_code=?, stdout_path=?, stderr_path=?,
                   generated_files_json=?, error=? WHERE id=?""",
                values[1:] + values[:1],
            )

    def tool_runs(self, artifact_id: str | None = None) -> list[ToolRun]:
        query, args = "SELECT * FROM tool_runs", ()
        if artifact_id:
            query, args = query + " WHERE artifact_id=?", (artifact_id,)
        rows = self.connection.execute(query + " ORDER BY COALESCE(started_at, '')", args).fetchall()
        return [self._tool_run(row) for row in rows]

    def add_flags(self, flags: Iterable[FlagCandidate]) -> None:
        rows = [
            (f.id, f.artifact_id, f.value, json.dumps(f.transform_chain), f.source,
             f.location, f.confidence, f.created_at)
            for f in flags
        ]
        with self._lock, self.connection:
            self.connection.executemany(
                "INSERT OR IGNORE INTO flag_candidates VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows
            )

    def flags(self) -> list[FlagCandidate]:
        return [
            FlagCandidate(
                id=r["id"], artifact_id=r["artifact_id"], value=r["value"],
                transform_chain=json.loads(r["transform_chain_json"]), source=r["source"],
                location=r["location"], confidence=r["confidence"], created_at=r["created_at"],
            ) for r in self.connection.execute("SELECT * FROM flag_candidates ORDER BY created_at").fetchall()
        ]

    def add_errors(self, errors: Iterable[AnalysisError]) -> None:
        rows = [
            (error.id, error.artifact_id, error.message, error.source, error.created_at)
            for error in errors
        ]
        with self._lock, self.connection:
            self.connection.executemany(
                "INSERT OR IGNORE INTO analysis_errors VALUES (?, ?, ?, ?, ?)", rows
            )

    def errors(self, artifact_id: str | None = None) -> list[AnalysisError]:
        query, args = "SELECT * FROM analysis_errors", ()
        if artifact_id:
            query, args = query + " WHERE artifact_id=?", (artifact_id,)
        return [
            AnalysisError(
                id=row["id"], artifact_id=row["artifact_id"], message=row["message"],
                source=row["source"], created_at=row["created_at"],
            )
            for row in self.connection.execute(query + " ORDER BY created_at", args).fetchall()
        ]

    @staticmethod
    def _artifact(row: sqlite3.Row) -> Artifact:
        return Artifact(
            id=row["id"], case_id=row["case_id"], parent_id=row["parent_id"], path=row["path"],
            logical_name=row["logical_name"], sha256=row["sha256"], size=row["size"], mime=row["mime"],
            magic=row["magic"], artifact_type=row["artifact_type"], depth=row["depth"],
            created_by_tool_run_id=row["created_by_tool_run_id"], created_at=row["created_at"],
            classifications=[Classification(**item) for item in json.loads(row["classifications_json"])],
        )

    @staticmethod
    def _tool_run_values(run: ToolRun) -> tuple[Any, ...]:
        return (
            run.id, run.artifact_id, run.tool, json.dumps(run.command_argv), run.timeout,
            run.status.value, run.started_at, run.ended_at, run.exit_code, run.stdout_path,
            run.stderr_path, json.dumps(run.generated_files), run.error,
        )

    @staticmethod
    def _tool_run(row: sqlite3.Row) -> ToolRun:
        return ToolRun(
            id=row["id"], artifact_id=row["artifact_id"], tool=row["tool"],
            command_argv=json.loads(row["command_argv_json"]), timeout=row["timeout"],
            status=ToolRunStatus(row["status"]), started_at=row["started_at"], ended_at=row["ended_at"],
            exit_code=row["exit_code"], stdout_path=row["stdout_path"], stderr_path=row["stderr_path"],
            generated_files=json.loads(row["generated_files_json"]), error=row["error"],
        )
