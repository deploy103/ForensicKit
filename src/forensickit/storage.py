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
    Hypothesis,
    Observation,
    SearchHit,
    ToolRun,
    ToolRunStatus,
    Verification,
    VerificationStatus,
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
    created_by_tool_run_id TEXT, source_path TEXT, created_at TEXT NOT NULL,
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
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id),
    statement TEXT NOT NULL, rationale TEXT NOT NULL, source TEXT NOT NULL,
    confidence REAL NOT NULL, evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hypotheses_artifact ON hypotheses(artifact_id, created_at);
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id),
    hypothesis_id TEXT NOT NULL UNIQUE REFERENCES hypotheses(id),
    method TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('supported', 'unverified')),
    conclusion TEXT NOT NULL, source TEXT NOT NULL,
    evidence_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verifications_artifact ON verifications(artifact_id, created_at);
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
    encoding TEXT NOT NULL DEFAULT 'utf-8', context TEXT,
    source_kind TEXT NOT NULL DEFAULT 'evidence', origin_path TEXT,
    discovered_path TEXT, offset INTEGER,
    locations_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'candidate',
    UNIQUE(artifact_id, value, source, location)
);
CREATE TABLE IF NOT EXISTS search_hits (
    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES artifacts(id),
    value TEXT NOT NULL, query TEXT NOT NULL, match_type TEXT NOT NULL,
    source TEXT NOT NULL, location TEXT, encoding TEXT NOT NULL,
    transform_chain_json TEXT NOT NULL, context TEXT,
    source_kind TEXT NOT NULL, origin_path TEXT, discovered_path TEXT,
    offset INTEGER, locations_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_search_hits_query ON search_hits(match_type, query, value);
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
            self._migrate_schema()

    def _migrate_schema(self) -> None:
        """Upgrade older case databases and complete their investigation chain."""
        additions = {
            "artifacts": {"source_path": "TEXT"},
            "flag_candidates": {
                "encoding": "TEXT NOT NULL DEFAULT 'utf-8'",
                "context": "TEXT",
                "source_kind": "TEXT NOT NULL DEFAULT 'evidence'",
                "origin_path": "TEXT",
                "discovered_path": "TEXT",
                "offset": "INTEGER",
                "locations_json": "TEXT NOT NULL DEFAULT '[]'",
                "status": "TEXT NOT NULL DEFAULT 'candidate'",
            },
        }
        for table, columns in additions.items():
            existing = {
                str(row["name"])
                for row in self.connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for name, declaration in columns.items():
                if name not in existing:
                    self.connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {declaration}"
                    )
        for row in self.connection.execute(
            "SELECT * FROM findings ORDER BY created_at, id"
        ).fetchall():
            self._ensure_investigation_chain(row)

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
                 artifact_type, classifications_json, depth, created_by_tool_run_id,
                 source_path, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    artifact.id, artifact.case_id, artifact.parent_id, artifact.path,
                    artifact.logical_name, artifact.sha256, artifact.size, artifact.mime,
                    artifact.magic, artifact.artifact_type, json.dumps(classifications),
                    artifact.depth, artifact.created_by_tool_run_id,
                    artifact.source_path, artifact.created_at,
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
        with self._lock, self.connection:
            for finding in findings:
                self.connection.execute(
                    "INSERT OR IGNORE INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        finding.id, finding.artifact_id, finding.title, finding.category,
                        finding.severity, finding.confidence, finding.explanation,
                        finding.source, json.dumps(finding.supporting_evidence),
                        finding.created_at,
                    ),
                )
                persisted = self.connection.execute(
                    "SELECT * FROM findings WHERE id=?", (finding.id,),
                ).fetchone()
                if persisted is not None:
                    self._ensure_investigation_chain(persisted)

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

    def hypotheses(
        self, artifact_id: str | None = None, finding_id: str | None = None,
    ) -> list[Hypothesis]:
        query = "SELECT * FROM hypotheses"
        clauses: list[str] = []
        args: list[str] = []
        if artifact_id:
            clauses.append("artifact_id=?")
            args.append(artifact_id)
        if finding_id:
            clauses.append("finding_id=?")
            args.append(finding_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        rows = self.connection.execute(
            query + " ORDER BY created_at, id", tuple(args),
        ).fetchall()
        return [
            Hypothesis(
                id=row["id"], artifact_id=row["artifact_id"],
                finding_id=row["finding_id"], statement=row["statement"],
                rationale=row["rationale"], source=row["source"],
                confidence=row["confidence"], evidence=json.loads(row["evidence_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def verifications(
        self, artifact_id: str | None = None, finding_id: str | None = None,
    ) -> list[Verification]:
        query = "SELECT * FROM verifications"
        clauses: list[str] = []
        args: list[str] = []
        if artifact_id:
            clauses.append("artifact_id=?")
            args.append(artifact_id)
        if finding_id:
            clauses.append("finding_id=?")
            args.append(finding_id)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        rows = self.connection.execute(
            query + " ORDER BY created_at, id", tuple(args),
        ).fetchall()
        return [
            Verification(
                id=row["id"], artifact_id=row["artifact_id"],
                finding_id=row["finding_id"], hypothesis_id=row["hypothesis_id"],
                method=row["method"], status=VerificationStatus(row["status"]),
                conclusion=row["conclusion"], source=row["source"],
                evidence=json.loads(row["evidence_json"]),
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def _ensure_investigation_chain(self, finding: sqlite3.Row) -> None:
        """Create the one-to-one hypothesis and verification for a finding.

        This method always runs inside the caller's SQLite transaction, so a
        finding can never commit without both linked records.
        """
        finding_id = str(finding["id"])
        artifact_id = str(finding["artifact_id"])
        evidence_json = str(finding["supporting_evidence_json"] or "[]")
        try:
            evidence = json.loads(evidence_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            evidence = []
            evidence_json = "[]"
        if not isinstance(evidence, list):
            evidence = [str(evidence)]
            evidence_json = json.dumps(evidence)

        self.connection.execute(
            """INSERT OR IGNORE INTO hypotheses
               (id, artifact_id, finding_id, statement, rationale, source,
                confidence, evidence_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"hypothesis-{finding_id}", artifact_id, finding_id,
                str(finding["title"]), str(finding["explanation"]),
                str(finding["source"]), float(finding["confidence"]),
                evidence_json, str(finding["created_at"]),
            ),
        )
        hypothesis = self.connection.execute(
            "SELECT id FROM hypotheses WHERE finding_id=?", (finding_id,),
        ).fetchone()
        if hypothesis is None:
            raise sqlite3.IntegrityError(
                f"unable to persist hypothesis for finding {finding_id}"
            )
        supported = bool(evidence)
        status = (
            VerificationStatus.SUPPORTED.value
            if supported else VerificationStatus.UNVERIFIED.value
        )
        conclusion = (
            "The finding is supported by its recorded evidence."
            if supported else
            "No supporting evidence was recorded; analyst verification is required."
        )
        self.connection.execute(
            """INSERT OR IGNORE INTO verifications
               (id, artifact_id, finding_id, hypothesis_id, method, status,
                conclusion, source, evidence_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"verification-{finding_id}", artifact_id, finding_id,
                str(hypothesis["id"]), "recorded_supporting_evidence_review",
                status, conclusion, str(finding["source"]), evidence_json,
                str(finding["created_at"]),
            ),
        )
        verification = self.connection.execute(
            "SELECT id FROM verifications WHERE finding_id=?", (finding_id,),
        ).fetchone()
        if verification is None:
            raise sqlite3.IntegrityError(
                f"unable to persist verification for finding {finding_id}"
            )

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
        with self._lock, self.connection:
            for candidate in flags:
                locations = candidate.locations or [self._flag_location(candidate)]
                existing = self.connection.execute(
                    "SELECT * FROM flag_candidates WHERE value=? AND status=? ORDER BY created_at LIMIT 1",
                    (candidate.value, candidate.status),
                ).fetchone()
                if existing is not None:
                    previous_locations = json.loads(existing["locations_json"] or "[]")
                    merged = self._merge_locations(
                        previous_locations, locations
                    )
                    if self._location_priority(locations) > self._location_priority(previous_locations[:1]):
                        merged = self._merge_locations(locations, previous_locations)
                        self.connection.execute(
                            """UPDATE flag_candidates SET artifact_id=?,
                               transform_chain_json=?, source=?, location=?, confidence=?,
                               encoding=?, context=?, source_kind=?, origin_path=?,
                               discovered_path=?, offset=?, locations_json=? WHERE id=?""",
                            (
                                candidate.artifact_id, json.dumps(candidate.transform_chain),
                                candidate.source, candidate.location,
                                max(existing["confidence"], candidate.confidence),
                                candidate.encoding, candidate.context, candidate.source_kind,
                                candidate.origin_path, candidate.discovered_path,
                                candidate.offset, json.dumps(merged), existing["id"],
                            ),
                        )
                    else:
                        self.connection.execute(
                            """UPDATE flag_candidates SET locations_json=?, confidence=?
                               WHERE id=?""",
                            (json.dumps(merged), max(existing["confidence"], candidate.confidence), existing["id"]),
                        )
                    continue
                self.connection.execute(
                    """INSERT INTO flag_candidates
                    (id, artifact_id, value, transform_chain_json, source, location,
                     confidence, created_at, encoding, context, source_kind,
                     origin_path, discovered_path, offset, locations_json, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        candidate.id, candidate.artifact_id, candidate.value,
                        json.dumps(candidate.transform_chain), candidate.source,
                        candidate.location, candidate.confidence, candidate.created_at,
                        candidate.encoding, candidate.context, candidate.source_kind,
                        candidate.origin_path, candidate.discovered_path, candidate.offset,
                        json.dumps(locations), candidate.status,
                    ),
                )

    def flags(self) -> list[FlagCandidate]:
        return [
            FlagCandidate(
                id=r["id"], artifact_id=r["artifact_id"], value=r["value"],
                transform_chain=json.loads(r["transform_chain_json"]), source=r["source"],
                location=r["location"], confidence=r["confidence"],
                encoding=r["encoding"], context=r["context"],
                source_kind=r["source_kind"], origin_path=r["origin_path"],
                discovered_path=r["discovered_path"], offset=r["offset"],
                locations=json.loads(r["locations_json"] or "[]"),
                status=r["status"], created_at=r["created_at"],
            ) for r in self.connection.execute("SELECT * FROM flag_candidates ORDER BY created_at").fetchall()
        ]

    def add_search_hits(self, hits: Iterable[SearchHit]) -> None:
        with self._lock, self.connection:
            for hit in hits:
                locations = hit.locations or [self._search_location(hit)]
                existing = self.connection.execute(
                    """SELECT * FROM search_hits
                       WHERE match_type=? AND query=? AND value=?
                       ORDER BY created_at LIMIT 1""",
                    (hit.match_type, hit.query, hit.value),
                ).fetchone()
                if existing is not None:
                    merged = self._merge_locations(
                        json.loads(existing["locations_json"] or "[]"), locations
                    )
                    self.connection.execute(
                        "UPDATE search_hits SET locations_json=? WHERE id=?",
                        (json.dumps(merged), existing["id"]),
                    )
                    continue
                self.connection.execute(
                    """INSERT INTO search_hits
                    (id, artifact_id, value, query, match_type, source, location,
                     encoding, transform_chain_json, context, source_kind,
                     origin_path, discovered_path, offset, locations_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        hit.id, hit.artifact_id, hit.value, hit.query, hit.match_type,
                        hit.source, hit.location, hit.encoding,
                        json.dumps(hit.transform_chain), hit.context, hit.source_kind,
                        hit.origin_path, hit.discovered_path, hit.offset,
                        json.dumps(locations), hit.created_at,
                    ),
                )

    def search_hits(self) -> list[SearchHit]:
        return [
            SearchHit(
                id=row["id"], artifact_id=row["artifact_id"], value=row["value"],
                query=row["query"], match_type=row["match_type"], source=row["source"],
                location=row["location"], encoding=row["encoding"],
                transform_chain=json.loads(row["transform_chain_json"]),
                context=row["context"], source_kind=row["source_kind"],
                origin_path=row["origin_path"], discovered_path=row["discovered_path"],
                offset=row["offset"], locations=json.loads(row["locations_json"] or "[]"),
                created_at=row["created_at"],
            )
            for row in self.connection.execute(
                "SELECT * FROM search_hits ORDER BY created_at"
            ).fetchall()
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
            source_path=row["source_path"],
            classifications=[Classification(**item) for item in json.loads(row["classifications_json"])],
        )

    @staticmethod
    def _merge_locations(existing: list[dict[str, Any]], additions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        output = list(existing)
        identities = {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in output}
        for item in additions:
            identity = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if identity not in identities:
                output.append(item)
                identities.add(identity)
        return output

    @staticmethod
    def _location_priority(locations: list[dict[str, Any]]) -> tuple[int, int]:
        if not locations:
            return (-1, -1)
        location = locations[0]
        depth = location.get("artifact_depth")
        kind_priority = {
            "derived_tool_output": 7,
            "derived_record": 6,
            "extracted_evidence": 5,
            "original_evidence": 4,
            "parsed_record": 3,
            "filename": 1,
            "program_log": 0,
        }.get(str(location.get("source_kind") or ""), 1)
        return (int(depth) if isinstance(depth, int) else 0, kind_priority)

    @staticmethod
    def _flag_location(candidate: FlagCandidate) -> dict[str, Any]:
        return {
            "artifact_id": candidate.artifact_id,
            "artifact_depth": None,
            "origin_path": candidate.origin_path,
            "discovered_path": candidate.discovered_path,
            "source": candidate.source,
            "source_kind": candidate.source_kind,
            "location": candidate.location,
            "offset": candidate.offset,
            "encoding": candidate.encoding,
            "transform_chain": candidate.transform_chain,
            "context": candidate.context,
        }

    @staticmethod
    def _search_location(hit: SearchHit) -> dict[str, Any]:
        return {
            "artifact_id": hit.artifact_id,
            "artifact_depth": None,
            "origin_path": hit.origin_path,
            "discovered_path": hit.discovered_path,
            "source": hit.source,
            "source_kind": hit.source_kind,
            "location": hit.location,
            "offset": hit.offset,
            "encoding": hit.encoding,
            "transform_chain": hit.transform_chain,
            "context": hit.context,
        }

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
