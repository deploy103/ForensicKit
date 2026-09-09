from __future__ import annotations

"""Keyboard-first, offline Textual analysis and case-review interface."""

from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
import json
from pathlib import Path
import shutil
import sqlite3
from typing import Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import Artifact, Observation


@dataclass(frozen=True, slots=True)
class ArtifactTreeRow:
    """Presentation-safe artifact lineage row used by the Textual UI."""

    artifact: Artifact
    tree_label: str
    parent_name: str
    lineage: tuple[str, ...]
    lineage_issue: str | None = None


@dataclass(frozen=True, slots=True)
class ClassificationRow:
    """One primary or alternate classification displayed for an artifact."""

    artifact: Artifact
    artifact_type: str
    confidence: float | None
    reason: str
    source: str
    selected: bool


@dataclass(frozen=True, slots=True)
class ObservationRow:
    """Observation joined to its artifact without dropping broken references."""

    observation: Observation
    artifact: Artifact | None
    artifact_name: str
    lineage: tuple[str, ...]
    lineage_issue: str | None = None


def _artifact_sort_key(artifact: Artifact) -> tuple[int, str, str, str]:
    return (
        max(0, artifact.depth), artifact.created_at or "",
        artifact.logical_name.casefold(), artifact.id,
    )


def _lineage_for(
    artifact: Artifact, artifacts_by_id: dict[str, Artifact],
) -> tuple[tuple[str, ...], str | None]:
    """Resolve an artifact's ancestry without trusting stored depth or parent links."""
    chain: list[str] = []
    seen: set[str] = set()
    current = artifact
    issue: str | None = None
    while True:
        if current.id in seen:
            issue = f"cyclic parent link at {current.logical_name} ({current.id})"
            break
        seen.add(current.id)
        chain.append(current.logical_name)
        if current.parent_id is None:
            break
        parent = artifacts_by_id.get(current.parent_id)
        if parent is None:
            issue = f"missing parent {current.parent_id}"
            break
        current = parent
    chain.reverse()
    return tuple(chain), issue


def build_artifact_tree_rows(artifacts: Iterable[Artifact]) -> list[ArtifactTreeRow]:
    """Build a stable, complete tree projection, including orphan/cyclic rows.

    Live case databases can briefly contain inconsistent lineage (or an old case
    may have been manually edited).  Every unique artifact is therefore emitted
    at most once and malformed links are described instead of recursed forever.
    """
    ordered = sorted(artifacts, key=_artifact_sort_key)
    artifacts_by_id: dict[str, Artifact] = {}
    for artifact in ordered:
        artifacts_by_id.setdefault(artifact.id, artifact)

    children: dict[str, list[Artifact]] = {artifact_id: [] for artifact_id in artifacts_by_id}
    roots: list[Artifact] = []
    for artifact in artifacts_by_id.values():
        parent_id = artifact.parent_id
        if parent_id is None or parent_id not in artifacts_by_id or parent_id == artifact.id:
            roots.append(artifact)
        else:
            children[parent_id].append(artifact)
    roots.sort(key=_artifact_sort_key)
    for values in children.values():
        values.sort(key=_artifact_sort_key)

    rows: list[ArtifactTreeRow] = []
    visited: set[str] = set()

    def append_branch(artifact: Artifact, prefix: str, connector: str) -> None:
        if artifact.id in visited:
            return
        visited.add(artifact.id)
        lineage, issue = _lineage_for(artifact, artifacts_by_id)
        if artifact.parent_id == artifact.id:
            issue = f"self-referencing parent {artifact.id}"
        label = f"{prefix}{connector}{artifact.logical_name}"
        if issue:
            label += " [lineage warning]"
        parent = artifacts_by_id.get(artifact.parent_id or "")
        rows.append(ArtifactTreeRow(
            artifact=artifact,
            tree_label=label,
            parent_name=parent.logical_name if parent else (artifact.parent_id or "original evidence"),
            lineage=lineage,
            lineage_issue=issue,
        ))
        branch_children = [item for item in children.get(artifact.id, []) if item.id not in visited]
        for index, child in enumerate(branch_children):
            last = index == len(branch_children) - 1
            ancestor_prefix = "" if connector == "" else ("   " if connector == "└─ " else "│  ")
            append_branch(
                child, prefix + ancestor_prefix,
                "└─ " if last else "├─ ",
            )

    for root in roots:
        append_branch(root, "", "")

    # A parent cycle has no natural root.  Start a synthetic branch for each
    # still-unvisited component so corrupt/partial data cannot disappear.
    for artifact in artifacts_by_id.values():
        if artifact.id not in visited:
            append_branch(artifact, "", "")
    return rows


def build_classification_rows(artifacts: Iterable[Artifact]) -> list[ClassificationRow]:
    """Return primary and alternate detections without hiding unclassified evidence."""
    rows: list[ClassificationRow] = []
    for artifact in sorted(artifacts, key=_artifact_sort_key):
        classifications = list(artifact.classifications)
        selected_types = {item.artifact_type for item in classifications}
        if artifact.artifact_type not in selected_types:
            rows.append(ClassificationRow(
                artifact=artifact,
                artifact_type=artifact.artifact_type or "unknown",
                confidence=None,
                reason=artifact.magic or artifact.mime or "no classifier evidence recorded",
                source="artifact identification",
                selected=True,
            ))
        for classification in classifications:
            rows.append(ClassificationRow(
                artifact=artifact,
                artifact_type=classification.artifact_type,
                confidence=classification.confidence,
                reason=classification.reason,
                source=classification.source,
                selected=classification.artifact_type == artifact.artifact_type,
            ))
    return rows


def build_observation_rows(
    artifacts: Iterable[Artifact], observations: Iterable[Observation],
) -> list[ObservationRow]:
    """Join every observation to lineage while retaining stale live-case rows."""
    artifacts_by_id = {artifact.id: artifact for artifact in artifacts}
    rows: list[ObservationRow] = []
    for observation in observations:
        artifact = artifacts_by_id.get(observation.artifact_id)
        if artifact is None:
            rows.append(ObservationRow(
                observation=observation,
                artifact=None,
                artifact_name=f"unknown artifact ({observation.artifact_id})",
                lineage=(),
                lineage_issue=f"missing artifact {observation.artifact_id}",
            ))
            continue
        lineage, issue = _lineage_for(artifact, artifacts_by_id)
        rows.append(ObservationRow(
            observation=observation,
            artifact=artifact,
            artifact_name=artifact.logical_name,
            lineage=lineage,
            lineage_issue=issue,
        ))
    return rows


def observation_value_preview(value: object, limit: int = 240) -> str:
    """Render arbitrary observation values predictably for a single table cell."""
    try:
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError, RecursionError):
        rendered = repr(value)
    rendered = " ".join(rendered.splitlines())
    return rendered if len(rendered) <= limit else f"{rendered[:max(0, limit - 1)]}…"


def observation_value_detail(value: object, limit: int = 512 * 1024) -> str:
    """Pretty-print a selected value while bounding terminal memory consumption."""
    try:
        rendered = json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError, RecursionError):
        rendered = repr(value)
    if len(rendered) <= limit:
        return rendered
    return f"{rendered[:limit]}\n[observation value truncated at {limit} characters]"


def launch_tui(workspace: Path | None = None, *, _build_only: bool = False) -> int | object:
    """Start the local analysis UI, returning a useful code if unavailable."""
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.widgets import (
            Button, Checkbox, DataTable, Footer, Header, Input, Select, Static,
            TabbedContent, TabPane,
        )
    except ImportError:
        print(
            "Textual TUI dependency is unavailable. The standard installation is incomplete; "
            "reinstall the verified offline ForensicKit wheel set and rerun `forensickit`."
        )
        return 2

    from .config import ForensicKitConfig
    from .models import AnalysisMode
    from .session import AnalysisRequest, AnalysisSession, SessionStatus
    from .workspace import CaseWorkspace

    class ForensicKitTui(App[None]):
        CSS = """
        Screen { layout: vertical; }
        #controls { height: auto; padding: 0 1; border: round $accent; }
        .control-row { height: 3; }
        .control-row Input { width: 1fr; margin-right: 1; }
        .control-row Select { width: 24; margin-right: 1; }
        .control-row Button { margin-right: 1; }
        #status { height: auto; min-height: 3; padding: 0 1; border: round $secondary; }
        #filters { height: 3; padding: 0 1; }
        #filters Input { width: 1fr; margin-right: 1; }
        #filters Button { width: 12; }
        TabbedContent { height: 1fr; }
        TabPane { padding: 0; }
        DataTable { height: 1fr; min-height: 8; }
        #detail-scroll { height: 10; border: round $primary; }
        #detail { height: auto; padding: 1; }
        """
        BINDINGS = [
            ("ctrl+r", "refresh_case", "Refresh"),
            ("ctrl+c", "cancel_analysis", "Cancel"),
            ("c", "copy_selected", "Copy candidate"),
            ("f2", "show_artifacts", "Artifacts"),
            ("f3", "show_classifications", "Detections"),
            ("f4", "show_observations", "Observations"),
            ("f5", "show_findings", "Findings"),
            ("q", "quit", "Quit"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self.case_workspace = workspace.resolve() if workspace is not None else None
            self.session = AnalysisSession()
            self._records: dict[str, list[object]] = {}
            self._tool_names_by_run_id: dict[str, str] = {}
            self._selected_record: object | None = None
            self._progress_lines: deque[str] = deque(maxlen=12)
            self._last_terminal_attempt = 0

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Vertical(id="controls"):
                with Horizontal(classes="control-row"):
                    yield Input(placeholder="Evidence file or directory", id="evidence-path")
                    yield Input(value="cases", placeholder="Case workspace base", id="workspace-base")
                    yield Select(
                        [
                            ("Quick analysis", AnalysisMode.TRIAGE.value),
                            ("Automatic", AnalysisMode.AUTO.value),
                            ("Deep", AnalysisMode.DEEP.value),
                            ("Plan only", AnalysisMode.PLAN.value),
                        ],
                        value=AnalysisMode.TRIAGE.value,
                        allow_blank=False,
                        id="analysis-mode",
                    )
                with Horizontal(classes="control-row"):
                    yield Input(placeholder="Flag prefix, e.g. ACME{", id="flag-prefix")
                    yield Input(placeholder="Exact string", id="exact-string")
                    yield Input(placeholder="Clue/search term", id="search-term")
                    yield Input(placeholder="Advanced regex", id="regex-pattern")
                    yield Checkbox("Enable regex", id="regex-enabled")
                with Horizontal(classes="control-row"):
                    yield Input(placeholder="Selected memory PIDs, comma-separated", id="memory-pids")
                    yield Input(placeholder="Save selected extraction to directory", id="save-directory")
                    yield Button("Analyze", id="analyze", variant="primary")
                    yield Button("Cancel", id="cancel", variant="warning", disabled=True)
                    yield Button("Retry", id="retry", disabled=True)
                    yield Button("Save extracted", id="save-extracted")
            yield Static("Waiting for evidence selection.", id="status")
            with Horizontal(id="filters"):
                yield Input(placeholder="Start ISO time", id="filter-start")
                yield Input(placeholder="End ISO time", id="filter-end")
                yield Input(placeholder="PID", id="filter-pid")
                yield Input(placeholder="User", id="filter-user")
                yield Input(placeholder="Path", id="filter-path")
                yield Input(placeholder="Text", id="filter-text")
                yield Input(value="UTC", placeholder="Display timezone", id="display-timezone")
                yield Button("Apply", id="apply-filter")
            with TabbedContent(initial="summary-pane", id="results"):
                with TabPane("Artifact tree", id="artifacts-pane"):
                    yield DataTable(id="artifacts", cursor_type="row")
                with TabPane("Detection", id="classifications-pane"):
                    yield DataTable(id="classifications", cursor_type="row")
                with TabPane("Observations", id="observations-pane"):
                    yield DataTable(id="observations", cursor_type="row")
                with TabPane("Summary", id="summary-pane"):
                    yield DataTable(id="summary", cursor_type="row")
                with TabPane("Flag candidates", id="flags-pane"):
                    yield DataTable(id="flags", cursor_type="row")
                with TabPane("Memory", id="memory-pane"):
                    yield DataTable(id="memory", cursor_type="row")
                with TabPane("Windows artifacts", id="windows-pane"):
                    yield DataTable(id="windows", cursor_type="row")
                with TabPane("Timeline", id="timeline-pane"):
                    yield DataTable(id="timeline", cursor_type="row")
                with TabPane("Extracted files", id="extracted-pane"):
                    yield DataTable(id="extracted", cursor_type="row")
                with TabPane("Execution log", id="runs-pane"):
                    yield DataTable(id="runs", cursor_type="row")
                with TabPane("Search hits", id="search-pane"):
                    yield DataTable(id="search_hits", cursor_type="row")
                with TabPane("Next actions", id="plans-pane"):
                    yield DataTable(id="plans", cursor_type="row")
            yield VerticalScroll(
                Static("Select a row to inspect its local provenance.", id="detail"),
                id="detail-scroll",
            )
            yield Footer()

        def on_mount(self) -> None:
            self.query_one("#artifacts", DataTable).add_columns("Artifact lineage", "Detected type", "Depth", "Created by")
            self.query_one("#classifications", DataTable).add_columns("Artifact", "Selected", "Classification", "Confidence", "Reason / source")
            self.query_one("#observations", DataTable).add_columns("Artifact", "Observation", "Confidence", "Source", "Value")
            self.query_one("#summary", DataTable).add_columns("Severity", "Finding", "Confidence", "Why")
            self.query_one("#flags", DataTable).add_columns("Candidate", "Locations", "Encoding", "Source")
            self.query_one("#memory", DataTable).add_columns("Severity", "Memory result", "Confidence", "Source")
            self.query_one("#windows", DataTable).add_columns("Severity", "Windows result", "Category", "Confidence")
            self.query_one("#timeline", DataTable).add_columns("Displayed time", "Category", "PID/User", "Path/Title", "Source")
            self.query_one("#extracted", DataTable).add_columns("Extracted file", "Type", "Parent", "SHA-256")
            self.query_one("#runs", DataTable).add_columns("Tool", "Status", "Exit", "Failure / stdout")
            self.query_one("#search_hits", DataTable).add_columns("Type", "Query", "Match", "Locations")
            self.query_one("#plans", DataTable).add_columns("Tool", "Available", "Mode/cost", "Reason")
            self.set_interval(0.2, self._poll_session)
            if self.case_workspace is not None:
                self.action_refresh_case()

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = event.button.id
            if button_id == "analyze":
                self._start_analysis()
            elif button_id == "cancel":
                self.action_cancel_analysis()
            elif button_id == "retry":
                self._retry_analysis()
            elif button_id == "apply-filter":
                if self._validate_filter_inputs():
                    self.action_refresh_case()
            elif button_id == "save-extracted":
                self._save_selected_extraction()

        def _start_analysis(self) -> None:
            evidence_text = self.query_one("#evidence-path", Input).value.strip()
            workspace_text = self.query_one("#workspace-base", Input).value.strip()
            if not evidence_text or not workspace_text:
                self._set_status("Evidence and workspace paths are required.")
                return
            regex = self.query_one("#regex-pattern", Input).value.strip()
            if regex and not self.query_one("#regex-enabled", Checkbox).value:
                self._set_status("Advanced regex text is ignored until ‘Enable regex’ is checked.")
                return
            config = ForensicKitConfig()
            prefix = self.query_one("#flag-prefix", Input).value.strip()
            exact = self.query_one("#exact-string", Input).value
            term = self.query_one("#search-term", Input).value.strip()
            if prefix:
                config.flag_prefixes = [prefix]
            if exact:
                config.exact_strings = [exact]
            if term:
                config.search_terms = [term]
            if regex:
                config.regex_patterns = [regex]
            pid_text = self.query_one("#memory-pids", Input).value.strip()
            try:
                pids = [] if not pid_text else list(dict.fromkeys(
                    int(item.strip(), 0) for item in pid_text.split(",") if item.strip()
                ))
            except ValueError:
                self._set_status("Memory PIDs must be comma-separated positive integers.")
                return
            if len(pids) > 16 or any(pid <= 0 or pid > 0xFFFFFFFF for pid in pids):
                self._set_status("Supply at most 16 positive 32-bit memory PIDs.")
                return
            config.memory_pids = pids
            mode_value = self.query_one("#analysis-mode", Select).value
            try:
                mode = AnalysisMode(str(mode_value))
                request = AnalysisRequest(
                    evidence=(Path(evidence_text),),
                    workspace_base=Path(workspace_text),
                    mode=mode,
                    execute=False if mode is AnalysisMode.PLAN else None,
                    config=config,
                )
                self.session.start(request)
            except (OSError, RuntimeError, ValueError) as exc:
                self._set_status(f"Unable to start analysis: {exc}")
                return
            self._progress_lines.clear()
            self._selected_record = None
            self.query_one("#analyze", Button).disabled = True
            self.query_one("#cancel", Button).disabled = False
            self.query_one("#retry", Button).disabled = True
            self._set_status(f"Running {mode.value} analysis without blocking the result screen…")

        def _retry_analysis(self) -> None:
            try:
                self.session.retry()
            except RuntimeError as exc:
                self._set_status(str(exc))
                return
            self.query_one("#analyze", Button).disabled = True
            self.query_one("#cancel", Button).disabled = False
            self.query_one("#retry", Button).disabled = True
            self._set_status("Retrying the previous analysis in a new case workspace…")

        def action_cancel_analysis(self) -> None:
            if self.session.cancel():
                self._set_status("Cancellation requested; active local tools are being stopped.")

        def action_quit(self) -> None:
            if self.session.snapshot().status is SessionStatus.RUNNING:
                self.session.cancel()
                self.session.wait(5)
            self.exit()

        def _poll_session(self) -> None:
            events = self.session.drain_events()
            refresh_partial = False
            for event in events:
                kind = str(event.get("event") or "progress")
                if kind == "case_created" and event.get("workspace"):
                    self.case_workspace = Path(str(event["workspace"]))
                    refresh_partial = True
                elif kind == "artifact_started":
                    self._progress_lines.append(f"analyzing {event.get('logical_name')}")
                elif kind == "artifact_finished":
                    self._progress_lines.append(f"artifact {event.get('status')}: {event.get('logical_name')}")
                    refresh_partial = True
                elif kind == "tool_started":
                    self._progress_lines.append(f"tool running: {event.get('tool')}")
                elif kind == "tool_finished":
                    self._progress_lines.append(f"tool {event.get('status')}: {event.get('tool')}")
                    refresh_partial = True
                elif kind == "session_finished":
                    self._progress_lines.append(f"analysis {event.get('status')}")
                    refresh_partial = True
            snapshot = self.session.snapshot()
            if refresh_partial and self.case_workspace is not None:
                self._load_case(silent=True)
            if snapshot.status is SessionStatus.RUNNING:
                text = "Analysis running"
                if snapshot.workspace:
                    text += f" · case {snapshot.workspace}"
                if self._progress_lines:
                    text += "\n" + " · ".join(self._progress_lines)
                self._set_status(text)
            elif snapshot.attempt and snapshot.attempt != self._last_terminal_attempt:
                self._last_terminal_attempt = snapshot.attempt
                self.query_one("#analyze", Button).disabled = False
                self.query_one("#cancel", Button).disabled = True
                self.query_one("#retry", Button).disabled = False
                if snapshot.workspace:
                    self.case_workspace = Path(snapshot.workspace)
                    self._load_case(silent=True)
                if snapshot.status is SessionStatus.FAILED:
                    self._set_status(f"Analysis failed: {snapshot.error or 'unknown error'} · Retry is available.")
                elif snapshot.status is SessionStatus.CANCELED:
                    self._set_status("Analysis canceled. Partial case evidence and logs remain available; Retry starts a new case.")
                else:
                    self._set_status(f"Analysis completed · case {snapshot.workspace}")

        def action_refresh_case(self) -> None:
            self._load_case(silent=False)

        def _show_pane(self, pane_id: str) -> None:
            self.query_one("#results", TabbedContent).active = pane_id

        def action_show_artifacts(self) -> None:
            self._show_pane("artifacts-pane")

        def action_show_classifications(self) -> None:
            self._show_pane("classifications-pane")

        def action_show_observations(self) -> None:
            self._show_pane("observations-pane")

        def action_show_findings(self) -> None:
            self._show_pane("summary-pane")

        def _load_case(self, *, silent: bool) -> None:
            if self.case_workspace is None:
                if not silent:
                    self._set_status("No case selected. Enter an evidence path and press Analyze.")
                return
            try:
                with CaseWorkspace.open(self.case_workspace) as case:
                    artifacts = case.database.artifacts()
                    findings = case.database.findings()
                    runs = case.database.tool_runs()
                    flags = case.database.flags()
                    search_hits = case.database.search_hits()
                    observations = case.database.observations()
                    plans = [
                        item.value for item in observations
                        if item.key == "planner.tool_plan" and isinstance(item.value, dict)
                    ]
                    timeline = self._read_timeline(case.root)
                    self._populate_tables(
                        artifacts, observations, findings, runs, flags,
                        search_hits, timeline, plans,
                    )
                    if not silent:
                        evidence_names = ", ".join(
                            item.logical_name for item in artifacts if item.parent_id is None
                        )
                        self._set_status(
                            f"Case {case.case.name} · evidence {evidence_names or 'not registered yet'} · "
                            f"{len(artifacts)} artifacts · {len(observations)} observations · "
                            f"{len(findings)} findings · {len(flags)} flag candidates · "
                            f"{len(runs)} tool runs"
                        )
            except (
                KeyError, LookupError, OSError, TypeError, ValueError,
                json.JSONDecodeError, sqlite3.DatabaseError,
            ) as exc:
                if not silent:
                    self._set_status(f"Unable to open case workspace: {exc}")

        @staticmethod
        def _read_timeline(case_root: Path) -> list[dict[str, object]]:
            report = case_root / "reports" / "report.json"
            try:
                if not report.is_file() or report.stat().st_size > 128 * 1024 * 1024:
                    return []
                payload = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                return []
            rows = payload.get("timeline", []) if isinstance(payload, dict) else []
            return [item for item in rows[:10_000] if isinstance(item, dict)] if isinstance(rows, list) else []

        def _filter_values(self) -> dict[str, str]:
            return {
                "start": self.query_one("#filter-start", Input).value.strip(),
                "end": self.query_one("#filter-end", Input).value.strip(),
                "pid": self.query_one("#filter-pid", Input).value.strip().casefold(),
                "user": self.query_one("#filter-user", Input).value.strip().casefold(),
                "path": self.query_one("#filter-path", Input).value.strip().casefold(),
                "text": self.query_one("#filter-text", Input).value.strip().casefold(),
            }

        def _filter_timestamp(self, value: str) -> float | None:
            if not value:
                return None
            timezone_name = self.query_one("#display-timezone", Input).value.strip() or "UTC"
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=ZoneInfo(timezone_name))
            return parsed.timestamp()

        def _validate_filter_inputs(self) -> bool:
            try:
                ZoneInfo(self.query_one("#display-timezone", Input).value.strip() or "UTC")
                self._filter_timestamp(self.query_one("#filter-start", Input).value.strip())
                self._filter_timestamp(self.query_one("#filter-end", Input).value.strip())
            except (ValueError, ZoneInfoNotFoundError) as exc:
                self._set_status(f"Invalid time filter or display timezone: {exc}")
                return False
            return True

        def _matches(self, value: object, *, timestamp: object = None, pid: object = None, user: object = None, path: object = None) -> bool:
            filters = self._filter_values()
            timestamp_text = str(timestamp or "")
            try:
                current_time = self._filter_timestamp(timestamp_text)
                start_time = self._filter_timestamp(filters["start"])
                end_time = self._filter_timestamp(filters["end"])
            except (ValueError, ZoneInfoNotFoundError):
                return False
            if start_time is not None and (current_time is None or current_time < start_time):
                return False
            if end_time is not None and (current_time is None or current_time > end_time):
                return False
            if filters["pid"] and filters["pid"] != str(pid or "").strip().casefold():
                return False
            if filters["user"] and filters["user"] not in str(user or "").casefold():
                return False
            if filters["path"] and filters["path"] not in str(path or "").casefold():
                return False
            if filters["text"]:
                try:
                    haystack = json.dumps(asdict(value), ensure_ascii=False, default=str) if not isinstance(value, dict) else json.dumps(value, ensure_ascii=False, default=str)
                except TypeError:
                    haystack = str(value)
                if filters["text"] not in haystack.casefold():
                    return False
            return True

        def _populate_tables(self, artifacts, observations, findings, runs, flags, search_hits, timeline, plans) -> None:
            table_ids = (
                "artifacts", "classifications", "observations", "summary", "flags",
                "memory", "windows", "timeline", "extracted", "runs", "search_hits", "plans",
            )
            for table_id in table_ids:
                self.query_one(f"#{table_id}", DataTable).clear(columns=False)
            self._records = {key: [] for key in table_ids}

            artifact_by_id = {item.id: item for item in artifacts}
            self._tool_names_by_run_id = {run.id: run.tool for run in runs}
            for row in build_artifact_tree_rows(artifacts):
                artifact = row.artifact
                if not self._matches(
                    artifact, timestamp=artifact.created_at, path=artifact.logical_name,
                ):
                    continue
                self._records["artifacts"].append(row)
                self.query_one("#artifacts", DataTable).add_row(
                    row.tree_label,
                    artifact.artifact_type,
                    str(artifact.depth),
                    self._artifact_producer(artifact),
                )

            for row in build_classification_rows(artifacts):
                artifact = row.artifact
                if not self._matches(
                    artifact, timestamp=artifact.created_at, path=artifact.logical_name,
                ):
                    continue
                confidence = "—" if row.confidence is None else f"{row.confidence:.2f}"
                self._records["classifications"].append(row)
                self.query_one("#classifications", DataTable).add_row(
                    artifact.logical_name,
                    "yes" if row.selected else "alternate",
                    row.artifact_type,
                    confidence,
                    f"{row.reason} [{row.source}]",
                )

            for row in build_observation_rows(artifacts, observations):
                observation = row.observation
                if not self._matches(
                    observation, timestamp=observation.created_at, path=row.artifact_name,
                ):
                    continue
                self._records["observations"].append(row)
                self.query_one("#observations", DataTable).add_row(
                    row.artifact_name,
                    observation.key,
                    f"{observation.confidence:.2f}",
                    observation.source,
                    observation_value_preview(observation.value),
                )

            for finding in findings:
                artifact = artifact_by_id.get(finding.artifact_id)
                path = artifact.logical_name if artifact else ""
                if not self._matches(finding, timestamp=finding.created_at, path=path):
                    continue
                self._records["summary"].append(finding)
                self.query_one("#summary", DataTable).add_row(
                    finding.severity, finding.title, f"{finding.confidence:.2f}", finding.explanation[:180],
                )
                category = finding.category.casefold()
                if category.startswith("memory"):
                    self._records["memory"].append(finding)
                    self.query_one("#memory", DataTable).add_row(
                        finding.severity, finding.title, f"{finding.confidence:.2f}", finding.source,
                    )
                if category.startswith(("windows", "evtx", "registry", "ntfs", "browser")):
                    self._records["windows"].append(finding)
                    self.query_one("#windows", DataTable).add_row(
                        finding.severity, finding.title, finding.category, f"{finding.confidence:.2f}",
                    )

            for flag in flags:
                if not self._matches(flag, timestamp=flag.created_at, path=flag.discovered_path):
                    continue
                self._records["flags"].append(flag)
                self.query_one("#flags", DataTable).add_row(
                    flag.value, str(len(flag.locations)), flag.encoding, flag.source_kind,
                )

            for row in timeline:
                timestamp = row.get("timestamp_utc") or row.get("timestamp")
                pid = row.get("process_id")
                user = row.get("user") or row.get("target_user")
                path = row.get("path") or row.get("process_path") or row.get("file_name")
                if not self._matches(row, timestamp=timestamp, pid=pid, user=user, path=path):
                    continue
                self._records["timeline"].append(row)
                actor = "/".join(str(item) for item in (pid, user) if item not in {None, ""})
                description = path or row.get("title") or row.get("event_id") or ""
                self.query_one("#timeline", DataTable).add_row(
                    self._display_time(timestamp), str(row.get("category") or ""), actor,
                    str(description), str(row.get("sources") or ""),
                )

            for artifact in artifacts:
                if artifact.parent_id is None or not self._matches(artifact, timestamp=artifact.created_at, path=artifact.logical_name):
                    continue
                self._records["extracted"].append(artifact)
                parent = artifact_by_id.get(artifact.parent_id)
                self.query_one("#extracted", DataTable).add_row(
                    artifact.logical_name, artifact.artifact_type,
                    parent.logical_name if parent else artifact.parent_id or "", artifact.sha256[:16],
                )

            for run in runs:
                artifact = artifact_by_id.get(run.artifact_id)
                if not self._matches(run, timestamp=run.started_at, path=artifact.logical_name if artifact else ""):
                    continue
                self._records["runs"].append(run)
                failure = run.error or run.stdout_path or ""
                self.query_one("#runs", DataTable).add_row(
                    run.tool, run.status.value, "" if run.exit_code is None else str(run.exit_code), failure[:240],
                )

            for hit in search_hits:
                if not self._matches(hit, timestamp=hit.created_at, path=hit.discovered_path):
                    continue
                self._records["search_hits"].append(hit)
                self.query_one("#search_hits", DataTable).add_row(
                    hit.match_type, hit.query, hit.value, str(len(hit.locations)),
                )

            for plan in plans:
                if not self._matches(plan):
                    continue
                self._records["plans"].append(plan)
                reasons = plan.get("reasons") if isinstance(plan.get("reasons"), list) else []
                self.query_one("#plans", DataTable).add_row(
                    str(plan.get("tool") or ""), "yes" if plan.get("available") else "no",
                    f"{plan.get('mode') or ''}/{plan.get('cost') or ''}",
                    "; ".join(str(item) for item in reasons[:5]),
                )

        def _display_time(self, value: object) -> str:
            if not isinstance(value, str) or not value:
                return ""
            timezone_name = self.query_one("#display-timezone", Input).value.strip() or "UTC"
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    return value
                return parsed.astimezone(ZoneInfo(timezone_name)).isoformat()
            except (ValueError, ZoneInfoNotFoundError):
                return value

        def _artifact_producer(self, artifact: Artifact) -> str:
            run_id = artifact.created_by_tool_run_id
            if run_id:
                tool = self._tool_names_by_run_id.get(run_id)
                return f"{tool} ({run_id})" if tool else f"tool run {run_id}"
            return "evidence ingestion" if artifact.parent_id is None else "built-in extraction"

        def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
            table_id = event.data_table.id or ""
            records = self._records.get(table_id, [])
            if event.cursor_row < 0 or event.cursor_row >= len(records):
                return
            record = records[event.cursor_row]
            self._selected_record = record
            detail = self.query_one("#detail", Static)
            if table_id == "artifacts":
                artifact = record.artifact
                classifications = "\n".join(
                    f"- {item.artifact_type} ({item.confidence:.2f}): {item.reason} [{item.source}]"
                    for item in artifact.classifications
                ) or "- no alternate classification records"
                issue = f"\nLineage warning: {record.lineage_issue}" if record.lineage_issue else ""
                detail.update(
                    f"Artifact: {artifact.logical_name}\nID: {artifact.id}\n"
                    f"Lineage: {' → '.join(record.lineage)}{issue}\n"
                    f"Stored path: {artifact.path}\nOriginal source: {artifact.source_path or 'derived artifact'}\n"
                    f"SHA-256: {artifact.sha256}\nSize: {artifact.size} bytes\n"
                    f"Detected type: {artifact.artifact_type}\nMIME: {artifact.mime or 'unknown'}\n"
                    f"Magic: {artifact.magic or 'unknown'}\nParent: {record.parent_name}\n"
                    f"Created by: {self._artifact_producer(artifact)}\n\n"
                    f"Classifications:\n{classifications}"
                )
            elif table_id == "classifications":
                artifact = record.artifact
                confidence = "not separately recorded" if record.confidence is None else f"{record.confidence:.2f}"
                detail.update(
                    f"Artifact: {artifact.logical_name} ({artifact.id})\n"
                    f"Selected artifact type: {artifact.artifact_type}\n"
                    f"Displayed classification: {record.artifact_type}\n"
                    f"Selected: {'yes' if record.selected else 'alternate'}\n"
                    f"Confidence: {confidence}\nReason: {record.reason}\nSource: {record.source}\n"
                    f"MIME: {artifact.mime or 'unknown'}\nMagic: {artifact.magic or 'unknown'}"
                )
            elif table_id == "observations":
                observation = record.observation
                issue = f"\nLineage warning: {record.lineage_issue}" if record.lineage_issue else ""
                detail.update(
                    f"Observation: {observation.key}\nID: {observation.id}\n"
                    f"Artifact: {record.artifact_name}\n"
                    f"Lineage: {' → '.join(record.lineage) or 'unavailable'}{issue}\n"
                    f"Source: {observation.source}\nConfidence: {observation.confidence:.2f}\n"
                    f"Recorded: {observation.created_at}\n\n"
                    f"Value:\n{observation_value_detail(observation.value)}"
                )
            elif table_id in {"summary", "memory", "windows"}:
                evidence = "\n".join(f"- {item}" for item in record.supporting_evidence[:50]) or "- none"
                detail.update(
                    f"{record.title}\nCategory: {record.category}\nSeverity/confidence: {record.severity} / {record.confidence:.2f}\n"
                    f"Source: {record.source}\nWhy shown: {record.explanation}\n\nOriginal evidence/records:\n{evidence}"
                )
            elif table_id == "flags":
                detail.update(
                    f"Flag candidate (not automatically confirmed): {record.value}\nConfidence: {record.confidence:.2f}\n"
                    f"Transform: {' → '.join(record.transform_chain)}\nSource: {record.source} ({record.source_kind})\n"
                    + "\n".join(
                        f"- origin={item.get('origin_path')} found={item.get('discovered_path')} location={item.get('location')} "
                        f"encoding={item.get('encoding')} transform={' → '.join(item.get('transform_chain') or [])}\n  context={item.get('context') or ''}"
                        for item in record.locations[:50]
                    )
                )
            elif table_id == "search_hits":
                detail.update(
                    f"Search hit ({record.match_type})\nQuery: {record.query}\nMatch: {record.value}\n"
                    + "\n".join(
                        f"- {item.get('discovered_path')}: {item.get('location')}\n  context={item.get('context') or ''}"
                        for item in record.locations[:50]
                    )
                )
            elif table_id == "runs":
                stdout = self._raw_output_preview(record.stdout_path, "stdout")
                stderr = self._raw_output_preview(record.stderr_path, "stderr")
                detail.update(
                    f"Tool: {record.tool}\nStatus: {record.status.value}; exit={record.exit_code}; timeout={record.timeout:g}s\n"
                    f"Reproducible argv array: {json.dumps(record.command_argv, ensure_ascii=False)}\n"
                    f"Failure: {record.error or 'none'}\n\n{stdout}\n\n{stderr}"
                )
            elif table_id == "extracted":
                detail.update(
                    f"Extracted artifact: {record.logical_name}\nID: {record.id}\nStored path: {record.path}\n"
                    f"SHA-256: {record.sha256}\nParent: {record.parent_id}\nCreated by tool run: {record.created_by_tool_run_id or 'built-in extraction'}"
                )
            elif table_id == "timeline":
                detail.update(json.dumps(record, indent=2, ensure_ascii=False, default=str))
            elif table_id == "plans":
                detail.update(
                    f"Next analysis option: {record.get('tool')}\nAvailable offline: {record.get('available')}\n"
                    f"Mode/cost: {record.get('mode')} / {record.get('cost')}\nTimeout: {record.get('timeout')}s\n"
                    f"Why planned: {'; '.join(str(item) for item in record.get('reasons', []))}\n"
                    f"Reproducible argv array: {json.dumps(record.get('command_argv') or [], ensure_ascii=False)}"
                )

        def action_copy_selected(self) -> None:
            value = getattr(self._selected_record, "value", None)
            if not isinstance(value, str):
                self._set_status("Select a flag candidate or search hit before copying.")
                return
            try:
                self.copy_to_clipboard(value)
            except Exception as exc:
                self._set_status(f"Clipboard is unavailable in this terminal: {exc}")
                return
            self._set_status("Selected candidate text copied to the terminal clipboard.")

        def _save_selected_extraction(self) -> None:
            artifact = self._selected_record
            if isinstance(artifact, ArtifactTreeRow):
                artifact = artifact.artifact
            destination_text = self.query_one("#save-directory", Input).value.strip()
            if not isinstance(artifact, Artifact) or artifact.parent_id is None:
                self._set_status("Select a row in Extracted files first.")
                return
            if not destination_text or self.case_workspace is None:
                self._set_status("Enter an explicit destination directory.")
                return
            try:
                destination = Path(destination_text).expanduser().resolve()
                destination.mkdir(parents=True, exist_ok=True)
                if not destination.is_dir():
                    raise ValueError("destination is not a directory")
                with CaseWorkspace.open(self.case_workspace) as case:
                    source = case.resolve_stored_path(artifact.path)
                    name = Path(artifact.logical_name).name or artifact.id
                    target = destination / name
                    if target.exists():
                        target = destination / f"{Path(name).stem}-{artifact.sha256[:12]}{Path(name).suffix}"
                    if target.exists():
                        raise FileExistsError(f"destination already exists: {target}")
                    shutil.copy2(source, target)
            except (LookupError, OSError, ValueError) as exc:
                self._set_status(f"Unable to save extracted file: {exc}")
                return
            self._set_status(f"Saved extracted file to {target}")

        def _raw_output_preview(self, stored_path: str | None, label: str) -> str:
            if not stored_path or self.case_workspace is None:
                return f"{label}: no preserved output"
            try:
                with CaseWorkspace.open(self.case_workspace) as case:
                    path = case.resolve_stored_path(stored_path)
                    with path.open("rb") as stream:
                        raw = stream.read(64 * 1024 + 1)
                suffix = "\n[preview truncated at 64 KiB]" if len(raw) > 64 * 1024 else ""
                return f"{label} ({stored_path}):\n{raw[:64 * 1024].decode('utf-8', errors='replace')}{suffix}"
            except (LookupError, OSError, ValueError) as exc:
                return f"{label}: unable to read preserved output ({exc})"

        def _set_status(self, text: str) -> None:
            self.query_one("#status", Static).update(text)

    app = ForensicKitTui()
    if _build_only:
        return app
    app.run()
    return 0


__all__ = [
    "ArtifactTreeRow", "ClassificationRow", "ObservationRow",
    "build_artifact_tree_rows", "build_classification_rows", "build_observation_rows",
    "launch_tui", "observation_value_detail", "observation_value_preview",
]
