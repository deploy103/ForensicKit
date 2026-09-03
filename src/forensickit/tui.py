from __future__ import annotations

"""Keyboard-first Textual case viewer.

The TUI is deliberately a read-only viewer: evidence ingestion and tool runs
remain explicit CLI actions, while a competition analyst can review the case
database without accidentally altering original evidence.  Textual is loaded
lazily so headless CLI commands do not import terminal UI dependencies.
"""

from pathlib import Path


def launch_tui(workspace: Path | None = None) -> int:
    """Start the local case viewer, returning a useful code if unavailable."""
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Horizontal, VerticalScroll
        from textual.widgets import DataTable, Footer, Header, Static
    except ImportError:
        print(
            "Textual TUI dependency is unavailable. Install the offline package extra "
            "`forensickit[tui]` (or Textual) and rerun `forensickit`."
        )
        return 2

    from .workspace import CaseWorkspace

    class ForensicKitTui(App[None]):
        CSS = """
        Screen { layout: vertical; }
        #summary { height: auto; padding: 1; border: round $accent; }
        DataTable { height: 1fr; min-height: 8; border: round $secondary; }
        #detail { height: 7; padding: 1; border: round $primary; overflow-y: auto; }
        Horizontal { height: 2fr; }
        """
        BINDINGS = [
            ("r", "refresh_case", "Refresh"),
            ("q", "quit", "Quit"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self.case_workspace = workspace
            self._records: dict[str, list[object]] = {
                "artifacts": [], "findings": [], "runs": [], "flags": [],
            }

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield Static("Loading local case database…", id="summary")
            with Horizontal():
                yield DataTable(id="artifacts", cursor_type="row")
                yield DataTable(id="findings", cursor_type="row")
            with Horizontal():
                yield DataTable(id="runs", cursor_type="row")
                yield DataTable(id="flags", cursor_type="row")
            yield VerticalScroll(Static("Select a row to inspect locally stored details.", id="detail"))
            yield Footer()

        def on_mount(self) -> None:
            self.query_one("#artifacts", DataTable).add_columns("Artifact", "Type", "Depth", "SHA-256")
            self.query_one("#findings", DataTable).add_columns("Severity", "Finding", "Confidence")
            self.query_one("#runs", DataTable).add_columns("Tool", "Status", "Exit", "Raw stdout")
            self.query_one("#flags", DataTable).add_columns("Flag candidate", "Transform chain", "Source")
            self.action_refresh_case()

        def action_refresh_case(self) -> None:
            summary = self.query_one("#summary", Static)
            detail = self.query_one("#detail", Static)
            for table_id in ("#artifacts", "#findings", "#runs", "#flags"):
                self.query_one(table_id, DataTable).clear(columns=False)
            self._records = {"artifacts": [], "findings": [], "runs": [], "flags": []}
            if self.case_workspace is None:
                summary.update(
                    "No case workspace selected. Run `forensickit analyze FILE --workspace cases` "
                    "then start `forensickit tui cases/<case-directory>`.\n\n"
                    "Keys: r refresh · q quit"
                )
                detail.update("The TUI never opens network connections or mutates evidence.")
                return
            try:
                with CaseWorkspace.open(self.case_workspace) as case:
                    artifacts = case.database.artifacts()
                    findings = case.database.findings()
                    runs = case.database.tool_runs()
                    flags = case.database.flags()
                    self._records = {
                        "artifacts": artifacts, "findings": findings, "runs": runs, "flags": flags,
                    }
                    summary.update(
                        f"Case: {case.case.name}\nWorkspace: {case.root}\n"
                        f"Artifacts: {len(artifacts)} · Findings: {len(findings)} · "
                        f"Tool runs: {len(runs)} · Flag candidates: {len(flags)}\n"
                        "Keys: r refresh · q quit"
                    )
                    artifact_table = self.query_one("#artifacts", DataTable)
                    for artifact in artifacts:
                        artifact_table.add_row(
                            f"{'  ' * artifact.depth}{'└─ ' if artifact.depth else ''}{artifact.logical_name}",
                            artifact.artifact_type, str(artifact.depth), artifact.sha256[:16],
                        )
                    finding_table = self.query_one("#findings", DataTable)
                    for finding in findings:
                        finding_table.add_row(finding.severity, finding.title, f"{finding.confidence:.2f}")
                    run_table = self.query_one("#runs", DataTable)
                    for run in runs:
                        run_table.add_row(run.tool, run.status.value, str(run.exit_code), run.stdout_path or "")
                    flag_table = self.query_one("#flags", DataTable)
                    for flag in flags:
                        flag_table.add_row(flag.value, " → ".join(flag.transform_chain), flag.source)
                    detail.update(
                        "Raw stdout/stderr paths are shown in Tool runs and remain in this case workspace. "
                        "Use the headless `artifacts`, `findings`, `flags`, or `report` commands for scripted review."
                    )
            except (LookupError, OSError, ValueError) as exc:
                summary.update(f"Unable to open case workspace: {exc}")
                detail.update("Select a directory containing case.db.")

        def on_data_table_row_selected(self, event) -> None:
            """Show local provenance when an artifact/finding/run/flag is selected."""
            table_id = event.data_table.id or ""
            records = self._records.get(table_id, [])
            if event.cursor_row < 0 or event.cursor_row >= len(records):
                return
            record = records[event.cursor_row]
            detail = self.query_one("#detail", Static)
            if table_id == "artifacts":
                artifact = record
                detail.update(
                    f"Artifact: {artifact.logical_name}\nID: {artifact.id}\n"
                    f"Path: {artifact.path}\nSHA-256: {artifact.sha256}\n"
                    f"Parent: {artifact.parent_id or 'root evidence'}\n"
                    f"Magic: {artifact.magic or 'unknown'}"
                )
            elif table_id == "findings":
                finding = record
                evidence = "\n".join(f"- {item}" for item in finding.supporting_evidence[:30]) or "- none"
                detail.update(
                    f"{finding.title}\nCategory: {finding.category}\n"
                    f"Severity/confidence: {finding.severity} / {finding.confidence:.2f}\n"
                    f"Source: {finding.source}\n\n{finding.explanation}\n\nEvidence:\n{evidence}"
                )
            elif table_id == "flags":
                flag = record
                detail.update(
                    f"Flag candidate: {flag.value}\nConfidence: {flag.confidence:.2f}\n"
                    f"Transform chain: {' → '.join(flag.transform_chain)}\n"
                    f"Source: {flag.source}\nLocation: {flag.location or 'unknown'}"
                )
            elif table_id == "runs":
                run = record
                preview = self._raw_output_preview(run.stdout_path, "stdout")
                stderr_preview = self._raw_output_preview(run.stderr_path, "stderr")
                command = " ".join(run.command_argv) or "(command was not built)"
                detail.update(
                    f"Tool: {run.tool}\nStatus: {run.status.value}; exit={run.exit_code}; timeout={run.timeout:g}s\n"
                    f"argv: {command}\n\n{preview}\n\n{stderr_preview}"
                )

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

    ForensicKitTui().run()
    return 0


__all__ = ["launch_tui"]
