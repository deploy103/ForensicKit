from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Iterable, Mapping

from ..models import Artifact, Finding, Observation, ToolRun, ToolRunStatus, utc_now
from ..workspace import CaseWorkspace
from .parsers import OutputParserRegistry, ParsedToolOutput
from .registry import ToolDefinition, ToolRegistry


@dataclass(slots=True)
class ToolExecutionResult:
    run: ToolRun
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    stdout_preview: str = ""
    stderr_preview: str = ""
    generated_directory: str | None = None

    @property
    def status(self) -> ToolRunStatus:
        return self.run.status


class ToolRunner:
    """Runs trusted forensic utilities without a shell and persists exact provenance."""

    def __init__(
        self,
        workspace: CaseWorkspace,
        registry: ToolRegistry | None = None,
        parsers: OutputParserRegistry | None = None,
        *,
        preview_bytes: int = 64 * 1024,
        parser_bytes: int = 2 * 1024 * 1024,
        termination_grace: float = 0.5,
        max_generated_files: int = 1_000,
        max_timeout: float | None = None,
        cancel_event: Event | None = None,
        max_memory_bytes: int | None = None,
        max_output_file_bytes: int | None = None,
    ) -> None:
        if preview_bytes <= 0 or parser_bytes <= 0 or max_generated_files <= 0 or (max_timeout is not None and max_timeout <= 0) or (max_memory_bytes is not None and max_memory_bytes <= 0) or (max_output_file_bytes is not None and max_output_file_bytes <= 0):
            raise ValueError("output bounds must be positive")
        self.workspace = workspace
        self.registry = registry or ToolRegistry.default()
        self.parsers = parsers or OutputParserRegistry.default()
        self.preview_bytes = preview_bytes
        self.parser_bytes = parser_bytes
        self.termination_grace = max(0.05, termination_grace)
        self.max_generated_files = max_generated_files
        self.max_timeout = max_timeout
        self.cancel_event = cancel_event
        self.max_memory_bytes = max_memory_bytes
        self.max_output_file_bytes = max_output_file_bytes

    def run(
        self,
        tool: str,
        artifact: Artifact,
        *,
        mode: str = "default",
        timeout: float | None = None,
        extra_args: Iterable[str] = (),
        output_directory: Path | None = None,
        template_values: Mapping[str, str] | None = None,
    ) -> ToolExecutionResult:
        """Execute one catalog command and return its persisted normalized result.

        `artifact.path` is deliberately resolved through CaseWorkspace rather than
        treated as a host path.  `extra_args` remain distinct argv values.
        """

        definition: ToolDefinition | None
        try:
            definition = self.registry.get(tool)
        except KeyError:
            definition = None

        effective_timeout = float(timeout if timeout is not None else (definition.timeout if definition else 60.0))
        if self.max_timeout is not None:
            effective_timeout = min(effective_timeout, self.max_timeout)
        if effective_timeout <= 0:
            raise ValueError("tool timeout must be positive")

        run = ToolRun(
            artifact_id=artifact.id,
            tool=definition.name if definition else tool,
            command_argv=[],
            timeout=effective_timeout,
        )
        stdout_file = self.workspace.path("outputs", f"{run.id}.stdout.log")
        stderr_file = self.workspace.path("logs", f"{run.id}.stderr.log")
        generated_dir = self._generated_directory(run.id, output_directory)
        generated_dir.mkdir(parents=True, exist_ok=False)
        stdout_file.touch(exist_ok=False)
        stderr_file.touch(exist_ok=False)
        run.stdout_path = self.workspace.relative(stdout_file)
        run.stderr_path = self.workspace.relative(stderr_file)

        if definition is None:
            run.status = ToolRunStatus.SKIPPED
            run.error = f"unknown tool: {tool}"
            run.ended_at = utc_now()
            self.workspace.database.add_tool_run(run)
            return self._finish_without_parser(run, generated_dir, available=False)

        executable = self.registry.resolve_executable(definition)
        if executable is None:
            run.status = ToolRunStatus.SKIPPED
            run.error = f"tool executable not found: {definition.name} ({', '.join(definition.executable_candidates)})"
            run.ended_at = utc_now()
            self.workspace.database.add_tool_run(run)
            return self._finish_without_parser(run, generated_dir, available=False)

        try:
            evidence_path = self.workspace.resolve_stored_path(artifact.path)
            run.command_argv = self.registry.build_command(
                definition,
                evidence_path,
                mode=mode,
                output_directory=generated_dir,
                executable=executable,
                extra_args=extra_args,
                template_values=template_values,
            )
        except (OSError, ValueError) as exc:
            run.status = ToolRunStatus.FAILED
            run.error = f"command preparation failed: {exc}"
            run.ended_at = utc_now()
            self.workspace.database.add_tool_run(run)
            return self._finish_without_parser(run, generated_dir, available=True)

        self.workspace.database.add_tool_run(run)
        if self.cancel_event is not None and self.cancel_event.is_set():
            run.status = ToolRunStatus.CANCELED
            run.error = "tool canceled before launch"
            run.ended_at = utc_now()
            self.workspace.database.update_tool_run(run)
            return self._finish_without_parser(run, generated_dir, available=True)
        run.started_at = utc_now()
        run.status = ToolRunStatus.RUNNING
        self.workspace.database.update_tool_run(run)

        process: subprocess.Popen[bytes] | None = None
        try:
            with stdout_file.open("wb") as stdout_handle, stderr_file.open("wb") as stderr_handle:
                popen_options: dict[str, object] = {}
                if os.name == "posix":
                    popen_options["start_new_session"] = True
                elif os.name == "nt":  # pragma: no cover - competition targets are Linux.
                    popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
                process = subprocess.Popen(
                    run.command_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    cwd=generated_dir,
                    shell=False,
                    close_fds=True,
                    **popen_options,
                )
                self._apply_process_limits(process)
                deadline = time.monotonic() + effective_timeout
                while True:
                    if self.cancel_event is not None and self.cancel_event.is_set():
                        self._terminate_process_group(process)
                        run.exit_code = process.returncode
                        run.status = ToolRunStatus.CANCELED
                        run.error = "tool canceled by analyst"
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._terminate_process_group(process)
                        run.exit_code = process.returncode
                        run.status = ToolRunStatus.TIMED_OUT
                        run.error = f"tool exceeded {effective_timeout:g} second timeout"
                        break
                    try:
                        run.exit_code = process.wait(timeout=min(0.25, remaining))
                    except subprocess.TimeoutExpired:
                        continue
                    run.status = (
                        ToolRunStatus.COMPLETED if run.exit_code == 0 else ToolRunStatus.FAILED
                    )
                    if run.exit_code != 0:
                        run.error = f"tool exited with status {run.exit_code}"
                    break
        except OSError as exc:
            if process is not None and process.poll() is None:
                self._terminate_process_group(process)
            run.exit_code = process.returncode if process is not None else None
            run.status = ToolRunStatus.FAILED
            run.error = f"tool launch failed: {exc}"
        except KeyboardInterrupt:
            if process is not None and process.poll() is None:
                self._terminate_process_group(process)
            run.exit_code = process.returncode if process is not None else None
            run.status = ToolRunStatus.CANCELED
            run.error = "tool canceled by analyst interrupt"
        finally:
            run.ended_at = utc_now()

        run.generated_files, generated_truncated = self._generated_files(generated_dir)
        self.workspace.database.update_tool_run(run)

        stdout_for_parser = self._read_bounded(stdout_file, self.parser_bytes)
        stderr_for_parser = self._read_bounded(stderr_file, self.parser_bytes)
        parsed = self.parsers.parse(
            definition.parser,
            artifact_id=artifact.id,
            stdout=stdout_for_parser,
            stderr=stderr_for_parser,
            exit_code=run.exit_code,
            tool=definition.name,
        )
        # Some tools (notably Hayabusa) intentionally write their structured
        # timeline to the output directory rather than stdout. Parse only the
        # bounded CSV artifact and retain it as a separately registered child
        # later in the engine, so normalized leads never replace evidence.
        if definition.name == "hayabusa":
            for generated in run.generated_files:
                if not generated.lower().endswith(".csv"):
                    continue
                try:
                    csv_path = self.workspace.resolve_stored_path(generated)
                    csv_output = self._read_bounded(csv_path, self.parser_bytes)
                except OSError:
                    continue
                parsed_csv = self.parsers.parse(
                    "event_csv",
                    artifact_id=artifact.id,
                    stdout=csv_output,
                    stderr="",
                    exit_code=run.exit_code,
                    tool=definition.name,
                )
                parsed.observations.extend(parsed_csv.observations)
                parsed.findings.extend(parsed_csv.findings)
        if definition.name in {"aleapp", "ileapp"}:
            structured_reports: list[str] = []
            for generated in run.generated_files:
                if not generated.lower().endswith((".csv", ".json", ".jsonl")):
                    continue
                try:
                    report_path = self.workspace.resolve_stored_path(generated)
                    report_output = self._read_bounded(report_path, self.parser_bytes)
                except OSError:
                    continue
                parsed_report = self.parsers.parse(
                    "leapp",
                    artifact_id=artifact.id,
                    stdout=report_output,
                    stderr="",
                    exit_code=run.exit_code,
                    tool=definition.name,
                )
                parsed.observations.extend(parsed_report.observations)
                parsed.findings.extend(parsed_report.findings)
                structured_reports.append(generated)
            if structured_reports:
                parsed.observations.append(
                    Observation(
                        artifact_id=artifact.id,
                        key=f"mobile.{definition.name}.structured_reports",
                        value=structured_reports[: self.max_generated_files],
                        source=f"tool:{definition.name}",
                        confidence=1.0,
                    )
                )
        if definition.name == "bulk_extractor":
            feature_files: list[dict[str, object]] = []
            useful_names = {"url.txt", "email.txt", "domain.txt", "telephone.txt", "ccn.txt", "wordlist.txt"}
            for generated in run.generated_files:
                if Path(generated).name.lower() not in useful_names:
                    continue
                try:
                    feature_path = self.workspace.resolve_stored_path(generated)
                    feature_output = self._read_bounded(feature_path, self.parser_bytes)
                except OSError:
                    continue
                parsed_feature = self.parsers.parse(
                    "bulk_extractor_feature",
                    artifact_id=artifact.id,
                    stdout=feature_output,
                    stderr="",
                    exit_code=run.exit_code,
                    tool=definition.name,
                )
                # Keep generated-file identity on each normalized lead so
                # repeated scanner outputs never lose their provenance.
                for observation in parsed_feature.observations:
                    observation.key = f"{observation.key}.{Path(generated).stem.lower()}"
                parsed.observations.extend(parsed_feature.observations)
                feature_files.append({"path": generated, "kind": Path(generated).stem.lower()})
            if feature_files:
                parsed.observations.append(
                    Observation(
                        artifact_id=artifact.id,
                        key="bulk_extractor.feature_files",
                        value=feature_files,
                        source="tool:bulk_extractor",
                        confidence=1.0,
                    )
                )
        if definition.name == "tshark" and run.generated_files:
            # ``--export-objects http,<dir>`` writes recovered application
            # objects directly to the run directory.  Record a compact
            # inventory before the extraction manager promotes each file to a
            # recursive child artifact.  This bridges packet-tool execution
            # and evidence recursion without assuming a filename is safe or
            # attempting to parse arbitrary exported bytes here.
            exported: list[dict[str, object]] = []
            for stored_path in run.generated_files:
                try:
                    generated_path = self.workspace.resolve_stored_path(stored_path)
                    exported.append({
                        "path": stored_path,
                        "name": generated_path.name[:512],
                        "size": generated_path.stat().st_size,
                    })
                except OSError:
                    continue
            if exported:
                parsed.observations.extend((
                    Observation(
                        artifact_id=artifact.id,
                        key="pcap.tshark.exported_http_object_count",
                        value=len(exported),
                        source="tool:tshark",
                        confidence=1.0,
                    ),
                    Observation(
                        artifact_id=artifact.id,
                        key="pcap.tshark.exported_http_objects",
                        value=exported,
                        source="tool:tshark",
                        confidence=1.0,
                    ),
                ))
                parsed.findings.append(
                    Finding(
                        artifact_id=artifact.id,
                        title=f"tshark exported {len(exported)} HTTP object(s)",
                        category="pcap_exported_object",
                        severity="info",
                        confidence=1.0,
                        explanation=(
                            "tshark recovered application-layer HTTP objects. "
                            "Each retained output is promoted into the case as a child artifact for deterministic triage."
                        ),
                        source="tool:tshark",
                        supporting_evidence=[item["path"] for item in exported[:100]],
                    )
                )
        if definition.name in {"pdfdetach", "pdfimages"} and run.generated_files:
            # Poppler writes recovered attachments/images to an output prefix
            # or its current directory instead of stdout.  Preserve a compact
            # typed inventory before those bytes become recursive child
            # artifacts, so a report can distinguish PDF recovery output from
            # an arbitrary tool-generated file without inspecting the child.
            generated_kind = "attachments" if definition.name == "pdfdetach" else "images"
            inventory: list[dict[str, object]] = []
            for stored_path in run.generated_files:
                try:
                    generated_path = self.workspace.resolve_stored_path(stored_path)
                    inventory.append({
                        "path": stored_path,
                        "name": generated_path.name[:512],
                        "size": generated_path.stat().st_size,
                    })
                except OSError:
                    continue
            if inventory:
                parsed.observations.append(
                    Observation(
                        artifact_id=artifact.id,
                        key=f"pdf.{definition.name}.{generated_kind}",
                        value=inventory,
                        source=f"tool:{definition.name}",
                        confidence=1.0,
                    )
                )
                parsed.findings.append(
                    Finding(
                        artifact_id=artifact.id,
                        title=f"{definition.name} recovered {len(inventory)} PDF {generated_kind}",
                        category=(
                            "pdf_attachment_recovery"
                            if definition.name == "pdfdetach"
                            else "pdf_image_recovery"
                        ),
                        severity="info",
                        confidence=1.0,
                        explanation=(
                            "Poppler wrote recovered PDF content into the isolated tool-output directory. "
                            "Each retained file is promoted to a lineage-preserving child artifact for recursive analysis."
                        ),
                        source=f"tool:{definition.name}",
                        supporting_evidence=[item["path"] for item in inventory[:100]],
                    )
                )
        if run.generated_files:
            parsed.observations.extend((
                Observation(
                    artifact_id=artifact.id,
                    key=f"tool.{definition.name}.generated_file_count",
                    value=len(run.generated_files),
                    source=f"tool_runner:{run.id}",
                    confidence=1.0,
                ),
                Observation(
                    artifact_id=artifact.id,
                    key=f"tool.{definition.name}.generated_files",
                    value=run.generated_files[: self.max_generated_files],
                    source=f"tool_runner:{run.id}",
                    confidence=1.0,
                ),
            ))
        if generated_truncated:
            parsed.observations.append(
                Observation(
                    artifact_id=artifact.id,
                    key=f"tool.{definition.name}.generated_files_truncated",
                    value={"limit": self.max_generated_files},
                    source=f"tool_runner:{run.id}",
                    confidence=1.0,
                )
            )
        self._attach_run_provenance(parsed, run)
        self._persist_parsed(parsed)
        return ToolExecutionResult(
            run=run,
            observations=parsed.observations,
            findings=parsed.findings,
            stdout_preview=self._read_bounded(stdout_file, self.preview_bytes),
            stderr_preview=self._read_bounded(stderr_file, self.preview_bytes),
            generated_directory=self.workspace.relative(generated_dir),
        )

    def _finish_without_parser(
        self,
        run: ToolRun,
        generated_dir: Path,
        *,
        available: bool,
    ) -> ToolExecutionResult:
        observation = Observation(
            artifact_id=run.artifact_id,
            key=f"tool.{run.tool}.available",
            value=available,
            source=f"tool_runner:{run.id}",
            confidence=1.0,
        )
        self.workspace.database.add_observations([observation])
        return ToolExecutionResult(
            run=run,
            observations=[observation],
            generated_directory=self.workspace.relative(generated_dir),
        )

    def _generated_directory(self, run_id: str, requested: Path | None) -> Path:
        if requested is None:
            return self.workspace.path("extracted", run_id)
        requested_path = Path(requested)
        candidate = (
            requested_path.resolve()
            if requested_path.is_absolute()
            else (self.workspace.root / requested_path).resolve()
        )
        if candidate == self.workspace.root or self.workspace.root not in candidate.parents:
            raise ValueError("generated output directory must be inside the case workspace")
        return candidate

    def _generated_files(self, directory: Path) -> tuple[list[str], bool]:
        files: list[str] = []
        truncated = False
        for path in sorted(directory.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                files.append(self.workspace.relative(path))
            except ValueError:
                continue
            if len(files) >= self.max_generated_files:
                truncated = True
                break
        return files, truncated

    def _persist_parsed(self, parsed: ParsedToolOutput) -> None:
        if parsed.observations:
            self.workspace.database.add_observations(parsed.observations)
        if parsed.findings:
            self.workspace.database.add_findings(parsed.findings)

    @staticmethod
    def _attach_run_provenance(parsed: ParsedToolOutput, run: ToolRun) -> None:
        for observation in parsed.observations:
            if observation.source.startswith("tool:"):
                observation.source = f"{observation.source}:{run.id}"
        references = [
            f"tool_run:{run.id}",
            f"stdout:{run.stdout_path}",
            f"stderr:{run.stderr_path}",
        ]
        for finding in parsed.findings:
            if finding.source.startswith("tool:"):
                finding.source = f"{finding.source}:{run.id}"
            for reference in references:
                if reference not in finding.supporting_evidence:
                    finding.supporting_evidence.append(reference)

    def _terminate_process_group(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
        else:  # pragma: no cover - competition targets are Linux.
            process.terminate()
        try:
            process.wait(timeout=self.termination_grace)
            return
        except subprocess.TimeoutExpired:
            pass
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:  # pragma: no cover
            process.kill()
        try:
            process.wait(timeout=self.termination_grace)
        except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL should be final.
            process.kill()
            process.wait()

    def _apply_process_limits(self, process: subprocess.Popen[bytes]) -> None:
        """Apply Linux resource ceilings immediately after a trusted tool starts."""
        if os.name != "posix" or (
            self.max_memory_bytes is None and self.max_output_file_bytes is None
        ):
            return
        try:
            import resource
            if not hasattr(resource, "prlimit"):
                return
            if self.max_memory_bytes is not None:
                resource.prlimit(
                    process.pid, resource.RLIMIT_AS,
                    (self.max_memory_bytes, self.max_memory_bytes),
                )
            if self.max_output_file_bytes is not None:
                resource.prlimit(
                    process.pid, resource.RLIMIT_FSIZE,
                    (self.max_output_file_bytes, self.max_output_file_bytes),
                )
        except (OSError, ValueError) as exc:
            self._terminate_process_group(process)
            raise OSError(f"resource limit setup failed: {exc}") from exc

    @staticmethod
    def _read_bounded(path: Path, maximum: int) -> str:
        with path.open("rb") as handle:
            data = handle.read(maximum + 1)
        truncated = len(data) > maximum
        text = data[:maximum].decode("utf-8", errors="replace")
        if truncated:
            text += f"\n[ForensicKit: preview truncated after {maximum} bytes]"
        return text


__all__ = ["ToolExecutionResult", "ToolRunner"]
