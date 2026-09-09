from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import signal
import sqlite3
import sys
from threading import Event

from . import __version__
from .config import ForensicKitConfig
from .doctor import Doctor
from .engine import AnalysisEngine
from .extraction import ExtractionManager
from .flags import UnsafeRegexError
from .models import AnalysisMode
from .resources import default_tool_catalog
from .reporting import ReportGenerator
from .tools import ToolRegistry
from .tools import ToolRunner
from .workspace import CaseWorkspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensickit",
        description="Offline CTF digital-forensics triage, orchestration, and evidence reporting.",
        epilog="Start safely: forensickit doctor; then: forensickit analyze EVIDENCE --auto",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    analyze = sub.add_parser("analyze", help="analyze one or more evidence files/directories")
    analyze.add_argument("files", type=Path, nargs="+", metavar="FILE")
    analyze.add_argument("--workspace", type=Path, default=Path("cases"))
    analyze.add_argument("--auto", action="store_true")
    analyze.add_argument("--deep", action="store_true")
    analyze.add_argument("--plan", action="store_true")
    analyze.add_argument("--no-run", action="store_true", help="do not execute external tools")
    analyze.add_argument("--json", action="store_true")
    analyze.add_argument("--verbose", action="store_true")
    analyze.add_argument("--flag-prefix", action="append", default=[], help="custom flag prefix, for example ACME or ACME{")
    analyze.add_argument("--exact-string", action="append", default=[], help="case-sensitive exact string to locate")
    analyze.add_argument("--regex", action="append", default=[], help="advanced bounded regular expression search")
    analyze.add_argument("--search-term", action="append", default=[], help="case-insensitive filename/content clue")
    analyze.add_argument("--max-search-bytes", type=int, help="maximum bytes searched per file")
    analyze.add_argument("--search-timeout", type=float, help="seconds allowed per file search")
    analyze.add_argument("--decode-depth", type=int, help="maximum repeated decode depth")
    analyze.add_argument("--pid", type=int, action="append", default=[], help="PID selected for deep memory extraction")
    analyze.add_argument("--flag-pattern", action="append", default=[], help="legacy advanced flag regex")
    recursion = analyze.add_mutually_exclusive_group()
    recursion.add_argument("--recursive", action="store_true", help="enable bounded child analysis (default)")
    recursion.add_argument("--no-recursive", action="store_true", help="do not analyze registered child artifacts")
    extraction = analyze.add_mutually_exclusive_group()
    extraction.add_argument("--extract", action="store_true", help="enable bounded built-in extraction (default)")
    extraction.add_argument("--no-extract", action="store_true", help="do not extract built-in container payloads")
    analyze.add_argument("--tool", action="append", default=[])
    analyze.add_argument("--category", action="append", default=[])
    analyze.add_argument("--timeout", type=float)
    analyze.add_argument("--jobs", type=int)
    analyze.add_argument("--memory-jobs", type=int, help="maximum concurrent tools for memory evidence")
    analyze.add_argument("--tool-memory-bytes", type=int, help="per-process address-space cap on Linux")
    analyze.add_argument("--tool-output-bytes", type=int, help="per-generated-file size cap on Linux")
    triage = sub.add_parser("triage", help="run fast built-in checks only")
    triage.add_argument("files", type=Path, nargs="+", metavar="FILE")
    triage.add_argument("--workspace", type=Path, default=Path("cases"))
    triage.add_argument("--flag-pattern", action="append", default=[])
    triage.add_argument("--flag-prefix", action="append", default=[])
    triage.add_argument("--exact-string", action="append", default=[])
    triage.add_argument("--regex", action="append", default=[])
    triage.add_argument("--search-term", action="append", default=[])
    triage.add_argument("--max-search-bytes", type=int)
    triage.add_argument("--search-timeout", type=float)
    triage.add_argument("--decode-depth", type=int)
    triage.add_argument("--verbose", action="store_true")
    triage.add_argument("--tool", action="append", default=[])
    triage.add_argument("--category", action="append", default=[])
    triage.add_argument("--timeout", type=float)
    triage.add_argument("--jobs", type=int)
    triage.add_argument("--memory-jobs", type=int)
    triage.add_argument("--tool-memory-bytes", type=int)
    triage.add_argument("--tool-output-bytes", type=int)
    recommend = sub.add_parser("recommend", help="show justified tool recommendations without running them")
    recommend.add_argument("file", type=Path)
    recommend.add_argument("--workspace", type=Path, default=Path("cases"))
    recommend.add_argument("--tool", action="append", default=[])
    recommend.add_argument("--category", action="append", default=[])
    recommend.add_argument("--timeout", type=float)
    recommend.add_argument("--jobs", type=int)
    recommend.add_argument("--memory-jobs", type=int)
    recommend.add_argument("--tool-memory-bytes", type=int)
    recommend.add_argument("--tool-output-bytes", type=int)
    recommend.add_argument("--verbose", action="store_true")
    run = sub.add_parser("run", help="run one registered local tool against evidence")
    run.add_argument("tool")
    run.add_argument("file", type=Path)
    run.add_argument("--workspace", type=Path, default=Path("cases"))
    run.add_argument("--timeout", type=float)
    run.add_argument("--flag-pattern", action="append", default=[])
    run.add_argument("--flag-prefix", action="append", default=[])
    run.add_argument("--exact-string", action="append", default=[])
    run.add_argument("--regex", action="append", default=[])
    run.add_argument("--search-term", action="append", default=[])
    run.add_argument("--max-search-bytes", type=int)
    run.add_argument("--search-timeout", type=float)
    run.add_argument("--decode-depth", type=int)
    run.add_argument("--tool-memory-bytes", type=int, help="per-process address-space cap on Linux")
    run.add_argument("--tool-output-bytes", type=int, help="per-generated-file size cap on Linux")
    tools = sub.add_parser("tools", help="show detected and missing local forensic tools")
    tools.add_argument("--json", action="store_true")
    doctor = sub.add_parser("doctor", help="check offline competition readiness")
    doctor.add_argument("--workspace", type=Path, default=Path("cases"))
    doctor.add_argument("--bundle", type=Path, help="validate a staged offline bundle manifest")
    doctor.add_argument("--json", action="store_true")
    self_test = sub.add_parser("self-test", help="run a deterministic end-to-end installed-runtime smoke test")
    self_test.add_argument("--json", action="store_true")
    tui = sub.add_parser("tui", help="open the keyboard-first case viewer")
    tui.add_argument("workspace", type=Path, nargs="?")
    for name in ("artifacts", "findings", "flags", "search-hits", "errors"):
        command = sub.add_parser(name, help=f"list case {name}")
        command.add_argument("workspace", type=Path)
        command.add_argument("--json", action="store_true")
    report = sub.add_parser("report", help="regenerate JSON/Markdown/CSV reports")
    report.add_argument("workspace", type=Path)
    return parser


def _main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {None, "tui"}:
        from .tui import launch_tui
        return launch_tui(getattr(args, "workspace", None))
    if args.command == "tools":
        detected = ToolRegistry.default(default_tool_catalog()).detect_all()
        if args.json:
            print(json.dumps([asdict(item) for item in detected], indent=2))
        else:
            for item in detected:
                print(f"{'[OK]' if item.available else '[MISSING]'} {item.name}: {item.executable or ''}")
        return 0
    if args.command == "doctor":
        result = Doctor(ToolRegistry.default(default_tool_catalog())).run(args.workspace, args.bundle)
        if args.json:
            print(json.dumps({"healthy": result.healthy, "checks": [asdict(item) for item in result.checks]}, indent=2))
        else:
            for check in result.checks:
                print(f"[{check.status}] {check.requirement:<11} {check.name}: {check.detail}")
        return 0 if result.healthy else 1
    if args.command == "self-test":
        from .selftest import run_self_test
        result = run_self_test()
        if args.json:
            print(json.dumps({"healthy": result.healthy, "checks": result.checks, "errors": result.errors}, indent=2))
        else:
            for check in result.checks:
                print(f"[OK] {check}")
            for error in result.errors:
                print(f"[BROKEN] {error}", file=sys.stderr)
        return 0 if result.healthy else 1
    if args.command in {"artifacts", "findings", "flags", "search-hits", "errors"}:
        with CaseWorkspace.open(args.workspace) as workspace:
            method = args.command.replace("-", "_")
            values = getattr(workspace.database, method)()
            if args.json:
                print(json.dumps([asdict(value) for value in values], indent=2, default=str))
            else:
                for value in values:
                    if args.command == "artifacts":
                        print(f"{value.id} depth={value.depth} {value.artifact_type} {value.logical_name}")
                    elif args.command == "findings":
                        print(f"[{value.severity}] {value.title} ({value.confidence:.2f})")
                    elif args.command == "flags":
                        print(f"{value.value} [{value.status}] locations={len(value.locations)} via {' → '.join(value.transform_chain)}")
                    elif args.command == "search-hits":
                        print(f"[{value.match_type}] {value.query!r}: {value.value!r} locations={len(value.locations)}")
                    else:
                        target = value.artifact_id or "case"
                        print(f"[{value.source}] {target}: {value.message}")
        return 0
    if args.command == "report":
        with CaseWorkspace.open(args.workspace) as workspace:
            json_path, markdown_path = ReportGenerator().generate(workspace)
            print(json_path)
            print(markdown_path)
            print(workspace.path("reports", "timeline.csv"))
            print(workspace.path("reports", "search_results.csv"))
            print(workspace.path("reports", "report.html"))
        return 0
    if args.command == "recommend":
        result = _analysis_engine(_analysis_config(args)).analyze(args.file, args.workspace, mode=AnalysisMode.PLAN, execute=False)
        print(f"Case: {result.case.workspace}")
        for plan in result.plans:
            availability = "available" if plan.available else "missing"
            print(f"[{availability}] {plan.tool}: {'; '.join(plan.reasons)}")
            if args.verbose and plan.command_argv:
                print(f"  argv: {plan.command_argv}")
        return 0
    if args.command == "run":
        config = _analysis_config(args)
        analysis = _analysis_engine(config)
        preliminary = analysis.analyze(args.file, args.workspace, mode=AnalysisMode.TRIAGE, execute=False)
        with CaseWorkspace.open(Path(preliminary.case.workspace)) as workspace:
            root = next(artifact for artifact in workspace.database.artifacts() if artifact.parent_id is None)
            execution = ToolRunner(
                workspace, ToolRegistry.default(default_tool_catalog()),
                max_timeout=config.limits.per_tool_timeout,
                max_memory_bytes=config.limits.tool_max_memory_bytes,
                max_output_file_bytes=config.limits.tool_max_output_file_bytes,
            ).run(
                args.tool, root, timeout=args.timeout
            )
            if execution.run.error:
                analysis._record_errors(
                    workspace, preliminary, root.id, [execution.run.error], f"tool_runner:{execution.run.tool}",
                )
            if execution.observations:
                workspace.database.add_observations(execution.observations)
            if execution.findings:
                workspace.database.add_findings(execution.findings)
            output_matches = analysis._scan_tool_output_matches(workspace, root, execution.run)
            output_flags = output_matches.flags
            if output_flags:
                workspace.database.add_flags(output_flags)
            if output_matches.hits:
                workspace.database.add_search_hits(output_matches.hits)
            generated = ExtractionManager(workspace, config.limits).register_tool_outputs(root, execution.run)
            if generated.errors:
                analysis._record_errors(workspace, preliminary, root.id, generated.errors, "tool_output_registrar")
            all_findings = [*execution.findings, *generated.findings]
            if all_findings:
                workspace.database.add_findings(all_findings)
            ReportGenerator().generate(workspace)
            print(f"{execution.run.tool}: {execution.status.value}")
            for finding in execution.findings:
                print(f"[!] {finding.title} ({finding.confidence:.2f})")
            for flag in output_flags:
                print(f"[FLAG] {flag.value} via {' → '.join(flag.transform_chain)}")
            for hit in output_matches.hits:
                print(f"[SEARCH:{hit.match_type}] {hit.value} at {hit.location}")
            if generated.artifacts:
                print(f"Registered {len(generated.artifacts)} generated artifact(s)")
            for error in generated.errors:
                print(f"[output] {error}")
            if execution.run.error:
                print(execution.run.error)
        return 0 if execution.status.value == "completed" else 1
    if args.command in {"analyze", "triage"}:
        mode = AnalysisMode.TRIAGE
        if getattr(args, "auto", False): mode = AnalysisMode.AUTO
        if getattr(args, "deep", False): mode = AnalysisMode.DEEP
        if getattr(args, "plan", False): mode = AnalysisMode.PLAN
        config = _analysis_config(args)
        cancel_event = Event()
        previous_handler = signal.getsignal(signal.SIGINT)

        def cancel_analysis(_signum, _frame) -> None:
            if cancel_event.is_set():
                raise KeyboardInterrupt
            cancel_event.set()
            print("[STATUS] cancellation requested; stopping active local tools…", file=sys.stderr)

        def show_progress(event: dict[str, object]) -> None:
            kind = event.get("event")
            if kind == "case_created":
                print(f"[STATUS] case started: {event.get('workspace')}", file=sys.stderr)
            elif kind == "artifact_started":
                print(f"[STATUS] analyzing: {event.get('logical_name')}", file=sys.stderr)
            elif kind == "tool_started":
                print(f"[STATUS] tool running: {event.get('tool')}", file=sys.stderr)
            elif kind == "tool_finished":
                print(f"[STATUS] tool {event.get('status')}: {event.get('tool')}", file=sys.stderr)

        signal.signal(signal.SIGINT, cancel_analysis)
        try:
            result = _analysis_engine(
                config, progress=show_progress, cancel_event=cancel_event,
            ).analyze_many(
                args.files, args.workspace, mode=mode,
                execute=False if getattr(args, "no_run", False) else None,
            )
        finally:
            signal.signal(signal.SIGINT, previous_handler)
        payload = result.to_dict()
        if getattr(args, "json", False): print(json.dumps(payload, indent=2, default=str))
        else:
            print(f"Case: {result.case.workspace}")
            roots = [artifact for artifact in result.artifacts if artifact.parent_id is None]
            if len(roots) == 1:
                print(f"Artifact: {result.root_artifact.logical_name} ({result.root_artifact.artifact_type})")
            else:
                print(f"Root artifacts: {len(roots)}")
                for artifact in roots:
                    print(f"  - {artifact.logical_name} ({artifact.artifact_type})")
            for finding in result.findings: print(f"[!] {finding.title} ({finding.confidence:.2f})")
            for flag in result.flags: print(f"[FLAG] {flag.value} via {' → '.join(flag.transform_chain)}")
            for hit in result.search_hits:
                print(f"[SEARCH:{hit.match_type}] {hit.value} at {hit.location}")
            if args.verbose:
                for plan in result.plans:
                    availability = "available" if plan.available else "missing"
                    argv = " ".join(plan.command_argv) if plan.command_argv else "(argv unavailable)"
                    print(f"[PLAN:{availability}] {plan.tool} [{plan.command_mode}] {argv}")
                for run in result.tool_runs:
                    print(f"[RUN:{run.status.value}] {run.tool}: {' '.join(run.command_argv)}")
                for error in result.errors:
                    print(f"[ERROR] {error}")
            print(f"Report: {result.case.workspace}/reports/report.md")
        return 0
    build_parser().print_help()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI without leaking routine evidence/workspace failures as traces."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("analysis interrupted by analyst", file=sys.stderr)
        return 130
    except BrokenPipeError:
        return 0
    except (LookupError, OSError, RuntimeError, ValueError, sqlite3.DatabaseError) as exc:
        arguments = sys.argv[1:] if argv is None else argv
        if "--json" in arguments:
            print(json.dumps({"error": str(exc), "type": type(exc).__name__}), file=sys.stderr)
        else:
            print(f"forensickit: {exc}", file=sys.stderr)
        return 2


def _analysis_config(args) -> ForensicKitConfig:
    """Build the narrowly scoped runtime configuration accepted by the CLI."""
    config = ForensicKitConfig()
    flag_patterns = getattr(args, "flag_pattern", [])
    if flag_patterns:
        config.flag_patterns.extend(flag_patterns)
    config.flag_prefixes = list(getattr(args, "flag_prefix", []) or [])
    config.exact_strings = list(getattr(args, "exact_string", []) or [])
    config.regex_patterns = list(getattr(args, "regex", []) or [])
    config.search_terms = list(getattr(args, "search_term", []) or [])
    requested_pids = list(dict.fromkeys(getattr(args, "pid", []) or []))
    if any(pid <= 0 or pid > 0xFFFFFFFF for pid in requested_pids) or len(requested_pids) > 16:
        raise SystemExit("--pid must be a positive 32-bit integer and may be supplied at most 16 times")
    config.memory_pids = requested_pids
    if getattr(args, "no_recursive", False):
        config.recursive = False
    if getattr(args, "recursive", False):
        config.recursive = True
    if getattr(args, "no_extract", False):
        config.extract = False
    if getattr(args, "extract", False):
        config.extract = True
    config.tool_allowlist = list(getattr(args, "tool", []) or [])
    config.category_filter = list(getattr(args, "category", []) or [])
    timeout = getattr(args, "timeout", None)
    if timeout is not None:
        config.limits.per_tool_timeout = timeout
    jobs = getattr(args, "jobs", None)
    if jobs is not None:
        config.limits.jobs = jobs
    memory_jobs = getattr(args, "memory_jobs", None)
    if memory_jobs is not None:
        config.limits.memory_jobs = memory_jobs
    tool_memory_bytes = getattr(args, "tool_memory_bytes", None)
    if tool_memory_bytes is not None:
        config.limits.tool_max_memory_bytes = tool_memory_bytes
    tool_output_bytes = getattr(args, "tool_output_bytes", None)
    if tool_output_bytes is not None:
        config.limits.tool_max_output_file_bytes = tool_output_bytes
    max_search_bytes = getattr(args, "max_search_bytes", None)
    if max_search_bytes is not None:
        config.limits.flag_max_scan_bytes = max_search_bytes
    search_timeout = getattr(args, "search_timeout", None)
    if search_timeout is not None:
        config.limits.flag_scan_timeout = search_timeout
    decode_depth = getattr(args, "decode_depth", None)
    if decode_depth is not None:
        config.limits.flag_decode_depth = decode_depth
    config.limits.__post_init__()
    return config


def _analysis_engine(config: ForensicKitConfig, **kwargs) -> AnalysisEngine:
    try:
        return AnalysisEngine(config, **kwargs)
    except UnsafeRegexError as exc:
        print(f"unsafe or invalid regular expression: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    raise SystemExit(main())
