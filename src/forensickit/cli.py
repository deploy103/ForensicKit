from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .config import ForensicKitConfig
from .doctor import Doctor
from .engine import AnalysisEngine
from .extraction import ExtractionManager
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
    analyze.add_argument("--flag-pattern", action="append", default=[])
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
    triage = sub.add_parser("triage", help="run fast built-in checks only")
    triage.add_argument("files", type=Path, nargs="+", metavar="FILE")
    triage.add_argument("--workspace", type=Path, default=Path("cases"))
    triage.add_argument("--flag-pattern", action="append", default=[])
    triage.add_argument("--verbose", action="store_true")
    triage.add_argument("--tool", action="append", default=[])
    triage.add_argument("--category", action="append", default=[])
    triage.add_argument("--timeout", type=float)
    triage.add_argument("--jobs", type=int)
    recommend = sub.add_parser("recommend", help="show justified tool recommendations without running them")
    recommend.add_argument("file", type=Path)
    recommend.add_argument("--workspace", type=Path, default=Path("cases"))
    recommend.add_argument("--tool", action="append", default=[])
    recommend.add_argument("--category", action="append", default=[])
    recommend.add_argument("--timeout", type=float)
    recommend.add_argument("--jobs", type=int)
    recommend.add_argument("--verbose", action="store_true")
    run = sub.add_parser("run", help="run one registered local tool against evidence")
    run.add_argument("tool")
    run.add_argument("file", type=Path)
    run.add_argument("--workspace", type=Path, default=Path("cases"))
    run.add_argument("--timeout", type=float)
    run.add_argument("--flag-pattern", action="append", default=[])
    sub.add_parser("tools", help="show detected and missing local forensic tools")
    doctor = sub.add_parser("doctor", help="check offline competition readiness")
    doctor.add_argument("--workspace", type=Path, default=Path("cases"))
    doctor.add_argument("--bundle", type=Path, help="validate a staged offline bundle manifest")
    tui = sub.add_parser("tui", help="open the keyboard-first case viewer")
    tui.add_argument("workspace", type=Path, nargs="?")
    for name in ("artifacts", "findings", "flags", "errors"):
        command = sub.add_parser(name, help=f"list case {name}")
        command.add_argument("workspace", type=Path)
        command.add_argument("--json", action="store_true")
    report = sub.add_parser("report", help="regenerate JSON/Markdown/CSV reports")
    report.add_argument("workspace", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in {None, "tui"}:
        from .tui import launch_tui
        return launch_tui(getattr(args, "workspace", None))
    if args.command == "tools":
        for item in ToolRegistry.default(default_tool_catalog()).detect_all():
            print(f"{'[OK]' if item.available else '[MISSING]'} {item.name}: {item.executable or ''}")
        return 0
    if args.command == "doctor":
        result = Doctor(ToolRegistry.default(default_tool_catalog())).run(args.workspace, args.bundle)
        for check in result.checks:
            print(f"[{check.status}] {check.requirement:<11} {check.name}: {check.detail}")
        return 0 if result.healthy else 1
    if args.command in {"artifacts", "findings", "flags", "errors"}:
        with CaseWorkspace.open(args.workspace) as workspace:
            values = getattr(workspace.database, args.command)()
            if args.json:
                from dataclasses import asdict
                print(json.dumps([asdict(value) for value in values], indent=2, default=str))
            else:
                for value in values:
                    if args.command == "artifacts":
                        print(f"{value.id} depth={value.depth} {value.artifact_type} {value.logical_name}")
                    elif args.command == "findings":
                        print(f"[{value.severity}] {value.title} ({value.confidence:.2f})")
                    elif args.command == "flags":
                        print(f"{value.value} via {' → '.join(value.transform_chain)}")
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
        return 0
    if args.command == "recommend":
        result = AnalysisEngine(_analysis_config(args)).analyze(args.file, args.workspace, mode=AnalysisMode.PLAN, execute=False)
        print(f"Case: {result.case.workspace}")
        for plan in result.plans:
            availability = "available" if plan.available else "missing"
            print(f"[{availability}] {plan.tool}: {'; '.join(plan.reasons)}")
            if args.verbose and plan.command_argv:
                print(f"  argv: {plan.command_argv}")
        return 0
    if args.command == "run":
        config = _analysis_config(args)
        analysis = AnalysisEngine(config)
        preliminary = analysis.analyze(args.file, args.workspace, mode=AnalysisMode.TRIAGE, execute=False)
        with CaseWorkspace.open(Path(preliminary.case.workspace)) as workspace:
            root = next(artifact for artifact in workspace.database.artifacts() if artifact.parent_id is None)
            execution = ToolRunner(
                workspace, ToolRegistry.default(default_tool_catalog()), max_timeout=config.limits.per_tool_timeout,
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
            output_flags = analysis._scan_tool_output_flags(workspace, root, execution.run)
            if output_flags:
                workspace.database.add_flags(output_flags)
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
        result = AnalysisEngine(config).analyze_many(
            args.files, args.workspace, mode=mode,
            execute=False if getattr(args, "no_run", False) else None,
        )
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


def _analysis_config(args) -> ForensicKitConfig:
    """Build the narrowly scoped runtime configuration accepted by the CLI."""
    config = ForensicKitConfig()
    flag_patterns = getattr(args, "flag_pattern", [])
    if flag_patterns:
        config.flag_patterns.extend(flag_patterns)
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
    config.limits.__post_init__()
    return config


if __name__ == "__main__":
    raise SystemExit(main())
