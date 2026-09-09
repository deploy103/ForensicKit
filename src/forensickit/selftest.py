from __future__ import annotations

"""Deterministic installed-runtime smoke test for competition readiness."""

import base64
from dataclasses import dataclass
import hashlib
from io import BytesIO
import json
from pathlib import Path
import tempfile
from zipfile import ZipFile

from .engine import AnalysisEngine
from .models import AnalysisMode


@dataclass(frozen=True, slots=True)
class SelfTestResult:
    checks: tuple[str, ...]
    errors: tuple[str, ...]

    @property
    def healthy(self) -> bool:
        return not self.errors


def run_self_test() -> SelfTestResult:
    """Exercise preservation, extraction, recursion, search, lineage and reports.

    External tools are deliberately disabled: this verifies the installed
    deterministic core even on the offline competition workstation before its
    optional forensic-tool inventory is complete.
    """

    checks: list[str] = []
    errors: list[str] = []
    expected_flag = "CTF{forensickit_self_test}"
    archive = BytesIO()
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr("flag.txt", base64.b64encode(expected_flag.encode("ascii")))
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24 + b"IEND\xaeB`\x82"
    payload = png + archive.getvalue()

    try:
        with tempfile.TemporaryDirectory(prefix="forensickit-self-test-") as raw_root:
            root = Path(raw_root)
            evidence = root / "challenge.png"
            evidence.write_bytes(payload)
            result = AnalysisEngine().analyze(
                evidence, root / "cases", mode=AnalysisMode.AUTO, execute=False,
            )
            workspace = Path(result.case.workspace)

            if hashlib.sha256(evidence.read_bytes()).hexdigest() != result.root_artifact.sha256:
                errors.append("preserved evidence hash differs from the submitted source")
            else:
                checks.append("evidence preservation and SHA-256")

            children = [item for item in result.artifacts if item.parent_id == result.root_artifact.id]
            if not any(item.logical_name == "flag.txt" for item in children):
                errors.append("appended ZIP child was not extracted with parent lineage")
            else:
                checks.append("bounded extraction and artifact lineage")

            candidates = [item for item in result.flags if item.value == expected_flag]
            if not candidates or not any("base64" in item.transform_chain for item in candidates):
                errors.append("recursive Base64 flag candidate was not retained with transform provenance")
            else:
                checks.append("recursive flag search and transform provenance")

            required = (
                workspace / "case.db",
                workspace / "reports" / "report.json",
                workspace / "reports" / "report.md",
                workspace / "reports" / "report.html",
            )
            missing = [path.name for path in required if not path.is_file() or path.stat().st_size == 0]
            if missing:
                errors.append("missing or empty case output: " + ", ".join(missing))
            else:
                checks.append("SQLite and JSON/Markdown/HTML reports")

            try:
                report = json.loads((workspace / "reports" / "report.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"report.json could not be parsed: {exc}")
            else:
                report_flags = report.get("flag_candidates", report.get("flags", []))
                if expected_flag not in json.dumps(report_flags, ensure_ascii=False):
                    errors.append("report.json omitted the recursive flag candidate")
                else:
                    checks.append("machine-readable finding provenance")
                findings = report.get("findings", [])
                hypotheses = report.get("hypotheses", [])
                verifications = report.get("verifications", [])
                finding_ids = {item.get("id") for item in findings if isinstance(item, dict)}
                hypothesis_findings = {
                    item.get("finding_id") for item in hypotheses if isinstance(item, dict)
                }
                verification_findings = {
                    item.get("finding_id") for item in verifications if isinstance(item, dict)
                }
                if not finding_ids or not finding_ids <= hypothesis_findings or not finding_ids <= verification_findings:
                    errors.append("report.json omitted a finding hypothesis/verification chain")
                else:
                    checks.append("observation-to-hypothesis verification records")
    except Exception as exc:  # the CLI must turn smoke failures into a useful exit code
        errors.append(f"self-test pipeline raised {type(exc).__name__}: {exc}")

    return SelfTestResult(tuple(checks), tuple(errors))


__all__ = ["SelfTestResult", "run_self_test"]
