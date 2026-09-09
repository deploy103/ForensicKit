from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from forensickit.models import Artifact, Finding, VerificationStatus
from forensickit.reporting import ReportGenerator
from forensickit.workspace import CaseWorkspace


def _artifact(case_id: str, artifact_id: str = "artifact") -> Artifact:
    return Artifact(
        id=artifact_id,
        case_id=case_id,
        path=f"evidence/{artifact_id}.bin",
        logical_name=f"{artifact_id}.bin",
        sha256=(artifact_id.encode().hex() + "0" * 64)[:64],
        size=64,
        artifact_type="data",
    )


def _finding(
    artifact_id: str,
    finding_id: str,
    evidence: list[str],
) -> Finding:
    return Finding(
        id=finding_id,
        artifact_id=artifact_id,
        title=f"Hypothesis for {finding_id}",
        category="test",
        severity="medium",
        confidence=0.81,
        explanation="A testable explanation derived from forensic observations.",
        source="profile:test-chain",
        supporting_evidence=evidence,
    )


def test_add_findings_transactionally_persists_one_complete_chain(tmp_path: Path) -> None:
    with CaseWorkspace.create(tmp_path / "cases", "chain") as workspace:
        artifact = _artifact(workspace.case.id)
        workspace.database.add_artifact(artifact)
        with_evidence = _finding(artifact.id, "finding-with-evidence", ["offset=512", "<record>"])
        unverified = _finding(artifact.id, "finding-unverified", [])

        workspace.database.add_findings([with_evidence, unverified])
        workspace.database.add_findings([with_evidence, unverified])

        hypotheses = workspace.database.hypotheses(artifact_id=artifact.id)
        verifications = workspace.database.verifications(artifact_id=artifact.id)
        assert len(workspace.database.findings(artifact.id)) == 2
        assert len(hypotheses) == 2
        assert len(verifications) == 2
        assert {item.finding_id for item in hypotheses} == {
            "finding-with-evidence", "finding-unverified",
        }
        assert {item.finding_id for item in verifications} == {
            "finding-with-evidence", "finding-unverified",
        }
        evidence_hypothesis = workspace.database.hypotheses(
            finding_id=with_evidence.id,
        )[0]
        evidence_verification = workspace.database.verifications(
            finding_id=with_evidence.id,
        )[0]
        assert evidence_hypothesis.statement == with_evidence.title
        assert evidence_hypothesis.rationale == with_evidence.explanation
        assert evidence_hypothesis.source == with_evidence.source
        assert evidence_hypothesis.evidence == with_evidence.supporting_evidence
        assert evidence_verification.hypothesis_id == evidence_hypothesis.id
        assert evidence_verification.finding_id == with_evidence.id
        assert evidence_verification.source == with_evidence.source
        assert evidence_verification.method == "not_performed"
        assert evidence_verification.evidence == with_evidence.supporting_evidence
        assert evidence_verification.status is VerificationStatus.UNVERIFIED
        assert workspace.database.verifications(
            finding_id=unverified.id,
        )[0].status is VerificationStatus.UNVERIFIED
        assert workspace.database.connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall() == []


def test_reopening_legacy_database_backfills_chain_without_duplicates(tmp_path: Path) -> None:
    workspace = CaseWorkspace.create(tmp_path / "cases", "legacy")
    artifact = _artifact(workspace.case.id, "legacy-artifact")
    workspace.database.add_artifact(artifact)
    finding = _finding(artifact.id, "legacy-finding", ["legacy evidence"])
    workspace.database.add_findings([finding])
    root = workspace.root
    workspace.close()

    with sqlite3.connect(root / "case.db") as connection:
        connection.execute("DROP TABLE verifications")
        connection.execute("DROP TABLE hypotheses")

    with CaseWorkspace.open(root) as reopened:
        assert len(reopened.database.hypotheses(finding_id=finding.id)) == 1
        assert len(reopened.database.verifications(finding_id=finding.id)) == 1
        assert reopened.database.verifications(
            finding_id=finding.id,
        )[0].status is VerificationStatus.UNVERIFIED

    with CaseWorkspace.open(root) as reopened_again:
        assert len(reopened_again.database.hypotheses()) == 1
        assert len(reopened_again.database.verifications()) == 1
        assert reopened_again.database.connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall() == []


def test_reports_include_linked_hypothesis_verification_and_evidence(tmp_path: Path) -> None:
    with CaseWorkspace.create(tmp_path / "cases", "report-chain") as workspace:
        artifact = _artifact(workspace.case.id, "report-artifact")
        workspace.database.add_artifact(artifact)
        finding = _finding(artifact.id, "report-finding", ["offset=4096", "<record>"])
        workspace.database.add_findings([finding])

        json_path, markdown_path = ReportGenerator().generate(workspace)
        report = json.loads(json_path.read_text(encoding="utf-8"))
        markdown = markdown_path.read_text(encoding="utf-8")
        html = workspace.path("reports", "report.html").read_text(encoding="utf-8")

        assert report["schema_version"] == 4
        assert report["hypotheses"][0]["finding_id"] == finding.id
        assert report["hypotheses"][0]["source"] == finding.source
        assert report["verifications"][0]["finding_id"] == finding.id
        assert report["verifications"][0]["status"] == "unverified"
        assert report["verifications"][0]["method"] == "not_performed"
        assert report["verifications"][0]["evidence"] == ["offset=4096", "<record>"]
        assert "## Investigation chain" in markdown
        assert "`not_performed`" in markdown
        assert "offset=4096" in markdown
        assert "<h2>Investigation chain</h2>" in html
        assert "not_performed" in html
        assert "&lt;record&gt;" in html


def test_explicit_verification_requires_a_real_method_and_evidence(tmp_path: Path) -> None:
    with CaseWorkspace.create(tmp_path / "cases", "explicit-verification") as workspace:
        artifact = _artifact(workspace.case.id, "verified-artifact")
        workspace.database.add_artifact(artifact)
        finding = _finding(artifact.id, "verified-finding", ["candidate offset=17"])
        workspace.database.add_findings([finding])

        with pytest.raises(ValueError, match="method"):
            workspace.database.record_verification(
                finding.id,
                method="not_performed",
                status=VerificationStatus.SUPPORTED,
                conclusion="Confirmed against preserved bytes.",
                source="analyst:test",
                evidence=["reviewed offset=17"],
            )
        with pytest.raises(ValueError, match="requires recorded evidence"):
            workspace.database.record_verification(
                finding.id,
                method="independent_hex_review",
                status=VerificationStatus.SUPPORTED,
                conclusion="Confirmed against preserved bytes.",
                source="analyst:test",
            )

        verification = workspace.database.record_verification(
            finding.id,
            method="independent_hex_review",
            status=VerificationStatus.SUPPORTED,
            conclusion="The exact preserved bytes at offset 17 confirm the hypothesis.",
            source="analyst:test",
            evidence=["artifact=verified-artifact offset=17 bytes=4354467b"],
        )

        assert verification.status is VerificationStatus.SUPPORTED
        assert verification.method == "independent_hex_review"
        assert verification.source == "analyst:test"
        assert verification.evidence == [
            "artifact=verified-artifact offset=17 bytes=4354467b"
        ]


def test_legacy_automatic_supported_placeholder_is_downgraded(tmp_path: Path) -> None:
    workspace = CaseWorkspace.create(tmp_path / "cases", "legacy-supported")
    artifact = _artifact(workspace.case.id, "legacy-supported-artifact")
    workspace.database.add_artifact(artifact)
    finding = _finding(artifact.id, "legacy-supported-finding", ["unreviewed clue"])
    workspace.database.add_findings([finding])
    root = workspace.root
    with workspace.database.connection:
        workspace.database.connection.execute(
            """UPDATE verifications
               SET method='recorded_supporting_evidence_review', status='supported',
                   conclusion='The finding is supported by its recorded evidence.'
               WHERE finding_id=?""",
            (finding.id,),
        )
    workspace.close()

    with CaseWorkspace.open(root) as reopened:
        verification = reopened.database.verifications(finding_id=finding.id)[0]
        assert verification.status is VerificationStatus.UNVERIFIED
        assert verification.method == "not_performed"
        assert "no independent verification" in verification.conclusion
