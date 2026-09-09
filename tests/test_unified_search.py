from __future__ import annotations

import base64
import json
from pathlib import Path
import zipfile

import pytest

from forensickit.config import ForensicKitConfig
from forensickit.engine import AnalysisEngine
from forensickit.flags import FlagHunter, UnsafeRegexError
from forensickit.models import AnalysisMode, Artifact


def _artifact(path: Path) -> Artifact:
    return Artifact(
        id="artifact", case_id="case", path=str(path), logical_name=path.name,
        sha256="fixture", size=path.stat().st_size, source_path=str(path),
    )


def test_chunk_boundary_utf16_and_all_duplicate_offsets_are_preserved(tmp_path: Path) -> None:
    evidence = tmp_path / "boundary.bin"
    first = b"CTF{same}"
    second_offset = 67
    payload = first + b"x" * (second_offset - len(first)) + first
    wide_offset = len(payload) + 5
    payload += b"-----" + "FLAG{utf16_boundary}".encode("utf-16-be")
    evidence.write_bytes(payload)

    result = FlagHunter(
        [r"CTF\{[^}]+\}", r"FLAG\{[^}]+\}"], chunk_size=64,
    ).scan_all(evidence, _artifact(evidence))

    same = next(item for item in result.flags if item.value == "CTF{same}")
    assert {item["offset"] for item in same.locations} == {0, second_offset}
    wide = next(item for item in result.flags if item.value == "FLAG{utf16_boundary}")
    assert wide.offset == wide_offset
    assert wide.encoding == "utf-16-be"


def test_repeated_decoding_has_bounded_chain_and_no_fake_original_offset(tmp_path: Path) -> None:
    evidence = tmp_path / "encoded.txt"
    encoded = base64.b64encode(base64.b64encode(b"CTF{double_base64}"))
    evidence.write_bytes(encoded)

    candidate = FlagHunter([r"CTF\{[^}]+\}"], decode_depth=3).scan(
        evidence, _artifact(evidence)
    )[0]

    assert candidate.value == "CTF{double_base64}"
    assert candidate.transform_chain == ["raw", "base64", "base64"]
    assert candidate.offset is None
    assert "not an original evidence offset" in (candidate.location or "")
    assert candidate.locations[0]["source_offset"] == 0


def test_exact_keyword_regex_and_filename_queries_remain_distinct(tmp_path: Path) -> None:
    evidence = tmp_path / "alice-notes.bin"
    evidence.write_bytes(b"Account=Alice host=Example.TEST ticket-4821")
    hunter = FlagHunter(
        [], exact_strings=["Account=Alice"], search_terms=["example.test", "alice"],
        regex_patterns=[r"ticket-[0-9]{4}"],
    )

    result = hunter.scan_all(evidence, _artifact(evidence))

    assert {(item.match_type, item.query, item.value) for item in result.hits} == {
        ("exact", "Account=Alice", "Account=Alice"),
        ("keyword", "example.test", "Example.TEST"),
        ("keyword", "alice", "Alice"),
        ("keyword", "alice", "alice"),
        ("regex", r"ticket-[0-9]{4}", "ticket-4821"),
    }
    filename = next(item for item in result.hits if item.value == "alice")
    assert filename.locations[0]["source_kind"] == "filename"


def test_catastrophic_and_backreference_regexes_are_rejected() -> None:
    with pytest.raises(UnsafeRegexError, match="nested repetition"):
        FlagHunter([], regex_patterns=[r"(a+)+$"])
    with pytest.raises(UnsafeRegexError, match="backreferences"):
        FlagHunter([], regex_patterns=[r"(a+)\1"])


def test_directory_nested_archive_search_and_safe_reports(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "raw.txt").write_bytes(b"CTF{raw_fixture} owner=Alice <script>alert(1)</script>")
    (evidence / "wide.bin").write_bytes("FLAG{wide_fixture}".encode("utf-16-le"))
    inner = evidence / "inner.zip"
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("encoded.txt", base64.b64encode(b"CTF{decoded_fixture}"))
    outer = evidence / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.write(inner, "level/inner.zip")
    inner.unlink()

    config = ForensicKitConfig(
        exact_strings=["owner=Alice"], search_terms=["alice"],
        regex_patterns=[r"alert\([0-9]+\)"],
    )
    result = AnalysisEngine(config).analyze(
        evidence, tmp_path / "cases", mode=AnalysisMode.AUTO, execute=False,
    )

    assert {item.value for item in result.flags} >= {
        "CTF{raw_fixture}", "FLAG{wide_fixture}", "CTF{decoded_fixture}",
    }
    decoded = next(item for item in result.flags if item.value == "CTF{decoded_fixture}")
    assert any("base64" in item["transform_chain"] for item in decoded.locations)
    assert any("outer.zip" in str(item["origin_path"]) for item in decoded.locations)
    assert any("encoded.txt" in str(item["discovered_path"]) for item in decoded.locations)
    assert any(artifact.logical_name == "level/inner.zip" for artifact in result.artifacts)
    assert {item.match_type for item in result.search_hits} >= {"exact", "keyword", "regex"}

    report_dir = Path(result.case.workspace) / "reports"
    report = json.loads((report_dir / "report.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == 4
    assert report["search_hits"]
    html_report = (report_dir / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_report
    assert (report_dir / "search_results.csv").is_file()
