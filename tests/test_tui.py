from __future__ import annotations

import asyncio
import importlib.util

from forensickit.models import Artifact, Classification, Observation
from forensickit.tui import (
    build_artifact_tree_rows,
    build_classification_rows,
    build_observation_rows,
    observation_value_detail,
    observation_value_preview,
    launch_tui,
)


def _artifact(
    artifact_id: str,
    name: str,
    *,
    parent_id: str | None = None,
    depth: int = 0,
    artifact_type: str = "unknown",
) -> Artifact:
    return Artifact(
        id=artifact_id,
        case_id="case",
        parent_id=parent_id,
        path=f"artifacts/{name}",
        logical_name=name,
        sha256=artifact_id.rjust(64, "0"),
        size=10,
        artifact_type=artifact_type,
        depth=depth,
        created_at=f"2026-09-09T00:00:0{min(depth, 9)}+00:00",
    )


def test_artifact_tree_rows_preserve_branch_order_and_exact_lineage() -> None:
    root = _artifact("root", "evidence.png", artifact_type="image")
    first = _artifact("first", "hidden.zip", parent_id="root", depth=1, artifact_type="archive")
    second = _artifact("second", "note.txt", parent_id="root", depth=1, artifact_type="text")
    leaf = _artifact("leaf", "flag.txt", parent_id="first", depth=2, artifact_type="text")

    rows = build_artifact_tree_rows([leaf, second, root, first])

    assert [row.artifact.id for row in rows] == ["root", "first", "leaf", "second"]
    assert [row.tree_label for row in rows] == [
        "evidence.png", "├─ hidden.zip", "│  └─ flag.txt", "└─ note.txt",
    ]
    assert rows[2].lineage == ("evidence.png", "hidden.zip", "flag.txt")
    assert rows[2].parent_name == "hidden.zip"
    assert all(row.lineage_issue is None for row in rows)


def test_artifact_tree_rows_keep_orphans_and_cycles_visible() -> None:
    orphan = _artifact("orphan", "orphan.bin", parent_id="missing", depth=2)
    self_cycle = _artifact("self", "self.bin", parent_id="self", depth=1)
    cycle_a = _artifact("a", "a.bin", parent_id="b", depth=3)
    cycle_b = _artifact("b", "b.bin", parent_id="a", depth=4)

    rows = build_artifact_tree_rows([cycle_b, self_cycle, orphan, cycle_a])

    assert {row.artifact.id for row in rows} == {"orphan", "self", "a", "b"}
    assert len(rows) == 4
    assert all(row.lineage_issue for row in rows)
    assert "missing parent missing" in next(
        row.lineage_issue for row in rows if row.artifact.id == "orphan"
    )
    assert "cyclic parent link" in next(
        row.lineage_issue for row in rows if row.artifact.id == "a"
    )


def test_classification_rows_show_selected_alternates_and_unknowns() -> None:
    detected = _artifact("detected", "sample.bin", artifact_type="archive")
    detected.classifications = [
        Classification("archive", 0.97, "ZIP local header", "signature"),
        Classification("image", 0.42, "PNG trailer", "embedded-signature"),
    ]
    unknown = _artifact("unknown", "unknown.bin")
    unknown.magic = "opaque data"

    rows = build_classification_rows([unknown, detected])

    detected_rows = [row for row in rows if row.artifact.id == "detected"]
    unknown_row = next(row for row in rows if row.artifact.id == "unknown")
    assert [(row.artifact_type, row.selected) for row in detected_rows] == [
        ("archive", True), ("image", False),
    ]
    assert detected_rows[0].confidence == 0.97
    assert unknown_row.artifact_type == "unknown"
    assert unknown_row.confidence is None
    assert unknown_row.reason == "opaque data"


def test_observation_rendering_is_readable_and_bounded() -> None:
    value = {"records": [{"pid": 4, "name": "System"}], "valid": True}

    assert observation_value_preview(value, limit=500) == (
        '{"records": [{"name": "System", "pid": 4}], "valid": true}'
    )
    assert '\n  "records": [' in observation_value_detail(value)
    assert observation_value_preview("x" * 100, limit=12).endswith("…")
    assert "truncated at 16 characters" in observation_value_detail("x" * 100, limit=16)

    recursive: list[object] = []
    recursive.append(recursive)
    assert "..." in observation_value_detail(recursive)


def test_observation_rows_include_all_kinds_and_stale_artifact_references() -> None:
    root = _artifact("root", "disk.raw", artifact_type="disk")
    child = _artifact("child", "record.bin", parent_id="root", depth=1)
    observations = [
        Observation("child", "filesystem.record", {"offset": 512}, "builtin:triage"),
        Observation("child", "planner.tool_plan", {"tool": "fls"}, "planner"),
        Observation("not-yet-visible", "live.partial", True, "worker"),
    ]

    rows = build_observation_rows([root, child], observations)

    assert [row.observation.key for row in rows] == [
        "filesystem.record", "planner.tool_plan", "live.partial",
    ]
    assert rows[0].lineage == ("disk.raw", "record.bin")
    assert rows[2].artifact is None
    assert rows[2].artifact_name == "unknown artifact (not-yet-visible)"
    assert rows[2].lineage_issue == "missing artifact not-yet-visible"


def test_textual_app_mounts_required_investigation_views_when_installed() -> None:
    if importlib.util.find_spec("textual") is None:
        return

    async def exercise() -> None:
        from textual.app import App
        from textual.widgets import DataTable, TabbedContent

        app = launch_tui(_build_only=True)
        assert isinstance(app, App)
        async with app.run_test(size=(180, 55)) as pilot:
            for table_id in ("artifacts", "classifications", "observations", "summary"):
                assert app.query_one(f"#{table_id}", DataTable)
            await pilot.press("f2")
            assert app.query_one("#results", TabbedContent).active == "artifacts-pane"
            await pilot.press("f3")
            assert app.query_one("#results", TabbedContent).active == "classifications-pane"
            await pilot.press("f4")
            assert app.query_one("#results", TabbedContent).active == "observations-pane"
            await pilot.press("f5")
            assert app.query_one("#results", TabbedContent).active == "summary-pane"

    asyncio.run(exercise())


def test_textual_app_runs_real_nonblocking_analysis_when_installed(tmp_path) -> None:
    if importlib.util.find_spec("textual") is None:
        return

    async def exercise() -> None:
        from textual.app import App
        from textual.widgets import Button, DataTable, Input

        evidence = tmp_path / "tui-evidence.txt"
        evidence.write_text("FLAG{TUI_ACTIVE_PIPELINE}", encoding="utf-8")
        app = launch_tui(_build_only=True)
        assert isinstance(app, App)
        async with app.run_test(size=(180, 55)) as pilot:
            app.query_one("#evidence-path", Input).value = str(evidence)
            app.query_one("#workspace-base", Input).value = str(tmp_path / "cases")
            app.query_one("#analyze", Button).press()
            for _ in range(200):
                await pilot.pause(0.05)
                if app.session.snapshot().status.value not in {"idle", "running"}:
                    break
            assert app.session.snapshot().status.value == "completed"
            await pilot.pause(0.5)
            assert app.query_one("#flags", DataTable).row_count == 1
            assert app.query_one("#artifacts", DataTable).row_count == 1
            assert app.query_one("#observations", DataTable).row_count > 0

    asyncio.run(exercise())
