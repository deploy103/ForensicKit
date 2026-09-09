from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from forensickit.browser import inspect_browser_database
from forensickit.engine import AnalysisEngine
from forensickit.models import AnalysisMode


def _chromium_schema(connection: sqlite3.Connection) -> None:
    connection.executescript("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
            typed_count INTEGER, last_visit_time INTEGER
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
            from_visit INTEGER, transition INTEGER
        );
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT,
            start_time INTEGER, end_time INTEGER, received_bytes INTEGER,
            total_bytes INTEGER, state INTEGER, danger_type INTEGER,
            interrupt_reason INTEGER, tab_url TEXT, tab_referrer_url TEXT
        );
        CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER, url TEXT);
        CREATE TABLE keyword_search_terms (keyword_id INTEGER, url_id INTEGER, term TEXT);
    """)


def test_chromium_history_download_and_search_are_normalized(tmp_path: Path) -> None:
    evidence = tmp_path / "History"
    connection = sqlite3.connect(evidence)
    try:
        _chromium_schema(connection)
        chromium_time = 13_370_000_000_000_000
        connection.execute(
            "INSERT INTO urls VALUES (1, ?, ?, 3, 1, ?)",
            ("https://ctf.invalid/search?q=trace", "Trace", chromium_time),
        )
        connection.execute("INSERT INTO visits VALUES (10, 1, ?, 0, 1)", (chromium_time,))
        connection.execute(
            "INSERT INTO downloads VALUES (20, ?, ?, ?, ?, 12, 12, 1, 0, 0, ?, ?)",
            (r"C:\\Temp\\answer.zip.crdownload", r"C:\\Temp\\answer.zip", chromium_time, chromium_time,
             "https://ctf.invalid/download", "https://ctf.invalid/"),
        )
        connection.execute("INSERT INTO downloads_url_chains VALUES (20, 0, ?)", ("https://cdn.invalid/answer.zip",))
        connection.execute("INSERT INTO keyword_search_terms VALUES (2, 1, ?)", ("offline flag clue",))
        connection.commit()
    finally:
        connection.close()

    inspected = inspect_browser_database(evidence, immutable=True)
    assert inspected.family == "chromium"
    assert {item["kind"] for item in inspected.records} == {"visit", "download", "search"}
    visit = next(item for item in inspected.records if item["kind"] == "visit")
    download = next(item for item in inspected.records if item["kind"] == "download")
    assert visit["visit_time_raw"] == 13_370_000_000_000_000
    assert visit["visit_time_basis"] == "microseconds since 1601-01-01 UTC"
    assert isinstance(visit["visit_time_utc"], str)
    assert download["url_chain"] == ["https://cdn.invalid/answer.zip"]


def test_firefox_and_safari_epochs_remain_explicit(tmp_path: Path) -> None:
    firefox = tmp_path / "places.sqlite"
    connection = sqlite3.connect(firefox)
    try:
        connection.executescript("""
            CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
            CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, from_visit INTEGER, visit_type INTEGER);
            INSERT INTO moz_places VALUES (1, 'https://firefox.invalid/', 'Firefox', 1, 1700000000000000);
            INSERT INTO moz_historyvisits VALUES (2, 1, 1700000000000000, 0, 1);
        """)
        connection.commit()
    finally:
        connection.close()
    safari = tmp_path / "History.db"
    connection = sqlite3.connect(safari)
    try:
        connection.executescript("""
            CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
            CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT);
            INSERT INTO history_items VALUES (1, 'https://safari.invalid/', 'Safari', 1);
            INSERT INTO history_visits VALUES (2, 1, 721692800, 'Safari visit');
        """)
        connection.commit()
    finally:
        connection.close()

    firefox_record = inspect_browser_database(firefox, immutable=True).records[0]
    safari_record = inspect_browser_database(safari, immutable=True).records[0]
    assert firefox_record["visit_date_basis"] == "microseconds since 1970-01-01 UTC"
    assert firefox_record["visit_date_utc"] == "2023-11-14T22:13:20+00:00"
    assert safari_record["visit_time_basis"] == "seconds since 2001-01-01 UTC"
    assert safari_record["visit_time_utc"] == "2023-11-14T22:13:20+00:00"


def test_supplied_wal_record_reaches_common_flag_search(tmp_path: Path) -> None:
    bundle = tmp_path / "browser"
    bundle.mkdir()
    database = bundle / "History"
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        _chromium_schema(connection)
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        chromium_time = 13_370_000_000_000_000
        connection.execute(
            "INSERT INTO urls VALUES (1, ?, ?, 1, 0, ?)",
            ("https://ctf.invalid/", "WAL", chromium_time),
        )
        connection.execute("INSERT INTO visits VALUES (1, 1, ?, 0, 1)", (chromium_time,))
        connection.execute("INSERT INTO keyword_search_terms VALUES (1, 1, ?)", ("FLAG{WAL_RECORD}",))
        connection.commit()
        assert (bundle / "History-wal").is_file()

        result = AnalysisEngine().analyze(
            bundle, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False,
        )
    finally:
        connection.close()

    main = next(item for item in result.artifacts if item.logical_name == "History")
    wal_observations = [
        item for item in result.observations
        if item.artifact_id == main.id and item.key == "browser.wal_records"
    ]
    assert wal_observations
    assert any(
        record.get("term") == "FLAG{WAL_RECORD}"
        for record in wal_observations[0].value
        if isinstance(record, dict)
    )
    candidate = next(item for item in result.flags if item.value == "FLAG{WAL_RECORD}")
    assert any(
        location.get("artifact_id") == main.id
        and location.get("source_kind") == "parsed_record"
        for location in candidate.locations
    )
    assert any(item.category == "browser_sqlite_wal" for item in result.findings)
    report = json.loads(Path(result.case.workspace, "reports", "report.json").read_text(encoding="utf-8"))
    timeline = [item for item in report["timeline"] if item.get("category") == "browser_activity"]
    assert any(item.get("search_term") == "FLAG{WAL_RECORD}" for item in timeline)
    assert any(
        item.get("url") == "https://ctf.invalid/"
        and item.get("timestamp_basis") == "microseconds since 1601-01-01 UTC"
        for item in timeline
    )


def test_non_wal_exact_name_companion_is_rejected(tmp_path: Path) -> None:
    bundle = tmp_path / "browser"
    bundle.mkdir()
    database = bundle / "History"
    connection = sqlite3.connect(database)
    try:
        _chromium_schema(connection)
        connection.commit()
    finally:
        connection.close()
    (bundle / "History-wal").write_bytes(b"not a WAL")

    result = AnalysisEngine().analyze(
        bundle, tmp_path / "cases", mode=AnalysisMode.TRIAGE, execute=False,
    )
    main = next(item for item in result.artifacts if item.logical_name == "History")
    errors = [
        item.value for item in result.observations
        if item.artifact_id == main.id and item.key == "browser.wal_errors"
    ]
    assert errors == [["exact-name companion does not have a SQLite WAL signature"]]
    assert not any(item.category == "browser_sqlite_wal" for item in result.findings)
