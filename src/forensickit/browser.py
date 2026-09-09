from __future__ import annotations

"""Read-only, bounded normalization for common browser SQLite schemas."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from typing import Callable


@dataclass(slots=True)
class BrowserInspection:
    family: str | None = None
    profile: str | None = None
    records: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    wal_applied: bool = False


def inspect_browser_database(
    path: Path,
    *,
    immutable: bool,
    wal_applied: bool = False,
    max_records: int = 2_000,
) -> BrowserInspection:
    """Normalize known history/download/search records using fixed SQL only."""
    if max_records <= 0:
        raise ValueError("max_records must be positive")
    result = BrowserInspection(wal_applied=wal_applied)
    query = "?mode=ro&immutable=1" if immutable else "?mode=ro"
    uri = f"{Path(path).resolve().as_uri()}{query}"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2.0)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            tables = {
                str(row[0]).casefold(): str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' LIMIT 1000"
                )
            }
            if {"urls", "visits"} <= set(tables):
                result.family, result.profile = "chromium", "history"
                _inspect_chromium(connection, tables, result, max_records)
            elif {"moz_places", "moz_historyvisits"} <= set(tables):
                result.family, result.profile = "firefox", "places"
                _inspect_firefox(connection, tables, result, max_records)
            elif {"history_items", "history_visits"} <= set(tables):
                result.family, result.profile = "safari", "history"
                _inspect_safari(connection, tables, result, max_records)
            elif "moz_formhistory" in tables:
                result.family, result.profile = "firefox", "formhistory"
                _inspect_firefox_formhistory(connection, tables, result, max_records)
        finally:
            connection.close()
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        result.errors.append(str(exc)[:2_000])
    return result


def _inspect_chromium(
    connection: sqlite3.Connection,
    tables: dict[str, str],
    result: BrowserInspection,
    limit: int,
) -> None:
    remaining = limit
    try:
        rows = connection.execute(
            "SELECT v.id AS visit_id, v.visit_time, v.from_visit, v.transition, "
            "u.id AS url_id, u.url, u.title, u.visit_count, u.typed_count, u.last_visit_time "
            "FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time DESC LIMIT ?",
            (remaining + 1,),
        ).fetchall()
        result.truncated |= len(rows) > remaining
        for row in rows[:remaining]:
            result.records.append({
                "kind": "visit", "table": "visits+urls", "row_id": row["visit_id"],
                "url_id": row["url_id"], "url": _text(row["url"]), "title": _text(row["title"]),
                "visit_count": row["visit_count"], "typed_count": row["typed_count"],
                **_timestamp("visit_time", row["visit_time"], _chromium_time, "microseconds since 1601-01-01 UTC"),
                "from_visit": row["from_visit"], "transition": row["transition"],
                "last_visit_time_raw": row["last_visit_time"],
            })
        remaining = max(0, limit - len(result.records))
    except sqlite3.DatabaseError as exc:
        result.errors.append(f"chromium visits: {exc}"[:2_000])

    if remaining and "downloads" in tables:
        columns = _columns(connection, tables["downloads"])
        selected = [
            name for name in (
                "id", "current_path", "target_path", "full_path", "start_time", "end_time",
                "received_bytes", "total_bytes", "state", "danger_type", "interrupt_reason",
                "tab_url", "tab_referrer_url", "referrer", "url",
            ) if name in columns
        ]
        if "id" in selected:
            try:
                sql = "SELECT " + ", ".join(_quote(name) for name in selected) + " FROM downloads ORDER BY id DESC LIMIT ?"
                rows = connection.execute(sql, (remaining + 1,)).fetchall()
                result.truncated |= len(rows) > remaining
                chains = _chromium_download_chains(connection, tables, remaining)
                for row in rows[:remaining]:
                    values = dict(row)
                    record: dict[str, object] = {
                        "kind": "download", "table": "downloads", "row_id": values.get("id"),
                        "path": _text(values.get("target_path") or values.get("current_path") or values.get("full_path")),
                        "url": _text(values.get("tab_url") or values.get("url")),
                        "referrer_url": _text(values.get("tab_referrer_url") or values.get("referrer")),
                        "url_chain": chains.get(values.get("id"), []),
                    }
                    for name in ("received_bytes", "total_bytes", "state", "danger_type", "interrupt_reason"):
                        if name in values:
                            record[name] = values[name]
                    if "start_time" in values:
                        record.update(_timestamp("start_time", values["start_time"], _chromium_time, "microseconds since 1601-01-01 UTC"))
                    if "end_time" in values:
                        record.update(_timestamp("end_time", values["end_time"], _chromium_time, "microseconds since 1601-01-01 UTC"))
                    result.records.append(record)
                remaining = max(0, limit - len(result.records))
            except sqlite3.DatabaseError as exc:
                result.errors.append(f"chromium downloads: {exc}"[:2_000])

    if remaining and "keyword_search_terms" in tables:
        try:
            rows = connection.execute(
                "SELECT k.rowid AS record_id, k.keyword_id, k.url_id, k.term, u.url "
                "FROM keyword_search_terms k LEFT JOIN urls u ON u.id=k.url_id "
                "ORDER BY k.rowid DESC LIMIT ?", (remaining + 1,),
            ).fetchall()
            result.truncated |= len(rows) > remaining
            for row in rows[:remaining]:
                result.records.append({
                    "kind": "search", "table": "keyword_search_terms", "row_id": row["record_id"],
                    "keyword_id": row["keyword_id"], "url_id": row["url_id"],
                    "term": _text(row["term"]), "url": _text(row["url"]),
                    "timestamp_raw": None, "timestamp_utc": None,
                })
        except sqlite3.DatabaseError as exc:
            result.errors.append(f"chromium search terms: {exc}"[:2_000])


def _chromium_download_chains(
    connection: sqlite3.Connection, tables: dict[str, str], limit: int
) -> dict[object, list[str]]:
    if "downloads_url_chains" not in tables:
        return {}
    output: dict[object, list[str]] = {}
    try:
        rows = connection.execute(
            "SELECT id, chain_index, url FROM downloads_url_chains "
            "ORDER BY id DESC, chain_index ASC LIMIT ?", (min(limit * 8, 16_000),),
        ).fetchall()
        for row in rows:
            urls = output.setdefault(row["id"], [])
            if len(urls) < 32:
                urls.append(_text(row["url"]))
    except sqlite3.DatabaseError:
        return {}
    return output


def _inspect_firefox(
    connection: sqlite3.Connection,
    tables: dict[str, str],
    result: BrowserInspection,
    limit: int,
) -> None:
    try:
        rows = connection.execute(
            "SELECT h.id AS visit_id, h.visit_date, h.from_visit, h.visit_type, "
            "p.id AS place_id, p.url, p.title, p.visit_count, p.last_visit_date "
            "FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id "
            "ORDER BY h.visit_date DESC LIMIT ?", (limit + 1,),
        ).fetchall()
        result.truncated |= len(rows) > limit
        for row in rows[:limit]:
            result.records.append({
                "kind": "visit", "table": "moz_historyvisits+moz_places", "row_id": row["visit_id"],
                "place_id": row["place_id"], "url": _text(row["url"]), "title": _text(row["title"]),
                "visit_count": row["visit_count"], "from_visit": row["from_visit"],
                "visit_type": row["visit_type"],
                **_timestamp("visit_date", row["visit_date"], _unix_microseconds, "microseconds since 1970-01-01 UTC"),
                "last_visit_date_raw": row["last_visit_date"],
            })
    except sqlite3.DatabaseError as exc:
        result.errors.append(f"firefox history: {exc}"[:2_000])


def _inspect_safari(
    connection: sqlite3.Connection,
    tables: dict[str, str],
    result: BrowserInspection,
    limit: int,
) -> None:
    try:
        rows = connection.execute(
            "SELECT v.id AS visit_id, v.visit_time, v.title AS visit_title, "
            "i.id AS item_id, i.url, i.title AS item_title, i.visit_count "
            "FROM history_visits v JOIN history_items i ON i.id=v.history_item "
            "ORDER BY v.visit_time DESC LIMIT ?", (limit + 1,),
        ).fetchall()
        result.truncated |= len(rows) > limit
        for row in rows[:limit]:
            result.records.append({
                "kind": "visit", "table": "history_visits+history_items", "row_id": row["visit_id"],
                "item_id": row["item_id"], "url": _text(row["url"]),
                "title": _text(row["visit_title"] or row["item_title"]), "visit_count": row["visit_count"],
                **_timestamp("visit_time", row["visit_time"], _safari_time, "seconds since 2001-01-01 UTC"),
            })
    except sqlite3.DatabaseError as exc:
        result.errors.append(f"safari history: {exc}"[:2_000])


def _inspect_firefox_formhistory(
    connection: sqlite3.Connection,
    tables: dict[str, str],
    result: BrowserInspection,
    limit: int,
) -> None:
    columns = _columns(connection, tables["moz_formhistory"])
    selected = [
        name for name in ("id", "fieldname", "value", "timesused", "firstused", "lastused")
        if name in columns
    ]
    if not {"fieldname", "value"} <= set(selected):
        return
    try:
        sql = "SELECT rowid AS record_id, " + ", ".join(_quote(name) for name in selected) + " FROM moz_formhistory ORDER BY rowid DESC LIMIT ?"
        rows = connection.execute(sql, (limit + 1,)).fetchall()
        result.truncated |= len(rows) > limit
        for row in rows[:limit]:
            values = dict(row)
            record: dict[str, object] = {
                "kind": "form_input", "table": "moz_formhistory", "row_id": values.get("record_id"),
                "field_name": _text(values.get("fieldname")), "value": _text(values.get("value")),
                "times_used": values.get("timesused"),
            }
            if "firstused" in values:
                record.update(_timestamp("first_used", values["firstused"], _unix_microseconds, "microseconds since 1970-01-01 UTC"))
            if "lastused" in values:
                record.update(_timestamp("last_used", values["lastused"], _unix_microseconds, "microseconds since 1970-01-01 UTC"))
            result.records.append(record)
    except sqlite3.DatabaseError as exc:
        result.errors.append(f"firefox form history: {exc}"[:2_000])


def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1]).casefold()
        for row in connection.execute(f"PRAGMA table_info({_quote(table)})")
    }


def _quote(identifier: str) -> str:
    # Callers only pass fixed allowlisted names or sqlite_master output.
    return '"' + identifier.replace('"', '""') + '"'


def _text(value: object) -> str:
    if value is None:
        return ""
    return str(value)[:8_192]


def _timestamp(
    name: str,
    raw: object,
    converter: Callable[[object], str | None],
    basis: str,
) -> dict[str, object]:
    return {
        f"{name}_raw": raw,
        f"{name}_basis": basis,
        f"{name}_utc": converter(raw),
    }


def _chromium_time(value: object) -> str | None:
    return _offset_time(value, datetime(1601, 1, 1, tzinfo=UTC), microseconds=True)


def _unix_microseconds(value: object) -> str | None:
    return _offset_time(value, datetime(1970, 1, 1, tzinfo=UTC), microseconds=True)


def _safari_time(value: object) -> str | None:
    return _offset_time(value, datetime(2001, 1, 1, tzinfo=UTC), microseconds=False)


def _offset_time(value: object, epoch: datetime, *, microseconds: bool) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        delta = timedelta(microseconds=value) if microseconds else timedelta(seconds=value)
        converted = epoch + delta
    except (OverflowError, ValueError):
        return None
    if converted.year < 1990 or converted.year > 2200:
        return None
    return converted.isoformat()
