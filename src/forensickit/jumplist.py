from __future__ import annotations

"""Bounded Windows Jump List structure inspection.

Automatic Destinations are CFB containers with a ``DestList`` stream and
numbered Shell Link streams.  Custom Destinations are concatenated Shell Link
records ending at a documented marker.  The helpers retain stream/range
provenance and never resolve or launch a shortcut target.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re

from .cfb import CompoundFileError, CompoundFileReader


LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
CUSTOM_DESTINATIONS_FOOTER = bytes.fromhex(
    "abfbbfba4c42a7468c01f83a9c654cb3"
)
_NUMBERED_STREAM = re.compile(r"[0-9a-f]+", re.I)


@dataclass(slots=True)
class JumpListInspection:
    kind: str | None = None
    valid: bool = False
    application_id: str | None = None
    streams: list[dict[str, object]] = field(default_factory=list)
    destinations: list[dict[str, object]] = field(default_factory=list)
    destlist_header: dict[str, object] | None = None
    errors: list[str] = field(default_factory=list)
    truncated: bool = False


def inspect_jumplist(
    path: Path,
    *,
    logical_name: str,
    max_bytes: int = 64 * 1024 * 1024,
    max_entries: int = 4_096,
) -> JumpListInspection:
    result = JumpListInspection(application_id=_application_id(logical_name))
    size = path.stat().st_size
    try:
        with path.open("rb") as stream:
            header = stream.read(max(len(LNK_HEADER), 8))
    except OSError as exc:
        result.errors.append(str(exc)[:2_000])
        return result
    if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _inspect_automatic(
            path, result, max_bytes=max_bytes, max_entries=max_entries
        )
    maximum = min(size, max_bytes)
    try:
        with path.open("rb") as stream:
            data = stream.read(maximum)
    except OSError as exc:
        result.errors.append(str(exc)[:2_000])
        return result
    result.truncated = maximum < size
    offsets = _custom_link_offsets(data, max_entries=max_entries)
    footer_offsets = _all_offsets(data, CUSTOM_DESTINATIONS_FOOTER, max_entries + 1)
    # A standalone .lnk is not a Jump List.  The custom footer is the strong
    # structural discriminator; two or more concatenated valid headers are a
    # lower-confidence but still deterministic recovery condition.
    if not offsets or (not footer_offsets and len(offsets) < 2):
        return result
    result.kind = "custom_destinations"
    for index, offset in enumerate(offsets):
        next_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        footer = next(
            (item for item in footer_offsets if offset + len(LNK_HEADER) <= item <= next_offset),
            None,
        )
        end = footer if footer is not None else next_offset
        if end - offset < 76:
            result.errors.append(f"shortcut at offset {offset} is truncated")
            continue
        result.streams.append({
            "name": f"custom-{index:04d}",
            "source": "file_range",
            "offset": offset,
            "length": end - offset,
            "lnk_header_valid": True,
            "footer_offset": footer,
        })
    result.valid = bool(result.streams) and (bool(footer_offsets) or len(result.streams) >= 2)
    result.truncated = result.truncated or len(offsets) >= max_entries
    return result


def _inspect_automatic(
    path: Path,
    result: JumpListInspection,
    *,
    max_bytes: int,
    max_entries: int,
) -> JumpListInspection:
    try:
        reader = CompoundFileReader(
            path,
            max_table_bytes=min(max_bytes, 16 * 1024 * 1024),
            max_stream_bytes=max_bytes,
            max_directory_entries=max_entries + 256,
        )
    except (OSError, CompoundFileError, ValueError) as exc:
        result.errors.append(str(exc)[:2_000])
        return result
    dest_entry = next(
        (entry for entry in reader.stream_entries() if entry.name.casefold() == "destlist"),
        None,
    )
    if dest_entry is None:
        return result
    result.kind = "automatic_destinations"
    try:
        destlist = reader.stream(dest_entry)
        header, records, errors, truncated = parse_destlist(
            destlist, max_entries=max_entries
        )
        result.destlist_header = header
        result.destinations = records
        result.errors.extend(errors)
        result.truncated = truncated
    except (OSError, CompoundFileError, ValueError) as exc:
        result.errors.append(f"DestList: {exc}"[:2_000])
        return result
    for entry in reader.stream_entries():
        if entry is dest_entry or not _NUMBERED_STREAM.fullmatch(entry.name):
            continue
        record: dict[str, object] = {
            "name": entry.name,
            "source": "cfb_stream",
            "offset": None,
            "length": entry.size,
            "lnk_header_valid": False,
        }
        try:
            payload = reader.stream(entry)
            record["lnk_header_valid"] = payload.startswith(LNK_HEADER)
        except (OSError, CompoundFileError, ValueError) as exc:
            record["error"] = str(exc)[:1_000]
        result.streams.append(record)
        if len(result.streams) >= max_entries:
            result.truncated = True
            break
    version = result.destlist_header.get("version") if result.destlist_header else None
    result.valid = version in {1, 3, 4} and all(
        bool(item.get("lnk_header_valid")) for item in result.streams
    )
    return result


def parse_destlist(
    data: bytes, *, max_entries: int = 4_096
) -> tuple[dict[str, object], list[dict[str, object]], list[str], bool]:
    if len(data) < 32:
        raise ValueError("DestList stream is smaller than its 32-byte header")
    version = int.from_bytes(data[0:4], "little")
    declared_entries = int.from_bytes(data[4:8], "little")
    header: dict[str, object] = {
        "version": version,
        "declared_entries": declared_entries,
        "pinned_entries": int.from_bytes(data[8:12], "little"),
        "last_issued_entry_id": int.from_bytes(data[16:24], "little"),
        "stream_size": len(data),
    }
    if version not in {1, 3, 4}:
        raise ValueError(f"unsupported DestList version {version}")
    fixed_size = 114 if version == 1 else 130
    timestamp_offset = 96 if version == 1 else 100
    pin_offset = 104 if version == 1 else 108
    records: list[dict[str, object]] = []
    errors: list[str] = []
    cursor = 32
    target_count = min(declared_entries, max_entries)
    while len(records) < target_count and cursor < len(data):
        if cursor + fixed_size > len(data):
            errors.append(f"truncated DestList record header at stream offset {cursor}")
            break
        path_characters = int.from_bytes(
            data[cursor + fixed_size - 2:cursor + fixed_size], "little"
        )
        if path_characters > 32_768:
            errors.append(f"DestList path length exceeds safety cap at stream offset {cursor}")
            break
        end = cursor + fixed_size + path_characters * 2
        if end > len(data):
            errors.append(f"truncated DestList path at stream offset {cursor}")
            break
        raw_hostname = data[cursor + 72:cursor + 88]
        hostname = raw_hostname.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        path_text = data[cursor + fixed_size:end].decode("utf-16le", errors="replace")
        timestamp_raw = int.from_bytes(
            data[cursor + timestamp_offset:cursor + timestamp_offset + 8], "little"
        )
        record: dict[str, object] = {
            "record_index": len(records),
            "stream_offset": cursor,
            "record_length": end - cursor,
            "entry_id": int.from_bytes(data[cursor + 88:cursor + 96], "little"),
            "hostname": hostname[:256],
            "path": path_text[:8_192],
            "path_characters": path_characters,
            "last_access_time_raw_filetime": timestamp_raw,
            "last_access_time_utc": _filetime(timestamp_raw),
            "pin_status": int.from_bytes(
                data[cursor + pin_offset:cursor + pin_offset + 4], "little"
            ),
        }
        if version in {3, 4}:
            record["access_count"] = int.from_bytes(
                data[cursor + 116:cursor + 120], "little"
            )
        records.append(record)
        cursor = end
    truncated = declared_entries > max_entries
    if len(records) != min(declared_entries, max_entries):
        errors.append(
            f"DestList declared {declared_entries} entries but {len(records)} bounded records parsed"
        )
    if cursor < len(data) and len(records) >= target_count:
        header["unparsed_tail_bytes"] = len(data) - cursor
    return header, records, errors, truncated


def automatic_link_streams(
    path: Path, *, max_bytes: int, max_entries: int
) -> list[tuple[str, bytes]]:
    reader = CompoundFileReader(
        path,
        max_table_bytes=min(max_bytes, 16 * 1024 * 1024),
        max_stream_bytes=max_bytes,
        max_directory_entries=max_entries + 256,
    )
    output: list[tuple[str, bytes]] = []
    for entry in reader.stream_entries():
        if not _NUMBERED_STREAM.fullmatch(entry.name):
            continue
        payload = reader.stream(entry)
        if payload.startswith(LNK_HEADER):
            output.append((entry.name, payload))
        if len(output) >= max_entries:
            break
    return output


def custom_link_ranges(
    path: Path, *, max_bytes: int, max_entries: int
) -> list[tuple[int, int]]:
    size = path.stat().st_size
    with path.open("rb") as stream:
        data = stream.read(min(size, max_bytes))
    offsets = _custom_link_offsets(data, max_entries=max_entries)
    footers = _all_offsets(data, CUSTOM_DESTINATIONS_FOOTER, max_entries + 1)
    if not offsets or (not footers and len(offsets) < 2):
        return []
    output: list[tuple[int, int]] = []
    for index, offset in enumerate(offsets):
        next_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
        footer = next(
            (item for item in footers if offset + len(LNK_HEADER) <= item <= next_offset),
            None,
        )
        end = footer if footer is not None else next_offset
        if end - offset >= 76:
            output.append((offset, end))
    return output


def _custom_link_offsets(data: bytes, *, max_entries: int) -> list[int]:
    return _all_offsets(data, LNK_HEADER, max_entries)


def _all_offsets(data: bytes, marker: bytes, limit: int) -> list[int]:
    output: list[int] = []
    cursor = 0
    while len(output) < limit:
        offset = data.find(marker, cursor)
        if offset < 0:
            break
        output.append(offset)
        cursor = offset + len(marker)
    return output


def _application_id(logical_name: str) -> str | None:
    basename = logical_name.replace("\\", "/").rsplit("/", 1)[-1]
    folded = basename.casefold()
    for suffix in (".automaticdestinations-ms", ".customdestinations-ms"):
        if folded.endswith(suffix):
            candidate = basename[:-len(suffix)]
            return candidate[:256] or None
    return None


def _filetime(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        return (
            datetime(1601, 1, 1, tzinfo=UTC)
            + timedelta(microseconds=value // 10)
        ).isoformat()
    except (OverflowError, ValueError):
        return None
