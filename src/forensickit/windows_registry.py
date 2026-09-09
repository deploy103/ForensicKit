from __future__ import annotations

"""Bounded semantic readers for Amcache and AppCompatCache Registry data.

The reader intentionally follows only a few fixed Windows artifact paths.  It
does not replay transaction logs, enumerate an entire hive, or infer program
execution from cache presence.  All cell references are range checked against
the immutable input file before they are followed.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
import zlib


_HIVE_DATA_OFFSET = 4096
_UNSET_OFFSETS = {0xFFFFFFFF, 0xFFFFFFFE}
_VALUE_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


@dataclass(slots=True)
class RegistryActivityResult:
    amcache_detected: bool = False
    amcache_schema: str | None = None
    amcache_records: list[dict[str, object]] = field(default_factory=list)
    shimcache_detected: bool = False
    shimcache_formats: list[str] = field(default_factory=list)
    shimcache_records: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Key:
    offset: int
    name: str
    last_write_raw: int
    last_write_utc: str | None
    subkey_count: int
    subkey_list_offset: int
    value_count: int
    value_list_offset: int


@dataclass(frozen=True, slots=True)
class _Value:
    cell_offset: int
    name: str
    type_code: int
    type_name: str
    data: bytes | None
    data_size: int
    data_file_offset: int | None
    error: str | None = None


def _filetime(raw: int) -> str | None:
    if raw <= 0:
        return None
    try:
        return (
            datetime(1601, 1, 1, tzinfo=UTC)
            + timedelta(microseconds=raw // 10)
        ).isoformat()
    except OverflowError:
        return None


class _HiveReader:
    """Small random-access hive reader with hard traversal and data limits."""

    def __init__(
        self,
        path: Path,
        *,
        max_nodes: int = 4096,
        max_cell_bytes: int = 4 * 1024 * 1024,
        max_value_data_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        self.path = path
        self.size = path.stat().st_size
        self.max_nodes = max_nodes
        self.max_cell_bytes = max_cell_bytes
        self.max_value_data_bytes = max_value_data_bytes
        self.nodes_read = 0
        self.truncated = False
        self.errors: list[str] = []
        with path.open("rb") as stream:
            base = stream.read(_HIVE_DATA_OFFSET)
        if len(base) < 44 or base[:4] != b"regf":
            raise ValueError("not a structurally recognizable Registry hive")
        self.root_offset = int.from_bytes(base[36:40], "little")

    def _cell(self, offset: int, *, maximum: int | None = None) -> bytes | None:
        if offset in _UNSET_OFFSETS or offset < 0 or self.nodes_read >= self.max_nodes:
            if self.nodes_read >= self.max_nodes:
                self.truncated = True
            return None
        absolute = _HIVE_DATA_OFFSET + offset
        if absolute < _HIVE_DATA_OFFSET or absolute + 4 > self.size:
            return None
        maximum = min(maximum or self.max_cell_bytes, self.max_cell_bytes)
        try:
            with self.path.open("rb") as stream:
                stream.seek(absolute)
                raw_size = stream.read(4)
                if len(raw_size) != 4:
                    return None
                signed_size = int.from_bytes(raw_size, "little", signed=True)
                cell_size = -signed_size
                if signed_size >= -4 or cell_size > maximum or absolute + cell_size > self.size:
                    return None
                payload = stream.read(cell_size - 4)
        except OSError as exc:
            self.errors.append(str(exc)[:2_000])
            return None
        if len(payload) != cell_size - 4:
            return None
        self.nodes_read += 1
        return raw_size + payload

    def key(self, offset: int) -> _Key | None:
        cell = self._cell(offset, maximum=64 * 1024)
        if cell is None or len(cell) < 80 or cell[4:6] != b"nk":
            return None
        name_length = int.from_bytes(cell[76:78], "little")
        if name_length > 32 * 1024 or 80 + name_length > len(cell):
            return None
        flags = int.from_bytes(cell[6:8], "little")
        encoding = "latin-1" if flags & 0x20 else "utf-16le"
        if encoding == "utf-16le" and name_length % 2:
            return None
        name = cell[80:80 + name_length].decode(encoding, errors="replace")[:8_192]
        last_write_raw = int.from_bytes(cell[8:16], "little")
        return _Key(
            offset=offset,
            name=name,
            last_write_raw=last_write_raw,
            last_write_utc=_filetime(last_write_raw),
            subkey_count=int.from_bytes(cell[24:28], "little"),
            subkey_list_offset=int.from_bytes(cell[32:36], "little"),
            value_count=int.from_bytes(cell[40:44], "little"),
            value_list_offset=int.from_bytes(cell[44:48], "little"),
        )

    def child_offsets(self, key: _Key, *, maximum: int = 2048) -> list[int]:
        if key.subkey_count <= 0 or key.subkey_list_offset in _UNSET_OFFSETS:
            return []
        result: list[int] = []
        seen_lists: set[int] = set()

        def visit(offset: int, depth: int) -> None:
            if len(result) >= maximum:
                self.truncated = True
                return
            if depth > 3 or offset in seen_lists:
                return
            seen_lists.add(offset)
            cell = self._cell(offset, maximum=256 * 1024)
            if cell is None or len(cell) < 8:
                return
            signature = cell[4:6]
            count = int.from_bytes(cell[6:8], "little")
            if count > 65_536:
                self.errors.append(f"oversized subkey list at hive offset 0x{offset:x}")
                return
            if signature == b"ri":
                available = (len(cell) - 8) // 4
                for index in range(min(count, available)):
                    visit(int.from_bytes(cell[8 + index * 4:12 + index * 4], "little"), depth + 1)
            elif signature in {b"li", b"lf", b"lh"}:
                stride = 4 if signature == b"li" else 8
                available = (len(cell) - 8) // stride
                for index in range(min(count, available, maximum - len(result))):
                    result.append(int.from_bytes(cell[8 + index * stride:12 + index * stride], "little"))
                if count > available or len(result) >= maximum < count:
                    self.truncated = True

        visit(key.subkey_list_offset, 0)
        # A malformed list can repeat an NK reference.  Never parse it twice.
        return list(dict.fromkeys(result))[:maximum]

    def children(self, key: _Key, *, maximum: int = 2048) -> list[_Key]:
        children: list[_Key] = []
        for offset in self.child_offsets(key, maximum=maximum):
            child = self.key(offset)
            if child is not None:
                children.append(child)
        return children

    def child(self, key: _Key, name: str) -> _Key | None:
        wanted = name.casefold()
        return next(
            (item for item in self.children(key) if item.name.casefold() == wanted),
            None,
        )

    def values(self, key: _Key, *, maximum: int = 512) -> list[_Value]:
        if key.value_count <= 0 or key.value_list_offset in _UNSET_OFFSETS:
            return []
        count = min(key.value_count, maximum)
        if key.value_count > maximum:
            self.truncated = True
        cell = self._cell(key.value_list_offset, maximum=4 + count * 4 + 8)
        if cell is None or len(cell) < 4 + count * 4:
            self.errors.append(f"invalid value list for key {key.name!r} at 0x{key.offset:x}")
            return []
        values: list[_Value] = []
        for index in range(count):
            value_offset = int.from_bytes(cell[4 + index * 4:8 + index * 4], "little")
            value = self._value(value_offset)
            if value is not None:
                values.append(value)
        return values

    def _value(self, offset: int) -> _Value | None:
        cell = self._cell(offset, maximum=64 * 1024)
        if cell is None or len(cell) < 24 or cell[4:6] != b"vk":
            return None
        name_length = int.from_bytes(cell[6:8], "little")
        if name_length > 32 * 1024 or 24 + name_length > len(cell):
            return None
        flags = int.from_bytes(cell[20:22], "little")
        encoding = "latin-1" if flags & 1 else "utf-16le"
        if encoding == "utf-16le" and name_length % 2:
            return None
        raw_name = cell[24:24 + name_length]
        name = raw_name.decode(encoding, errors="replace")[:8_192] if raw_name else "(Default)"
        stored_size = int.from_bytes(cell[8:12], "little")
        data_size = stored_size & 0x7FFFFFFF
        type_code = int.from_bytes(cell[16:20], "little")
        type_name = _VALUE_TYPES.get(type_code, f"REG_UNKNOWN_{type_code}")
        if data_size > self.max_value_data_bytes:
            self.truncated = True
            return _Value(offset, name, type_code, type_name, None, data_size, None, "value data exceeds 16 MiB cap")
        if stored_size & 0x80000000:
            if data_size > 4:
                return _Value(offset, name, type_code, type_name, None, data_size, None, "invalid inline value size")
            return _Value(offset, name, type_code, type_name, cell[12:16][:data_size], data_size, _HIVE_DATA_OFFSET + offset + 12)
        data_offset = int.from_bytes(cell[12:16], "little")
        # Registry cells are 8-byte aligned, so the allocation can include up
        # to seven padding bytes beyond the four-byte cell header and payload.
        data_cell = self._cell(data_offset, maximum=max(8, data_size + 11))
        if data_cell is None or len(data_cell) - 4 < data_size:
            return _Value(offset, name, type_code, type_name, None, data_size, None, "invalid or truncated value-data cell")
        if data_cell[4:6] == b"db":
            return _Value(offset, name, type_code, type_name, None, data_size, None, "indirect Registry big-data value is unsupported")
        return _Value(
            offset, name, type_code, type_name, data_cell[4:4 + data_size], data_size,
            _HIVE_DATA_OFFSET + data_offset + 4,
        )


def _decoded_value(value: _Value) -> object:
    data = value.data
    if data is None:
        return {"unavailable": value.error or "data unavailable", "declared_size": value.data_size}
    if value.type_code in {1, 2, 6}:
        if len(data) % 2:
            return {"decode_error": "odd UTF-16 byte length", "data_hex": data[:256].hex()}
        return data.decode("utf-16le", errors="replace").rstrip("\x00")[:8_192]
    if value.type_code == 7:
        if len(data) % 2:
            return {"decode_error": "odd UTF-16 byte length", "data_hex": data[:256].hex()}
        return [item for item in data.decode("utf-16le", errors="replace").rstrip("\x00").split("\x00") if item][:256]
    if value.type_code == 4 and len(data) == 4:
        return int.from_bytes(data, "little")
    if value.type_code == 5 and len(data) == 4:
        return int.from_bytes(data, "big")
    if value.type_code == 11 and len(data) == 8:
        return int.from_bytes(data, "little")
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "preview_hex": data[:256].hex(),
        "preview_truncated": len(data) > 256,
    }


def _record_values(reader: _HiveReader, key: _Key) -> tuple[dict[str, object], list[dict[str, object]]]:
    decoded: dict[str, object] = {}
    provenance: list[dict[str, object]] = []
    for value in reader.values(key):
        rendered = _decoded_value(value)
        decoded[value.name] = rendered
        provenance.append({
            "name": value.name,
            "type": value.type_name,
            "type_code": value.type_code,
            "value_hive_offset": value.cell_offset,
            "value_file_offset": _HIVE_DATA_OFFSET + value.cell_offset,
            "data_file_offset": value.data_file_offset,
            "data_size": value.data_size,
            "value": rendered,
        })
    return decoded, provenance


def _pick(values: dict[str, object], *names: str) -> object | None:
    by_name = {key.casefold(): value for key, value in values.items()}
    for name in names:
        if name.casefold() in by_name:
            return by_name[name.casefold()]
    return None


def _amcache_record(reader: _HiveReader, key: _Key, kind: str, key_path: str) -> dict[str, object]:
    values, provenance = _record_values(reader, key)
    record: dict[str, object] = {
        "record_kind": kind,
        "key_path": key_path,
        "key_name": key.name,
        "key_hive_offset": key.offset,
        "key_file_offset": _HIVE_DATA_OFFSET + key.offset,
        "key_last_write_time_raw_filetime": key.last_write_raw,
        "key_last_write_time_utc": key.last_write_utc,
        "timestamp_basis": "Registry NK last-write FILETIME; not an execution timestamp",
        "values": values,
        "value_provenance": provenance,
    }
    mappings = {
        "name": ("Name", "ProductName"),
        "version": ("Version", "ProductVersion"),
        "publisher": ("Publisher", "CompanyName"),
        "path": ("LowerCaseLongPath", "LongPath", "FullPath", "RootDirPath"),
        "program_id": ("ProgramId",),
        "program_instance_id": ("ProgramInstanceId",),
        "file_id": ("FileId",),
        "size": ("Size", "FileSize"),
        "source": ("Source",),
        "install_date_raw": ("InstallDate", "InstallDateArpLastModified"),
        "link_date_raw": ("LinkDate",),
    }
    for output_name, source_names in mappings.items():
        value = _pick(values, *source_names)
        if value is not None and value != "":
            record[output_name] = value
    return record


def _parse_amcache(reader: _HiveReader, root: _Key, result: RegistryActivityResult) -> None:
    branches = {child.name.casefold(): child for child in reader.children(root, maximum=512)}
    schemas: list[str] = []

    for branch_name, kind in (
        ("inventoryapplication", "application"),
        ("inventoryapplicationfile", "application_file"),
        ("programs", "program"),
    ):
        branch = branches.get(branch_name)
        if branch is None:
            continue
        result.amcache_detected = True
        schemas.append(branch.name)
        for key in reader.children(branch, maximum=2_000):
            result.amcache_records.append(
                _amcache_record(reader, key, kind, f"{branch.name}\\{key.name}")
            )
            if len(result.amcache_records) >= 4_000:
                reader.truncated = True
                break

    # Windows 7-era Amcache uses Root\File\<volume>\<file-reference>.
    file_branch = branches.get("file")
    if file_branch is not None:
        result.amcache_detected = True
        schemas.append(file_branch.name)
        for volume in reader.children(file_branch, maximum=256):
            for key in reader.children(volume, maximum=2_000):
                result.amcache_records.append(
                    _amcache_record(reader, key, "file", f"{file_branch.name}\\{volume.name}\\{key.name}")
                )
                if len(result.amcache_records) >= 4_000:
                    reader.truncated = True
                    break
            if len(result.amcache_records) >= 4_000:
                break
    if schemas:
        result.amcache_schema = "+".join(schemas)


def _shimcache_entries(
    value: _Value,
    *,
    control_set: str,
    key_path: str,
    maximum: int = 4_000,
) -> tuple[list[dict[str, object]], list[str], list[str], bool]:
    data = value.data
    if data is None:
        return [], [value.error or "AppCompatCache value data is unavailable"], [], False
    records: list[dict[str, object]] = []
    errors: list[str] = []
    formats: list[str] = []
    cursor = 0
    while len(records) < maximum:
        positions = [position for magic in (b"10ts", b"00ts") if (position := data.find(magic, cursor)) >= 0]
        if not positions:
            break
        offset = min(positions)
        magic = data[offset:offset + 4]
        if offset + 14 > len(data):
            errors.append(f"truncated {magic.decode('ascii', errors='replace')} entry header at value offset 0x{offset:x}")
            break
        checksum = int.from_bytes(data[offset + 4:offset + 8], "little")
        entry_size = int.from_bytes(data[offset + 8:offset + 12], "little")
        end = offset + 12 + entry_size
        path_size = int.from_bytes(data[offset + 12:offset + 14], "little")
        if (
            entry_size < 14 or end > len(data) or path_size < 2 or path_size % 2
            or path_size > 32 * 1024 or 2 + path_size + 12 > entry_size
        ):
            errors.append(f"invalid {magic.decode('ascii', errors='replace')} entry bounds at value offset 0x{offset:x}")
            cursor = offset + 4
            continue
        body = data[offset + 12:end]
        raw_path = body[2:2 + path_size]
        path_text = raw_path.decode("utf-16le", errors="replace").rstrip("\x00")[:16_384]
        trailer = 2 + path_size
        modified_raw = int.from_bytes(body[trailer:trailer + 8], "little")
        payload_size = int.from_bytes(body[trailer + 8:trailer + 12], "little")
        if trailer + 12 + payload_size > len(body):
            errors.append(f"entry payload exceeds declared {magic.decode('ascii', errors='replace')} bounds at value offset 0x{offset:x}")
            cursor = offset + 4
            continue
        format_name = "windows_10_or_newer_10ts" if magic == b"10ts" else "windows_8_or_newer_00ts"
        if format_name not in formats:
            formats.append(format_name)
        checksum_computed = zlib.crc32(body) & 0xFFFFFFFF
        records.append({
            "record_kind": "shimcache_entry",
            "cache_format": format_name,
            "control_set": control_set,
            "key_path": key_path,
            "value_name": value.name,
            "value_hive_offset": value.cell_offset,
            "value_file_offset": _HIVE_DATA_OFFSET + value.cell_offset,
            "value_data_file_offset": value.data_file_offset,
            "entry_offset_in_value": offset,
            "entry_hive_offset": (
                value.data_file_offset + offset - _HIVE_DATA_OFFSET
                if value.data_file_offset is not None else None
            ),
            "entry_file_offset": value.data_file_offset + offset if value.data_file_offset is not None else None,
            "entry_size": entry_size,
            "path": path_text,
            "last_modified_time_raw_filetime": modified_raw,
            "last_modified_time_utc": _filetime(modified_raw),
            "timestamp_basis": "cached file last-modified FILETIME; not an execution timestamp",
            "entry_payload_size": payload_size,
            "checksum_stored": f"0x{checksum:08x}",
            "checksum_crc32_body": f"0x{checksum_computed:08x}",
            "checksum_matches_crc32_body": checksum == checksum_computed,
        })
        cursor = end
    truncated = len(records) >= maximum
    if not records:
        errors.append("AppCompatCache value uses an unsupported or unrecognized entry layout")
    return records, errors, formats, truncated


def _parse_shimcache(reader: _HiveReader, root: _Key, result: RegistryActivityResult) -> None:
    root_children = reader.children(root, maximum=512)
    controls = [child for child in root_children if child.name.casefold().startswith("controlset")]
    for control_set in controls[:32]:
        control = reader.child(control_set, "Control")
        session_manager = reader.child(control, "Session Manager") if control else None
        cache_key = reader.child(session_manager, "AppCompatCache") if session_manager else None
        if cache_key is None:
            continue
        key_path = f"{control_set.name}\\Control\\Session Manager\\AppCompatCache"
        cache_values = [
            value for value in reader.values(cache_key, maximum=32)
            if value.name.casefold() in {"appcompatcache", "cachemainsdb"}
        ]
        if not cache_values:
            continue
        result.shimcache_detected = True
        for value in cache_values:
            records, errors, formats, truncated = _shimcache_entries(
                value, control_set=control_set.name, key_path=key_path,
            )
            result.shimcache_records.extend(records)
            result.errors.extend(f"{key_path}\\{value.name}: {error}" for error in errors)
            result.truncated = result.truncated or truncated
            for format_name in formats:
                if format_name not in result.shimcache_formats:
                    result.shimcache_formats.append(format_name)


def inspect_registry_activity(path: Path) -> RegistryActivityResult:
    """Inspect one hive for structurally addressed Amcache/Shimcache records."""
    result = RegistryActivityResult()
    try:
        reader = _HiveReader(path)
        root = reader.key(reader.root_offset)
        if root is None:
            result.errors.append("Registry root NK cell is invalid")
            return result
        _parse_amcache(reader, root, result)
        _parse_shimcache(reader, root, result)
        result.errors.extend(reader.errors[:128])
        result.truncated = result.truncated or reader.truncated
    except (OSError, ValueError) as exc:
        result.errors.append(str(exc)[:2_000])
    result.amcache_records = result.amcache_records[:4_000]
    result.shimcache_records = result.shimcache_records[:4_000]
    return result
