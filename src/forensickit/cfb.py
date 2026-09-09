from __future__ import annotations

"""Small, bounded Compound File Binary (CFB/OLE) reader.

The runtime cannot assume that the optional ``olefile`` package is present.
This reader deliberately implements only the pieces needed to inventory and
extract streams from supplied evidence.  It validates every sector reference,
caps allocation, and never writes to or evaluates content from the container.
"""

from dataclasses import dataclass
from pathlib import Path


_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_DIFSECT = 0xFFFFFFFC
_SPECIAL_SECTOR_MIN = 0xFFFFFFFA


class CompoundFileError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CompoundDirectoryEntry:
    index: int
    name: str
    object_type: int
    start_sector: int
    size: int

    @property
    def type_name(self) -> str:
        return {1: "storage", 2: "stream", 5: "root"}.get(
            self.object_type, "unknown"
        )


class CompoundFileReader:
    """Read validated CFB streams with finite sector and byte budgets."""

    def __init__(
        self,
        path: Path,
        *,
        max_table_bytes: int = 16 * 1024 * 1024,
        max_stream_bytes: int = 64 * 1024 * 1024,
        max_directory_entries: int = 16_384,
    ) -> None:
        self.path = Path(path).resolve(strict=True)
        self.file_size = self.path.stat().st_size
        self.max_table_bytes = max_table_bytes
        self.max_stream_bytes = max_stream_bytes
        self.max_directory_entries = max_directory_entries
        if min(max_table_bytes, max_stream_bytes, max_directory_entries) <= 0:
            raise ValueError("CFB limits must be positive")
        self._header = self._read_at(0, min(self.file_size, 512))
        self._parse_header()
        self._fat = self._load_fat()
        self.entries = self._load_directory()
        self._root = next(
            (entry for entry in self.entries if entry.object_type == 5), None
        )
        self._mini_fat: list[int] | None = None
        self._mini_stream: bytes | None = None

    def _parse_header(self) -> None:
        header = self._header
        if len(header) < 512 or header[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            raise CompoundFileError("invalid CFB signature or truncated header")
        if header[28:30] != b"\xfe\xff":
            raise CompoundFileError("unsupported CFB byte order")
        self.major_version = int.from_bytes(header[26:28], "little")
        sector_shift = int.from_bytes(header[30:32], "little")
        mini_sector_shift = int.from_bytes(header[32:34], "little")
        self.sector_size = 1 << sector_shift if sector_shift < 31 else 0
        self.mini_sector_size = 1 << mini_sector_shift if mini_sector_shift < 31 else 0
        if self.major_version not in {3, 4}:
            raise CompoundFileError(f"unsupported CFB major version {self.major_version}")
        if self.sector_size != (512 if self.major_version == 3 else 4096):
            raise CompoundFileError("CFB version and sector size disagree")
        if self.mini_sector_size != 64:
            raise CompoundFileError("unsupported CFB mini-sector size")
        if self.file_size < self.sector_size:
            raise CompoundFileError("CFB evidence is smaller than one header sector")
        self.sector_count = self.file_size // self.sector_size - 1
        self.fat_sector_count = int.from_bytes(header[44:48], "little")
        self.first_directory_sector = int.from_bytes(header[48:52], "little")
        self.mini_stream_cutoff = int.from_bytes(header[56:60], "little")
        self.first_minifat_sector = int.from_bytes(header[60:64], "little")
        self.minifat_sector_count = int.from_bytes(header[64:68], "little")
        self.first_difat_sector = int.from_bytes(header[68:72], "little")
        self.difat_sector_count = int.from_bytes(header[72:76], "little")
        if self.mini_stream_cutoff != 4096:
            raise CompoundFileError("unsupported CFB mini-stream cutoff")
        if self.fat_sector_count > self.sector_count:
            raise CompoundFileError("declared FAT sector count exceeds evidence")

    def _read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset > self.file_size or length > self.file_size - offset:
            raise CompoundFileError("CFB read exceeds supplied evidence")
        with self.path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(length)
        if len(data) != length:
            raise CompoundFileError("short CFB evidence read")
        return data

    def _sector(self, sector_id: int) -> bytes:
        if sector_id < 0 or sector_id >= self.sector_count:
            raise CompoundFileError(f"CFB sector {sector_id} is outside evidence")
        return self._read_at((sector_id + 1) * self.sector_size, self.sector_size)

    def _load_fat(self) -> list[int]:
        header_ids = [
            int.from_bytes(self._header[offset:offset + 4], "little")
            for offset in range(76, 512, 4)
        ]
        fat_sector_ids = [value for value in header_ids if value < _SPECIAL_SECTOR_MIN]
        next_difat = self.first_difat_sector
        seen_difat: set[int] = set()
        entries_per_difat = self.sector_size // 4 - 1
        for _ in range(self.difat_sector_count):
            if next_difat >= _SPECIAL_SECTOR_MIN or next_difat in seen_difat:
                raise CompoundFileError("invalid or cyclic CFB DIFAT chain")
            seen_difat.add(next_difat)
            raw = self._sector(next_difat)
            for index in range(entries_per_difat):
                value = int.from_bytes(raw[index * 4:index * 4 + 4], "little")
                if value < _SPECIAL_SECTOR_MIN:
                    fat_sector_ids.append(value)
            next_difat = int.from_bytes(raw[-4:], "little")
        if self.difat_sector_count and next_difat != _ENDOFCHAIN:
            raise CompoundFileError("CFB DIFAT chain did not terminate")
        if len(fat_sector_ids) < self.fat_sector_count:
            raise CompoundFileError("CFB DIFAT contains too few FAT sectors")
        fat_sector_ids = fat_sector_ids[: self.fat_sector_count]
        if len(set(fat_sector_ids)) != len(fat_sector_ids):
            raise CompoundFileError("duplicate CFB FAT sector reference")
        if len(fat_sector_ids) * self.sector_size > self.max_table_bytes:
            raise CompoundFileError("CFB FAT exceeds configured table limit")
        raw_fat = b"".join(self._sector(sector_id) for sector_id in fat_sector_ids)
        return [
            int.from_bytes(raw_fat[offset:offset + 4], "little")
            for offset in range(0, len(raw_fat), 4)
        ]

    def _chain_ids(self, start_sector: int, *, max_sectors: int) -> list[int]:
        if start_sector == _ENDOFCHAIN:
            return []
        current = start_sector
        seen: set[int] = set()
        output: list[int] = []
        while current != _ENDOFCHAIN:
            if current >= _SPECIAL_SECTOR_MIN or current >= self.sector_count:
                raise CompoundFileError("CFB chain references an invalid sector")
            if current >= len(self._fat):
                raise CompoundFileError("CFB chain is outside the loaded FAT")
            if current in seen:
                raise CompoundFileError("cyclic CFB sector chain")
            if len(output) >= max_sectors:
                raise CompoundFileError("CFB sector chain exceeds configured limit")
            seen.add(current)
            output.append(current)
            current = self._fat[current]
        return output

    def _read_regular_chain(
        self, start_sector: int, *, declared_size: int | None, limit: int
    ) -> bytes:
        if declared_size is not None and declared_size > limit:
            raise CompoundFileError("CFB stream exceeds configured byte limit")
        wanted = limit if declared_size is None else declared_size
        maximum_sectors = max(1, (wanted + self.sector_size - 1) // self.sector_size)
        sector_ids = self._chain_ids(start_sector, max_sectors=maximum_sectors)
        data = b"".join(self._sector(sector_id) for sector_id in sector_ids)
        if declared_size is not None:
            if len(data) < declared_size:
                raise CompoundFileError("CFB stream chain is shorter than declared size")
            return data[:declared_size]
        if len(data) >= limit and sector_ids and self._fat[sector_ids[-1]] != _ENDOFCHAIN:
            raise CompoundFileError("CFB unbounded chain reached configured byte limit")
        return data

    def _load_directory(self) -> list[CompoundDirectoryEntry]:
        raw = self._read_regular_chain(
            self.first_directory_sector,
            declared_size=None,
            limit=min(self.max_table_bytes, self.max_directory_entries * 128),
        )
        entries: list[CompoundDirectoryEntry] = []
        for index in range(min(len(raw) // 128, self.max_directory_entries)):
            item = raw[index * 128:(index + 1) * 128]
            object_type = item[66]
            if object_type not in {1, 2, 5}:
                continue
            name_length = int.from_bytes(item[64:66], "little")
            if name_length < 2 or name_length > 64 or name_length & 1:
                raise CompoundFileError("invalid CFB directory entry name length")
            name = item[:name_length - 2].decode("utf-16le", errors="replace")
            size = int.from_bytes(item[120:128], "little")
            if self.major_version == 3:
                size &= 0xFFFFFFFF
            entries.append(
                CompoundDirectoryEntry(
                    index=index,
                    name=name,
                    object_type=object_type,
                    start_sector=int.from_bytes(item[116:120], "little"),
                    size=size,
                )
            )
        if not entries:
            raise CompoundFileError("CFB directory has no valid entries")
        return entries

    def stream_entries(self) -> list[CompoundDirectoryEntry]:
        return [entry for entry in self.entries if entry.object_type == 2]

    def stream(self, entry: CompoundDirectoryEntry | str) -> bytes:
        if isinstance(entry, str):
            folded = entry.casefold()
            matched = next(
                (item for item in self.stream_entries() if item.name.casefold() == folded),
                None,
            )
            if matched is None:
                raise CompoundFileError(f"CFB stream not found: {entry}")
            entry = matched
        if entry.object_type != 2:
            raise CompoundFileError("requested CFB directory entry is not a stream")
        if entry.size > self.max_stream_bytes:
            raise CompoundFileError("CFB stream exceeds configured byte limit")
        if entry.size == 0:
            return b""
        if entry.size >= self.mini_stream_cutoff:
            return self._read_regular_chain(
                entry.start_sector, declared_size=entry.size, limit=self.max_stream_bytes
            )
        return self._read_mini_stream(entry.start_sector, entry.size)

    def _read_mini_stream(self, start_sector: int, size: int) -> bytes:
        if self._root is None:
            raise CompoundFileError("CFB mini stream has no root directory entry")
        if self._mini_fat is None:
            raw = self._read_regular_chain(
                self.first_minifat_sector,
                declared_size=self.minifat_sector_count * self.sector_size,
                limit=self.max_table_bytes,
            )
            self._mini_fat = [
                int.from_bytes(raw[offset:offset + 4], "little")
                for offset in range(0, len(raw), 4)
            ]
        if self._mini_stream is None:
            self._mini_stream = self._read_regular_chain(
                self._root.start_sector,
                declared_size=self._root.size,
                limit=self.max_stream_bytes,
            )
        current = start_sector
        seen: set[int] = set()
        output = bytearray()
        maximum = (size + self.mini_sector_size - 1) // self.mini_sector_size
        while current != _ENDOFCHAIN and len(seen) < maximum:
            if current >= _SPECIAL_SECTOR_MIN or current >= len(self._mini_fat):
                raise CompoundFileError("CFB mini stream references invalid mini sector")
            if current in seen:
                raise CompoundFileError("cyclic CFB mini-sector chain")
            offset = current * self.mini_sector_size
            if offset + self.mini_sector_size > len(self._mini_stream):
                raise CompoundFileError("CFB mini sector exceeds root mini stream")
            seen.add(current)
            output.extend(self._mini_stream[offset:offset + self.mini_sector_size])
            current = self._mini_fat[current]
        if len(output) < size or current != _ENDOFCHAIN:
            raise CompoundFileError("CFB mini stream chain does not match declared size")
        return bytes(output[:size])
