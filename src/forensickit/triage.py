from __future__ import annotations

import hashlib
import math
import plistlib
import re
import sqlite3
import struct
import uuid
import zipfile
import zlib
from datetime import UTC, datetime, timedelta
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .config import AnalysisLimits
from .models import Artifact, Observation
from .pcap import PcapObservationEngine


_MIB = 1024 * 1024
_MAX_PREVIEW = 512


@dataclass(frozen=True, slots=True)
class _Signature:
    name: str
    format: str
    value: bytes


_SIGNATURES = (
    _Signature("png", "png", b"\x89PNG\r\n\x1a\n"),
    _Signature("jpeg", "jpeg", b"\xff\xd8\xff"),
    _Signature("gif87a", "gif", b"GIF87a"),
    _Signature("gif89a", "gif", b"GIF89a"),
    _Signature("bmp", "bmp", b"BM"),
    _Signature("tiff_le", "tiff", b"II\x2a\x00"),
    _Signature("tiff_be", "tiff", b"MM\x00\x2a"),
    _Signature("zip_local", "zip", b"PK\x03\x04"),
    _Signature("zip_central", "zip", b"PK\x01\x02"),
    _Signature("zip_eocd", "zip", b"PK\x05\x06"),
    _Signature("7z", "7z", b"7z\xbc\xaf\x27\x1c"),
    _Signature("gzip", "gzip", b"\x1f\x8b\x08"),
    _Signature("pdf", "pdf", b"%PDF-"),
    _Signature("pcap_le", "pcap", b"\xd4\xc3\xb2\xa1"),
    _Signature("pcap_be", "pcap", b"\xa1\xb2\xc3\xd4"),
    _Signature("pcap_ns_le", "pcap", b"\x4d\x3c\xb2\xa1"),
    _Signature("pcap_ns_be", "pcap", b"\xa1\xb2\x3c\x4d"),
    _Signature("pcapng", "pcapng", b"\x0a\x0d\x0d\x0a"),
    _Signature("sqlite", "sqlite", b"SQLite format 3\x00"),
    _Signature("ole", "ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
    _Signature("elf", "elf", b"\x7fELF"),
    _Signature("dos_mz", "pe", b"MZ"),
    # These extra common container signatures improve generic triage without
    # requiring an external command or parser.
    _Signature("rar4", "rar", b"Rar!\x1a\x07\x00"),
    _Signature("rar5", "rar", b"Rar!\x1a\x07\x01\x00"),
    _Signature("cpio_newc", "cpio", b"070701"),
    _Signature("cpio_crc", "cpio", b"070702"),
    _Signature("cpio_odc", "cpio", b"070707"),
    _Signature("bzip2", "bzip2", b"BZh"),
    _Signature("xz", "xz", b"\xfd7zXZ\x00"),
    _Signature("ewf", "ewf", b"EVF\x09\x0d\x0a\xff\x00"),
    _Signature("hiberfil", "memory", b"hibr"),
    _Signature("windows_crash_dump", "memory", b"PAGE"),
    _Signature("evtx", "evtx", b"ElfFile\x00"),
    _Signature("registry", "registry", b"regf"),
    _Signature("android_backup", "android_backup", b"ANDROID BACKUP\n"),
    _Signature("binary_plist", "plist", b"bplist00"),
    _Signature("squashfs", "squashfs", b"hsqs"),
    _Signature("uimage", "uimage", b"\x27\x05\x19\x56"),
    _Signature("android_boot", "android_boot", b"ANDROID!"),
    _Signature("qcow2", "qcow2", b"QFI\xfb"),
    _Signature("id3", "audio", b"ID3"),
)

_MAX_SIGNATURE_LENGTH = max(len(item.value) for item in _SIGNATURES)


def _xml_attribute(element: str, name: str) -> str | None:
    """Return one local XML attribute value without constructing an XML tree."""
    match = re.search(
        rf"(?:\b[\w.-]+:)?{re.escape(name)}\s*=\s*(['\"])(.*?)\1",
        element,
        re.I | re.S,
    )
    return match.group(2)[:2_000] if match else None

_EXPECTED_EXTENSIONS: dict[str, frozenset[str]] = {
    "png": frozenset({".png"}),
    "jpeg": frozenset({".jpg", ".jpeg", ".jpe", ".jfif"}),
    "gif": frozenset({".gif"}),
    "bmp": frozenset({".bmp", ".dib"}),
    "tiff": frozenset({".tif", ".tiff"}),
    "zip": frozenset({".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx"}),
    "7z": frozenset({".7z"}),
    "gzip": frozenset({".gz", ".gzip", ".tgz"}),
    "tar": frozenset({".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2"}),
    "rar": frozenset({".rar"}),
    "cpio": frozenset({".cpio", ".newc"}),
    "iso9660": frozenset({".iso"}),
    "bzip2": frozenset({".bz2", ".tbz", ".tbz2"}),
    "xz": frozenset({".xz", ".txz"}),
    "pdf": frozenset({".pdf"}),
    "pcap": frozenset({".pcap", ".cap"}),
    "pcapng": frozenset({".pcapng", ".pcap"}),
    "sqlite": frozenset({".sqlite", ".sqlite3", ".db", ".db3"}),
    "android_backup": frozenset({".ab"}),
    "plist": frozenset({".plist", ".mobileconfig"}),
    "qcow2": frozenset({".qcow", ".qcow2"}),
    "squashfs": frozenset({".squashfs", ".sqsh"}),
    "uimage": frozenset({".uimage", ".img"}),
    "audio": frozenset({".mp3", ".wav", ".flac", ".ogg", ".m4a"}),
    "video": frozenset({".mp4", ".mov", ".mkv", ".avi", ".webm"}),
    "ole": frozenset({".doc", ".xls", ".ppt", ".msg", ".msi", ".ole"}),
    "elf": frozenset({".elf", ".so", ".bin", ""}),
    "pe": frozenset({".exe", ".dll", ".sys", ".scr", ".ocx"}),
}


@dataclass(slots=True)
class _ScanResult:
    offsets: dict[str, list[int]]
    counts: dict[str, int]
    last_offsets: dict[str, int]
    bytes_scanned: int
    scope: str


class GenericTriageEngine:
    """Bounded, deterministic in-process triage for untrusted evidence.

    The engine never loads an unbounded file into memory. Large files use
    explicit stratified samples for entropy and strings, while signature
    scanning is bounded by ``AnalysisLimits.signature_scan_bytes``. Every
    sampled result includes its scope and byte count so downstream rules do
    not mistake a sample for a whole-file measurement.
    """

    def __init__(
        self,
        limits: AnalysisLimits | None = None,
        *,
        entropy_scan_bytes: int = 16 * _MIB,
        header_bytes: int = 256,
        footer_bytes: int = 256,
        minimum_string_length: int = 4,
        max_signature_offsets: int = 128,
    ) -> None:
        self.limits = limits or AnalysisLimits()
        if entropy_scan_bytes <= 0 or header_bytes <= 0 or footer_bytes <= 0:
            raise ValueError("triage byte limits must be positive")
        if minimum_string_length < 2:
            raise ValueError("minimum_string_length must be at least two")
        if max_signature_offsets <= 0:
            raise ValueError("max_signature_offsets must be positive")
        self.entropy_scan_bytes = entropy_scan_bytes
        self.header_bytes = header_bytes
        self.footer_bytes = footer_bytes
        self.minimum_string_length = minimum_string_length
        self.max_signature_offsets = max_signature_offsets
        minimum = str(minimum_string_length).encode("ascii")
        self._ascii_pattern = re.compile(rb"[\x20-\x7e]{" + minimum + rb",}")
        self._utf16le_pattern = re.compile(
            rb"(?:[\x20-\x7e]\x00){" + minimum + rb",}"
        )
        self._utf16be_pattern = re.compile(
            rb"(?:\x00[\x20-\x7e]){" + minimum + rb",}"
        )

    def analyze(self, artifact: Artifact, path: Path) -> list[Observation]:
        """Return generic observations for *path* without changing the file."""

        path = path.resolve(strict=True)
        if not path.is_file():
            raise ValueError(f"artifact path is not a regular file: {path}")
        actual_size = path.stat().st_size
        observations: list[Observation] = []

        with path.open("rb") as stream:
            header = stream.read(min(self.header_bytes, actual_size))
            if actual_size:
                stream.seek(max(0, actual_size - self.footer_bytes))
                footer = stream.read(min(self.footer_bytes, actual_size))
            else:
                footer = b""

        observations.extend(
            (
                self._observation(artifact, "artifact.size", actual_size),
                self._observation(artifact, "artifact.header.hex", header.hex()),
                self._observation(artifact, "artifact.header.length", len(header)),
                self._observation(artifact, "artifact.footer.hex", footer.hex()),
                self._observation(artifact, "artifact.footer.length", len(footer)),
            )
        )
        if actual_size != artifact.size:
            observations.append(
                self._observation(
                    artifact,
                    "artifact.size_mismatch",
                    {"registered": artifact.size, "observed": actual_size},
                    confidence=1.0,
                )
            )

        entropy, entropy_bytes, entropy_scope, printable_ratio, nul_ratio = (
            self._measure_entropy(path, actual_size)
        )
        observations.extend(
            (
                self._observation(artifact, "entropy.shannon", entropy),
                self._observation(artifact, "entropy.scope", entropy_scope),
                self._observation(artifact, "entropy.bytes_sampled", entropy_bytes),
                self._observation(artifact, "content.printable_ratio", printable_ratio),
                self._observation(artifact, "content.nul_ratio", nul_ratio),
            )
        )

        observations.extend(self._string_observations(artifact, path, actual_size))

        signature_result = self._scan_signatures(path, actual_size)
        observations.extend(
            self._signature_observations(artifact, signature_result, header)
        )

        detected_format = self._detect_header_format(path, header, actual_size)
        observations.append(
            self._observation(
                artifact,
                "triage.detected_header_format",
                detected_format or "unknown",
                confidence=0.99 if detected_format else 0.3,
            )
        )
        observations.extend(
            self._extension_observations(artifact, detected_format)
        )

        if detected_format == "png":
            observations.extend(self._inspect_png(artifact, path, actual_size))
        if detected_format == "jpeg":
            observations.extend(
                self._inspect_jpeg(artifact, path, actual_size, signature_result)
            )
        if detected_format == "gif":
            observations.extend(self._inspect_gif(artifact, path, actual_size))
        if detected_format == "bmp":
            observations.extend(self._inspect_bmp(artifact, header, actual_size))
        if detected_format == "tiff":
            observations.extend(self._inspect_tiff(artifact, path, actual_size))
        if signature_result.counts.get("zip_local", 0):
            observations.extend(
                self._inspect_zip_headers(artifact, path, actual_size, signature_result)
            )
            observations.extend(self._inspect_ooxml(artifact, path))
            observations.extend(self._inspect_apk(artifact, path))
        if detected_format == "gzip":
            observations.extend(self._inspect_gzip_header(artifact, header))
        if detected_format == "cpio":
            observations.extend(self._inspect_cpio(artifact, path, actual_size))
        if detected_format == "iso9660":
            observations.extend(self._inspect_iso9660(artifact, path, actual_size))
        if detected_format in {"pcap", "pcapng"}:
            observations.extend(PcapObservationEngine(max_bytes=self.limits.signature_scan_bytes).analyze(artifact, path))
        if detected_format == "sqlite":
            observations.extend(self._inspect_sqlite(artifact, path, actual_size))
        if detected_format == "android_backup":
            observations.extend(self._inspect_android_backup(artifact, path))
        if detected_format == "plist":
            observations.extend(self._inspect_plist(artifact, path, actual_size))
        if detected_format in {"squashfs", "uimage", "android_boot"}:
            observations.extend(self._inspect_firmware(artifact, path, header, actual_size, detected_format))
        media_format = self._detect_media_format(header)
        if media_format is not None:
            observations.extend(self._inspect_media(artifact, path, header, actual_size, media_format))
        if detected_format == "pdf":
            observations.extend(self._inspect_pdf(artifact, path, actual_size))
        if detected_format == "ole":
            observations.extend(self._inspect_ole(artifact, path, header, actual_size))
        observations.extend(self._inspect_windows_artifacts(artifact, path, header, actual_size))
        if detected_format == "evtx":
            observations.extend(self._inspect_evtx(artifact, path))
        if detected_format == "registry":
            observations.extend(self._inspect_registry_hive(artifact, path))
        if self._is_tar(path, actual_size):
            observations.extend(
                (
                    self._observation(artifact, "archive.tar_signature", True),
                    self._observation(artifact, "archive.container_kind", "tar"),
                )
            )
            observations.extend(self._inspect_tar_headers(artifact, path, actual_size))
        if header.startswith(b"MZ"):
            observations.extend(self._inspect_pe_header(artifact, path, header, actual_size))
        if detected_format == "elf":
            observations.extend(self._inspect_elf_header(artifact, path, header, actual_size))
        observations.extend(self._inspect_disk_memory(artifact, path, header, actual_size))
        observations.extend(self._inspect_memory_markers(artifact, path, actual_size))
        if header.startswith(b"MDMP"):
            observations.extend(self._inspect_minidump(artifact, path, actual_size))
        observations.extend(self._inspect_filesystem_signatures(artifact, path, header, actual_size))
        if artifact.logical_name.replace("\\", "/").casefold().endswith("$usnjrnl:$j"):
            observations.extend(self._inspect_ntfs_usn_journal(artifact, path, actual_size))

        return observations

    # A concise alias is convenient for pipeline code and CLI handlers.
    triage = analyze

    @staticmethod
    def _observation(
        artifact: Artifact,
        key: str,
        value: object,
        *,
        confidence: float = 1.0,
    ) -> Observation:
        return Observation(
            artifact_id=artifact.id,
            key=key,
            value=value,
            source="generic_triage",
            confidence=confidence,
        )

    def _measure_entropy(
        self, path: Path, size: int
    ) -> tuple[float, int, str, float, float]:
        histogram = [0] * 256
        total = 0
        printable = 0
        nul = 0
        regions = _sample_regions(size, self.entropy_scan_bytes)
        with path.open("rb") as stream:
            for chunk, _ in _iter_region_chunks(stream, regions):
                total += len(chunk)
                printable += sum(1 for byte in chunk if byte in (9, 10, 13) or 32 <= byte <= 126)
                nul += chunk.count(0)
                for byte in chunk:
                    histogram[byte] += 1
        if total == 0:
            return 0.0, 0, "full", 0.0, 0.0
        entropy = -sum(
            (count / total) * math.log2(count / total)
            for count in histogram
            if count
        )
        scope = "full" if total == size else "sample"
        return (
            round(entropy, 6),
            total,
            scope,
            round(printable / total, 6),
            round(nul / total, 6),
        )

    def _string_observations(
        self, artifact: Artifact, path: Path, size: int
    ) -> list[Observation]:
        regions = _sample_regions(size, self.limits.max_string_scan_bytes)
        per_kind_limit = max(1, self.limits.max_strings // 3)
        counts = {"ascii": 0, "utf16le": 0, "utf16be": 0}
        samples: dict[str, list[dict[str, object]]] = {
            "ascii": [],
            "utf16le": [],
            "utf16be": [],
        }
        scanned = 0

        with path.open("rb") as stream:
            for start, length in regions:
                stream.seek(start)
                data = stream.read(length)
                scanned += len(data)
                self._collect_ascii_strings(
                    data, start, counts, samples, per_kind_limit
                )
                self._collect_utf16_strings(
                    data, start, counts, samples, per_kind_limit
                )

        scope = "full" if scanned == size else "sample"
        result = [
            self._observation(artifact, "strings.scope", scope),
            self._observation(artifact, "strings.bytes_scanned", scanned),
        ]
        for kind in ("ascii", "utf16le", "utf16be"):
            result.extend(
                (
                    self._observation(artifact, f"strings.{kind}.count", counts[kind]),
                    self._observation(artifact, f"strings.{kind}.samples", samples[kind]),
                    self._observation(
                        artifact,
                        f"strings.{kind}.samples_truncated",
                        counts[kind] > len(samples[kind]),
                    ),
                )
            )
        return result

    def _collect_ascii_strings(
        self,
        data: bytes,
        base_offset: int,
        counts: dict[str, int],
        samples: dict[str, list[dict[str, object]]],
        limit: int,
    ) -> None:
        for match in self._ascii_pattern.finditer(data):
            index, end = match.span()
            length = end - index
            counts["ascii"] += 1
            if len(samples["ascii"]) < limit:
                preview = data[index : min(end, index + _MAX_PREVIEW)].decode(
                    "ascii", errors="replace"
                )
                samples["ascii"].append(
                    {
                        "offset": base_offset + index,
                        "length": length,
                        "text": preview,
                        "truncated": length > _MAX_PREVIEW,
                    }
                )

    def _collect_utf16_strings(
        self,
        data: bytes,
        base_offset: int,
        counts: dict[str, int],
        samples: dict[str, list[dict[str, object]]],
        limit: int,
    ) -> None:
        self._collect_one_utf16_endian(
            data, base_offset, "utf16le", True, counts, samples, limit
        )
        self._collect_one_utf16_endian(
            data, base_offset, "utf16be", False, counts, samples, limit
        )

    def _collect_one_utf16_endian(
        self,
        data: bytes,
        base_offset: int,
        kind: str,
        little_endian: bool,
        counts: dict[str, int],
        samples: dict[str, list[dict[str, object]]],
        limit: int,
    ) -> None:
        data_length = len(data)
        pattern = self._utf16le_pattern if little_endian else self._utf16be_pattern
        for match in pattern.finditer(data):
            index, end = match.span()
            characters = (end - index) // 2
            # An ASCII-only UTF-16 string also resembles the opposite endian
            # when shifted one byte. Suppress that shifted view.
            if little_endian:
                shifted = (
                    index > 0
                    and data[index - 1] == 0
                    and end < data_length
                    and _is_printable_ascii(data[end])
                )
            else:
                shifted = (
                    index > 0
                    and _is_printable_ascii(data[index - 1])
                    and end < data_length
                    and data[end] == 0
                )
            if not shifted:
                counts[kind] += 1
                if len(samples[kind]) < limit:
                    preview_characters = min(characters, _MAX_PREVIEW)
                    raw = data[index : index + preview_characters * 2]
                    encoding = "utf-16-le" if little_endian else "utf-16-be"
                    samples[kind].append(
                        {
                            "offset": base_offset + index,
                            "length": characters,
                            "text": raw.decode(encoding, errors="replace"),
                            "truncated": characters > _MAX_PREVIEW,
                        }
                    )

    def _scan_signatures(self, path: Path, size: int) -> _ScanResult:
        offsets = {item.name: [] for item in _SIGNATURES}
        counts = {item.name: 0 for item in _SIGNATURES}
        last_offsets: dict[str, int] = {}
        regions = _sample_regions(size, self.limits.signature_scan_bytes)
        bytes_scanned = 0
        previous_by_name: dict[str, int] = {}

        with path.open("rb") as stream:
            for region_start, region_length in regions:
                carry = b""
                consumed = 0
                stream.seek(region_start)
                remaining = region_length
                while remaining:
                    chunk = stream.read(min(_MIB, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    bytes_scanned += len(chunk)
                    data = carry + chunk
                    data_offset = region_start + consumed - len(carry)
                    for signature in _SIGNATURES:
                        search_from = 0
                        while True:
                            found = data.find(signature.value, search_from)
                            if found < 0:
                                break
                            absolute = data_offset + found
                            if previous_by_name.get(signature.name) != absolute:
                                counts[signature.name] += 1
                                last_offsets[signature.name] = absolute
                                previous_by_name[signature.name] = absolute
                                if len(offsets[signature.name]) < self.max_signature_offsets:
                                    offsets[signature.name].append(absolute)
                            search_from = found + 1
                    carry = data[-(_MAX_SIGNATURE_LENGTH - 1) :]
                    consumed += len(chunk)

        return _ScanResult(
            offsets=offsets,
            counts=counts,
            last_offsets=last_offsets,
            bytes_scanned=bytes_scanned,
            scope="full" if bytes_scanned == size else "sample",
        )

    def _signature_observations(
        self, artifact: Artifact, scan: _ScanResult, header: bytes
    ) -> list[Observation]:
        result = [
            self._observation(artifact, "signatures.scope", scan.scope),
            self._observation(artifact, "signatures.bytes_scanned", scan.bytes_scanned),
        ]
        offsets_by_format: dict[str, set[int]] = {}
        counts_by_format: dict[str, int] = {}
        for signature in _SIGNATURES:
            if scan.counts[signature.name] == 0:
                continue
            result.extend(
                (
                    self._observation(
                        artifact,
                        f"signature.{signature.name}.offsets",
                        scan.offsets[signature.name],
                    ),
                    self._observation(
                        artifact,
                        f"signature.{signature.name}.count",
                        scan.counts[signature.name],
                    ),
                    self._observation(
                        artifact,
                        f"signature.{signature.name}.offsets_truncated",
                        scan.counts[signature.name]
                        > len(scan.offsets[signature.name]),
                    ),
                )
            )
            offsets_by_format.setdefault(signature.format, set()).update(
                scan.offsets[signature.name]
            )
            counts_by_format[signature.format] = (
                counts_by_format.get(signature.format, 0)
                + scan.counts[signature.name]
            )

        detected = _format_from_header_bytes(header)
        embedded: list[dict[str, object]] = []
        for format_name, format_offsets in sorted(offsets_by_format.items()):
            sorted_offsets = sorted(format_offsets)
            result.extend(
                (
                    self._observation(
                        artifact,
                        f"signature.{format_name}.offsets",
                        sorted_offsets,
                    ),
                    self._observation(
                        artifact,
                        f"signature.{format_name}.count",
                        counts_by_format[format_name],
                    ),
                )
            )
            # Internal records in a native container are not themselves an
            # embedded artifact. A signature for a different format is.
            embedded_offsets = (
                []
                if format_name == detected
                else [offset for offset in sorted_offsets if offset > 0]
            )
            if embedded_offsets:
                result.extend(
                    (
                        self._observation(
                            artifact,
                            f"embedded.{format_name}_signature",
                            True,
                        ),
                        self._observation(
                            artifact,
                            f"embedded.{format_name}.offsets",
                            embedded_offsets,
                        ),
                    )
                )
                embedded.extend(
                    {"format": format_name, "offset": offset}
                    for offset in embedded_offsets
                )

        zip_embedded = any(item["format"] == "zip" for item in embedded)
        result.extend(
            (
                self._observation(artifact, "embedded.pk_signature", zip_embedded),
                self._observation(artifact, "embedded.signatures", embedded),
                self._observation(artifact, "embedded.signature_count", len(embedded)),
            )
        )
        return result

    def _detect_header_format(self, path: Path, header: bytes, size: int) -> str | None:
        detected = _format_from_header_bytes(header)
        if detected is None:
            # XML plists commonly start with a declaration, whitespace, or a
            # UTF-8 BOM.  Require the actual plist element rather than using
            # an extension as format evidence.
            xml_head = header.lstrip(b"\xef\xbb\xbf\x00\t\r\n ").lower()
            if xml_head.startswith(b"<?xml") and b"<plist" in xml_head[:1024]:
                detected = "plist"
        if detected == "pe" and not _valid_pe_signature(path, header, size):
            return None
        if detected is None and self._is_tar(path, size):
            return "tar"
        if detected is None and self._is_iso9660(path, size):
            return "iso9660"
        return detected

    @staticmethod
    def _is_tar(path: Path, size: int) -> bool:
        if size < 512:
            return False
        try:
            with path.open("rb") as stream:
                stream.seek(257)
                return stream.read(5) == b"ustar"
        except OSError:
            return False

    @staticmethod
    def _is_iso9660(path: Path, size: int) -> bool:
        descriptor_offset = 16 * 2_048
        if size < descriptor_offset + 7:
            return False
        try:
            with path.open("rb") as stream:
                stream.seek(descriptor_offset)
                header = stream.read(7)
        except OSError:
            return False
        return header[:1] in {b"\x00", b"\x01", b"\x02", b"\x03", b"\xff"} and header[1:6] == b"CD001" and header[6:7] == b"\x01"

    def _inspect_tar_headers(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Walk a bounded TAR header prefix without extracting any member."""
        entries: list[dict[str, object]] = []
        invalid_checksums: list[dict[str, object]] = []
        offset = 0
        scanned = 0
        limit = min(size, 32 * _MIB)
        terminated = False
        error: str | None = None
        type_names = {
            b"0": "regular", b"\x00": "regular", b"1": "hardlink", b"2": "symlink",
            b"3": "character", b"4": "block", b"5": "directory", b"6": "fifo",
            b"g": "pax_global", b"x": "pax_extended", b"L": "gnu_long_name", b"K": "gnu_long_link",
        }
        try:
            with path.open("rb") as stream:
                while offset + 512 <= size and offset + 512 <= limit and len(entries) < 2_000:
                    stream.seek(offset)
                    header = stream.read(512)
                    scanned = offset + len(header)
                    if len(header) != 512:
                        error = "truncated TAR header"
                        break
                    if header == b"\x00" * 512:
                        terminated = True
                        break
                    raw_size = header[124:136].rstrip(b"\x00 ")
                    try:
                        member_size = int(raw_size or b"0", 8)
                    except ValueError:
                        error = f"invalid TAR member size at {offset:#x}"
                        break
                    stored_checksum = header[148:156].rstrip(b"\x00 ")
                    try:
                        expected_checksum = int(stored_checksum or b"0", 8)
                    except ValueError:
                        expected_checksum = -1
                    checksum_input = bytearray(header)
                    checksum_input[148:156] = b" " * 8
                    checksum_valid = sum(checksum_input) == expected_checksum
                    name = header[:100].rstrip(b"\x00").decode("utf-8", errors="replace")
                    prefix = header[345:500].rstrip(b"\x00").decode("utf-8", errors="replace")
                    full_name = f"{prefix}/{name}" if prefix and name else prefix or name
                    typeflag = header[156:157]
                    entry = {
                        "name": full_name[:2_000],
                        "offset": offset,
                        "size": member_size,
                        "type": type_names.get(typeflag, f"unknown_{typeflag.hex()}"),
                        "checksum_valid": checksum_valid,
                    }
                    entries.append(entry)
                    if not checksum_valid and len(invalid_checksums) < 100:
                        invalid_checksums.append(entry)
                    data_blocks = (member_size + 511) // 512
                    next_offset = offset + 512 + data_blocks * 512
                    if next_offset <= offset or next_offset > size:
                        error = f"TAR member at {offset:#x} extends past evidence"
                        break
                    offset = next_offset
        except OSError as exc:
            error = str(exc)[:2_000]
        return [
            self._observation(artifact, "archive.tar.entries_inspected", len(entries)),
            self._observation(artifact, "archive.tar.entries", entries),
            self._observation(artifact, "archive.tar.invalid_checksums", invalid_checksums),
            self._observation(artifact, "archive.tar.scan_bytes", scanned),
            self._observation(artifact, "archive.tar.scan_truncated", scanned < size and not terminated and error is None),
            self._observation(artifact, "archive.tar.terminated", terminated),
            self._observation(artifact, "archive.tar.structure_error", error),
        ]

    def _inspect_cpio(
        self, artifact: Artifact, path: Path, size: int,
    ) -> list[Observation]:
        """Walk a bounded portable-ASCII or SVR4 CPIO archive without extraction."""
        entries: list[dict[str, object]] = []
        invalid_checksums: list[dict[str, object]] = []
        formats: set[str] = set()
        trailer: dict[str, object] | None = None
        structure_error: str | None = None
        scan_truncated = False
        entry_limit_reached = False
        cursor = 0
        scan_limit = min(size, self.limits.signature_scan_bytes)
        entry_limit = min(self.limits.max_artifact_count, 4_096)
        checksum_budget = min(self.limits.signature_scan_bytes, 16 * _MIB)
        checksum_bytes_read = 0
        bytes_read = 0
        magic_names = {b"070701": "newc", b"070702": "crc", b"070707": "odc"}
        type_names = {
            0o010000: "fifo",
            0o020000: "character",
            0o040000: "directory",
            0o060000: "block",
            0o100000: "regular",
            0o120000: "symlink",
            0o140000: "socket",
        }
        newc_field_names = (
            "inode", "mode", "uid", "gid", "link_count", "mtime",
            "file_size", "device_major", "device_minor",
            "rdevice_major", "rdevice_minor", "name_size", "checksum",
        )
        try:
            with path.open("rb") as stream:
                while len(entries) < entry_limit:
                    if cursor + 6 > size:
                        structure_error = f"truncated CPIO header at offset {cursor}"
                        break
                    if cursor + 6 > scan_limit:
                        scan_truncated = True
                        break
                    stream.seek(cursor)
                    magic = stream.read(6)
                    bytes_read += len(magic)
                    format_name = magic_names.get(magic)
                    if format_name is None:
                        structure_error = f"invalid CPIO magic at offset {cursor}"
                        break
                    header_length = 76 if format_name == "odc" else 110
                    alignment = 2 if format_name == "odc" else 4
                    numeric_encoding = "octal" if format_name == "odc" else "hexadecimal"
                    if cursor + header_length > size:
                        structure_error = f"truncated CPIO header at offset {cursor}"
                        break
                    if cursor + header_length > scan_limit:
                        scan_truncated = True
                        break
                    stream.seek(cursor)
                    header = stream.read(header_length)
                    bytes_read += len(header)
                    if len(header) != header_length:
                        structure_error = f"truncated CPIO header at offset {cursor}"
                        break
                    formats.add(format_name)
                    if format_name == "odc":
                        if any(byte not in b"01234567" for byte in header[6:]):
                            structure_error = f"non-octal CPIO odc header field at offset {cursor}"
                            break
                        fields = {
                            "device": int(header[6:12], 8),
                            "inode": int(header[12:18], 8),
                            "mode": int(header[18:24], 8),
                            "uid": int(header[24:30], 8),
                            "gid": int(header[30:36], 8),
                            "link_count": int(header[36:42], 8),
                            "rdevice": int(header[42:48], 8),
                            "mtime": int(header[48:59], 8),
                            "name_size": int(header[59:65], 8),
                            "file_size": int(header[65:76], 8),
                            "checksum": None,
                        }
                    else:
                        if any(byte not in b"0123456789abcdefABCDEF" for byte in header[6:]):
                            structure_error = f"non-hex CPIO header field at offset {cursor}"
                            break
                        values = [
                            int(header[6 + field * 8:14 + field * 8], 16)
                            for field in range(13)
                        ]
                        fields = dict(zip(newc_field_names, values, strict=True))
                    name_size = int(fields["name_size"])
                    file_size = int(fields["file_size"])
                    if not 1 <= name_size <= 4_096:
                        structure_error = (
                            f"invalid CPIO pathname length {name_size} at offset {cursor}"
                        )
                        break
                    name_offset = cursor + header_length
                    name_end = name_offset + name_size
                    if name_end > size:
                        structure_error = f"CPIO pathname at offset {name_offset} exceeds evidence"
                        break
                    if name_end > scan_limit:
                        scan_truncated = True
                        break
                    stream.seek(name_offset)
                    raw_name = stream.read(name_size)
                    bytes_read += len(raw_name)
                    if (
                        len(raw_name) != name_size
                        or not raw_name.endswith(b"\x00")
                        or b"\x00" in raw_name[:-1]
                    ):
                        structure_error = f"invalid CPIO pathname terminator at offset {name_offset}"
                        break
                    name = raw_name[:-1].decode("utf-8", errors="replace")
                    if not name:
                        structure_error = f"empty CPIO pathname at offset {name_offset}"
                        break
                    name_padding_length = (-name_end) % alignment
                    data_offset = name_end + name_padding_length
                    data_end = data_offset + file_size
                    data_padding_length = (-data_end) % alignment
                    next_header_offset = data_end + data_padding_length
                    mode = int(fields["mode"])
                    file_type_code = mode & 0o170000
                    normalized_name = name.replace("\\", "/")
                    path_safe = (
                        not normalized_name.startswith("/")
                        and re.match(r"^[A-Za-z]:/", normalized_name) is None
                        and ".." not in normalized_name.split("/")
                    )
                    record: dict[str, object] = {
                        "index": len(entries),
                        "format": format_name,
                        "magic": magic.decode("ascii"),
                        "header_offset": cursor,
                        "header_length": header_length,
                        "numeric_encoding": numeric_encoding,
                        "alignment": alignment,
                        "name": name[:4_095],
                        "name_raw_hex": raw_name[:-1].hex(),
                        "name_offset": name_offset,
                        "name_size_including_nul": name_size,
                        "name_padding_length": name_padding_length,
                        "data_offset": data_offset,
                        "data_length": file_size,
                        "data_end_offset": data_end,
                        "data_padding_length": data_padding_length,
                        "next_header_offset": next_header_offset,
                        "data_within_evidence": data_end <= size,
                        "path_safe": path_safe,
                        "inode": int(fields["inode"]),
                        "mode": f"0o{mode:o}",
                        "permissions": f"0o{mode & 0o7777:04o}",
                        "file_type": type_names.get(file_type_code, f"unknown_0o{file_type_code:o}"),
                        "uid": int(fields["uid"]),
                        "gid": int(fields["gid"]),
                        "link_count": int(fields["link_count"]),
                        "mtime_unix": int(fields["mtime"]),
                        "device_major": fields.get("device_major"),
                        "device_minor": fields.get("device_minor"),
                        "rdevice_major": fields.get("rdevice_major"),
                        "rdevice_minor": fields.get("rdevice_minor"),
                        "legacy_device": fields.get("device"),
                        "legacy_rdevice": fields.get("rdevice"),
                        "stored_checksum": fields["checksum"],
                        "calculated_checksum": None,
                        "checksum_valid": None,
                        "checksum_verification": (
                            "not_checked" if format_name == "crc" else "not_applicable"
                        ),
                    }
                    if format_name == "newc":
                        record["checksum_field_zero"] = int(fields["checksum"]) == 0
                    if data_end > size:
                        entries.append(record)
                        structure_error = (
                            f"CPIO member {name!r} at offset {cursor} exceeds evidence"
                        )
                        break
                    if next_header_offset > size:
                        entries.append(record)
                        structure_error = (
                            f"CPIO member {name!r} padding at offset {data_end} exceeds evidence"
                        )
                        break
                    stream.seek(name_end)
                    name_padding = stream.read(name_padding_length)
                    bytes_read += len(name_padding)
                    stream.seek(data_end)
                    data_padding = stream.read(data_padding_length)
                    bytes_read += len(data_padding)
                    record["name_padding_nonzero"] = any(name_padding)
                    record["data_padding_nonzero"] = any(data_padding)

                    if format_name == "crc":
                        checksum_remaining = checksum_budget - checksum_bytes_read
                        if file_size <= checksum_remaining:
                            calculated = 0
                            remaining = file_size
                            stream.seek(data_offset)
                            while remaining:
                                chunk = stream.read(min(1024 * 1024, remaining))
                                if not chunk:
                                    break
                                calculated = (calculated + sum(chunk)) & 0xFFFFFFFF
                                checksum_bytes_read += len(chunk)
                                bytes_read += len(chunk)
                                remaining -= len(chunk)
                            if remaining:
                                record["checksum_verification"] = "truncated_read"
                            else:
                                record["calculated_checksum"] = calculated
                                record["checksum_valid"] = calculated == int(fields["checksum"])
                                record["checksum_verification"] = "complete"
                                if record["checksum_valid"] is False:
                                    invalid_checksums.append(record)
                        else:
                            record["checksum_verification"] = "skipped_archive_checksum_byte_limit"

                    if name == "TRAILER!!!":
                        trailer = {**record, "valid_zero_length": file_size == 0}
                        if file_size != 0:
                            structure_error = "CPIO TRAILER!!! entry has nonzero data length"
                        cursor = next_header_offset
                        break
                    entries.append(record)
                    cursor = next_header_offset
                    if cursor > scan_limit:
                        scan_truncated = True
                        break
                else:
                    entry_limit_reached = True
                    scan_truncated = True
        except OSError as exc:
            structure_error = str(exc)[:2_000]

        if trailer is None and structure_error is None and not scan_truncated:
            structure_error = "CPIO archive ended without a TRAILER!!! entry"
        return [
            self._observation(artifact, "archive.cpio.detected", True),
            self._observation(artifact, "archive.cpio.formats", sorted(formats)),
            self._observation(artifact, "archive.cpio.format_consistent", len(formats) <= 1),
            self._observation(artifact, "archive.cpio.entry_count", len(entries)),
            self._observation(artifact, "archive.cpio.entries", entries),
            self._observation(artifact, "archive.cpio.invalid_checksums", invalid_checksums),
            self._observation(artifact, "archive.cpio.checksum_bytes_read", checksum_bytes_read),
            self._observation(artifact, "archive.cpio.checksum_byte_limit", checksum_budget),
            self._observation(artifact, "archive.cpio.trailer_found", trailer is not None),
            self._observation(artifact, "archive.cpio.trailer", trailer),
            self._observation(artifact, "archive.cpio.complete", trailer is not None and structure_error is None),
            self._observation(artifact, "archive.cpio.scan_limit", scan_limit),
            self._observation(artifact, "archive.cpio.scan_end_offset", cursor),
            self._observation(artifact, "archive.cpio.bytes_read", bytes_read),
            self._observation(artifact, "archive.cpio.scan_truncated", scan_truncated),
            self._observation(artifact, "archive.cpio.entry_limit_reached", entry_limit_reached),
            self._observation(artifact, "archive.cpio.structure_error", structure_error),
            self._observation(artifact, "archive.container_kind", "cpio"),
        ]

    def _inspect_iso9660(
        self, artifact: Artifact, path: Path, size: int,
    ) -> list[Observation]:
        """Parse bounded ISO 9660 descriptors and active primary-volume directories."""
        physical_block_size = 2_048
        descriptor_start = 16 * physical_block_size
        descriptor_budget = min(self.limits.signature_scan_bytes, 64 * physical_block_size)
        descriptor_end = min(size, descriptor_start + descriptor_budget)
        descriptor_types = {
            0: "boot",
            1: "primary",
            2: "supplementary",
            3: "partition",
            255: "terminator",
        }
        descriptors: list[dict[str, object]] = []
        descriptor_error: str | None = None
        descriptor_terminator_found = False
        pvd: dict[str, object] | None = None
        joliet_descriptors: list[dict[str, object]] = []
        el_torito_boot_records: list[dict[str, object]] = []

        try:
            with path.open("rb") as stream:
                for descriptor_index in range(64):
                    offset = descriptor_start + descriptor_index * physical_block_size
                    if offset + physical_block_size > size:
                        descriptor_error = f"truncated ISO volume descriptor at offset {offset}"
                        break
                    if offset + physical_block_size > descriptor_end:
                        descriptor_error = "ISO volume-descriptor scan reached its byte limit"
                        break
                    stream.seek(offset)
                    raw = stream.read(physical_block_size)
                    if len(raw) != physical_block_size:
                        descriptor_error = f"truncated ISO volume descriptor at offset {offset}"
                        break
                    descriptor_type = raw[0]
                    signature_valid = raw[1:6] == b"CD001"
                    version_valid = raw[6] == 1
                    descriptor = {
                        "index": descriptor_index,
                        "block": 16 + descriptor_index,
                        "offset": offset,
                        "type_code": descriptor_type,
                        "type": descriptor_types.get(descriptor_type, f"unknown_{descriptor_type}"),
                        "identifier_raw_hex": raw[1:6].hex(),
                        "identifier": raw[1:6].decode("ascii", errors="replace"),
                        "version": raw[6],
                        "signature_valid": signature_valid,
                        "version_valid": version_valid,
                    }
                    descriptors.append(descriptor)
                    if not signature_valid or not version_valid:
                        descriptor_error = f"invalid ISO volume descriptor header at offset {offset}"
                        break
                    if descriptor_type == 0:
                        boot_system_identifier = raw[7:39].decode(
                            "ascii", errors="replace"
                        ).rstrip(" \x00")
                        if boot_system_identifier == "EL TORITO SPECIFICATION":
                            catalog_block = int.from_bytes(raw[71:75], "little")
                            el_torito_boot_records.append({
                                "descriptor_offset": offset,
                                "descriptor_block": 16 + descriptor_index,
                                "boot_system_identifier": boot_system_identifier,
                                "boot_identifier": raw[39:71].decode(
                                    "ascii", errors="replace"
                                ).rstrip(" \x00"),
                                "catalog_block": catalog_block,
                                "catalog_block_field_offset": offset + 71,
                                "catalog_block_field_raw_hex": raw[71:75].hex(),
                                "valid": catalog_block > 0,
                            })
                    if descriptor_type == 1 and pvd is None:
                        volume_space_le = int.from_bytes(raw[80:84], "little")
                        volume_space_be = int.from_bytes(raw[84:88], "big")
                        volume_set_size_le = int.from_bytes(raw[120:122], "little")
                        volume_set_size_be = int.from_bytes(raw[122:124], "big")
                        volume_sequence_le = int.from_bytes(raw[124:126], "little")
                        volume_sequence_be = int.from_bytes(raw[126:128], "big")
                        logical_block_le = int.from_bytes(raw[128:130], "little")
                        logical_block_be = int.from_bytes(raw[130:132], "big")
                        path_table_size_le = int.from_bytes(raw[132:136], "little")
                        path_table_size_be = int.from_bytes(raw[136:140], "big")
                        declared_volume_bytes = volume_space_le * logical_block_le
                        root_length = raw[156]
                        root_raw = raw[156:156 + root_length]
                        root_record, root_error = self._iso9660_directory_record(
                            root_raw,
                            record_offset=offset + 156,
                            logical_block_size=logical_block_le,
                            evidence_size=size,
                            declared_volume_bytes=declared_volume_bytes,
                        )
                        failed_checks: list[str] = []
                        if volume_space_le <= 0 or volume_space_le != volume_space_be:
                            failed_checks.append("volume_space_size_both_endian")
                        if volume_set_size_le <= 0 or volume_set_size_le != volume_set_size_be:
                            failed_checks.append("volume_set_size_both_endian")
                        if volume_sequence_le <= 0 or volume_sequence_le != volume_sequence_be:
                            failed_checks.append("volume_sequence_number_both_endian")
                        if (
                            logical_block_le != logical_block_be
                            or logical_block_le < 512
                            or logical_block_le > 32_768
                            or logical_block_le & (logical_block_le - 1)
                        ):
                            failed_checks.append("logical_block_size_both_endian")
                        if path_table_size_le != path_table_size_be:
                            failed_checks.append("path_table_size_both_endian")
                        if declared_volume_bytes > size:
                            failed_checks.append("declared_volume_within_evidence")
                        if root_error is not None or root_record.get("file_type") != "directory":
                            failed_checks.append("root_directory_record")
                        pvd = {
                            "descriptor_offset": offset,
                            "descriptor_block": 16 + descriptor_index,
                            "system_identifier": raw[8:40].decode("ascii", errors="replace").rstrip(" "),
                            "volume_identifier": raw[40:72].decode("ascii", errors="replace").rstrip(" "),
                            "volume_space_blocks": volume_space_le,
                            "volume_space_blocks_big_endian": volume_space_be,
                            "volume_space_both_endian_match": volume_space_le == volume_space_be,
                            "declared_volume_bytes": declared_volume_bytes,
                            "declared_volume_within_evidence": declared_volume_bytes <= size,
                            "volume_set_size": volume_set_size_le,
                            "volume_set_size_big_endian": volume_set_size_be,
                            "volume_sequence_number": volume_sequence_le,
                            "volume_sequence_number_big_endian": volume_sequence_be,
                            "logical_block_size": logical_block_le,
                            "logical_block_size_big_endian": logical_block_be,
                            "logical_block_size_both_endian_match": logical_block_le == logical_block_be,
                            "path_table_size": path_table_size_le,
                            "path_table_size_big_endian": path_table_size_be,
                            "path_table_size_both_endian_match": path_table_size_le == path_table_size_be,
                            "little_endian_path_table_block": int.from_bytes(raw[140:144], "little"),
                            "optional_little_endian_path_table_block": int.from_bytes(raw[144:148], "little"),
                            "big_endian_path_table_block": int.from_bytes(raw[148:152], "big"),
                            "optional_big_endian_path_table_block": int.from_bytes(raw[152:156], "big"),
                            "root_directory_record_offset": offset + 156,
                            "root_directory_record_length": root_length,
                            "root_directory_record": root_record,
                            "root_directory_record_error": root_error,
                            "failed_checks": failed_checks,
                            "valid": not failed_checks,
                        }
                    if descriptor_type == 2 and raw[88:91] in {
                        b"%/@", b"%/C", b"%/E",
                    }:
                        joliet_level = {b"%/@": 1, b"%/C": 2, b"%/E": 3}[raw[88:91]]
                        volume_space_le = int.from_bytes(raw[80:84], "little")
                        volume_space_be = int.from_bytes(raw[84:88], "big")
                        volume_set_size_le = int.from_bytes(raw[120:122], "little")
                        volume_set_size_be = int.from_bytes(raw[122:124], "big")
                        volume_sequence_le = int.from_bytes(raw[124:126], "little")
                        volume_sequence_be = int.from_bytes(raw[126:128], "big")
                        logical_block_le = int.from_bytes(raw[128:130], "little")
                        logical_block_be = int.from_bytes(raw[130:132], "big")
                        path_table_size_le = int.from_bytes(raw[132:136], "little")
                        path_table_size_be = int.from_bytes(raw[136:140], "big")
                        declared_volume_bytes = volume_space_le * logical_block_le
                        root_length = raw[156]
                        root_raw = raw[156:156 + root_length]
                        root_record, root_error = self._iso9660_directory_record(
                            root_raw,
                            record_offset=offset + 156,
                            logical_block_size=logical_block_le,
                            evidence_size=size,
                            declared_volume_bytes=declared_volume_bytes,
                            identifier_encoding="joliet",
                        )
                        failed_checks: list[str] = []
                        if volume_space_le <= 0 or volume_space_le != volume_space_be:
                            failed_checks.append("volume_space_size_both_endian")
                        if volume_set_size_le <= 0 or volume_set_size_le != volume_set_size_be:
                            failed_checks.append("volume_set_size_both_endian")
                        if volume_sequence_le <= 0 or volume_sequence_le != volume_sequence_be:
                            failed_checks.append("volume_sequence_number_both_endian")
                        if (
                            logical_block_le != logical_block_be
                            or logical_block_le < 512
                            or logical_block_le > 32_768
                            or logical_block_le & (logical_block_le - 1)
                        ):
                            failed_checks.append("logical_block_size_both_endian")
                        if path_table_size_le != path_table_size_be:
                            failed_checks.append("path_table_size_both_endian")
                        if declared_volume_bytes > size:
                            failed_checks.append("declared_volume_within_evidence")
                        if root_error is not None or root_record.get("file_type") != "directory":
                            failed_checks.append("root_directory_record")
                        volume_identifier, volume_identifier_encoding_valid = (
                            self._iso9660_decode_ucs2(raw[40:72])
                        )
                        volume_identifier = volume_identifier.rstrip(" \x00")
                        if not volume_identifier_encoding_valid:
                            failed_checks.append("volume_identifier_ucs2")
                        joliet_descriptor = {
                            "descriptor_offset": offset,
                            "descriptor_block": 16 + descriptor_index,
                            "escape_sequence_raw_hex": raw[88:91].hex(),
                            "escape_sequence": raw[88:91].decode("ascii"),
                            "joliet_level": joliet_level,
                            "volume_identifier": volume_identifier,
                            "volume_identifier_encoding_valid": volume_identifier_encoding_valid,
                            "volume_space_blocks": volume_space_le,
                            "volume_space_blocks_big_endian": volume_space_be,
                            "declared_volume_bytes": declared_volume_bytes,
                            "volume_set_size": volume_set_size_le,
                            "volume_set_size_big_endian": volume_set_size_be,
                            "volume_sequence_number": volume_sequence_le,
                            "volume_sequence_number_big_endian": volume_sequence_be,
                            "logical_block_size": logical_block_le,
                            "logical_block_size_big_endian": logical_block_be,
                            "path_table_size": path_table_size_le,
                            "path_table_size_big_endian": path_table_size_be,
                            "little_endian_path_table_block": int.from_bytes(raw[140:144], "little"),
                            "optional_little_endian_path_table_block": int.from_bytes(raw[144:148], "little"),
                            "big_endian_path_table_block": int.from_bytes(raw[148:152], "big"),
                            "optional_big_endian_path_table_block": int.from_bytes(raw[152:156], "big"),
                            "root_directory_record_offset": offset + 156,
                            "root_directory_record_length": root_length,
                            "root_directory_record": root_record,
                            "root_directory_record_error": root_error,
                            "failed_checks": failed_checks,
                            "valid": not failed_checks,
                        }
                        joliet_descriptors.append(joliet_descriptor)
                        descriptor["joliet"] = joliet_descriptor
                    if descriptor_type == 255:
                        descriptor_terminator_found = True
                        break
        except OSError as exc:
            descriptor_error = str(exc)[:2_000]

        if pvd is None and descriptor_error is None:
            descriptor_error = "ISO descriptor sequence has no primary volume descriptor"

        el_torito_catalogs: list[dict[str, object]] = []
        el_torito_errors: list[dict[str, object]] = []
        el_torito_boot_images: list[dict[str, object]] = []
        if pvd is not None and pvd.get("valid") is True:
            (
                el_torito_catalogs,
                el_torito_errors,
                el_torito_boot_images,
            ) = self._iso9660_el_torito_catalogs(
                path,
                evidence_size=size,
                pvd=pvd,
                boot_records=el_torito_boot_records,
            )

        root_entries: list[dict[str, object]] = []
        root_error: str | None = None
        root_scan_bytes = 0
        root_scan_truncated = False
        root_entry_limit_reached = False
        if pvd is not None and isinstance(pvd.get("root_directory_record"), dict):
            root = pvd["root_directory_record"]
            logical_block_size = pvd.get("logical_block_size")
            root_offset = root.get("data_offset")
            root_length = root.get("data_length")
            if (
                pvd.get("valid") is True
                and isinstance(logical_block_size, int)
                and isinstance(root_offset, int)
                and isinstance(root_length, int)
                and 0 <= root_offset <= size
                and 0 <= root_length <= size - root_offset
            ):
                root_scan_bytes = min(
                    root_length, self.limits.signature_scan_bytes, 8 * _MIB,
                )
                root_scan_truncated = root_scan_bytes < root_length
                try:
                    with path.open("rb") as stream:
                        stream.seek(root_offset)
                        directory_data = stream.read(root_scan_bytes)
                except OSError as exc:
                    root_error = str(exc)[:2_000]
                    directory_data = b""
                entry_limit = min(self.limits.max_artifact_count + 2, 4_096)
                if root_error is None and len(directory_data) != root_scan_bytes:
                    root_error = (
                        f"truncated ISO root directory read at offset {root_offset}: "
                        f"expected {root_scan_bytes} bytes, received {len(directory_data)}"
                    )
                if root_error is None:
                    root_entries, parse_error, root_entry_limit_reached = (
                        self._iso9660_directory_records(
                            directory_data,
                            directory_offset=root_offset,
                            logical_block_size=logical_block_size,
                            evidence_size=size,
                            declared_volume_bytes=int(pvd["declared_volume_bytes"]),
                            entry_limit=entry_limit,
                        )
                    )
                    for record in root_entries:
                        record["root_directory_relative_offset"] = record.get(
                            "directory_relative_offset"
                        )
                    if not (
                        root_scan_truncated
                        and parse_error is not None
                        and parse_error.startswith("truncated ISO directory record")
                    ):
                        root_error = parse_error
                    if root_entry_limit_reached:
                        root_scan_truncated = True

        susp_config: dict[str, object] = {
            "detected": False,
            "skip_bytes": None,
            "source_record_offset": None,
            "extension_identifiers": [],
            "rock_ridge_detected": False,
        }
        susp_errors: list[dict[str, object]] = []
        root_self_entry = next(
            (entry for entry in root_entries if entry.get("logical_name") == "."),
            None,
        )
        if root_self_entry is not None:
            susp_config = self._iso9660_susp_configuration(root_self_entry)
        susp_skip = susp_config.get("skip_bytes")
        rock_ridge_detected = susp_config.get("rock_ridge_detected") is True
        susp_continuation_state: dict[str, object] = {
            "bytes_read": 0,
            "byte_limit": min(self.limits.signature_scan_bytes, _MIB),
            "area_count": 0,
            "area_limit": 128,
            "claimed_ranges": [],
        }
        if susp_config.get("detected") is True and isinstance(susp_skip, int):
            for entry in root_entries:
                continued_entries, continuation_errors = (
                    self._iso9660_resolve_susp_continuations(
                        path,
                        entry,
                        skip_bytes=susp_skip,
                        logical_block_size=int(pvd["logical_block_size"]),
                        evidence_size=size,
                        declared_volume_bytes=int(pvd["declared_volume_bytes"]),
                        state=susp_continuation_state,
                    )
                )
                susp_error, rrip_anomalies = self._iso9660_enrich_susp_record(
                    entry,
                    skip_bytes=susp_skip,
                    rock_ridge_detected=rock_ridge_detected,
                    continued_entries=continued_entries,
                    continuation_errors=continuation_errors,
                )
                if susp_error or rrip_anomalies:
                    susp_errors.append({
                        "record_offset": entry.get("record_offset"),
                        "file_identifier": entry.get("file_identifier"),
                            "susp_error": susp_error,
                            "continuation_errors": continuation_errors,
                        "rock_ridge_anomalies": rrip_anomalies,
                    })

        all_directory_entries = list(root_entries)
        multi_extent_chains: list[dict[str, object]] = []
        multi_extent_errors: list[dict[str, object]] = []
        directory_inventory: list[dict[str, object]] = []
        directory_traversal_errors: list[dict[str, object]] = []
        directory_scan_bytes = root_scan_bytes
        directory_scan_byte_limit = min(self.limits.signature_scan_bytes, 8 * _MIB)
        directory_limit = 32
        directory_traversal_truncated = root_scan_truncated
        total_entry_limit = min(self.limits.max_artifact_count + 64, 4_096)
        if pvd is not None and pvd.get("valid") is True:
            root_record = pvd.get("root_directory_record")
            logical_block_size = pvd.get("logical_block_size")
            declared_volume_bytes = pvd.get("declared_volume_bytes")
            if (
                isinstance(root_record, dict)
                and isinstance(logical_block_size, int)
                and isinstance(declared_volume_bytes, int)
            ):
                root_extent = (
                    root_record.get("data_offset"), root_record.get("data_length"),
                )
                root_identity = {
                    "logical_name": "/",
                    "file_identifier": ".",
                    "directory_record_offset": root_record.get("record_offset"),
                    "extent_block": root_record.get("extent_block"),
                    "data_offset": root_record.get("data_offset"),
                    "data_length": root_record.get("data_length"),
                }
                for entry in root_entries:
                    entry["containing_directory_identity"] = root_identity
                    entry["directory_identity_lineage"] = []
                    if entry.get("logical_name") not in {".", ".."}:
                        entry["archive_path"] = entry.get(
                            "archive_name", entry.get("logical_name")
                        )
                root_chains, root_chain_errors = self._iso9660_assemble_multi_extents(
                    root_entries, namespace="primary",
                )
                multi_extent_chains.extend(root_chains)
                multi_extent_errors.extend(root_chain_errors)

                queue: list[
                    tuple[
                        dict[str, object], list[dict[str, object]],
                        set[tuple[object, object]], tuple[object, object],
                    ]
                ] = []
                claimed_extents: set[tuple[object, object]] = {root_extent}

                def schedule_directory(
                    entry: dict[str, object],
                    parent_lineage: list[dict[str, object]],
                    ancestor_extents: set[tuple[object, object]],
                    parent_extent: tuple[object, object],
                ) -> None:
                    if (
                        entry.get("file_type") != "directory"
                        or entry.get("logical_name") in {".", ".."}
                        or entry.get("valid") is not True
                    ):
                        return
                    if entry.get("rock_ridge_type_mismatch") is True:
                        entry["directory_traversal"] = "rock_ridge_type_mismatch"
                        directory_traversal_errors.append({
                            "reason": "rock_ridge_type_mismatch",
                            "entry": entry,
                        })
                        return
                    if entry.get("susp_error"):
                        entry["directory_traversal"] = "susp_anomaly"
                        directory_traversal_errors.append({
                            "reason": "susp_anomaly",
                            "entry": entry,
                        })
                        return
                    if entry.get("rock_ridge_name_usable") is False:
                        entry["directory_traversal"] = "rock_ridge_name_unusable"
                        directory_traversal_errors.append({
                            "reason": "rock_ridge_name_unusable",
                            "entry": entry,
                        })
                        return
                    if entry.get("rock_ridge_relocation_traversal_suppressed") is True:
                        entry["directory_traversal"] = "rock_ridge_relocation"
                        return
                    if (
                        entry.get("multi_extent") is True
                        or entry.get("file_unit_size") not in {0, None}
                        or entry.get("interleave_gap_size") not in {0, None}
                    ):
                        entry["directory_traversal"] = "unsupported_layout"
                        directory_traversal_errors.append({
                            "reason": "unsupported_directory_layout",
                            "entry": entry,
                        })
                        return
                    extent = (entry.get("data_offset"), entry.get("data_length"))
                    identity = {
                        "logical_name": entry.get("archive_name", entry.get("logical_name")),
                        "file_identifier": entry.get("file_identifier"),
                        "directory_record_offset": entry.get("record_offset"),
                        "extent_block": entry.get("extent_block"),
                        "data_offset": entry.get("data_offset"),
                        "data_length": entry.get("data_length"),
                    }
                    if extent in ancestor_extents:
                        entry["directory_traversal"] = "ancestor_cycle"
                        directory_traversal_errors.append({
                            "reason": "ancestor_cycle",
                            "entry": entry,
                            "conflicting_extent": extent,
                        })
                        return
                    if extent in claimed_extents:
                        entry["directory_traversal"] = "shared_extent"
                        directory_traversal_errors.append({
                            "reason": "shared_extent",
                            "entry": entry,
                            "conflicting_extent": extent,
                        })
                        return
                    claimed_extents.add(extent)
                    entry["directory_traversal"] = "scheduled"
                    queue.append((
                        entry,
                        [*parent_lineage, identity],
                        {*ancestor_extents, extent},
                        parent_extent,
                    ))

                for entry in root_entries:
                    schedule_directory(entry, [], {root_extent}, root_extent)

                processed_directories = 0
                while queue and processed_directories < directory_limit:
                    directory_entry, lineage, ancestor_extents, parent_extent = queue.pop(0)
                    data_offset = directory_entry.get("data_offset")
                    data_length = directory_entry.get("data_length")
                    if (
                        not isinstance(data_offset, int)
                        or not isinstance(data_length, int)
                        or data_length <= 0
                        or data_offset < 0
                        or data_offset + data_length > size
                    ):
                        directory_entry["directory_traversal"] = "invalid_range"
                        directory_traversal_errors.append({
                            "reason": "invalid_range", "entry": directory_entry,
                        })
                        continue
                    if directory_scan_bytes + data_length > directory_scan_byte_limit:
                        directory_entry["directory_traversal"] = "byte_limit"
                        directory_traversal_errors.append({
                            "reason": "byte_limit", "entry": directory_entry,
                        })
                        directory_traversal_truncated = True
                        continue
                    remaining_entries = total_entry_limit - len(all_directory_entries)
                    if remaining_entries <= 0:
                        directory_entry["directory_traversal"] = "entry_limit"
                        directory_traversal_truncated = True
                        directory_traversal_errors.append({
                            "reason": "entry_limit", "entry": directory_entry,
                            "entry_limit": total_entry_limit,
                        })
                        break
                    try:
                        with path.open("rb") as stream:
                            stream.seek(data_offset)
                            directory_data = stream.read(data_length)
                    except OSError as exc:
                        directory_entry["directory_traversal"] = "read_error"
                        directory_traversal_errors.append({
                            "reason": "read_error", "error": str(exc)[:2_000],
                            "entry": directory_entry,
                        })
                        continue
                    directory_scan_bytes += len(directory_data)
                    if len(directory_data) != data_length:
                        directory_entry["directory_traversal"] = "truncated_read"
                        directory_traversal_errors.append({
                            "reason": "truncated_read", "entry": directory_entry,
                            "expected_bytes": data_length,
                            "received_bytes": len(directory_data),
                        })
                        continue
                    child_entries, child_error, child_limit = self._iso9660_directory_records(
                        directory_data,
                        directory_offset=data_offset,
                        logical_block_size=logical_block_size,
                        evidence_size=size,
                        declared_volume_bytes=declared_volume_bytes,
                        entry_limit=remaining_entries,
                    )
                    if susp_config.get("detected") is True and isinstance(susp_skip, int):
                        for child_entry in child_entries:
                            continued_entries, continuation_errors = (
                                self._iso9660_resolve_susp_continuations(
                                    path,
                                    child_entry,
                                    skip_bytes=susp_skip,
                                    logical_block_size=logical_block_size,
                                    evidence_size=size,
                                    declared_volume_bytes=declared_volume_bytes,
                                    state=susp_continuation_state,
                                )
                            )
                            susp_error, rrip_anomalies = self._iso9660_enrich_susp_record(
                                child_entry,
                                skip_bytes=susp_skip,
                                rock_ridge_detected=rock_ridge_detected,
                                continued_entries=continued_entries,
                                continuation_errors=continuation_errors,
                            )
                            if susp_error or rrip_anomalies:
                                susp_errors.append({
                                    "record_offset": child_entry.get("record_offset"),
                                    "file_identifier": child_entry.get("file_identifier"),
                                    "susp_error": susp_error,
                                    "continuation_errors": continuation_errors,
                                    "rock_ridge_anomalies": rrip_anomalies,
                                })
                    processed_directories += 1
                    directory_entry["directory_traversal"] = (
                        "parsed" if child_error is None and not child_limit else "parsed_with_anomaly"
                    )
                    current_identity = lineage[-1]
                    for child_entry in child_entries:
                        child_entry["containing_directory_identity"] = current_identity
                        child_entry["directory_identity_lineage"] = lineage
                        if child_entry.get("logical_name") not in {".", ".."}:
                            child_entry["archive_path"] = "/".join(
                                [
                                    *[
                                        str(identity.get("logical_name"))
                                        for identity in lineage
                                    ],
                                    str(child_entry.get(
                                        "archive_name", child_entry.get("logical_name")
                                    )),
                                ]
                            )
                    child_chains, child_chain_errors = self._iso9660_assemble_multi_extents(
                        child_entries, namespace="primary",
                    )
                    multi_extent_chains.extend(child_chains)
                    multi_extent_errors.extend(child_chain_errors)
                    all_directory_entries.extend(child_entries)
                    dot_entry = next(
                        (entry for entry in child_entries if entry.get("logical_name") == "."),
                        None,
                    )
                    dotdot_entry = next(
                        (entry for entry in child_entries if entry.get("logical_name") == ".."),
                        None,
                    )
                    self_extent = (data_offset, data_length)
                    dot_matches_self = bool(
                        dot_entry
                        and dot_entry.get("valid") is True
                        and dot_entry.get("file_type") == "directory"
                        and (dot_entry.get("data_offset"), dot_entry.get("data_length")) == self_extent
                    )
                    dotdot_matches_parent = bool(
                        dotdot_entry
                        and dotdot_entry.get("valid") is True
                        and dotdot_entry.get("file_type") == "directory"
                        and (dotdot_entry.get("data_offset"), dotdot_entry.get("data_length")) == parent_extent
                    )
                    inventory_record = {
                        "directory_identity": current_identity,
                        "directory_identity_lineage": lineage,
                        "ancestor_extents": sorted(
                            [list(extent) for extent in ancestor_extents],
                            key=lambda item: (str(item[0]), str(item[1])),
                        ),
                        "source_entry_offset": directory_entry.get("record_offset"),
                        "data_offset": data_offset,
                        "data_length": data_length,
                        "entry_count": len(child_entries),
                        "dot_entry_matches_self": dot_matches_self,
                        "dotdot_entry_matches_parent": dotdot_matches_parent,
                        "parse_error": child_error,
                        "entry_limit_reached": child_limit,
                    }
                    directory_inventory.append(inventory_record)
                    if child_error or child_limit or not dot_matches_self or not dotdot_matches_parent:
                        directory_traversal_errors.append({
                            "reason": "directory_consistency",
                            "inventory": inventory_record,
                        })
                    for child_entry in child_entries:
                        schedule_directory(
                            child_entry, lineage, ancestor_extents, self_extent,
                        )
                if queue:
                    directory_traversal_truncated = True
                    directory_traversal_errors.append({
                        "reason": "directory_limit",
                        "remaining_directory_count": len(queue),
                        "directory_limit": directory_limit,
                    })

        rock_ridge_relocations: list[dict[str, object]] = []
        known_directory_extents = [{
            "logical_name": "/",
            "record_offset": pvd.get("root_directory_record_offset") if pvd else None,
            "extent_block": (
                pvd.get("root_directory_record", {}).get("extent_block")
                if pvd and isinstance(pvd.get("root_directory_record"), dict) else None
            ),
            "archive_path": "/",
        }]
        known_directory_extents.extend(
            entry for entry in all_directory_entries
            if entry.get("file_type") == "directory"
            and entry.get("logical_name") not in {".", ".."}
        )
        for entry in all_directory_entries:
            relocation = entry.get("rock_ridge_relocation")
            if not isinstance(relocation, dict):
                continue
            record: dict[str, object] = {
                "source_record_offset": entry.get("record_offset"),
                "source_file_identifier": entry.get("file_identifier"),
                "source_archive_path": entry.get("archive_path"),
                "source_file_type": entry.get("file_type"),
                "traversal_suppressed": entry.get(
                    "rock_ridge_relocation_traversal_suppressed", False
                ),
                "child_links": [],
                "parent_links": [],
                "relocated_markers": relocation.get("relocated_markers", []),
            }
            for role, target_key in (
                ("child_links", "target_block"), ("parent_links", "target_block"),
            ):
                links = relocation.get(role, [])
                if not isinstance(links, list):
                    continue
                for link in links:
                    if not isinstance(link, dict):
                        continue
                    target_block = link.get(target_key)
                    matches = [
                        candidate for candidate in known_directory_extents
                        if candidate.get("extent_block") == target_block
                    ]
                    record[role].append({
                        **link,
                        "known_directory_match_count": len(matches),
                        "known_directory_record_offset": (
                            matches[0].get("record_offset") if len(matches) == 1 else None
                        ),
                        "known_directory_archive_path": (
                            matches[0].get("archive_path") if len(matches) == 1 else None
                        ),
                        "uniquely_reconciled": len(matches) == 1,
                    })
            rock_ridge_relocations.append(record)

        path_tables: list[dict[str, object]] = []
        path_table_comparison: dict[str, object] = {
            "available": False, "consistent": None,
            "reason": "primary_volume_descriptor_invalid_or_unavailable",
        }
        path_table_reconciliation: list[dict[str, object]] = []
        if pvd is not None and pvd.get("valid") is True:
            (
                path_tables,
                path_table_comparison,
                path_table_reconciliation,
            ) = self._iso9660_path_tables(
                path,
                evidence_size=size,
                pvd=pvd,
                directory_entries=all_directory_entries,
            )
        regular_files = [
            entry for entry in all_directory_entries
            if entry.get("file_type") == "regular"
            and entry.get("logical_name") not in {".", ".."}
            and entry.get("multi_extent_chain_role") not in {
                "continuation", "tail", "overflow",
            }
        ]
        valid_joliet_descriptors = [
            descriptor for descriptor in joliet_descriptors
            if descriptor.get("valid") is True
        ]
        active_joliet_descriptor = next(iter(sorted(
            valid_joliet_descriptors,
            key=lambda item: (
                -int(item.get("joliet_level", 0)),
                int(item.get("descriptor_offset", 0)),
            ),
        )), None)
        joliet_walk: dict[str, object] = {
            "entries": [], "regular_files": [], "inventory": [], "errors": [],
            "bytes_read": 0,
            "byte_limit": min(self.limits.signature_scan_bytes, 8 * _MIB),
            "entry_limit": min(self.limits.max_artifact_count + 64, 4_096),
            "directory_limit": 32,
            "truncated": False,
        }
        if active_joliet_descriptor is not None:
            joliet_walk = self._iso9660_walk_namespace(
                path,
                evidence_size=size,
                descriptor=active_joliet_descriptor,
                namespace="joliet",
                identifier_encoding="joliet",
            )
        joliet_entries = joliet_walk.get("entries", [])
        joliet_regular_files = joliet_walk.get("regular_files", [])
        joliet_multi_extent_chains = joliet_walk.get("multi_extent_chains", [])
        joliet_multi_extent_errors = joliet_walk.get("multi_extent_errors", [])
        if isinstance(joliet_multi_extent_chains, list):
            multi_extent_chains.extend(joliet_multi_extent_chains)
        if isinstance(joliet_multi_extent_errors, list):
            multi_extent_errors.extend(joliet_multi_extent_errors)
        joliet_aliases: list[dict[str, object]] = []
        joliet_reconciliation_errors: list[dict[str, object]] = []
        if isinstance(joliet_regular_files, list):
            for joliet_entry in joliet_regular_files:
                if not isinstance(joliet_entry, dict):
                    continue
                extent = self._iso9660_logical_extent_identity(joliet_entry)
                if extent is None:
                    joliet_entry["extraction_eligible"] = False
                    joliet_entry["extraction_reconciliation_ambiguous"] = True
                    joliet_reconciliation_errors.append({
                        "reason": "invalid_logical_extent_identity",
                        "joliet_entry": joliet_entry,
                    })
                    continue
                primary_matches = [
                    entry for entry in regular_files
                    if self._iso9660_logical_extent_identity(entry) == extent
                ]
                joliet_matches = [
                    entry for entry in joliet_regular_files
                    if isinstance(entry, dict)
                    and self._iso9660_logical_extent_identity(entry) == extent
                ]
                if len(primary_matches) == 1 and len(joliet_matches) == 1:
                    primary_entry = primary_matches[0]
                    alias = {
                        "data_offset": extent[0][0] if len(extent) == 1 else None,
                        "data_length": extent[0][1] if len(extent) == 1 else None,
                        "primary_record_offset": primary_entry.get("record_offset"),
                        "primary_archive_path": primary_entry.get("archive_path"),
                        "joliet_record_offset": joliet_entry.get("record_offset"),
                        "joliet_archive_path": joliet_entry.get("archive_path"),
                        "joliet_descriptor_offset": active_joliet_descriptor.get(
                            "descriptor_offset"
                        ) if active_joliet_descriptor else None,
                    }
                    if len(extent) > 1:
                        alias["logical_extent_segments"] = [
                            {"data_offset": segment[0], "data_length": segment[1]}
                            for segment in extent
                        ]
                        alias["assembled_data_length"] = sum(
                            segment[1] for segment in extent
                        )
                    joliet_aliases.append(alias)
                    primary_entry["joliet_alias"] = alias
                    primary_entry["joliet_archive_path"] = joliet_entry.get("archive_path")
                    primary_entry["joliet_record_offset"] = joliet_entry.get("record_offset")
                    primary_entry["joliet_containing_directory_identity"] = joliet_entry.get(
                        "containing_directory_identity"
                    )
                    primary_entry["joliet_directory_identity_lineage"] = joliet_entry.get(
                        "directory_identity_lineage"
                    )
                    if primary_entry.get("rock_ridge_name_usable") is not True:
                        primary_entry["archive_path"] = joliet_entry.get("archive_path")
                        primary_entry["archive_name_source"] = "joliet_extent_alias"
                    joliet_entry["primary_entry_match"] = alias
                    joliet_entry["extraction_reconciled_to_primary"] = True
                    joliet_entry["extraction_eligible"] = False
                elif not primary_matches and len(joliet_matches) == 1:
                    joliet_entry["extraction_reconciled_to_primary"] = False
                    regular_files.append(joliet_entry)
                else:
                    joliet_entry["extraction_eligible"] = False
                    joliet_entry["extraction_reconciliation_ambiguous"] = True
                    joliet_reconciliation_errors.append({
                        "reason": "ambiguous_extent_reconciliation",
                        "joliet_entry": joliet_entry,
                        "primary_match_count": len(primary_matches),
                        "joliet_match_count": len(joliet_matches),
                    })
        rock_ridge_entries = [
            entry for entry in all_directory_entries
            if entry.get("rock_ridge_present") is True
        ]
        rock_ridge_symlinks = [
            entry for entry in all_directory_entries
            if entry.get("rock_ridge_symlink") is True
        ]
        return [
            self._observation(artifact, "archive.iso9660.signature", True),
            self._observation(artifact, "archive.iso9660.physical_descriptor_block_size", physical_block_size),
            self._observation(artifact, "archive.iso9660.volume_descriptors", descriptors),
            self._observation(artifact, "archive.iso9660.descriptor_count", len(descriptors)),
            self._observation(artifact, "archive.iso9660.descriptor_terminator_found", descriptor_terminator_found),
            self._observation(artifact, "archive.iso9660.descriptor_error", descriptor_error),
            self._observation(artifact, "archive.iso9660.primary_volume_descriptor", pvd),
            self._observation(artifact, "archive.iso9660.root_directory_entries", root_entries),
            self._observation(artifact, "archive.iso9660.root_directory_entry_count", len(root_entries)),
            self._observation(artifact, "archive.iso9660.root_directory_scan_bytes", root_scan_bytes),
            self._observation(artifact, "archive.iso9660.root_directory_scan_truncated", root_scan_truncated),
            self._observation(artifact, "archive.iso9660.root_directory_entry_limit_reached", root_entry_limit_reached),
            self._observation(artifact, "archive.iso9660.root_directory_error", root_error),
            self._observation(artifact, "archive.iso9660.directory_entries", all_directory_entries),
            self._observation(artifact, "archive.iso9660.regular_files", regular_files),
            self._observation(artifact, "archive.iso9660.regular_file_count", len(regular_files)),
            self._observation(artifact, "archive.iso9660.multi_extent_chains", multi_extent_chains),
            self._observation(artifact, "archive.iso9660.multi_extent_errors", multi_extent_errors),
            self._observation(artifact, "archive.iso9660.subdirectory_inventory", directory_inventory),
            self._observation(artifact, "archive.iso9660.subdirectory_count", len(directory_inventory)),
            self._observation(artifact, "archive.iso9660.directory_scan_bytes", directory_scan_bytes),
            self._observation(artifact, "archive.iso9660.directory_scan_byte_limit", directory_scan_byte_limit),
            self._observation(artifact, "archive.iso9660.directory_limit", directory_limit),
            self._observation(artifact, "archive.iso9660.directory_traversal_truncated", directory_traversal_truncated),
            self._observation(artifact, "archive.iso9660.directory_traversal_errors", directory_traversal_errors),
            self._observation(artifact, "archive.iso9660.susp", susp_config),
            self._observation(artifact, "archive.iso9660.susp_errors", susp_errors),
            self._observation(artifact, "archive.iso9660.susp_continuation_state", {
                key: value for key, value in susp_continuation_state.items()
                if key != "claimed_ranges"
            }),
            self._observation(artifact, "archive.iso9660.rock_ridge_relocations", rock_ridge_relocations),
            self._observation(artifact, "archive.iso9660.rock_ridge_detected", rock_ridge_detected),
            self._observation(artifact, "archive.iso9660.rock_ridge_entries", rock_ridge_entries),
            self._observation(artifact, "archive.iso9660.rock_ridge_entry_count", len(rock_ridge_entries)),
            self._observation(artifact, "archive.iso9660.rock_ridge_symlinks", rock_ridge_symlinks),
            self._observation(artifact, "archive.iso9660.rock_ridge_symlink_count", len(rock_ridge_symlinks)),
            self._observation(artifact, "archive.iso9660.joliet_detected", bool(joliet_descriptors)),
            self._observation(artifact, "archive.iso9660.joliet_descriptors", joliet_descriptors),
            self._observation(artifact, "archive.iso9660.joliet_active_descriptor", active_joliet_descriptor),
            self._observation(artifact, "archive.iso9660.joliet_directory_entries", joliet_entries),
            self._observation(artifact, "archive.iso9660.joliet_regular_files", joliet_regular_files),
            self._observation(artifact, "archive.iso9660.joliet_directory_inventory", joliet_walk.get("inventory", [])),
            self._observation(artifact, "archive.iso9660.joliet_traversal_errors", joliet_walk.get("errors", [])),
            self._observation(artifact, "archive.iso9660.joliet_traversal_truncated", joliet_walk.get("truncated", False)),
            self._observation(artifact, "archive.iso9660.joliet_directory_scan_bytes", joliet_walk.get("bytes_read", 0)),
            self._observation(artifact, "archive.iso9660.joliet_extent_aliases", joliet_aliases),
            self._observation(artifact, "archive.iso9660.joliet_reconciliation_errors", joliet_reconciliation_errors),
            self._observation(artifact, "archive.iso9660.el_torito_detected", bool(el_torito_boot_records)),
            self._observation(artifact, "archive.iso9660.el_torito_boot_records", el_torito_boot_records),
            self._observation(artifact, "archive.iso9660.el_torito_catalogs", el_torito_catalogs),
            self._observation(artifact, "archive.iso9660.el_torito_errors", el_torito_errors),
            self._observation(artifact, "archive.iso9660.el_torito_boot_images", el_torito_boot_images),
            self._observation(artifact, "archive.iso9660.path_tables", path_tables),
            self._observation(artifact, "archive.iso9660.path_table_comparison", path_table_comparison),
            self._observation(artifact, "archive.iso9660.path_table_reconciliation", path_table_reconciliation),
            self._observation(artifact, "archive.container_kind", "iso9660"),
        ]

    @staticmethod
    def _iso9660_directory_records(
        directory_data: bytes,
        *,
        directory_offset: int,
        logical_block_size: int,
        evidence_size: int,
        declared_volume_bytes: int,
        entry_limit: int,
        identifier_encoding: str = "ascii",
    ) -> tuple[list[dict[str, object]], str | None, bool]:
        """Decode block-bounded records from one already bounded directory extent."""
        entries: list[dict[str, object]] = []
        first_error: str | None = None
        entry_limit_reached = False
        cursor = 0
        if logical_block_size <= 0:
            return entries, "invalid ISO logical block size for directory parsing", False
        while cursor < len(directory_data):
            record_length = directory_data[cursor]
            if record_length == 0:
                next_block = ((cursor // logical_block_size) + 1) * logical_block_size
                if next_block <= cursor:
                    return entries, "ISO directory padding did not advance parsing", False
                cursor = next_block
                continue
            if len(entries) >= entry_limit:
                entry_limit_reached = True
                break
            record_offset = directory_offset + cursor
            if record_length < 34:
                first_error = (
                    f"invalid ISO directory record length {record_length} "
                    f"at offset {record_offset}"
                )
                break
            if cursor % logical_block_size + record_length > logical_block_size:
                first_error = (
                    f"ISO directory record at offset {record_offset} crosses a logical-block boundary"
                )
                break
            if cursor + record_length > len(directory_data):
                first_error = (
                    f"truncated ISO directory record at offset {record_offset}: "
                    f"declared length {record_length} exceeds available directory bytes"
                )
                break
            record, record_error = GenericTriageEngine._iso9660_directory_record(
                directory_data[cursor:cursor + record_length],
                record_offset=record_offset,
                logical_block_size=logical_block_size,
                evidence_size=evidence_size,
                declared_volume_bytes=declared_volume_bytes,
                identifier_encoding=identifier_encoding,
            )
            record["directory_relative_offset"] = cursor
            entries.append(record)
            if record_error is not None and first_error is None:
                first_error = record_error
            cursor += record_length
        return entries, first_error, entry_limit_reached

    def _iso9660_assemble_multi_extents(
        self,
        entries: list[dict[str, object]],
        *,
        namespace: str,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        """Validate adjacent ISO multi-extent record chains without reading payloads."""
        chains: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        segment_limit = 128
        byte_limit = self.limits.max_single_artifact_size

        def identifier_key(record: dict[str, object]) -> tuple[object, ...]:
            return (
                record.get("identifier_encoding"),
                record.get("identifier_raw_hex"),
                record.get("file_identifier"),
                record.get("version"),
                record.get("volume_sequence_number"),
            )

        index = 0
        while index < len(entries):
            leader = entries[index]
            if (
                leader.get("file_type") != "regular"
                or leader.get("logical_name") in {".", ".."}
                or leader.get("multi_extent") is not True
                or leader.get("multi_extent_chain_role") is not None
            ):
                index += 1
                continue

            expected_identifier = identifier_key(leader)
            segments = [leader]
            next_index = index + 1
            termination_reason: str | None = None
            termination_record: dict[str, object] | None = None
            final_seen = False
            overflow_segments: list[dict[str, object]] = []
            while len(segments) < segment_limit:
                if next_index >= len(entries):
                    termination_reason = "missing_final_record"
                    break
                candidate = entries[next_index]
                if identifier_key(candidate) != expected_identifier:
                    termination_reason = "next_record_identifier_mismatch"
                    termination_record = candidate
                    break
                if (
                    candidate.get("file_type") != "regular"
                    or candidate.get("logical_name") in {".", ".."}
                ):
                    termination_reason = "next_record_not_regular"
                    termination_record = candidate
                    break
                segments.append(candidate)
                next_index += 1
                if candidate.get("multi_extent") is not True:
                    final_seen = True
                    break
            if not final_seen and termination_reason is None:
                termination_reason = "segment_limit"
                while next_index < len(entries):
                    candidate = entries[next_index]
                    if (
                        identifier_key(candidate) != expected_identifier
                        or candidate.get("file_type") != "regular"
                        or candidate.get("logical_name") in {".", ".."}
                    ):
                        break
                    overflow_segments.append(candidate)
                    next_index += 1
                    if candidate.get("multi_extent") is not True:
                        break

            failed_checks: list[str] = []
            if not final_seen:
                failed_checks.append(str(termination_reason or "missing_final_record"))
            if len(segments) < 2:
                failed_checks.append("segment_count")

            total_data_length = 0
            ranges: list[tuple[int, int]] = []
            record_offsets: set[int] = set()
            first_block_size = leader.get("logical_block_size")
            for segment_index, segment in enumerate(segments):
                if segment.get("valid") is not True:
                    failed_checks.append(f"segment_{segment_index}_record_invalid")
                if segment.get("file_type") != "regular":
                    failed_checks.append(f"segment_{segment_index}_not_regular")
                if segment.get("path_safe") is not True:
                    failed_checks.append(f"segment_{segment_index}_unsafe_identifier")
                if segment.get("file_unit_size") != 0 or segment.get("interleave_gap_size") != 0:
                    failed_checks.append(f"segment_{segment_index}_interleaved")
                if segment.get("logical_block_size") != first_block_size:
                    failed_checks.append(f"segment_{segment_index}_block_size_mismatch")
                if identifier_key(segment) != expected_identifier:
                    failed_checks.append(f"segment_{segment_index}_identifier_mismatch")
                if (
                    segment.get("rock_ridge_symlink") is True
                    or segment.get("rock_ridge_non_regular") is True
                    or segment.get("rock_ridge_type_mismatch") is True
                    or segment.get("rock_ridge_name_usable") is False
                    or segment.get("susp_error")
                    or segment.get("susp_continuation_unparsed") is True
                    or segment.get("rock_ridge_relocation_traversal_suppressed") is True
                ):
                    failed_checks.append(f"segment_{segment_index}_metadata_unsafe")
                data_offset = segment.get("data_offset")
                data_length = segment.get("data_length")
                record_offset = segment.get("record_offset")
                if (
                    not isinstance(data_offset, int)
                    or isinstance(data_offset, bool)
                    or not isinstance(data_length, int)
                    or isinstance(data_length, bool)
                    or data_offset < 0
                    or data_length <= 0
                ):
                    failed_checks.append(f"segment_{segment_index}_range_invalid")
                else:
                    total_data_length += data_length
                    end_offset = data_offset + data_length
                    if any(
                        data_offset < prior_end and prior_start < end_offset
                        for prior_start, prior_end in ranges
                    ):
                        failed_checks.append(f"segment_{segment_index}_range_overlap")
                    ranges.append((data_offset, end_offset))
                    if (
                        segment_index < len(segments) - 1
                        and isinstance(first_block_size, int)
                        and data_length % first_block_size != 0
                    ):
                        failed_checks.append(
                            f"segment_{segment_index}_nonfinal_length_not_block_aligned"
                        )
                if not isinstance(record_offset, int) or isinstance(record_offset, bool):
                    failed_checks.append(f"segment_{segment_index}_record_offset_invalid")
                elif record_offset in record_offsets:
                    failed_checks.append(f"segment_{segment_index}_record_offset_duplicate")
                else:
                    record_offsets.add(record_offset)
                expected_multi_extent = segment_index < len(segments) - 1 or not final_seen
                if segment.get("multi_extent") is not expected_multi_extent:
                    failed_checks.append(f"segment_{segment_index}_multi_extent_flag")

            if total_data_length > byte_limit:
                failed_checks.append("assembled_size_limit")
            failed_checks = list(dict.fromkeys(failed_checks))
            complete = final_seen and not failed_checks
            chain_id = (
                f"{namespace}:{leader.get('record_offset')}:"
                f"{leader.get('identifier_raw_hex')}"
            )
            segment_provenance = [{
                **{
                    key: segment.get(key)
                    for key in (
                        "record_offset", "record_length", "record_raw_hex",
                        "identifier_length", "identifier_raw_hex",
                        "identifier_encoding", "file_identifier", "logical_name",
                        "version", "extended_attribute_blocks",
                        "logical_block_size", "extent_block",
                        "extent_block_big_endian", "extent_both_endian_match",
                        "data_offset", "data_length", "data_length_big_endian",
                        "data_length_both_endian_match", "data_end_offset",
                        "flags_raw", "multi_extent", "file_unit_size",
                        "interleave_gap_size", "volume_sequence_number",
                        "volume_sequence_number_big_endian", "valid",
                        "failed_checks",
                    )
                },
                "susp_continuation_areas": (
                    segment.get("susp_continuation_areas") or []
                ),
            } for segment in segments]
            chain: dict[str, object] = {
                "chain_id": chain_id,
                "namespace": namespace,
                "archive_path": leader.get("archive_path"),
                "file_identifier": leader.get("file_identifier"),
                "identifier_raw_hex": leader.get("identifier_raw_hex"),
                "version": leader.get("version"),
                "containing_directory_identity": leader.get(
                    "containing_directory_identity"
                ),
                "first_record_offset": leader.get("record_offset"),
                "last_record_offset": segments[-1].get("record_offset"),
                "segment_count": len(segments),
                "segment_limit": segment_limit,
                "total_data_length": total_data_length,
                "byte_limit": byte_limit,
                "complete": complete,
                "extraction_eligible": complete,
                "termination_reason": termination_reason,
                "termination_record_offset": (
                    termination_record.get("record_offset")
                    if termination_record is not None else None
                ),
                "termination_file_identifier": (
                    termination_record.get("file_identifier")
                    if termination_record is not None else None
                ),
                "overflow_segment_count": len(overflow_segments),
                "overflow_record_offsets": [
                    segment.get("record_offset") for segment in overflow_segments
                ],
                "failed_checks": failed_checks,
                "segments": segment_provenance,
            }
            chains.append(chain)
            if failed_checks:
                errors.append({
                    "reason": "invalid_multi_extent_chain",
                    "chain_id": chain_id,
                    "namespace": namespace,
                    "archive_path": leader.get("archive_path"),
                    "first_record_offset": leader.get("record_offset"),
                    "failed_checks": failed_checks,
                    "termination_record_offset": chain["termination_record_offset"],
                    "termination_file_identifier": chain["termination_file_identifier"],
                })

            for segment_index, segment in enumerate(segments):
                role = (
                    "head" if segment_index == 0
                    else "tail" if final_seen and segment_index == len(segments) - 1
                    else "continuation"
                )
                segment.update({
                    "multi_extent_chain_id": chain_id,
                    "multi_extent_chain_role": role,
                    "multi_extent_segment_index": segment_index,
                    "multi_extent_chain_complete": complete,
                    "extraction_eligible": False,
                })
            for overflow_index, segment in enumerate(overflow_segments):
                segment.update({
                    "multi_extent_chain_id": chain_id,
                    "multi_extent_chain_role": "overflow",
                    "multi_extent_segment_index": segment_limit + overflow_index,
                    "multi_extent_chain_complete": False,
                    "extraction_eligible": False,
                })
            leader.update({
                "multi_extent_chain": chain,
                "multi_extent_segments": segment_provenance,
                "multi_extent_assembled": complete,
                "assembled_data_length": total_data_length,
                "logical_extent_identity": {
                    "kind": "multi_extent",
                    "segments": [
                        {"data_offset": start, "data_length": end - start}
                        for start, end in ranges
                    ],
                    "total_data_length": total_data_length,
                },
                "extraction_eligible": complete,
            })
            index += len(segments) + len(overflow_segments)
        return chains, errors

    @staticmethod
    def _iso9660_logical_extent_identity(
        record: dict[str, object],
    ) -> tuple[tuple[int, int], ...] | None:
        """Return an exact ordered byte-range identity for one logical ISO file."""
        if record.get("multi_extent_chain_role") in {
            "continuation", "tail", "overflow",
        }:
            return None
        if record.get("multi_extent") is True:
            if record.get("multi_extent_assembled") is not True:
                return None
            raw_segments = record.get("multi_extent_segments")
            if not isinstance(raw_segments, list) or not 2 <= len(raw_segments) <= 128:
                return None
            identity: list[tuple[int, int]] = []
            for segment in raw_segments:
                if not isinstance(segment, dict):
                    return None
                offset = segment.get("data_offset")
                length = segment.get("data_length")
                if (
                    not isinstance(offset, int) or isinstance(offset, bool)
                    or not isinstance(length, int) or isinstance(length, bool)
                    or offset < 0 or length <= 0
                ):
                    return None
                identity.append((offset, length))
            return tuple(identity)
        offset = record.get("data_offset")
        length = record.get("data_length")
        if (
            not isinstance(offset, int) or isinstance(offset, bool)
            or not isinstance(length, int) or isinstance(length, bool)
            or offset < 0 or length < 0
        ):
            return None
        return ((offset, length),)

    @staticmethod
    def _iso9660_el_torito_catalogs(
        path: Path,
        *,
        evidence_size: int,
        pvd: dict[str, object],
        boot_records: list[dict[str, object]],
    ) -> tuple[
        list[dict[str, object]], list[dict[str, object]], list[dict[str, object]],
    ]:
        """Validate El Torito validation/default entries without inferring image size."""
        catalogs: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        boot_images: list[dict[str, object]] = []
        block_size = pvd.get("logical_block_size")
        declared_volume_bytes = pvd.get("declared_volume_bytes")
        if not isinstance(block_size, int) or not isinstance(declared_volume_bytes, int):
            return catalogs, errors, boot_images
        platform_names = {0x00: "x86", 0x01: "powerpc", 0x02: "mac", 0xEF: "efi"}
        media_names = {
            0: "no_emulation", 1: "floppy_1_2m", 2: "floppy_1_44m",
            3: "floppy_2_88m", 4: "hard_disk",
        }
        media_lengths = {1: 1_200 * 1_024, 2: 1_440 * 1_024, 3: 2_880 * 1_024}
        for boot_record in boot_records[:8]:
            catalog_block = boot_record.get("catalog_block")
            if not isinstance(catalog_block, int) or catalog_block <= 0:
                errors.append({"reason": "invalid_catalog_block", "boot_record": boot_record})
                continue
            catalog_offset = catalog_block * block_size
            if (
                catalog_offset < 0
                or catalog_offset + 64 > evidence_size
                or catalog_offset + 64 > declared_volume_bytes
            ):
                errors.append({
                    "reason": "catalog_out_of_bounds", "boot_record": boot_record,
                    "catalog_offset": catalog_offset,
                })
                continue
            try:
                with path.open("rb") as stream:
                    stream.seek(catalog_offset)
                    catalog_read_length = min(
                        8 * 1_024,
                        evidence_size - catalog_offset,
                        declared_volume_bytes - catalog_offset,
                    )
                    raw = stream.read(catalog_read_length)
            except OSError as exc:
                errors.append({
                    "reason": "catalog_read_error", "boot_record": boot_record,
                    "error": str(exc)[:2_000],
                })
                continue
            if len(raw) < 64:
                errors.append({
                    "reason": "catalog_truncated_read", "boot_record": boot_record,
                    "received_bytes": len(raw),
                })
                continue
            validation = raw[:32]
            validation_checksum = sum(
                int.from_bytes(validation[index:index + 2], "little")
                for index in range(0, 32, 2)
            ) & 0xFFFF
            validation_entry = {
                "offset": catalog_offset,
                "raw_hex": validation.hex(),
                "header_id": validation[0],
                "platform_id": validation[1],
                "platform": platform_names.get(validation[1], f"unknown_0x{validation[1]:02x}"),
                "reserved_raw_hex": validation[2:4].hex(),
                "identifier": validation[4:28].decode(
                    "ascii", errors="replace"
                ).rstrip(" \x00"),
                "checksum_field": int.from_bytes(validation[28:30], "little"),
                "checksum_sum_16bit": validation_checksum,
                "checksum_valid": validation_checksum == 0,
                "key_bytes_raw_hex": validation[30:32].hex(),
                "key_bytes_valid": validation[30:32] == b"\x55\xaa",
            }
            validation_entry["valid"] = bool(
                validation_entry["header_id"] == 1
                and validation_entry["reserved_raw_hex"] == "0000"
                and validation_entry["checksum_valid"]
                and validation_entry["key_bytes_valid"]
            )
            initial = raw[32:64]
            boot_indicator = initial[0]
            media_type = initial[1]
            sector_count = int.from_bytes(initial[6:8], "little")
            load_block = int.from_bytes(initial[8:12], "little")
            data_offset = load_block * block_size
            if media_type == 0:
                data_length = sector_count * 512 if sector_count > 0 else None
                length_source = "catalog_sector_count_512_bytes"
            elif media_type in media_lengths:
                data_length = media_lengths[media_type]
                length_source = "el_torito_fixed_floppy_geometry"
            else:
                data_length = None
                length_source = "not_determinable"
            within_bounds = bool(
                isinstance(data_length, int)
                and data_length > 0
                and data_offset >= 0
                and data_offset + data_length <= evidence_size
                and data_offset + data_length <= declared_volume_bytes
            )
            range_invalid = isinstance(data_length, int) and not within_bounds
            missing_no_emulation_size = media_type == 0 and sector_count == 0
            initial_entry = {
                "offset": catalog_offset + 32,
                "raw_hex": initial.hex(),
                "boot_indicator_raw": f"0x{boot_indicator:02x}",
                "bootable": boot_indicator == 0x88,
                "boot_indicator_valid": boot_indicator in {0x00, 0x88},
                "media_type": media_type,
                "media": media_names.get(media_type, f"unknown_{media_type}"),
                "media_type_valid": media_type in media_names,
                "load_segment": int.from_bytes(initial[2:4], "little"),
                "system_type": initial[4],
                "reserved_byte": initial[5],
                "sector_count": sector_count,
                "load_block": load_block,
                "data_offset": data_offset,
                "data_length": data_length,
                "data_length_source": length_source,
                "data_length_determinable": isinstance(data_length, int),
                "data_within_evidence_and_volume": within_bounds,
                "selection_criteria_raw_hex": initial[12:32].hex(),
            }
            initial_entry["valid"] = bool(
                initial_entry["boot_indicator_valid"]
                and initial_entry["media_type_valid"]
                and initial_entry["reserved_byte"] == 0
                and load_block > 0
            )
            initial_entry["extraction_eligible"] = bool(
                validation_entry["valid"]
                and initial_entry["valid"]
                and initial_entry["bootable"]
                and within_bounds
            )
            if initial_entry["extraction_eligible"]:
                platform = str(validation_entry["platform"])
                media = str(initial_entry["media"])
                boot_images.append({
                    **initial_entry,
                    "logical_name": f"eltorito_default_{platform}_{media}.img",
                    "catalog_offset": catalog_offset,
                    "catalog_validation_entry": validation_entry,
                    "boot_record": boot_record,
                })
            catalog = {
                "boot_record": boot_record,
                "catalog_offset": catalog_offset,
                "bytes_read": len(raw),
                "validation_entry": validation_entry,
                "initial_entry": initial_entry,
                "section_headers": [],
                "section_entries": [],
                "extension_entries": [],
                "section_entry_limit": 64,
                "section_entry_limit_reached": False,
                "final_section_header_found": False,
                "valid": validation_entry["valid"] and initial_entry["valid"],
            }
            cursor = 64
            section_index = 0
            section_slots = 0
            section_error: str | None = None
            while cursor + 32 <= len(raw) and any(raw[cursor:cursor + 32]):
                header_raw = raw[cursor:cursor + 32]
                header_indicator = header_raw[0]
                if header_indicator not in {0x90, 0x91}:
                    section_error = (
                        f"invalid El Torito section header indicator 0x{header_indicator:02x} "
                        f"at offset {catalog_offset + cursor}"
                    )
                    break
                section_count = int.from_bytes(header_raw[2:4], "little")
                section_platform = header_raw[1]
                header = {
                    "section_index": section_index,
                    "offset": catalog_offset + cursor,
                    "raw_hex": header_raw.hex(),
                    "indicator_raw": f"0x{header_indicator:02x}",
                    "final": header_indicator == 0x91,
                    "platform_id": section_platform,
                    "platform": platform_names.get(
                        section_platform, f"unknown_0x{section_platform:02x}"
                    ),
                    "entry_count": section_count,
                    "identifier": header_raw[4:32].decode(
                        "ascii", errors="replace"
                    ).rstrip(" \x00"),
                    "valid": section_count > 0,
                }
                catalog["section_headers"].append(header)
                cursor += 32
                if section_count <= 0:
                    section_error = (
                        f"empty El Torito section at offset {header['offset']}"
                    )
                    break
                if section_slots + section_count > 64:
                    catalog["section_entry_limit_reached"] = True
                    section_error = "El Torito section entries exceed the bounded 64-entry limit"
                    break
                if cursor + section_count * 32 > len(raw):
                    section_error = (
                        f"truncated El Torito section at offset {header['offset']}: "
                        f"declares {section_count} entries"
                    )
                    break
                last_boot_entry: dict[str, object] | None = None
                extension_chain_open = False
                for section_entry_index in range(section_count):
                    entry_raw = raw[cursor:cursor + 32]
                    entry_offset = catalog_offset + cursor
                    section_slots += 1
                    if entry_raw[0] == 0x44:
                        extension_entry = {
                            "section_index": section_index,
                            "section_entry_index": section_entry_index,
                            "offset": entry_offset,
                            "raw_hex": entry_raw.hex(),
                            "indicator_raw": "0x44",
                            "flags_raw": f"0x{entry_raw[1]:02x}",
                            "more_extensions": bool(entry_raw[1] & 0x20),
                            "reserved_flags_raw": f"0x{entry_raw[1] & ~0x20:02x}",
                            "criteria_raw_hex": entry_raw[2:32].hex(),
                            "parent_section_entry_offset": (
                                last_boot_entry.get("offset")
                                if last_boot_entry is not None else None
                            ),
                            "valid": (
                                entry_raw[1] & ~0x20 == 0
                                and last_boot_entry is not None
                            ),
                        }
                        catalog["extension_entries"].append(extension_entry)
                        if not extension_entry["valid"]:
                            section_error = section_error or (
                                f"invalid El Torito extension flags at offset {entry_offset}"
                            )
                        extension_chain_open = extension_entry["more_extensions"] is True
                        cursor += 32
                        continue
                    if extension_chain_open:
                        section_error = section_error or (
                            f"incomplete El Torito extension chain before offset {entry_offset}"
                        )
                    section_boot_indicator = entry_raw[0]
                    section_media_type = entry_raw[1]
                    section_sector_count = int.from_bytes(entry_raw[6:8], "little")
                    section_load_block = int.from_bytes(entry_raw[8:12], "little")
                    section_data_offset = section_load_block * block_size
                    if section_media_type == 0:
                        section_data_length = (
                            section_sector_count * 512 if section_sector_count > 0 else None
                        )
                        section_length_source = "catalog_sector_count_512_bytes"
                    elif section_media_type in media_lengths:
                        section_data_length = media_lengths[section_media_type]
                        section_length_source = "el_torito_fixed_floppy_geometry"
                    else:
                        section_data_length = None
                        section_length_source = "not_determinable"
                    section_within_bounds = bool(
                        isinstance(section_data_length, int)
                        and section_data_length > 0
                        and section_data_offset >= 0
                        and section_data_offset + section_data_length <= evidence_size
                        and section_data_offset + section_data_length <= declared_volume_bytes
                    )
                    section_entry = {
                        "section_index": section_index,
                        "section_entry_index": section_entry_index,
                        "section_header_offset": header["offset"],
                        "platform_id": section_platform,
                        "platform": header["platform"],
                        "offset": entry_offset,
                        "raw_hex": entry_raw.hex(),
                        "boot_indicator_raw": f"0x{section_boot_indicator:02x}",
                        "bootable": section_boot_indicator == 0x88,
                        "boot_indicator_valid": section_boot_indicator in {0x00, 0x88},
                        "media_type": section_media_type,
                        "media": media_names.get(
                            section_media_type, f"unknown_{section_media_type}"
                        ),
                        "media_type_valid": section_media_type in media_names,
                        "load_segment": int.from_bytes(entry_raw[2:4], "little"),
                        "system_type": entry_raw[4],
                        "reserved_byte": entry_raw[5],
                        "sector_count": section_sector_count,
                        "load_block": section_load_block,
                        "data_offset": section_data_offset,
                        "data_length": section_data_length,
                        "data_length_source": section_length_source,
                        "data_length_determinable": isinstance(section_data_length, int),
                        "data_within_evidence_and_volume": section_within_bounds,
                        "selection_criteria_raw_hex": entry_raw[12:32].hex(),
                    }
                    section_entry["valid"] = bool(
                        section_entry["boot_indicator_valid"]
                        and section_entry["media_type_valid"]
                        and section_entry["reserved_byte"] == 0
                        and section_load_block > 0
                    )
                    section_entry["extraction_eligible"] = bool(
                        validation_entry["valid"]
                        and header["valid"]
                        and section_entry["valid"]
                        and section_entry["bootable"]
                        and section_within_bounds
                    )
                    catalog["section_entries"].append(section_entry)
                    last_boot_entry = section_entry
                    if (
                        not section_entry["valid"]
                        or (
                            section_entry["bootable"]
                            and isinstance(section_data_length, int)
                            and not section_within_bounds
                        )
                        or (
                            section_entry["bootable"]
                            and section_media_type == 0
                            and section_sector_count == 0
                        )
                    ):
                        section_error = section_error or (
                            f"invalid El Torito section entry at offset {entry_offset}"
                        )
                    if section_entry["extraction_eligible"]:
                        platform = str(section_entry["platform"])
                        media = str(section_entry["media"])
                        boot_images.append({
                            **section_entry,
                            "logical_name": (
                                f"eltorito_section_{section_index:02d}_entry_"
                                f"{section_entry_index:02d}_{platform}_{media}.img"
                            ),
                            "catalog_offset": catalog_offset,
                            "catalog_validation_entry": validation_entry,
                            "section_header": header,
                            "boot_record": boot_record,
                        })
                    cursor += 32
                if extension_chain_open:
                    section_error = section_error or (
                        f"incomplete El Torito extension chain in section {section_index}"
                    )
                if section_error:
                    break
                if header["final"]:
                    catalog["final_section_header_found"] = True
                    break
                section_index += 1
            catalog["section_parse_end_offset"] = catalog_offset + cursor
            catalog["section_parse_error"] = section_error
            if catalog["section_headers"] and not catalog["final_section_header_found"]:
                section_error = section_error or "El Torito section sequence has no final header"
                catalog["section_parse_error"] = section_error
            if section_error:
                catalog["valid"] = False
            catalogs.append(catalog)
            if (
                not catalog["valid"]
                or (initial_entry["bootable"] and range_invalid)
                or (initial_entry["bootable"] and missing_no_emulation_size)
            ):
                errors.append({"reason": "invalid_catalog_or_boot_range", "catalog": catalog})
            if section_error:
                errors.append({"reason": "section_structure", "catalog": catalog})
        return catalogs, errors, boot_images

    def _iso9660_path_tables(
        self,
        path: Path,
        *,
        evidence_size: int,
        pvd: dict[str, object],
        directory_entries: list[dict[str, object]],
    ) -> tuple[list[dict[str, object]], dict[str, object], list[dict[str, object]]]:
        """Parse bounded primary path-table copies without selecting a divergent copy."""
        tables: list[dict[str, object]] = []
        reconciliation: list[dict[str, object]] = []
        path_table_size = pvd.get("path_table_size")
        block_size = pvd.get("logical_block_size")
        declared_volume_bytes = pvd.get("declared_volume_bytes")
        if (
            not isinstance(path_table_size, int)
            or not isinstance(block_size, int)
            or not isinstance(declared_volume_bytes, int)
            or path_table_size <= 0
        ):
            return tables, {
                "available": False,
                "consistent": None,
                "reason": "path_table_size_is_zero_or_invalid",
            }, reconciliation
        byte_limit = min(self.limits.signature_scan_bytes, 8 * _MIB)
        entry_limit = min(self.limits.max_artifact_count + 64, 4_096)
        locations = (
            ("little", "mandatory", pvd.get("little_endian_path_table_block")),
            ("little", "optional", pvd.get("optional_little_endian_path_table_block")),
            ("big", "mandatory", pvd.get("big_endian_path_table_block")),
            ("big", "optional", pvd.get("optional_big_endian_path_table_block")),
        )
        for byte_order, copy_kind, table_block in locations:
            if copy_kind == "optional" and table_block == 0:
                continue
            table: dict[str, object] = {
                "byte_order": byte_order,
                "copy_kind": copy_kind,
                "table_block": table_block,
                "declared_size": path_table_size,
                "byte_limit": byte_limit,
                "entry_limit": entry_limit,
                "entries": [],
                "error": None,
                "truncated": False,
                "valid": False,
            }
            tables.append(table)
            if not isinstance(table_block, int) or table_block <= 0:
                table["error"] = "required path-table block is zero or invalid"
                continue
            table_offset = table_block * block_size
            table["table_offset"] = table_offset
            if path_table_size > byte_limit:
                table["error"] = "path table exceeds configured byte limit"
                table["truncated"] = True
                continue
            if (
                table_offset < 0
                or table_offset + path_table_size > evidence_size
                or table_offset + path_table_size > declared_volume_bytes
            ):
                table["error"] = "path table exceeds evidence or declared volume"
                continue
            try:
                with path.open("rb") as stream:
                    stream.seek(table_offset)
                    raw = stream.read(path_table_size)
            except OSError as exc:
                table["error"] = str(exc)[:2_000]
                continue
            table["bytes_read"] = len(raw)
            table["raw_sha256"] = hashlib.sha256(raw).hexdigest()
            if len(raw) != path_table_size:
                table["error"] = "truncated path-table read"
                table["truncated"] = True
                continue
            entries: list[dict[str, object]] = []
            cursor = 0
            first_error: str | None = None
            while cursor < len(raw):
                if len(entries) >= entry_limit:
                    first_error = "path-table entry limit reached"
                    table["truncated"] = True
                    break
                if cursor + 8 > len(raw):
                    first_error = f"truncated path-table header at offset {table_offset + cursor}"
                    break
                identifier_length = raw[cursor]
                extended_attribute_blocks = raw[cursor + 1]
                entry_length = 8 + identifier_length + (identifier_length % 2)
                if identifier_length == 0 or cursor + entry_length > len(raw):
                    first_error = f"invalid path-table entry at offset {table_offset + cursor}"
                    break
                if byte_order == "little":
                    extent_block = int.from_bytes(raw[cursor + 2:cursor + 6], "little")
                    parent_number = int.from_bytes(raw[cursor + 6:cursor + 8], "little")
                else:
                    extent_block = int.from_bytes(raw[cursor + 2:cursor + 6], "big")
                    parent_number = int.from_bytes(raw[cursor + 6:cursor + 8], "big")
                identifier_raw = raw[cursor + 8:cursor + 8 + identifier_length]
                identifier = (
                    "." if identifier_raw == b"\x00"
                    else identifier_raw.decode("ascii", errors="replace")
                )
                normalized = identifier.replace("\\", "/")
                path_safe = bool(
                    identifier == "."
                    or (
                        identifier
                        and "\x00" not in identifier
                        and not normalized.startswith("/")
                        and re.match(r"^[A-Za-z]:/", normalized) is None
                        and ".." not in normalized.split("/")
                        and "/" not in normalized
                    )
                )
                directory_number = len(entries) + 1
                parent_valid = (
                    parent_number == 1 if directory_number == 1
                    else 1 <= parent_number < directory_number
                )
                data_offset = (extent_block + extended_attribute_blocks) * block_size
                extent_valid = 0 <= data_offset < min(evidence_size, declared_volume_bytes)
                encoding_valid = "\ufffd" not in identifier
                entry = {
                    "directory_number": directory_number,
                    "offset": table_offset + cursor,
                    "relative_offset": cursor,
                    "raw_hex": raw[cursor:cursor + entry_length].hex(),
                    "entry_length": entry_length,
                    "identifier_length": identifier_length,
                    "identifier_raw_hex": identifier_raw.hex(),
                    "identifier": identifier,
                    "identifier_encoding_valid": encoding_valid,
                    "path_safe": path_safe,
                    "extended_attribute_blocks": extended_attribute_blocks,
                    "extent_block": extent_block,
                    "data_offset": data_offset,
                    "extent_start_within_evidence_and_volume": extent_valid,
                    "parent_directory_number": parent_number,
                    "parent_directory_number_valid": parent_valid,
                    "padding_length": identifier_length % 2,
                    "padding_raw_hex": raw[
                        cursor + 8 + identifier_length:cursor + entry_length
                    ].hex(),
                }
                padding_valid = (
                    identifier_length % 2 == 0
                    or entry["padding_raw_hex"] == "00"
                )
                entry["padding_valid"] = padding_valid
                if directory_number == 1:
                    archive_path = "/" if identifier == "." else None
                else:
                    parent = entries[parent_number - 1] if parent_valid else None
                    parent_path = parent.get("archive_path") if isinstance(parent, dict) else None
                    archive_path = (
                        identifier if parent_path == "/"
                        else f"{parent_path}/{identifier}" if isinstance(parent_path, str) else None
                    )
                entry["archive_path"] = archive_path
                entry["valid"] = bool(
                    encoding_valid and path_safe and parent_valid and extent_valid
                    and padding_valid
                    and (directory_number != 1 or identifier == ".")
                    and (directory_number != 1 or extent_block == pvd.get(
                        "root_directory_record", {}
                    ).get("extent_block"))
                )
                if not entry["valid"] and first_error is None:
                    first_error = f"path-table entry {directory_number} failed validation"
                entries.append(entry)
                cursor += entry_length
            table["entries"] = entries
            table["entry_count"] = len(entries)
            table["parse_end_offset"] = table_offset + cursor
            table["error"] = first_error
            table["valid"] = first_error is None and cursor == len(raw)

        mandatory_little = next((
            table for table in tables
            if table.get("byte_order") == "little" and table.get("copy_kind") == "mandatory"
        ), None)
        mandatory_big = next((
            table for table in tables
            if table.get("byte_order") == "big" and table.get("copy_kind") == "mandatory"
        ), None)
        comparison: dict[str, object] = {
            "available": mandatory_little is not None and mandatory_big is not None,
            "consistent": False,
            "little_table_offset": mandatory_little.get("table_offset") if mandatory_little else None,
            "big_table_offset": mandatory_big.get("table_offset") if mandatory_big else None,
            "first_difference_index": None,
            "copy_comparisons": [],
        }
        if mandatory_little and mandatory_big:
            little_entries = mandatory_little.get("entries", [])
            big_entries = mandatory_big.get("entries", [])
            canonical_little = [
                (
                    entry.get("extended_attribute_blocks"), entry.get("extent_block"),
                    entry.get("parent_directory_number"), entry.get("identifier_raw_hex"),
                )
                for entry in little_entries if isinstance(entry, dict)
            ]
            canonical_big = [
                (
                    entry.get("extended_attribute_blocks"), entry.get("extent_block"),
                    entry.get("parent_directory_number"), entry.get("identifier_raw_hex"),
                )
                for entry in big_entries if isinstance(entry, dict)
            ]
            comparison["little_entry_count"] = len(canonical_little)
            comparison["big_entry_count"] = len(canonical_big)
            comparison["consistent"] = bool(
                mandatory_little.get("valid") is True
                and mandatory_big.get("valid") is True
                and canonical_little == canonical_big
            )
            if canonical_little != canonical_big:
                common = min(len(canonical_little), len(canonical_big))
                comparison["first_difference_index"] = next(
                    (
                        index for index in range(common)
                        if canonical_little[index] != canonical_big[index]
                    ),
                    common,
                )

            for table in tables:
                if table is mandatory_little:
                    continue
                entries = table.get("entries", [])
                canonical = [
                    (
                        entry.get("extended_attribute_blocks"),
                        entry.get("extent_block"),
                        entry.get("parent_directory_number"),
                        entry.get("identifier_raw_hex"),
                    )
                    for entry in entries if isinstance(entry, dict)
                ]
                copy_match = bool(
                    table.get("valid") is True and canonical == canonical_little
                )
                comparison["copy_comparisons"].append({
                    "byte_order": table.get("byte_order"),
                    "copy_kind": table.get("copy_kind"),
                    "table_offset": table.get("table_offset"),
                    "entry_count": len(canonical),
                    "matches_mandatory_little": copy_match,
                })
            comparison["consistent"] = bool(
                comparison["consistent"]
                and all(
                    item["matches_mandatory_little"]
                    for item in comparison["copy_comparisons"]
                )
            )

        if comparison.get("consistent") is True and mandatory_little:
            root = pvd.get("root_directory_record", {})
            root_self = next((
                entry for entry in directory_entries
                if entry.get("logical_name") == "."
                and entry.get("extent_block") == root.get("extent_block")
            ), None)
            candidates = [{
                "record_offset": (
                    root_self.get("record_offset") if root_self else root.get("record_offset")
                ),
                "extent_block": root.get("extent_block"),
                "file_identifier": ".",
                "archive_path": "/",
            }]
            candidates.extend(
                entry for entry in directory_entries
                if entry.get("file_type") == "directory"
                and entry.get("logical_name") not in {".", ".."}
            )
            for path_entry in mandatory_little.get("entries", []):
                if not isinstance(path_entry, dict):
                    continue
                matches = [
                    candidate for candidate in candidates
                    if candidate.get("extent_block") == path_entry.get("extent_block")
                    and candidate.get("file_identifier") == path_entry.get("identifier")
                ]
                record = {
                    "directory_number": path_entry.get("directory_number"),
                    "path_table_entry_offset": path_entry.get("offset"),
                    "path_table_archive_path": path_entry.get("archive_path"),
                    "extent_block": path_entry.get("extent_block"),
                    "directory_record_match_count": len(matches),
                    "directory_record_offset": (
                        matches[0].get("record_offset") if len(matches) == 1 else None
                    ),
                    "directory_record_archive_path": (
                        matches[0].get("archive_path") if len(matches) == 1 else None
                    ),
                    "reconciled": len(matches) == 1,
                }
                reconciliation.append(record)
        comparison["all_entries_reconciled"] = bool(
            reconciliation and all(item["reconciled"] for item in reconciliation)
        ) if comparison.get("consistent") is True else False
        return tables, comparison, reconciliation

    def _iso9660_walk_namespace(
        self,
        path: Path,
        *,
        evidence_size: int,
        descriptor: dict[str, object],
        namespace: str,
        identifier_encoding: str,
    ) -> dict[str, object]:
        """Walk one independently validated ISO namespace under fixed shared bounds."""
        entries: list[dict[str, object]] = []
        inventory: list[dict[str, object]] = []
        errors: list[dict[str, object]] = []
        multi_extent_chains: list[dict[str, object]] = []
        multi_extent_errors: list[dict[str, object]] = []
        byte_limit = min(self.limits.signature_scan_bytes, 8 * _MIB)
        entry_limit = min(self.limits.max_artifact_count + 64, 4_096)
        directory_limit = 32
        bytes_read = 0
        truncated = False
        root = descriptor.get("root_directory_record")
        block_size = descriptor.get("logical_block_size")
        declared_volume_bytes = descriptor.get("declared_volume_bytes")
        if (
            descriptor.get("valid") is not True
            or not isinstance(root, dict)
            or not isinstance(block_size, int)
            or not isinstance(declared_volume_bytes, int)
        ):
            return {
                "entries": entries, "inventory": inventory, "errors": errors,
                "bytes_read": bytes_read, "byte_limit": byte_limit,
                "entry_limit": entry_limit, "directory_limit": directory_limit,
                "truncated": truncated,
            }

        root_offset = root.get("data_offset")
        root_length = root.get("data_length")
        if (
            not isinstance(root_offset, int)
            or not isinstance(root_length, int)
            or root_length <= 0
            or root_offset < 0
            or root_offset + root_length > evidence_size
        ):
            errors.append({"reason": "invalid_root_range", "root_record": root})
            return {
                "entries": entries, "inventory": inventory, "errors": errors,
                "bytes_read": bytes_read, "byte_limit": byte_limit,
                "entry_limit": entry_limit, "directory_limit": directory_limit,
                "truncated": truncated,
            }
        if root_length > byte_limit:
            errors.append({
                "reason": "root_byte_limit", "root_record": root,
                "byte_limit": byte_limit,
            })
            truncated = True
            return {
                "entries": entries, "inventory": inventory, "errors": errors,
                "bytes_read": bytes_read, "byte_limit": byte_limit,
                "entry_limit": entry_limit, "directory_limit": directory_limit,
                "truncated": truncated,
            }
        try:
            with path.open("rb") as stream:
                stream.seek(root_offset)
                root_data = stream.read(root_length)
        except OSError as exc:
            errors.append({"reason": "root_read_error", "error": str(exc)[:2_000]})
            return {
                "entries": entries, "inventory": inventory, "errors": errors,
                "bytes_read": bytes_read, "byte_limit": byte_limit,
                "entry_limit": entry_limit, "directory_limit": directory_limit,
                "truncated": truncated,
            }
        bytes_read = len(root_data)
        if len(root_data) != root_length:
            errors.append({
                "reason": "root_truncated_read", "expected_bytes": root_length,
                "received_bytes": len(root_data),
            })
            return {
                "entries": entries, "inventory": inventory, "errors": errors,
                "bytes_read": bytes_read, "byte_limit": byte_limit,
                "entry_limit": entry_limit, "directory_limit": directory_limit,
                "truncated": True,
            }
        root_entries, root_error, root_entry_limit = self._iso9660_directory_records(
            root_data,
            directory_offset=root_offset,
            logical_block_size=block_size,
            evidence_size=evidence_size,
            declared_volume_bytes=declared_volume_bytes,
            entry_limit=entry_limit,
            identifier_encoding=identifier_encoding,
        )
        entries.extend(root_entries)
        root_extent = (root_offset, root_length)
        root_identity = {
            "namespace": namespace,
            "logical_name": "/",
            "file_identifier": ".",
            "directory_record_offset": root.get("record_offset"),
            "extent_block": root.get("extent_block"),
            "data_offset": root_offset,
            "data_length": root_length,
        }
        for entry in root_entries:
            entry["namespace"] = namespace
            entry["containing_directory_identity"] = root_identity
            entry["directory_identity_lineage"] = []
            if entry.get("logical_name") not in {".", ".."}:
                entry["archive_path"] = entry.get("logical_name")
        root_chains, root_chain_errors = self._iso9660_assemble_multi_extents(
            root_entries, namespace=namespace,
        )
        multi_extent_chains.extend(root_chains)
        multi_extent_errors.extend(root_chain_errors)
        if root_error or root_entry_limit:
            errors.append({
                "reason": "root_directory_consistency",
                "parse_error": root_error,
                "entry_limit_reached": root_entry_limit,
            })
            truncated = truncated or root_entry_limit

        queue: list[
            tuple[
                dict[str, object], list[dict[str, object]],
                set[tuple[object, object]], tuple[object, object],
            ]
        ] = []
        claimed_extents: set[tuple[object, object]] = {root_extent}

        def schedule(
            entry: dict[str, object], lineage: list[dict[str, object]],
            ancestors: set[tuple[object, object]], parent_extent: tuple[object, object],
        ) -> None:
            if (
                entry.get("file_type") != "directory"
                or entry.get("logical_name") in {".", ".."}
                or entry.get("valid") is not True
            ):
                return
            if (
                entry.get("multi_extent") is True
                or entry.get("file_unit_size") not in {0, None}
                or entry.get("interleave_gap_size") not in {0, None}
            ):
                entry["directory_traversal"] = "unsupported_layout"
                errors.append({"reason": "unsupported_directory_layout", "entry": entry})
                return
            extent = (entry.get("data_offset"), entry.get("data_length"))
            identity = {
                "namespace": namespace,
                "logical_name": entry.get("logical_name"),
                "file_identifier": entry.get("file_identifier"),
                "directory_record_offset": entry.get("record_offset"),
                "extent_block": entry.get("extent_block"),
                "data_offset": entry.get("data_offset"),
                "data_length": entry.get("data_length"),
            }
            if extent in ancestors:
                entry["directory_traversal"] = "ancestor_cycle"
                errors.append({"reason": "ancestor_cycle", "entry": entry})
                return
            if extent in claimed_extents:
                entry["directory_traversal"] = "shared_extent"
                errors.append({"reason": "shared_extent", "entry": entry})
                return
            claimed_extents.add(extent)
            entry["directory_traversal"] = "scheduled"
            queue.append((entry, [*lineage, identity], {*ancestors, extent}, parent_extent))

        for entry in root_entries:
            schedule(entry, [], {root_extent}, root_extent)

        processed = 0
        while queue and processed < directory_limit:
            source_entry, lineage, ancestors, parent_extent = queue.pop(0)
            data_offset = source_entry.get("data_offset")
            data_length = source_entry.get("data_length")
            if (
                not isinstance(data_offset, int)
                or not isinstance(data_length, int)
                or data_length <= 0
                or data_offset < 0
                or data_offset + data_length > evidence_size
            ):
                source_entry["directory_traversal"] = "invalid_range"
                errors.append({"reason": "invalid_range", "entry": source_entry})
                continue
            if bytes_read + data_length > byte_limit:
                source_entry["directory_traversal"] = "byte_limit"
                errors.append({"reason": "byte_limit", "entry": source_entry})
                truncated = True
                continue
            remaining_entries = entry_limit - len(entries)
            if remaining_entries <= 0:
                source_entry["directory_traversal"] = "entry_limit"
                errors.append({"reason": "entry_limit", "entry": source_entry})
                truncated = True
                break
            try:
                with path.open("rb") as stream:
                    stream.seek(data_offset)
                    directory_data = stream.read(data_length)
            except OSError as exc:
                source_entry["directory_traversal"] = "read_error"
                errors.append({
                    "reason": "read_error", "entry": source_entry,
                    "error": str(exc)[:2_000],
                })
                continue
            bytes_read += len(directory_data)
            if len(directory_data) != data_length:
                source_entry["directory_traversal"] = "truncated_read"
                errors.append({"reason": "truncated_read", "entry": source_entry})
                truncated = True
                continue
            child_entries, parse_error, child_limit = self._iso9660_directory_records(
                directory_data,
                directory_offset=data_offset,
                logical_block_size=block_size,
                evidence_size=evidence_size,
                declared_volume_bytes=declared_volume_bytes,
                entry_limit=remaining_entries,
                identifier_encoding=identifier_encoding,
            )
            processed += 1
            source_entry["directory_traversal"] = (
                "parsed" if parse_error is None and not child_limit else "parsed_with_anomaly"
            )
            current_identity = lineage[-1]
            for entry in child_entries:
                entry["namespace"] = namespace
                entry["containing_directory_identity"] = current_identity
                entry["directory_identity_lineage"] = lineage
                if entry.get("logical_name") not in {".", ".."}:
                    entry["archive_path"] = "/".join([
                        *[str(identity.get("logical_name")) for identity in lineage],
                        str(entry.get("logical_name")),
                    ])
            child_chains, child_chain_errors = self._iso9660_assemble_multi_extents(
                child_entries, namespace=namespace,
            )
            multi_extent_chains.extend(child_chains)
            multi_extent_errors.extend(child_chain_errors)
            entries.extend(child_entries)
            dot = next((entry for entry in child_entries if entry.get("logical_name") == "."), None)
            dotdot = next((entry for entry in child_entries if entry.get("logical_name") == ".."), None)
            current_extent = (data_offset, data_length)
            dot_matches = bool(
                dot and dot.get("valid") is True
                and dot.get("file_type") == "directory"
                and (dot.get("data_offset"), dot.get("data_length")) == current_extent
            )
            dotdot_matches = bool(
                dotdot and dotdot.get("valid") is True
                and dotdot.get("file_type") == "directory"
                and (dotdot.get("data_offset"), dotdot.get("data_length")) == parent_extent
            )
            inventory_record = {
                "directory_identity": current_identity,
                "directory_identity_lineage": lineage,
                "data_offset": data_offset,
                "data_length": data_length,
                "entry_count": len(child_entries),
                "dot_entry_matches_self": dot_matches,
                "dotdot_entry_matches_parent": dotdot_matches,
                "parse_error": parse_error,
                "entry_limit_reached": child_limit,
            }
            inventory.append(inventory_record)
            if parse_error or child_limit or not dot_matches or not dotdot_matches:
                errors.append({"reason": "directory_consistency", "inventory": inventory_record})
                truncated = truncated or child_limit
            for entry in child_entries:
                schedule(entry, lineage, ancestors, current_extent)
        if queue:
            errors.append({
                "reason": "directory_limit",
                "remaining_directory_count": len(queue),
                "directory_limit": directory_limit,
            })
            truncated = True
        return {
            "entries": entries,
            "regular_files": [
                entry for entry in entries
                if entry.get("file_type") == "regular"
                and entry.get("logical_name") not in {".", ".."}
                and entry.get("multi_extent_chain_role") not in {
                    "continuation", "tail", "overflow",
                }
            ],
            "multi_extent_chains": multi_extent_chains,
            "multi_extent_errors": multi_extent_errors,
            "inventory": inventory,
            "errors": errors,
            "bytes_read": bytes_read,
            "byte_limit": byte_limit,
            "entry_limit": entry_limit,
            "directory_limit": directory_limit,
            "truncated": truncated,
        }

    @staticmethod
    def _iso9660_susp_configuration(record: dict[str, object]) -> dict[str, object]:
        """Recognize SUSP only from its mandatory marker in the root self entry."""
        config: dict[str, object] = {
            "detected": False,
            "skip_bytes": None,
            "source_record_offset": record.get("record_offset"),
            "extension_identifiers": [],
            "rock_ridge_detected": False,
        }
        raw_hex = record.get("system_use_raw_hex")
        if not isinstance(raw_hex, str):
            return config
        try:
            system_use = bytes.fromhex(raw_hex)
        except ValueError:
            return config
        for skip_bytes in range(max(0, len(system_use) - 6)):
            if (
                system_use[skip_bytes:skip_bytes + 2] != b"SP"
                or system_use[skip_bytes + 2] != 7
                or system_use[skip_bytes + 3] != 1
                or system_use[skip_bytes + 4:skip_bytes + 6] != b"\xbe\xef"
                or system_use[skip_bytes + 6] != skip_bytes
            ):
                continue
            entries, parse_error = GenericTriageEngine._iso9660_susp_records(
                system_use, skip_bytes=skip_bytes,
            )
            extension_identifiers = [
                str(entry["extension_identifier"])
                for entry in entries
                if entry.get("signature") == "ER"
                and entry.get("valid") is True
                and isinstance(entry.get("extension_identifier"), str)
            ]
            rrip_signatures = {
                str(entry.get("signature")) for entry in entries
                if entry.get("signature") in {
                    "RR", "PX", "NM", "SL", "TF", "CL", "PL", "RE", "PN",
                }
            }
            rock_ridge_detected = bool(rrip_signatures) or any(
                identifier == "RRIP_1991A" or identifier.startswith("IEEE_P1282")
                for identifier in extension_identifiers
            )
            config.update({
                "detected": True,
                "skip_bytes": skip_bytes,
                "source_record_offset": record.get("record_offset"),
                "sp_system_use_offset": skip_bytes,
                "skipped_prefix_raw_hex": system_use[:skip_bytes].hex(),
                "extension_identifiers": extension_identifiers,
                "root_entry_signatures": [
                    entry.get("signature") for entry in entries
                ],
                "root_entry_parse_error": parse_error,
                "rock_ridge_signatures": sorted(rrip_signatures),
                "rock_ridge_detected": rock_ridge_detected,
            })
            return config
        return config

    @staticmethod
    def _iso9660_susp_records(
        system_use: bytes, *, skip_bytes: int,
    ) -> tuple[list[dict[str, object]], str | None]:
        """Frame inline SUSP entries while retaining every bounded raw field."""
        entries: list[dict[str, object]] = []
        first_error: str | None = None
        cursor = skip_bytes

        def fail(entry: dict[str, object], message: str) -> None:
            nonlocal first_error
            entry["valid"] = False
            entry.setdefault("errors", []).append(message)
            if first_error is None:
                first_error = message

        while cursor < len(system_use):
            if not any(system_use[cursor:]):
                break
            if cursor + 4 > len(system_use):
                first_error = first_error or (
                    f"truncated SUSP entry header at system-use offset {cursor}"
                )
                break
            signature_raw = system_use[cursor:cursor + 2]
            entry_length = system_use[cursor + 2]
            version = system_use[cursor + 3]
            if entry_length < 4:
                first_error = first_error or (
                    f"invalid SUSP entry length {entry_length} at system-use offset {cursor}"
                )
                break
            if cursor + entry_length > len(system_use):
                first_error = first_error or (
                    f"truncated SUSP entry at system-use offset {cursor}: "
                    f"declared length {entry_length}"
                )
                break
            raw = system_use[cursor:cursor + entry_length]
            signature = signature_raw.decode("ascii", errors="replace")
            entry: dict[str, object] = {
                "signature": signature,
                "signature_raw_hex": signature_raw.hex(),
                "length": entry_length,
                "version": version,
                "system_use_offset": cursor,
                "raw_hex": raw.hex(),
                "data_raw_hex": raw[4:].hex(),
                "valid": version == 1,
                "errors": [],
            }
            if version != 1:
                fail(entry, f"unsupported SUSP {signature} version {version}")

            if signature == "SP":
                if entry_length != 7 or raw[4:6] != b"\xbe\xef":
                    fail(entry, "invalid SUSP SP marker")
                else:
                    entry["check_bytes_raw_hex"] = raw[4:6].hex()
                    entry["skip_bytes"] = raw[6]
            elif signature == "ER":
                if entry_length < 8:
                    fail(entry, "truncated SUSP ER entry")
                else:
                    identifier_length = raw[4]
                    descriptor_length = raw[5]
                    source_length = raw[6]
                    expected_length = 8 + identifier_length + descriptor_length + source_length
                    entry.update({
                        "identifier_length": identifier_length,
                        "descriptor_length": descriptor_length,
                        "source_length": source_length,
                        "extension_version": raw[7],
                    })
                    if expected_length != entry_length:
                        fail(entry, "invalid SUSP ER string lengths")
                    else:
                        identifier_end = 8 + identifier_length
                        descriptor_end = identifier_end + descriptor_length
                        try:
                            extension_identifier = raw[8:identifier_end].decode("ascii")
                            extension_descriptor = raw[
                                identifier_end:descriptor_end
                            ].decode("utf-8")
                            extension_source = raw[descriptor_end:].decode("utf-8")
                        except UnicodeDecodeError:
                            fail(entry, "invalid SUSP ER text encoding")
                        else:
                            entry.update({
                                "extension_identifier": extension_identifier,
                                "extension_descriptor": extension_descriptor,
                                "extension_source": extension_source,
                            })
            elif signature == "RR":
                if entry_length != 5:
                    fail(entry, "invalid RRIP RR entry length")
                else:
                    flags = raw[4]
                    flag_names = (
                        "PX", "PN", "SL", "NM", "CL", "PL", "RE", "TF",
                    )
                    entry["flags_raw"] = f"0x{flags:02x}"
                    entry["fields_present"] = [
                        name for bit, name in enumerate(flag_names) if flags & (1 << bit)
                    ]
            elif signature == "NM":
                if entry_length < 5:
                    fail(entry, "truncated RRIP NM entry")
                else:
                    flags = raw[4]
                    name_raw = raw[5:]
                    entry.update({
                        "flags_raw": f"0x{flags:02x}",
                        "continuation": bool(flags & 0x01),
                        "current": bool(flags & 0x02),
                        "parent": bool(flags & 0x04),
                        "root": bool(flags & 0x08),
                        "name_raw_hex": name_raw.hex(),
                    })
                    try:
                        entry["name"] = name_raw.decode("utf-8")
                        entry["name_encoding_valid"] = True
                    except UnicodeDecodeError:
                        entry["name"] = name_raw.decode("utf-8", errors="replace")
                        entry["name_encoding_valid"] = False
            elif signature == "PX":
                if entry_length not in {36, 44}:
                    fail(entry, "invalid RRIP PX entry length")
                else:
                    field_names = ("mode", "link_count", "user_id", "group_id")
                    if entry_length == 44:
                        field_names += ("serial_number",)
                    for field_index, field_name in enumerate(field_names):
                        field_offset = 4 + field_index * 8
                        little = int.from_bytes(raw[field_offset:field_offset + 4], "little")
                        big = int.from_bytes(raw[field_offset + 4:field_offset + 8], "big")
                        entry[field_name] = little
                        entry[f"{field_name}_big_endian"] = big
                        entry[f"{field_name}_both_endian_match"] = little == big
                        if little != big:
                            fail(entry, f"RRIP PX {field_name} both-endian mismatch")
            elif signature == "PN":
                if entry_length != 20:
                    fail(entry, "invalid RRIP PN entry length")
                else:
                    for field_index, field_name in enumerate(("device_high", "device_low")):
                        field_offset = 4 + field_index * 8
                        little = int.from_bytes(raw[field_offset:field_offset + 4], "little")
                        big = int.from_bytes(raw[field_offset + 4:field_offset + 8], "big")
                        entry[field_name] = little
                        entry[f"{field_name}_big_endian"] = big
                        entry[f"{field_name}_both_endian_match"] = little == big
                        if little != big:
                            fail(entry, f"RRIP PN {field_name} both-endian mismatch")
            elif signature == "TF":
                if entry_length < 5:
                    fail(entry, "truncated RRIP TF entry")
                else:
                    flags = raw[4]
                    long_form = bool(flags & 0x80)
                    timestamp_length = 17 if long_form else 7
                    timestamp_names = (
                        "creation", "modify", "access", "attributes",
                        "backup", "expiration", "effective",
                    )
                    present_names = [
                        name for bit, name in enumerate(timestamp_names)
                        if flags & (1 << bit)
                    ]
                    expected_length = 5 + len(present_names) * timestamp_length
                    entry.update({
                        "flags_raw": f"0x{flags:02x}",
                        "long_form": long_form,
                        "timestamp_length": timestamp_length,
                        "fields_present": present_names,
                        "timestamps": {},
                    })
                    if expected_length != entry_length:
                        fail(entry, "RRIP TF flags and entry length disagree")
                    else:
                        time_cursor = 5
                        for timestamp_name in present_names:
                            timestamp_raw = raw[time_cursor:time_cursor + timestamp_length]
                            if long_form:
                                timestamp, timestamp_valid, offset_units = (
                                    GenericTriageEngine._iso9660_long_recording_time(
                                        timestamp_raw
                                    )
                                )
                            else:
                                timestamp, timestamp_valid = (
                                    GenericTriageEngine._iso9660_recording_time(timestamp_raw)
                                )
                                offset_units = (
                                    timestamp_raw[6] - 256
                                    if timestamp_raw[6] >= 128 else timestamp_raw[6]
                                )
                            entry["timestamps"][timestamp_name] = {
                                "raw_hex": timestamp_raw.hex(),
                                "utc": timestamp,
                                "valid": timestamp_valid,
                                "gmt_offset_15_minutes": offset_units,
                            }
                            if not timestamp_valid:
                                fail(entry, f"invalid RRIP TF {timestamp_name} timestamp")
                            time_cursor += timestamp_length
            elif signature == "SL":
                if entry_length < 5:
                    fail(entry, "truncated RRIP SL entry")
                else:
                    entry_flags = raw[4]
                    component_cursor = 5
                    components: list[dict[str, object]] = []
                    while component_cursor < entry_length:
                        if component_cursor + 2 > entry_length:
                            fail(entry, "truncated RRIP SL component header")
                            break
                        component_flags = raw[component_cursor]
                        component_length = raw[component_cursor + 1]
                        component_end = component_cursor + 2 + component_length
                        if component_end > entry_length:
                            fail(entry, "truncated RRIP SL component")
                            break
                        component_raw = raw[component_cursor + 2:component_end]
                        component: dict[str, object] = {
                            "flags_raw": f"0x{component_flags:02x}",
                            "continuation": bool(component_flags & 0x01),
                            "current": bool(component_flags & 0x02),
                            "parent": bool(component_flags & 0x04),
                            "root": bool(component_flags & 0x08),
                            "volume_root": bool(component_flags & 0x10),
                            "host": bool(component_flags & 0x20),
                            "length": component_length,
                            "raw_hex": component_raw.hex(),
                        }
                        try:
                            component["text"] = component_raw.decode("utf-8")
                            component["text_encoding_valid"] = True
                        except UnicodeDecodeError:
                            component["text"] = component_raw.decode(
                                "utf-8", errors="replace"
                            )
                            component["text_encoding_valid"] = False
                        components.append(component)
                        component_cursor = component_end
                    entry.update({
                        "flags_raw": f"0x{entry_flags:02x}",
                        "continuation": bool(entry_flags & 0x01),
                        "components": components,
                    })
            elif signature in {"CE", "CL", "PL"}:
                expected_length = 28 if signature == "CE" else 12
                if entry_length != expected_length:
                    fail(entry, f"invalid SUSP {signature} entry length")
                else:
                    field_names = (
                        ("continuation_block", "continuation_offset", "continuation_length")
                        if signature == "CE"
                        else ("child_link_block",) if signature == "CL"
                        else ("parent_link_block",)
                    )
                    for field_index, field_name in enumerate(field_names):
                        field_offset = 4 + field_index * 8
                        little = int.from_bytes(raw[field_offset:field_offset + 4], "little")
                        big = int.from_bytes(raw[field_offset + 4:field_offset + 8], "big")
                        entry[field_name] = little
                        entry[f"{field_name}_big_endian"] = big
                        entry[f"{field_name}_both_endian_match"] = little == big
                        if little != big:
                            fail(entry, f"SUSP {signature} {field_name} both-endian mismatch")
            elif signature == "RE":
                if entry_length != 4:
                    fail(entry, "invalid RRIP RE entry length")
            elif signature == "ST" and entry_length != 4:
                fail(entry, "invalid SUSP ST entry length")

            entries.append(entry)
            cursor += entry_length
            if signature == "ST":
                break
        return entries, first_error

    @staticmethod
    def _iso9660_resolve_susp_continuations(
        path: Path,
        record: dict[str, object],
        *,
        skip_bytes: int,
        logical_block_size: int,
        evidence_size: int,
        declared_volume_bytes: int,
        state: dict[str, object],
    ) -> tuple[list[dict[str, object]], list[str]]:
        """Read explicitly referenced SUSP continuation areas under one global budget."""
        raw_hex = record.get("system_use_raw_hex")
        if not isinstance(raw_hex, str):
            return [], []
        try:
            inline = bytes.fromhex(raw_hex)
        except ValueError:
            return [], ["invalid inline system-use hex"]
        inline_entries, _ = GenericTriageEngine._iso9660_susp_records(
            inline, skip_bytes=skip_bytes,
        )
        record_offset = record.get("record_offset")
        system_use_offset = record.get("system_use_offset_in_record")
        for entry in inline_entries:
            relative = entry.get("system_use_offset")
            if (
                isinstance(record_offset, int)
                and isinstance(system_use_offset, int)
                and isinstance(relative, int)
            ):
                entry["absolute_offset"] = record_offset + system_use_offset + relative
        queue: list[tuple[dict[str, object], int]] = [
            (entry, 0) for entry in inline_entries
            if entry.get("signature") == "CE"
        ]
        resolved: list[dict[str, object]] = []
        areas: list[dict[str, object]] = []
        errors: list[str] = []
        while queue:
            ce, depth = queue.pop(0)
            if depth >= 8:
                errors.append("SUSP continuation nesting exceeds 8 levels")
                break
            if ce.get("valid") is not True:
                errors.append("invalid SUSP CE entry cannot be followed")
                continue
            block = ce.get("continuation_block")
            area_offset = ce.get("continuation_offset")
            area_length = ce.get("continuation_length")
            if not all(isinstance(value, int) for value in (block, area_offset, area_length)):
                errors.append("SUSP CE entry lacks numeric continuation fields")
                continue
            assert isinstance(block, int)
            assert isinstance(area_offset, int)
            assert isinstance(area_length, int)
            absolute_offset = block * logical_block_size + area_offset
            absolute_end = absolute_offset + area_length
            if (
                area_length <= 0
                or area_offset < 0
                or area_offset >= logical_block_size
                or absolute_offset < 0
                or absolute_end > evidence_size
                or absolute_end > declared_volume_bytes
            ):
                errors.append(
                    f"SUSP CE range {absolute_offset}:{absolute_end} is invalid or out of bounds"
                )
                continue
            claimed_ranges = state.get("claimed_ranges")
            if not isinstance(claimed_ranges, list):
                claimed_ranges = []
                state["claimed_ranges"] = claimed_ranges
            if any(
                absolute_offset < int(existing_end)
                and int(existing_start) < absolute_end
                for existing_start, existing_end in claimed_ranges
            ):
                errors.append(
                    f"SUSP CE range {absolute_offset}:{absolute_end} overlaps a claimed area"
                )
                continue
            byte_limit = int(state.get("byte_limit", _MIB))
            bytes_read = int(state.get("bytes_read", 0))
            area_limit = int(state.get("area_limit", 128))
            area_count = int(state.get("area_count", 0))
            if bytes_read + area_length > byte_limit:
                errors.append("SUSP continuation byte limit reached")
                continue
            if area_count >= area_limit:
                errors.append("SUSP continuation area-count limit reached")
                continue
            try:
                with path.open("rb") as stream:
                    stream.seek(absolute_offset)
                    area_raw = stream.read(area_length)
            except OSError as exc:
                errors.append(f"SUSP continuation read failed: {str(exc)[:2_000]}")
                continue
            if len(area_raw) != area_length:
                errors.append(
                    f"truncated SUSP continuation read at offset {absolute_offset}"
                )
                continue
            claimed_ranges.append((absolute_offset, absolute_end))
            state["bytes_read"] = bytes_read + area_length
            state["area_count"] = area_count + 1
            continuation_entries, parse_error = GenericTriageEngine._iso9660_susp_records(
                area_raw, skip_bytes=0,
            )
            area = {
                "source_ce_absolute_offset": ce.get("absolute_offset"),
                "nesting_depth": depth,
                "block": block,
                "block_relative_offset": area_offset,
                "absolute_offset": absolute_offset,
                "length": area_length,
                "raw_sha256": hashlib.sha256(area_raw).hexdigest(),
                "raw_preview_hex": area_raw[:256].hex(),
                "raw_preview_truncated": len(area_raw) > 256,
                "entry_count": len(continuation_entries),
                "parse_error": parse_error,
            }
            areas.append(area)
            if parse_error:
                errors.append(parse_error)
            for continued in continuation_entries:
                relative = continued.get("system_use_offset")
                if isinstance(relative, int):
                    continued["absolute_offset"] = absolute_offset + relative
                continued["continuation_area_offset"] = absolute_offset
                continued["source_ce_absolute_offset"] = ce.get("absolute_offset")
                continued["continuation_nesting_depth"] = depth
                resolved.append(continued)
                if continued.get("signature") == "CE":
                    queue.append((continued, depth + 1))
        record["susp_continuation_areas"] = areas
        record["susp_continuation_errors"] = errors
        return resolved, errors

    @staticmethod
    def _iso9660_enrich_susp_record(
        record: dict[str, object], *, skip_bytes: int, rock_ridge_detected: bool,
        continued_entries: list[dict[str, object]] | None = None,
        continuation_errors: list[str] | None = None,
    ) -> tuple[str | None, list[str]]:
        """Attach inline SUSP/RRIP semantics without dereferencing continuation areas."""
        raw_hex = record.get("system_use_raw_hex")
        if not isinstance(raw_hex, str):
            return "missing ISO system-use bytes", []
        try:
            system_use = bytes.fromhex(raw_hex)
        except ValueError:
            return "invalid ISO system-use hex", []
        if not system_use:
            record.update({
                "susp_skip_bytes": skip_bytes,
                "susp_skipped_prefix_raw_hex": "",
                "susp_entries": [],
                "susp_error": None,
                "susp_continuation_entries": [],
                "susp_continuation_unparsed": False,
                "rock_ridge_present": False,
                "rock_ridge_symlink": False,
                "rock_ridge_anomalies": [],
            })
            return None, []
        if len(system_use) < skip_bytes:
            record.update({
                "susp_entries": [],
                "susp_error": "system-use area is shorter than the declared SUSP skip",
                "rock_ridge_present": False,
            })
            return str(record["susp_error"]), []
        entries, susp_error = GenericTriageEngine._iso9660_susp_records(
            system_use, skip_bytes=skip_bytes,
        )
        continued_entries = continued_entries or []
        continuation_errors = continuation_errors or []
        semantic_entries = [*entries, *continued_entries]
        if continuation_errors and susp_error is None:
            susp_error = continuation_errors[0]
        record_offset = record.get("record_offset")
        system_use_offset_in_record = record.get("system_use_offset_in_record")
        for entry in entries:
            system_use_offset = entry.get("system_use_offset")
            if (
                isinstance(record_offset, int)
                and isinstance(system_use_offset_in_record, int)
                and isinstance(system_use_offset, int)
            ):
                entry["record_relative_offset"] = (
                    system_use_offset_in_record + system_use_offset
                )
                entry["absolute_offset"] = (
                    record_offset + system_use_offset_in_record + system_use_offset
                )
        rrip_signatures = {"RR", "PX", "NM", "SL", "TF", "CL", "PL", "RE", "PN"}
        rrip_entries = [
            entry for entry in semantic_entries if entry.get("signature") in rrip_signatures
        ]
        continuation_entries = [
            entry for entry in entries if entry.get("signature") == "CE"
        ]
        anomalies: list[str] = []
        continuation_unparsed = bool(
            continuation_entries and (not continued_entries or continuation_errors)
        )
        if continuation_unparsed:
            anomalies.append("unresolved_susp_continuation")
        record.update({
            "susp_skip_bytes": skip_bytes,
            "susp_skipped_prefix_raw_hex": system_use[:skip_bytes].hex(),
            "susp_entries": entries,
            "susp_error": susp_error,
            "susp_resolved_continuation_entries": continued_entries,
            "susp_continuation_entries": continuation_entries,
            "susp_continuation_unparsed": continuation_unparsed,
            "rock_ridge_present": rock_ridge_detected and bool(rrip_entries),
        })

        px_entry = next(
            (
                entry for entry in rrip_entries
                if entry.get("signature") == "PX" and entry.get("valid") is True
            ),
            None,
        )
        if px_entry is not None and isinstance(px_entry.get("mode"), int):
            mode = int(px_entry["mode"])
            mode_type = mode & 0o170000
            file_type = {
                0o010000: "fifo",
                0o020000: "character_device",
                0o040000: "directory",
                0o060000: "block_device",
                0o100000: "regular",
                0o120000: "symlink",
                0o140000: "socket",
            }.get(mode_type, "unknown")
            record["rock_ridge_posix"] = {
                "mode": mode,
                "permissions": f"0o{mode & 0o7777:04o}",
                "file_type": file_type,
                "link_count": px_entry.get("link_count"),
                "user_id": px_entry.get("user_id"),
                "group_id": px_entry.get("group_id"),
                "serial_number": px_entry.get("serial_number"),
                "source_system_use_offset": px_entry.get("system_use_offset"),
            }
            iso_file_type = record.get("file_type")
            type_mismatch = (
                (file_type == "directory" and iso_file_type != "directory")
                or (file_type != "directory" and iso_file_type == "directory")
            )
            record["rock_ridge_type_mismatch"] = type_mismatch
            if type_mismatch:
                anomalies.append("rock_ridge_iso_file_type_mismatch")
            if file_type not in {"regular", "directory"}:
                record["rock_ridge_non_regular"] = True

        tf_entries = [
            entry for entry in rrip_entries if entry.get("signature") == "TF"
        ]
        if tf_entries:
            timestamps: list[dict[str, object]] = []
            seen_timestamp_names: set[str] = set()
            for tf_entry in tf_entries:
                entry_timestamps = tf_entry.get("timestamps", {})
                if not isinstance(entry_timestamps, dict):
                    continue
                for timestamp_name, timestamp_value in entry_timestamps.items():
                    timestamps.append({
                        "type": timestamp_name,
                        "value": timestamp_value,
                        "source_absolute_offset": tf_entry.get("absolute_offset"),
                        "long_form": tf_entry.get("long_form"),
                    })
                    if timestamp_name in seen_timestamp_names:
                        anomalies.append(f"duplicate_rock_ridge_timestamp:{timestamp_name}")
                    seen_timestamp_names.add(timestamp_name)
            record["rock_ridge_timestamps"] = timestamps

        pn_entries = [
            entry for entry in rrip_entries if entry.get("signature") == "PN"
        ]
        if pn_entries:
            record["rock_ridge_devices"] = [{
                "device_high": entry.get("device_high"),
                "device_low": entry.get("device_low"),
                "source_absolute_offset": entry.get("absolute_offset"),
                "valid": entry.get("valid"),
            } for entry in pn_entries]
            if len(pn_entries) > 1:
                anomalies.append("duplicate_rock_ridge_device_number")

        cl_entries = [
            entry for entry in rrip_entries if entry.get("signature") == "CL"
        ]
        pl_entries = [
            entry for entry in rrip_entries if entry.get("signature") == "PL"
        ]
        re_entries = [
            entry for entry in rrip_entries if entry.get("signature") == "RE"
        ]
        if cl_entries or pl_entries or re_entries:
            relocation = {
                "child_links": [{
                    "target_block": entry.get("child_link_block"),
                    "valid": entry.get("valid"),
                    "source_absolute_offset": entry.get("absolute_offset"),
                } for entry in cl_entries],
                "parent_links": [{
                    "target_block": entry.get("parent_link_block"),
                    "valid": entry.get("valid"),
                    "source_absolute_offset": entry.get("absolute_offset"),
                } for entry in pl_entries],
                "relocated_markers": [{
                    "valid": entry.get("valid"),
                    "source_absolute_offset": entry.get("absolute_offset"),
                } for entry in re_entries],
            }
            record["rock_ridge_relocation"] = relocation
            if len(cl_entries) > 1:
                anomalies.append("duplicate_rock_ridge_child_link")
            if len(pl_entries) > 1:
                anomalies.append("duplicate_rock_ridge_parent_link")
            if len(re_entries) > 1:
                anomalies.append("duplicate_rock_ridge_relocated_marker")
            if cl_entries and record.get("file_type") != "directory":
                anomalies.append("rock_ridge_child_link_on_non_directory")
            if pl_entries and record.get("logical_name") != "..":
                anomalies.append("rock_ridge_parent_link_outside_parent_entry")
            if re_entries and record.get("file_type") != "directory":
                anomalies.append("rock_ridge_relocated_marker_on_non_directory")
            if cl_entries or re_entries:
                record["rock_ridge_relocation_traversal_suppressed"] = True

        nm_entries = [
            entry for entry in rrip_entries if entry.get("signature") == "NM"
        ]
        if nm_entries:
            special_name = None
            if len(nm_entries) == 1 and nm_entries[0].get("valid") is True:
                nm_flags = int(str(nm_entries[0].get("flags_raw", "0x00")), 16)
                if nm_flags == 0x02 and record.get("logical_name") == ".":
                    special_name = "."
                elif nm_flags == 0x04 and record.get("logical_name") == "..":
                    special_name = ".."
            normal_flags = all(
                int(str(entry.get("flags_raw", "0x00")), 16) & ~0x01 == 0
                for entry in nm_entries
            )
            chain_complete = (
                special_name is not None
                or (
                    all(entry.get("valid") is True for entry in nm_entries)
                    and normal_flags
                    and all(entry.get("continuation") is True for entry in nm_entries[:-1])
                    and nm_entries[-1].get("continuation") is False
                )
            )
            name_raw = b"".join(
                bytes.fromhex(str(entry.get("name_raw_hex", "")))
                for entry in nm_entries
            )
            if special_name is not None:
                alternate_name = special_name
                encoding_valid = True
            else:
                try:
                    alternate_name = name_raw.decode("utf-8")
                    encoding_valid = True
                except UnicodeDecodeError:
                    alternate_name = name_raw.decode("utf-8", errors="replace")
                    encoding_valid = False
            normalized_name = alternate_name.replace("\\", "/")
            path_safe = bool(
                alternate_name in {".", ".."}
                or (
                    alternate_name
                    and "\x00" not in alternate_name
                    and not normalized_name.startswith("/")
                    and re.match(r"^[A-Za-z]:/", normalized_name) is None
                    and ".." not in normalized_name.split("/")
                    and "/" not in normalized_name
                )
            )
            name_usable = chain_complete and encoding_valid and path_safe
            record.update({
                "rock_ridge_name_raw_hex": name_raw.hex(),
                "rock_ridge_name": alternate_name,
                "rock_ridge_name_encoding_valid": encoding_valid,
                "rock_ridge_name_chain_complete": chain_complete,
                "rock_ridge_name_path_safe": path_safe,
                "rock_ridge_name_usable": name_usable,
            })
            if not encoding_valid:
                anomalies.append("rock_ridge_name_encoding")
            if chain_complete and not path_safe:
                anomalies.append("unsafe_rock_ridge_name")
            if (
                name_usable
                and alternate_name not in {".", ".."}
                and rock_ridge_detected
            ):
                record["archive_name"] = alternate_name
            elif not chain_complete and not continuation_entries:
                anomalies.append("invalid_rock_ridge_name_chain")

        sl_entries = [
            entry for entry in rrip_entries if entry.get("signature") == "SL"
        ]
        rock_ridge_symlink = rock_ridge_detected and (
            bool(sl_entries)
            or record.get("rock_ridge_posix", {}).get("file_type") == "symlink"
        )
        if sl_entries:
            record["rock_ridge_symlink_entries"] = sl_entries
            symlink_targets: list[dict[str, object]] = []
            for sl_entry in sl_entries:
                target_parts: list[str] = []
                absolute = False
                components = sl_entry.get("components", [])
                if not isinstance(components, list):
                    components = []
                for component in components:
                    if not isinstance(component, dict):
                        continue
                    if component.get("root") is True or component.get("volume_root") is True:
                        absolute = True
                    elif component.get("current") is True:
                        target_parts.append(".")
                    elif component.get("parent") is True:
                        target_parts.append("..")
                    elif component.get("host") is True:
                        target_parts.append(f"<host:{component.get('text', '')}>")
                    else:
                        target_parts.append(str(component.get("text", "")))
                target = "/".join(target_parts)
                if absolute:
                    target = f"/{target}"
                symlink_targets.append({
                    "target": target,
                    "complete": (
                        sl_entry.get("valid") is True
                        and sl_entry.get("continuation") is False
                        and all(
                            isinstance(component, dict)
                            and component.get("continuation") is False
                            and component.get("text_encoding_valid") is True
                            for component in components
                        )
                    ),
                    "source_absolute_offset": sl_entry.get("absolute_offset"),
                })
            record["rock_ridge_symlink_targets"] = symlink_targets
        record["rock_ridge_symlink"] = rock_ridge_symlink
        if (
            rock_ridge_symlink
            or record.get("rock_ridge_non_regular") is True
            or record.get("rock_ridge_type_mismatch") is True
            or record.get("rock_ridge_name_usable") is False
            or (susp_error is not None and rock_ridge_detected)
            or continuation_unparsed
            or record.get("rock_ridge_relocation_traversal_suppressed") is True
        ):
            record["extraction_eligible"] = False
        record["rock_ridge_anomalies"] = anomalies
        return susp_error, anomalies

    @staticmethod
    def _iso9660_decode_ucs2(raw: bytes) -> tuple[str, bool]:
        """Decode big-endian UCS-2 while rejecting UTF-16 surrogate semantics."""
        valid = len(raw) % 2 == 0 and all(
            not 0xD800 <= int.from_bytes(raw[index:index + 2], "big") <= 0xDFFF
            for index in range(0, len(raw) - 1, 2)
        )
        try:
            decoded = raw.decode("utf-16-be", errors="strict" if valid else "replace")
        except UnicodeDecodeError:
            return raw.decode("utf-16-be", errors="replace"), False
        return decoded, valid

    @staticmethod
    def _iso9660_directory_record(
        raw: bytes,
        *,
        record_offset: int,
        logical_block_size: int,
        evidence_size: int,
        declared_volume_bytes: int,
        identifier_encoding: str = "ascii",
    ) -> tuple[dict[str, object], str | None]:
        """Decode one bounded ISO directory record with both-endian checks."""
        record: dict[str, object] = {
            "record_offset": record_offset,
            "record_length": len(raw),
            "record_raw_hex": raw.hex(),
            "valid": False,
        }
        if len(raw) < 34 or raw[0] != len(raw):
            return record, f"invalid ISO directory record framing at offset {record_offset}"
        identifier_length = raw[32]
        identifier_end = 33 + identifier_length
        identifier_padding = 1 if identifier_length % 2 == 0 else 0
        system_use_offset = identifier_end + identifier_padding
        if identifier_length == 0 or identifier_end > len(raw) or system_use_offset > len(raw):
            return record, f"invalid ISO file identifier bounds at offset {record_offset}"
        extent_le = int.from_bytes(raw[2:6], "little")
        extent_be = int.from_bytes(raw[6:10], "big")
        data_length_le = int.from_bytes(raw[10:14], "little")
        data_length_be = int.from_bytes(raw[14:18], "big")
        volume_sequence_le = int.from_bytes(raw[28:30], "little")
        volume_sequence_be = int.from_bytes(raw[30:32], "big")
        raw_identifier = raw[33:identifier_end]
        if raw_identifier == b"\x00":
            identifier = "."
        elif raw_identifier == b"\x01":
            identifier = ".."
        elif identifier_encoding == "joliet":
            identifier, joliet_identifier_valid = (
                GenericTriageEngine._iso9660_decode_ucs2(raw_identifier)
            )
        else:
            identifier = raw_identifier.decode("ascii", errors="replace")
        version_match = re.search(r";([0-9]+)$", identifier)
        version = int(version_match.group(1)) if version_match else None
        logical_name = identifier[:version_match.start()] if version_match else identifier
        normalized_name = logical_name.replace("\\", "/")
        path_safe = (
            logical_name in {".", ".."}
            or (
                not normalized_name.startswith("/")
                and "\x00" not in normalized_name
                and re.match(r"^[A-Za-z]:/", normalized_name) is None
                and ".." not in normalized_name.split("/")
                and "/" not in normalized_name
            )
        )
        extended_attribute_blocks = raw[1]
        data_offset = (extent_le + extended_attribute_blocks) * logical_block_size
        data_end = data_offset + data_length_le
        flags = raw[25]
        timestamp, timestamp_valid = GenericTriageEngine._iso9660_recording_time(raw[18:25])
        failed_checks: list[str] = []
        if (
            identifier_encoding == "joliet"
            and raw_identifier not in {b"\x00", b"\x01"}
            and not joliet_identifier_valid
        ):
            failed_checks.append("file_identifier_ucs2")
        if extent_le != extent_be:
            failed_checks.append("extent_location_both_endian")
        if data_length_le != data_length_be:
            failed_checks.append("data_length_both_endian")
        if volume_sequence_le <= 0 or volume_sequence_le != volume_sequence_be:
            failed_checks.append("volume_sequence_number_both_endian")
        if data_offset < 0 or data_end > evidence_size:
            failed_checks.append("extent_within_evidence")
        if data_end > declared_volume_bytes:
            failed_checks.append("extent_within_declared_volume")
        if not path_safe:
            failed_checks.append("file_identifier_path_safe")
        record.update({
            "extended_attribute_blocks": extended_attribute_blocks,
            "logical_block_size": logical_block_size,
            "extent_block": extent_le,
            "extent_block_big_endian": extent_be,
            "extent_both_endian_match": extent_le == extent_be,
            "data_offset": data_offset,
            "data_length": data_length_le,
            "data_length_big_endian": data_length_be,
            "data_length_both_endian_match": data_length_le == data_length_be,
            "data_end_offset": data_end,
            "data_within_evidence": data_end <= evidence_size,
            "data_within_declared_volume": data_end <= declared_volume_bytes,
            "recording_time_raw_hex": raw[18:25].hex(),
            "recording_time_utc": timestamp,
            "recording_time_valid": timestamp_valid,
            "gmt_offset_15_minutes": raw[24] - 256 if raw[24] >= 128 else raw[24],
            "flags_raw": f"0x{flags:02x}",
            "hidden": bool(flags & 0x01),
            "directory": bool(flags & 0x02),
            "associated_file": bool(flags & 0x04),
            "record_format": bool(flags & 0x08),
            "protection": bool(flags & 0x10),
            "multi_extent": bool(flags & 0x80),
            "file_type": "directory" if flags & 0x02 else "regular",
            "file_unit_size": raw[26],
            "interleave_gap_size": raw[27],
            "volume_sequence_number": volume_sequence_le,
            "volume_sequence_number_big_endian": volume_sequence_be,
            "identifier_length": identifier_length,
            "identifier_raw_hex": raw_identifier.hex(),
            "identifier_encoding": identifier_encoding,
            "file_identifier": identifier,
            "logical_name": logical_name,
            "archive_name": logical_name,
            "version": version,
            "identifier_padding_length": identifier_padding,
            "path_safe": path_safe,
            "system_use_offset_in_record": system_use_offset,
            "system_use_length": len(raw) - system_use_offset,
            "system_use_raw_hex": raw[system_use_offset:].hex(),
            "failed_checks": failed_checks,
            "valid": not failed_checks,
            "extraction_eligible": (
                not failed_checks
                and not bool(flags & 0x02)
                and not bool(flags & 0x80)
                and raw[26] == 0
                and raw[27] == 0
                and logical_name not in {".", ".."}
            ),
        })
        return record, None if not failed_checks else (
            f"ISO directory record at offset {record_offset} failed: {', '.join(failed_checks)}"
        )

    @staticmethod
    def _iso9660_long_recording_time(
        raw: bytes,
    ) -> tuple[str | None, bool, int | None]:
        if len(raw) != 17 or not raw[:16].isdigit():
            return None, False, None
        offset_units = raw[16] - 256 if raw[16] >= 128 else raw[16]
        try:
            if not -48 <= offset_units <= 52:
                return None, False, offset_units
            text = raw[:16].decode("ascii")
            local_time = datetime(
                int(text[0:4]), int(text[4:6]), int(text[6:8]),
                int(text[8:10]), int(text[10:12]), int(text[12:14]),
                int(text[14:16]) * 10_000,
            )
            utc_time = local_time - timedelta(minutes=offset_units * 15)
        except (UnicodeDecodeError, ValueError):
            return None, False, offset_units
        return utc_time.replace(tzinfo=UTC).isoformat(), True, offset_units

    @staticmethod
    def _iso9660_recording_time(raw: bytes) -> tuple[str | None, bool]:
        if len(raw) != 7:
            return None, False
        offset_units = raw[6] - 256 if raw[6] >= 128 else raw[6]
        try:
            if not -48 <= offset_units <= 52:
                return None, False
            local_time = datetime(
                raw[0] + 1900, raw[1], raw[2], raw[3], raw[4], raw[5],
            )
            utc_time = local_time - timedelta(minutes=offset_units * 15)
        except ValueError:
            return None, False
        return utc_time.replace(tzinfo=UTC).isoformat(), True

    def _inspect_disk_memory(
        self, artifact: Artifact, path: Path, header: bytes, size: int
    ) -> list[Observation]:
        """Parse bounded MBR/GPT layout metadata without mounting evidence."""
        mbr = False
        boot_signature = False
        gpt = False
        sector = b""
        if size >= 512:
            with path.open("rb") as stream:
                sector = stream.read(512)
                boot_signature = sector[510:512] == b"\x55\xaa"
        gpt_header = b""
        if size >= 1024:
            with path.open("rb") as stream:
                stream.seek(512)
                gpt_header = stream.read(512)
                gpt = gpt_header[:8] == b"EFI PART"
        ewf = header.startswith(b"EVF\x09\x0d\x0a\xff\x00")
        qcow_header = self._qcow2_header(header, size) if header.startswith(b"QFI\xfb") else {"valid": False}
        vhd_footer = self._vhd_footer(path, size)
        hiber = header.startswith(b"hibr")
        crash = header.startswith((b"PAGE", b"DU64", b"MDMP"))
        # The 0x55aa boot signature also occurs on raw NTFS/FAT volumes.  It
        # becomes an MBR classification only when a non-empty primary entry
        # is present; raw volume images retain filesystem-first routing.
        mbr_partitions = self._mbr_partitions(sector, size) if boot_signature else []
        mbr = bool(mbr_partitions)
        ebr_chains, logical_partitions = self._mbr_logical_partitions(
            path, size, mbr_partitions,
        )
        gpt_details, gpt_partitions = self._gpt_partitions(path, size, gpt_header) if gpt else ({"valid": False}, [])
        gpt_filesystem_validation = {
            "eligible": bool(
                gpt_details.get("valid") is True
                and gpt_details.get("header_crc_valid") is True
                and gpt_details.get("partition_entry_crc_valid") is True
            ),
            "header_structurally_valid": gpt_details.get("valid"),
            "header_crc_valid": gpt_details.get("header_crc_valid"),
            "partition_entry_crc_valid": gpt_details.get("partition_entry_crc_valid"),
            "reason": None,
        }
        if not gpt_filesystem_validation["eligible"]:
            gpt_filesystem_validation["reason"] = (
                "GPT header geometry, header CRC, and complete partition-entry-table CRC must all validate"
            )
        partition_extent_conflicts = self._partition_extent_conflicts(
            mbr_partitions,
            logical_partitions,
            gpt_partitions if gpt_filesystem_validation["eligible"] else [],
        )
        partition_filesystems = self._inspect_mbr_partition_filesystems(
            path, size, mbr_partitions,
        )
        logical_partition_filesystems = self._inspect_mbr_logical_partition_filesystems(
            path, size, logical_partitions,
        )
        gpt_partition_filesystems = (
            self._inspect_gpt_partition_filesystems(path, size, gpt_partitions)
            if gpt_filesystem_validation["eligible"] else []
        )
        return [
            self._observation(artifact, "disk.mbr_signature", mbr),
            self._observation(artifact, "disk.boot_signature", boot_signature),
            self._observation(artifact, "disk.gpt_signature", gpt),
            self._observation(artifact, "signature.partition_table", mbr or gpt),
            self._observation(artifact, "disk.mbr.partition_count", len(mbr_partitions)),
            self._observation(artifact, "disk.mbr.partitions", mbr_partitions),
            self._observation(artifact, "disk.mbr.partition_filesystems", partition_filesystems),
            self._observation(artifact, "disk.mbr.ebr_chains", ebr_chains),
            self._observation(artifact, "disk.mbr.logical_partition_count", len(logical_partitions)),
            self._observation(artifact, "disk.mbr.logical_partitions", logical_partitions),
            self._observation(artifact, "disk.mbr.logical_partition_filesystems", logical_partition_filesystems),
            self._observation(artifact, "disk.gpt.header", gpt_details),
            self._observation(artifact, "disk.gpt.partition_count", len(gpt_partitions)),
            self._observation(artifact, "disk.gpt.partitions", gpt_partitions),
            self._observation(artifact, "disk.gpt.partition_filesystem_validation", gpt_filesystem_validation),
            self._observation(artifact, "disk.gpt.partition_filesystems", gpt_partition_filesystems),
            self._observation(artifact, "disk.partition_extent_conflicts", partition_extent_conflicts),
            self._observation(artifact, "disk.ewf_signature", ewf),
            self._observation(artifact, "disk.qcow2_signature", header.startswith(b"QFI\xfb")),
            self._observation(artifact, "disk.qcow2.header", qcow_header),
            self._observation(artifact, "disk.vhd_signature", bool(vhd_footer.get("signature"))),
            self._observation(artifact, "disk.vhd.footer", vhd_footer),
            self._observation(artifact, "signature.memory_dump", hiber or crash),
            self._observation(artifact, "memory.windows_crash_signature", crash),
            self._observation(artifact, "memory.hiberfil_signature", hiber),
        ]

    @staticmethod
    def _qcow2_header(header: bytes, image_size: int) -> dict[str, object]:
        """Parse fixed QCOW2 header metadata without following tables."""
        if len(header) < 72 or not header.startswith(b"QFI\xfb"):
            return {"valid": False}
        version = int.from_bytes(header[4:8], "big")
        backing_offset = int.from_bytes(header[8:16], "big")
        backing_size = int.from_bytes(header[16:20], "big")
        cluster_bits = int.from_bytes(header[20:24], "big")
        virtual_size = int.from_bytes(header[24:32], "big")
        crypt_method = int.from_bytes(header[32:36], "big")
        l1_size = int.from_bytes(header[36:40], "big")
        l1_offset = int.from_bytes(header[40:48], "big")
        valid = (
            version in {2, 3}
            and 9 <= cluster_bits <= 21
            and virtual_size > 0
            and l1_size > 0
            and l1_offset % 8 == 0
            and l1_offset < image_size
            and (backing_offset == 0 or backing_offset + backing_size <= image_size)
        )
        return {
            "valid": valid,
            "version": version,
            "cluster_size": 1 << cluster_bits if cluster_bits < 63 else None,
            "virtual_size": virtual_size,
            "backing_file_offset": backing_offset,
            "backing_file_size": backing_size,
            "crypt_method": crypt_method,
            "l1_size": l1_size,
            "l1_table_offset": l1_offset,
        }

    @staticmethod
    def _vhd_footer(path: Path, image_size: int) -> dict[str, object]:
        """Validate the fixed 512-byte VHD footer, never its dynamic tables."""
        if image_size < 512:
            return {"signature": False, "valid": False}
        try:
            with path.open("rb") as stream:
                stream.seek(image_size - 512)
                footer = stream.read(512)
        except OSError:
            return {"signature": False, "valid": False}
        if len(footer) != 512 or footer[:8] != b"conectix":
            return {"signature": False, "valid": False}
        stored_checksum = int.from_bytes(footer[64:68], "big")
        checksum_input = bytearray(footer)
        checksum_input[64:68] = b"\x00" * 4
        calculated_checksum = (~sum(checksum_input)) & 0xFFFFFFFF
        features = int.from_bytes(footer[8:12], "big")
        format_version = int.from_bytes(footer[12:16], "big")
        data_offset = int.from_bytes(footer[16:24], "big")
        original_size = int.from_bytes(footer[40:48], "big")
        current_size = int.from_bytes(footer[48:56], "big")
        disk_type = int.from_bytes(footer[60:64], "big")
        type_names = {2: "fixed", 3: "dynamic", 4: "differencing"}
        valid = (
            format_version == 0x00010000
            and current_size > 0
            and disk_type in type_names
            and stored_checksum == calculated_checksum
        )
        return {
            "signature": True,
            "valid": valid,
            "features": f"0x{features:08x}",
            "format_version": f"{format_version >> 16}.{format_version & 0xffff}",
            "data_offset": data_offset,
            "original_size": original_size,
            "current_size": current_size,
            "disk_type": type_names.get(disk_type, f"unknown_{disk_type}"),
            "checksum_valid": stored_checksum == calculated_checksum,
            "uuid": str(uuid.UUID(bytes=footer[68:84])),
            "saved_state": bool(footer[84]),
        }

    @staticmethod
    def _mbr_partitions(sector: bytes, image_size: int) -> list[dict[str, object]]:
        if len(sector) < 512:
            return []
        sectors = image_size // 512
        type_names = {
            0x01: "FAT12", 0x04: "FAT16", 0x05: "extended", 0x06: "FAT16",
            0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32-LBA",
            0x0E: "FAT16-LBA", 0x0F: "extended-LBA", 0x27: "Windows recovery",
            0x82: "Linux swap", 0x83: "Linux", 0x85: "Linux extended", 0xEE: "GPT protective",
        }
        partitions: list[dict[str, object]] = []
        for index in range(4):
            entry = sector[446 + index * 16:462 + index * 16]
            if len(entry) != 16:
                continue
            status, kind = entry[0], entry[4]
            start_lba, sector_count = struct.unpack_from("<II", entry, 8)
            if kind == 0 and sector_count == 0:
                continue
            end_lba = start_lba + sector_count - 1 if sector_count else start_lba
            partitions.append({
                "slot": index + 1,
                "bootable": status == 0x80,
                "status": f"0x{status:02x}",
                "status_valid": status in {0x00, 0x80},
                "entry_valid": status in {0x00, 0x80} and kind != 0 and sector_count > 0,
                "entry_offset": 446 + index * 16,
                "raw_hex": entry.hex(),
                "type_code": f"0x{kind:02x}",
                "type": type_names.get(kind, "unknown"),
                "start_lba": start_lba,
                "sector_count": sector_count,
                "end_lba": end_lba,
                "within_image": bool(sector_count and end_lba < sectors),
            })
        return partitions

    @staticmethod
    def _partition_extent_conflicts(
        primary_partitions: list[dict[str, object]],
        logical_partitions: list[dict[str, object]],
        gpt_partitions: list[dict[str, object]],
    ) -> dict[str, object]:
        """Inventory ambiguous data-partition extents under a fixed bounded table scope.

        Extended MBR entries and the protective 0xEE entry are address-space
        containers, not independently materializable data partitions. Their
        expected containment of logical/GPT entries is retained but excluded
        from conflict decisions.
        """
        candidates: list[tuple[dict[str, object], dict[str, object]]] = []
        excluded: list[dict[str, object]] = []

        def add_candidate(
            record: dict[str, object],
            *,
            table: str,
            index_key: str,
            index_value: object,
            start_key: str,
            type_fields: tuple[str, ...],
            excluded_role: str | None = None,
        ) -> None:
            start_lba = record.get(start_key)
            sector_count = record.get("sector_count")
            if (
                record.get("entry_valid") is not True
                or isinstance(start_lba, bool) or not isinstance(start_lba, int)
                or isinstance(sector_count, bool) or not isinstance(sector_count, int)
                or start_lba < 0 or sector_count <= 0
            ):
                return
            identity = f"{table}:{index_value}"
            descriptor: dict[str, object] = {
                "identity": identity,
                "partition_table": table,
                "partition_extent_role": excluded_role or "data",
                index_key: index_value,
                "entry_offset": record.get("entry_offset"),
                "start_lba": start_lba,
                "end_lba": start_lba + sector_count - 1,
                "sector_count": sector_count,
                "partition_offset": start_lba * 512,
                "partition_length": sector_count * 512,
                "partition_end_offset_exclusive": (start_lba + sector_count) * 512,
            }
            for key in type_fields:
                if key in record:
                    descriptor[key] = record[key]
            record["partition_extent_identity"] = identity
            record["partition_extent_role"] = excluded_role or "data"
            record["partition_extent_ambiguous"] = False
            record["partition_extent_conflict_count"] = 0
            if excluded_role is not None:
                excluded.append(descriptor)
                return
            candidates.append((record, descriptor))

        for partition in primary_partitions[:4]:
            type_code = str(partition.get("type_code", "")).lower()
            role = None
            if type_code in {"0x05", "0x0f", "0x85"}:
                role = "extended_container"
            elif type_code == "0xee":
                role = "gpt_protective_container"
            add_candidate(
                partition,
                table="mbr_primary",
                index_key="slot",
                index_value=partition.get("slot"),
                start_key="start_lba",
                type_fields=("status", "type_code", "type", "raw_hex", "within_image"),
                excluded_role=role,
            )
        for partition in logical_partitions[:32]:
            add_candidate(
                partition,
                table="mbr_logical",
                index_key="logical_partition_index",
                index_value=partition.get("logical_index"),
                start_key="start_lba",
                type_fields=(
                    "extended_primary_slot", "extended_base_lba", "extended_end_lba",
                    "ebr_lba", "ebr_offset", "relative_start_lba", "status",
                    "type_code", "type", "raw_hex", "within_image",
                ),
            )
        for partition in gpt_partitions[:256]:
            add_candidate(
                partition,
                table="gpt",
                index_key="gpt_partition_index",
                index_value=partition.get("index"),
                start_key="first_lba",
                type_fields=(
                    "type_guid", "unique_guid", "name", "within_usable_range", "within_image",
                ),
            )

        conflict_records: list[dict[str, object]] = []
        conflict_count = 0
        ambiguous_identities: set[str] = set()
        for left_index, (left_record, left) in enumerate(candidates):
            left_start = int(left["start_lba"])
            left_end = int(left["end_lba"])
            for right_record, right in candidates[left_index + 1:]:
                right_start = int(right["start_lba"])
                right_end = int(right["end_lba"])
                overlap_start = max(left_start, right_start)
                overlap_end = min(left_end, right_end)
                if overlap_start > overlap_end:
                    continue
                relation = (
                    "exact_duplicate"
                    if left_start == right_start and left_end == right_end
                    else "partial_overlap"
                )
                containment: str | None = None
                if relation == "partial_overlap":
                    if left_start <= right_start and right_end <= left_end:
                        containment = "left_contains_right"
                    elif right_start <= left_start and left_end <= right_end:
                        containment = "right_contains_left"
                conflict_count += 1
                left_record["partition_extent_ambiguous"] = True
                right_record["partition_extent_ambiguous"] = True
                left_record["partition_extent_conflict_count"] = int(
                    left_record["partition_extent_conflict_count"]
                ) + 1
                right_record["partition_extent_conflict_count"] = int(
                    right_record["partition_extent_conflict_count"]
                ) + 1
                ambiguous_identities.update((str(left["identity"]), str(right["identity"])))
                if len(conflict_records) < 128:
                    conflict_records.append({
                        "relation": relation,
                        "containment": containment,
                        "overlap_start_lba": overlap_start,
                        "overlap_end_lba": overlap_end,
                        "overlap_sector_count": overlap_end - overlap_start + 1,
                        "overlap_offset": overlap_start * 512,
                        "overlap_length": (overlap_end - overlap_start + 1) * 512,
                        "left": left,
                        "right": right,
                    })
        return {
            "sector_size": 512,
            "candidate_count": len(candidates),
            "excluded_semantic_container_count": len(excluded),
            "excluded_semantic_containers": excluded[:8],
            "conflict_count": conflict_count,
            "ambiguous_candidate_count": len(ambiguous_identities),
            "ambiguous_candidate_identities": sorted(ambiguous_identities)[:256],
            "ambiguous_candidate_identities_truncated": len(ambiguous_identities) > 256,
            "records": conflict_records,
            "records_truncated": conflict_count > len(conflict_records),
        }

    @staticmethod
    def _mbr_logical_partitions(
        path: Path,
        image_size: int,
        primary_partitions: list[dict[str, object]],
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        """Follow bounded EBR chains with explicit current/base-relative semantics."""
        extended_types = {"0x05", "0x0f", "0x85"}
        type_names = {
            0x01: "FAT12", 0x04: "FAT16", 0x06: "FAT16", 0x07: "NTFS/exFAT",
            0x0B: "FAT32", 0x0C: "FAT32-LBA", 0x0E: "FAT16-LBA",
            0x82: "Linux swap", 0x83: "Linux", 0x8E: "Linux LVM",
        }
        image_sectors = image_size // 512
        chains: list[dict[str, object]] = []
        logical_partitions: list[dict[str, object]] = []
        for primary in primary_partitions:
            if str(primary.get("type_code", "")).lower() not in extended_types:
                continue
            base_lba = int(primary.get("start_lba", 0))
            extended_sectors = int(primary.get("sector_count", 0))
            extended_end_lba = (
                base_lba + extended_sectors - 1 if extended_sectors > 0 else base_lba
            )
            chain: dict[str, object] = {
                "extended_primary_slot": primary.get("slot"),
                "extended_type_code": primary.get("type_code"),
                "extended_base_lba": base_lba,
                "extended_end_lba": extended_end_lba,
                "ebr_records": [],
                "errors": [],
                "termination": "limit",
            }
            records = chain["ebr_records"]
            errors = chain["errors"]
            if not isinstance(records, list) or not isinstance(errors, list):
                continue
            current_ebr_lba = base_lba
            visited: set[int] = set()
            for _ in range(32 - len(logical_partitions)):
                if current_ebr_lba in visited:
                    chain["termination"] = "cycle"
                    errors.append(f"EBR chain cycles at LBA {current_ebr_lba}")
                    break
                if not (
                    base_lba <= current_ebr_lba <= extended_end_lba
                    and current_ebr_lba < image_sectors
                ):
                    chain["termination"] = "bounds"
                    errors.append(f"EBR LBA {current_ebr_lba} is outside extended/image bounds")
                    break
                visited.add(current_ebr_lba)
                ebr_offset = current_ebr_lba * 512
                try:
                    with path.open("rb") as stream:
                        stream.seek(ebr_offset)
                        sector = stream.read(512)
                except OSError as exc:
                    chain["termination"] = "read_error"
                    errors.append(str(exc)[:2_000])
                    break
                if len(sector) != 512:
                    chain["termination"] = "truncated_read"
                    errors.append(f"EBR at LBA {current_ebr_lba} could not be read completely")
                    break
                ebr_record: dict[str, object] = {
                    "ebr_lba": current_ebr_lba,
                    "ebr_offset": ebr_offset,
                    "signature_valid": sector[510:512] == b"\x55\xaa",
                    "logical_entry_offset": ebr_offset + 446,
                    "link_entry_offset": ebr_offset + 462,
                    "logical_entry_relative_to": "current_ebr_lba",
                    "link_entry_relative_to": "extended_base_lba",
                }
                records.append(ebr_record)
                if not ebr_record["signature_valid"]:
                    chain["termination"] = "invalid_signature"
                    errors.append(f"EBR at LBA {current_ebr_lba} lacks the 55 AA marker")
                    break
                logical_entry = sector[446:462]
                status, kind = logical_entry[0], logical_entry[4]
                relative_start = int.from_bytes(logical_entry[8:12], "little")
                sector_count = int.from_bytes(logical_entry[12:16], "little")
                logical_start = current_ebr_lba + relative_start
                logical_end = (
                    logical_start + sector_count - 1 if sector_count else logical_start
                )
                logical_valid = (
                    status in {0x00, 0x80}
                    and kind != 0
                    and f"0x{kind:02x}" not in extended_types
                    and relative_start > 0
                    and sector_count > 0
                    and base_lba <= logical_start <= logical_end <= extended_end_lba
                )
                ebr_record["logical_entry"] = {
                    "status": f"0x{status:02x}",
                    "status_valid": status in {0x00, 0x80},
                    "type_code": f"0x{kind:02x}",
                    "relative_start_lba": relative_start,
                    "sector_count": sector_count,
                    "absolute_start_lba": logical_start,
                    "absolute_end_lba": logical_end,
                    "valid": logical_valid,
                }
                if kind or relative_start or sector_count:
                    if logical_valid:
                        logical_partitions.append({
                            "logical_index": len(logical_partitions) + 1,
                            "extended_primary_slot": primary.get("slot"),
                            "extended_type_code": primary.get("type_code"),
                            "extended_base_lba": base_lba,
                            "extended_end_lba": extended_end_lba,
                            "ebr_lba": current_ebr_lba,
                            "ebr_offset": ebr_offset,
                            "entry_offset": ebr_offset + 446,
                            "entry_valid": True,
                            "raw_hex": logical_entry.hex(),
                            "status": f"0x{status:02x}",
                            "bootable": status == 0x80,
                            "type_code": f"0x{kind:02x}",
                            "type": type_names.get(kind, "unknown"),
                            "relative_start_lba": relative_start,
                            "start_lba": logical_start,
                            "sector_count": sector_count,
                            "end_lba": logical_end,
                            "within_extended_partition": True,
                            "within_image": logical_end < image_sectors,
                        })
                    else:
                        errors.append(f"invalid logical entry at EBR LBA {current_ebr_lba}")

                link_entry = sector[462:478]
                link_status, link_kind = link_entry[0], link_entry[4]
                link_relative = int.from_bytes(link_entry[8:12], "little")
                link_sectors = int.from_bytes(link_entry[12:16], "little")
                ebr_record["link_entry"] = {
                    "status": f"0x{link_status:02x}",
                    "status_valid": link_status in {0x00, 0x80},
                    "type_code": f"0x{link_kind:02x}",
                    "relative_start_lba": link_relative,
                    "sector_count": link_sectors,
                    "absolute_ebr_lba": base_lba + link_relative if link_relative else None,
                }
                if link_kind == 0 and link_relative == 0 and link_sectors == 0:
                    chain["termination"] = "end"
                    break
                next_ebr_lba = base_lba + link_relative
                if (
                    link_status not in {0x00, 0x80}
                    or f"0x{link_kind:02x}" not in extended_types
                    or link_relative <= 0
                    or link_sectors <= 0
                    or not base_lba <= next_ebr_lba <= extended_end_lba
                ):
                    chain["termination"] = "invalid_link"
                    errors.append(f"invalid EBR link at LBA {current_ebr_lba}")
                    break
                current_ebr_lba = next_ebr_lba
            else:
                errors.append("EBR traversal reached the shared 32-logical-partition bound")
            chains.append(chain)
            if len(logical_partitions) >= 32:
                break
        return chains, logical_partitions

    def _inspect_mbr_partition_filesystems(
        self,
        path: Path,
        image_size: int,
        partitions: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Validate filesystem boot sectors at exact primary-MBR LBA offsets."""
        expected_by_type = {
            "0x01": ["fat12"],
            "0x04": ["fat16"],
            "0x06": ["fat16"],
            "0x0b": ["fat32"],
            "0x0c": ["fat32"],
            "0x0e": ["fat16"],
            "0x07": ["ntfs", "exfat"],
        }
        results: list[dict[str, object]] = []
        for partition in partitions[:4]:
            start_lba = int(partition.get("start_lba", 0))
            sector_count = int(partition.get("sector_count", 0))
            partition_offset = start_lba * 512
            declared_bytes = sector_count * 512
            available_bytes = (
                min(declared_bytes, image_size - partition_offset)
                if declared_bytes > 0 and 0 <= partition_offset < image_size else 0
            )
            type_code = str(partition.get("type_code", ""))
            expected = expected_by_type.get(type_code, [])
            record: dict[str, object] = {
                "slot": partition.get("slot"),
                "partition_table": partition.get("partition_table", "mbr_primary"),
                "partition_type_code": type_code,
                "partition_type": partition.get("type"),
                "start_lba": start_lba,
                "sector_count": sector_count,
                "partition_offset": partition_offset,
                "declared_partition_bytes": declared_bytes,
                "available_partition_bytes": available_bytes,
                "partition_within_supplied_image": partition.get("within_image"),
                "partition_entry_valid": partition.get("entry_valid"),
                "partition_entry_offset": partition.get("entry_offset"),
                "partition_extent_identity": partition.get("partition_extent_identity"),
                "partition_extent_role": partition.get("partition_extent_role"),
                "partition_extent_ambiguous": partition.get("partition_extent_ambiguous", False),
                "partition_extent_conflict_count": partition.get("partition_extent_conflict_count", 0),
                "boot_sector_offset": partition_offset,
                "boot_sector_available": available_bytes >= 512,
                "expected_filesystems_from_type_code": expected,
                "filesystem_candidate": None,
                "detected_filesystem": None,
                "detection_basis": None,
                "validation": None,
                "partition_type_matches_detected": None,
                "boot_declared_start_lba": None,
                "boot_declared_start_lba_field_offset": None,
                "boot_declared_start_lba_matches_mbr": None,
                "boot_declared_volume_bytes": None,
                "boot_declared_volume_field_offset": None,
                "boot_declared_volume_field_width": None,
                "boot_declared_volume_matches_partition": None,
            }
            if record["partition_entry_valid"] is False:
                record["error"] = "partition table entry failed structural validation"
                results.append(record)
                continue
            if available_bytes < 512:
                record["error"] = "partition boot sector is outside supplied image bounds"
                results.append(record)
                continue
            try:
                with path.open("rb") as stream:
                    stream.seek(partition_offset)
                    boot_sector = stream.read(512)
            except OSError as exc:
                record["error"] = str(exc)[:2_000]
                results.append(record)
                continue
            if len(boot_sector) != 512:
                record["error"] = "partition boot sector could not be read completely"
                results.append(record)
                continue

            detected: str | None = None
            if boot_sector[3:11] == b"NTFS    ":
                record["filesystem_candidate"] = "ntfs"
                record["detection_basis"] = "ntfs_oem_identifier_and_bpb"
                validation = self._ntfs_partition_boot_validation(
                    boot_sector, declared_bytes,
                )
                record["validation"] = validation
                if validation["valid"] is True:
                    detected = "ntfs"
            elif boot_sector[3:11] == b"EXFAT   ":
                record["filesystem_candidate"] = "exfat"
                record["detection_basis"] = "exfat_name_and_boot_geometry"
                validation = self._exfat_partition_boot_validation(
                    boot_sector, declared_bytes,
                )
                record["validation"] = validation
                if validation["valid"] is True:
                    detected = "exfat"
            else:
                fat_bits = self._fat_bpb_cluster_count_variant(boot_sector)
                label_records = self._fat_type_label_records(boot_sector)
                explicit_label_bits = {
                    int(item["explicit_fat_bits"])
                    for item in label_records
                    if isinstance(item.get("explicit_fat_bits"), int)
                }
                label_bits = (
                    next(iter(explicit_label_bits))
                    if len(explicit_label_bits) == 1 else 0
                )
                candidate_bits = fat_bits or label_bits
                if candidate_bits:
                    record["filesystem_candidate"] = f"fat{candidate_bits}"
                    record["detection_basis"] = "fat_bpb_cluster_count"
                    validation = self._fat_bpb_validation(
                        boot_sector, declared_bytes, candidate_bits,
                    )
                    validation["declared_volume_within_partition"] = validation.pop(
                        "declared_volume_within_supplied_image"
                    )
                    validation["type_label_records"] = [
                        {**item, "image_offset": partition_offset + int(item["offset"])}
                        for item in label_records
                    ]
                    record["validation"] = validation
                    if validation["valid"] is True and fat_bits == candidate_bits:
                        detected = f"fat{candidate_bits}"
            if record["filesystem_candidate"] is not None:
                start_field_offset = 64 if record["filesystem_candidate"] == "exfat" else 28
                start_field_width = 8 if record["filesystem_candidate"] == "exfat" else 4
                declared_start_lba = int.from_bytes(
                    boot_sector[start_field_offset:start_field_offset + start_field_width],
                    "little",
                )
                record["boot_declared_start_lba"] = declared_start_lba
                record["boot_declared_start_lba_field_offset"] = (
                    partition_offset + start_field_offset
                )
                record["boot_declared_start_lba_matches_mbr"] = (
                    declared_start_lba == start_lba
                )
                validation = record.get("validation")
                if isinstance(validation, dict):
                    declared_volume_bytes = validation.get("declared_volume_bytes")
                    if isinstance(declared_volume_bytes, int):
                        record["boot_declared_volume_bytes"] = declared_volume_bytes
                        if record["filesystem_candidate"] == "exfat":
                            volume_field_offset, volume_field_width = 72, 8
                        elif record["filesystem_candidate"] == "ntfs":
                            volume_field_offset, volume_field_width = 40, 8
                        elif int.from_bytes(boot_sector[19:21], "little"):
                            volume_field_offset, volume_field_width = 19, 2
                        else:
                            volume_field_offset, volume_field_width = 32, 4
                        record["boot_declared_volume_field_offset"] = (
                            partition_offset + volume_field_offset
                        )
                        record["boot_declared_volume_field_width"] = volume_field_width
                        record["boot_declared_volume_matches_partition"] = (
                            declared_volume_bytes == declared_bytes
                        )
            record["detected_filesystem"] = detected
            if detected is not None and expected:
                record["partition_type_matches_detected"] = detected in expected
            results.append(record)
        return results

    def _inspect_mbr_logical_partition_filesystems(
        self,
        path: Path,
        image_size: int,
        partitions: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Apply the shared boot validators to bounded EBR-derived partitions."""
        results: list[dict[str, object]] = []
        for partition in partitions[:32]:
            pseudo_partition = {
                "slot": partition.get("logical_index"),
                "partition_table": "mbr_logical",
                "type_code": partition.get("type_code"),
                "type": partition.get("type"),
                "start_lba": partition.get("start_lba"),
                "sector_count": partition.get("sector_count"),
                "within_image": partition.get("within_image"),
                "entry_valid": True,
                "entry_offset": partition.get("entry_offset"),
                "partition_extent_identity": partition.get("partition_extent_identity"),
                "partition_extent_role": partition.get("partition_extent_role"),
                "partition_extent_ambiguous": partition.get("partition_extent_ambiguous"),
                "partition_extent_conflict_count": partition.get("partition_extent_conflict_count"),
            }
            records = self._inspect_mbr_partition_filesystems(
                path, image_size, [pseudo_partition],
            )
            if not records:
                continue
            record = records[0]
            record.update({
                "partition_table": "mbr_logical",
                "logical_partition_index": partition.get("logical_index"),
                "extended_primary_slot": partition.get("extended_primary_slot"),
                "extended_type_code": partition.get("extended_type_code"),
                "extended_base_lba": partition.get("extended_base_lba"),
                "extended_end_lba": partition.get("extended_end_lba"),
                "ebr_lba": partition.get("ebr_lba"),
                "ebr_offset": partition.get("ebr_offset"),
                "logical_entry_offset": partition.get("entry_offset"),
                "logical_relative_start_lba": partition.get("relative_start_lba"),
            })
            record.pop("slot", None)
            record["boot_declared_start_lba_matches_logical_entry"] = record.pop(
                "boot_declared_start_lba_matches_mbr", None,
            )
            results.append(record)
        return results

    def _inspect_gpt_partition_filesystems(
        self,
        path: Path,
        image_size: int,
        partitions: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Apply boot validators only to entries from a CRC-validated GPT table."""
        expected_by_guid = {
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": ["fat12", "fat16", "fat32"],
            "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": [
                "fat12", "fat16", "fat32", "ntfs", "exfat",
            ],
        }
        results: list[dict[str, object]] = []
        for partition in partitions[:32]:
            first_lba = int(partition.get("first_lba", 0))
            pseudo_partition = {
                "slot": partition.get("index"),
                "partition_table": "gpt",
                "type_code": "",
                "type": "GPT",
                "start_lba": first_lba,
                "sector_count": partition.get("sector_count", 0),
                "within_image": partition.get("within_image"),
                "entry_valid": partition.get("entry_valid"),
                "entry_offset": partition.get("entry_offset"),
                "partition_extent_identity": partition.get("partition_extent_identity"),
                "partition_extent_role": partition.get("partition_extent_role"),
                "partition_extent_ambiguous": partition.get("partition_extent_ambiguous"),
                "partition_extent_conflict_count": partition.get("partition_extent_conflict_count"),
            }
            records = self._inspect_mbr_partition_filesystems(
                path, image_size, [pseudo_partition],
            )
            if not records:
                continue
            record = records[0]
            type_guid = str(partition.get("type_guid", "")).lower()
            expected = expected_by_guid.get(type_guid, [])
            record.update({
                "partition_table": "gpt",
                "gpt_partition_index": partition.get("index"),
                "partition_type_guid": partition.get("type_guid"),
                "partition_unique_guid": partition.get("unique_guid"),
                "partition_name": partition.get("name"),
                "last_lba": partition.get("last_lba"),
                "expected_filesystems_from_type_guid": expected,
            })
            record.pop("slot", None)
            record.pop("partition_type_code", None)
            record.pop("partition_type", None)
            record.pop("expected_filesystems_from_type_code", None)
            record["boot_declared_start_lba_matches_gpt"] = record.pop(
                "boot_declared_start_lba_matches_mbr", None,
            )
            detected = record.get("detected_filesystem")
            record["partition_type_matches_detected"] = (
                detected in expected if detected is not None and expected else None
            )
            results.append(record)
        return results

    @staticmethod
    def _ntfs_partition_boot_validation(
        boot_sector: bytes, partition_bytes: int,
    ) -> dict[str, object]:
        bytes_per_sector = int.from_bytes(boot_sector[11:13], "little")
        sectors_per_cluster = boot_sector[13]
        total_sectors = int.from_bytes(boot_sector[40:48], "little")
        cluster_count = total_sectors // sectors_per_cluster if sectors_per_cluster else 0
        mft_lcn = int.from_bytes(boot_sector[48:56], "little")
        mft_mirror_lcn = int.from_bytes(boot_sector[56:64], "little")
        cluster_size = bytes_per_sector * sectors_per_cluster

        def record_size(raw: int) -> int:
            signed = raw - 256 if raw >= 128 else raw
            if signed < 0:
                return 1 << -signed if -signed < 31 else 0
            return signed * cluster_size

        file_record_size = record_size(boot_sector[64])
        index_record_size = record_size(boot_sector[68])
        jump_target = (
            2 + int.from_bytes(boot_sector[1:2], "little", signed=True)
            if boot_sector[0] == 0xEB else None
        )
        checks = {
            "oem_identifier_valid": boot_sector[3:11] == b"NTFS    ",
            "jump_instruction_valid": (
                boot_sector[0] == 0xEB and boot_sector[2] == 0x90
                and jump_target is not None and 3 <= jump_target < 510
            ),
            "end_marker_valid": boot_sector[510:512] == b"\x55\xaa",
            "bytes_per_sector_valid": bytes_per_sector in {512, 1024, 2048, 4096},
            "sectors_per_cluster_valid": (
                0 < sectors_per_cluster <= 128
                and sectors_per_cluster & (sectors_per_cluster - 1) == 0
            ),
            "reserved_bpb_fields_valid": (
                boot_sector[14:16] == b"\x00\x00"
                and boot_sector[16:21] == b"\x00" * 5
                and boot_sector[21] == 0xF8
                and boot_sector[22:24] == b"\x00\x00"
                and boot_sector[32:40] == b"\x00" * 8
            ),
            "total_sectors_valid": total_sectors > 0,
            "mft_lcn_valid": 0 < mft_lcn < cluster_count,
            "mft_mirror_lcn_valid": 0 < mft_mirror_lcn < cluster_count,
            "file_record_size_valid": (
                256 <= file_record_size <= 65_536
                and file_record_size & (file_record_size - 1) == 0
            ),
            "index_record_size_valid": (
                256 <= index_record_size <= 65_536
                and index_record_size & (index_record_size - 1) == 0
            ),
        }
        declared_volume_bytes = total_sectors * bytes_per_sector
        return {
            "available": len(boot_sector) == 512,
            "valid": all(checks.values()),
            "failed_checks": [name for name, valid in checks.items() if not valid],
            "checks": checks,
            "jump_target_offset": jump_target,
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "cluster_size": cluster_size,
            "total_sectors": total_sectors,
            "cluster_count": cluster_count,
            "mft_lcn": mft_lcn,
            "mft_mirror_lcn": mft_mirror_lcn,
            "file_record_size": file_record_size,
            "index_record_size": index_record_size,
            "declared_volume_bytes": declared_volume_bytes,
            "declared_volume_within_partition": declared_volume_bytes <= partition_bytes,
        }

    @staticmethod
    def _exfat_partition_boot_validation(
        boot_sector: bytes, partition_bytes: int,
    ) -> dict[str, object]:
        volume_sectors = int.from_bytes(boot_sector[72:80], "little")
        fat_offset = int.from_bytes(boot_sector[80:84], "little")
        fat_length = int.from_bytes(boot_sector[84:88], "little")
        cluster_heap_offset = int.from_bytes(boot_sector[88:92], "little")
        cluster_count = int.from_bytes(boot_sector[92:96], "little")
        root_cluster = int.from_bytes(boot_sector[96:100], "little")
        revision = int.from_bytes(boot_sector[104:106], "little")
        bytes_shift = boot_sector[108]
        sectors_shift = boot_sector[109]
        fat_count = boot_sector[110]
        percent_in_use = boot_sector[112]
        bytes_per_sector = 1 << bytes_shift if bytes_shift < 31 else 0
        sectors_per_cluster = 1 << sectors_shift if sectors_shift < 31 else 0
        fat_entry_capacity = (
            fat_length * bytes_per_sector // 4 if bytes_per_sector else 0
        )
        checks = {
            "jump_instruction_valid": boot_sector[:3] == b"\xeb\x76\x90",
            "filesystem_name_valid": boot_sector[3:11] == b"EXFAT   ",
            "must_be_zero_valid": boot_sector[11:64] == b"\x00" * 53,
            "end_marker_valid": boot_sector[510:512] == b"\x55\xaa",
            "revision_valid": revision == 0x0100,
            "bytes_per_sector_shift_valid": 9 <= bytes_shift <= 12,
            "sectors_per_cluster_shift_valid": (
                sectors_shift <= 25 - bytes_shift if bytes_shift <= 25 else False
            ),
            "fat_count_valid": fat_count in {1, 2},
            "percent_in_use_valid": percent_in_use <= 100 or percent_in_use == 0xFF,
            "volume_sectors_valid": volume_sectors > 0,
            "fat_region_valid": (
                fat_offset >= 24 and fat_length > 0
                and fat_offset + fat_count * fat_length <= cluster_heap_offset
            ),
            "cluster_heap_valid": (
                cluster_count > 0
                and cluster_heap_offset + cluster_count * sectors_per_cluster <= volume_sectors
            ),
            "root_cluster_valid": 2 <= root_cluster < cluster_count + 2,
            "fat_entry_capacity_sufficient": fat_entry_capacity >= cluster_count + 2,
        }
        declared_volume_bytes = volume_sectors * bytes_per_sector
        return {
            "available": len(boot_sector) == 512,
            "valid": all(checks.values()),
            "failed_checks": [name for name, valid in checks.items() if not valid],
            "checks": checks,
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "volume_sectors": volume_sectors,
            "fat_offset_sectors": fat_offset,
            "fat_length_sectors": fat_length,
            "fat_count": fat_count,
            "fat_entry_capacity": fat_entry_capacity,
            "cluster_heap_offset_sectors": cluster_heap_offset,
            "cluster_count": cluster_count,
            "root_cluster": root_cluster,
            "filesystem_revision": f"{revision >> 8}.{revision & 0xFF}",
            "declared_volume_bytes": declared_volume_bytes,
            "declared_volume_within_partition": declared_volume_bytes <= partition_bytes,
        }

    @staticmethod
    def _gpt_partitions(path: Path, image_size: int, header: bytes) -> tuple[dict[str, object], list[dict[str, object]]]:
        if len(header) < 92 or header[:8] != b"EFI PART":
            return {"valid": False}, []
        header_size = int.from_bytes(header[12:16], "little")
        entry_lba = int.from_bytes(header[72:80], "little")
        entry_count = int.from_bytes(header[80:84], "little")
        entry_size = int.from_bytes(header[84:88], "little")
        entry_crc_stored = int.from_bytes(header[88:92], "little")
        image_sectors = image_size // 512
        current_lba = int.from_bytes(header[24:32], "little")
        backup_lba = int.from_bytes(header[32:40], "little")
        first_usable_lba = int.from_bytes(header[40:48], "little")
        last_usable_lba = int.from_bytes(header[48:56], "little")
        valid = (
            92 <= header_size <= 512 and entry_lba >= 2 and entry_lba < image_sectors
            and 128 <= entry_size <= 4096 and entry_size % 8 == 0 and entry_count > 0
            and current_lba < image_sectors and backup_lba < image_sectors
            and first_usable_lba <= last_usable_lba < image_sectors
        )
        header_crc_stored = int.from_bytes(header[16:20], "little")
        header_crc_valid: bool | None = None
        if valid:
            crc_input = bytearray(header[:header_size])
            crc_input[16:20] = b"\x00\x00\x00\x00"
            header_crc_valid = (zlib.crc32(crc_input) & 0xFFFFFFFF) == header_crc_stored
        revision = int.from_bytes(header[8:12], "little")
        details: dict[str, object] = {
            "valid": valid,
            "header_offset": 512,
            "revision": f"{revision >> 16}.{revision & 0xffff}",
            "header_size": header_size,
            "header_crc32": f"0x{header_crc_stored:08x}",
            "header_crc_valid": header_crc_valid,
            "current_lba": current_lba,
            "backup_lba": backup_lba,
            "first_usable_lba": first_usable_lba,
            "last_usable_lba": last_usable_lba,
            "disk_guid": str(uuid.UUID(bytes_le=header[56:72])),
            "partition_entry_lba": entry_lba,
            "partition_entry_offset": entry_lba * 512,
            "partition_entry_count": entry_count,
            "partition_entry_size": entry_size,
            "partition_entry_crc32": f"0x{entry_crc_stored:08x}",
        }
        if not valid:
            return details, []
        entry_bytes = entry_count * entry_size
        primary_entry_table: bytes | None = None
        if entry_bytes <= 64 * _MIB and entry_lba * 512 + entry_bytes <= image_size:
            try:
                with path.open("rb") as stream:
                    stream.seek(entry_lba * 512)
                    entry_table = stream.read(entry_bytes)
                primary_entry_table = entry_table if len(entry_table) == entry_bytes else None
                details["partition_entry_crc_valid"] = len(entry_table) == entry_bytes and (zlib.crc32(entry_table) & 0xFFFFFFFF) == entry_crc_stored
            except OSError:
                details["partition_entry_crc_valid"] = None
        else:
            details["partition_entry_crc_valid"] = None
        details["backup"] = GenericTriageEngine._gpt_backup_validation(
            path, image_size, details, primary_entry_table,
        )
        # Only the first 256 entries are required for triage; the bound also
        # prevents a forged GPT header from causing a giant allocation/read.
        read_count = min(entry_count, 256)
        maximum = min(read_count * entry_size, 2 * _MIB)
        try:
            with path.open("rb") as stream:
                stream.seek(entry_lba * 512)
                raw_entries = stream.read(maximum)
        except OSError:
            return details, []
        partitions: list[dict[str, object]] = []
        for index in range(read_count):
            entry = raw_entries[index * entry_size:(index + 1) * entry_size]
            if len(entry) < 128 or entry[:16] == b"\x00" * 16:
                continue
            first_lba = int.from_bytes(entry[32:40], "little")
            last_lba = int.from_bytes(entry[40:48], "little")
            name = entry[56:128].decode("utf-16le", errors="replace").split("\x00", 1)[0]
            within_usable_range = (
                first_usable_lba <= first_lba <= last_lba <= last_usable_lba
            )
            partitions.append({
                "index": index + 1,
                "entry_offset": entry_lba * 512 + index * entry_size,
                "entry_valid": within_usable_range,
                "type_guid": str(uuid.UUID(bytes_le=entry[:16])),
                "unique_guid": str(uuid.UUID(bytes_le=entry[16:32])),
                "first_lba": first_lba,
                "last_lba": last_lba,
                "sector_count": last_lba - first_lba + 1 if last_lba >= first_lba else 0,
                "name": name[:512],
                "within_usable_range": within_usable_range,
                "within_image": first_lba <= last_lba < image_sectors,
            })
        return details, partitions

    @staticmethod
    def _gpt_backup_validation(
        path: Path,
        image_size: int,
        primary: dict[str, object],
        primary_entry_table: bytes | None,
    ) -> dict[str, object]:
        """Validate the declared backup GPT header/table without choosing a preferred copy."""
        backup_lba = int(primary.get("backup_lba", 0))
        backup_offset = backup_lba * 512
        result: dict[str, object] = {
            "expected_header_lba": backup_lba,
            "header_offset": backup_offset,
            "available": False,
            "signature_valid": False,
            "layout_valid": False,
            "header_crc_valid": None,
            "partition_entry_crc_valid": None,
            "reciprocal_locations_match": None,
            "shared_geometry_matches": None,
            "partition_entry_crc_matches_primary": None,
            "partition_entry_table_matches_primary": None,
            "first_partition_entry_difference": None,
            "valid": False,
        }
        if backup_offset < 0 or backup_offset + 512 > image_size:
            result["error"] = "declared backup GPT header is outside supplied image bounds"
            return result
        try:
            with path.open("rb") as stream:
                stream.seek(backup_offset)
                header = stream.read(512)
        except OSError as exc:
            result["error"] = str(exc)[:2_000]
            return result
        if len(header) != 512:
            result["error"] = "backup GPT header could not be read completely"
            return result
        result["available"] = True
        result["signature_valid"] = header[:8] == b"EFI PART"
        header_size = int.from_bytes(header[12:16], "little")
        current_lba = int.from_bytes(header[24:32], "little")
        reciprocal_lba = int.from_bytes(header[32:40], "little")
        first_usable_lba = int.from_bytes(header[40:48], "little")
        last_usable_lba = int.from_bytes(header[48:56], "little")
        disk_guid = str(uuid.UUID(bytes_le=header[56:72]))
        entry_lba = int.from_bytes(header[72:80], "little")
        entry_count = int.from_bytes(header[80:84], "little")
        entry_size = int.from_bytes(header[84:88], "little")
        entry_crc_stored = int.from_bytes(header[88:92], "little")
        entry_bytes = entry_count * entry_size
        layout_valid = (
            result["signature_valid"] is True
            and 92 <= header_size <= 512
            and current_lba < image_size // 512
            and reciprocal_lba < image_size // 512
            and first_usable_lba <= last_usable_lba < image_size // 512
            and entry_lba < image_size // 512
            and 0 < entry_count
            and 128 <= entry_size <= 4096
            and entry_size % 8 == 0
            and entry_bytes <= 64 * _MIB
            and entry_lba * 512 + entry_bytes <= image_size
        )
        result.update({
            "layout_valid": layout_valid,
            "header_size": header_size,
            "current_lba": current_lba,
            "backup_lba": reciprocal_lba,
            "first_usable_lba": first_usable_lba,
            "last_usable_lba": last_usable_lba,
            "disk_guid": disk_guid,
            "partition_entry_lba": entry_lba,
            "partition_entry_offset": entry_lba * 512,
            "partition_entry_count": entry_count,
            "partition_entry_size": entry_size,
            "partition_entry_crc32": f"0x{entry_crc_stored:08x}",
        })
        if not layout_valid:
            return result
        stored_header_crc = int.from_bytes(header[16:20], "little")
        header_crc_input = bytearray(header[:header_size])
        header_crc_input[16:20] = b"\x00" * 4
        header_crc_valid = (
            zlib.crc32(header_crc_input) & 0xFFFFFFFF
        ) == stored_header_crc
        result["header_crc32"] = f"0x{stored_header_crc:08x}"
        result["header_crc_valid"] = header_crc_valid
        result["reciprocal_locations_match"] = (
            current_lba == int(primary.get("backup_lba", -1))
            and reciprocal_lba == int(primary.get("current_lba", -1))
        )
        result["shared_geometry_matches"] = (
            first_usable_lba == int(primary.get("first_usable_lba", -1))
            and last_usable_lba == int(primary.get("last_usable_lba", -1))
            and disk_guid == primary.get("disk_guid")
            and entry_count == int(primary.get("partition_entry_count", -1))
            and entry_size == int(primary.get("partition_entry_size", -1))
        )
        result["partition_entry_crc_matches_primary"] = (
            f"0x{entry_crc_stored:08x}" == primary.get("partition_entry_crc32")
        )
        try:
            with path.open("rb") as stream:
                stream.seek(entry_lba * 512)
                backup_entry_table = stream.read(entry_bytes)
        except OSError as exc:
            result["error"] = str(exc)[:2_000]
            return result
        entry_crc_valid = (
            len(backup_entry_table) == entry_bytes
            and (zlib.crc32(backup_entry_table) & 0xFFFFFFFF) == entry_crc_stored
        )
        result["partition_entry_crc_valid"] = entry_crc_valid
        if primary_entry_table is not None and len(backup_entry_table) == len(primary_entry_table):
            difference = next(
                (
                    index for index, (primary_byte, backup_byte)
                    in enumerate(zip(primary_entry_table, backup_entry_table, strict=True))
                    if primary_byte != backup_byte
                ),
                None,
            )
            result["partition_entry_table_matches_primary"] = difference is None
            if difference is not None:
                result["first_partition_entry_difference"] = {
                    "relative_offset": difference,
                    "primary_absolute_offset": int(primary["partition_entry_offset"]) + difference,
                    "backup_absolute_offset": entry_lba * 512 + difference,
                    "primary_byte": f"0x{primary_entry_table[difference]:02X}",
                    "backup_byte": f"0x{backup_entry_table[difference]:02X}",
                }
        result["valid"] = all((
            header_crc_valid,
            entry_crc_valid,
            result["reciprocal_locations_match"],
            result["shared_geometry_matches"],
            result["partition_entry_crc_matches_primary"],
            result["partition_entry_table_matches_primary"] is not False,
        ))
        return result

    def _inspect_sqlite(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        try:
            with path.open("rb") as stream:
                header = stream.read(100)
        except OSError as exc:
            return [self._observation(artifact, "sqlite.header_error", str(exc), confidence=0.8)]
        if len(header) < 100 or not header.startswith(b"SQLite format 3\x00"):
            return [self._observation(artifact, "sqlite.header_valid", False)]
        page_size = int.from_bytes(header[16:18], "big")
        if page_size == 1:
            page_size = 65_536
        write_version = header[18]
        read_version = header[19]
        page_count = int.from_bytes(header[28:32], "big")
        freelist_trunk = int.from_bytes(header[32:36], "big")
        freelist_pages = int.from_bytes(header[36:40], "big")
        application_id = int.from_bytes(header[68:72], "big")
        observations = [
            self._observation(artifact, "sqlite.header_valid", page_size in {512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}),
            self._observation(artifact, "sqlite.page_size", page_size),
            self._observation(artifact, "sqlite.write_version", write_version),
            self._observation(artifact, "sqlite.read_version", read_version),
            self._observation(artifact, "sqlite.wal_mode", write_version == 2 or read_version == 2),
            self._observation(artifact, "sqlite.page_count", page_count),
            self._observation(artifact, "sqlite.freelist_trunk_page", freelist_trunk),
            self._observation(artifact, "sqlite.freelist_page_count", freelist_pages),
            self._observation(artifact, "sqlite.application_id", application_id),
            self._observation(artifact, "sqlite.size_matches_page_count", page_count == 0 or page_count * page_size <= size),
        ]
        # Python ships SQLite with the standard interpreter, giving the
        # offline engine a useful schema inventory even when the sqlite3 CLI
        # is unavailable.  URI read-only + immutable mode prevents journals,
        # locks, and any accidental evidence mutation.  We never execute SQL
        # recovered from the database; only fixed metadata queries are used.
        sample_rows: list[dict[str, object]] = []
        sample_errors: list[str] = []
        ios_manifest_detected = False
        ios_manifest_columns: list[str] = []
        ios_manifest_domain_counts: list[dict[str, object]] = []
        ios_manifest_file_samples: list[dict[str, object]] = []
        ios_manifest_file_references: list[dict[str, object]] = []
        ios_manifest_references_truncated = False
        ios_manifest_error: str | None = None
        try:
            database_uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
            connection = sqlite3.connect(database_uri, uri=True)
            try:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                rows = connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master "
                    "WHERE type IN ('table', 'index', 'trigger', 'view') "
                    "ORDER BY type, name LIMIT 500"
                ).fetchall()
                virtual_prefixes = {
                    str(row[1]).lower() + "_"
                    for row in rows
                    if row[0] == "table" and "VIRTUAL TABLE" in str(row[3] or "").upper()
                }
                tables_for_sample = [
                    str(row[1]) for row in rows
                    if (
                        row[0] == "table"
                        and not str(row[1]).startswith("sqlite_")
                        and "VIRTUAL TABLE" not in str(row[3] or "").upper()
                        and not any(str(row[1]).lower().startswith(prefix) for prefix in virtual_prefixes)
                    )
                ][:25]
                # iOS backups use a SQLite Manifest.db whose Files table
                # links opaque file IDs to domains and relative paths.  Do a
                # small fixed-column, read-only sample rather than decoding
                # its metadata BLOB or scanning the entire backup database.
                manifest_table = next((table for table in tables_for_sample if table.casefold() == "files"), None)
                if manifest_table is not None:
                    quoted_manifest = '"' + manifest_table.replace('"', '""') + '"'
                    try:
                        manifest_columns = connection.execute(f"PRAGMA table_info({quoted_manifest})").fetchall()
                        column_lookup = {str(item[1]).casefold(): str(item[1]) for item in manifest_columns}
                        required = {"fileid", "domain", "relativepath"}
                        ios_manifest_columns = [str(item[1])[:512] for item in manifest_columns[:64]]
                        if required <= set(column_lookup):
                            ios_manifest_detected = True
                            select_columns = [
                                column_lookup["fileid"], column_lookup["domain"], column_lookup["relativepath"],
                            ]
                            if "flags" in column_lookup:
                                select_columns.append(column_lookup["flags"])
                            quoted_columns = ", ".join(
                                '"' + column.replace('"', '""') + '"' for column in select_columns
                            )
                            manifest_rows = connection.execute(
                                f"SELECT {quoted_columns} FROM {quoted_manifest} LIMIT 1001"
                            ).fetchall()
                            domain_counts: dict[str, int] = {}
                            ios_manifest_references_truncated = len(manifest_rows) > 1000
                            for index, entry in enumerate(manifest_rows[:1000]):
                                values = {
                                    column: (str(value)[:2_000] if value is not None else None)
                                    for column, value in zip(select_columns, entry)
                                }
                                domain = values.get(column_lookup["domain"])
                                if isinstance(domain, str):
                                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
                                reference = {
                                    "file_id": values.get(column_lookup["fileid"]),
                                    "domain": domain,
                                    "relative_path": values.get(column_lookup["relativepath"]),
                                    "flags": values.get(column_lookup["flags"]) if "flags" in column_lookup else None,
                                }
                                ios_manifest_file_references.append(reference)
                                if index < 200:
                                    ios_manifest_file_samples.append(reference)
                            ios_manifest_domain_counts = [
                                {"domain": domain, "sample_count": count}
                                for domain, count in sorted(domain_counts.items(), key=lambda item: (-item[1], item[0]))[:100]
                            ]
                    except sqlite3.DatabaseError as exc:
                        ios_manifest_error = str(exc)[:1_000]
                for table in tables_for_sample:
                    quoted = '"' + table.replace('"', '""') + '"'
                    try:
                        column_rows = connection.execute(f"PRAGMA table_info({quoted})").fetchall()
                        columns = [str(column[1]) for column in column_rows[:32]]
                        if not columns:
                            continue
                        fetched = connection.execute(f"SELECT * FROM {quoted} LIMIT 20").fetchall()
                    except sqlite3.DatabaseError as exc:
                        sample_errors.append(f"{table}: {exc}"[:1_000])
                        continue
                    for row_index, row in enumerate(fetched):
                        values: dict[str, object] = {}
                        for column, value in zip(columns, row):
                            if isinstance(value, bytes):
                                values[column] = {"bytes": len(value), "preview_hex": value[:64].hex()}
                            elif value is None or isinstance(value, (int, float)):
                                values[column] = value
                            else:
                                values[column] = str(value)[:2_000]
                        sample_rows.append({"table": table, "row": row_index, "values": values})
                        if len(sample_rows) >= 250:
                            break
                    if len(sample_rows) >= 250:
                        break
            finally:
                connection.close()
        except (OSError, sqlite3.DatabaseError, ValueError) as exc:
            observations.append(
                self._observation(artifact, "sqlite.schema_read_error", str(exc)[:2_000], confidence=0.85)
            )
            return observations

        tables = [str(row[1]) for row in rows if row[0] == "table" and not str(row[1]).startswith("sqlite_")]
        virtual_tables = [
            str(row[1]) for row in rows
            if row[0] == "table" and "VIRTUAL TABLE" in str(row[3] or "").upper()
        ]
        views = [str(row[1]) for row in rows if row[0] == "view"]
        triggers = [str(row[1]) for row in rows if row[0] == "trigger"]
        indexes = [str(row[1]) for row in rows if row[0] == "index" and not str(row[1]).startswith("sqlite_autoindex")]
        suspicious = [
            name for name in tables
            if re.search(r"(?:flag|secret|password|credential|token|cookie|history|message|chat)", name, re.I)
        ]
        schema = [
            {
                "type": str(row[0]),
                "name": str(row[1])[:512],
                "table": str(row[2])[:512],
                "sql": (str(row[3])[:4_000] if row[3] is not None else None),
            }
            for row in rows
        ]
        observations.extend(
            (
                self._observation(artifact, "sqlite.schema_readable", True),
                self._observation(artifact, "sqlite.table_count", len(tables)),
                self._observation(artifact, "sqlite.tables", tables),
                self._observation(artifact, "sqlite.virtual_tables", virtual_tables),
                self._observation(artifact, "sqlite.view_count", len(views)),
                self._observation(artifact, "sqlite.views", views),
                self._observation(artifact, "sqlite.trigger_count", len(triggers)),
                self._observation(artifact, "sqlite.index_count", len(indexes)),
                self._observation(artifact, "sqlite.schema_entries", schema),
                self._observation(artifact, "sqlite.suspicious_table_names", suspicious, confidence=0.85),
                self._observation(artifact, "sqlite.sample_row_count", len(sample_rows)),
                self._observation(artifact, "sqlite.sample_rows", sample_rows, confidence=0.85),
                self._observation(artifact, "sqlite.sample_errors", sample_errors, confidence=0.8),
                self._observation(artifact, "mobile.ios_manifest_detected", ios_manifest_detected, confidence=0.95 if ios_manifest_detected else 1.0),
                self._observation(artifact, "mobile.ios_manifest_file_columns", ios_manifest_columns),
                self._observation(artifact, "mobile.ios_manifest_domain_counts", ios_manifest_domain_counts),
                self._observation(artifact, "mobile.ios_manifest_file_samples", ios_manifest_file_samples),
                self._observation(artifact, "mobile.ios_manifest_file_references", ios_manifest_file_references),
                self._observation(artifact, "mobile.ios_manifest_references_truncated", ios_manifest_references_truncated),
                self._observation(artifact, "mobile.ios_manifest_error", ios_manifest_error, confidence=0.8),
            )
        )
        return observations

    def _inspect_ooxml(self, artifact: Artifact, path: Path) -> list[Observation]:
        """Inventory high-value OOXML package parts without extracting them.

        OOXML is a ZIP container, but interpreting just names and bounded
        relationship XML gives the decision engine macro/external-link leads
        even when oletools is absent.  The method never follows a relationship
        or resolves anything outside the evidence package.
        """
        try:
            with zipfile.ZipFile(path) as package:
                infos = package.infolist()
                names = [item.filename for item in infos[:10_000]]
                lowered = {name.lower(): name for name in names}
                detected = "[content_types].xml" in lowered and any(
                    name.startswith(("word/", "xl/", "ppt/")) for name in lowered
                )
                if not detected:
                    return [self._observation(artifact, "office.ooxml.detected", False)]
                if any(name.startswith("word/") for name in lowered):
                    kind = "docx"
                elif any(name.startswith("xl/") for name in lowered):
                    kind = "xlsx"
                else:
                    kind = "pptx"
                vba_parts = [name for name in names if name.lower().endswith("vbaproject.bin")]
                embedded_parts = [
                    name for name in names
                    if re.search(r"(?:^|/)(?:embeddings|oleobjects?)/|oleobject\d+\.bin$", name, re.I)
                ][:500]
                encrypted_parts = [
                    name for name in names if name.lower() in {"encryptedpackage", "encryptioninfo"}
                ]
                external: list[str] = []
                remaining = 4 * _MIB
                for info in infos:
                    if not info.filename.lower().endswith(".rels") or info.file_size > _MIB or remaining <= 0:
                        continue
                    limit = min(info.file_size, remaining)
                    with package.open(info) as stream:
                        content = stream.read(limit + 1)
                    if len(content) > limit:
                        continue
                    remaining -= len(content)
                    for target in re.findall(rb"\bTarget\s*=\s*[\"']([^\"']+)[\"']", content):
                        # TargetMode is checked in a deliberately local
                        # window so ordinary internal targets are not labeled
                        # external merely because another relationship is.
                        position = content.find(target)
                        window = content[max(0, position - 300):position + len(target) + 300]
                        if re.search(rb"\bTargetMode\s*=\s*[\"']External[\"']", window, re.I):
                            external.append(target.decode("utf-8", errors="replace")[:2_000])
                            if len(external) >= 200:
                                break
                    if len(external) >= 200:
                        break
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            return [self._observation(artifact, "office.ooxml.read_error", str(exc)[:2_000], confidence=0.8)]
        return [
            self._observation(artifact, "office.ooxml.detected", True),
            self._observation(artifact, "office.ooxml.kind", kind),
            self._observation(artifact, "office.ooxml.part_count", len(names)),
            self._observation(artifact, "office.ooxml.has_vba", bool(vba_parts)),
            self._observation(artifact, "office.ooxml.vba_parts", vba_parts),
            self._observation(artifact, "office.ooxml.embedded_parts", embedded_parts),
            self._observation(artifact, "office.ooxml.encrypted_parts", encrypted_parts),
            self._observation(artifact, "office.ooxml.external_relationship_count", len(external)),
            self._observation(artifact, "office.ooxml.external_relationships", external),
        ]

    def _inspect_apk(self, artifact: Artifact, path: Path) -> list[Observation]:
        """Inspect a small, plaintext AndroidManifest.xml without decompiling APK code.

        Production APK manifests are usually Android binary XML, which is
        deliberately left to JADX/APKTool.  CTF APKs and unpacked/repacked
        samples sometimes carry ordinary XML, however; a bounded local read
        gives the planner useful permission and package leads while remaining
        independent of Java tooling.
        """
        maximum_manifest = _MIB
        try:
            with zipfile.ZipFile(path) as package:
                infos = package.infolist()[:10_000]
                lookup = {info.filename.replace("\\", "/").casefold(): info for info in infos}
                manifest = lookup.get("androidmanifest.xml")
                dex_names = [info.filename for info in infos if re.fullmatch(r"classes(?:\d+)?\.dex", Path(info.filename).name, re.I)]
                if manifest is None or not dex_names:
                    return [self._observation(artifact, "android.apk_detected", False)]
                native_libraries = [
                    info.filename for info in infos
                    if re.match(r"^lib/[^/]+/[^/]+\.so$", info.filename.replace("\\", "/"), re.I)
                ][:256]
                if manifest.file_size > maximum_manifest:
                    return [
                        self._observation(artifact, "android.apk_detected", True),
                        self._observation(artifact, "android.apk.manifest_format", "oversized"),
                        self._observation(artifact, "android.apk.manifest_error", "manifest exceeds 1 MiB triage cap", confidence=0.8),
                        self._observation(artifact, "android.apk.dex_count", len(dex_names)),
                        self._observation(artifact, "android.apk.native_libraries", native_libraries),
                    ]
                with package.open(manifest) as stream:
                    raw = stream.read(maximum_manifest + 1)
                if len(raw) > maximum_manifest:
                    return [
                        self._observation(artifact, "android.apk_detected", True),
                        self._observation(artifact, "android.apk.manifest_format", "oversized"),
                        self._observation(artifact, "android.apk.manifest_error", "manifest read exceeds 1 MiB triage cap", confidence=0.8),
                        self._observation(artifact, "android.apk.dex_count", len(dex_names)),
                        self._observation(artifact, "android.apk.native_libraries", native_libraries),
                    ]
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            return [self._observation(artifact, "android.apk_error", str(exc)[:2_000], confidence=0.8)]

        base_observations = [
            self._observation(artifact, "android.apk_detected", True),
            self._observation(artifact, "android.apk.dex_count", len(dex_names)),
            self._observation(artifact, "android.apk.native_libraries", native_libraries),
        ]
        # Android binary XML begins with a RES_XML_TYPE chunk.  It is not safe
        # or useful to guess strings from its pool in generic triage.
        if raw.startswith(b"\x03\x00\x08\x00"):
            return [*base_observations, self._observation(artifact, "android.apk.manifest_format", "binary")]
        if not re.match(rb"\s*(?:<\?xml\b[^>]*>\s*)?<manifest\b", raw, re.I):
            return [*base_observations, self._observation(artifact, "android.apk.manifest_format", "unknown")]

        text = raw.decode("utf-8", errors="replace")
        manifest_open = re.search(r"<manifest\b[^>]*>", text, re.I)
        attrs = manifest_open.group(0) if manifest_open else ""
        package_name = _xml_attribute(attrs, "package")
        version_name = _xml_attribute(attrs, "versionName")
        version_code = _xml_attribute(attrs, "versionCode")
        permissions = list(dict.fromkeys(
            value[:512] for value in re.findall(
                r"<uses-permission(?:-[^\s>/]+)?\b[^>]*\b(?:android:)?name\s*=\s*['\"]([^'\"]+)['\"]",
                text, re.I,
            )
        ))[:256]
        sdk_match = re.search(r"<uses-sdk\b[^>]*>", text, re.I)
        sdk_attrs = sdk_match.group(0) if sdk_match else ""
        sdk = {
            key: value for key, value in {
                "min_sdk": _xml_attribute(sdk_attrs, "minSdkVersion"),
                "target_sdk": _xml_attribute(sdk_attrs, "targetSdkVersion"),
            }.items() if value is not None
        }
        suspicious_markers = (
            "send_sms", "read_sms", "receive_sms", "request_install_packages",
            "system_alert_window", "bind_accessibility_service", "record_audio",
            "read_contacts", "write_settings", "manage_external_storage",
        )
        suspicious_permissions = [
            permission for permission in permissions
            if any(marker in permission.casefold() for marker in suspicious_markers)
        ]
        return [
            *base_observations,
            self._observation(artifact, "android.apk.manifest_format", "xml"),
            self._observation(artifact, "android.apk.package_name", package_name),
            self._observation(artifact, "android.apk.version_name", version_name),
            self._observation(artifact, "android.apk.version_code", version_code),
            self._observation(artifact, "android.apk.sdk", sdk),
            self._observation(artifact, "android.apk.permissions", permissions),
            self._observation(artifact, "android.apk.suspicious_permissions", suspicious_permissions, confidence=0.85),
        ]

    def _inspect_android_backup(self, artifact: Artifact, path: Path) -> list[Observation]:
        """Parse only the plaintext Android Backup header; payload remains opaque."""
        try:
            with path.open("rb") as stream:
                header = stream.read(1024)
        except OSError as exc:
            return [self._observation(artifact, "mobile.android_backup_error", str(exc), confidence=0.8)]
        lines = header.splitlines()[:4]
        if not lines or lines[0] != b"ANDROID BACKUP":
            return [self._observation(artifact, "mobile.android_backup_valid", False)]
        decoded = [line.decode("ascii", errors="replace")[:128] for line in lines]
        version = decoded[1] if len(decoded) > 1 else None
        compressed = decoded[2] == "1" if len(decoded) > 2 else None
        encryption = decoded[3] if len(decoded) > 3 else None
        return [
            self._observation(artifact, "mobile.android_backup_valid", bool(version and compressed is not None and encryption is not None)),
            self._observation(artifact, "mobile.android_backup_version", version),
            self._observation(artifact, "mobile.android_backup_compressed", compressed),
            self._observation(artifact, "mobile.android_backup_encryption", encryption),
        ]

    def _inspect_plist(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Inventory an Apple XML/binary property list with a strict size cap."""
        maximum = 4 * _MIB
        if size > maximum:
            return [
                self._observation(artifact, "plist.parsed", False, confidence=0.8),
                self._observation(artifact, "plist.parse_error", f"plist exceeds {maximum} byte triage cap", confidence=0.8),
                self._observation(artifact, "mobile.ios_backup_info_plist", False),
            ]
        try:
            with path.open("rb") as stream:
                document = plistlib.loads(stream.read(maximum))
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            return [
                self._observation(artifact, "plist.parsed", False, confidence=0.8),
                self._observation(artifact, "plist.parse_error", str(exc)[:2_000], confidence=0.8),
                self._observation(artifact, "mobile.ios_backup_info_plist", False),
            ]
        keys: list[str] = []
        scalar_values: dict[str, object] = {}
        if isinstance(document, dict):
            keys = [str(key)[:512] for key in list(document)[:512]]
            interesting = {
                "Device Name", "Display Name", "Product Version", "Product Type",
                "Unique Identifier", "Target Identifier", "Last Backup Date", "iTunes Version",
                "Build Version", "ICCID", "Phone Number",
            }
            for key, value in document.items():
                key_text = str(key)
                if key_text in interesting and isinstance(value, (str, int, float, bool, datetime)):
                    scalar_values[key_text] = value.isoformat() if isinstance(value, datetime) else value
        normalized_keys = {key.casefold() for key in keys}
        logical_name = Path(artifact.logical_name).name.casefold()
        ios_backup_info = (
            logical_name == "info.plist"
            and "product version" in normalized_keys
            and ("unique identifier" in normalized_keys or "target identifier" in normalized_keys)
        )
        return [
            self._observation(artifact, "plist.parsed", True),
            self._observation(artifact, "plist.root_type", type(document).__name__),
            self._observation(artifact, "plist.top_level_keys", keys),
            self._observation(artifact, "plist.scalar_metadata", scalar_values),
            self._observation(artifact, "mobile.ios_backup_info_plist", ios_backup_info, confidence=0.95 if ios_backup_info else 1.0),
        ]

    def _inspect_firmware(
        self, artifact: Artifact, path: Path, header: bytes, size: int, format_name: str
    ) -> list[Observation]:
        if format_name == "squashfs":
            if len(header) < 96:
                return [self._observation(artifact, "firmware.squashfs_valid", False)]
            return [
                self._observation(artifact, "firmware.squashfs_valid", header[:4] == b"hsqs"),
                self._observation(artifact, "firmware.squashfs.inode_count", int.from_bytes(header[4:8], "little")),
                self._observation(artifact, "firmware.squashfs.block_size", int.from_bytes(header[12:16], "little")),
                self._observation(artifact, "firmware.squashfs.compression", int.from_bytes(header[20:22], "little")),
                self._observation(artifact, "firmware.squashfs.version", f"{int.from_bytes(header[30:32], 'little')}.{int.from_bytes(header[28:30], 'little')}"),
                self._observation(artifact, "firmware.squashfs.bytes_used", int.from_bytes(header[40:48], "little")),
            ]
        if format_name == "uimage":
            if len(header) < 64:
                return [self._observation(artifact, "firmware.uimage_valid", False)]
            image_size = int.from_bytes(header[12:16], "big")
            name = header[32:64].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            header_crc_stored = int.from_bytes(header[4:8], "big")
            header_crc_input = bytearray(header[:64])
            header_crc_input[4:8] = b"\x00" * 4
            header_crc_valid = (zlib.crc32(header_crc_input) & 0xFFFFFFFF) == header_crc_stored
            payload_crc_stored = int.from_bytes(header[24:28], "big")
            payload_crc_valid: bool | None = None
            if image_size <= 32 * _MIB and image_size <= max(0, size - 64):
                try:
                    with path.open("rb") as stream:
                        stream.seek(64)
                        payload = stream.read(image_size)
                    payload_crc_valid = len(payload) == image_size and (zlib.crc32(payload) & 0xFFFFFFFF) == payload_crc_stored
                except OSError:
                    payload_crc_valid = None
            return [
                self._observation(artifact, "firmware.uimage_valid", image_size <= max(0, size - 64) and header_crc_valid),
                self._observation(artifact, "firmware.uimage.timestamp", int.from_bytes(header[8:12], "big")),
                self._observation(artifact, "firmware.uimage.payload_size", image_size),
                self._observation(artifact, "firmware.uimage.load_address", f"0x{int.from_bytes(header[16:20], 'big'):08x}"),
                self._observation(artifact, "firmware.uimage.entry_address", f"0x{int.from_bytes(header[20:24], 'big'):08x}"),
                self._observation(artifact, "firmware.uimage.name", name),
                self._observation(artifact, "firmware.uimage.os", header[28]),
                self._observation(artifact, "firmware.uimage.architecture", header[29]),
                self._observation(artifact, "firmware.uimage.type", header[30]),
                self._observation(artifact, "firmware.uimage.compression", header[31]),
                self._observation(artifact, "firmware.uimage.header_crc32", f"0x{header_crc_stored:08x}"),
                self._observation(artifact, "firmware.uimage.header_crc_valid", header_crc_valid),
                self._observation(artifact, "firmware.uimage.payload_crc32", f"0x{payload_crc_stored:08x}"),
                self._observation(artifact, "firmware.uimage.payload_crc_valid", payload_crc_valid),
            ]
        # Android boot image v0-v2 shares this leading structure; later
        # versions still retain the magic and are routed to binwalk safely.
        kernel_size = int.from_bytes(header[8:12], "little") if len(header) >= 12 else 0
        ramdisk_size = int.from_bytes(header[16:20], "little") if len(header) >= 20 else 0
        page_size = int.from_bytes(header[36:40], "little") if len(header) >= 40 else 0
        legacy_geometry_valid: bool | None = None
        if page_size in {2048, 4096, 8192, 16384, 32768, 65536}:
            kernel_offset = page_size
            ramdisk_offset = kernel_offset + ((kernel_size + page_size - 1) // page_size) * page_size
            legacy_geometry_valid = kernel_offset + kernel_size <= size and ramdisk_offset + ramdisk_size <= size
        return [
            self._observation(artifact, "firmware.android_boot_valid", header.startswith(b"ANDROID!") and legacy_geometry_valid is not False),
            self._observation(artifact, "firmware.android_boot.kernel_size", kernel_size),
            self._observation(artifact, "firmware.android_boot.ramdisk_size", ramdisk_size),
            self._observation(artifact, "firmware.android_boot.page_size", page_size),
            self._observation(artifact, "firmware.android_boot.legacy_geometry_valid", legacy_geometry_valid),
        ]

    @staticmethod
    def _detect_media_format(header: bytes) -> str | None:
        if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WAVE":
            return "wav"
        if header.startswith(b"fLaC"):
            return "flac"
        if header.startswith(b"OggS"):
            return "ogg"
        if header.startswith(b"ID3") or (len(header) >= 2 and header[:2] == b"\xff\xfb"):
            return "mp3"
        if len(header) >= 12 and header[4:8] == b"ftyp":
            return "isobmff"
        if header.startswith(b"\x1aE\xdf\xa3"):
            return "matroska"
        if header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"AVI ":
            return "avi"
        return None

    def _inspect_media(
        self, artifact: Artifact, path: Path, header: bytes, size: int, media_format: str
    ) -> list[Observation]:
        is_video = media_format in {"isobmff", "matroska", "avi"}
        observations = [
            self._observation(artifact, "media.format", media_format),
            self._observation(artifact, "media.kind", "video" if is_video else "audio"),
        ]
        if media_format == "wav" and len(header) >= 44:
            observations.extend((
                self._observation(artifact, "media.wav.declared_file_size", int.from_bytes(header[4:8], "little") + 8),
                self._observation(artifact, "media.wav.audio_format", int.from_bytes(header[20:22], "little")),
                self._observation(artifact, "media.wav.channels", int.from_bytes(header[22:24], "little")),
                self._observation(artifact, "media.wav.sample_rate", int.from_bytes(header[24:28], "little")),
                self._observation(artifact, "media.wav.bits_per_sample", int.from_bytes(header[34:36], "little")),
                self._observation(artifact, "media.wav.size_matches", int.from_bytes(header[4:8], "little") + 8 == size),
            ))
            observations.extend(self._inspect_wav_chunks(artifact, path, size))
        elif media_format == "mp3" and header.startswith(b"ID3") and len(header) >= 10:
            tag_size = ((header[6] & 0x7F) << 21) | ((header[7] & 0x7F) << 14) | ((header[8] & 0x7F) << 7) | (header[9] & 0x7F)
            observations.extend((
                self._observation(artifact, "media.id3.version", f"{header[3]}.{header[4]}"),
                self._observation(artifact, "media.id3.tag_size", tag_size),
                self._observation(artifact, "media.id3.unsynchronization", bool(header[5] & 0x80)),
            ))
            if not header[5] & 0x80 and tag_size <= 4 * _MIB:
                observations.extend(self._inspect_id3_frames(artifact, path, header[3], tag_size))
        elif media_format == "isobmff":
            brand = header[8:12].decode("latin-1", errors="replace")
            observations.append(self._observation(artifact, "media.isobmff.major_brand", brand))
            observations.extend(self._inspect_isobmff(artifact, path, size))
        elif media_format == "matroska":
            observations.extend(self._inspect_matroska(artifact, path, size))
        elif media_format == "avi":
            observations.extend(self._inspect_avi(artifact, path, size))
        return observations

    def _inspect_wav_chunks(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Inventory bounded RIFF/WAV chunks and plain LIST/INFO metadata."""
        maximum = min(size, 16 * _MIB)
        try:
            with path.open("rb") as stream:
                data = stream.read(maximum)
        except OSError as exc:
            return [self._observation(artifact, "media.wav.read_error", str(exc), confidence=0.8)]
        if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
            return [self._observation(artifact, "media.wav.structure_valid", False)]
        declared_total = int.from_bytes(data[4:8], "little") + 8
        malformed = declared_total < 12 or declared_total > size
        chunks: list[dict[str, object]] = []
        info_tags: dict[str, str] = {}
        offset = 12
        while offset + 8 <= min(declared_total, len(data)) and len(chunks) < 1_000:
            chunk_id = data[offset:offset + 4]
            declared = int.from_bytes(data[offset + 4:offset + 8], "little")
            payload_start = offset + 8
            payload_end = payload_start + declared
            padded_end = payload_end + (declared & 1)
            if payload_end > size or padded_end > declared_total:
                malformed = True
                break
            name = chunk_id.decode("latin-1", errors="replace")
            chunks.append({"id": name, "offset": offset, "size": declared, "fully_sampled": payload_end <= len(data)})
            if chunk_id == b"LIST" and declared >= 4 and data[payload_start:payload_start + 4] == b"INFO" and payload_end <= len(data):
                tag_offset = payload_start + 4
                while tag_offset + 8 <= payload_end and len(info_tags) < 100:
                    tag_id = data[tag_offset:tag_offset + 4]
                    tag_size = int.from_bytes(data[tag_offset + 4:tag_offset + 8], "little")
                    tag_start = tag_offset + 8
                    tag_end = tag_start + tag_size
                    if tag_end > payload_end or tag_size > 64 * 1024:
                        malformed = True
                        break
                    key = tag_id.decode("latin-1", errors="replace")
                    # RIFF INFO values are NUL-terminated ANSI in practice;
                    # preserve arbitrary bytes safely via replacement text.
                    info_tags[key] = data[tag_start:tag_end].rstrip(b"\x00").decode("cp1252", errors="replace")[:4_000]
                    tag_offset = tag_end + (tag_size & 1)
            if padded_end > len(data):
                break
            offset = padded_end
        return [
            self._observation(artifact, "media.wav.chunk_count", len(chunks)),
            self._observation(artifact, "media.wav.chunks", chunks),
            self._observation(artifact, "media.wav.info_tags", info_tags),
            self._observation(artifact, "media.wav.scan_bytes", len(data)),
            self._observation(artifact, "media.wav.scan_truncated", len(data) < size or len(chunks) >= 1_000),
            self._observation(artifact, "media.wav.structure_valid", not malformed),
        ]

    def _inspect_isobmff(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Inventory a bounded prefix of ISO-BMFF atoms and `mvhd` timing.

        Atom sizes are attacker-controlled, so the parser keeps a 16 MiB
        prefix, validates every 32/64-bit box length, and only descends into a
        `moov` box that is wholly present in that prefix.  This is enough to
        distinguish ordinary media layout from malformed/appended containers
        without becoming a codec parser.
        """
        maximum = min(size, 16 * _MIB)
        try:
            with path.open("rb") as stream:
                data = stream.read(maximum)
        except OSError as exc:
            return [self._observation(artifact, "media.isobmff.read_error", str(exc), confidence=0.8)]
        atoms: list[dict[str, object]] = []
        malformed = False
        offset = 0
        moov_payload: bytes | None = None
        while offset + 8 <= len(data) and len(atoms) < 2_000:
            declared = int.from_bytes(data[offset:offset + 4], "big")
            raw_type = data[offset + 4:offset + 8]
            header_size = 8
            if declared == 1:
                if offset + 16 > len(data):
                    malformed = True
                    break
                declared = int.from_bytes(data[offset + 8:offset + 16], "big")
                header_size = 16
            elif declared == 0:
                declared = size - offset
            if declared < header_size or offset + declared > size:
                malformed = True
                break
            try:
                name = raw_type.decode("ascii")
            except UnicodeDecodeError:
                name = raw_type.hex()
            available = min(declared, max(0, len(data) - offset))
            atoms.append({
                "type": name, "offset": offset, "size": declared,
                "fully_sampled": available == declared,
            })
            if raw_type == b"moov" and available == declared:
                moov_payload = data[offset + header_size:offset + declared]
            if declared > len(data) - offset:
                break
            offset += declared
        mvhd: dict[str, object] | None = self._isobmff_mvhd(moov_payload) if moov_payload is not None else None
        atom_types = [str(item["type"]) for item in atoms]
        return [
            self._observation(artifact, "media.isobmff.atom_count", len(atoms)),
            self._observation(artifact, "media.isobmff.atoms", atoms),
            self._observation(artifact, "media.isobmff.atom_types", atom_types),
            self._observation(artifact, "media.isobmff.scan_bytes", len(data)),
            self._observation(artifact, "media.isobmff.scan_truncated", len(data) < size or len(atoms) >= 2_000),
            self._observation(artifact, "media.isobmff.structure_valid", not malformed),
            self._observation(artifact, "media.isobmff.movie_header", mvhd),
        ]

    @staticmethod
    def _isobmff_mvhd(moov: bytes | None) -> dict[str, object] | None:
        if not moov:
            return None
        offset = 0
        while offset + 8 <= len(moov):
            declared = int.from_bytes(moov[offset:offset + 4], "big")
            raw_type = moov[offset + 4:offset + 8]
            header_size = 8
            if declared == 1:
                if offset + 16 > len(moov):
                    return None
                declared = int.from_bytes(moov[offset + 8:offset + 16], "big")
                header_size = 16
            elif declared == 0:
                declared = len(moov) - offset
            if declared < header_size or offset + declared > len(moov):
                return None
            if raw_type == b"mvhd":
                body = moov[offset + header_size:offset + declared]
                if len(body) < 20:
                    return None
                version = body[0]
                if version == 0 and len(body) >= 20:
                    timescale = int.from_bytes(body[12:16], "big")
                    duration = int.from_bytes(body[16:20], "big")
                elif version == 1 and len(body) >= 32:
                    timescale = int.from_bytes(body[20:24], "big")
                    duration = int.from_bytes(body[24:32], "big")
                else:
                    return {"version": version, "valid": False}
                return {
                    "version": version,
                    "valid": timescale > 0,
                    "timescale": timescale,
                    "duration_units": duration,
                    "duration_seconds": (duration / timescale) if timescale else None,
                }
            offset += declared
        return None

    def _inspect_matroska(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Parse a small, non-codec subset of EBML/Matroska container data.

        EBML sizes are variable length and fully attacker-controlled.  The
        parser therefore reads at most 16 MiB, never follows offsets, limits
        the top-level Segment children, and treats an element extending past
        the supplied evidence as malformed rather than trying to recover it.
        Unknown-length Segments are valid EBML and are represented as a
        bounded prefix scan instead of an error.
        """
        maximum = min(size, 16 * _MIB)
        try:
            with path.open("rb") as stream:
                data = stream.read(maximum)
        except OSError as exc:
            return [self._observation(artifact, "media.matroska.read_error", str(exc), confidence=0.8)]

        def vint(offset: int, *, identifier: bool = False) -> tuple[int, int] | None:
            if offset >= len(data):
                return None
            first = data[offset]
            mask = 0x80
            width = 1
            while width <= 8 and not first & mask:
                mask >>= 1
                width += 1
            if width > 8 or offset + width > len(data):
                return None
            raw = data[offset:offset + width]
            if identifier:
                return int.from_bytes(raw, "big"), width
            value = first & (mask - 1)
            for byte in raw[1:]:
                value = (value << 8) | byte
            return value, width

        names = {
            0x1A45DFA3: "ebml", 0x18538067: "segment", 0x1549A966: "info",
            0x1654AE6B: "tracks", 0x1C53BB6B: "cues", 0x1941A469: "attachments",
            0x1043A770: "chapters", 0x1254C367: "tags", 0x1F43B675: "cluster",
        }
        info_names = {0x2AD7B1: "timecode_scale", 0x4489: "duration", 0x7BA9: "title", 0x4D80: "muxing_app", 0x5741: "writing_app"}
        offset = 0
        elements: list[dict[str, object]] = []
        info: dict[str, object] = {}
        malformed = False
        scan_truncated = len(data) < size
        segment_found = False
        while offset < len(data) and len(elements) < 512:
            item_id = vint(offset, identifier=True)
            if item_id is None:
                malformed = True
                break
            element_id, id_width = item_id
            item_size = vint(offset + id_width)
            if item_size is None:
                malformed = True
                break
            declared_size, size_width = item_size
            header_size = id_width + size_width
            unknown_size = declared_size == (1 << (7 * size_width)) - 1
            payload_start = offset + header_size
            available_size = len(data) - payload_start
            if unknown_size:
                # Only Segment is expected to use unknown length in ordinary
                # Matroska.  Its bounded prefix is still useful for inventory.
                element_end = len(data)
            else:
                element_end = payload_start + declared_size
                if element_end > size:
                    malformed = True
                    break
            name = names.get(element_id, f"0x{element_id:x}")
            elements.append({
                "id": f"0x{element_id:x}", "type": name, "offset": offset,
                "size": None if unknown_size else declared_size,
                "fully_sampled": unknown_size or element_end <= len(data),
            })
            if element_id == 0x18538067:
                segment_found = True
                child_end = min(element_end, len(data))
                child_offset = payload_start
                child_count = 0
                while child_offset < child_end and child_count < 512:
                    child_id = vint(child_offset, identifier=True)
                    if child_id is None:
                        malformed = True
                        break
                    nested_id, nested_id_width = child_id
                    child_size = vint(child_offset + nested_id_width)
                    if child_size is None:
                        malformed = True
                        break
                    nested_size, nested_size_width = child_size
                    nested_header = nested_id_width + nested_size_width
                    nested_start = child_offset + nested_header
                    nested_unknown = nested_size == (1 << (7 * nested_size_width)) - 1
                    nested_end = child_end if nested_unknown else nested_start + nested_size
                    if nested_end > size or (not nested_unknown and nested_end > child_end):
                        malformed = True
                        break
                    if nested_id == 0x1549A966 and nested_end <= len(data):
                        info_offset = nested_start
                        while info_offset < nested_end and len(info) < 16:
                            info_id = vint(info_offset, identifier=True)
                            if info_id is None:
                                malformed = True
                                break
                            value_id, value_id_width = info_id
                            value_size_item = vint(info_offset + value_id_width)
                            if value_size_item is None:
                                malformed = True
                                break
                            value_size, value_size_width = value_size_item
                            value_start = info_offset + value_id_width + value_size_width
                            value_end = value_start + value_size
                            if value_size == (1 << (7 * value_size_width)) - 1 or value_end > nested_end:
                                malformed = True
                                break
                            key = info_names.get(value_id)
                            if key:
                                payload = data[value_start:value_end]
                                if key == "duration" and len(payload) in {4, 8}:
                                    try:
                                        info[key] = struct.unpack(">f" if len(payload) == 4 else ">d", payload)[0]
                                    except struct.error:
                                        pass
                                elif key == "timecode_scale" and 0 < len(payload) <= 8:
                                    info[key] = int.from_bytes(payload, "big")
                                elif key in {"title", "muxing_app", "writing_app"}:
                                    info[key] = payload.decode("utf-8", errors="replace")[:2_000]
                            info_offset = value_end
                    child_count += 1
                    if nested_unknown or nested_end > len(data):
                        scan_truncated = scan_truncated or nested_end > len(data)
                        break
                    child_offset = nested_end
                break  # Segment spans the remainder in ordinary Matroska.
            if unknown_size or element_end > len(data):
                scan_truncated = True
                break
            offset = element_end
        duration = info.get("duration")
        scale = info.get("timecode_scale", 1_000_000)
        if isinstance(duration, (float, int)) and isinstance(scale, int) and scale > 0:
            info["duration_seconds"] = float(duration) * scale / 1_000_000_000
        return [
            self._observation(artifact, "media.matroska.segment_found", segment_found),
            self._observation(artifact, "media.matroska.elements", elements),
            self._observation(artifact, "media.matroska.info", info),
            self._observation(artifact, "media.matroska.scan_bytes", len(data)),
            self._observation(artifact, "media.matroska.scan_truncated", scan_truncated or len(elements) >= 512),
            self._observation(artifact, "media.matroska.structure_valid", segment_found and not malformed),
        ]

    def _inspect_avi(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Inventory RIFF/AVI chunks and the fixed AVIMAINHEADER safely."""
        maximum = min(size, 16 * _MIB)
        try:
            with path.open("rb") as stream:
                data = stream.read(maximum)
        except OSError as exc:
            return [self._observation(artifact, "media.avi.read_error", str(exc), confidence=0.8)]
        if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"AVI ":
            return [self._observation(artifact, "media.avi.structure_valid", False)]
        declared_total = int.from_bytes(data[4:8], "little") + 8
        malformed = declared_total < 12 or declared_total > size
        chunks: list[dict[str, object]] = []
        streams: list[dict[str, object]] = []
        avih: dict[str, object] | None = None

        def walk(start: int, end: int, depth: int = 0) -> None:
            nonlocal malformed, avih
            offset = start
            while offset + 8 <= end and len(chunks) < 1_000:
                chunk_id = data[offset:offset + 4]
                declared = int.from_bytes(data[offset + 4:offset + 8], "little")
                payload_start = offset + 8
                payload_end = payload_start + declared
                padded_end = payload_end + (declared & 1)
                if payload_end > size or padded_end > end:
                    malformed = True
                    return
                name = chunk_id.decode("latin-1", errors="replace")
                chunks.append({"id": name, "offset": offset, "size": declared, "fully_sampled": payload_end <= len(data)})
                if chunk_id == b"avih" and declared >= 40 and payload_end <= len(data):
                    payload = data[payload_start:payload_end]
                    avih = {
                        "microseconds_per_frame": int.from_bytes(payload[0:4], "little"),
                        "max_bytes_per_second": int.from_bytes(payload[4:8], "little"),
                        "flags": f"0x{int.from_bytes(payload[12:16], 'little'):08x}",
                        "total_frames": int.from_bytes(payload[16:20], "little"),
                        "stream_count": int.from_bytes(payload[24:28], "little"),
                        "width": int.from_bytes(payload[32:36], "little"),
                        "height": int.from_bytes(payload[36:40], "little"),
                    }
                elif chunk_id == b"strh" and declared >= 48 and payload_end <= len(data) and len(streams) < 128:
                    payload = data[payload_start:payload_end]
                    scale = int.from_bytes(payload[20:24], "little")
                    rate = int.from_bytes(payload[24:28], "little")
                    streams.append({
                        "type": payload[:4].decode("latin-1", errors="replace"),
                        "handler": payload[4:8].decode("latin-1", errors="replace"),
                        "scale": scale, "rate": rate,
                        "length": int.from_bytes(payload[32:36], "little"),
                        "duration_seconds": (int.from_bytes(payload[32:36], "little") * scale / rate) if rate else None,
                    })
                elif chunk_id == b"LIST" and declared >= 4 and depth < 3 and payload_start + 4 <= len(data):
                    # RIFF lists have a four-byte type then ordinary chunks.
                    walk(payload_start + 4, payload_end, depth + 1)
                offset = padded_end

        walk(12, min(declared_total, len(data)))
        return [
            self._observation(artifact, "media.avi.declared_file_size", declared_total),
            self._observation(artifact, "media.avi.size_matches", declared_total == size),
            self._observation(artifact, "media.avi.chunks", chunks),
            self._observation(artifact, "media.avi.main_header", avih),
            self._observation(artifact, "media.avi.streams", streams),
            self._observation(artifact, "media.avi.scan_bytes", len(data)),
            self._observation(artifact, "media.avi.scan_truncated", len(data) < size or len(chunks) >= 1_000),
            self._observation(artifact, "media.avi.structure_valid", not malformed),
        ]

    def _inspect_id3_frames(self, artifact: Artifact, path: Path, major_version: int, tag_size: int) -> list[Observation]:
        try:
            with path.open("rb") as stream:
                stream.seek(10)
                payload = stream.read(tag_size)
        except OSError as exc:
            return [self._observation(artifact, "media.id3.frame_error", str(exc), confidence=0.8)]
        if major_version not in {3, 4}:
            return [self._observation(artifact, "media.id3.text_frames", [])]
        offset = 0
        frames: list[dict[str, str]] = []
        while offset + 10 <= len(payload) and len(frames) < 200:
            frame_id = payload[offset:offset + 4]
            if frame_id == b"\x00" * 4:
                break
            if not re.fullmatch(rb"[A-Z0-9]{4}", frame_id):
                break
            raw_size = payload[offset + 4:offset + 8]
            frame_size = (
                ((raw_size[0] & 0x7F) << 21) | ((raw_size[1] & 0x7F) << 14) | ((raw_size[2] & 0x7F) << 7) | (raw_size[3] & 0x7F)
                if major_version == 4 else int.from_bytes(raw_size, "big")
            )
            offset += 10
            if frame_size < 0 or offset + frame_size > len(payload):
                break
            frame = payload[offset:offset + frame_size]
            offset += frame_size
            identifier = frame_id.decode("ascii")
            if identifier.startswith("T") and frame:
                encoding = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(frame[0])
                if encoding:
                    text = frame[1:].decode(encoding, errors="replace").split("\x00", 1)[0].strip()
                    if text:
                        frames.append({"id": identifier, "text": text[:2_000]})
            elif identifier == "COMM" and len(frame) >= 4:
                encoding = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(frame[0])
                if encoding:
                    text = frame[4:].decode(encoding, errors="replace").replace("\x00", " ").strip()
                    if text:
                        frames.append({"id": identifier, "text": text[:2_000]})
        return [
            self._observation(artifact, "media.id3.text_frame_count", len(frames)),
            self._observation(artifact, "media.id3.text_frames", frames),
        ]

    def _inspect_ole(self, artifact: Artifact, path: Path, header: bytes, size: int) -> list[Observation]:
        """Record Compound File Binary Format header geometry without parsing streams."""
        valid = (
            len(header) >= 76 and header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
            and header[28:30] == b"\xfe\xff"
        )
        if not valid:
            return [self._observation(artifact, "office.ole.header_valid", False)]
        sector_shift = int.from_bytes(header[30:32], "little")
        mini_sector_shift = int.from_bytes(header[32:34], "little")
        observations = [
            self._observation(artifact, "office.ole.header_valid", sector_shift in {9, 12} and mini_sector_shift == 6),
            self._observation(artifact, "office.ole.major_version", int.from_bytes(header[26:28], "little")),
            self._observation(artifact, "office.ole.sector_size", 1 << sector_shift if sector_shift < 31 else None),
            self._observation(artifact, "office.ole.mini_sector_size", 1 << mini_sector_shift if mini_sector_shift < 31 else None),
            self._observation(artifact, "office.ole.fat_sector_count", int.from_bytes(header[44:48], "little")),
            self._observation(artifact, "office.ole.first_directory_sector", int.from_bytes(header[48:52], "little")),
            self._observation(artifact, "office.ole.mini_stream_cutoff", int.from_bytes(header[56:60], "little")),
            self._observation(artifact, "office.ole.first_minifat_sector", int.from_bytes(header[60:64], "little")),
            self._observation(artifact, "office.ole.minifat_sector_count", int.from_bytes(header[64:68], "little")),
        ]
        sector_size = 1 << sector_shift if sector_shift < 31 else 0
        directory_sector = int.from_bytes(header[48:52], "little")
        directory_offset = (directory_sector + 1) * sector_size
        if sector_size not in {512, 4096} or directory_sector >= 0xFFFFFFFA or directory_offset >= size:
            observations.append(self._observation(artifact, "office.ole.directory_entries", []))
            return observations
        try:
            with path.open("rb") as stream:
                stream.seek(directory_offset)
                directory = stream.read(min(sector_size, 16 * 1024))
        except OSError as exc:
            observations.append(self._observation(artifact, "office.ole.directory_error", str(exc), confidence=0.8))
            return observations
        type_names = {1: "storage", 2: "stream", 5: "root"}
        entries: list[dict[str, object]] = []
        for index in range(min(128, len(directory) // 128)):
            item = directory[index * 128:(index + 1) * 128]
            object_type = item[66]
            if object_type not in type_names:
                continue
            name_length = int.from_bytes(item[64:66], "little")
            if name_length < 2 or name_length > 64 or name_length % 2:
                name = ""
            else:
                name = item[:name_length - 2].decode("utf-16le", errors="replace")
            entries.append({
                "id": index,
                "name": name[:512],
                "type": type_names[object_type],
                "left": int.from_bytes(item[68:72], "little"),
                "right": int.from_bytes(item[72:76], "little"),
                "child": int.from_bytes(item[76:80], "little"),
                "start_sector": int.from_bytes(item[116:120], "little"),
                "size": int.from_bytes(item[120:128], "little"),
            })
        names = [str(entry["name"]) for entry in entries if entry["name"]]
        macro_names = [name for name in names if re.search(r"(?:^|_)(?:vba|project|dir|_vba_project)(?:$|_)", name, re.I) or name.lower() in {"vba", "project", "dir"}]
        observations.extend((
            self._observation(artifact, "office.ole.directory_entries", entries),
            self._observation(artifact, "office.ole.directory_entry_count", len(entries)),
            self._observation(artifact, "office.ole.stream_names", names),
            self._observation(artifact, "office.ole.macro_stream_names", macro_names),
        ))
        return observations

    def _inspect_filesystem_signatures(
        self, artifact: Artifact, path: Path, header: bytes, size: int
    ) -> list[Observation]:
        boot_sector = header
        if size >= 512 and len(boot_sector) < 512:
            try:
                with path.open("rb") as stream:
                    boot_sector = stream.read(512)
            except OSError:
                pass
        ntfs = len(header) >= 11 and header[3:11] == b"NTFS    "
        exfat = len(header) >= 11 and header[3:11] == b"EXFAT   "
        fat_label_records = self._fat_type_label_records(boot_sector)
        explicit_label_bits = {
            int(item["explicit_fat_bits"])
            for item in fat_label_records
            if isinstance(item.get("explicit_fat_bits"), int)
        }
        fat_label_bits = next(iter(explicit_label_bits)) if len(explicit_label_bits) == 1 else 0
        bpb_fat_bits = self._fat_bpb_cluster_count_variant(boot_sector)
        bpb_validation = (
            self._fat_bpb_validation(boot_sector, size, bpb_fat_bits)
            if bpb_fat_bits else None
        )
        bpb_fat_recognized = bool(
            bpb_validation
            and bpb_validation.get("available") is True
            and bpb_validation.get("valid") is True
        )
        fat = bool(fat_label_records) or bpb_fat_recognized
        selected_fat_bits = bpb_fat_bits if bpb_fat_recognized else fat_label_bits
        ext = False
        ext_superblock = b""
        if size >= 1082:
            with path.open("rb") as stream:
                stream.seek(1024)
                ext_superblock = stream.read(1024)
                ext = ext_superblock[56:58] == b"\x53\xef"
        detected = "ntfs" if ntfs else "exfat" if exfat else "fat" if fat else "ext" if ext else None
        observations = [
            self._observation(artifact, "filesystem.signature_detected", detected is not None),
            self._observation(artifact, "filesystem.type", detected),
            self._observation(artifact, "filesystem.ntfs_signature", ntfs),
            self._observation(artifact, "filesystem.exfat_signature", exfat),
            self._observation(artifact, "filesystem.fat_signature", fat),
            self._observation(artifact, "filesystem.fat.label_signature", bool(fat_label_records)),
            self._observation(artifact, "filesystem.ext_signature", ext),
        ]
        if exfat:
            observations.extend(self._inspect_exfat_boot_regions(artifact, path, size, header))
            observations.extend(self._inspect_exfat_root(artifact, path, size, header))
        if ntfs:
            bytes_per_sector = int.from_bytes(header[11:13], "little")
            sectors_per_cluster = header[13]
            record_clusters = int.from_bytes(header[64:65], "little", signed=True)
            record_size = (1 << -record_clusters) if record_clusters < 0 and -record_clusters < 31 else record_clusters * bytes_per_sector * sectors_per_cluster
            index_clusters = int.from_bytes(header[68:69], "little", signed=True)
            index_record_size = (1 << -index_clusters) if index_clusters < 0 and -index_clusters < 31 else index_clusters * bytes_per_sector * sectors_per_cluster
            mft_lcn = int.from_bytes(header[48:56], "little")
            mft_mirror_lcn = int.from_bytes(header[56:64], "little")
            observations.extend((
                self._observation(artifact, "filesystem.ntfs.bytes_per_sector", bytes_per_sector),
                self._observation(artifact, "filesystem.ntfs.sectors_per_cluster", sectors_per_cluster),
                self._observation(artifact, "filesystem.ntfs.total_sectors", int.from_bytes(header[40:48], "little")),
                self._observation(artifact, "filesystem.ntfs.mft_lcn", mft_lcn),
                self._observation(artifact, "filesystem.ntfs.mft_mirror_lcn", mft_mirror_lcn),
                self._observation(artifact, "filesystem.ntfs.file_record_size", record_size),
                self._observation(artifact, "filesystem.ntfs.index_record_size", index_record_size),
                self._observation(artifact, "filesystem.ntfs.volume_serial", header[72:80].hex()),
            ))
            observations.extend(self._inspect_ntfs_backup_boot(
                artifact, path, size, bytes_per_sector
            ))
            observations.extend(
                self._inspect_ntfs_mft0(
                    artifact, path, size, mft_lcn, bytes_per_sector, sectors_per_cluster,
                    record_size, index_record_size, mft_mirror_lcn,
                )
            )
        if fat:
            fat_header = boot_sector
            bytes_per_sector = int.from_bytes(fat_header[11:13], "little")
            sectors_per_cluster = fat_header[13]
            fat_size_16 = int.from_bytes(fat_header[22:24], "little")
            fat32 = selected_fat_bits == 32
            fat16 = selected_fat_bits == 16
            fat12 = selected_fat_bits == 12
            label_structure_agree = (
                explicit_label_bits == {bpb_fat_bits}
                if explicit_label_bits and bpb_fat_recognized else None
            )
            variant_evidence = {
                "text_label_records": fat_label_records,
                "text_label_fat_bits": fat_label_bits or None,
                "text_label_ambiguous": len(explicit_label_bits) > 1,
                "bpb_cluster_count_fat_bits": bpb_fat_bits or None,
                "bpb_structure_recognized": bpb_fat_recognized,
                "label_structure_agree": label_structure_agree,
                "selected_fat_bits": selected_fat_bits or None,
                "selection_basis": (
                    "bpb_cluster_count" if bpb_fat_recognized
                    else "text_label" if selected_fat_bits
                    else "unresolved_text_label"
                ),
            }
            observations.extend((
                self._observation(
                    artifact, "filesystem.fat.variant",
                    "fat32" if fat32 else "fat16" if fat16 else "fat12" if fat12 else "fat12_or_fat16",
                ),
                self._observation(artifact, "filesystem.fat.variant_evidence", variant_evidence),
                self._observation(artifact, "filesystem.fat.bytes_per_sector", bytes_per_sector),
                self._observation(artifact, "filesystem.fat.sectors_per_cluster", sectors_per_cluster),
                self._observation(artifact, "filesystem.fat.reserved_sector_count", int.from_bytes(fat_header[14:16], "little")),
                self._observation(artifact, "filesystem.fat.count", fat_header[16]),
                self._observation(artifact, "filesystem.fat.total_sectors", int.from_bytes(fat_header[19:21], "little") or int.from_bytes(fat_header[32:36], "little")),
                self._observation(artifact, "filesystem.fat.size_sectors", int.from_bytes(fat_header[36:40], "little") if fat32 else fat_size_16),
                self._observation(artifact, "filesystem.fat.volume_label", (fat_header[71:82] if fat32 else fat_header[43:54]).decode("ascii", errors="replace").strip()),
            ))
            fat_bits = 32 if fat32 else 16 if fat16 else 12 if fat12 else 0
            if fat_bits:
                if not bpb_fat_recognized or bpb_validation is None:
                    bpb_validation = self._fat_bpb_validation(
                        boot_sector, size, fat_bits,
                    )
                observations.append(self._observation(
                    artifact, "filesystem.fat.bpb_validation",
                    bpb_validation,
                ))
            if fat32:
                observations.extend(self._inspect_fat_duplicate_tables(
                    artifact, path, size, fat_header, bytes_per_sector,
                    sectors_per_cluster, int.from_bytes(fat_header[14:16], "little"),
                    fat_header[16], int.from_bytes(fat_header[36:40], "little"), fat_bits=32,
                ))
                observations.extend(self._inspect_fat32_metadata_sectors(
                    artifact, path, size, fat_header, bytes_per_sector,
                    sectors_per_cluster, int.from_bytes(fat_header[14:16], "little"),
                    fat_header[16], int.from_bytes(fat_header[36:40], "little"),
                ))
                observations.extend(self._inspect_fat32_root_directory(
                    artifact, path, size, fat_header, bytes_per_sector,
                    sectors_per_cluster, int.from_bytes(fat_header[14:16], "little"),
                    fat_header[16], int.from_bytes(fat_header[36:40], "little"),
                ))
            elif fat16:
                observations.extend(self._inspect_fat_duplicate_tables(
                    artifact, path, size, fat_header, bytes_per_sector,
                    sectors_per_cluster, int.from_bytes(fat_header[14:16], "little"),
                    fat_header[16], fat_size_16, fat_bits=16,
                ))
                observations.extend(self._inspect_fat_fixed_root_directory(
                    artifact, path, size, fat_header, bytes_per_sector,
                    sectors_per_cluster, int.from_bytes(fat_header[14:16], "little"),
                    fat_header[16], fat_size_16, fat_bits=16,
                ))
            elif fat12:
                observations.extend(self._inspect_fat_duplicate_tables(
                    artifact, path, size, fat_header, bytes_per_sector,
                    sectors_per_cluster, int.from_bytes(fat_header[14:16], "little"),
                    fat_header[16], fat_size_16, fat_bits=12,
                ))
                observations.extend(self._inspect_fat_fixed_root_directory(
                    artifact, path, size, fat_header, bytes_per_sector,
                    sectors_per_cluster, int.from_bytes(fat_header[14:16], "little"),
                    fat_header[16], fat_size_16, fat_bits=12,
                ))
        if ext and len(ext_superblock) >= 136:
            log_block_size = int.from_bytes(ext_superblock[24:28], "little")
            block_size = 1024 << log_block_size if log_block_size <= 6 else None
            observations.extend((
                self._observation(artifact, "filesystem.ext.inode_count", int.from_bytes(ext_superblock[0:4], "little")),
                self._observation(artifact, "filesystem.ext.block_count", int.from_bytes(ext_superblock[4:8], "little")),
                self._observation(artifact, "filesystem.ext.block_size", block_size),
                self._observation(artifact, "filesystem.ext.blocks_per_group", int.from_bytes(ext_superblock[32:36], "little")),
                self._observation(artifact, "filesystem.ext.inodes_per_group", int.from_bytes(ext_superblock[40:44], "little")),
                self._observation(artifact, "filesystem.ext.mount_count", int.from_bytes(ext_superblock[52:54], "little")),
                self._observation(artifact, "filesystem.ext.state", int.from_bytes(ext_superblock[58:60], "little")),
                self._observation(artifact, "filesystem.ext.uuid", str(uuid.UUID(bytes=ext_superblock[104:120]))),
                self._observation(artifact, "filesystem.ext.volume_name", ext_superblock[120:136].split(b"\x00", 1)[0].decode("utf-8", errors="replace")),
            ))
            observations.extend(self._inspect_ext_root_directory(
                artifact, path, size, ext_superblock,
            ))
        return observations

    @staticmethod
    def _fat_type_label_records(header: bytes) -> list[dict[str, object]]:
        """Retain informational FAT type-label fields without treating them as truth."""
        records: list[dict[str, object]] = []
        for offset, field in ((54, header[54:62]), (82, header[82:90])):
            if not field.startswith(b"FAT"):
                continue
            explicit_bits = (
                12 if field.startswith(b"FAT12")
                else 16 if field.startswith(b"FAT16")
                else 32 if field.startswith(b"FAT32")
                else None
            )
            records.append({
                "offset": offset,
                "raw_hex": field.hex(),
                "text": field.decode("ascii", errors="replace"),
                "explicit_fat_bits": explicit_bits,
            })
        return records

    @staticmethod
    def _fat_bpb_cluster_count_variant(header: bytes) -> int:
        """Derive the FAT variant using the specification's cluster-count thresholds."""
        if len(header) < 64:
            return 0
        bytes_per_sector = int.from_bytes(header[11:13], "little")
        sectors_per_cluster = header[13]
        reserved_sectors = int.from_bytes(header[14:16], "little")
        fat_count = header[16]
        root_entries = int.from_bytes(header[17:19], "little")
        total_sectors = (
            int.from_bytes(header[19:21], "little")
            or int.from_bytes(header[32:36], "little")
        )
        fat_size = (
            int.from_bytes(header[22:24], "little")
            or int.from_bytes(header[36:40], "little")
        )
        if not bytes_per_sector or not sectors_per_cluster or not fat_size:
            return 0
        root_sectors = (
            root_entries * 32 + bytes_per_sector - 1
        ) // bytes_per_sector
        first_data_sector = reserved_sectors + fat_count * fat_size + root_sectors
        if total_sectors <= first_data_sector:
            return 0
        cluster_count = (total_sectors - first_data_sector) // sectors_per_cluster
        if cluster_count < 4_085:
            return 12 if cluster_count > 0 else 0
        return 16 if cluster_count < 65_525 else 32

    @staticmethod
    def _fat_bpb_validation(header: bytes, image_size: int, fat_bits: int) -> dict[str, object]:
        """Validate format-specific relationships from one bounded FAT boot sector."""
        bytes_per_sector = int.from_bytes(header[11:13], "little")
        sectors_per_cluster = header[13] if len(header) > 13 else 0
        reserved_sectors = int.from_bytes(header[14:16], "little")
        fat_count = header[16] if len(header) > 16 else 0
        root_entries = int.from_bytes(header[17:19], "little")
        total_sectors_16 = int.from_bytes(header[19:21], "little")
        media_descriptor = header[21] if len(header) > 21 else 0
        fat_size_16 = int.from_bytes(header[22:24], "little")
        total_sectors_32 = int.from_bytes(header[32:36], "little")
        fat_size_32 = int.from_bytes(header[36:40], "little")
        total_sectors = total_sectors_16 or total_sectors_32
        fat_size = fat_size_32 if fat_bits == 32 else fat_size_16
        root_sectors = (
            (root_entries * 32 + bytes_per_sector - 1) // bytes_per_sector
            if bytes_per_sector else 0
        )
        first_data_sector = reserved_sectors + fat_count * fat_size + root_sectors
        data_sectors = total_sectors - first_data_sector
        cluster_count = data_sectors // sectors_per_cluster if sectors_per_cluster and data_sectors > 0 else 0

        jump_opcode = header[0] if header else 0
        jump_target: int | None = None
        jump_encoding = "unknown"
        jump_valid = False
        if jump_opcode == 0xEB and len(header) >= 3:
            jump_encoding = "short"
            jump_target = 2 + int.from_bytes(header[1:2], "little", signed=True)
            jump_valid = header[2] == 0x90 and 3 <= jump_target < 510
        elif jump_opcode == 0xE9 and len(header) >= 3:
            jump_encoding = "near"
            jump_target = 3 + int.from_bytes(header[1:3], "little", signed=True)
            jump_valid = 3 <= jump_target < 510

        total_fields_valid = (
            total_sectors > 0
            and not (total_sectors_16 and total_sectors_32)
            and (fat_bits != 32 or total_sectors_16 == 0)
        )
        root_bytes_aligned = (
            bytes_per_sector > 0 and root_entries * 32 % bytes_per_sector == 0
        )
        if fat_bits == 32:
            fat_size_fields_valid = fat_size_16 == 0 and fat_size_32 > 0
            root_entry_count_valid = root_entries == 0
            cluster_class_valid = cluster_count >= 65_525
            fs_version_valid = int.from_bytes(header[42:44], "little") == 0
            reserved_bpb_bytes_zero = header[52:64] == b"\x00" * 12
        else:
            fat_size_fields_valid = fat_size_16 > 0
            root_entry_count_valid = root_entries > 0 and root_bytes_aligned
            cluster_class_valid = (
                0 < cluster_count < 4_085
                if fat_bits == 12 else 4_085 <= cluster_count < 65_525
            )
            fs_version_valid = True
            reserved_bpb_bytes_zero = True
        fat_bytes = fat_size * bytes_per_sector
        fat_entry_capacity = (
            fat_bytes * 2 // 3 if fat_bits == 12
            else fat_bytes // 2 if fat_bits == 16
            else fat_bytes // 4 if fat_bits == 32
            else 0
        )
        checks = {
            "jump_instruction_valid": jump_valid,
            "end_marker_valid": header[510:512] == b"\x55\xaa",
            "bytes_per_sector_valid": bytes_per_sector in {512, 1024, 2048, 4096},
            "sectors_per_cluster_valid": (
                0 < sectors_per_cluster <= 128
                and sectors_per_cluster & (sectors_per_cluster - 1) == 0
            ),
            "reserved_sector_count_valid": reserved_sectors > 0,
            "fat_count_valid": 1 <= fat_count <= 4,
            "media_descriptor_valid": media_descriptor == 0xF0 or 0xF8 <= media_descriptor <= 0xFF,
            "total_sector_fields_valid": total_fields_valid,
            "fat_size_fields_valid": fat_size_fields_valid,
            "root_entry_count_valid": root_entry_count_valid,
            "data_region_nonempty": total_sectors > first_data_sector,
            "cluster_count_matches_variant": cluster_class_valid,
            "fat_entry_capacity_sufficient": fat_entry_capacity >= cluster_count + 2,
            "fat32_fs_version_valid": fs_version_valid,
            "fat32_reserved_bpb_bytes_zero": reserved_bpb_bytes_zero,
        }
        declared_volume_bytes = (
            total_sectors * bytes_per_sector if total_sectors and bytes_per_sector else 0
        )
        return {
            "available": len(header) >= 512,
            "fat_bits": fat_bits,
            "valid": all(checks.values()),
            "failed_checks": [name for name, valid in checks.items() if not valid],
            "checks": checks,
            "jump_opcode": f"0x{jump_opcode:02X}",
            "jump_encoding": jump_encoding,
            "jump_target_offset": jump_target,
            "bytes_per_sector": bytes_per_sector,
            "sectors_per_cluster": sectors_per_cluster,
            "reserved_sector_count": reserved_sectors,
            "fat_count": fat_count,
            "root_entry_count": root_entries,
            "root_directory_bytes_aligned": root_bytes_aligned if fat_bits != 32 else None,
            "total_sectors_16": total_sectors_16,
            "total_sectors_32": total_sectors_32,
            "selected_total_sectors": total_sectors,
            "fat_size_16": fat_size_16,
            "fat_size_32": fat_size_32 if fat_bits == 32 else None,
            "selected_fat_size_sectors": fat_size,
            "first_data_sector": first_data_sector,
            "data_sectors": data_sectors,
            "cluster_count": cluster_count,
            "fat_entry_capacity": fat_entry_capacity,
            "declared_volume_bytes": declared_volume_bytes,
            "declared_volume_within_supplied_image": declared_volume_bytes <= image_size,
        }

    def _inspect_ext_root_directory(
        self, artifact: Artifact, path: Path, image_size: int, superblock: bytes
    ) -> list[Observation]:
        prefix = "filesystem.ext.root"
        inodes_count = int.from_bytes(superblock[0:4], "little")
        log_block_size = int.from_bytes(superblock[24:28], "little")
        block_size = 1024 << log_block_size if log_block_size <= 6 else 0
        incompat = int.from_bytes(superblock[96:100], "little")
        blocks_count = int.from_bytes(superblock[4:8], "little")
        if incompat & 0x80 and len(superblock) >= 340:
            blocks_count |= int.from_bytes(superblock[336:340], "little") << 32
        inodes_per_group = int.from_bytes(superblock[40:44], "little")
        inode_size = int.from_bytes(superblock[88:90], "little") or 128
        descriptor_size = int.from_bytes(superblock[254:256], "little") if len(superblock) >= 256 else 0
        descriptor_size = descriptor_size if 32 <= descriptor_size <= 256 else 32
        descriptor_offset = 2 * block_size if block_size == 1024 else block_size
        geometry_valid = (
            block_size in {1024, 2048, 4096, 8192, 16384, 32768, 65536}
            and blocks_count > 0 and inodes_count >= 2 and inodes_per_group >= 2
            and 128 <= inode_size <= block_size and inode_size % 4 == 0
            and descriptor_offset + descriptor_size <= image_size
        )
        if not geometry_valid:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.error", "invalid group/inode geometry"),
            ]
        try:
            with path.open("rb") as stream:
                stream.seek(descriptor_offset)
                descriptor = stream.read(descriptor_size)
                if len(descriptor) != descriptor_size:
                    raise RuntimeError("truncated group-zero descriptor")
                inode_table_block = int.from_bytes(descriptor[8:12], "little")
                if incompat & 0x80 and descriptor_size >= 64:
                    inode_table_block |= int.from_bytes(descriptor[40:44], "little") << 32
                root_inode_offset = inode_table_block * block_size + inode_size
                if (
                    inode_table_block <= 0 or inode_table_block >= blocks_count
                    or root_inode_offset < 0 or root_inode_offset + inode_size > image_size
                ):
                    raise RuntimeError("root inode maps outside filesystem/image bounds")
                stream.seek(root_inode_offset)
                inode = stream.read(inode_size)
                if len(inode) != inode_size:
                    raise RuntimeError("truncated root inode")
                mode = int.from_bytes(inode[0:2], "little")
                flags = int.from_bytes(inode[32:36], "little")
                directory_size = int.from_bytes(inode[4:8], "little")
                if len(inode) >= 112:
                    directory_size |= int.from_bytes(inode[108:112], "little") << 32
                if mode & 0xF000 != 0x4000:
                    raise RuntimeError("inode 2 is not an allocated directory")
                if not 0 < directory_size <= _MIB:
                    raise RuntimeError("root directory size is outside the 1-MiB bound")
                required_blocks = (directory_size + block_size - 1) // block_size
                if not 1 <= required_blocks <= 64:
                    raise RuntimeError("root directory exceeds the 64-block bound")
                root_segments, mapping_mode, mapping_error, extent_inventory = self._ext_inode_segments(
                    stream, inode, root_inode_offset, block_size=block_size,
                    blocks_count=blocks_count, image_size=image_size,
                    size_limit=_MIB, block_limit=64,
                )
                if not root_segments:
                    raise RuntimeError(f"root directory mapping failed: {mapping_error}")
                block_payloads: list[tuple[int, int, bytes]] = []
                block_segments: list[dict[str, int]] = []
                for segment in root_segments:
                    logical_offset = int(segment["logical_offset"])
                    logical = logical_offset // block_size
                    physical = int(segment["physical_block"])
                    physical_offset = int(segment["physical_offset"])
                    take = int(segment["length"])
                    stream.seek(physical_offset)
                    block = stream.read(take)
                    if len(block) != take:
                        raise RuntimeError("truncated root directory block")
                    block_payloads.append((logical, physical_offset, block))
                    block_segments.append({
                        "logical_block": logical, "physical_block": physical,
                        "physical_offset": physical_offset, "data_length": take,
                    })
        except (OSError, RuntimeError) as exc:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.error", str(exc)[:2_000], confidence=0.9),
            ]

        entries: list[dict[str, object]] = []
        errors: list[str] = []
        file_types = {
            0: "unknown", 1: "regular", 2: "directory", 3: "character",
            4: "block", 5: "fifo", 6: "socket", 7: "symlink",
        }
        has_file_type = bool(incompat & 0x02)
        for logical, physical_offset, block in block_payloads:
            cursor = 0
            while cursor < len(block) and len(entries) < 2_048:
                if len(block) - cursor < 8:
                    errors.append(f"logical block {logical}: truncated directory entry header at {cursor}")
                    break
                inode_number = int.from_bytes(block[cursor:cursor + 4], "little")
                record_length = int.from_bytes(block[cursor + 4:cursor + 6], "little")
                name_length = (
                    block[cursor + 6] if has_file_type
                    else int.from_bytes(block[cursor + 6:cursor + 8], "little")
                )
                file_type = block[cursor + 7] if has_file_type else 0
                if (
                    record_length < 8 or record_length % 4
                    or cursor + record_length > len(block) or name_length > record_length - 8
                ):
                    errors.append(f"logical block {logical}: invalid record length/name at {cursor}")
                    break
                raw_name = block[cursor + 8:cursor + 8 + name_length]
                if inode_number and raw_name and b"\x00" not in raw_name and b"/" not in raw_name:
                    entries.append({
                        "inode": inode_number,
                        "name": raw_name.decode("utf-8", errors="replace"),
                        "raw_name_hex": raw_name.hex(),
                        "file_type": file_types.get(file_type, f"reserved_{file_type}"),
                        "file_type_value": file_type,
                        "record_length": record_length,
                        "logical_offset": logical * block_size + cursor,
                        "physical_offset": physical_offset + cursor,
                    })
                cursor += record_length
        subdirectory_entries: list[dict[str, object]] = []
        subdirectory_inventory: list[dict[str, object]] = []
        subdirectory_errors: list[str] = []
        directory_queue = [
            {**entry, "parent_inode_lineage": [2], "parent_path": "/"}
            for entry in entries
            if entry.get("name") not in {".", ".."} and entry.get("file_type_value") in {0, 2}
        ][:128]
        visited_directory_inodes = {2}
        visited_directory_blocks = {int(item["physical_block"]) for item in block_segments}
        total_directory_blocks = len(block_segments)
        total_directory_bytes = directory_size
        inspected_directory_candidates = 0
        try:
            with path.open("rb") as stream:
                while directory_queue and len(subdirectory_inventory) < 32 and inspected_directory_candidates < 256:
                    candidate = directory_queue.pop(0)
                    inspected_directory_candidates += 1
                    candidate_inode = candidate.get("inode")
                    if not isinstance(candidate_inode, int) or candidate_inode in visited_directory_inodes:
                        continue
                    child_inode, child_inode_offset, inode_error = self._ext_read_inode(
                        stream, candidate_inode,
                        inodes_count=inodes_count, inodes_per_group=inodes_per_group,
                        inode_size=inode_size, descriptor_offset=descriptor_offset,
                        descriptor_size=descriptor_size, block_size=block_size,
                        blocks_count=blocks_count, image_size=image_size, incompat=incompat,
                    )
                    if child_inode is None or child_inode_offset is None:
                        subdirectory_errors.append(f"inode {candidate_inode}: {inode_error}")
                        continue
                    child_mode = int.from_bytes(child_inode[0:2], "little")
                    child_links = int.from_bytes(child_inode[26:28], "little")
                    if child_mode & 0xF000 != 0x4000:
                        continue
                    visited_directory_inodes.add(candidate_inode)
                    if child_links == 0:
                        subdirectory_errors.append(f"directory inode {candidate_inode}: zero link count")
                        continue
                    child_segments, child_mapping_mode, mapping_error, child_mapping_provenance = self._ext_inode_segments(
                        stream, child_inode, child_inode_offset, block_size=block_size,
                        blocks_count=blocks_count, image_size=image_size,
                        size_limit=_MIB, block_limit=64,
                    )
                    child_size = int.from_bytes(child_inode[4:8], "little")
                    if len(child_inode) >= 112:
                        child_size |= int.from_bytes(child_inode[108:112], "little") << 32
                    if not child_segments:
                        subdirectory_errors.append(f"directory inode {candidate_inode}: {mapping_error}")
                        continue
                    child_blocks = {int(item["physical_block"]) for item in child_segments}
                    if child_blocks & visited_directory_blocks:
                        subdirectory_errors.append(f"directory inode {candidate_inode}: loop/shared directory block")
                        continue
                    if total_directory_blocks + len(child_segments) > 64 or total_directory_bytes + child_size > 8 * _MIB:
                        subdirectory_errors.append(f"directory inode {candidate_inode}: shared 64-block/8-MiB bound reached")
                        continue
                    visited_directory_blocks.update(child_blocks)
                    total_directory_blocks += len(child_segments)
                    total_directory_bytes += child_size
                    child_entries, child_parse_errors = self._ext_directory_entries_from_segments(
                        stream, child_segments, block_size=block_size,
                        has_file_type=has_file_type,
                    )
                    inode_lineage = [*candidate.get("parent_inode_lineage", [2]), candidate_inode]
                    parent_path = str(candidate.get("parent_path", "/"))
                    directory_name = str(candidate.get("name", f"inode-{candidate_inode}"))
                    directory_path = f"{parent_path.rstrip('/')}/{directory_name}"
                    decorated = [{
                        **entry,
                        "directory_inode": candidate_inode,
                        "directory_inode_offset": child_inode_offset,
                        "directory_name": directory_name,
                        "directory_path": directory_path,
                        "directory_inode_lineage": inode_lineage,
                        "directory_source_entry_offset": candidate.get("physical_offset"),
                        "directory_block_lineage": sorted(child_blocks),
                    } for entry in child_entries]
                    subdirectory_entries.extend(decorated[:max(0, 4_096 - len(subdirectory_entries))])
                    subdirectory_inventory.append({
                        "name": directory_name, "path": directory_path,
                        "inode": candidate_inode, "inode_offset": child_inode_offset,
                        "source_entry_offset": candidate.get("physical_offset"),
                        "parent_inode_lineage": candidate.get("parent_inode_lineage", [2]),
                        "inode_lineage": inode_lineage, "link_count": child_links,
                        "mapping_mode": child_mapping_mode, "mapping_provenance": child_mapping_provenance,
                        "data_segments": child_segments,
                    })
                    subdirectory_errors.extend(
                        f"directory inode {candidate_inode}: {error}" for error in child_parse_errors[:64]
                    )
                    for child_entry in decorated:
                        if (
                            child_entry.get("name") not in {".", ".."}
                            and child_entry.get("file_type_value") in {0, 2}
                            and len(directory_queue) < 128
                        ):
                            directory_queue.append({
                                **child_entry,
                                "parent_inode_lineage": inode_lineage,
                                "parent_path": directory_path,
                            })
        except OSError as exc:
            subdirectory_errors.append(f"active subdirectory traversal failed: {str(exc)[:500]}")
        if directory_queue:
            subdirectory_errors.append("active ext subdirectory traversal reached a directory/candidate bound")

        file_source_entries = [*entries, *subdirectory_entries]
        recoverable_files: list[dict[str, object]] = []
        file_errors: list[str] = []
        seen_inodes: set[int] = set()
        try:
            with path.open("rb") as stream:
                for entry in file_source_entries:
                    inode_number = entry.get("inode")
                    if (
                        entry.get("file_type_value") not in {0, 1}
                        or entry.get("name") in {".", ".."}
                        or not isinstance(inode_number, int) or inode_number in seen_inodes
                        or not 1 <= inode_number <= inodes_count
                        or len(recoverable_files) >= 128
                    ):
                        continue
                    seen_inodes.add(inode_number)
                    group = (inode_number - 1) // inodes_per_group
                    group_index = (inode_number - 1) % inodes_per_group
                    group_descriptor_offset = descriptor_offset + group * descriptor_size
                    if group_descriptor_offset + descriptor_size > image_size:
                        file_errors.append(f"inode {inode_number}: group descriptor outside image")
                        continue
                    stream.seek(group_descriptor_offset)
                    group_descriptor = stream.read(descriptor_size)
                    if len(group_descriptor) != descriptor_size:
                        file_errors.append(f"inode {inode_number}: truncated group descriptor")
                        continue
                    file_inode_table = int.from_bytes(group_descriptor[8:12], "little")
                    if incompat & 0x80 and descriptor_size >= 64:
                        file_inode_table |= int.from_bytes(group_descriptor[40:44], "little") << 32
                    file_inode_offset = file_inode_table * block_size + group_index * inode_size
                    if (
                        file_inode_table <= 0 or file_inode_table >= blocks_count
                        or file_inode_offset + inode_size > image_size
                    ):
                        file_errors.append(f"inode {inode_number}: inode table mapping outside bounds")
                        continue
                    stream.seek(file_inode_offset)
                    file_inode = stream.read(inode_size)
                    if len(file_inode) != inode_size:
                        file_errors.append(f"inode {inode_number}: truncated inode")
                        continue
                    file_mode = int.from_bytes(file_inode[0:2], "little")
                    link_count = int.from_bytes(file_inode[26:28], "little")
                    file_size = int.from_bytes(file_inode[4:8], "little")
                    if len(file_inode) >= 112:
                        file_size |= int.from_bytes(file_inode[108:112], "little") << 32
                    if file_mode & 0xF000 != 0x8000 or link_count == 0 or not 0 < file_size <= 8 * _MIB:
                        file_errors.append(f"inode {inode_number}: not an allocated bounded regular file")
                        continue
                    data_segments, file_mapping_mode, mapping_error, file_mapping_provenance = self._ext_inode_segments(
                        stream, file_inode, file_inode_offset, block_size=block_size,
                        blocks_count=blocks_count, image_size=image_size,
                        size_limit=8 * _MIB, block_limit=64,
                    )
                    if not data_segments:
                        file_errors.append(f"inode {inode_number}: {mapping_error}")
                        continue
                    file_flags = int.from_bytes(file_inode[32:36], "little")
                    recoverable_files.append({
                        "name": entry.get("name"),
                        "directory_entry_offset": entry.get("physical_offset"),
                        "inode": inode_number,
                        "inode_offset": file_inode_offset,
                        "inode_mode": f"0x{file_mode:04X}",
                        "inode_flags": f"0x{file_flags:08X}",
                        "link_count": link_count,
                        "size": file_size,
                        "mapping_mode": file_mapping_mode,
                        "mapping_provenance": file_mapping_provenance,
                        "data_segments": data_segments,
                        "directory_inode": entry.get("directory_inode", 2),
                        "directory_inode_offset": entry.get("directory_inode_offset", root_inode_offset),
                        "directory_path": entry.get("directory_path", "/"),
                        "directory_inode_lineage": entry.get("directory_inode_lineage", [2]),
                        "directory_source_entry_offset": entry.get("directory_source_entry_offset"),
                        "directory_block_lineage": entry.get("directory_block_lineage", [
                            int(item["physical_block"]) for item in block_segments
                        ]),
                    })
        except OSError as exc:
            file_errors.append(f"regular-file inode inventory failed: {str(exc)[:500]}")
        return [
            self._observation(artifact, f"{prefix}.available", True),
            self._observation(artifact, f"{prefix}.group_descriptor_offset", descriptor_offset),
            self._observation(artifact, f"{prefix}.inode_table_block", inode_table_block),
            self._observation(artifact, f"{prefix}.inode_offset", root_inode_offset),
            self._observation(artifact, f"{prefix}.inode_mode", f"0x{mode:04X}"),
            self._observation(artifact, f"{prefix}.inode_flags", f"0x{flags:08X}"),
            self._observation(artifact, f"{prefix}.directory_size", directory_size),
            self._observation(artifact, f"{prefix}.mapping_mode", mapping_mode),
            self._observation(artifact, f"{prefix}.directory_filetype_feature", has_file_type),
            self._observation(artifact, f"{prefix}.mapping", extent_inventory),
            self._observation(artifact, f"{prefix}.block_segments", block_segments),
            self._observation(artifact, f"{prefix}.directory_entries", entries),
            self._observation(artifact, f"{prefix}.directory_errors", errors[:256]),
            self._observation(artifact, f"{prefix}.subdirectory_entries", subdirectory_entries[:4_096]),
            self._observation(artifact, f"{prefix}.subdirectory_inventory", subdirectory_inventory),
            self._observation(artifact, f"{prefix}.subdirectory_errors", subdirectory_errors[:256]),
            self._observation(artifact, f"{prefix}.recoverable_regular_files", recoverable_files),
            self._observation(artifact, f"{prefix}.regular_file_errors", file_errors[:256]),
            self._observation(artifact, f"{prefix}.entries_truncated", len(entries) >= 2_048),
        ]

    @staticmethod
    def _ext_read_inode(
        stream,
        inode_number: int,
        *,
        inodes_count: int,
        inodes_per_group: int,
        inode_size: int,
        descriptor_offset: int,
        descriptor_size: int,
        block_size: int,
        blocks_count: int,
        image_size: int,
        incompat: int,
    ) -> tuple[bytes | None, int | None, str | None]:
        if not 1 <= inode_number <= inodes_count:
            return None, None, "inode number outside filesystem bounds"
        group = (inode_number - 1) // inodes_per_group
        group_index = (inode_number - 1) % inodes_per_group
        group_descriptor_offset = descriptor_offset + group * descriptor_size
        if group_descriptor_offset + descriptor_size > image_size:
            return None, None, "group descriptor outside supplied image"
        stream.seek(group_descriptor_offset)
        descriptor = stream.read(descriptor_size)
        if len(descriptor) != descriptor_size:
            return None, None, "truncated group descriptor"
        inode_table = int.from_bytes(descriptor[8:12], "little")
        if incompat & 0x80 and descriptor_size >= 64:
            inode_table |= int.from_bytes(descriptor[40:44], "little") << 32
        inode_offset = inode_table * block_size + group_index * inode_size
        if inode_table <= 0 or inode_table >= blocks_count or inode_offset + inode_size > image_size:
            return None, None, "inode table mapping outside filesystem/image bounds"
        stream.seek(inode_offset)
        inode = stream.read(inode_size)
        if len(inode) != inode_size:
            return None, None, "truncated inode"
        return inode, inode_offset, None

    @staticmethod
    def _ext_inode_segments(
        stream: BinaryIO,
        inode: bytes,
        inode_offset: int,
        *,
        block_size: int,
        blocks_count: int,
        image_size: int,
        size_limit: int,
        block_limit: int,
    ) -> tuple[list[dict[str, int]], str | None, str | None, list[dict[str, object]]]:
        size = int.from_bytes(inode[4:8], "little")
        if len(inode) >= 112:
            size |= int.from_bytes(inode[108:112], "little") << 32
        if not 0 < size <= size_limit:
            return [], None, "inode size outside configured bound", []
        required = (size + block_size - 1) // block_size
        if not 1 <= required <= block_limit:
            return [], None, "inode block count outside configured bound", []
        flags = int.from_bytes(inode[32:36], "little")
        logical_blocks: dict[int, int] = {}
        block_provenance: dict[int, dict[str, int]] = {}
        mapping_provenance: list[dict[str, object]] = []
        mode = "ext2_3_direct_blocks"
        if flags & 0x00080000:
            root = inode[40:100]
            count = int.from_bytes(root[2:4], "little")
            maximum = int.from_bytes(root[4:6], "little")
            depth = int.from_bytes(root[6:8], "little")
            mode = "ext4_depth0_extents" if depth == 0 else f"ext4_depth{depth}_extent_tree"
            if (
                int.from_bytes(root[0:2], "little") != 0xF30A
                or depth not in {0, 1, 2} or not 1 <= count <= maximum or maximum > 4
            ):
                return [], mode, "invalid or unsupported extent root", []
            extent_sources: list[tuple[bytes, int, int | None, int | None]] = []
            extent_tree_blocks: set[int] = set()
            if depth == 0:
                extent_sources.append((root, inode_offset + 40, None, None))
            else:
                index_queue: list[
                    tuple[bytes, int, int, int | None, int | None, int | None]
                ] = [(root, inode_offset + 40, depth, None, None, None)]
                total_index_entries = 0
                while index_queue:
                    node, node_offset, node_depth, lower_bound, upper_bound, parent_entry_offset = index_queue.pop(0)
                    node_count = int.from_bytes(node[2:4], "little")
                    total_index_entries += node_count
                    if total_index_entries > block_limit:
                        return [], mode, "extent index entry count exceeds configured block bound", mapping_provenance
                    indices: list[tuple[int, int, int]] = []
                    previous_index_logical = -1
                    for index_number in range(node_count):
                        relative_offset = 12 + index_number * 12
                        logical_start = int.from_bytes(node[relative_offset:relative_offset + 4], "little")
                        child_block = (
                            int.from_bytes(node[relative_offset + 8:relative_offset + 10], "little") << 32
                            | int.from_bytes(node[relative_offset + 4:relative_offset + 8], "little")
                        )
                        index_offset = node_offset + relative_offset
                        if (
                            logical_start <= previous_index_logical
                            or (lower_bound is not None and logical_start < lower_bound)
                            or (upper_bound is not None and logical_start >= upper_bound)
                            or child_block <= 0 or child_block >= blocks_count
                            or child_block in extent_tree_blocks
                            or child_block * block_size + block_size > image_size
                        ):
                            return [], mode, "invalid, unsorted, out-of-range, or repeated extent-tree index", mapping_provenance
                        extent_tree_blocks.add(child_block)
                        indices.append((logical_start, child_block, index_offset))
                        index_evidence: dict[str, object] = {
                            "kind": "extent_index", "logical_block": logical_start,
                            "child_block": child_block, "child_depth": node_depth - 1,
                            "index_node_depth": node_depth, "index_node_offset": node_offset,
                            "index_entry_offset": index_offset,
                        }
                        if parent_entry_offset is not None:
                            index_evidence["parent_index_entry_offset"] = parent_entry_offset
                        if node_depth == 1:
                            index_evidence["leaf_block"] = child_block
                        mapping_provenance.append(index_evidence)
                        previous_index_logical = logical_start
                    for index_number, (logical_start, child_block, index_offset) in enumerate(indices):
                        child_upper = (
                            indices[index_number + 1][0]
                            if index_number + 1 < len(indices) else upper_bound
                        )
                        child_offset = child_block * block_size
                        stream.seek(child_offset)
                        child = stream.read(block_size)
                        if len(child) != block_size:
                            return [], mode, "truncated extent-tree child block", mapping_provenance
                        child_count = int.from_bytes(child[2:4], "little")
                        child_maximum = int.from_bytes(child[4:6], "little")
                        child_depth = int.from_bytes(child[6:8], "little")
                        child_capacity = (block_size - 12) // 12
                        if (
                            int.from_bytes(child[0:2], "little") != 0xF30A
                            or child_depth != node_depth - 1
                            or not 1 <= child_count <= child_maximum
                            or child_maximum > child_capacity
                        ):
                            return [], mode, "invalid extent-tree child header", mapping_provenance
                        if child_depth == 0:
                            mapping_provenance.append({
                                "kind": "extent_leaf", "index_logical_block": logical_start,
                                "leaf_block": child_block, "leaf_offset": child_offset,
                                "entry_count": child_count, "maximum": child_maximum,
                                "index_entry_offset": index_offset,
                            })
                            extent_sources.append((child, child_offset, logical_start, child_upper))
                        else:
                            mapping_provenance.append({
                                "kind": "extent_index_node", "index_logical_block": logical_start,
                                "index_block": child_block, "index_node_offset": child_offset,
                                "tree_depth": child_depth, "entry_count": child_count,
                                "maximum": child_maximum, "parent_index_entry_offset": index_offset,
                            })
                            index_queue.append((
                                child, child_offset, child_depth, logical_start,
                                child_upper, index_offset,
                            ))
            if sum(int.from_bytes(node[2:4], "little") for node, *_ in extent_sources) > block_limit:
                return [], mode, "extent entry count exceeds configured block bound", mapping_provenance
            previous_end = 0
            physical_intervals: list[tuple[int, int]] = []
            for extent_node, node_offset, lower_logical, upper_logical in extent_sources:
                node_count = int.from_bytes(extent_node[2:4], "little")
                for extent_index in range(node_count):
                    offset = 12 + extent_index * 12
                    logical_start = int.from_bytes(extent_node[offset:offset + 4], "little")
                    raw_length = int.from_bytes(extent_node[offset + 4:offset + 6], "little")
                    length = raw_length & 0x7FFF
                    physical_start = (
                        int.from_bytes(extent_node[offset + 6:offset + 8], "little") << 32
                        | int.from_bytes(extent_node[offset + 8:offset + 12], "little")
                    )
                    if (
                        raw_length & 0x8000 or length == 0 or logical_start < previous_end
                        or (lower_logical is not None and logical_start < lower_logical)
                        or (upper_logical is not None and logical_start >= upper_logical)
                        or (upper_logical is not None and logical_start + length > upper_logical)
                        or physical_start <= 0 or physical_start + length > blocks_count
                        or (physical_start + length) * block_size > image_size
                        or any(
                            physical_start <= tree_block < physical_start + length
                            for tree_block in extent_tree_blocks
                        )
                        or any(
                            physical_start < interval_end and physical_start + length > interval_start
                            for interval_start, interval_end in physical_intervals
                        )
                    ):
                        return [], mode, "invalid, overlapping, repeated, tree-referencing, or uninitialized extent", mapping_provenance
                    entry_offset = node_offset + offset
                    extent_evidence: dict[str, object] = {
                        "kind": "extent", "logical_block": logical_start,
                        "block_count": length, "physical_block": physical_start,
                        "uninitialized": False,
                    }
                    if depth == 0:
                        extent_evidence["inode_byte_offset"] = entry_offset
                    else:
                        extent_evidence.update({
                            "leaf_block": node_offset // block_size,
                            "leaf_offset": node_offset,
                            "leaf_entry_offset": entry_offset,
                        })
                    mapping_provenance.append(extent_evidence)
                    physical_intervals.append((physical_start, physical_start + length))
                    for part in range(min(length, max(0, required - logical_start))):
                        logical = logical_start + part
                        if logical < required:
                            logical_blocks[logical] = physical_start + part
                            if depth >= 1:
                                block_provenance[logical] = {
                                    "extent_leaf_block": node_offset // block_size,
                                    "extent_leaf_offset": node_offset,
                                    "extent_entry_offset": entry_offset,
                                    "extent_tree_depth": depth,
                                }
                    previous_end = logical_start + length
        else:
            direct_count = min(required, 12)
            seen_data_blocks: set[int] = set()
            for logical in range(direct_count):
                physical = int.from_bytes(inode[40 + logical * 4:44 + logical * 4], "little")
                if (
                    physical <= 0 or physical >= blocks_count or physical in seen_data_blocks
                    or physical * block_size + block_size > image_size
                ):
                    return [], mode, "missing or invalid direct block pointer", mapping_provenance
                logical_blocks[logical] = physical
                seen_data_blocks.add(physical)
                mapping_provenance.append({
                    "logical_block": logical, "block_count": 1,
                    "physical_block": physical, "uninitialized": False,
                    "inode_byte_offset": inode_offset + 40 + logical * 4,
                })
            if required > 12:
                indirect_count = required - 12
                indirect_capacity = block_size // 4
                indirect_block = int.from_bytes(inode[88:92], "little")
                indirect_offset = indirect_block * block_size
                if (
                    not 1 <= indirect_count <= indirect_capacity
                    or indirect_block <= 0 or indirect_block >= blocks_count
                    or indirect_block in seen_data_blocks
                    or indirect_offset + block_size > image_size
                ):
                    return [], mode, "missing, aliased, or invalid single-indirect block", mapping_provenance
                stream.seek(indirect_offset)
                indirect = stream.read(block_size)
                if len(indirect) != block_size:
                    return [], mode, "truncated single-indirect block", mapping_provenance
                mode = "ext2_3_direct_single_indirect"
                mapping_provenance.append({
                    "kind": "single_indirect_block", "logical_block": 12,
                    "physical_block": indirect_block, "physical_offset": indirect_offset,
                    "inode_pointer_offset": inode_offset + 88,
                    "pointer_count": indirect_count, "pointer_capacity": indirect_capacity,
                })
                for pointer_index in range(indirect_count):
                    pointer_offset = indirect_offset + pointer_index * 4
                    physical = int.from_bytes(
                        indirect[pointer_index * 4:pointer_index * 4 + 4], "little"
                    )
                    logical = 12 + pointer_index
                    if (
                        physical <= 0 or physical >= blocks_count
                        or physical == indirect_block or physical in seen_data_blocks
                        or physical * block_size + block_size > image_size
                    ):
                        return [], mode, "missing, repeated, aliased, or invalid single-indirect data pointer", mapping_provenance
                    logical_blocks[logical] = physical
                    seen_data_blocks.add(physical)
                    block_provenance[logical] = {
                        "indirect_block": indirect_block,
                        "indirect_block_offset": indirect_offset,
                        "indirect_pointer_offset": pointer_offset,
                    }
                    mapping_provenance.append({
                        "kind": "indirect_data_pointer", "logical_block": logical,
                        "physical_block": physical, "pointer_index": pointer_index,
                        "pointer_offset": pointer_offset, "indirect_block": indirect_block,
                    })
        if set(logical_blocks) != set(range(required)):
            return [], mode, "sparse, missing, or incomplete logical mapping", mapping_provenance
        segments: list[dict[str, int]] = []
        remaining = size
        for logical in range(required):
            physical = logical_blocks[logical]
            physical_offset = physical * block_size
            if physical_offset < 0 or physical_offset + block_size > image_size:
                return [], mode, "data block outside supplied image", mapping_provenance
            take = min(block_size, remaining)
            segment = {
                "logical_offset": logical * block_size, "physical_block": physical,
                "physical_offset": physical_offset, "length": take,
            }
            segment.update(block_provenance.get(logical, {}))
            segments.append(segment)
            remaining -= take
        return segments, mode, None, mapping_provenance

    @staticmethod
    def _ext_directory_entries_from_segments(
        stream,
        segments: list[dict[str, int]],
        *,
        block_size: int,
        has_file_type: bool,
        entry_limit: int = 2_048,
    ) -> tuple[list[dict[str, object]], list[str]]:
        entries: list[dict[str, object]] = []
        errors: list[str] = []
        types = {0: "unknown", 1: "regular", 2: "directory", 3: "character", 4: "block", 5: "fifo", 6: "socket", 7: "symlink"}
        for segment in segments:
            stream.seek(segment["physical_offset"])
            block = stream.read(segment["length"])
            if len(block) != segment["length"]:
                errors.append(f"logical offset {segment['logical_offset']}: truncated directory block")
                continue
            cursor = 0
            while cursor < len(block) and len(entries) < entry_limit:
                if len(block) - cursor < 8:
                    errors.append(f"logical offset {segment['logical_offset']}: truncated entry header at {cursor}")
                    break
                inode_number = int.from_bytes(block[cursor:cursor + 4], "little")
                record_length = int.from_bytes(block[cursor + 4:cursor + 6], "little")
                name_length = block[cursor + 6] if has_file_type else int.from_bytes(block[cursor + 6:cursor + 8], "little")
                file_type = block[cursor + 7] if has_file_type else 0
                if record_length < 8 or record_length % 4 or cursor + record_length > len(block) or name_length > record_length - 8:
                    errors.append(f"logical offset {segment['logical_offset']}: invalid record at {cursor}")
                    break
                raw_name = block[cursor + 8:cursor + 8 + name_length]
                if inode_number and raw_name and b"\x00" not in raw_name and b"/" not in raw_name:
                    entries.append({
                        "inode": inode_number, "name": raw_name.decode("utf-8", errors="replace"),
                        "raw_name_hex": raw_name.hex(), "file_type": types.get(file_type, f"reserved_{file_type}"),
                        "file_type_value": file_type, "record_length": record_length,
                        "logical_offset": segment["logical_offset"] + cursor,
                        "physical_offset": segment["physical_offset"] + cursor,
                    })
                cursor += record_length
        return entries, errors

    def _inspect_exfat_boot_regions(
        self, artifact: Artifact, path: Path, image_size: int, header: bytes
    ) -> list[Observation]:
        prefix = "filesystem.exfat.boot_regions"
        sector_shift = header[108] if len(header) > 108 else 0
        bytes_per_sector = 1 << sector_shift if 9 <= sector_shift <= 12 else 0
        region_size = bytes_per_sector * 12
        if not bytes_per_sector or image_size < region_size * 2:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(
                    artifact, f"{prefix}.unavailable_reason",
                    "invalid sector geometry or fewer than 24 complete sectors",
                ),
            ]
        try:
            with path.open("rb") as stream:
                regions = stream.read(region_size * 2)
        except OSError as exc:
            return [self._observation(artifact, f"{prefix}.error", str(exc)[:2_000], confidence=0.9)]
        if len(regions) != region_size * 2:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.unavailable_reason", "truncated boot-region read"),
            ]

        def validate(region: bytes, absolute_offset: int) -> dict[str, object]:
            calculated = self._exfat_boot_checksum(region[:11 * bytes_per_sector])
            checksum_sector = region[11 * bytes_per_sector:12 * bytes_per_sector]
            stored_values = {
                int.from_bytes(checksum_sector[offset:offset + 4], "little")
                for offset in range(0, len(checksum_sector), 4)
            }
            extended_signatures = [
                region[sector * bytes_per_sector + bytes_per_sector - 4:(sector + 1) * bytes_per_sector]
                == b"\x00\x00\x55\xaa"
                for sector in range(1, 9)
            ]
            extended_boot_code_zero = [
                not any(region[sector * bytes_per_sector:(sector + 1) * bytes_per_sector - 4])
                for sector in range(1, 9)
            ]
            return {
                "offset": absolute_offset,
                "calculated_checksum": f"0x{calculated:08X}",
                "stored_checksum_values": [f"0x{value:08X}" for value in sorted(stored_values)],
                "checksum_repeated": len(stored_values) == 1,
                "checksum_valid": stored_values == {calculated},
                "boot_signature_valid": region[510:512] == b"\x55\xaa",
                "extended_boot_signatures_valid": all(extended_signatures),
                "extended_boot_code_all_zero": all(extended_boot_code_zero),
                "oem_parameters_offset": absolute_offset + 9 * bytes_per_sector,
                "reserved_sector_zero": not any(region[10 * bytes_per_sector:11 * bytes_per_sector]),
                "checksum_sector_offset": absolute_offset + 11 * bytes_per_sector,
            }

        main_region = regions[:region_size]
        backup_region = regions[region_size:]
        main = validate(main_region, 0)
        backup = validate(backup_region, region_size)
        compare_length = 11 * bytes_per_sector
        ignored = {106, 107, 112}
        differences = [
            index for index in range(compare_length)
            if index not in ignored and main_region[index] != backup_region[index]
        ]
        return [
            self._observation(artifact, f"{prefix}.available", True),
            self._observation(artifact, f"{prefix}.bytes_per_sector", bytes_per_sector),
            self._observation(artifact, f"{prefix}.main", main),
            self._observation(artifact, f"{prefix}.backup", backup),
            self._observation(artifact, f"{prefix}.immutable_fields_match", not differences),
            self._observation(
                artifact, f"{prefix}.first_immutable_difference",
                ({
                    "relative_offset": differences[0],
                    "main_absolute_offset": differences[0],
                    "backup_absolute_offset": region_size + differences[0],
                    "main_byte": f"0x{main_region[differences[0]]:02X}",
                    "backup_byte": f"0x{backup_region[differences[0]]:02X}",
                } if differences else None),
            ),
            self._observation(artifact, f"{prefix}.difference_count", len(differences)),
            self._observation(
                artifact, f"{prefix}.comparison_exclusions",
                ["VolumeFlags[106:108]", "PercentInUse[112]"],
            ),
        ]

    @staticmethod
    def _exfat_boot_checksum(boot_region_without_checksum_sector: bytes) -> int:
        checksum = 0
        for offset, value in enumerate(boot_region_without_checksum_sector):
            if offset in {106, 107, 112}:
                continue
            checksum = ((checksum << 31) | (checksum >> 1)) & 0xFFFFFFFF
            checksum = (checksum + value) & 0xFFFFFFFF
        return checksum

    def _inspect_exfat_root(
        self, artifact: Artifact, path: Path, image_size: int, header: bytes
    ) -> list[Observation]:
        prefix = "filesystem.exfat"
        sector_shift, cluster_shift = header[108], header[109]
        bytes_per_sector = 1 << sector_shift if 9 <= sector_shift <= 12 else 0
        sectors_per_cluster = 1 << cluster_shift if cluster_shift <= 25 else 0
        cluster_size = bytes_per_sector * sectors_per_cluster
        fat_offset = int.from_bytes(header[80:84], "little")
        fat_length = int.from_bytes(header[84:88], "little")
        heap_offset = int.from_bytes(header[88:92], "little")
        cluster_count = int.from_bytes(header[92:96], "little")
        root_cluster = int.from_bytes(header[96:100], "little")
        volume_flags = int.from_bytes(header[106:108], "little")
        fat_count = header[110]
        root_offset = (heap_offset + (root_cluster - 2) * sectors_per_cluster) * bytes_per_sector
        valid = (
            bytes_per_sector > 0 and sectors_per_cluster > 0 and 0 < cluster_size <= 2 * _MIB
            and fat_count in {1, 2} and fat_offset > 0 and fat_length > 0
            and heap_offset > fat_offset and cluster_count > 0
            and 2 <= root_cluster < cluster_count + 2
            and 0 <= root_offset and root_offset + cluster_size <= image_size
        )
        if not valid:
            return [self._observation(artifact, f"{prefix}.root_available", False)]
        segments: list[dict[str, int]] = []
        entry_offsets: list[int] = []
        chunks: list[bytes] = []
        errors: list[str] = []
        termination = "limit"
        fat_byte_offset = fat_offset * bytes_per_sector
        fat_byte_end = fat_byte_offset + fat_length * bytes_per_sector
        current = root_cluster
        visited: set[int] = set()
        cluster_limit = max(1, min(64, (8 * _MIB) // cluster_size))
        try:
            with path.open("rb") as stream:
                for _ in range(cluster_limit):
                    if current in visited:
                        termination = "loop"
                        errors.append(f"root FAT chain loops at cluster {current}")
                        break
                    visited.add(current)
                    physical_offset = (heap_offset + (current - 2) * sectors_per_cluster) * bytes_per_sector
                    if current < 2 or current >= cluster_count + 2 or physical_offset < 0 or physical_offset + cluster_size > image_size:
                        termination = "image_or_volume_bounds"
                        errors.append(f"root cluster {current} is outside volume/image bounds")
                        break
                    stream.seek(physical_offset)
                    chunk = stream.read(cluster_size)
                    if len(chunk) != cluster_size:
                        termination = "truncated_read"
                        errors.append(f"root cluster {current} is truncated")
                        break
                    chunks.append(chunk)
                    segments.append({"cluster": current, "offset": physical_offset, "length": cluster_size})
                    entry_offsets.extend(physical_offset + part * 32 for part in range(cluster_size // 32))
                    fat_entry_offset = fat_byte_offset + current * 4
                    if fat_entry_offset < fat_byte_offset or fat_entry_offset + 4 > fat_byte_end or fat_entry_offset + 4 > image_size:
                        termination = "fat_bounds"
                        errors.append(f"root FAT entry for cluster {current} is outside bounds")
                        break
                    stream.seek(fat_entry_offset)
                    next_cluster = int.from_bytes(stream.read(4), "little")
                    if next_cluster >= 0xFFFFFFF8:
                        termination = "eoc"
                        break
                    if next_cluster < 2 or next_cluster == 0xFFFFFFF7 or 0xFFFFFFF0 <= next_cluster <= 0xFFFFFFF6:
                        termination = "invalid_fat_value"
                        errors.append(f"root cluster {current} points to invalid value 0x{next_cluster:08X}")
                        break
                    current = next_cluster
        except OSError as exc:
            return [self._observation(artifact, f"{prefix}.root_error", str(exc)[:2_000], confidence=0.9)]
        data = b"".join(chunks)
        entry_count = len(data) // 32

        def read_exact_fat_chain(first_cluster: int, data_length: int) -> tuple[bytes | None, list[dict[str, int]], str]:
            if not 0 < data_length <= 8 * _MIB:
                return None, [], "data_length_limit"
            required_clusters = (data_length + cluster_size - 1) // cluster_size
            if not 1 <= required_clusters <= 64:
                return None, [], "cluster_count_limit"
            payload = bytearray()
            mapped: list[dict[str, int]] = []
            seen: set[int] = set()
            current_cluster = first_cluster
            try:
                with path.open("rb") as stream:
                    for cluster_index in range(required_clusters):
                        if current_cluster in seen:
                            return None, mapped, "fat_loop"
                        if not 2 <= current_cluster < cluster_count + 2:
                            return None, mapped, "volume_bounds"
                        seen.add(current_cluster)
                        physical_offset = (
                            heap_offset + (current_cluster - 2) * sectors_per_cluster
                        ) * bytes_per_sector
                        if physical_offset < 0 or physical_offset + cluster_size > image_size:
                            return None, mapped, "image_bounds"
                        take = min(cluster_size, data_length - len(payload))
                        stream.seek(physical_offset)
                        chunk = stream.read(take)
                        if len(chunk) != take:
                            return None, mapped, "truncated_read"
                        payload.extend(chunk)
                        mapped.append({
                            "cluster": current_cluster, "offset": physical_offset,
                            "length": cluster_size, "data_length": take,
                        })
                        fat_entry_offset = fat_byte_offset + current_cluster * 4
                        if (
                            fat_entry_offset < fat_byte_offset
                            or fat_entry_offset + 4 > fat_byte_end
                            or fat_entry_offset + 4 > image_size
                        ):
                            return None, mapped, "fat_bounds"
                        stream.seek(fat_entry_offset)
                        raw_next = stream.read(4)
                        if len(raw_next) != 4:
                            return None, mapped, "fat_truncated"
                        next_cluster = int.from_bytes(raw_next, "little")
                        if cluster_index == required_clusters - 1:
                            if next_cluster < 0xFFFFFFF8:
                                return None, mapped, "final_cluster_not_eoc"
                            return bytes(payload), mapped, "eoc"
                        if (
                            next_cluster < 2 or next_cluster >= 0xFFFFFFF8
                            or next_cluster == 0xFFFFFFF7
                            or 0xFFFFFFF0 <= next_cluster <= 0xFFFFFFF6
                        ):
                            return None, mapped, "invalid_or_early_eoc"
                        current_cluster = next_cluster
            except OSError:
                return None, mapped, "read_error"
            return None, mapped, "incomplete"

        active_fat = volume_flags & 0x01 if fat_count == 2 else 0
        expected_bitmap_length = (cluster_count + 7) // 8
        allocation_bitmaps: list[dict[str, object]] = []
        upcase_tables: list[dict[str, object]] = []
        for metadata_index in range(entry_count):
            entry = data[metadata_index * 32:(metadata_index + 1) * 32]
            if entry[0] == 0:
                break
            if entry[0] == 0x81:
                bitmap_flags = entry[1]
                bitmap_record: dict[str, object] = {
                    "entry_index": metadata_index,
                    "offset": entry_offsets[metadata_index],
                    "bitmap_flags": f"0x{bitmap_flags:02X}",
                    "fat_index": bitmap_flags & 0x01,
                    "first_cluster": int.from_bytes(entry[20:24], "little"),
                    "data_length": int.from_bytes(entry[24:32], "little"),
                    "expected_data_length": expected_bitmap_length,
                    "active": (bitmap_flags & 0x01) == active_fat,
                    "structurally_valid": bitmap_flags & 0xFE == 0 and not any(entry[2:20]),
                }
                allocation_bitmaps.append(bitmap_record)
            elif entry[0] == 0x82:
                upcase_record: dict[str, object] = {
                    "entry_index": metadata_index,
                    "offset": entry_offsets[metadata_index],
                    "stored_checksum": f"0x{int.from_bytes(entry[4:8], 'little'):08X}",
                    "first_cluster": int.from_bytes(entry[20:24], "little"),
                    "data_length": int.from_bytes(entry[24:32], "little"),
                    "structurally_valid": not any(entry[1:4]) and not any(entry[8:20]),
                }
                upcase_tables.append(upcase_record)

        bitmap_bytes: bytes | None = None
        bitmap_segments: list[dict[str, int]] = []
        active_bitmap_candidates = [
            item for item in allocation_bitmaps
            if item["active"] and item["structurally_valid"]
            and item["data_length"] == expected_bitmap_length
        ]
        if len(active_bitmap_candidates) == 1:
            active_bitmap = active_bitmap_candidates[0]
            bitmap_bytes, bitmap_segments, bitmap_termination = read_exact_fat_chain(
                int(active_bitmap["first_cluster"]), int(active_bitmap["data_length"])
            )
            active_bitmap["cluster_segments"] = bitmap_segments
            active_bitmap["chain_termination"] = bitmap_termination
            padding_valid = bool(bitmap_bytes is not None)
            if bitmap_bytes is not None and cluster_count % 8:
                unused_mask = 0xFF << (cluster_count % 8) & 0xFF
                padding_valid = bitmap_bytes[-1] & unused_mask == 0
            active_bitmap["unused_bits_zero"] = padding_valid
            active_bitmap["validation"] = "valid" if bitmap_bytes is not None and padding_valid else "invalid"
            if not padding_valid:
                bitmap_bytes = None
        elif active_bitmap_candidates:
            errors.append("multiple structurally valid active allocation bitmap entries")

        upcase_mapping: list[int] | None = None
        valid_upcase_candidates = [
            item for item in upcase_tables
            if item["structurally_valid"] and isinstance(item["data_length"], int)
            and 0 < item["data_length"] <= 128 * 1024 and item["data_length"] % 2 == 0
        ]
        if len(valid_upcase_candidates) == 1:
            upcase = valid_upcase_candidates[0]
            upcase_bytes, upcase_segments, upcase_termination = read_exact_fat_chain(
                int(upcase["first_cluster"]), int(upcase["data_length"])
            )
            upcase["cluster_segments"] = upcase_segments
            upcase["chain_termination"] = upcase_termination
            calculated_upcase_checksum = (
                self._exfat_upcase_checksum(upcase_bytes) if upcase_bytes is not None else None
            )
            upcase["calculated_checksum"] = (
                f"0x{calculated_upcase_checksum:08X}" if calculated_upcase_checksum is not None else None
            )
            checksum_valid = (
                calculated_upcase_checksum is not None
                and calculated_upcase_checksum == int(str(upcase["stored_checksum"]), 16)
            )
            upcase["checksum_valid"] = checksum_valid
            if checksum_valid and upcase_bytes is not None:
                upcase_mapping = self._decode_exfat_upcase_table(upcase_bytes)
            upcase["mapping_complete"] = upcase_mapping is not None
            upcase["validation"] = "valid" if upcase_mapping is not None else "invalid"
        elif valid_upcase_candidates:
            errors.append("multiple structurally valid upcase table entries")

        deleted_sets: list[dict[str, object]] = []
        index = 0
        while index < entry_count and len(deleted_sets) < 256:
            primary = data[index * 32:(index + 1) * 32]
            if primary[0] == 0:
                break
            if primary[0] != 0x05:
                index += 1
                continue
            secondary_count = primary[1]
            total = secondary_count + 1
            if not 2 <= secondary_count <= 18 or index + total > entry_count:
                errors.append(f"entry {index}: invalid deleted file-entry set length")
                index += 1
                continue
            entries = [data[(index + part) * 32:(index + part + 1) * 32] for part in range(total)]
            stream_entry, names = entries[1], entries[2:]
            name_length = stream_entry[3]
            if (
                stream_entry[0] != 0x40 or stream_entry[1] & 0xFC
                or not 1 <= name_length <= 255
                or len(names) != (name_length + 14) // 15
                or any(item[0] != 0x41 for item in names)
            ):
                errors.append(f"entry {index}: invalid deleted stream/name sequence")
                index += total
                continue
            restored = [bytes([item[0] | 0x80]) + item[1:] for item in entries]
            stored_checksum = int.from_bytes(primary[2:4], "little")
            calculated = self._exfat_entry_set_checksum(restored)
            raw_name = b"".join(item[2:32] for item in names)
            if calculated != stored_checksum or any(raw_name[name_length * 2:]):
                errors.append(f"entry {index}: restored checksum or name padding is invalid")
                index += total
                continue
            try:
                name = raw_name[:name_length * 2].decode("utf-16le")
            except UnicodeDecodeError:
                name = ""
            if not name or any(ord(char) < 32 or char in '\\/:*?"<>|' for char in name):
                errors.append(f"entry {index}: invalid UTF-16 filename")
                index += total
                continue
            stored_name_hash = int.from_bytes(stream_entry[4:6], "little")
            calculated_name_hash = (
                self._exfat_name_hash(raw_name[:name_length * 2], upcase_mapping)
                if upcase_mapping is not None else None
            )
            deleted_sets.append({
                "entry_index": index, "offset": entry_offsets[index],
                "secondary_count": secondary_count,
                "entry_offsets": [entry_offsets[index + part] for part in range(total)],
                "name": name, "attributes": f"0x{int.from_bytes(primary[4:6], 'little'):04X}",
                "stream_flags": f"0x{stream_entry[1]:02X}",
                "name_hash": f"0x{stored_name_hash:04X}",
                "calculated_name_hash": (
                    f"0x{calculated_name_hash:04X}" if calculated_name_hash is not None else None
                ),
                "name_hash_validation": (
                    "valid" if calculated_name_hash == stored_name_hash
                    else "mismatch" if calculated_name_hash is not None
                    else "not_verified_without_upcase_table"
                ),
                "valid_data_length": int.from_bytes(stream_entry[8:16], "little"),
                "first_cluster": int.from_bytes(stream_entry[20:24], "little"),
                "data_length": int.from_bytes(stream_entry[24:32], "little"),
                "stored_set_checksum": f"0x{stored_checksum:04X}",
                "calculated_restored_set_checksum": f"0x{calculated:04X}",
                "checksum_valid_after_in_use_restore": True,
            })
            index += total

        active_root_sets, active_root_errors = self._parse_exfat_file_sets(
            data, entry_offsets, in_use=True, upcase_mapping=upcase_mapping,
        )
        errors.extend(f"active root {error}" for error in active_root_errors[:64])
        directory_queue = [
            {
                **item,
                "parent_cluster_lineage": [],
                "directory_source_entry_offset": item.get("offset"),
            }
            for item in active_root_sets
            if int(str(item.get("attributes", "0")), 16) & 0x10
        ][:64]
        subdirectory_deleted_sets: list[dict[str, object]] = []
        directory_inventory: list[dict[str, object]] = []
        directory_errors: list[str] = []
        visited_directory_starts: set[int] = set()
        visited_directory_clusters = {int(item["cluster"]) for item in segments}
        visited_directory_clusters.update(int(item["cluster"]) for item in bitmap_segments)
        for table in upcase_tables:
            visited_directory_clusters.update(
                int(item["cluster"]) for item in table.get("cluster_segments", [])
            )
        total_directory_clusters = 0
        total_directory_bytes = 0
        while directory_queue and len(directory_inventory) < 32:
            directory = directory_queue.pop(0)
            start_cluster = directory.get("first_cluster")
            data_length = directory.get("data_length")
            valid_length = directory.get("valid_data_length")
            try:
                directory_flags = int(str(directory.get("stream_flags")), 16)
            except ValueError:
                continue
            if (
                not isinstance(start_cluster, int) or start_cluster in visited_directory_starts
                or not isinstance(data_length, int) or not 0 < data_length <= 8 * _MIB
                or valid_length != data_length
            ):
                continue
            required_clusters = (data_length + cluster_size - 1) // cluster_size
            if (
                required_clusters < 1 or total_directory_clusters + required_clusters > 64
                or total_directory_bytes + data_length > 8 * _MIB
            ):
                directory_errors.append(
                    f"directory cluster {start_cluster}: shared 32-directory/64-cluster/8-MiB bound reached"
                )
                continue
            visited_directory_starts.add(start_cluster)
            directory_data: bytes | None = None
            directory_segments: list[dict[str, int]] = []
            mapping_mode = "nofatchain_contiguous" if directory_flags & 0x02 else "fat_chain_eoc"
            mapping_error = ""
            if directory_flags & 0x02:
                contiguous = list(range(start_cluster, start_cluster + required_clusters))
                if not all(2 <= cluster < cluster_count + 2 for cluster in contiguous):
                    mapping_error = "volume_bounds"
                elif any(cluster in visited_directory_clusters for cluster in contiguous):
                    mapping_error = "loop_or_shared_cluster"
                else:
                    payload = bytearray()
                    try:
                        with path.open("rb") as directory_stream:
                            for cluster in contiguous:
                                physical_offset = (
                                    heap_offset + (cluster - 2) * sectors_per_cluster
                                ) * bytes_per_sector
                                if physical_offset < 0 or physical_offset + cluster_size > image_size:
                                    mapping_error = "image_bounds"
                                    break
                                take = min(cluster_size, data_length - len(payload))
                                directory_stream.seek(physical_offset)
                                chunk = directory_stream.read(take)
                                if len(chunk) != take:
                                    mapping_error = "truncated_read"
                                    break
                                payload.extend(chunk)
                                directory_segments.append({
                                    "cluster": cluster, "offset": physical_offset,
                                    "length": cluster_size, "data_length": take,
                                })
                    except OSError:
                        mapping_error = "read_error"
                    if not mapping_error and len(payload) == data_length:
                        directory_data = bytes(payload)
            else:
                directory_data, directory_segments, mapping_error = read_exact_fat_chain(
                    start_cluster, data_length
                )
                mapped_clusters = [int(item["cluster"]) for item in directory_segments]
                if directory_data is not None and any(
                    cluster in visited_directory_clusters for cluster in mapped_clusters
                ):
                    directory_data = None
                    mapping_error = "loop_or_shared_cluster"
            if directory_data is None:
                directory_errors.append(
                    f"directory cluster {start_cluster}: {mapping_mode} mapping failed ({mapping_error})"
                )
                continue
            mapped_clusters = [int(item["cluster"]) for item in directory_segments]
            visited_directory_clusters.update(mapped_clusters)
            total_directory_clusters += len(mapped_clusters)
            total_directory_bytes += len(directory_data)
            directory_offsets: list[int] = []
            for segment in directory_segments:
                directory_offsets.extend(
                    int(segment["offset"]) + part * 32
                    for part in range(int(segment["data_length"]) // 32)
                )
            directory_record = {
                "name": directory.get("name"),
                "start_cluster": start_cluster,
                "data_length": data_length,
                "stream_flags": directory.get("stream_flags"),
                "mapping_mode": mapping_mode,
                "source_entry_offset": directory.get("offset"),
                "parent_cluster_lineage": directory.get("parent_cluster_lineage", []),
                "cluster_chain": directory_segments,
                "termination": "contiguous_extent" if directory_flags & 0x02 else "eoc",
            }
            directory_inventory.append(directory_record)
            contained_deleted, contained_errors = self._parse_exfat_file_sets(
                directory_data, directory_offsets, in_use=False, upcase_mapping=upcase_mapping,
            )
            directory_errors.extend(
                f"directory cluster {start_cluster} {error}" for error in contained_errors[:64]
            )
            for item in contained_deleted:
                if len(subdirectory_deleted_sets) >= 512:
                    break
                subdirectory_deleted_sets.append({
                    **item,
                    "directory_start_cluster": start_cluster,
                    "directory_name": directory.get("name"),
                    "directory_cluster_lineage": mapped_clusters,
                    "directory_source_entry_offset": directory.get("offset"),
                })
            active_children, child_errors = self._parse_exfat_file_sets(
                directory_data, directory_offsets, in_use=True, upcase_mapping=upcase_mapping,
            )
            directory_errors.extend(
                f"directory cluster {start_cluster} {error}" for error in child_errors[:64]
            )
            for child in active_children:
                try:
                    child_attributes = int(str(child.get("attributes", "0")), 16)
                except ValueError:
                    continue
                if child_attributes & 0x10 and len(directory_queue) < 64:
                    directory_queue.append({
                        **child,
                        "parent_cluster_lineage": mapped_clusters,
                        "directory_source_entry_offset": child.get("offset"),
                    })
        if directory_queue:
            directory_errors.append("active exFAT subdirectory traversal reached the 32-directory bound")

        all_deleted_sets = [*deleted_sets, *subdirectory_deleted_sets]
        if bitmap_bytes is not None:
            def bitmap_allocated(cluster: int) -> bool:
                bit_index = cluster - 2
                return bool(bitmap_bytes[bit_index // 8] & (1 << (bit_index % 8)))

            allocated_count = sum(byte.bit_count() for byte in bitmap_bytes)
            active_bitmap_candidates[0]["allocated_cluster_count"] = allocated_count
            system_clusters = [item["cluster"] for item in segments]
            system_clusters.extend(item["cluster"] for item in bitmap_segments)
            if valid_upcase_candidates and valid_upcase_candidates[0].get("validation") == "valid":
                system_clusters.extend(
                    item["cluster"] for item in valid_upcase_candidates[0].get("cluster_segments", [])
                )
            free_system_clusters = [cluster for cluster in sorted(set(system_clusters)) if not bitmap_allocated(cluster)]
            active_bitmap_candidates[0]["system_clusters_marked_free"] = free_system_clusters
            active_bitmap_candidates[0]["system_allocation_consistent"] = not free_system_clusters

            try:
                with path.open("rb") as fat_stream:
                    for deleted in all_deleted_sets:
                        data_length = deleted.get("data_length")
                        first_cluster = deleted.get("first_cluster")
                        stream_flags = int(str(deleted.get("stream_flags")), 16)
                        if (
                            not isinstance(data_length, int) or not 0 < data_length <= 8 * _MIB
                            or not isinstance(first_cluster, int)
                        ):
                            continue
                        required_clusters = (data_length + cluster_size - 1) // cluster_size
                        if not 1 <= required_clusters <= 64:
                            continue
                        candidate_clusters: list[int] = []
                        if stream_flags & 0x02:
                            candidate_clusters = list(range(first_cluster, first_cluster + required_clusters))
                            if not all(2 <= cluster < cluster_count + 2 for cluster in candidate_clusters):
                                candidate_clusters = []
                        else:
                            current_cluster = first_cluster
                            seen_clusters: set[int] = set()
                            for cluster_index in range(required_clusters):
                                if current_cluster in seen_clusters or not 2 <= current_cluster < cluster_count + 2:
                                    candidate_clusters = []
                                    break
                                seen_clusters.add(current_cluster)
                                candidate_clusters.append(current_cluster)
                                fat_entry_offset = fat_byte_offset + current_cluster * 4
                                if fat_entry_offset + 4 > min(fat_byte_end, image_size):
                                    candidate_clusters = []
                                    break
                                fat_stream.seek(fat_entry_offset)
                                raw_next = fat_stream.read(4)
                                if len(raw_next) != 4:
                                    candidate_clusters = []
                                    break
                                next_cluster = int.from_bytes(raw_next, "little")
                                if cluster_index == required_clusters - 1:
                                    if next_cluster < 0xFFFFFFF8:
                                        candidate_clusters = []
                                    break
                                if (
                                    next_cluster < 2 or next_cluster >= 0xFFFFFFF8
                                    or next_cluster == 0xFFFFFFF7
                                    or 0xFFFFFFF0 <= next_cluster <= 0xFFFFFFF6
                                ):
                                    candidate_clusters = []
                                    break
                                current_cluster = next_cluster
                        if candidate_clusters:
                            cluster_states = [
                                {"cluster": cluster, "allocated": bitmap_allocated(cluster)}
                                for cluster in candidate_clusters
                            ]
                            reuse_warning = any(item["allocated"] for item in cluster_states)
                            deleted["allocation_bitmap_cluster_states"] = cluster_states
                            deleted["allocation_bitmap_state"] = (
                                "one_or_more_clusters_currently_allocated_possible_reuse"
                                if reuse_warning else "all_candidate_clusters_currently_clear"
                            )
                            deleted["allocation_reuse_warning"] = reuse_warning
                            deleted["allocation_bitmap_interpretation"] = (
                                "current_allocation_state_only_not_deleted_file_ownership"
                            )
            except OSError as exc:
                errors.append(f"allocation bitmap correlation failed: {str(exc)[:500]}")
        return [
            self._observation(artifact, f"{prefix}.root_available", True),
            self._observation(artifact, f"{prefix}.bytes_per_sector", bytes_per_sector),
            self._observation(artifact, f"{prefix}.cluster_size", cluster_size),
            self._observation(artifact, f"{prefix}.sectors_per_cluster", sectors_per_cluster),
            self._observation(artifact, f"{prefix}.cluster_heap_offset_sectors", heap_offset),
            self._observation(artifact, f"{prefix}.fat_offset_sectors", fat_offset),
            self._observation(artifact, f"{prefix}.fat_length_sectors", fat_length),
            self._observation(artifact, f"{prefix}.cluster_count", cluster_count),
            self._observation(artifact, f"{prefix}.active_fat", active_fat),
            self._observation(artifact, f"{prefix}.root_cluster", root_cluster),
            self._observation(artifact, f"{prefix}.root_offset", root_offset),
            self._observation(artifact, f"{prefix}.root_cluster_segments", segments),
            self._observation(artifact, f"{prefix}.root_chain_termination", termination),
            self._observation(artifact, f"{prefix}.root_chain_truncated", termination == "limit"),
            self._observation(artifact, f"{prefix}.allocation_bitmaps", allocation_bitmaps),
            self._observation(artifact, f"{prefix}.upcase_tables", upcase_tables),
            self._observation(artifact, f"{prefix}.deleted_file_sets", deleted_sets),
            self._observation(artifact, f"{prefix}.subdirectory_deleted_file_sets", subdirectory_deleted_sets),
            self._observation(artifact, f"{prefix}.subdirectory_inventory", directory_inventory),
            self._observation(artifact, f"{prefix}.subdirectory_errors", directory_errors[:256]),
            self._observation(artifact, f"{prefix}.deleted_file_set_errors", errors[:256]),
        ]

    @staticmethod
    def _exfat_entry_set_checksum(entries: list[bytes]) -> int:
        checksum = 0
        for entry_index, entry in enumerate(entries):
            for byte_index, value in enumerate(entry):
                if entry_index == 0 and byte_index in {2, 3}:
                    continue
                checksum = ((checksum << 15) | (checksum >> 1)) & 0xFFFF
                checksum = (checksum + value) & 0xFFFF
        return checksum

    @classmethod
    def _parse_exfat_file_sets(
        cls,
        data: bytes,
        entry_offsets: list[int],
        *,
        in_use: bool,
        upcase_mapping: list[int] | None,
    ) -> tuple[list[dict[str, object]], list[str]]:
        """Parse complete active or deletion-cleared exFAT file entry sets."""
        parsed: list[dict[str, object]] = []
        errors: list[str] = []
        primary_type = 0x85 if in_use else 0x05
        stream_type = 0xC0 if in_use else 0x40
        name_type = 0xC1 if in_use else 0x41
        index = 0
        entry_count = min(len(data) // 32, len(entry_offsets), 2_048)
        while index < entry_count and len(parsed) < 512:
            primary = data[index * 32:(index + 1) * 32]
            if primary[0] == 0:
                break
            if primary[0] != primary_type:
                index += 1
                continue
            secondary_count = primary[1]
            total = secondary_count + 1
            if not 2 <= secondary_count <= 18 or index + total > entry_count:
                errors.append(f"entry {index}: invalid file-entry set length")
                index += 1
                continue
            entries = [data[(index + part) * 32:(index + part + 1) * 32] for part in range(total)]
            stream_entry, names = entries[1], entries[2:]
            name_length = stream_entry[3]
            if (
                stream_entry[0] != stream_type or stream_entry[1] & 0xFC
                or not 1 <= name_length <= 255
                or len(names) != (name_length + 14) // 15
                or any(item[0] != name_type for item in names)
            ):
                errors.append(f"entry {index}: invalid stream/name sequence")
                index += total
                continue
            checksum_entries = entries if in_use else [bytes([item[0] | 0x80]) + item[1:] for item in entries]
            stored_checksum = int.from_bytes(primary[2:4], "little")
            calculated_checksum = cls._exfat_entry_set_checksum(checksum_entries)
            raw_name = b"".join(item[2:32] for item in names)
            if calculated_checksum != stored_checksum or any(raw_name[name_length * 2:]):
                errors.append(f"entry {index}: checksum or name padding is invalid")
                index += total
                continue
            try:
                name = raw_name[:name_length * 2].decode("utf-16le")
            except UnicodeDecodeError:
                name = ""
            if not name or any(ord(char) < 32 or char in '\\/:*?"<>|' for char in name):
                errors.append(f"entry {index}: invalid UTF-16 filename")
                index += total
                continue
            stored_name_hash = int.from_bytes(stream_entry[4:6], "little")
            calculated_name_hash = (
                cls._exfat_name_hash(raw_name[:name_length * 2], upcase_mapping)
                if upcase_mapping is not None else None
            )
            record: dict[str, object] = {
                "entry_index": index,
                "offset": entry_offsets[index],
                "secondary_count": secondary_count,
                "entry_offsets": [entry_offsets[index + part] for part in range(total)],
                "name": name,
                "attributes": f"0x{int.from_bytes(primary[4:6], 'little'):04X}",
                "stream_flags": f"0x{stream_entry[1]:02X}",
                "name_hash": f"0x{stored_name_hash:04X}",
                "calculated_name_hash": (
                    f"0x{calculated_name_hash:04X}" if calculated_name_hash is not None else None
                ),
                "name_hash_validation": (
                    "valid" if calculated_name_hash == stored_name_hash
                    else "mismatch" if calculated_name_hash is not None
                    else "not_verified_without_upcase_table"
                ),
                "valid_data_length": int.from_bytes(stream_entry[8:16], "little"),
                "first_cluster": int.from_bytes(stream_entry[20:24], "little"),
                "data_length": int.from_bytes(stream_entry[24:32], "little"),
                "stored_set_checksum": f"0x{stored_checksum:04X}",
            }
            if in_use:
                record["calculated_set_checksum"] = f"0x{calculated_checksum:04X}"
                record["checksum_valid"] = True
            else:
                record["calculated_restored_set_checksum"] = f"0x{calculated_checksum:04X}"
                record["checksum_valid_after_in_use_restore"] = True
            parsed.append(record)
            index += total
        return parsed, errors

    @staticmethod
    def _exfat_upcase_checksum(data: bytes) -> int:
        checksum = 0
        for value in data:
            checksum = ((checksum << 31) | (checksum >> 1)) & 0xFFFFFFFF
            checksum = (checksum + value) & 0xFFFFFFFF
        return checksum

    @staticmethod
    def _decode_exfat_upcase_table(data: bytes) -> list[int] | None:
        if not data or len(data) % 2:
            return None
        words = [int.from_bytes(data[offset:offset + 2], "little") for offset in range(0, len(data), 2)]
        mapping: list[int] = []
        index = 0
        while index < len(words) and len(mapping) < 65_536:
            value = words[index]
            index += 1
            if value == 0xFFFF and not (len(mapping) == 0xFFFF and index == len(words)):
                if index >= len(words):
                    return None
                run_length = words[index]
                index += 1
                if run_length == 0 or len(mapping) + run_length > 65_536:
                    return None
                mapping.extend(range(len(mapping), len(mapping) + run_length))
            else:
                mapping.append(value)
        return mapping if len(mapping) == 65_536 and index == len(words) else None

    @staticmethod
    def _exfat_name_hash(raw_utf16le: bytes, upcase_mapping: list[int]) -> int:
        name_hash = 0
        for offset in range(0, len(raw_utf16le), 2):
            code_unit = int.from_bytes(raw_utf16le[offset:offset + 2], "little")
            upper = upcase_mapping[code_unit]
            for value in (upper & 0xFF, upper >> 8):
                name_hash = ((name_hash << 15) | (name_hash >> 1)) & 0xFFFF
                name_hash = (name_hash + value) & 0xFFFF
        return name_hash

    def _inspect_fat_duplicate_tables(
        self,
        artifact: Artifact,
        path: Path,
        image_size: int,
        header: bytes,
        bytes_per_sector: int,
        sectors_per_cluster: int,
        reserved_sectors: int,
        fat_count: int,
        fat_size: int,
        *,
        fat_bits: int,
    ) -> list[Observation]:
        """Compare declared FAT tables without inferring an authoritative copy."""
        variant = f"fat{fat_bits}"
        prefix = f"filesystem.{variant}.fat_copies"
        root_entries = int.from_bytes(header[17:19], "little")
        total_sectors = (
            int.from_bytes(header[19:21], "little")
            or int.from_bytes(header[32:36], "little")
        )
        root_sectors = (
            (root_entries * 32 + bytes_per_sector - 1) // bytes_per_sector
            if bytes_per_sector and fat_bits != 32 else 0
        )
        first_data_sector = reserved_sectors + fat_count * fat_size + root_sectors
        data_sectors = total_sectors - first_data_sector
        cluster_count = data_sectors // sectors_per_cluster if sectors_per_cluster else 0
        fat_size_bytes = fat_size * bytes_per_sector
        fat_entry_capacity = (
            fat_size_bytes // 4 if fat_bits == 32
            else fat_size_bytes // 2 if fat_bits == 16
            else fat_size_bytes * 2 // 3 if fat_bits == 12
            else 0
        )
        geometry_valid = (
            bytes_per_sector in {512, 1024, 2048, 4096}
            and sectors_per_cluster > 0
            and sectors_per_cluster & (sectors_per_cluster - 1) == 0
            and sectors_per_cluster <= 128 and reserved_sectors > 0
            and 1 <= fat_count <= 4 and fat_size > 0
            and (fat_bits == 32 or 0 < root_entries <= 65_535)
            and total_sectors > first_data_sector
            and (
                (fat_bits == 32 and cluster_count >= 65_525)
                or (fat_bits == 16 and 4_085 <= cluster_count < 65_525)
                or (fat_bits == 12 and 0 < cluster_count < 4_085)
            )
            and fat_entry_capacity >= cluster_count + 2
        )
        comparison_limit = 8 * _MIB
        media_descriptor = header[21] if len(header) > 21 else 0
        inventory: dict[str, object] = {
            "available": geometry_valid and fat_count >= 2,
            "variant": variant,
            "declared_count": fat_count,
            "media_descriptor": f"0x{media_descriptor:02X}",
            "media_descriptor_valid": media_descriptor == 0xF0 or 0xF8 <= media_descriptor <= 0xFF,
            "fat_size_bytes": fat_size_bytes,
            "cluster_count": cluster_count,
            "fat_entry_capacity": fat_entry_capacity,
            "comparison_limit_bytes": comparison_limit,
            "reference_copy_index": 0,
            "authoritative_copy_selected": False,
            "copies": [],
            "comparisons": [],
            "all_copies_match": None,
        }
        if fat_bits == 32:
            ext_flags = int.from_bytes(header[40:42], "little") if len(header) >= 42 else 0
            mirroring_enabled = not bool(ext_flags & 0x0080)
            active_copy_index = 0 if mirroring_enabled else ext_flags & 0x000F
            inventory.update({
                "ext_flags": f"0x{ext_flags:04X}",
                "mirroring_enabled": mirroring_enabled,
                "copies_expected_to_match": mirroring_enabled,
                "active_copy_index": active_copy_index,
                "active_copy_index_valid": active_copy_index < fat_count,
                "ext_flags_reserved_bits_zero": not bool(ext_flags & 0xFF70),
                "selection_basis": (
                    "mirroring_enabled_reference_copy_zero"
                    if mirroring_enabled else "bpb_extflags_active_copy"
                ),
            })
        if not geometry_valid:
            inventory["reason"] = f"invalid {variant.upper()} allocation-table geometry"
            return [self._observation(artifact, prefix, inventory)]

        declared_volume_bytes = total_sectors * bytes_per_sector
        copies: list[dict[str, object]] = []
        for copy_index in range(fat_count):
            offset = (reserved_sectors + copy_index * fat_size) * bytes_per_sector
            end_offset = offset + fat_size_bytes
            within_declared_volume = end_offset <= declared_volume_bytes
            within_supplied_image = end_offset <= image_size
            copy_record: dict[str, object] = {
                "index": copy_index,
                "offset": offset,
                "end_offset": end_offset,
                "length": fat_size_bytes,
                "within_declared_volume": within_declared_volume,
                "within_supplied_image": within_supplied_image,
                "available": within_declared_volume and within_supplied_image,
            }
            if not within_declared_volume:
                copy_record["reason"] = "declared FAT range exceeds declared volume"
            elif not within_supplied_image:
                copy_record["reason"] = "declared FAT range exceeds supplied image"
            copies.append(copy_record)
        inventory["copies"] = copies
        reserved_width = 3 if fat_bits == 12 else 4 if fat_bits == 16 else 8
        try:
            with path.open("rb") as stream:
                for copy_record in copies:
                    if copy_record["available"] is not True:
                        continue
                    stream.seek(int(copy_record["offset"]))
                    reserved = stream.read(reserved_width)
                    if len(reserved) != reserved_width:
                        copy_record["reserved_entries"] = {
                            "available": False,
                            "reason": "truncated reserved-entry read",
                            "bytes_read": len(reserved),
                        }
                        continue
                    if fat_bits == 12:
                        entry0 = reserved[0] | ((reserved[1] & 0x0F) << 8)
                        entry1 = (reserved[1] >> 4) | (reserved[2] << 4)
                        reserved_entries: dict[str, object] = {
                            "available": True,
                            "raw_hex": reserved.hex(),
                            "entry0_offset": copy_record["offset"],
                            "entry1_packed_offset": int(copy_record["offset"]) + 1,
                            "entry0": f"0x{entry0:03X}",
                            "entry1": f"0x{entry1:03X}",
                            "entry0_media_matches": entry0 & 0xFF == media_descriptor,
                            "entry0_reserved_bits_valid": entry0 & 0xF00 == 0xF00,
                            "entry1_eoc_valid": entry1 >= 0xFF8,
                        }
                    elif fat_bits == 16:
                        entry0 = int.from_bytes(reserved[0:2], "little")
                        entry1 = int.from_bytes(reserved[2:4], "little")
                        reserved_entries = {
                            "available": True,
                            "raw_hex": reserved.hex(),
                            "entry0_offset": copy_record["offset"],
                            "entry1_offset": int(copy_record["offset"]) + 2,
                            "entry0": f"0x{entry0:04X}",
                            "entry1": f"0x{entry1:04X}",
                            "entry0_media_matches": entry0 & 0xFF == media_descriptor,
                            "entry0_reserved_bits_valid": entry0 & 0xFF00 == 0xFF00,
                            "entry1_eoc_valid": entry1 & 0x3FFF >= 0x3FF8,
                            "entry1_clean_shutdown": bool(entry1 & 0x8000),
                            "entry1_no_io_errors": bool(entry1 & 0x4000),
                        }
                    else:
                        raw_entry0 = int.from_bytes(reserved[0:4], "little")
                        raw_entry1 = int.from_bytes(reserved[4:8], "little")
                        entry0 = raw_entry0 & 0x0FFFFFFF
                        entry1 = raw_entry1 & 0x0FFFFFFF
                        reserved_entries = {
                            "available": True,
                            "raw_hex": reserved.hex(),
                            "entry0_offset": copy_record["offset"],
                            "entry1_offset": int(copy_record["offset"]) + 4,
                            "entry0_raw": f"0x{raw_entry0:08X}",
                            "entry1_raw": f"0x{raw_entry1:08X}",
                            "entry0_masked": f"0x{entry0:08X}",
                            "entry1_masked": f"0x{entry1:08X}",
                            "entry0_reserved_high_nibble": raw_entry0 >> 28,
                            "entry1_reserved_high_nibble": raw_entry1 >> 28,
                            "entry0_media_matches": entry0 & 0xFF == media_descriptor,
                            "entry0_reserved_bits_valid": entry0 & 0x0FFFFF00 == 0x0FFFFF00,
                            "entry1_eoc_valid": entry1 & 0x03FFFFFF >= 0x03FFFFF8,
                            "entry1_clean_shutdown": bool(entry1 & 0x08000000),
                            "entry1_no_io_errors": bool(entry1 & 0x04000000),
                        }
                    reserved_entries["valid"] = (
                        reserved_entries["entry0_media_matches"] is True
                        and reserved_entries["entry0_reserved_bits_valid"] is True
                        and reserved_entries["entry1_eoc_valid"] is True
                    )
                    copy_record["reserved_entries"] = reserved_entries
        except OSError as exc:
            inventory["reserved_entry_error"] = str(exc)[:2_000]
        if fat_bits == 32:
            active_copy_index = inventory["active_copy_index"]
            inventory["active_copy_available"] = (
                isinstance(active_copy_index, int)
                and active_copy_index < len(copies)
                and copies[active_copy_index]["available"] is True
            )
        if fat_count < 2:
            inventory["reason"] = "fewer than two FAT copies are declared"
            return [self._observation(artifact, prefix, inventory)]

        comparisons: list[dict[str, object]] = []
        reference = copies[0]
        try:
            with path.open("rb") as stream:
                for copy_record in copies[1:]:
                    comparison: dict[str, object] = {
                        "reference_index": 0,
                        "compared_index": copy_record["index"],
                        "available": bool(reference["available"] and copy_record["available"]),
                        "compared_bytes": 0,
                        "full_table_compared": False,
                        "match": None,
                        "first_difference": None,
                    }
                    if not comparison["available"]:
                        comparison["reason"] = "one or both declared FAT copies are unavailable"
                        comparisons.append(comparison)
                        continue
                    scan_bytes = min(fat_size_bytes, comparison_limit)
                    scanned = 0
                    difference: dict[str, object] | None = None
                    while scanned < scan_bytes:
                        take = min(64 * 1024, scan_bytes - scanned)
                        stream.seek(int(reference["offset"]) + scanned)
                        reference_chunk = stream.read(take)
                        stream.seek(int(copy_record["offset"]) + scanned)
                        compared_chunk = stream.read(take)
                        if len(reference_chunk) != take or len(compared_chunk) != take:
                            comparison["reason"] = "truncated FAT comparison read"
                            break
                        relative = next(
                            (
                                index for index, (reference_byte, compared_byte)
                                in enumerate(zip(reference_chunk, compared_chunk, strict=True))
                                if reference_byte != compared_byte
                            ),
                            None,
                        )
                        if relative is not None:
                            relative += scanned
                            difference = {
                                "relative_offset": relative,
                                "reference_absolute_offset": int(reference["offset"]) + relative,
                                "compared_absolute_offset": int(copy_record["offset"]) + relative,
                                "reference_byte": f"0x{reference_chunk[relative - scanned]:02X}",
                                "compared_byte": f"0x{compared_chunk[relative - scanned]:02X}",
                            }
                            scanned = relative + 1
                            break
                        scanned += take
                    comparison["compared_bytes"] = scanned
                    comparison["first_difference"] = difference
                    if difference is not None:
                        comparison["match"] = False
                    elif scanned == fat_size_bytes:
                        comparison["full_table_compared"] = True
                        comparison["match"] = True
                    elif scanned == comparison_limit and fat_size_bytes > comparison_limit:
                        comparison["comparison_bound_reached"] = True
                        comparison["reason"] = "declared FAT exceeds bounded comparison limit"
                    comparisons.append(comparison)
        except OSError as exc:
            inventory["error"] = str(exc)[:2_000]
        inventory["comparisons"] = comparisons
        matches = [comparison.get("match") for comparison in comparisons]
        if any(match is False for match in matches):
            inventory["all_copies_match"] = False
        elif len(matches) == fat_count - 1 and all(match is True for match in matches):
            inventory["all_copies_match"] = True
        return [self._observation(artifact, prefix, inventory)]

    def _inspect_fat_fixed_root_directory(
        self,
        artifact: Artifact,
        path: Path,
        image_size: int,
        header: bytes,
        bytes_per_sector: int,
        sectors_per_cluster: int,
        reserved_sectors: int,
        fat_count: int,
        fat_size: int,
        *,
        fat_bits: int,
    ) -> list[Observation]:
        variant = f"fat{fat_bits}"
        prefix = f"filesystem.{variant}.root"
        root_entries = int.from_bytes(header[17:19], "little")
        total_sectors = (
            int.from_bytes(header[19:21], "little")
            or int.from_bytes(header[32:36], "little")
        )
        cluster_size = bytes_per_sector * sectors_per_cluster
        root_logical_bytes = root_entries * 32
        root_sectors = (
            (root_logical_bytes + bytes_per_sector - 1) // bytes_per_sector
            if bytes_per_sector else 0
        )
        root_sector = reserved_sectors + fat_count * fat_size
        first_data_sector = root_sector + root_sectors
        data_sectors = total_sectors - first_data_sector
        cluster_count = data_sectors // sectors_per_cluster if sectors_per_cluster else 0
        fat_bytes = fat_size * bytes_per_sector
        fat_entry_capacity = (
            fat_bytes // 2 if fat_bits == 16
            else fat_bytes * 2 // 3 if fat_bits == 12
            else 0
        )
        root_offset = root_sector * bytes_per_sector
        root_storage_bytes = root_sectors * bytes_per_sector
        valid_geometry = (
            bytes_per_sector in {512, 1024, 2048, 4096}
            and sectors_per_cluster > 0
            and sectors_per_cluster & (sectors_per_cluster - 1) == 0
            and sectors_per_cluster <= 128 and reserved_sectors > 0
            and 1 <= fat_count <= 4 and fat_size > 0
            and 0 < root_entries <= 65_535 and 0 < root_logical_bytes <= 8 * _MIB
            and total_sectors > first_data_sector
            and (
                (fat_bits == 16 and 4_085 <= cluster_count < 65_525)
                or (fat_bits == 12 and 0 < cluster_count < 4_085)
            )
            and fat_entry_capacity >= cluster_count + 2
            and root_offset >= 0 and root_storage_bytes >= root_logical_bytes
            and root_offset + root_storage_bytes <= image_size
            and (root_sector + root_sectors) <= total_sectors
            and 0 < cluster_size <= 2 * _MIB
        )
        if not valid_geometry:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.offset", root_offset if bytes_per_sector else None),
                self._observation(artifact, f"{prefix}.error", f"invalid {variant.upper()} fixed-root geometry"),
            ]
        try:
            with path.open("rb") as stream:
                stream.seek(root_offset)
                stored = stream.read(root_storage_bytes)
        except OSError as exc:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.error", str(exc)[:2_000], confidence=0.9),
            ]
        if len(stored) != root_storage_bytes:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.error", f"truncated {variant.upper()} fixed-root directory"),
            ]
        data = stored[:root_logical_bytes]
        entry_offsets = [root_offset + index * 32 for index in range(root_entries)]
        fat_offset = reserved_sectors * bytes_per_sector
        fat_end = fat_offset + fat_size * bytes_per_sector
        (
            subdirectory_entries, subdirectory_inventory, subdirectory_errors,
            active_cluster_starts, subdirectory_active_files,
            subdirectory_unlinked_lfn_slots,
        ) = (
            self._fat_fixed_subdirectory_deleted_entries(
                path, image_size, data, entry_offsets, bytes_per_sector,
                sectors_per_cluster, first_data_sector, fat_offset, fat_end,
                cluster_count, fat_bits=fat_bits,
            )
        )
        lost_chains = self._fat_lost_chain_inventory(
            path, image_size, bytes_per_sector, sectors_per_cluster,
            first_data_sector, fat_offset, fat_end, cluster_count,
            active_cluster_starts, fat_bits=fat_bits,
            directory_reference_scope_limited=(
                root_entries > 4_096 or bool(subdirectory_errors)
            ),
        )
        deleted_entries: list[dict[str, object]] = []
        active_regular_files: list[dict[str, object]] = []
        unlinked_lfn_slots: list[dict[str, object]] = []
        pending_lfn: list[tuple[int, bytes]] = []
        examined = 0
        scan_limit = min(root_entries, 4_096)
        for index in range(scan_limit):
            entry = data[index * 32:(index + 1) * 32]
            if entry[0] == 0:
                if pending_lfn:
                    deleted_slots = all(slot[0] == 0xE5 for _, slot in pending_lfn)
                    unlinked_lfn_slots.append({
                        "short_entry_index": None, "short_entry_offset": None,
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": (
                            "deleted LFN slots are not followed by a deleted short entry"
                            if deleted_slots else "LFN slots are not followed by a short entry"
                        ),
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
                break
            examined += 1
            attributes = entry[11]
            if attributes == 0x0F:
                if len(pending_lfn) < 21:
                    pending_lfn.append((index, entry))
                continue
            if entry[0] != 0xE5:
                if pending_lfn and any(slot[0] == 0xE5 for _, slot in pending_lfn):
                    unlinked_lfn_slots.append({
                        "short_entry_index": index,
                        "short_entry_offset": entry_offsets[index],
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": "deleted LFN slots are followed by an active short entry",
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
                elif pending_lfn and attributes & 0x08:
                    unlinked_lfn_slots.append({
                        "short_entry_index": index,
                        "short_entry_offset": entry_offsets[index],
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": "LFN slots are followed by an incompatible volume-label entry",
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
                elif pending_lfn and attributes & 0x10:
                    directory_lfn, lfn_error = self._fat_active_lfn_candidate(
                        pending_lfn, entry, entry_offsets,
                    )
                    if directory_lfn is not None:
                        directory_record = next(
                            (
                                item for item in subdirectory_inventory
                                if item.get("source_entry_offset") == entry_offsets[index]
                            ),
                            None,
                        )
                        if directory_record is not None:
                            directory_record.update(directory_lfn)
                    else:
                        unlinked_lfn_slots.append({
                            "short_entry_index": index,
                            "short_entry_offset": entry_offsets[index],
                            "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                            "reason": lfn_error,
                            "raw_hex": [slot.hex() for _, slot in pending_lfn],
                        })
                elif not attributes & 0x18:
                    first_cluster = int.from_bytes(entry[26:28], "little")
                    high_reserved = int.from_bytes(entry[20:22], "little")
                    file_size = int.from_bytes(entry[28:32], "little")
                    if (
                        high_reserved == 0 and 2 <= first_cluster < cluster_count + 2
                        and 0 < file_size <= 8 * _MIB
                    ):
                        short_raw = bytes([0xE5]) + entry[1:11] if entry[0] == 0x05 else entry[:11]
                        base = short_raw[:8].decode("cp437", errors="replace").rstrip(" ")
                        extension = short_raw[8:11].decode("cp437", errors="replace").rstrip(" ")
                        active_file: dict[str, object] = {
                            "entry_index": index, "offset": entry_offsets[index],
                            "short_name": base + (f".{extension}" if extension else ""),
                            "attributes": f"0x{attributes:02X}",
                            "first_cluster": first_cluster,
                            "cluster_high_reserved": high_reserved,
                            f"{variant}_cluster_high_reserved": high_reserved,
                            "size": file_size, "raw_hex": entry.hex(),
                        }
                        if pending_lfn:
                            lfn, lfn_error = self._fat_active_lfn_candidate(
                                pending_lfn, entry, entry_offsets,
                            )
                            if lfn is not None:
                                active_file.update(lfn)
                            else:
                                unlinked_lfn_slots.append({
                                    "short_entry_index": index,
                                    "short_entry_offset": entry_offsets[index],
                                    "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                                    "reason": lfn_error,
                                    "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                })
                        active_regular_files.append(active_file)
                pending_lfn = []
                continue
            base = entry[1:8].decode("cp437", errors="replace").rstrip(" ")
            extension = entry[8:11].decode("cp437", errors="replace").rstrip(" ")
            recovered: dict[str, object] = {
                "entry_index": index, "offset": entry_offsets[index],
                "short_name": f"?{base}" + (f".{extension}" if extension else ""),
                "first_character_unknown": True, "attributes": f"0x{attributes:02X}",
                "first_cluster": int.from_bytes(entry[26:28], "little"),
                "cluster_high_reserved": int.from_bytes(entry[20:22], "little"),
                f"{variant}_cluster_high_reserved": int.from_bytes(entry[20:22], "little"),
                "size": int.from_bytes(entry[28:32], "little"),
                "created": self._fat_datetime(
                    int.from_bytes(entry[16:18], "little"),
                    int.from_bytes(entry[14:16], "little"), entry[13],
                ),
                "accessed": self._fat_datetime(int.from_bytes(entry[18:20], "little"), 0),
                "modified": self._fat_datetime(
                    int.from_bytes(entry[24:26], "little"),
                    int.from_bytes(entry[22:24], "little"),
                ),
                "raw_hex": entry.hex(),
            }
            if pending_lfn:
                lfn, lfn_error = self._fat_deleted_lfn_candidate(pending_lfn, entry, entry_offsets)
                if lfn is not None:
                    recovered.update(lfn)
                else:
                    unlinked_lfn_slots.append({
                        "short_entry_index": index,
                        "short_entry_offset": entry_offsets[index],
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": lfn_error,
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
            deleted_entries.append(recovered)
            pending_lfn = []
            if len(deleted_entries) >= 256:
                break
        return [
            self._observation(artifact, f"{prefix}.available", True),
            self._observation(artifact, f"{prefix}.offset", root_offset),
            self._observation(artifact, f"{prefix}.storage_bytes", root_storage_bytes),
            self._observation(artifact, f"{prefix}.logical_bytes", root_logical_bytes),
            self._observation(artifact, f"{prefix}.declared_entries", root_entries),
            self._observation(artifact, f"{prefix}.entries_examined", examined),
            self._observation(artifact, f"{prefix}.scan_truncated", root_entries > scan_limit),
            self._observation(artifact, f"{prefix}.first_data_sector", first_data_sector),
            self._observation(artifact, f"{prefix}.cluster_count", cluster_count),
            self._observation(artifact, f"{prefix}.fat_entry_capacity", fat_entry_capacity),
            self._observation(artifact, f"{prefix}.deleted_entries", deleted_entries),
            self._observation(
                artifact, f"{prefix}.recoverable_regular_files",
                [*active_regular_files, *subdirectory_active_files][:512],
            ),
            self._observation(artifact, f"{prefix}.subdirectory_deleted_entries", subdirectory_entries),
            self._observation(artifact, f"{prefix}.subdirectory_inventory", subdirectory_inventory),
            self._observation(artifact, f"{prefix}.subdirectory_errors", subdirectory_errors),
            self._observation(artifact, f"filesystem.{variant}.lost_chains", lost_chains),
            self._observation(
                artifact, f"{prefix}.unlinked_lfn_slots",
                [*unlinked_lfn_slots, *subdirectory_unlinked_lfn_slots][:512],
            ),
            self._observation(artifact, f"{prefix}.deleted_entries_truncated", len(deleted_entries) >= 256),
        ]

    @staticmethod
    def _fat_fixed_subdirectory_deleted_entries(
        path: Path,
        image_size: int,
        root_data: bytes,
        root_entry_offsets: list[int],
        bytes_per_sector: int,
        sectors_per_cluster: int,
        first_data_sector: int,
        fat_offset: int,
        fat_end: int,
        cluster_count: int,
        *,
        fat_bits: int,
    ) -> tuple[
        list[dict[str, object]], list[dict[str, object]], list[str], set[int],
        list[dict[str, object]], list[dict[str, object]],
    ]:
        """Traverse exact-EOC active FAT12/16 directories and inventory deleted children."""
        variant = f"FAT{fat_bits}"
        cluster_size = bytes_per_sector * sectors_per_cluster
        queue: list[dict[str, object]] = []
        deleted: list[dict[str, object]] = []
        inventory: list[dict[str, object]] = []
        errors: list[str] = []
        visited_starts: set[int] = set()
        visited_clusters: set[int] = set()
        active_cluster_starts: set[int] = set()
        active_regular_files: list[dict[str, object]] = []
        unlinked_lfn_slots: list[dict[str, object]] = []
        total_clusters = 0
        total_bytes = 0

        def active_directories(
            data: bytes, offsets: list[int], parent_lineage: list[int],
            ancestor_identities: list[dict[str, object]],
        ) -> None:
            pending_directory_lfn: list[tuple[int, bytes]] = []
            for index in range(min(len(data) // 32, 2_048)):
                entry = data[index * 32:(index + 1) * 32]
                if entry[0] == 0:
                    break
                attributes = entry[11]
                if attributes == 0x0F:
                    if len(pending_directory_lfn) < 21:
                        pending_directory_lfn.append((index, entry))
                    continue
                if (
                    entry[0] == 0xE5 or attributes & 0x08
                    or int.from_bytes(entry[20:22], "little") != 0
                ):
                    pending_directory_lfn = []
                    continue
                start = int.from_bytes(entry[26:28], "little")
                if 2 <= start < cluster_count + 2:
                    active_cluster_starts.add(start)
                if not attributes & 0x10:
                    pending_directory_lfn = []
                    continue
                base = entry[:8].decode("cp437", errors="replace").rstrip(" ")
                extension = entry[8:11].decode("cp437", errors="replace").rstrip(" ")
                short_name = base + (f".{extension}" if extension else "")
                if base in {".", ".."}:
                    pending_directory_lfn = []
                    continue
                if 2 <= start < cluster_count + 2 and len(queue) < 64:
                    directory_record: dict[str, object] = {
                        "name": short_name, "start_cluster": start,
                        "source_entry_offset": offsets[index],
                        "parent_cluster_lineage": parent_lineage,
                    }
                    if pending_directory_lfn:
                        directory_lfn, _ = GenericTriageEngine._fat_active_lfn_candidate(
                            pending_directory_lfn, entry, offsets,
                        )
                        if directory_lfn is not None:
                            directory_record.update(directory_lfn)
                    directory_record["directory_identity_lineage"] = [
                        *ancestor_identities,
                        {
                            "short_name": short_name,
                            "long_name": directory_record.get("long_name"),
                            "source_entry_offset": offsets[index],
                            "lfn_slot_offsets": directory_record.get("lfn_slot_offsets"),
                            "start_cluster": start,
                        },
                    ][:32]
                    queue.append(directory_record)
                pending_directory_lfn = []

        active_directories(root_data, root_entry_offsets, [], [])
        try:
            with path.open("rb") as stream:
                while queue and len(inventory) < 32 and total_clusters < 64 and total_bytes < 8 * _MIB:
                    directory = queue.pop(0)
                    start = directory["start_cluster"]
                    if not isinstance(start, int) or start in visited_starts:
                        continue
                    visited_starts.add(start)
                    current = start
                    chain: list[dict[str, object]] = []
                    chunks: list[bytes] = []
                    offsets: list[int] = []
                    local_seen: set[int] = set()
                    termination = "limit"
                    while total_clusters < 64 and total_bytes + cluster_size <= 8 * _MIB:
                        if current in local_seen or current in visited_clusters:
                            termination = "loop_or_shared_cluster"
                            errors.append(f"{variant} subdirectory cluster {start}: loop/shared cluster {current}")
                            break
                        if not 2 <= current < cluster_count + 2:
                            termination = "cluster_bounds"
                            errors.append(f"{variant} subdirectory cluster {start}: invalid cluster {current}")
                            break
                        physical_offset = (
                            first_data_sector + (current - 2) * sectors_per_cluster
                        ) * bytes_per_sector
                        if physical_offset < 0 or physical_offset + cluster_size > image_size:
                            termination = "image_bounds"
                            errors.append(f"{variant} subdirectory cluster {start}: cluster {current} outside image")
                            break
                        local_seen.add(current)
                        visited_clusters.add(current)
                        stream.seek(physical_offset)
                        chunk = stream.read(cluster_size)
                        if len(chunk) != cluster_size:
                            termination = "truncated_read"
                            errors.append(f"{variant} subdirectory cluster {start}: truncated cluster {current}")
                            break
                        chunks.append(chunk)
                        chain.append({"cluster": current, "offset": physical_offset, "length": cluster_size})
                        offsets.extend(physical_offset + index * 32 for index in range(cluster_size // 32))
                        total_clusters += 1
                        total_bytes += cluster_size
                        fat_entry_offset = (
                            fat_offset + current * 2 if fat_bits == 16
                            else fat_offset + current + current // 2
                        )
                        entry_width = 2
                        if fat_entry_offset < fat_offset or fat_entry_offset + entry_width > fat_end or fat_entry_offset + entry_width > image_size:
                            termination = "fat_bounds"
                            errors.append(f"{variant} subdirectory cluster {start}: FAT entry outside bounds")
                            break
                        stream.seek(fat_entry_offset)
                        raw_next = stream.read(entry_width)
                        if len(raw_next) != entry_width:
                            termination = "truncated_fat"
                            errors.append(f"{variant} subdirectory cluster {start}: truncated FAT entry")
                            break
                        packed = int.from_bytes(raw_next, "little")
                        next_cluster = (
                            packed if fat_bits == 16
                            else (packed >> 4) & 0x0FFF if current & 1
                            else packed & 0x0FFF
                        )
                        chain[-1].update({
                            "fat_entry_offset": fat_entry_offset,
                            "fat_entry_raw": raw_next.hex(),
                            "next_cluster": next_cluster,
                        })
                        eoc_minimum = 0xFFF8 if fat_bits == 16 else 0xFF8
                        bad_cluster = 0xFFF7 if fat_bits == 16 else 0xFF7
                        reserved_minimum = 0xFFF0 if fat_bits == 16 else 0xFF0
                        reserved_maximum = 0xFFF6 if fat_bits == 16 else 0xFF6
                        if next_cluster >= eoc_minimum:
                            termination = "eoc"
                            break
                        if (
                            next_cluster < 2 or next_cluster >= cluster_count + 2
                            or next_cluster == bad_cluster
                            or reserved_minimum <= next_cluster <= reserved_maximum
                        ):
                            termination = "invalid_fat_value"
                            errors.append(
                                f"{variant} subdirectory cluster {start}: invalid next cluster 0x{next_cluster:04X}"
                            )
                            break
                        current = next_cluster
                    inventory.append({
                        **directory, "cluster_chain": chain, "termination": termination,
                    })
                    if termination != "eoc":
                        continue
                    directory_data = b"".join(chunks)
                    lineage = [int(item["cluster"]) for item in chain]
                    directory_identities = directory.get("directory_identity_lineage")
                    active_directories(
                        directory_data, offsets, lineage,
                        directory_identities if isinstance(directory_identities, list) else [],
                    )
                    pending_lfn: list[tuple[int, bytes]] = []
                    for index in range(min(len(directory_data) // 32, 2_048)):
                        entry = directory_data[index * 32:(index + 1) * 32]
                        if entry[0] == 0:
                            if pending_lfn and len(unlinked_lfn_slots) < 256:
                                unlinked_lfn_slots.append({
                                    "directory_start_cluster": start,
                                    "directory_cluster_lineage": lineage,
                                    "directory_source_entry_offset": directory.get("source_entry_offset"),
                                    "short_entry_index": None,
                                    "short_entry_offset": None,
                                    "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                    "reason": "LFN slots are not followed by a short entry",
                                    "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                })
                            break
                        attributes = entry[11]
                        if attributes == 0x0F:
                            if len(pending_lfn) < 21:
                                pending_lfn.append((index, entry))
                            continue
                        if entry[0] != 0xE5:
                            if pending_lfn and attributes & 0x08:
                                if len(unlinked_lfn_slots) < 256:
                                    unlinked_lfn_slots.append({
                                        "directory_start_cluster": start,
                                        "directory_cluster_lineage": lineage,
                                        "directory_source_entry_offset": directory.get("source_entry_offset"),
                                        "short_entry_index": index,
                                        "short_entry_offset": offsets[index],
                                        "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                        "reason": "LFN slots are followed by an incompatible volume-label entry",
                                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                    })
                            elif pending_lfn and attributes & 0x10:
                                directory_lfn, lfn_error = GenericTriageEngine._fat_active_lfn_candidate(
                                    pending_lfn, entry, offsets,
                                )
                                if directory_lfn is not None:
                                    directory_record = next(
                                        (
                                            item for item in queue
                                            if item.get("source_entry_offset") == offsets[index]
                                        ),
                                        None,
                                    )
                                    if directory_record is not None:
                                        directory_record.update(directory_lfn)
                                elif len(unlinked_lfn_slots) < 256:
                                    unlinked_lfn_slots.append({
                                        "directory_start_cluster": start,
                                        "directory_cluster_lineage": lineage,
                                        "directory_source_entry_offset": directory.get("source_entry_offset"),
                                        "short_entry_index": index,
                                        "short_entry_offset": offsets[index],
                                        "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                        "reason": lfn_error,
                                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                    })
                            if (
                                not attributes & 0x18
                                and int.from_bytes(entry[20:22], "little") == 0
                                and len(active_regular_files) < 512
                            ):
                                first_cluster = int.from_bytes(entry[26:28], "little")
                                file_size = int.from_bytes(entry[28:32], "little")
                                if 2 <= first_cluster < cluster_count + 2 and 0 < file_size <= 8 * _MIB:
                                    short_raw = bytes([0xE5]) + entry[1:11] if entry[0] == 0x05 else entry[:11]
                                    base = short_raw[:8].decode("cp437", errors="replace").rstrip(" ")
                                    extension = short_raw[8:11].decode("cp437", errors="replace").rstrip(" ")
                                    active_file: dict[str, object] = {
                                        "directory_start_cluster": start,
                                        "directory_cluster_lineage": lineage,
                                        "directory_source_entry_offset": directory.get("source_entry_offset"),
                                        "directory_short_name": directory.get("name"),
                                        "directory_long_name": directory.get("long_name"),
                                        "directory_lfn_slot_offsets": directory.get("lfn_slot_offsets"),
                                        "directory_identity_lineage": directory.get("directory_identity_lineage"),
                                        "entry_index": index, "offset": offsets[index],
                                        "short_name": base + (f".{extension}" if extension else ""),
                                        "attributes": f"0x{attributes:02X}",
                                        "first_cluster": first_cluster,
                                        "cluster_high_reserved": 0,
                                        f"fat{fat_bits}_cluster_high_reserved": 0,
                                        "size": file_size, "raw_hex": entry.hex(),
                                    }
                                    if pending_lfn:
                                        lfn, lfn_error = GenericTriageEngine._fat_active_lfn_candidate(
                                            pending_lfn, entry, offsets,
                                        )
                                        if lfn is not None:
                                            active_file.update(lfn)
                                        elif len(unlinked_lfn_slots) < 256:
                                            unlinked_lfn_slots.append({
                                                "directory_start_cluster": start,
                                                "directory_cluster_lineage": lineage,
                                                "directory_source_entry_offset": directory.get("source_entry_offset"),
                                                "short_entry_index": index,
                                                "short_entry_offset": offsets[index],
                                                "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                                "reason": lfn_error,
                                                "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                            })
                                    active_regular_files.append(active_file)
                            pending_lfn = []
                            continue
                        base = entry[1:8].decode("cp437", errors="replace").rstrip(" ")
                        extension = entry[8:11].decode("cp437", errors="replace").rstrip(" ")
                        recovered: dict[str, object] = {
                            "directory_start_cluster": start,
                            "directory_cluster_lineage": lineage,
                            "directory_source_entry_offset": directory.get("source_entry_offset"),
                            "directory_short_name": directory.get("name"),
                            "directory_long_name": directory.get("long_name"),
                            "directory_lfn_slot_offsets": directory.get("lfn_slot_offsets"),
                            "directory_identity_lineage": directory.get("directory_identity_lineage"),
                            "entry_index": index, "offset": offsets[index],
                            "short_name": f"?{base}" + (f".{extension}" if extension else ""),
                            "first_character_unknown": True,
                            "attributes": f"0x{attributes:02X}",
                            "first_cluster": int.from_bytes(entry[26:28], "little"),
                            "cluster_high_reserved": int.from_bytes(entry[20:22], "little"),
                            f"fat{fat_bits}_cluster_high_reserved": int.from_bytes(entry[20:22], "little"),
                            "size": int.from_bytes(entry[28:32], "little"),
                            "raw_hex": entry.hex(),
                        }
                        if pending_lfn:
                            lfn, lfn_error = GenericTriageEngine._fat_deleted_lfn_candidate(
                                pending_lfn, entry, offsets
                            )
                            if lfn is not None:
                                recovered.update(lfn)
                            elif len(unlinked_lfn_slots) < 256:
                                unlinked_lfn_slots.append({
                                    "directory_start_cluster": start,
                                    "directory_cluster_lineage": lineage,
                                    "directory_source_entry_offset": directory.get("source_entry_offset"),
                                    "short_entry_index": index,
                                    "short_entry_offset": offsets[index],
                                    "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                    "reason": lfn_error,
                                    "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                })
                        deleted.append(recovered)
                        pending_lfn = []
                        if len(deleted) >= 512:
                            return (
                                deleted, inventory, errors, active_cluster_starts,
                                active_regular_files, unlinked_lfn_slots,
                            )
        except OSError as exc:
            errors.append(str(exc)[:2_000])
        if queue:
            errors.append(f"{variant} subdirectory traversal reached the 32-directory/64-cluster/8-MiB bound")
        return (
            deleted, inventory, errors, active_cluster_starts,
            active_regular_files, unlinked_lfn_slots,
        )

    @staticmethod
    def _fat_lost_chain_inventory(
        path: Path,
        image_size: int,
        bytes_per_sector: int,
        sectors_per_cluster: int,
        first_data_sector: int,
        fat_offset: int,
        fat_end: int,
        cluster_count: int,
        active_cluster_starts: set[int],
        *,
        fat_bits: int,
        directory_reference_scope_limited: bool,
    ) -> dict[str, object]:
        """Inventory allocated chains absent from the bounded active-directory reference set."""
        cluster_size = bytes_per_sector * sectors_per_cluster
        cluster_scan_limit = 131_072
        maximum_cluster = min(cluster_count + 1, cluster_scan_limit + 1)
        scan_cluster_count = max(0, maximum_cluster - 1)
        available = (
            fat_bits in {12, 16, 32} and cluster_count > 0
            and (fat_bits != 32 or cluster_count >= 65_525)
            and 0 < cluster_size <= 2 * _MIB and fat_offset >= 0
            and fat_end > fat_offset and fat_end <= image_size
            and first_data_sector > 0
        )
        inventory: dict[str, object] = {
            "available": available,
            "fat_bits": fat_bits,
            "active_fat_offset": fat_offset,
            "cluster_count": cluster_count,
            "cluster_scan_limit": cluster_scan_limit,
            "scanned_cluster_count": scan_cluster_count,
            "scan_complete_for_volume": scan_cluster_count == cluster_count,
            "directory_reference_scope": "bounded_validated_active_entries_only",
            "directory_reference_scope_limited": directory_reference_scope_limited,
            "active_start_clusters": sorted(active_cluster_starts)[:65_536],
            "active_start_clusters_truncated": len(active_cluster_starts) > 65_536,
            "chains": [],
            "chains_truncated": False,
            "ownership_inferred": False,
            "content_recovered": False,
        }
        if not available or scan_cluster_count == 0:
            inventory["reason"] = "invalid FAT/data geometry or active FAT is outside supplied image"
            return inventory

        relative_end = (
            maximum_cluster + maximum_cluster // 2 + 2 if fat_bits == 12
            else (maximum_cluster + 1) * (2 if fat_bits == 16 else 4)
        )
        read_length = min(fat_end - fat_offset, relative_end)
        try:
            with path.open("rb") as stream:
                stream.seek(fat_offset)
                fat_data = stream.read(read_length)
        except OSError as exc:
            inventory["available"] = False
            inventory["error"] = str(exc)[:2_000]
            return inventory
        if len(fat_data) != read_length:
            inventory["available"] = False
            inventory["reason"] = "truncated active-FAT scan"
            inventory["bytes_read"] = len(fat_data)
            return inventory

        eoc_minimum = 0xFF8 if fat_bits == 12 else 0xFFF8 if fat_bits == 16 else 0x0FFFFFF8

        def decode(cluster: int) -> tuple[int, int, str] | None:
            relative = (
                cluster + cluster // 2 if fat_bits == 12
                else cluster * (2 if fat_bits == 16 else 4)
            )
            width = 2 if fat_bits in {12, 16} else 4
            if relative < 0 or relative + width > len(fat_data):
                return None
            raw = fat_data[relative:relative + width]
            packed = int.from_bytes(raw, "little")
            value = (
                ((packed >> 4) & 0x0FFF if cluster & 1 else packed & 0x0FFF)
                if fat_bits == 12 else packed if fat_bits == 16 else packed & 0x0FFFFFFF
            )
            return value, fat_offset + relative, raw.hex()

        allocated: dict[int, tuple[int, int, str]] = {}
        for cluster in range(2, maximum_cluster + 1):
            decoded = decode(cluster)
            if decoded is None:
                break
            value = decoded[0]
            if value >= eoc_minimum or 2 <= value < cluster_count + 2:
                allocated[cluster] = decoded

        referenced_clusters: set[int] = set()
        reference_walk_limit = 262_144
        reference_steps = 0
        for start in sorted(active_cluster_starts)[:65_536]:
            current = start
            local_seen: set[int] = set()
            while reference_steps < reference_walk_limit and 2 <= current < cluster_count + 2:
                if current in local_seen:
                    break
                local_seen.add(current)
                referenced_clusters.add(current)
                reference_steps += 1
                decoded = allocated.get(current)
                if decoded is None or decoded[0] >= eoc_minimum:
                    break
                current = decoded[0]

        orphan_clusters = set(allocated) - referenced_clusters
        incoming: set[int] = set()
        for cluster in orphan_clusters:
            next_cluster = allocated[cluster][0]
            if next_cluster in orphan_clusters:
                incoming.add(next_cluster)
        heads = sorted(orphan_clusters - incoming)
        visited: set[int] = set()
        chains: list[dict[str, object]] = []

        def build_chain(start: int) -> dict[str, object]:
            chain: list[dict[str, object]] = []
            local_seen: set[int] = set()
            current = start
            termination = "cluster_limit"
            for _ in range(64):
                if current in local_seen:
                    termination = "loop"
                    break
                if current in visited:
                    termination = "joins_inventoried_chain"
                    break
                decoded = allocated.get(current)
                if current not in orphan_clusters or decoded is None:
                    termination = (
                        "joins_validated_reference" if current in referenced_clusters
                        else "points_to_nonallocated_cluster"
                    )
                    break
                local_seen.add(current)
                visited.add(current)
                next_cluster, entry_offset, raw_hex = decoded
                data_offset = (
                    first_data_sector + (current - 2) * sectors_per_cluster
                ) * bytes_per_sector
                chain.append({
                    "cluster": current,
                    "fat_entry_offset": entry_offset,
                    "fat_entry_raw": raw_hex,
                    "next_cluster": next_cluster,
                    "data_offset": data_offset,
                    "data_length": cluster_size,
                    "data_within_supplied_image": (
                        data_offset >= 0 and data_offset + cluster_size <= image_size
                    ),
                })
                if next_cluster >= eoc_minimum:
                    termination = "eoc"
                    break
                if next_cluster >= maximum_cluster + 1 and next_cluster < cluster_count + 2:
                    termination = "continues_beyond_fat_scan"
                    break
                current = next_cluster
            return {
                "start_cluster": start,
                "cluster_chain": chain,
                "termination": termination,
                "complete_eoc_chain": termination == "eoc",
            }

        for head in heads:
            if len(chains) >= 64:
                break
            chains.append(build_chain(head))
        if len(chains) < 64:
            for cycle_or_fragment in sorted(orphan_clusters - visited):
                if len(chains) >= 64:
                    break
                chains.append(build_chain(cycle_or_fragment))
        inventory.update({
            "allocated_cluster_count_in_scan": len(allocated),
            "validated_reference_cluster_count_in_scan": len(referenced_clusters & set(allocated)),
            "reference_walk_steps": reference_steps,
            "reference_walk_limit_reached": reference_steps >= reference_walk_limit,
            "unreferenced_allocated_cluster_count_in_scan": len(orphan_clusters),
            "candidate_chain_count": len(chains),
            "chains": chains,
            "chains_truncated": len(visited) < len(orphan_clusters),
            "interpretation": (
                "allocation chains absent from the bounded validated active-directory reference sample; "
                "not proof of lost-file ownership"
            ),
        })
        return inventory

    def _inspect_fat32_metadata_sectors(
        self,
        artifact: Artifact,
        path: Path,
        image_size: int,
        header: bytes,
        bytes_per_sector: int,
        sectors_per_cluster: int,
        reserved_sectors: int,
        fat_count: int,
        fat_size: int,
    ) -> list[Observation]:
        """Validate FAT32 FSInfo and backup metadata without selecting a preferred copy."""
        prefix = "filesystem.fat32"
        total_sectors = (
            int.from_bytes(header[19:21], "little")
            or int.from_bytes(header[32:36], "little")
        )
        first_data_sector = reserved_sectors + fat_count * fat_size
        data_sectors = total_sectors - first_data_sector
        cluster_count = data_sectors // sectors_per_cluster if sectors_per_cluster else 0
        fat_entry_capacity = fat_size * bytes_per_sector // 4 if bytes_per_sector else 0
        geometry_valid = (
            bytes_per_sector in {512, 1024, 2048, 4096}
            and sectors_per_cluster > 0
            and sectors_per_cluster & (sectors_per_cluster - 1) == 0
            and reserved_sectors > 0 and 1 <= fat_count <= 4 and fat_size > 0
            and total_sectors > first_data_sector and cluster_count >= 65_525
            and fat_entry_capacity >= cluster_count + 2
        )
        fsinfo_sector = int.from_bytes(header[48:50], "little") if len(header) >= 52 else 0
        backup_boot_sector = int.from_bytes(header[50:52], "little") if len(header) >= 52 else 0

        def fsinfo_record(data: bytes, sector: int, offset: int) -> dict[str, object]:
            free_raw = int.from_bytes(data[488:492], "little") if len(data) >= 512 else 0
            next_raw = int.from_bytes(data[492:496], "little") if len(data) >= 512 else 0
            free_count = None if free_raw == 0xFFFFFFFF else free_raw
            next_free = None if next_raw == 0xFFFFFFFF else next_raw
            lead = len(data) >= 512 and data[0:4] == b"RRaA"
            structure = len(data) >= 512 and data[484:488] == b"rrAa"
            trail = len(data) >= 512 and data[508:512] == b"\x00\x00\x55\xaa"
            return {
                "sector": sector, "offset": offset,
                "lead_signature_valid": lead,
                "structure_signature_valid": structure,
                "trail_signature_valid": trail,
                "valid": lead and structure and trail,
                "free_cluster_count_raw": f"0x{free_raw:08X}",
                "free_cluster_count": free_count,
                "free_cluster_count_in_range": None if free_count is None else free_count <= cluster_count,
                "next_free_cluster_raw": f"0x{next_raw:08X}",
                "next_free_cluster": next_free,
                "next_free_cluster_in_range": (
                    None if next_free is None else 2 <= next_free < cluster_count + 2
                ),
            }

        fsinfo: dict[str, object] = {
            "available": False, "sector": fsinfo_sector,
            "reason": "invalid FAT32 geometry or FSInfo sector outside reserved region",
        }
        backup_boot: dict[str, object] = {
            "available": False, "sector": backup_boot_sector,
            "reason": "invalid FAT32 geometry or backup boot sector outside reserved region",
        }
        backup_fsinfo: dict[str, object] = {
            "available": False,
            "sector": backup_boot_sector + fsinfo_sector,
            "reason": "backup FSInfo sector outside reserved region",
        }
        try:
            with path.open("rb") as stream:
                if geometry_valid and 0 < fsinfo_sector < reserved_sectors:
                    offset = fsinfo_sector * bytes_per_sector
                    if offset + bytes_per_sector <= image_size:
                        stream.seek(offset)
                        data = stream.read(bytes_per_sector)
                        if len(data) == bytes_per_sector:
                            fsinfo = {"available": True, **fsinfo_record(data, fsinfo_sector, offset)}
                        else:
                            fsinfo["reason"] = "truncated FSInfo sector"
                    else:
                        fsinfo["reason"] = "FSInfo sector outside supplied image"
                if geometry_valid and 0 < backup_boot_sector < reserved_sectors:
                    offset = backup_boot_sector * bytes_per_sector
                    if offset + bytes_per_sector <= image_size:
                        stream.seek(0)
                        primary = stream.read(bytes_per_sector)
                        stream.seek(offset)
                        data = stream.read(bytes_per_sector)
                        if len(data) == bytes_per_sector:
                            match = len(primary) == bytes_per_sector and primary == data
                            difference = None
                            if len(primary) == bytes_per_sector and not match:
                                difference = next(
                                    (index for index in range(bytes_per_sector) if primary[index] != data[index]),
                                    None,
                                )
                            backup_boot = {
                                "available": True, "sector": backup_boot_sector,
                                "offset": offset,
                                "signature_valid": data[510:512] == b"\x55\xaa",
                                "fat32_label_valid": data[82:90].startswith(b"FAT"),
                                "primary_match": match if len(primary) == bytes_per_sector else None,
                                "first_difference_offset": difference,
                            }
                        else:
                            backup_boot["reason"] = "truncated backup boot sector"
                    else:
                        backup_boot["reason"] = "backup boot sector outside supplied image"
                backup_fsinfo_sector = backup_boot_sector + fsinfo_sector
                if (
                    geometry_valid and 0 < fsinfo_sector < reserved_sectors
                    and 0 < backup_boot_sector < reserved_sectors
                    and backup_fsinfo_sector < reserved_sectors
                ):
                    offset = backup_fsinfo_sector * bytes_per_sector
                    if offset + bytes_per_sector <= image_size:
                        stream.seek(offset)
                        data = stream.read(bytes_per_sector)
                        if len(data) == bytes_per_sector:
                            backup_fsinfo = {
                                "available": True,
                                **fsinfo_record(data, backup_fsinfo_sector, offset),
                            }
                            if fsinfo.get("available"):
                                primary_offset = fsinfo_sector * bytes_per_sector
                                stream.seek(primary_offset)
                                primary_data = stream.read(bytes_per_sector)
                                match = len(primary_data) == bytes_per_sector and primary_data == data
                                difference = None
                                if len(primary_data) == bytes_per_sector and not match:
                                    difference = next(
                                        (index for index in range(bytes_per_sector) if primary_data[index] != data[index]),
                                        None,
                                    )
                                backup_fsinfo["primary_match"] = match
                                backup_fsinfo["first_difference_offset"] = difference
                        else:
                            backup_fsinfo["reason"] = "truncated backup FSInfo sector"
                    else:
                        backup_fsinfo["reason"] = "backup FSInfo sector outside supplied image"
        except OSError as exc:
            error = str(exc)[:2_000]
            fsinfo.setdefault("error", error)
            backup_boot.setdefault("error", error)
            backup_fsinfo.setdefault("error", error)
        return [
            self._observation(artifact, f"{prefix}.cluster_count", cluster_count),
            self._observation(artifact, f"{prefix}.fat_entry_capacity", fat_entry_capacity),
            self._observation(artifact, f"{prefix}.fsinfo", fsinfo),
            self._observation(artifact, f"{prefix}.backup_boot", backup_boot),
            self._observation(artifact, f"{prefix}.backup_fsinfo", backup_fsinfo),
        ]

    def _inspect_fat32_root_directory(
        self,
        artifact: Artifact,
        path: Path,
        image_size: int,
        header: bytes,
        bytes_per_sector: int,
        sectors_per_cluster: int,
        reserved_sectors: int,
        fat_count: int,
        fat_size: int,
    ) -> list[Observation]:
        prefix = "filesystem.fat.root"
        root_cluster = int.from_bytes(header[44:48], "little") if len(header) >= 48 else 0
        ext_flags = int.from_bytes(header[40:42], "little") if len(header) >= 42 else 0
        fat_mirroring_enabled = not bool(ext_flags & 0x0080)
        active_fat_index = 0 if fat_mirroring_enabled else ext_flags & 0x000F
        cluster_size = bytes_per_sector * sectors_per_cluster
        valid_geometry = (
            bytes_per_sector in {512, 1024, 2048, 4096}
            and sectors_per_cluster > 0 and sectors_per_cluster & (sectors_per_cluster - 1) == 0
            and sectors_per_cluster <= 128 and reserved_sectors > 0
            and 1 <= fat_count <= 4 and active_fat_index < fat_count
            and fat_size > 0 and root_cluster >= 2
            and 0 < cluster_size <= 2 * _MIB
        )
        first_data_sector = reserved_sectors + fat_count * fat_size
        root_sector = first_data_sector + (root_cluster - 2) * sectors_per_cluster
        root_offset = root_sector * bytes_per_sector
        if not valid_geometry or root_offset < 0 or root_offset + cluster_size > image_size:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.cluster", root_cluster),
                self._observation(artifact, f"{prefix}.offset", root_offset if valid_geometry else None),
                self._observation(artifact, f"{prefix}.fat_mirroring_enabled", fat_mirroring_enabled),
                self._observation(artifact, f"{prefix}.active_fat_index", active_fat_index),
            ]
        fat_offset = (reserved_sectors + active_fat_index * fat_size) * bytes_per_sector
        fat_end = fat_offset + fat_size * bytes_per_sector
        cluster_limit = max(1, min(64, (8 * _MIB) // cluster_size))
        cluster_segments: list[dict[str, int]] = []
        chain_errors: list[str] = []
        chain_termination = "limit"
        chunks: list[bytes] = []
        entry_offsets: list[int] = []
        visited: set[int] = set()
        current_cluster = root_cluster
        try:
            with path.open("rb") as stream:
                for _ in range(cluster_limit):
                    if current_cluster in visited:
                        chain_termination = "loop"
                        chain_errors.append(f"root directory FAT chain loops at cluster {current_cluster}")
                        break
                    visited.add(current_cluster)
                    cluster_sector = first_data_sector + (current_cluster - 2) * sectors_per_cluster
                    cluster_offset = cluster_sector * bytes_per_sector
                    if current_cluster < 2 or cluster_offset < 0 or cluster_offset + cluster_size > image_size:
                        chain_termination = "image_bounds"
                        chain_errors.append(f"cluster {current_cluster} maps outside supplied image")
                        break
                    stream.seek(cluster_offset)
                    chunk = stream.read(cluster_size)
                    if len(chunk) != cluster_size:
                        chain_termination = "truncated_read"
                        chain_errors.append(f"cluster {current_cluster} could not be read completely")
                        break
                    chunks.append(chunk)
                    cluster_segments.append({
                        "cluster": current_cluster, "offset": cluster_offset, "length": cluster_size,
                    })
                    entry_offsets.extend(cluster_offset + index * 32 for index in range(cluster_size // 32))
                    fat_entry_offset = fat_offset + current_cluster * 4
                    if fat_entry_offset < fat_offset or fat_entry_offset + 4 > fat_end or fat_entry_offset + 4 > image_size:
                        chain_termination = "fat_bounds"
                        chain_errors.append(f"FAT entry for cluster {current_cluster} is outside validated FAT bytes")
                        break
                    stream.seek(fat_entry_offset)
                    next_cluster = int.from_bytes(stream.read(4), "little") & 0x0FFFFFFF
                    if next_cluster >= 0x0FFFFFF8:
                        chain_termination = "eoc"
                        break
                    if next_cluster == 0:
                        chain_termination = "free_cluster"
                        chain_errors.append(f"cluster {current_cluster} points to a free FAT entry")
                        break
                    if next_cluster == 0x0FFFFFF7:
                        chain_termination = "bad_cluster"
                        chain_errors.append(f"cluster {current_cluster} points to the FAT bad-cluster marker")
                        break
                    if next_cluster == 1 or 0x0FFFFFF0 <= next_cluster <= 0x0FFFFFF6:
                        chain_termination = "reserved_cluster"
                        chain_errors.append(f"cluster {current_cluster} points to reserved value 0x{next_cluster:08X}")
                        break
                    current_cluster = next_cluster
        except OSError as exc:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.error", str(exc)[:2_000], confidence=0.9),
            ]
        data = b"".join(chunks)
        (
            subdirectory_entries, subdirectory_inventory, subdirectory_errors,
            active_cluster_starts, subdirectory_active_files,
            subdirectory_unlinked_lfn_slots,
        ) = self._fat32_subdirectory_deleted_entries(
            path, image_size, data, entry_offsets, bytes_per_sector, sectors_per_cluster,
            first_data_sector, fat_offset, fat_end,
        )
        total_sectors = (
            int.from_bytes(header[19:21], "little")
            or int.from_bytes(header[32:36], "little")
        )
        cluster_count = (
            (total_sectors - first_data_sector) // sectors_per_cluster
            if sectors_per_cluster and total_sectors > first_data_sector else 0
        )
        active_cluster_starts.add(root_cluster)
        lost_chains = self._fat_lost_chain_inventory(
            path, image_size, bytes_per_sector, sectors_per_cluster,
            first_data_sector, fat_offset, fat_end, cluster_count,
            active_cluster_starts, fat_bits=32,
            directory_reference_scope_limited=bool(chain_errors or subdirectory_errors),
        )
        deleted_entries: list[dict[str, object]] = []
        active_regular_files: list[dict[str, object]] = []
        unlinked_lfn_slots: list[dict[str, object]] = []
        pending_lfn: list[tuple[int, bytes]] = []
        examined = 0
        limit = min(len(data) // 32, 1_024)
        for index in range(limit):
            entry = data[index * 32:(index + 1) * 32]
            if entry[0] == 0x00:
                if pending_lfn:
                    deleted_slots = all(slot[0] == 0xE5 for _, slot in pending_lfn)
                    unlinked_lfn_slots.append({
                        "short_entry_index": None,
                        "short_entry_offset": None,
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": (
                            "deleted LFN slots are not followed by a deleted short entry"
                            if deleted_slots else "LFN slots are not followed by a short entry"
                        ),
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
                break
            examined += 1
            attributes = entry[11]
            if attributes == 0x0F:
                if len(pending_lfn) < 21:
                    pending_lfn.append((index, entry))
                continue
            if entry[0] != 0xE5:
                if pending_lfn and any(slot[0] == 0xE5 for _, slot in pending_lfn):
                    unlinked_lfn_slots.append({
                        "short_entry_index": index,
                        "short_entry_offset": entry_offsets[index],
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": "deleted LFN slots are followed by an active short entry",
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
                elif pending_lfn and attributes & 0x08:
                    unlinked_lfn_slots.append({
                        "short_entry_index": index,
                        "short_entry_offset": entry_offsets[index],
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": "LFN slots are followed by an incompatible volume-label entry",
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
                elif pending_lfn and attributes & 0x10:
                    directory_lfn, lfn_error = self._fat_active_lfn_candidate(
                        pending_lfn, entry, entry_offsets,
                    )
                    if directory_lfn is not None:
                        directory_record = next(
                            (
                                item for item in subdirectory_inventory
                                if item.get("source_entry_offset") == entry_offsets[index]
                            ),
                            None,
                        )
                        if directory_record is not None:
                            directory_record.update(directory_lfn)
                    else:
                        unlinked_lfn_slots.append({
                            "short_entry_index": index,
                            "short_entry_offset": entry_offsets[index],
                            "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                            "reason": lfn_error,
                            "raw_hex": [slot.hex() for _, slot in pending_lfn],
                        })
                elif not attributes & 0x18:
                    raw_cluster = (
                        int.from_bytes(entry[20:22], "little") << 16
                        | int.from_bytes(entry[26:28], "little")
                    )
                    first_cluster = raw_cluster & 0x0FFFFFFF
                    file_size = int.from_bytes(entry[28:32], "little")
                    if (
                        raw_cluster >> 28 == 0 and 2 <= first_cluster < cluster_count + 2
                        and 0 < file_size <= 8 * _MIB
                    ):
                        short_raw = bytes([0xE5]) + entry[1:11] if entry[0] == 0x05 else entry[:11]
                        base = short_raw[:8].decode("cp437", errors="replace").rstrip(" ")
                        extension = short_raw[8:11].decode("cp437", errors="replace").rstrip(" ")
                        active_file: dict[str, object] = {
                            "entry_index": index, "offset": entry_offsets[index],
                            "short_name": base + (f".{extension}" if extension else ""),
                            "attributes": f"0x{attributes:02X}",
                            "first_cluster": first_cluster,
                            "cluster_field_raw": f"0x{raw_cluster:08X}",
                            "fat32_cluster_high_reserved": raw_cluster >> 28,
                            "size": file_size, "raw_hex": entry.hex(),
                        }
                        if pending_lfn:
                            lfn, lfn_error = self._fat_active_lfn_candidate(
                                pending_lfn, entry, entry_offsets,
                            )
                            if lfn is not None:
                                active_file.update(lfn)
                            else:
                                unlinked_lfn_slots.append({
                                    "short_entry_index": index,
                                    "short_entry_offset": entry_offsets[index],
                                    "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                                    "reason": lfn_error,
                                    "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                })
                        active_regular_files.append(active_file)
                pending_lfn = []
                continue
            base = entry[1:8].decode("cp437", errors="replace").rstrip(" ")
            extension = entry[8:11].decode("cp437", errors="replace").rstrip(" ")
            short_name = f"?{base}" + (f".{extension}" if extension else "")
            raw_cluster = (
                int.from_bytes(entry[20:22], "little") << 16
                | int.from_bytes(entry[26:28], "little")
            )
            first_cluster = raw_cluster & 0x0FFFFFFF
            recovered: dict[str, object] = {
                "entry_index": index,
                "offset": entry_offsets[index],
                "short_name": short_name,
                "first_character_unknown": True,
                "attributes": f"0x{attributes:02X}",
                "first_cluster": first_cluster,
                "cluster_field_raw": f"0x{raw_cluster:08X}",
                "fat32_cluster_high_reserved": raw_cluster >> 28,
                "size": int.from_bytes(entry[28:32], "little"),
                "created": self._fat_datetime(
                    int.from_bytes(entry[16:18], "little"),
                    int.from_bytes(entry[14:16], "little"), entry[13],
                ),
                "accessed": self._fat_datetime(int.from_bytes(entry[18:20], "little"), 0),
                "modified": self._fat_datetime(
                    int.from_bytes(entry[24:26], "little"),
                    int.from_bytes(entry[22:24], "little"),
                ),
                "raw_hex": entry.hex(),
            }
            if pending_lfn:
                lfn, lfn_error = self._fat_deleted_lfn_candidate(pending_lfn, entry, entry_offsets)
                if lfn is not None:
                    recovered.update(lfn)
                else:
                    unlinked_lfn_slots.append({
                        "short_entry_index": index,
                        "short_entry_offset": entry_offsets[index],
                        "slot_offsets": [entry_offsets[slot_index] for slot_index, _ in pending_lfn],
                        "reason": lfn_error,
                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                    })
            deleted_entries.append(recovered)
            pending_lfn = []
            if len(deleted_entries) >= 256:
                break
        return [
            self._observation(artifact, f"{prefix}.available", True),
            self._observation(artifact, f"{prefix}.cluster", root_cluster),
            self._observation(artifact, f"{prefix}.offset", root_offset),
            self._observation(artifact, f"{prefix}.fat_mirroring_enabled", fat_mirroring_enabled),
            self._observation(artifact, f"{prefix}.active_fat_index", active_fat_index),
            self._observation(artifact, f"{prefix}.active_fat_offset", fat_offset),
            self._observation(artifact, f"{prefix}.cluster_segments", cluster_segments),
            self._observation(artifact, f"{prefix}.chain_termination", chain_termination),
            self._observation(artifact, f"{prefix}.chain_errors", chain_errors),
            self._observation(artifact, f"{prefix}.chain_truncated", chain_termination == "limit"),
            self._observation(artifact, f"{prefix}.bytes_read", len(data)),
            self._observation(artifact, f"{prefix}.entries_examined", examined),
            self._observation(artifact, "filesystem.fat.deleted_short_entries", deleted_entries),
            self._observation(
                artifact, "filesystem.fat.root.recoverable_regular_files",
                [*active_regular_files, *subdirectory_active_files][:512],
            ),
            self._observation(artifact, "filesystem.fat.subdirectory_deleted_entries", subdirectory_entries),
            self._observation(artifact, "filesystem.fat.subdirectory_inventory", subdirectory_inventory),
            self._observation(artifact, "filesystem.fat.subdirectory_errors", subdirectory_errors),
            self._observation(artifact, "filesystem.fat32.lost_chains", lost_chains),
            self._observation(
                artifact, "filesystem.fat.unlinked_lfn_slots",
                [*unlinked_lfn_slots, *subdirectory_unlinked_lfn_slots][:512],
            ),
            self._observation(artifact, "filesystem.fat.deleted_short_entries_truncated", len(deleted_entries) >= 256),
        ]

    @staticmethod
    def _fat32_subdirectory_deleted_entries(
        path: Path,
        image_size: int,
        root_data: bytes,
        root_entry_offsets: list[int],
        bytes_per_sector: int,
        sectors_per_cluster: int,
        first_data_sector: int,
        fat_offset: int,
        fat_end: int,
    ) -> tuple[
        list[dict[str, object]], list[dict[str, object]], list[str], set[int],
        list[dict[str, object]], list[dict[str, object]],
    ]:
        """Traverse active FAT32 directory chains and inventory deleted children."""
        cluster_size = bytes_per_sector * sectors_per_cluster
        queue: list[dict[str, object]] = []
        deleted: list[dict[str, object]] = []
        inventory: list[dict[str, object]] = []
        errors: list[str] = []
        visited_starts: set[int] = set()
        visited_clusters: set[int] = set()
        active_cluster_starts: set[int] = set()
        active_regular_files: list[dict[str, object]] = []
        unlinked_lfn_slots: list[dict[str, object]] = []
        total_clusters = 0

        def active_directories(
            data: bytes, offsets: list[int], parent_lineage: list[int],
            ancestor_identities: list[dict[str, object]],
        ) -> None:
            pending_directory_lfn: list[tuple[int, bytes]] = []
            for index in range(min(len(data) // 32, 2_048)):
                entry = data[index * 32:(index + 1) * 32]
                if entry[0] == 0:
                    break
                attributes = entry[11]
                if attributes == 0x0F:
                    if len(pending_directory_lfn) < 21:
                        pending_directory_lfn.append((index, entry))
                    continue
                if entry[0] == 0xE5 or attributes & 0x08:
                    pending_directory_lfn = []
                    continue
                raw_start = int.from_bytes(entry[20:22], "little") << 16 | int.from_bytes(entry[26:28], "little")
                start = raw_start & 0x0FFFFFFF
                if raw_start >> 28 == 0 and start >= 2:
                    active_cluster_starts.add(start)
                if not attributes & 0x10:
                    pending_directory_lfn = []
                    continue
                base = entry[:8].decode("cp437", errors="replace").rstrip(" ")
                extension = entry[8:11].decode("cp437", errors="replace").rstrip(" ")
                short_name = base + (f".{extension}" if extension else "")
                if base in {".", ".."}:
                    pending_directory_lfn = []
                    continue
                if raw_start >> 28 == 0 and start >= 2 and len(queue) < 64:
                    directory_record: dict[str, object] = {
                        "name": short_name, "start_cluster": start,
                        "source_entry_offset": offsets[index],
                        "parent_cluster_lineage": parent_lineage,
                    }
                    if pending_directory_lfn:
                        directory_lfn, _ = GenericTriageEngine._fat_active_lfn_candidate(
                            pending_directory_lfn, entry, offsets,
                        )
                        if directory_lfn is not None:
                            directory_record.update(directory_lfn)
                    directory_record["directory_identity_lineage"] = [
                        *ancestor_identities,
                        {
                            "short_name": short_name,
                            "long_name": directory_record.get("long_name"),
                            "source_entry_offset": offsets[index],
                            "lfn_slot_offsets": directory_record.get("lfn_slot_offsets"),
                            "start_cluster": start,
                        },
                    ][:32]
                    queue.append(directory_record)
                pending_directory_lfn = []

        active_directories(root_data, root_entry_offsets, [], [])
        try:
            with path.open("rb") as stream:
                while queue and len(inventory) < 32 and total_clusters < 64:
                    directory = queue.pop(0)
                    start = directory["start_cluster"]
                    if not isinstance(start, int) or start in visited_starts:
                        continue
                    visited_starts.add(start)
                    current = start
                    chain: list[dict[str, int]] = []
                    chunks: list[bytes] = []
                    offsets: list[int] = []
                    local_seen: set[int] = set()
                    termination = "limit"
                    while total_clusters < 64 and len(chunks) * cluster_size < 8 * _MIB:
                        if current in local_seen or current in visited_clusters:
                            termination = "loop_or_shared_cluster"
                            errors.append(f"subdirectory cluster {start}: loop/shared cluster {current}")
                            break
                        local_seen.add(current)
                        visited_clusters.add(current)
                        physical_offset = (
                            first_data_sector + (current - 2) * sectors_per_cluster
                        ) * bytes_per_sector
                        if current < 2 or physical_offset < 0 or physical_offset + cluster_size > image_size:
                            termination = "image_bounds"
                            errors.append(f"subdirectory cluster {start}: cluster {current} outside image")
                            break
                        stream.seek(physical_offset)
                        chunk = stream.read(cluster_size)
                        if len(chunk) != cluster_size:
                            termination = "truncated_read"
                            errors.append(f"subdirectory cluster {start}: truncated cluster {current}")
                            break
                        chunks.append(chunk)
                        chain.append({"cluster": current, "offset": physical_offset, "length": cluster_size})
                        offsets.extend(physical_offset + index * 32 for index in range(cluster_size // 32))
                        total_clusters += 1
                        fat_entry_offset = fat_offset + current * 4
                        if fat_entry_offset < fat_offset or fat_entry_offset + 4 > fat_end or fat_entry_offset + 4 > image_size:
                            termination = "fat_bounds"
                            errors.append(f"subdirectory cluster {start}: FAT entry outside bounds")
                            break
                        stream.seek(fat_entry_offset)
                        raw_next = stream.read(4)
                        if len(raw_next) != 4:
                            termination = "truncated_fat"
                            errors.append(f"subdirectory cluster {start}: truncated FAT entry")
                            break
                        next_cluster = int.from_bytes(raw_next, "little") & 0x0FFFFFFF
                        chain[-1].update({
                            "fat_entry_offset": fat_entry_offset,
                            "fat_entry_raw": raw_next.hex(),
                            "next_cluster": next_cluster,
                        })
                        if next_cluster >= 0x0FFFFFF8:
                            termination = "eoc"
                            break
                        if next_cluster < 2 or next_cluster == 0x0FFFFFF7 or 0x0FFFFFF0 <= next_cluster <= 0x0FFFFFF6:
                            termination = "invalid_fat_value"
                            errors.append(f"subdirectory cluster {start}: invalid next cluster 0x{next_cluster:08X}")
                            break
                        current = next_cluster
                    directory_data = b"".join(chunks)
                    lineage = [int(item["cluster"]) for item in chain]
                    inventory.append({
                        **directory, "cluster_chain": chain, "termination": termination,
                    })
                    directory_identities = directory.get("directory_identity_lineage")
                    active_directories(
                        directory_data, offsets, lineage,
                        directory_identities if isinstance(directory_identities, list) else [],
                    )
                    pending_lfn: list[tuple[int, bytes]] = []
                    for index in range(min(len(directory_data) // 32, 2_048)):
                        entry = directory_data[index * 32:(index + 1) * 32]
                        if entry[0] == 0:
                            if pending_lfn and len(unlinked_lfn_slots) < 256:
                                unlinked_lfn_slots.append({
                                    "directory_start_cluster": start,
                                    "directory_cluster_lineage": lineage,
                                    "directory_source_entry_offset": directory.get("source_entry_offset"),
                                    "short_entry_index": None,
                                    "short_entry_offset": None,
                                    "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                    "reason": "LFN slots are not followed by a short entry",
                                    "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                })
                            break
                        attributes = entry[11]
                        if attributes == 0x0F:
                            if len(pending_lfn) < 21:
                                pending_lfn.append((index, entry))
                            continue
                        if entry[0] != 0xE5:
                            if pending_lfn and attributes & 0x08:
                                if len(unlinked_lfn_slots) < 256:
                                    unlinked_lfn_slots.append({
                                        "directory_start_cluster": start,
                                        "directory_cluster_lineage": lineage,
                                        "directory_source_entry_offset": directory.get("source_entry_offset"),
                                        "short_entry_index": index,
                                        "short_entry_offset": offsets[index],
                                        "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                        "reason": "LFN slots are followed by an incompatible volume-label entry",
                                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                    })
                            elif pending_lfn and attributes & 0x10:
                                directory_lfn, lfn_error = GenericTriageEngine._fat_active_lfn_candidate(
                                    pending_lfn, entry, offsets,
                                )
                                if directory_lfn is not None:
                                    directory_record = next(
                                        (
                                            item for item in queue
                                            if item.get("source_entry_offset") == offsets[index]
                                        ),
                                        None,
                                    )
                                    if directory_record is not None:
                                        directory_record.update(directory_lfn)
                                elif len(unlinked_lfn_slots) < 256:
                                    unlinked_lfn_slots.append({
                                        "directory_start_cluster": start,
                                        "directory_cluster_lineage": lineage,
                                        "directory_source_entry_offset": directory.get("source_entry_offset"),
                                        "short_entry_index": index,
                                        "short_entry_offset": offsets[index],
                                        "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                        "reason": lfn_error,
                                        "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                    })
                            if not attributes & 0x18 and len(active_regular_files) < 512:
                                raw_cluster = (
                                    int.from_bytes(entry[20:22], "little") << 16
                                    | int.from_bytes(entry[26:28], "little")
                                )
                                first_cluster = raw_cluster & 0x0FFFFFFF
                                file_size = int.from_bytes(entry[28:32], "little")
                                if raw_cluster >> 28 == 0 and first_cluster >= 2 and 0 < file_size <= 8 * _MIB:
                                    short_raw = bytes([0xE5]) + entry[1:11] if entry[0] == 0x05 else entry[:11]
                                    base = short_raw[:8].decode("cp437", errors="replace").rstrip(" ")
                                    extension = short_raw[8:11].decode("cp437", errors="replace").rstrip(" ")
                                    active_file: dict[str, object] = {
                                        "directory_start_cluster": start,
                                        "directory_cluster_lineage": lineage,
                                        "directory_source_entry_offset": directory.get("source_entry_offset"),
                                        "directory_short_name": directory.get("name"),
                                        "directory_long_name": directory.get("long_name"),
                                        "directory_lfn_slot_offsets": directory.get("lfn_slot_offsets"),
                                        "directory_identity_lineage": directory.get("directory_identity_lineage"),
                                        "entry_index": index, "offset": offsets[index],
                                        "short_name": base + (f".{extension}" if extension else ""),
                                        "attributes": f"0x{attributes:02X}",
                                        "first_cluster": first_cluster,
                                        "cluster_field_raw": f"0x{raw_cluster:08X}",
                                        "fat32_cluster_high_reserved": raw_cluster >> 28,
                                        "size": file_size, "raw_hex": entry.hex(),
                                    }
                                    if pending_lfn:
                                        lfn, lfn_error = GenericTriageEngine._fat_active_lfn_candidate(
                                            pending_lfn, entry, offsets,
                                        )
                                        if lfn is not None:
                                            active_file.update(lfn)
                                        elif len(unlinked_lfn_slots) < 256:
                                            unlinked_lfn_slots.append({
                                                "directory_start_cluster": start,
                                                "directory_cluster_lineage": lineage,
                                                "directory_source_entry_offset": directory.get("source_entry_offset"),
                                                "short_entry_index": index,
                                                "short_entry_offset": offsets[index],
                                                "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                                "reason": lfn_error,
                                                "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                            })
                                    active_regular_files.append(active_file)
                            pending_lfn = []
                            continue
                        base = entry[1:8].decode("cp437", errors="replace").rstrip(" ")
                        extension = entry[8:11].decode("cp437", errors="replace").rstrip(" ")
                        raw_cluster = int.from_bytes(entry[20:22], "little") << 16 | int.from_bytes(entry[26:28], "little")
                        first_cluster = raw_cluster & 0x0FFFFFFF
                        recovered: dict[str, object] = {
                            "directory_start_cluster": start,
                            "directory_cluster_lineage": lineage,
                            "directory_source_entry_offset": directory.get("source_entry_offset"),
                            "directory_short_name": directory.get("name"),
                            "directory_long_name": directory.get("long_name"),
                            "directory_lfn_slot_offsets": directory.get("lfn_slot_offsets"),
                            "directory_identity_lineage": directory.get("directory_identity_lineage"),
                            "entry_index": index,
                            "offset": offsets[index],
                            "short_name": f"?{base}" + (f".{extension}" if extension else ""),
                            "first_character_unknown": True,
                            "attributes": f"0x{attributes:02X}",
                            "first_cluster": first_cluster,
                            "cluster_field_raw": f"0x{raw_cluster:08X}",
                            "fat32_cluster_high_reserved": raw_cluster >> 28,
                            "size": int.from_bytes(entry[28:32], "little"),
                            "raw_hex": entry.hex(),
                        }
                        if pending_lfn:
                            lfn, lfn_error = GenericTriageEngine._fat_deleted_lfn_candidate(
                                pending_lfn, entry, offsets,
                            )
                            if lfn is not None:
                                recovered.update(lfn)
                            elif len(unlinked_lfn_slots) < 256:
                                unlinked_lfn_slots.append({
                                    "directory_start_cluster": start,
                                    "directory_cluster_lineage": lineage,
                                    "directory_source_entry_offset": directory.get("source_entry_offset"),
                                    "short_entry_index": index,
                                    "short_entry_offset": offsets[index],
                                    "slot_offsets": [offsets[slot_index] for slot_index, _ in pending_lfn],
                                    "reason": lfn_error,
                                    "raw_hex": [slot.hex() for _, slot in pending_lfn],
                                })
                        deleted.append(recovered)
                        pending_lfn = []
                        if len(deleted) >= 512:
                            return (
                                deleted, inventory, errors, active_cluster_starts,
                                active_regular_files, unlinked_lfn_slots,
                            )
        except OSError as exc:
            errors.append(str(exc)[:2_000])
        if queue:
            errors.append("subdirectory traversal reached the 32-directory/64-cluster bound")
        return (
            deleted, inventory, errors, active_cluster_starts,
            active_regular_files, unlinked_lfn_slots,
        )

    @staticmethod
    def _fat_short_name_checksum(short_name: bytes) -> int:
        checksum = 0
        for value in short_name[:11]:
            checksum = (((checksum & 1) << 7) | (checksum >> 1)) + value
            checksum &= 0xFF
        return checksum

    @staticmethod
    def _fat_active_lfn_candidate(
        slots: list[tuple[int, bytes]], short_entry: bytes, entry_offsets: list[int]
    ) -> tuple[dict[str, object] | None, str | None]:
        """Validate an intact active LFN chain immediately preceding its short entry."""
        if not 1 <= len(slots) <= 20:
            return None, "LFN chain exceeds the 20-slot/255-character bound"
        if any(
            slot[0] == 0xE5 or slot[11] != 0x0F or slot[12] != 0
            or slot[26:28] != b"\x00\x00"
            for _, slot in slots
        ):
            return None, "active LFN slot structure is invalid or deleted"
        expected_ordinals = [
            (len(slots) | 0x40) if index == 0 else len(slots) - index
            for index in range(len(slots))
        ]
        if [slot[0] for _, slot in slots] != expected_ordinals:
            return None, "active LFN ordinal order or terminal marker is invalid"
        checksum = GenericTriageEngine._fat_short_name_checksum(short_entry[:11])
        if any(slot[13] != checksum for _, slot in slots):
            return None, "active LFN checksum does not match the short entry"
        units: list[int] = []
        for _, slot in reversed(slots):
            raw_name = slot[1:11] + slot[14:26] + slot[28:32]
            units.extend(
                int.from_bytes(raw_name[index:index + 2], "little")
                for index in range(0, 26, 2)
            )
        if 0 in units:
            terminator = units.index(0)
            if any(value != 0xFFFF for value in units[terminator + 1:]):
                return None, "active LFN bytes after NUL are not 0xFFFF padding"
            units = units[:terminator]
            terminal_validation = "nul_terminator_with_ffff_padding"
        else:
            if 0xFFFF in units:
                return None, "active LFN padding exists without a NUL terminator"
            terminal_validation = "exact_full_slot_name_without_padding"
        if not units or len(units) > 255:
            return None, "active LFN decoded length is invalid"
        raw_utf16 = b"".join(value.to_bytes(2, "little") for value in units)
        try:
            long_name = raw_utf16.decode("utf-16le", errors="strict")
        except UnicodeDecodeError:
            return None, "active LFN is not valid UTF-16LE"
        if any(character in long_name for character in "\x00/\\"):
            return None, "active LFN contains a path separator or NUL"
        return {
            "long_name": long_name,
            "lfn_slot_offsets": [entry_offsets[index] for index, _ in slots],
            "lfn_checksum": f"0x{checksum:02X}",
            "lfn_order_validation": "stored_ordinals_and_terminal_marker",
            "lfn_terminal_validation": terminal_validation,
        }, None

    @staticmethod
    def _fat_deleted_lfn_candidate(
        slots: list[tuple[int, bytes]], short_entry: bytes, entry_offsets: list[int]
    ) -> tuple[dict[str, object] | None, str | None]:
        if not 1 <= len(slots) <= 20:
            return None, "LFN chain exceeds the 20-slot/255-character bound"
        checksums = {slot[13] for _, slot in slots}
        if len(checksums) != 1:
            return None, "LFN slots do not share one short-name checksum"
        if any(slot[11] != 0x0F or slot[12] != 0 or slot[26:28] != b"\x00\x00" for _, slot in slots):
            return None, "LFN slot type, attributes, or first-cluster field is invalid"
        ordinals = [slot[0] for _, slot in slots]
        all_deleted = all(value == 0xE5 for value in ordinals)
        all_intact = all(value != 0xE5 for value in ordinals)
        if not (all_deleted or all_intact):
            return None, "LFN chain mixes destroyed and intact ordinal bytes"
        if all_intact:
            expected = [
                (len(slots) | 0x40) if index == 0 else len(slots) - index
                for index in range(len(slots))
            ]
            if ordinals != expected:
                return None, "LFN ordinal order or terminal-slot marker is invalid"
            order_validation = "stored_ordinals_and_terminal_marker"
        else:
            order_validation = "contiguous_deleted_slots_physical_order"
        checksum = next(iter(checksums))
        short_candidates = []
        for first_byte in range(256):
            candidate = bytes([first_byte]) + short_entry[1:11]
            if GenericTriageEngine._fat_short_name_checksum(candidate) == checksum:
                short_candidates.append(first_byte)
        if len(short_candidates) != 1:
            return None, f"deleted short-name first byte has {len(short_candidates)} checksum solutions"
        units: list[int] = []
        for _, slot in reversed(slots):
            raw_name = slot[1:11] + slot[14:26] + slot[28:32]
            units.extend(int.from_bytes(raw_name[index:index + 2], "little") for index in range(0, 26, 2))
        if 0 in units:
            terminator = units.index(0)
            if any(value != 0xFFFF for value in units[terminator + 1:]):
                return None, "LFN bytes after the terminator are not 0xFFFF padding"
            units = units[:terminator]
            terminal_validation = "nul_terminator_with_ffff_padding"
        else:
            if 0xFFFF in units:
                return None, "LFN padding exists without a preceding terminator"
            terminal_validation = "exact_full_slot_name_without_padding"
        if not units or len(units) > 255:
            return None, "LFN decoded length is outside 1..255 characters"
        try:
            long_name = b"".join(value.to_bytes(2, "little") for value in units).decode("utf-16le")
        except UnicodeDecodeError:
            return None, "LFN contains invalid UTF-16"
        if any(ord(character) < 32 or character in '\\/:*?"<>|' for character in long_name):
            return None, "LFN contains control or forbidden filename characters"
        recovered_first = short_candidates[0]
        display_first = 0xE5 if recovered_first == 0x05 else recovered_first
        recovered_short = bytes([display_first]) + short_entry[1:11]
        base = recovered_short[:8].decode("cp437", errors="replace").rstrip(" ")
        extension = recovered_short[8:11].decode("cp437", errors="replace").rstrip(" ")
        return {
            "long_name": long_name,
            "lfn_checksum": checksum,
            "lfn_slot_count": len(slots),
            "lfn_slot_indices": [index for index, _ in slots],
            "lfn_slot_offsets": [entry_offsets[index] for index, _ in slots],
            "lfn_ordinal_bytes_destroyed": all_deleted,
            "lfn_order_validation": order_validation,
            "lfn_terminal_validation": terminal_validation,
            "recovered_short_first_byte": f"0x{recovered_first:02X}",
            "reconstructed_short_name": base + (f".{extension}" if extension else ""),
        }, None

    @staticmethod
    def _fat_datetime(date_value: int, time_value: int, tenths: int = 0) -> str | None:
        if date_value == 0:
            return None
        year = 1980 + ((date_value >> 9) & 0x7F)
        month = (date_value >> 5) & 0x0F
        day = date_value & 0x1F
        hour = (time_value >> 11) & 0x1F
        minute = (time_value >> 5) & 0x3F
        second = (time_value & 0x1F) * 2
        bounded_tenths = min(max(tenths, 0), 199)
        microsecond = (bounded_tenths % 100) * 10_000
        if bounded_tenths >= 100:
            second += 1
        try:
            return datetime(year, month, day, hour, minute, second, microsecond).isoformat()
        except ValueError:
            return None

    def _inspect_ntfs_backup_boot(
        self, artifact: Artifact, path: Path, image_size: int, bytes_per_sector: int
    ) -> list[Observation]:
        prefix = "filesystem.ntfs.backup_boot"
        if bytes_per_sector not in {512, 1024, 2048, 4096} or image_size < bytes_per_sector * 2:
            return [self._observation(artifact, f"{prefix}.available", False)]
        backup_offset = image_size - bytes_per_sector
        try:
            with path.open("rb") as stream:
                primary = stream.read(bytes_per_sector)
                stream.seek(backup_offset)
                backup = stream.read(bytes_per_sector)
        except OSError as exc:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.error", str(exc)[:2_000], confidence=0.9),
            ]
        backup_signature = len(backup) >= 512 and backup[3:11] == b"NTFS    "
        backup_end_marker = len(backup) >= 512 and backup[510:512] == b"\x55\xaa"
        primary_valid = len(primary) >= 512 and primary[3:11] == b"NTFS    " and primary[510:512] == b"\x55\xaa"
        backup_valid = backup_signature and backup_end_marker
        match = None
        first_difference = None
        if primary_valid and backup_valid:
            match = primary[:512] == backup[:512]
            if not match:
                first_difference = next(
                    (index for index in range(512) if primary[index] != backup[index]), None
                )
        return [
            self._observation(artifact, f"{prefix}.available", backup_signature),
            self._observation(artifact, f"{prefix}.offset", backup_offset),
            self._observation(artifact, f"{prefix}.signature_valid", backup_signature),
            self._observation(artifact, f"{prefix}.end_marker_valid", backup_end_marker),
            self._observation(artifact, f"{prefix}.primary_valid", primary_valid),
            self._observation(artifact, f"{prefix}.valid", backup_valid),
            self._observation(artifact, f"{prefix}.primary_match", match),
            self._observation(artifact, f"{prefix}.first_difference_offset", first_difference),
        ]

    def _inspect_ntfs_mft0(
        self,
        artifact: Artifact,
        path: Path,
        image_size: int,
        mft_lcn: int,
        bytes_per_sector: int,
        sectors_per_cluster: int,
        record_size: int,
        index_record_size: int,
        mft_mirror_lcn: int,
    ) -> list[Observation]:
        """Read only the fixed header of MFT record zero when geometrically safe."""
        cluster_size = bytes_per_sector * sectors_per_cluster
        offset = mft_lcn * cluster_size
        if (
            bytes_per_sector not in {512, 1024, 2048, 4096}
            or sectors_per_cluster <= 0
            or cluster_size > 2 * _MIB
            or record_size < 48
            or record_size > 4 * _MIB
            or offset < 0
            or offset + 48 > image_size
        ):
            return [self._observation(artifact, "filesystem.ntfs.mft0_available", False)]
        try:
            with path.open("rb") as stream:
                stream.seek(offset)
                record = stream.read(min(record_size, 4096))
        except OSError as exc:
            return [self._observation(artifact, "filesystem.ntfs.mft0_error", str(exc), confidence=0.8)]
        if len(record) < 48:
            return [self._observation(artifact, "filesystem.ntfs.mft0_available", False)]
        signature_valid = record.startswith(b"FILE")
        usa_offset = int.from_bytes(record[4:6], "little")
        usa_count = int.from_bytes(record[6:8], "little")
        flags = int.from_bytes(record[22:24], "little")
        first_attribute = int.from_bytes(record[20:22], "little")
        used_size = int.from_bytes(record[24:28], "little")
        allocated_size = int.from_bytes(record[28:32], "little")
        bounds_valid = first_attribute >= 24 and used_size <= allocated_size <= record_size
        fixed_record, fixup_valid, fixup_error = self._ntfs_apply_usa_fixup(
            record, bytes_per_sector, usa_offset, usa_count, allocated_size
        )
        attributes, attribute_errors = self._ntfs_attribute_inventory(
            fixed_record, first_attribute, used_size, fixup_valid
        )
        timestamp_mismatches = self._ntfs_timestamp_mismatches(attributes)
        sample_records, sample_errors = self._inspect_ntfs_mft_record_sample(
            path, image_size, record_size, index_record_size, bytes_per_sector, cluster_size, attributes,
            signature_valid and bounds_valid and fixup_valid,
        )
        sample_parent_links = self._ntfs_sample_parent_links(sample_records)
        sample_index_links = self._ntfs_sample_index_links(sample_records)
        sample_attribute_list_links = self._ntfs_sample_attribute_list_links(sample_records)
        sample_record_anomalies = self._ntfs_sample_record_anomalies(sample_records)
        observations = [
            self._observation(artifact, "filesystem.ntfs.mft0_available", True),
            self._observation(artifact, "filesystem.ntfs.mft0_offset", offset),
            self._observation(artifact, "filesystem.ntfs.mft0_valid_signature", signature_valid),
            self._observation(artifact, "filesystem.ntfs.mft0_sequence_number", int.from_bytes(record[16:18], "little")),
            self._observation(artifact, "filesystem.ntfs.mft0_hard_link_count", int.from_bytes(record[18:20], "little")),
            self._observation(artifact, "filesystem.ntfs.mft0_first_attribute_offset", first_attribute),
            self._observation(artifact, "filesystem.ntfs.mft0_flags", {"in_use": bool(flags & 1), "directory": bool(flags & 2)}),
            self._observation(artifact, "filesystem.ntfs.mft0_used_size", used_size),
            self._observation(artifact, "filesystem.ntfs.mft0_allocated_size", allocated_size),
            self._observation(artifact, "filesystem.ntfs.mft0_usa_offset", usa_offset),
            self._observation(artifact, "filesystem.ntfs.mft0_usa_count", usa_count),
            self._observation(artifact, "filesystem.ntfs.mft0_bounds_valid", bounds_valid),
            self._observation(artifact, "filesystem.ntfs.mft0_usa_fixup_valid", fixup_valid),
            self._observation(artifact, "filesystem.ntfs.mft0_usa_fixup_error", fixup_error),
            self._observation(artifact, "filesystem.ntfs.mft0_attributes", attributes),
            self._observation(artifact, "filesystem.ntfs.mft0_attribute_errors", attribute_errors),
            self._observation(artifact, "filesystem.ntfs.mft0_timestamp_mismatches", timestamp_mismatches),
            self._observation(artifact, "filesystem.ntfs.mft_sample_limit", 256),
            self._observation(artifact, "filesystem.ntfs.mft_sample_records", sample_records),
            self._observation(artifact, "filesystem.ntfs.mft_sample_errors", sample_errors),
            self._observation(artifact, "filesystem.ntfs.mft_sample_parent_links", sample_parent_links),
            self._observation(artifact, "filesystem.ntfs.mft_sample_index_links", sample_index_links),
            self._observation(artifact, "filesystem.ntfs.mft_sample_attribute_list_links", sample_attribute_list_links),
            self._observation(artifact, "filesystem.ntfs.mft_sample_record_anomalies", sample_record_anomalies),
        ]
        observations.extend(self._inspect_ntfs_mft_mirror(
            artifact, path, image_size, mft_mirror_lcn, cluster_size,
            bytes_per_sector, record_size, fixed_record,
            signature_valid and bounds_valid and fixup_valid, allocated_size,
        ))
        return observations

    def _inspect_ntfs_mft_mirror(
        self,
        artifact: Artifact,
        path: Path,
        image_size: int,
        mirror_lcn: int,
        cluster_size: int,
        bytes_per_sector: int,
        record_size: int,
        primary_fixed: bytes,
        primary_valid: bool,
        primary_allocated_size: int,
    ) -> list[Observation]:
        offset = mirror_lcn * cluster_size
        available = (
            mirror_lcn > 0 and cluster_size > 0 and record_size >= 48
            and record_size <= 4096 and offset >= 0 and offset + record_size <= image_size
        )
        prefix = "filesystem.ntfs.mft_mirror"
        if not available:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.offset", offset if mirror_lcn > 0 else None),
            ]
        try:
            with path.open("rb") as stream:
                stream.seek(offset)
                raw = stream.read(record_size)
        except OSError as exc:
            return [
                self._observation(artifact, f"{prefix}.available", False),
                self._observation(artifact, f"{prefix}.offset", offset),
                self._observation(artifact, f"{prefix}.error", str(exc)[:2_000], confidence=0.9),
            ]
        signature_valid = raw.startswith(b"FILE")
        first_attribute = int.from_bytes(raw[20:22], "little")
        used_size = int.from_bytes(raw[24:28], "little")
        allocated_size = int.from_bytes(raw[28:32], "little")
        bounds_valid = (
            first_attribute >= 24 and used_size <= allocated_size <= record_size
        )
        fixed, fixup_valid, fixup_error = self._ntfs_apply_usa_fixup(
            raw, bytes_per_sector,
            int.from_bytes(raw[4:6], "little"),
            int.from_bytes(raw[6:8], "little"),
            allocated_size,
        )
        mirror_valid = signature_valid and bounds_valid and fixup_valid
        primary_match = None
        first_difference = None
        if primary_valid and mirror_valid:
            compare_length = min(primary_allocated_size, allocated_size)
            primary_match = (
                primary_allocated_size == allocated_size
                and primary_fixed[:compare_length] == fixed[:compare_length]
            )
            if not primary_match:
                for index in range(compare_length):
                    if primary_fixed[index] != fixed[index]:
                        first_difference = index
                        break
                if first_difference is None and primary_allocated_size != allocated_size:
                    first_difference = compare_length
        return [
            self._observation(artifact, f"{prefix}.available", True),
            self._observation(artifact, f"{prefix}.offset", offset),
            self._observation(artifact, f"{prefix}.signature_valid", signature_valid),
            self._observation(artifact, f"{prefix}.bounds_valid", bounds_valid),
            self._observation(artifact, f"{prefix}.usa_fixup_valid", fixup_valid),
            self._observation(artifact, f"{prefix}.usa_fixup_error", fixup_error),
            self._observation(artifact, f"{prefix}.allocated_size", allocated_size),
            self._observation(artifact, f"{prefix}.primary_match", primary_match),
            self._observation(artifact, f"{prefix}.first_difference_offset", first_difference),
        ]

    def _inspect_ntfs_usn_journal(
        self, artifact: Artifact, path: Path, size: int
    ) -> list[Observation]:
        """Parse aligned USN_RECORD_V2/V3/V4 entries only from an explicitly named `$J` stream."""
        window = 8 * _MIB
        ranges = [(0, min(size, window))]
        if size > window:
            ranges.append((max(window, size - window), size))
        records: list[dict[str, object]] = []
        errors: list[str] = []
        reason_names = {
            0x00000001: "data_overwrite", 0x00000002: "data_extend", 0x00000004: "data_truncation",
            0x00000010: "named_data_overwrite", 0x00000020: "named_data_extend", 0x00000040: "named_data_truncation",
            0x00000100: "file_create", 0x00000200: "file_delete", 0x00000400: "ea_change",
            0x00000800: "security_change", 0x00001000: "rename_old_name", 0x00002000: "rename_new_name",
            0x00004000: "indexable_change", 0x00008000: "basic_info_change", 0x00010000: "hard_link_change",
            0x00020000: "compression_change", 0x00040000: "encryption_change", 0x00080000: "object_id_change",
            0x00100000: "reparse_point_change", 0x00200000: "stream_change", 0x00400000: "transacted_change",
            0x80000000: "close",
        }
        try:
            with path.open("rb") as stream:
                for range_start, range_end in ranges:
                    stream.seek(range_start)
                    data = stream.read(range_end - range_start)
                    cursor = 0
                    while cursor + 8 <= len(data) and len(records) < 10_000:
                        record_length = int.from_bytes(data[cursor:cursor + 4], "little")
                        if record_length == 0:
                            cursor += 8
                            continue
                        major = int.from_bytes(data[cursor + 4:cursor + 6], "little")
                        minor = int.from_bytes(data[cursor + 6:cursor + 8], "little")
                        header_size = 60 if major == 2 else 76 if major == 3 else 64 if major == 4 else 0
                        if (
                            not header_size or minor != 0 or record_length < header_size
                            or record_length % 8 != 0 or cursor + record_length > len(data)
                        ):
                            if len(errors) < 128:
                                errors.append(
                                    f"offset {range_start + cursor}: invalid USN length/version ({record_length}, {major}.{minor})"
                                )
                            cursor += 8
                            continue
                        if major == 4:
                            extent_count = int.from_bytes(data[cursor + 60:cursor + 62], "little")
                            extent_size = int.from_bytes(data[cursor + 62:cursor + 64], "little")
                            if (
                                extent_count > 256 or not 16 <= extent_size <= 64
                                or 64 + extent_count * extent_size > record_length
                            ):
                                if len(errors) < 128:
                                    errors.append(f"offset {range_start + cursor}: invalid V4 extent bounds")
                                cursor += 8
                                continue
                            reason = int.from_bytes(data[cursor + 48:cursor + 52], "little")
                            extents: list[dict[str, int]] = []
                            extents_valid = True
                            for extent_index in range(extent_count):
                                extent_offset = cursor + 64 + extent_index * extent_size
                                byte_offset = int.from_bytes(
                                    data[extent_offset:extent_offset + 8], "little", signed=True
                                )
                                byte_length = int.from_bytes(
                                    data[extent_offset + 8:extent_offset + 16], "little", signed=True
                                )
                                if byte_length < 0:
                                    extents_valid = False
                                    break
                                extents.append({"offset": byte_offset, "length": byte_length})
                            if not extents_valid:
                                if len(errors) < 128:
                                    errors.append(f"offset {range_start + cursor}: negative V4 extent length")
                                cursor += 8
                                continue
                            records.append({
                                "offset": range_start + cursor,
                                "record_length": record_length,
                                "major_version": major,
                                "minor_version": minor,
                                "file_id_128": data[cursor + 8:cursor + 24].hex(),
                                "parent_file_id_128": data[cursor + 24:cursor + 40].hex(),
                                "usn": int.from_bytes(data[cursor + 40:cursor + 48], "little", signed=True),
                                "reason": f"0x{reason:08X}",
                                "reason_names": [name for bit, name in reason_names.items() if reason & bit],
                                "source_info": f"0x{int.from_bytes(data[cursor + 52:cursor + 56], 'little'):08X}",
                                "remaining_extents": int.from_bytes(data[cursor + 56:cursor + 60], "little"),
                                "number_of_extents": extent_count,
                                "extent_size": extent_size,
                                "extents": extents,
                            })
                            cursor += record_length
                            continue
                        usn_offset = 24 if major == 2 else 40
                        timestamp_offset = 32 if major == 2 else 48
                        reason_offset = 40 if major == 2 else 56
                        source_offset = 44 if major == 2 else 60
                        security_offset = 48 if major == 2 else 64
                        attributes_offset = 52 if major == 2 else 68
                        name_length_offset = 56 if major == 2 else 72
                        name_length = int.from_bytes(
                            data[cursor + name_length_offset:cursor + name_length_offset + 2], "little"
                        )
                        name_offset = int.from_bytes(
                            data[cursor + name_length_offset + 2:cursor + name_length_offset + 4], "little"
                        )
                        if (
                            name_length % 2 or name_offset < header_size
                            or name_offset + name_length > record_length
                        ):
                            if len(errors) < 128:
                                errors.append(f"offset {range_start + cursor}: invalid USN filename bounds")
                            cursor += 8
                            continue
                        reason = int.from_bytes(
                            data[cursor + reason_offset:cursor + reason_offset + 4], "little"
                        )
                        file_name = data[
                            cursor + name_offset:cursor + name_offset + name_length
                        ].decode("utf-16le", errors="replace")[:1_024]
                        parsed: dict[str, object] = {
                            "offset": range_start + cursor,
                            "record_length": record_length,
                            "major_version": major,
                            "minor_version": minor,
                            "usn": int.from_bytes(
                                data[cursor + usn_offset:cursor + usn_offset + 8], "little", signed=True
                            ),
                            "timestamp": self._filetime_to_iso(
                                data[cursor + timestamp_offset:cursor + timestamp_offset + 8]
                            ),
                            "reason": f"0x{reason:08X}",
                            "reason_names": [name for bit, name in reason_names.items() if reason & bit],
                            "source_info": f"0x{int.from_bytes(data[cursor + source_offset:cursor + source_offset + 4], 'little'):08X}",
                            "security_id": int.from_bytes(
                                data[cursor + security_offset:cursor + security_offset + 4], "little"
                            ),
                            "file_attributes": f"0x{int.from_bytes(data[cursor + attributes_offset:cursor + attributes_offset + 4], 'little'):08X}",
                            "file_name": file_name,
                        }
                        if major == 2:
                            file_reference = int.from_bytes(data[cursor + 8:cursor + 16], "little")
                            parent_reference = int.from_bytes(data[cursor + 16:cursor + 24], "little")
                            parsed.update({
                                "file_record_number": file_reference & ((1 << 48) - 1),
                                "file_sequence_number": file_reference >> 48,
                                "parent_record_number": parent_reference & ((1 << 48) - 1),
                                "parent_sequence_number": parent_reference >> 48,
                            })
                        else:
                            parsed.update({
                                "file_id_128": data[cursor + 8:cursor + 24].hex(),
                                "parent_file_id_128": data[cursor + 24:cursor + 40].hex(),
                            })
                        records.append(parsed)
                        cursor += record_length
        except OSError as exc:
            errors.append(str(exc)[:2_000])
        return [
            self._observation(artifact, "ntfs.usn_journal_detected", True),
            self._observation(
                artifact, "ntfs.usn.scan_ranges",
                [{"offset": start, "length": end - start} for start, end in ranges],
            ),
            self._observation(artifact, "ntfs.usn.records", records),
            self._observation(artifact, "ntfs.usn.record_count", len(records)),
            self._observation(artifact, "ntfs.usn.parse_errors", errors),
            self._observation(artifact, "ntfs.usn.truncated", len(records) >= 10_000),
        ]

    def _inspect_ntfs_mft_record_sample(
        self,
        path: Path,
        image_size: int,
        record_size: int,
        index_record_size: int,
        bytes_per_sector: int,
        cluster_size: int,
        attributes: list[dict[str, object]],
        mft0_valid: bool,
    ) -> tuple[list[dict[str, object]], list[str]]:
        """Map a small MFT-only record sample through validated record-zero runs."""
        if not mft0_valid or record_size <= 0 or record_size > 4096 or cluster_size <= 0:
            return [], []
        data_attribute = next(
            (
                item for item in attributes
                if item.get("type_name") == "data" and not item.get("name")
                and isinstance(item.get("data_runs"), list)
                and isinstance(item.get("real_size"), int)
            ),
            None,
        )
        if not isinstance(data_attribute, dict):
            return [], []
        runs = data_attribute["data_runs"]
        real_size = data_attribute["real_size"]
        if not isinstance(real_size, int) or real_size < record_size:
            return [], []
        # record_size is already capped at 4 KiB, so 256 records bound native
        # MFT sampling to at most 1 MiB of mapped reads.
        record_count = min(256, real_size // record_size)
        records: list[dict[str, object]] = []
        errors: list[str] = []
        try:
            with path.open("rb") as stream:
                for record_number in range(1, record_count):
                    raw, offsets, mapping_error = self._ntfs_read_mapped_range(
                        stream, runs, cluster_size, record_number * record_size, record_size, image_size
                    )
                    if mapping_error:
                        errors.append(f"record {record_number}: {mapping_error}")
                        break
                    if len(raw) != record_size:
                        errors.append(f"record {record_number}: mapped range is truncated")
                        break
                    signature_valid = raw.startswith(b"FILE")
                    usa_offset = int.from_bytes(raw[4:6], "little")
                    usa_count = int.from_bytes(raw[6:8], "little")
                    first_attribute = int.from_bytes(raw[20:22], "little")
                    flags = int.from_bytes(raw[22:24], "little")
                    used_size = int.from_bytes(raw[24:28], "little")
                    allocated_size = int.from_bytes(raw[28:32], "little")
                    bounds_valid = first_attribute >= 24 and used_size <= allocated_size <= record_size
                    fixed, fixup_valid, fixup_error = self._ntfs_apply_usa_fixup(
                        raw, bytes_per_sector,
                        usa_offset, usa_count, allocated_size,
                    )
                    record_attributes, attribute_errors = self._ntfs_attribute_inventory(
                        fixed, first_attribute, used_size, signature_valid and bounds_valid and fixup_valid
                    )
                    file_names = [
                        str(item["file_name"]) for item in record_attributes
                        if item.get("type_name") == "file_name" and isinstance(item.get("file_name"), str)
                    ]
                    file_name_references = [
                        {
                            "file_name": item.get("file_name"),
                            "parent_record_number": item.get("parent_record_number"),
                            "parent_sequence_number": item.get("parent_sequence_number"),
                        }
                        for item in record_attributes
                        if item.get("type_name") == "file_name"
                        and isinstance(item.get("file_name"), str)
                        and isinstance(item.get("parent_record_number"), int)
                        and isinstance(item.get("parent_sequence_number"), int)
                    ][:16]
                    standard_information = [
                        item["timestamps"] for item in record_attributes
                        if item.get("type_name") == "standard_information" and isinstance(item.get("timestamps"), dict)
                    ][:4]
                    attribute_list_references = [
                        reference for item in record_attributes
                        if item.get("type_name") == "attribute_list" and isinstance(item.get("extent_references"), list)
                        for reference in item["extent_references"]
                        if isinstance(reference, dict)
                    ][:64]
                    index_entries = [
                        {"attribute_offset": item.get("offset"), **entry}
                        for item in record_attributes
                        if item.get("type_name") == "index_root" and isinstance(item.get("index_entries"), list)
                        for entry in item["index_entries"][:64]
                        if isinstance(entry, dict)
                    ][:128]
                    index_allocation_entries: list[dict[str, object]] = []
                    index_allocation_slack_entries: list[dict[str, object]] = []
                    index_allocation_buffers: list[dict[str, object]] = []
                    index_allocation_errors: list[str] = []
                    if 512 <= index_record_size <= 64 * 1024 and index_record_size % bytes_per_sector == 0:
                        for item in record_attributes:
                            if (
                                item.get("type_name") != "index_allocation"
                                or item.get("nonresident") is not True
                                or item.get("name") not in {"$I30", None}
                            ):
                                continue
                            parsed_entries, parsed_slack, parsed_buffers, parsed_errors = self._ntfs_index_allocation_entries(
                                stream, item, cluster_size, index_record_size,
                                bytes_per_sector, image_size,
                            )
                            index_allocation_entries.extend(parsed_entries[:256 - len(index_allocation_entries)])
                            index_allocation_slack_entries.extend(
                                parsed_slack[:256 - len(index_allocation_slack_entries)]
                            )
                            index_allocation_buffers.extend(parsed_buffers[:64 - len(index_allocation_buffers)])
                            index_allocation_errors.extend(parsed_errors[:64 - len(index_allocation_errors)])
                            if len(index_allocation_entries) >= 256 or len(index_allocation_buffers) >= 64:
                                break
                    resident_data_attributes = [
                        {
                            "attribute_offset": item.get("offset"),
                            "resident_value_offset": item.get("resident_value_offset"),
                            "attribute_id": item.get("attribute_id"),
                            "stream_name": item.get("name"),
                            "value_length": item.get("value_length"),
                            "data_hex": item.get("resident_data_hex"),
                        }
                        for item in record_attributes
                        if item.get("type_name") == "data"
                        and item.get("nonresident") is False
                        and item.get("value_bounds_valid") is True
                        and isinstance(item.get("resident_data_hex"), str)
                        and isinstance(item.get("value_length"), int)
                    ][:16]
                    nonresident_data_attributes = [
                        {
                            "attribute_offset": item.get("offset"),
                            "attribute_id": item.get("attribute_id"),
                            "stream_name": item.get("name"),
                            "attribute_flags": item.get("attribute_flags"),
                            "lowest_vcn": item.get("lowest_vcn"),
                            "highest_vcn": item.get("highest_vcn"),
                            "allocated_size": item.get("allocated_size"),
                            "real_size": item.get("real_size"),
                            "initialized_size": item.get("initialized_size"),
                            "data_runs": item.get("data_runs"),
                        }
                        for item in record_attributes
                        if item.get("type_name") == "data"
                        and item.get("nonresident") is True
                        and isinstance(item.get("data_runs"), list)
                        and isinstance(item.get("real_size"), int)
                    ][:16]
                    summary = {
                        "record_number": record_number,
                        "physical_segments": offsets,
                        "signature_valid": signature_valid,
                        "bounds_valid": bounds_valid,
                        "usa_fixup_valid": fixup_valid,
                        "usa_fixup_error": fixup_error,
                        "sequence_number": int.from_bytes(raw[16:18], "little"),
                        "in_use": bool(flags & 1),
                        "directory": bool(flags & 2),
                        "deleted": signature_valid and bounds_valid and fixup_valid and not bool(flags & 1),
                        "file_names": file_names,
                        "file_name_references": file_name_references,
                        "standard_information": standard_information,
                        "attribute_list_references": attribute_list_references,
                        "index_root_entries": index_entries,
                        "attribute_errors": attribute_errors,
                    }
                    base_reference = int.from_bytes(raw[32:40], "little")
                    if base_reference:
                        summary["base_record_number"] = base_reference & ((1 << 48) - 1)
                        summary["base_sequence_number"] = base_reference >> 48
                    if index_allocation_entries:
                        summary["index_allocation_entries"] = index_allocation_entries
                    if index_allocation_slack_entries:
                        summary["index_allocation_slack_entries"] = index_allocation_slack_entries
                    if index_allocation_buffers:
                        summary["index_allocation_buffers"] = index_allocation_buffers
                    if index_allocation_errors:
                        summary["index_allocation_errors"] = index_allocation_errors
                    if resident_data_attributes:
                        summary["resident_data_attributes"] = resident_data_attributes
                    if nonresident_data_attributes:
                        summary["nonresident_data_attributes"] = nonresident_data_attributes
                    records.append(summary)
        except OSError as exc:
            return [], [str(exc)[:2_000]]
        GenericTriageEngine._ntfs_join_sampled_data_extents(records)
        return records, errors

    @staticmethod
    def _ntfs_join_sampled_data_extents(records: list[dict[str, object]]) -> None:
        """Attach complete sampled DATA extent sets after exact lineage checks."""
        by_record = {
            item["record_number"]: item
            for item in records
            if isinstance(item.get("record_number"), int)
            and item.get("signature_valid") is True
            and item.get("bounds_valid") is True
            and item.get("usa_fixup_valid") is True
        }
        for base in records:
            base_number = base.get("record_number")
            base_sequence = base.get("sequence_number")
            references = base.get("attribute_list_references")
            streams = base.get("nonresident_data_attributes")
            if (
                not isinstance(base_number, int) or not isinstance(base_sequence, int)
                or not isinstance(references, list) or not isinstance(streams, list)
            ):
                continue
            joined: list[dict[str, object]] = []
            for base_stream in streams[:16]:
                if not isinstance(base_stream, dict) or base_stream.get("lowest_vcn") != 0:
                    continue
                attribute_id = base_stream.get("attribute_id")
                stream_name = base_stream.get("stream_name")
                matching_refs = sorted(
                    (
                        reference for reference in references
                        if isinstance(reference, dict)
                        and reference.get("type_name") == "data"
                        and reference.get("name") == stream_name
                        and isinstance(reference.get("lowest_vcn"), int)
                    ),
                    key=lambda item: int(item["lowest_vcn"]),
                )
                base_ref_valid = any(
                    item.get("lowest_vcn") == 0
                    and item.get("record_number") == base_number
                    and item.get("sequence_number") == base_sequence
                    and item.get("attribute_id") == attribute_id
                    for item in matching_refs
                )
                extension_refs = [item for item in matching_refs if item.get("lowest_vcn", 0) > 0]
                if not base_ref_valid or not extension_refs or len(extension_refs) > 15:
                    continue
                extents = [base_stream]
                provenance = [{
                    "record_number": base_number,
                    "sequence_number": base_sequence,
                    "attribute_offset": base_stream.get("attribute_offset"),
                    "lowest_vcn": base_stream.get("lowest_vcn"),
                    "highest_vcn": base_stream.get("highest_vcn"),
                    "mft_physical_segments": base.get("physical_segments"),
                }]
                valid = True
                for reference in extension_refs:
                    target_number = reference.get("record_number")
                    target_sequence = reference.get("sequence_number")
                    target = by_record.get(target_number) if isinstance(target_number, int) else None
                    if (
                        not isinstance(target, dict)
                        or target.get("sequence_number") != target_sequence
                        or target.get("base_record_number") != base_number
                        or target.get("base_sequence_number") != base_sequence
                    ):
                        valid = False
                        break
                    target_streams = target.get("nonresident_data_attributes")
                    extent = next(
                        (
                            item for item in target_streams
                            if isinstance(item, dict)
                            and item.get("attribute_id") == reference.get("attribute_id")
                            and item.get("stream_name") == stream_name
                            and item.get("lowest_vcn") == reference.get("lowest_vcn")
                        ),
                        None,
                    ) if isinstance(target_streams, list) else None
                    if not isinstance(extent, dict):
                        valid = False
                        break
                    if extent.get("attribute_flags") != base_stream.get("attribute_flags"):
                        valid = False
                        break
                    extents.append(extent)
                    provenance.append({
                        "record_number": target_number,
                        "sequence_number": target_sequence,
                        "attribute_offset": extent.get("attribute_offset"),
                        "lowest_vcn": extent.get("lowest_vcn"),
                        "highest_vcn": extent.get("highest_vcn"),
                        "mft_physical_segments": target.get("physical_segments"),
                    })
                expected_vcn = 0
                combined_runs: list[dict[str, int | None]] = []
                for extent in sorted(extents, key=lambda item: int(item.get("lowest_vcn", -1))):
                    lowest = extent.get("lowest_vcn")
                    highest = extent.get("highest_vcn")
                    extent_runs = extent.get("data_runs")
                    if (
                        not isinstance(lowest, int) or lowest != expected_vcn
                        or not isinstance(highest, int) or highest < lowest
                        or not isinstance(extent_runs, list)
                    ):
                        valid = False
                        break
                    combined_runs.extend(extent_runs)
                    expected_vcn = highest + 1
                if not valid or len(combined_runs) > 64:
                    continue
                joined.append({
                    **base_stream,
                    "highest_vcn": expected_vcn - 1,
                    "data_runs": combined_runs,
                    "extent_provenance": provenance,
                })
            if joined:
                base["joined_nonresident_data_attributes"] = joined

    @staticmethod
    def _ntfs_index_allocation_entries(
        stream,
        attribute: dict[str, object],
        cluster_size: int,
        index_record_size: int,
        bytes_per_sector: int,
        image_size: int,
    ) -> tuple[
        list[dict[str, object]], list[dict[str, object]],
        list[dict[str, object]], list[str],
    ]:
        """Read at most 1 MiB/64 INDX buffers from one validated run list."""
        runs = attribute.get("data_runs")
        real_size = attribute.get("real_size")
        lowest_vcn = attribute.get("lowest_vcn")
        flags = attribute.get("attribute_flags")
        if (
            not isinstance(runs, list) or not runs or len(runs) > 64
            or not isinstance(real_size, int) or real_size < index_record_size
            or lowest_vcn != 0 or not isinstance(flags, int) or flags & 0xC001
        ):
            return [], [], [], ["INDEX_ALLOCATION mapping is incomplete, sparse, compressed, or encrypted"]
        buffer_count = min(real_size // index_record_size, 64, (1024 * 1024) // index_record_size)
        entries: list[dict[str, object]] = []
        slack_entries: list[dict[str, object]] = []
        buffers: list[dict[str, object]] = []
        errors: list[str] = []
        for buffer_index in range(buffer_count):
            logical_offset = buffer_index * index_record_size
            raw, physical_segments, mapping_error = GenericTriageEngine._ntfs_read_mapped_range(
                stream, runs, cluster_size, logical_offset, index_record_size, image_size
            )
            if mapping_error:
                errors.append(f"buffer {buffer_index}: {mapping_error}")
                continue
            if len(raw) != index_record_size or not raw.startswith(b"INDX"):
                errors.append(f"buffer {buffer_index}: missing INDX signature or truncated buffer")
                continue
            usa_offset = int.from_bytes(raw[4:6], "little")
            usa_count = int.from_bytes(raw[6:8], "little")
            fixed, fixup_valid, fixup_error = GenericTriageEngine._ntfs_apply_usa_fixup(
                raw, bytes_per_sector, usa_offset, usa_count, index_record_size
            )
            index_vcn = int.from_bytes(raw[16:24], "little")
            buffer_provenance = {
                "buffer_index": buffer_index,
                "index_vcn": index_vcn,
                "logical_offset": logical_offset,
                "physical_segments": physical_segments,
                "usa_fixup_valid": fixup_valid,
                "usa_fixup_error": fixup_error,
            }
            buffers.append(buffer_provenance)
            if not fixup_valid:
                errors.append(f"buffer {buffer_index}: {fixup_error}")
                continue
            first_entry = int.from_bytes(fixed[24:28], "little")
            total_entry_bytes = int.from_bytes(fixed[28:32], "little")
            allocated_entry_bytes = int.from_bytes(fixed[32:36], "little")
            entry_start = 24 + first_entry
            entry_end = 24 + total_entry_bytes
            if (
                first_entry < 16 or total_entry_bytes < first_entry
                or allocated_entry_bytes < total_entry_bytes
                or entry_start > entry_end or 24 + allocated_entry_bytes > index_record_size
            ):
                errors.append(f"buffer {buffer_index}: INDX entry bounds exceed buffer")
                continue
            cursor = entry_start
            terminal = False
            while cursor + 16 <= entry_end and len(entries) < 256:
                file_reference = int.from_bytes(fixed[cursor:cursor + 8], "little")
                entry_length = int.from_bytes(fixed[cursor + 8:cursor + 10], "little")
                key_length = int.from_bytes(fixed[cursor + 10:cursor + 12], "little")
                entry_flags = int.from_bytes(fixed[cursor + 12:cursor + 14], "little")
                subnode_bytes = 8 if entry_flags & 0x01 else 0
                if (
                    entry_length < 16 + subnode_bytes or cursor + entry_length > entry_end
                    or key_length > entry_length - 16 - subnode_bytes
                ):
                    errors.append(f"buffer {buffer_index}: invalid INDX entry bounds at {cursor}")
                    break
                if entry_flags & 0x02:
                    terminal = True
                    break
                file_name, file_name_error = GenericTriageEngine._ntfs_file_name_value(
                    fixed[cursor + 16:cursor + 16 + key_length]
                )
                if file_name_error:
                    errors.append(f"buffer {buffer_index}: invalid FILE_NAME key at {cursor}: {file_name_error}")
                    break
                entry = {
                    "attribute_offset": attribute.get("offset"),
                    "index_buffer": buffer_provenance,
                    "entry_offset": cursor,
                    "record_number": file_reference & ((1 << 48) - 1),
                    "sequence_number": file_reference >> 48,
                    "flags": entry_flags,
                    "file_name": file_name.get("file_name"),
                    "file_name_namespace": file_name.get("file_name_namespace"),
                }
                if entry_flags & 0x01:
                    entry["child_vcn"] = int.from_bytes(
                        fixed[cursor + entry_length - 8:cursor + entry_length], "little"
                    )
                entries.append(entry)
                cursor += entry_length
            if len(entries) >= 256:
                errors.append("INDEX_ALLOCATION inventory reached 256-entry safety limit")
                break
            if not terminal and cursor + 16 > entry_end:
                errors.append(f"buffer {buffer_index}: no terminal INDX entry before declared bounds")
            if terminal and len(slack_entries) < 256:
                slack_cursor = (entry_end + 7) & ~7
                allocation_end = 24 + allocated_entry_bytes
                while slack_cursor + 82 <= allocation_end and len(slack_entries) < 256:
                    file_reference = int.from_bytes(fixed[slack_cursor:slack_cursor + 8], "little")
                    entry_length = int.from_bytes(fixed[slack_cursor + 8:slack_cursor + 10], "little")
                    key_length = int.from_bytes(fixed[slack_cursor + 10:slack_cursor + 12], "little")
                    entry_flags = int.from_bytes(fixed[slack_cursor + 12:slack_cursor + 14], "little")
                    subnode_bytes = 8 if entry_flags & 0x01 else 0
                    structurally_possible = (
                        file_reference != 0
                        and entry_flags & ~0x01 == 0
                        and entry_length >= 16 + 66 + subnode_bytes
                        and entry_length % 8 == 0
                        and slack_cursor + entry_length <= allocation_end
                        and 66 <= key_length <= entry_length - 16 - subnode_bytes
                    )
                    if not structurally_possible:
                        slack_cursor += 8
                        continue
                    file_name, file_name_error = GenericTriageEngine._ntfs_file_name_value(
                        fixed[slack_cursor + 16:slack_cursor + 16 + key_length]
                    )
                    file_name_text = file_name.get("file_name") if not file_name_error else None
                    namespace = file_name.get("file_name_namespace") if not file_name_error else None
                    if (
                        not isinstance(file_name_text, str) or not file_name_text
                        or "\x00" in file_name_text or "\ufffd" in file_name_text
                        or namespace not in {0, 1, 2, 3}
                    ):
                        slack_cursor += 8
                        continue
                    candidate: dict[str, object] = {
                        "attribute_offset": attribute.get("offset"),
                        "index_buffer": buffer_provenance,
                        "slack_offset": slack_cursor,
                        "record_number": file_reference & ((1 << 48) - 1),
                        "sequence_number": file_reference >> 48,
                        "flags": entry_flags,
                        "file_name": file_name_text,
                        "file_name_namespace": namespace,
                        "slack_candidate": True,
                        "confidence": 0.72,
                    }
                    if entry_flags & 0x01:
                        candidate["child_vcn"] = int.from_bytes(
                            fixed[slack_cursor + entry_length - 8:slack_cursor + entry_length], "little"
                        )
                    slack_entries.append(candidate)
                    slack_cursor += entry_length
                if len(slack_entries) >= 256:
                    errors.append("INDEX_ALLOCATION slack inventory reached 256-entry safety limit")
                    break
        return entries, slack_entries, buffers, errors

    @staticmethod
    def _ntfs_sample_parent_links(records: list[dict[str, object]]) -> list[dict[str, object]]:
        """Correlate FILE_NAME parent references only to records in this bounded sample."""
        by_record = {
            item["record_number"]: item
            for item in records
            if isinstance(item.get("record_number"), int) and item.get("signature_valid") is True
        }
        links: list[dict[str, object]] = []
        for item in records:
            record_number = item.get("record_number")
            references = item.get("file_name_references")
            if not isinstance(record_number, int) or not isinstance(references, list):
                continue
            for reference in references:
                if not isinstance(reference, dict):
                    continue
                parent_record = reference.get("parent_record_number")
                parent_sequence = reference.get("parent_sequence_number")
                if not isinstance(parent_record, int) or not isinstance(parent_sequence, int):
                    continue
                parent = by_record.get(parent_record)
                links.append({
                    "child_record_number": record_number,
                    "file_name": reference.get("file_name"),
                    "parent_record_number": parent_record,
                    "parent_sequence_number": parent_sequence,
                    "parent_sampled": parent is not None,
                    "parent_sequence_matches": (
                        parent.get("sequence_number") == parent_sequence if isinstance(parent, dict) else None
                    ),
                })
                if len(links) >= 256:
                    return links
        return links

    @staticmethod
    def _ntfs_sample_index_links(records: list[dict[str, object]]) -> list[dict[str, object]]:
        """Correlate validated resident/nonresident index references within the sample."""
        by_record = {
            item["record_number"]: item
            for item in records
            if isinstance(item.get("record_number"), int) and item.get("signature_valid") is True
        }
        links: list[dict[str, object]] = []
        for directory in records:
            directory_record = directory.get("record_number")
            root_entries = directory.get("index_root_entries")
            allocation_entries = directory.get("index_allocation_entries")
            entries = [
                entry
                for collection in (root_entries, allocation_entries)
                if isinstance(collection, list)
                for entry in collection
            ]
            if not isinstance(directory_record, int):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                child_record = entry.get("record_number")
                child_sequence = entry.get("sequence_number")
                if not isinstance(child_record, int) or not isinstance(child_sequence, int):
                    continue
                child = by_record.get(child_record)
                child_names = child.get("file_names") if isinstance(child, dict) else None
                index_name = entry.get("file_name")
                links.append({
                    "directory_record_number": directory_record,
                    "index_attribute_offset": entry.get("attribute_offset"),
                    "file_name": index_name,
                    "child_record_number": child_record,
                    "child_sequence_number": child_sequence,
                    "child_sampled": child is not None,
                    "child_sequence_matches": child.get("sequence_number") == child_sequence if isinstance(child, dict) else None,
                    "child_file_name_matches": (
                        index_name in child_names if isinstance(index_name, str) and isinstance(child_names, list) else None
                    ),
                })
                if len(links) >= 512:
                    return links
        return links

    @staticmethod
    def _ntfs_sample_attribute_list_links(records: list[dict[str, object]]) -> list[dict[str, object]]:
        """Correlate ATTRIBUTE_LIST extents only to records already in the bounded sample."""
        by_record = {
            item["record_number"]: item
            for item in records
            if isinstance(item.get("record_number"), int) and item.get("signature_valid") is True
        }
        links: list[dict[str, object]] = []
        for source in records:
            source_record = source.get("record_number")
            references = source.get("attribute_list_references")
            if not isinstance(source_record, int) or not isinstance(references, list):
                continue
            for reference in references:
                if not isinstance(reference, dict):
                    continue
                target_record = reference.get("record_number")
                target_sequence = reference.get("sequence_number")
                if not isinstance(target_record, int) or not isinstance(target_sequence, int):
                    continue
                target = by_record.get(target_record)
                links.append({
                    "source_record_number": source_record,
                    "type_name": reference.get("type_name"),
                    "name": reference.get("name"),
                    "lowest_vcn": reference.get("lowest_vcn"),
                    "attribute_id": reference.get("attribute_id"),
                    "target_record_number": target_record,
                    "target_sequence_number": target_sequence,
                    "target_sampled": target is not None,
                    "target_sequence_matches": target.get("sequence_number") == target_sequence if isinstance(target, dict) else None,
                })
                if len(links) >= 256:
                    return links
        return links

    @staticmethod
    def _ntfs_sample_record_anomalies(records: list[dict[str, object]]) -> list[dict[str, object]]:
        anomalies: list[dict[str, object]] = []
        for item in records:
            failures = [
                name for name in ("signature_valid", "bounds_valid", "usa_fixup_valid")
                if item.get(name) is False
            ]
            if failures:
                anomalies.append({
                    "record_number": item.get("record_number"), "failed_checks": failures,
                    "usa_fixup_error": item.get("usa_fixup_error"), "physical_segments": item.get("physical_segments"),
                })
                if len(anomalies) >= 64:
                    return anomalies
        return anomalies

    @staticmethod
    def _ntfs_read_mapped_range(
        stream: BinaryIO,
        runs: object,
        cluster_size: int,
        logical_offset: int,
        length: int,
        image_size: int,
    ) -> tuple[bytes, list[dict[str, int]], str | None]:
        if not isinstance(runs, list) or logical_offset < 0 or length <= 0:
            return b"", [], "invalid MFT data-run mapping request"
        remaining = length
        current = logical_offset
        chunks: list[bytes] = []
        segments: list[dict[str, int]] = []
        while remaining:
            vcn, cluster_offset = divmod(current, cluster_size)
            run = next(
                (
                    item for item in runs
                    if isinstance(item, dict)
                    and isinstance(item.get("vcn"), int)
                    and isinstance(item.get("cluster_count"), int)
                    and item["vcn"] <= vcn < item["vcn"] + item["cluster_count"]
                ),
                None,
            )
            if not isinstance(run, dict):
                return b"", segments, "no validated data run maps the requested logical MFT range"
            lcn = run.get("lcn")
            if not isinstance(lcn, int):
                return b"", segments, "requested logical MFT range maps to a sparse run"
            run_remaining = (run["vcn"] + run["cluster_count"] - vcn) * cluster_size - cluster_offset
            take = min(remaining, run_remaining)
            physical_offset = (lcn + vcn - run["vcn"]) * cluster_size + cluster_offset
            if physical_offset < 0 or physical_offset + take > image_size:
                return b"", segments, "mapped physical MFT range exceeds supplied image bounds"
            stream.seek(physical_offset)
            chunk = stream.read(take)
            if len(chunk) != take:
                return b"", segments, "mapped physical MFT range could not be read completely"
            chunks.append(chunk)
            segments.append({"logical_offset": current, "physical_offset": physical_offset, "length": take})
            current += take
            remaining -= take
        return b"".join(chunks), segments, None

    @staticmethod
    def _ntfs_apply_usa_fixup(record: bytes, bytes_per_sector: int, usa_offset: int, usa_count: int, allocated_size: int) -> tuple[bytes, bool, str | None]:
        """Validate and apply an NTFS USA fixup only to an in-memory copy."""
        bounded_size = min(len(record), allocated_size)
        expected_count = bounded_size // bytes_per_sector + 1 if bytes_per_sector else 0
        if bytes_per_sector <= 0 or bounded_size < bytes_per_sector or usa_count != expected_count or usa_offset < 24 or usa_offset + usa_count * 2 > bounded_size:
            return record, False, "USA offset/count is inconsistent with bounded record geometry"
        sequence = record[usa_offset:usa_offset + 2]
        fixed = bytearray(record)
        for index in range(1, usa_count):
            trailer = index * bytes_per_sector - 2
            if fixed[trailer:trailer + 2] != sequence:
                return record, False, f"USA sequence mismatch at sector {index}"
            replacement = usa_offset + index * 2
            fixed[trailer:trailer + 2] = fixed[replacement:replacement + 2]
        return bytes(fixed), True, None

    @staticmethod
    def _ntfs_attribute_inventory(record: bytes, first_attribute: int, used_size: int, fixup_valid: bool) -> tuple[list[dict[str, object]], list[str]]:
        if not fixup_valid:
            return [], ["attributes not parsed because USA fixup did not validate"]
        end = min(len(record), used_size)
        if first_attribute < 24 or first_attribute >= end:
            return [], ["first attribute offset is outside used MFT record bytes"]
        names = {0x10: "standard_information", 0x20: "attribute_list", 0x30: "file_name", 0x80: "data", 0x90: "index_root", 0xA0: "index_allocation"}
        attributes: list[dict[str, object]] = []
        errors: list[str] = []
        cursor = first_attribute
        while cursor + 16 <= end and len(attributes) < 64:
            attribute_type = int.from_bytes(record[cursor:cursor + 4], "little")
            if attribute_type == 0xFFFFFFFF:
                break
            length = int.from_bytes(record[cursor + 4:cursor + 8], "little")
            if length < 24 or cursor + length > end:
                errors.append(f"invalid attribute length at {cursor}")
                break
            nonresident = bool(record[cursor + 8])
            name_length, name_offset = record[cursor + 9], int.from_bytes(record[cursor + 10:cursor + 12], "little")
            name = ""
            if name_length:
                name_end = name_offset + name_length * 2
                if name_offset < 16 or name_end > length:
                    errors.append(f"invalid attribute name bounds at {cursor}")
                    break
                name = record[cursor + name_offset:cursor + name_end].decode("utf-16le", errors="replace")[:512]
            entry: dict[str, object] = {"offset": cursor, "type": f"0x{attribute_type:02X}", "type_name": names.get(attribute_type, "unknown"), "length": length, "nonresident": nonresident, "name": name or None, "attribute_id": int.from_bytes(record[cursor + 14:cursor + 16], "little")}
            if nonresident:
                if length < 64:
                    errors.append(f"truncated nonresident attribute at {cursor}")
                    break
                run_offset = int.from_bytes(record[cursor + 32:cursor + 34], "little")
                data_runs: list[dict[str, int | None]] = []
                lowest_vcn = int.from_bytes(record[cursor + 16:cursor + 24], "little")
                if attribute_type in {0x80, 0xA0}:
                    data_runs, data_run_error = GenericTriageEngine._ntfs_data_runs(
                        record[cursor:cursor + length], run_offset, lowest_vcn
                    )
                    if data_run_error:
                        errors.append(f"data run error at {cursor}: {data_run_error}")
                entry.update({
                    "attribute_flags": int.from_bytes(record[cursor + 12:cursor + 14], "little"),
                    "lowest_vcn": lowest_vcn,
                    "highest_vcn": int.from_bytes(record[cursor + 24:cursor + 32], "little"),
                    "allocated_size": int.from_bytes(record[cursor + 40:cursor + 48], "little"),
                    "real_size": int.from_bytes(record[cursor + 48:cursor + 56], "little"),
                    "initialized_size": int.from_bytes(record[cursor + 56:cursor + 64], "little"),
                    "data_runs": data_runs,
                })
            else:
                value_length, value_offset = int.from_bytes(record[cursor + 16:cursor + 20], "little"), int.from_bytes(record[cursor + 20:cursor + 22], "little")
                value_bounds_valid = value_offset >= 24 and value_offset + value_length <= length
                entry.update({"value_length": value_length, "value_bounds_valid": value_bounds_valid})
                if value_bounds_valid:
                    value = record[cursor + value_offset:cursor + value_offset + value_length]
                    if attribute_type == 0x80:
                        # Sample records are at most 4 KiB. Preserve only the
                        # already USA-fixed, bounds-validated resident value;
                        # extraction re-applies case byte/count/depth limits.
                        entry["resident_value_offset"] = cursor + value_offset
                        entry["resident_data_hex"] = value.hex()
                    elif attribute_type == 0x10:
                        timestamps, timestamp_error = GenericTriageEngine._ntfs_standard_information_timestamps(value)
                        if timestamp_error:
                            errors.append(f"standard-information error at {cursor}: {timestamp_error}")
                        else:
                            entry["timestamps"] = timestamps
                    elif attribute_type == 0x20:
                        extent_references, list_error = GenericTriageEngine._ntfs_attribute_list_entries(value)
                        if list_error:
                            errors.append(f"attribute-list error at {cursor}: {list_error}")
                        entry["extent_references"] = extent_references
                    elif attribute_type == 0x30:
                        file_name, timestamp_error = GenericTriageEngine._ntfs_file_name_value(value)
                        if timestamp_error:
                            errors.append(f"file-name error at {cursor}: {timestamp_error}")
                        else:
                            entry.update(file_name)
                    elif attribute_type == 0x90:
                        index_root, index_error = GenericTriageEngine._ntfs_index_root_entries(value)
                        if index_error:
                            errors.append(f"index-root error at {cursor}: {index_error}")
                        if index_root:
                            entry.update(index_root)
            attributes.append(entry)
            cursor += length
        return attributes, errors

    @staticmethod
    def _ntfs_standard_information_timestamps(value: bytes) -> tuple[dict[str, object], str | None]:
        if len(value) < 32:
            return {}, "resident value is shorter than four FILETIME fields"
        result: dict[str, object] = {
            "created": GenericTriageEngine._filetime_to_iso(value[0:8]),
            "modified": GenericTriageEngine._filetime_to_iso(value[8:16]),
            "mft_changed": GenericTriageEngine._filetime_to_iso(value[16:24]),
            "accessed": GenericTriageEngine._filetime_to_iso(value[24:32]),
        }
        if len(value) >= 36:
            flags = int.from_bytes(value[32:36], "little")
            names = {
                0x0001: "read_only", 0x0002: "hidden", 0x0004: "system", 0x0020: "archive",
                0x0040: "device", 0x0080: "normal", 0x0100: "temporary", 0x0200: "sparse",
                0x0400: "reparse_point", 0x0800: "compressed", 0x1000: "offline", 0x2000: "not_content_indexed",
                0x4000: "encrypted", 0x10000000: "directory", 0x20000000: "index_view",
            }
            result["file_attributes"] = flags
            result["file_attribute_names"] = [name for bit, name in names.items() if flags & bit]
        if len(value) >= 48:
            result.update({
                "maximum_versions": int.from_bytes(value[36:40], "little"),
                "version_number": int.from_bytes(value[40:44], "little"),
                "class_id": int.from_bytes(value[44:48], "little"),
            })
        if len(value) >= 72:
            result.update({
                "owner_id": int.from_bytes(value[48:52], "little"),
                "security_id": int.from_bytes(value[52:56], "little"),
                "quota_charged": int.from_bytes(value[56:64], "little"),
                "update_sequence_number": int.from_bytes(value[64:72], "little"),
            })
        return result, None

    @staticmethod
    def _ntfs_attribute_list_entries(value: bytes) -> tuple[list[dict[str, object]], str | None]:
        type_names = {0x10: "standard_information", 0x20: "attribute_list", 0x30: "file_name", 0x80: "data", 0x90: "index_root", 0xA0: "index_allocation"}
        entries: list[dict[str, object]] = []
        cursor = 0
        while cursor < len(value) and len(entries) < 64:
            if cursor + 26 > len(value):
                return entries, "truncated ATTRIBUTE_LIST entry header"
            attribute_type = int.from_bytes(value[cursor:cursor + 4], "little")
            length = int.from_bytes(value[cursor + 4:cursor + 6], "little")
            name_length, name_offset = value[cursor + 6], value[cursor + 7]
            if length < 26 or cursor + length > len(value):
                return entries, f"invalid ATTRIBUTE_LIST entry length at resident offset {cursor}"
            name_end = name_offset + name_length * 2
            if name_length and (name_offset < 26 or name_end > length):
                return entries, f"invalid ATTRIBUTE_LIST entry name bounds at resident offset {cursor}"
            reference = int.from_bytes(value[cursor + 16:cursor + 24], "little")
            entries.append({
                "offset": cursor,
                "type": f"0x{attribute_type:02X}",
                "type_name": type_names.get(attribute_type, "unknown"),
                "length": length,
                "lowest_vcn": int.from_bytes(value[cursor + 8:cursor + 16], "little"),
                "record_number": reference & ((1 << 48) - 1),
                "sequence_number": reference >> 48,
                "attribute_id": int.from_bytes(value[cursor + 24:cursor + 26], "little"),
                "name": value[cursor + name_offset:cursor + name_end].decode("utf-16le", errors="replace")[:512] if name_length else None,
            })
            cursor += length
        if len(entries) == 64:
            return entries, "ATTRIBUTE_LIST inventory reached 64-entry safety limit"
        return entries, None

    @staticmethod
    def _ntfs_file_name_value(value: bytes) -> tuple[dict[str, object], str | None]:
        if len(value) < 66:
            return {}, "resident value is shorter than a FILE_NAME header"
        name_length = value[64]
        name_end = 66 + name_length * 2
        if name_end > len(value):
            return {}, "declared FILE_NAME text exceeds resident value bounds"
        parent_reference = int.from_bytes(value[0:8], "little")
        return {
            "file_name": value[66:name_end].decode("utf-16le", errors="replace")[:512],
            "file_name_namespace": value[65],
            "parent_record_number": parent_reference & ((1 << 48) - 1),
            "parent_sequence_number": parent_reference >> 48,
            "timestamps": {
                "created": GenericTriageEngine._filetime_to_iso(value[8:16]),
                "modified": GenericTriageEngine._filetime_to_iso(value[16:24]),
                "mft_changed": GenericTriageEngine._filetime_to_iso(value[24:32]),
                "accessed": GenericTriageEngine._filetime_to_iso(value[32:40]),
            },
        }, None

    @staticmethod
    def _ntfs_index_root_entries(value: bytes) -> tuple[dict[str, object], str | None]:
        """Inventory resident `$I30` entries without following index-allocation buffers."""
        if len(value) < 32:
            return {}, "resident INDEX_ROOT value is shorter than fixed headers"
        indexed_type = int.from_bytes(value[0:4], "little")
        header = 16
        first_entry = int.from_bytes(value[header:header + 4], "little")
        total_entry_bytes = int.from_bytes(value[header + 4:header + 8], "little")
        allocated_entry_bytes = int.from_bytes(value[header + 8:header + 12], "little")
        index_flags = value[header + 12]
        entry_start = header + first_entry
        entry_end = header + total_entry_bytes
        result: dict[str, object] = {
            "indexed_attribute_type": f"0x{indexed_type:02X}",
            "index_flags": index_flags,
            "entry_bytes": total_entry_bytes,
            "allocated_entry_bytes": allocated_entry_bytes,
            "index_entries": [],
        }
        if indexed_type != 0x30:
            return result, None
        if first_entry < 16 or total_entry_bytes < first_entry or entry_start > entry_end or entry_end > len(value):
            return {}, "INDEX_ROOT entry offsets exceed resident value bounds"
        entries: list[dict[str, object]] = []
        cursor = entry_start
        while cursor + 16 <= entry_end and len(entries) < 64:
            file_reference = int.from_bytes(value[cursor:cursor + 8], "little")
            entry_length = int.from_bytes(value[cursor + 8:cursor + 10], "little")
            key_length = int.from_bytes(value[cursor + 10:cursor + 12], "little")
            entry_flags = int.from_bytes(value[cursor + 12:cursor + 14], "little")
            if entry_length < 16 or cursor + entry_length > entry_end or key_length > entry_length - 16:
                return {}, f"invalid INDEX_ROOT entry bounds at resident offset {cursor}"
            if entry_flags & 0x02:
                return {**result, "index_entries": entries}, None
            file_name, file_name_error = GenericTriageEngine._ntfs_file_name_value(value[cursor + 16:cursor + 16 + key_length])
            if file_name_error:
                return {}, f"invalid INDEX_ROOT FILE_NAME key at resident offset {cursor}: {file_name_error}"
            entries.append({
                "offset": cursor,
                "record_number": file_reference & ((1 << 48) - 1),
                "sequence_number": file_reference >> 48,
                "flags": entry_flags,
                "file_name": file_name.get("file_name"),
                "file_name_namespace": file_name.get("file_name_namespace"),
            })
            cursor += entry_length
        if len(entries) == 64:
            return {**result, "index_entries": entries}, "INDEX_ROOT inventory reached 64-entry safety limit"
        return {}, "INDEX_ROOT has no terminal entry before declared entry bounds"

    @staticmethod
    def _ntfs_timestamp_mismatches(attributes: list[dict[str, object]]) -> list[dict[str, str | None]]:
        standard = next(
            (
                item.get("timestamps") for item in attributes
                if item.get("type_name") == "standard_information" and isinstance(item.get("timestamps"), dict)
            ),
            None,
        )
        if not isinstance(standard, dict):
            return []
        mismatches: list[dict[str, str | None]] = []
        for item in attributes:
            if item.get("type_name") != "file_name" or not isinstance(item.get("timestamps"), dict):
                continue
            file_name_timestamps = item["timestamps"]
            for field in ("created", "modified", "mft_changed", "accessed"):
                standard_value = standard.get(field)
                file_name_value = file_name_timestamps.get(field)
                if isinstance(standard_value, str) and isinstance(file_name_value, str) and standard_value != file_name_value:
                    mismatches.append({
                        "field": field,
                        "standard_information": standard_value, "file_name": str(item.get("file_name") or ""),
                        "file_name_timestamp": file_name_value,
                    })
                    if len(mismatches) >= 16:
                        return mismatches
        return mismatches

    @staticmethod
    def _ntfs_data_runs(
        attribute: bytes, offset: int, initial_vcn: int = 0
    ) -> tuple[list[dict[str, int | None]], str | None]:
        if offset < 64 or offset >= len(attribute):
            return [], "run-list offset is outside the nonresident attribute"
        runs: list[dict[str, int | None]] = []
        cursor = offset
        lcn, vcn = 0, initial_vcn
        while cursor < len(attribute) and len(runs) < 64:
            header = attribute[cursor]
            cursor += 1
            if header == 0:
                return runs, None
            length_bytes, offset_bytes = header & 0x0F, header >> 4
            if not length_bytes or length_bytes > 8 or offset_bytes > 8 or cursor + length_bytes + offset_bytes > len(attribute):
                return runs, "invalid data-run header or truncated descriptor"
            clusters = int.from_bytes(attribute[cursor:cursor + length_bytes], "little")
            cursor += length_bytes
            relative = int.from_bytes(attribute[cursor:cursor + offset_bytes], "little", signed=True) if offset_bytes else None
            cursor += offset_bytes
            if not clusters:
                return runs, "data-run cluster count is zero"
            if relative is not None:
                lcn += relative
            runs.append({"vcn": vcn, "cluster_count": clusters, "lcn": lcn if relative is not None else None})
            vcn += clusters
        if len(runs) == 64:
            return runs, "data-run inventory reached 64-run safety limit"
        return runs, "data-run list has no terminator before attribute end"

    def _inspect_memory_markers(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        scan_size = min(size, 8 * _MIB)
        try:
            with path.open("rb") as stream:
                sample = stream.read(scan_size)
        except OSError as exc:
            return [self._observation(artifact, "memory.marker_error", str(exc), confidence=0.8)]
        linux_index = sample.find(b"Linux version ")
        kdbg_index = sample.find(b"KDBG")
        linux_banner = None
        if linux_index >= 0:
            linux_banner = sample[linux_index:linux_index + 512].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        detected = linux_index >= 0 or kdbg_index >= 0
        return [
            self._observation(artifact, "memory.linux_banner", linux_banner),
            self._observation(artifact, "memory.kdbg_offset", kdbg_index if kdbg_index >= 0 else None),
            self._observation(artifact, "memory.signature_detected", detected),
        ]

    def _inspect_minidump(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        try:
            with path.open("rb") as stream:
                header = stream.read(32)
        except OSError as exc:
            return [self._observation(artifact, "memory.minidump_error", str(exc), confidence=0.8)]
        if len(header) < 32 or not header.startswith(b"MDMP"):
            return [self._observation(artifact, "memory.minidump_valid", False)]
        stream_count = int.from_bytes(header[8:12], "little")
        directory_rva = int.from_bytes(header[12:16], "little")
        valid = stream_count <= 4096 and directory_rva >= 32 and directory_rva + stream_count * 12 <= size
        entries: list[dict[str, int]] = []
        system_info: dict[str, object] | None = None
        modules: list[dict[str, object]] = []
        threads: list[dict[str, object]] = []
        memory_ranges: list[dict[str, object]] = []
        memory64_ranges: list[dict[str, object]] = []
        memory_info_ranges: list[dict[str, object]] = []
        handles: list[dict[str, object]] = []
        unloaded_modules: list[dict[str, object]] = []
        exception: dict[str, object] | None = None
        misc_info: dict[str, object] | None = None
        comments: list[dict[str, object]] = []
        parse_errors: list[str] = []
        if valid:
            try:
                with path.open("rb") as stream:
                    stream.seek(directory_rva)
                    directory = stream.read(min(stream_count, 256) * 12)
                for index in range(len(directory) // 12):
                    stream_type, data_size, rva = struct.unpack_from("<III", directory, index * 12)
                    entries.append({"type": stream_type, "size": data_size, "rva": rva, "within_image": int(rva + data_size <= size)})
            except OSError:
                valid = False
        if valid:
            # These fixed-size stream records give deterministic structural
            # leads without treating a minidump as a full memory image.
            try:
                with path.open("rb") as stream:
                    for entry in entries:
                        stream_type, data_size, rva = entry["type"], entry["size"], entry["rva"]
                        if not entry["within_image"]:
                            continue
                        if stream_type == 7 and data_size >= 32 and system_info is None:
                            stream.seek(rva)
                            raw = stream.read(min(data_size, 128))
                            if len(raw) < 32:
                                parse_errors.append("truncated system-info stream")
                                continue
                            architecture = int.from_bytes(raw[0:2], "little")
                            architecture_names = {
                                0: "x86", 5: "arm", 6: "ia64", 9: "x64", 12: "arm64",
                            }
                            csd_rva = int.from_bytes(raw[24:28], "little")
                            system_info = {
                                "architecture": architecture_names.get(architecture, f"unknown_{architecture}"),
                                "architecture_code": architecture,
                                "processor_count": raw[6],
                                "product_type": raw[7],
                                "major_version": int.from_bytes(raw[8:12], "little"),
                                "minor_version": int.from_bytes(raw[12:16], "little"),
                                "build_number": int.from_bytes(raw[16:20], "little"),
                                "platform_id": int.from_bytes(raw[20:24], "little"),
                                "service_pack": self._minidump_string(path, size, csd_rva),
                            }
                        elif stream_type == 4 and data_size >= 4 and not modules:
                            stream.seek(rva)
                            count_raw = stream.read(4)
                            if len(count_raw) != 4:
                                parse_errors.append("truncated module-list count")
                                continue
                            declared_count = int.from_bytes(count_raw, "little")
                            module_count = min(declared_count, (data_size - 4) // 108, 256)
                            for index in range(module_count):
                                offset = rva + 4 + index * 108
                                stream.seek(offset)
                                raw = stream.read(108)
                                if len(raw) != 108:
                                    parse_errors.append("truncated module-list entry")
                                    break
                                name_rva = int.from_bytes(raw[24:28], "little")
                                modules.append({
                                    "base_address": f"0x{int.from_bytes(raw[0:8], 'little'):x}",
                                    "image_size": int.from_bytes(raw[8:12], "little"),
                                    "timestamp": int.from_bytes(raw[16:20], "little"),
                                    "name": self._minidump_string(path, size, name_rva),
                                })
                        elif stream_type == 3 and data_size >= 4 and not threads:
                            # MINIDUMP_THREAD_LIST: count followed by packed
                            # 48-byte MINIDUMP_THREAD records.  Stack and
                            # context location descriptors are preserved only
                            # when their RVAs are inside this evidence file.
                            stream.seek(rva)
                            count_raw = stream.read(4)
                            if len(count_raw) != 4:
                                parse_errors.append("truncated thread-list count")
                                continue
                            declared_count = int.from_bytes(count_raw, "little")
                            thread_count = min(declared_count, (data_size - 4) // 48, 512)
                            for index in range(thread_count):
                                stream.seek(rva + 4 + index * 48)
                                raw = stream.read(48)
                                if len(raw) != 48:
                                    parse_errors.append("truncated thread-list entry")
                                    break
                                stack_size = int.from_bytes(raw[32:36], "little")
                                stack_rva = int.from_bytes(raw[36:40], "little")
                                context_size = int.from_bytes(raw[40:44], "little")
                                context_rva = int.from_bytes(raw[44:48], "little")
                                threads.append({
                                    "thread_id": int.from_bytes(raw[0:4], "little"),
                                    "suspend_count": int.from_bytes(raw[4:8], "little"),
                                    "priority_class": int.from_bytes(raw[8:12], "little"),
                                    "priority": int.from_bytes(raw[12:16], "little", signed=True),
                                    "teb": f"0x{int.from_bytes(raw[16:24], 'little'):x}",
                                    "stack_start": f"0x{int.from_bytes(raw[24:32], 'little'):x}",
                                    "stack_size": stack_size,
                                    "stack_rva": stack_rva,
                                    "stack_within_image": stack_rva + stack_size <= size,
                                    "context_size": context_size,
                                    "context_rva": context_rva,
                                    "context_within_image": context_rva + context_size <= size,
                                })
                        elif stream_type == 5 and data_size >= 4 and not memory_ranges:
                            # MINIDUMP_MEMORY_LIST descriptors are 16 bytes:
                            # virtual start plus a LOCATION_DESCRIPTOR.
                            stream.seek(rva)
                            count_raw = stream.read(4)
                            if len(count_raw) != 4:
                                parse_errors.append("truncated memory-list count")
                                continue
                            declared_count = int.from_bytes(count_raw, "little")
                            range_count = min(declared_count, (data_size - 4) // 16, 512)
                            for index in range(range_count):
                                stream.seek(rva + 4 + index * 16)
                                raw = stream.read(16)
                                if len(raw) != 16:
                                    parse_errors.append("truncated memory-list entry")
                                    break
                                data_length = int.from_bytes(raw[8:12], "little")
                                data_rva = int.from_bytes(raw[12:16], "little")
                                memory_ranges.append({
                                    "start": f"0x{int.from_bytes(raw[0:8], 'little'):x}",
                                    "size": data_length,
                                    "rva": data_rva,
                                    "within_image": data_rva + data_length <= size,
                                })
                        elif stream_type == 9 and data_size >= 16 and not memory64_ranges:
                            # MINIDUMP_MEMORY64_LIST carries descriptors plus
                            # one contiguous data area.  Validate the running
                            # source offset rather than dereferencing virtual
                            # addresses or materialising memory bytes.
                            stream.seek(rva)
                            header_raw = stream.read(16)
                            if len(header_raw) != 16:
                                parse_errors.append("truncated memory64-list header")
                                continue
                            declared_count = int.from_bytes(header_raw[0:8], "little")
                            base_rva = int.from_bytes(header_raw[8:16], "little")
                            range_count = min(declared_count, (data_size - 16) // 16, 512)
                            source_rva = base_rva
                            for index in range(range_count):
                                stream.seek(rva + 16 + index * 16)
                                raw = stream.read(16)
                                if len(raw) != 16:
                                    parse_errors.append("truncated memory64-list entry")
                                    break
                                data_length = int.from_bytes(raw[8:16], "little")
                                within_image = source_rva <= size and data_length <= size - source_rva
                                memory64_ranges.append({
                                    "start": f"0x{int.from_bytes(raw[0:8], 'little'):x}",
                                    "size": data_length,
                                    "rva": source_rva,
                                    "within_image": within_image,
                                })
                                if not within_image:
                                    # Do not permit integer growth from a
                                    # corrupted range to influence later rows.
                                    break
                                source_rva += data_length
                        elif stream_type == 12 and data_size >= 16 and not handles:
                            # MINIDUMP_HANDLE_DATA_STREAM is a self-contained
                            # descriptor table.  Recover only descriptor
                            # metadata and validated MINIDUMP_STRING RVAs;
                            # never dereference a dumped process object.
                            stream.seek(rva)
                            header_raw = stream.read(16)
                            if len(header_raw) != 16:
                                parse_errors.append("truncated handle-data header")
                                continue
                            header_size, descriptor_size, declared_count, _reserved = struct.unpack("<IIII", header_raw)
                            if (
                                header_size < 16
                                or descriptor_size < 32
                                or header_size > data_size
                            ):
                                parse_errors.append("invalid handle-data geometry")
                                continue
                            handle_count = min(declared_count, (data_size - header_size) // descriptor_size, 256)
                            for index in range(handle_count):
                                stream.seek(rva + header_size + index * descriptor_size)
                                raw = stream.read(descriptor_size)
                                if len(raw) != descriptor_size:
                                    parse_errors.append("truncated handle-data descriptor")
                                    break
                                handles.append({
                                    "handle": f"0x{int.from_bytes(raw[0:8], 'little'):x}",
                                    "type_name": self._minidump_string(path, size, int.from_bytes(raw[8:12], "little")),
                                    "object_name": self._minidump_string(path, size, int.from_bytes(raw[12:16], "little")),
                                    "attributes": f"0x{int.from_bytes(raw[16:20], 'little'):08x}",
                                    "granted_access": f"0x{int.from_bytes(raw[20:24], 'little'):08x}",
                                    "handle_count": int.from_bytes(raw[24:28], "little"),
                                    "pointer_count": int.from_bytes(raw[28:32], "little"),
                                })
                        elif stream_type == 14 and data_size >= 8 and not unloaded_modules:
                            # MINIDUMP_UNLOADED_MODULE_LIST keeps module
                            # metadata after a DLL is unloaded.  Its name is
                            # a file RVA, not a process-memory pointer.
                            stream.seek(rva)
                            header_raw = stream.read(8)
                            if len(header_raw) != 8:
                                parse_errors.append("truncated unloaded-module header")
                                continue
                            declared_count, descriptor_size = struct.unpack("<II", header_raw)
                            if descriptor_size < 24:
                                parse_errors.append("invalid unloaded-module geometry")
                                continue
                            module_count = min(declared_count, (data_size - 8) // descriptor_size, 256)
                            for index in range(module_count):
                                stream.seek(rva + 8 + index * descriptor_size)
                                raw = stream.read(descriptor_size)
                                if len(raw) != descriptor_size:
                                    parse_errors.append("truncated unloaded-module descriptor")
                                    break
                                unloaded_modules.append({
                                    "base_address": f"0x{int.from_bytes(raw[0:8], 'little'):x}",
                                    "image_size": int.from_bytes(raw[8:12], "little"),
                                    "checksum": f"0x{int.from_bytes(raw[12:16], 'little'):08x}",
                                    "timestamp": int.from_bytes(raw[16:20], "little"),
                                    "name": self._minidump_string(path, size, int.from_bytes(raw[20:24], "little")),
                                })
                        elif stream_type == 6 and data_size >= 168 and exception is None:
                            # MINIDUMP_EXCEPTION_STREAM contains a fixed
                            # exception record and a context LOCATION_DESCRIPTOR.
                            # Preserve only structural fields; decoding CPU
                            # contexts belongs to a dedicated debugger.
                            stream.seek(rva)
                            raw = stream.read(168)
                            if len(raw) != 168:
                                parse_errors.append("truncated exception stream")
                                continue
                            exception_code = int.from_bytes(raw[8:12], "little")
                            parameter_count = min(int.from_bytes(raw[32:36], "little"), 15)
                            context_size = int.from_bytes(raw[160:164], "little")
                            context_rva = int.from_bytes(raw[164:168], "little")
                            exception_names = {
                                0x80000003: "breakpoint", 0x80000004: "single_step",
                                0xC0000005: "access_violation", 0xC000001D: "illegal_instruction",
                                0xC0000094: "integer_divide_by_zero", 0xC00000FD: "stack_overflow",
                            }
                            exception = {
                                "thread_id": int.from_bytes(raw[0:4], "little"),
                                "code": f"0x{exception_code:08x}",
                                "name": exception_names.get(exception_code, "unknown"),
                                "flags": int.from_bytes(raw[12:16], "little"),
                                "address": f"0x{int.from_bytes(raw[24:32], 'little'):x}",
                                "parameter_count": parameter_count,
                                "context_size": context_size,
                                "context_rva": context_rva,
                                "context_within_image": context_rva + context_size <= size,
                            }
                        elif stream_type == 16 and data_size >= 16 and not memory_info_ranges:
                            # MINIDUMP_MEMORY_INFO_LIST documents virtual
                            # region state/protection.  It contains no memory
                            # bytes, so this gives high-value triage leads
                            # without dereferencing a process address.
                            stream.seek(rva)
                            header_raw = stream.read(16)
                            if len(header_raw) != 16:
                                parse_errors.append("truncated memory-info-list header")
                                continue
                            header_size = int.from_bytes(header_raw[0:4], "little")
                            entry_size = int.from_bytes(header_raw[4:8], "little")
                            declared_count = int.from_bytes(header_raw[8:16], "little")
                            if header_size < 16 or entry_size < 48 or header_size > data_size:
                                parse_errors.append("invalid memory-info-list geometry")
                                continue
                            range_count = min(declared_count, (data_size - header_size) // entry_size, 512)
                            protections = {
                                0x01: "noaccess", 0x02: "read", 0x04: "readwrite", 0x08: "writecopy",
                                0x10: "execute", 0x20: "execute_read", 0x40: "execute_readwrite", 0x80: "execute_writecopy",
                            }
                            states = {0x1000: "commit", 0x2000: "reserve", 0x10000: "free"}
                            region_types = {0x1000000: "image", 0x20000: "mapped", 0x2000000: "private"}
                            for index in range(range_count):
                                stream.seek(rva + header_size + index * entry_size)
                                raw = stream.read(entry_size)
                                if len(raw) != entry_size:
                                    parse_errors.append("truncated memory-info-list entry")
                                    break
                                protect = int.from_bytes(raw[36:40], "little")
                                state = int.from_bytes(raw[32:36], "little")
                                region_type = int.from_bytes(raw[40:44], "little")
                                memory_info_ranges.append({
                                    "base_address": f"0x{int.from_bytes(raw[0:8], 'little'):x}",
                                    "allocation_base": f"0x{int.from_bytes(raw[8:16], 'little'):x}",
                                    "size": int.from_bytes(raw[24:32], "little"),
                                    "state": states.get(state, f"unknown_0x{state:x}"),
                                    "protect": protections.get(protect & 0xFF, f"unknown_0x{protect:x}"),
                                    "type": region_types.get(region_type, f"unknown_0x{region_type:x}"),
                                })
                        elif stream_type == 15 and data_size >= 24 and misc_info is None:
                            # MINIDUMP_MISC_INFO v1 supplies dump-process
                            # identity/timing metadata.  It is useful for
                            # correlating a user-mode dump but contains no
                            # process memory and needs no symbol files.
                            stream.seek(rva)
                            raw = stream.read(min(data_size, 64))
                            if len(raw) < 24:
                                parse_errors.append("truncated misc-info stream")
                                continue
                            info_size = int.from_bytes(raw[0:4], "little")
                            flags1 = int.from_bytes(raw[4:8], "little")
                            process_create_time = int.from_bytes(raw[12:16], "little")
                            def unix_time(seconds: int) -> str | None:
                                # Preserve only plausible 32-bit Unix times;
                                # malformed values must not trigger datetime
                                # overflow or imply a real event.
                                if seconds > 4_102_444_800:
                                    return None
                                return (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds)).isoformat()
                            misc_info = {
                                "size": info_size,
                                "flags": f"0x{flags1:08x}",
                                "process_id": int.from_bytes(raw[8:12], "little"),
                                "process_create_time": unix_time(process_create_time),
                                "process_user_time_seconds": int.from_bytes(raw[16:20], "little"),
                                "process_kernel_time_seconds": int.from_bytes(raw[20:24], "little"),
                                "size_valid": 24 <= info_size <= data_size,
                            }
                        elif stream_type in {10, 11} and data_size and len(comments) < 20:
                            # CommentStreamA/W is self-contained metadata,
                            # not a pointer into process memory. Bound its
                            # bytes and preserve the stream type explicitly.
                            stream.seek(rva)
                            raw = stream.read(min(data_size, 64 * 1024))
                            encoding = "utf-16le" if stream_type == 11 else "utf-8"
                            if stream_type == 11 and len(raw) & 1:
                                raw = raw[:-1]
                            comments.append({
                                "stream": "unicode" if stream_type == 11 else "ansi",
                                "text": raw.rstrip(b"\x00").decode(encoding, errors="replace")[:8_000],
                                "truncated": data_size > len(raw),
                            })
            except OSError as exc:
                parse_errors.append(str(exc)[:2_000])
        return [
            self._observation(artifact, "memory.minidump_valid", valid),
            self._observation(artifact, "memory.minidump.version", f"{header[7]}.{header[6]}"),
            self._observation(artifact, "memory.minidump.stream_count", stream_count),
            self._observation(artifact, "memory.minidump.directory_rva", directory_rva),
            self._observation(artifact, "memory.minidump.streams", entries),
            self._observation(artifact, "memory.minidump.system_info", system_info),
            self._observation(artifact, "memory.minidump.module_count", len(modules)),
            self._observation(artifact, "memory.minidump.modules", modules),
            self._observation(artifact, "memory.minidump.thread_count", len(threads)),
            self._observation(artifact, "memory.minidump.threads", threads),
            self._observation(artifact, "memory.minidump.memory_range_count", len(memory_ranges)),
            self._observation(artifact, "memory.minidump.memory_ranges", memory_ranges),
            self._observation(artifact, "memory.minidump.memory64_range_count", len(memory64_ranges)),
            self._observation(artifact, "memory.minidump.memory64_ranges", memory64_ranges),
            self._observation(artifact, "memory.minidump.memory_info_range_count", len(memory_info_ranges)),
            self._observation(artifact, "memory.minidump.memory_info_ranges", memory_info_ranges),
            self._observation(artifact, "memory.minidump.handle_count", len(handles)),
            self._observation(artifact, "memory.minidump.handles", handles),
            self._observation(artifact, "memory.minidump.unloaded_module_count", len(unloaded_modules)),
            self._observation(artifact, "memory.minidump.unloaded_modules", unloaded_modules),
            self._observation(artifact, "memory.minidump.exception", exception),
            self._observation(artifact, "memory.minidump.misc_info", misc_info),
            self._observation(artifact, "memory.minidump.comments", comments),
            self._observation(artifact, "memory.minidump.parse_errors", parse_errors),
        ]

    @staticmethod
    def _minidump_string(path: Path, size: int, rva: int) -> str | None:
        """Read one bounded MINIDUMP_STRING referenced by a validated RVA."""
        if rva <= 0 or rva + 4 > size:
            return None
        try:
            with path.open("rb") as stream:
                stream.seek(rva)
                byte_length = int.from_bytes(stream.read(4), "little")
                if byte_length > 8 * 1024 or byte_length % 2 or rva + 4 + byte_length > size:
                    return None
                raw = stream.read(byte_length)
        except OSError:
            return None
        return raw.decode("utf-16le", errors="replace")[:4_000] if len(raw) == byte_length else None

    def _inspect_windows_artifacts(self, artifact: Artifact, path: Path, header: bytes, size: int) -> list[Observation]:
        lnk = (
            len(header) >= 76
            and int.from_bytes(header[:4], "little") == 0x4C
            and header[4:20] == bytes.fromhex("0114020000000000C000000000000046")
        )
        prefetch = len(header) >= 8 and header[4:8] == b"SCCA"
        logical_basename = artifact.logical_name.replace("\\", "/").rsplit("/", 1)[-1]
        recycle_bin_candidate = logical_basename.casefold().startswith("$i") and len(logical_basename) > 2
        observations = [
            self._observation(artifact, "windows.evtx_signature", header.startswith(b"ElfFile\x00")),
            self._observation(artifact, "windows.registry_signature", header.startswith(b"regf")),
            self._observation(artifact, "windows.lnk_signature", lnk),
            self._observation(artifact, "windows.prefetch_signature", prefetch),
        ]
        if recycle_bin_candidate:
            observations.extend(self._inspect_recycle_bin_item(artifact, path, size))
        if lnk:
            flags = int.from_bytes(header[20:24], "little")
            attributes = int.from_bytes(header[24:28], "little")
            link_flag_names = {
                0x00000001: "has_target_id_list", 0x00000002: "has_link_info",
                0x00000004: "has_name", 0x00000008: "has_relative_path",
                0x00000010: "has_working_directory", 0x00000020: "has_arguments",
                0x00000040: "has_icon_location", 0x00000080: "is_unicode",
                0x00000200: "has_expanded_string", 0x00001000: "has_darwin_id",
                0x00002000: "run_as_user", 0x00020000: "run_with_shim_layer",
                0x02000000: "prefer_environment_path",
            }
            active_flags = [name for bit, name in link_flag_names.items() if flags & bit]
            observations.extend((
                self._observation(artifact, "lnk.header_size", int.from_bytes(header[:4], "little")),
                self._observation(artifact, "lnk.link_flags", active_flags),
                self._observation(artifact, "lnk.file_attributes", attributes),
                self._observation(artifact, "lnk.creation_time", self._filetime_to_iso(header[28:36])),
                self._observation(artifact, "lnk.access_time", self._filetime_to_iso(header[36:44])),
                self._observation(artifact, "lnk.write_time", self._filetime_to_iso(header[44:52])),
                self._observation(artifact, "lnk.target_file_size", int.from_bytes(header[52:56], "little")),
                self._observation(artifact, "lnk.show_command", int.from_bytes(header[60:64], "little")),
            ))
            observations.extend(self._inspect_lnk_string_data(artifact, path, size, flags))
        if prefetch:
            version = int.from_bytes(header[:4], "little")
            declared_size = int.from_bytes(header[12:16], "little")
            executable_name = header[16:76].decode("utf-16le", errors="replace").split("\x00", 1)[0]
            executable_hash = int.from_bytes(header[76:80], "little") if len(header) >= 80 else None
            run_count_offsets = {17: 0x90, 23: 0x98, 26: 0xD0, 30: 0xD0}
            run_offset = run_count_offsets.get(version)
            run_count: int | None = None
            if run_offset is not None and size >= run_offset + 4:
                try:
                    with path.open("rb") as stream:
                        stream.seek(run_offset)
                        run_count = int.from_bytes(stream.read(4), "little")
                except OSError:
                    pass
            observations.extend((
                self._observation(artifact, "prefetch.version", version),
                self._observation(artifact, "prefetch.declared_file_size", declared_size),
                self._observation(artifact, "prefetch.size_matches_evidence", declared_size == size),
                self._observation(artifact, "prefetch.executable_name", executable_name[:512]),
                self._observation(artifact, "prefetch.executable_hash", f"{executable_hash:08X}" if executable_hash is not None else None),
                self._observation(artifact, "prefetch.run_count", run_count),
                self._observation(artifact, "prefetch.run_count_offset", run_offset),
            ))
        return observations

    def _inspect_recycle_bin_item(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Parse fixed `$I` deletion metadata without resolving its `$R` sibling."""
        if size < 24:
            return [self._observation(artifact, "windows.recycle_bin_valid", False)]
        try:
            with path.open("rb") as stream:
                fixed = stream.read(24)
                if len(fixed) != 24:
                    return [self._observation(artifact, "windows.recycle_bin_valid", False)]
                version = int.from_bytes(fixed[0:8], "little")
                if version not in {1, 2}:
                    return [
                        self._observation(artifact, "windows.recycle_bin_valid", False),
                        self._observation(artifact, "windows.recycle_bin_version", version),
                    ]
                original_size = int.from_bytes(fixed[8:16], "little")
                deletion_time = self._filetime_to_iso(fixed[16:24])
                declared_characters: int | None = None
                if version == 2:
                    raw_length = stream.read(4)
                    if len(raw_length) != 4:
                        return [self._observation(artifact, "windows.recycle_bin_valid", False)]
                    declared_characters = int.from_bytes(raw_length, "little")
                    if declared_characters > 32_768 or 28 + declared_characters * 2 > size:
                        return [
                            self._observation(artifact, "windows.recycle_bin_valid", False),
                            self._observation(artifact, "windows.recycle_bin_version", version),
                            self._observation(artifact, "windows.recycle_bin_path_error", "declared path exceeds evidence or 32768-character cap", confidence=0.8),
                        ]
                    raw_path = stream.read(declared_characters * 2)
                else:
                    # Version 1 stores a fixed MAX_PATH-sized UTF-16 buffer;
                    # never let arbitrary following bytes masquerade as a
                    # deletion path merely because the logical filename is
                    # `$I...`.
                    raw_path = stream.read(min(520, size - 24))
                if len(raw_path) % 2:
                    return [self._observation(artifact, "windows.recycle_bin_valid", False)]
                original_path = raw_path.decode("utf-16le", errors="replace").split("\x00", 1)[0][:32_768]
        except OSError as exc:
            return [self._observation(artifact, "windows.recycle_bin_error", str(exc)[:2_000], confidence=0.8)]
        return [
            self._observation(artifact, "windows.recycle_bin_valid", True),
            self._observation(artifact, "windows.recycle_bin_version", version),
            self._observation(artifact, "windows.recycle_bin_original_size", original_size),
            self._observation(artifact, "windows.recycle_bin_deletion_time", deletion_time),
            self._observation(artifact, "windows.recycle_bin_original_path", original_path),
            self._observation(artifact, "windows.recycle_bin_path_characters", declared_characters),
        ]

    @staticmethod
    def _filetime_to_iso(raw: bytes) -> str | None:
        if len(raw) != 8:
            return None
        value = int.from_bytes(raw, "little")
        if not value:
            return None
        try:
            return (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=value // 10)).isoformat()
        except OverflowError:
            return None

    def _inspect_lnk_string_data(self, artifact: Artifact, path: Path, size: int, flags: int) -> list[Observation]:
        """Recover bounded Shell Link StringData after validated variable blocks."""
        offset = 76
        link_info: dict[str, object] | None = None
        try:
            with path.open("rb") as stream:
                if flags & 0x00000001:  # HasLinkTargetIDList
                    stream.seek(offset)
                    raw = stream.read(2)
                    if len(raw) != 2:
                        return [self._observation(artifact, "lnk.string_data_error", "truncated target ID list size", confidence=0.8)]
                    offset += 2 + int.from_bytes(raw, "little")
                if flags & 0x00000002:  # HasLinkInfo
                    stream.seek(offset)
                    raw = stream.read(4)
                    if len(raw) != 4:
                        return [self._observation(artifact, "lnk.string_data_error", "truncated LinkInfo size", confidence=0.8)]
                    link_info_size = int.from_bytes(raw, "little")
                    if link_info_size < 28 or link_info_size > size - offset or link_info_size > _MIB:
                        return [self._observation(artifact, "lnk.string_data_error", "invalid LinkInfo size", confidence=0.8)]
                    stream.seek(offset)
                    encoded_link_info = stream.read(link_info_size)
                    if len(encoded_link_info) != link_info_size:
                        return [self._observation(artifact, "lnk.string_data_error", "truncated LinkInfo data", confidence=0.8)]
                    link_info = self._parse_lnk_link_info(encoded_link_info)
                    offset += link_info_size
                if offset > size:
                    return [self._observation(artifact, "lnk.string_data_error", "variable blocks exceed evidence", confidence=0.8)]
                string_flags = (
                    (0x00000004, "name"), (0x00000008, "relative_path"),
                    (0x00000010, "working_directory"), (0x00000020, "arguments"),
                    (0x00000040, "icon_location"),
                )
                strings: dict[str, str] = {}
                unicode = bool(flags & 0x00000080)
                for bit, name in string_flags:
                    if not flags & bit:
                        continue
                    stream.seek(offset)
                    raw_length = stream.read(2)
                    if len(raw_length) != 2:
                        break
                    characters = int.from_bytes(raw_length, "little")
                    byte_length = characters * (2 if unicode else 1)
                    if characters > 16_384 or offset + 2 + byte_length > size:
                        break
                    raw = stream.read(byte_length)
                    strings[name] = raw.decode("utf-16le" if unicode else "cp1252", errors="replace")[:8_000]
                    offset += 2 + byte_length
        except OSError as exc:
            return [self._observation(artifact, "lnk.string_data_error", str(exc), confidence=0.8)]
        observations = [
            self._observation(artifact, "lnk.string_data", strings),
            self._observation(artifact, "lnk.link_info", link_info),
        ]
        if isinstance(link_info, dict) and isinstance(link_info.get("target_path"), str):
            observations.append(self._observation(artifact, "lnk.target_path", link_info["target_path"], confidence=0.9))
        if "arguments" in strings:
            observations.append(self._observation(artifact, "lnk.arguments", strings["arguments"], confidence=0.9))
        if "relative_path" in strings:
            observations.append(self._observation(artifact, "lnk.relative_path", strings["relative_path"], confidence=0.9))
        return observations

    @staticmethod
    def _parse_lnk_link_info(data: bytes) -> dict[str, object]:
        """Decode bounded local LinkInfo path strings without following links."""
        header_size = int.from_bytes(data[4:8], "little")
        result: dict[str, object] = {
            "size": len(data),
            "header_size": header_size,
            "flags": f"0x{int.from_bytes(data[8:12], 'little'):08x}",
            "valid": 28 <= header_size <= len(data),
        }
        if header_size < 28 or header_size > len(data):
            return result
        local_offset = int.from_bytes(data[16:20], "little")
        suffix_offset = int.from_bytes(data[24:28], "little")
        unicode_local_offset = int.from_bytes(data[28:32], "little") if header_size >= 36 else 0
        unicode_suffix_offset = int.from_bytes(data[32:36], "little") if header_size >= 36 else 0

        def read_string(offset: int, encoding: str) -> str | None:
            if offset < header_size or offset >= len(data):
                return None
            raw = data[offset:min(len(data), offset + 16 * 1024)]
            if encoding == "utf-16le":
                raw = raw[:len(raw) - (len(raw) % 2)]
                terminator = next((index for index in range(0, len(raw), 2) if raw[index:index + 2] == b"\x00\x00"), len(raw))
                return raw[:terminator].decode(encoding, errors="replace")[:8_000]
            terminator = raw.find(b"\x00")
            return raw[:len(raw) if terminator < 0 else terminator].decode("cp1252", errors="replace")[:8_000]

        base = read_string(unicode_local_offset, "utf-16le") or read_string(local_offset, "cp1252")
        suffix = read_string(unicode_suffix_offset, "utf-16le") or read_string(suffix_offset, "cp1252")
        result["local_base_path"] = base
        result["common_path_suffix"] = suffix
        if base and suffix:
            result["target_path"] = base.rstrip("\\/") + "\\" + suffix.lstrip("\\/")
        return result

    def _inspect_registry_hive(self, artifact: Artifact, path: Path) -> list[Observation]:
        with path.open("rb") as stream:
            base = stream.read(4096)
        if len(base) < 48 or not base.startswith(b"regf"):
            return [self._observation(artifact, "registry.base_block_valid", False)]
        primary_sequence = int.from_bytes(base[4:8], "little")
        secondary_sequence = int.from_bytes(base[8:12], "little")
        filetime = int.from_bytes(base[12:20], "little")
        modified = None
        if filetime:
            try:
                modified = (datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=filetime // 10)).isoformat()
            except OverflowError:
                pass
        root_offset = int.from_bytes(base[36:40], "little")
        observations = [
            self._observation(artifact, "registry.base_block_valid", True),
            self._observation(artifact, "registry.primary_sequence", primary_sequence),
            self._observation(artifact, "registry.secondary_sequence", secondary_sequence),
            self._observation(artifact, "registry.sequence_mismatch", primary_sequence != secondary_sequence),
            self._observation(artifact, "registry.last_write_time", modified),
            self._observation(artifact, "registry.root_cell_offset", root_offset),
            self._observation(artifact, "registry.hbin_data_size", int.from_bytes(base[40:44], "little")),
        ]
        # Root cell offsets are relative to the first hbin at 0x1000.  A
        # direct bounded NK parse gives useful hive identity without walking
        # attacker-controlled subkey lists.
        try:
            with path.open("rb") as stream:
                stream.seek(4096 + root_offset)
                cell = stream.read(1024)
        except OSError as exc:
            observations.append(self._observation(artifact, "registry.root_cell_error", str(exc), confidence=0.8))
            return observations
        if len(cell) < 80:
            observations.append(self._observation(artifact, "registry.root_cell_valid", False))
            return observations
        cell_size = int.from_bytes(cell[:4], "little", signed=True)
        valid = cell_size <= -80 and cell[4:6] == b"nk"
        observations.append(self._observation(artifact, "registry.root_cell_valid", valid))
        if not valid:
            return observations
        key_name_length = int.from_bytes(cell[76:78], "little")
        key_name = cell[80:80 + min(key_name_length, max(0, len(cell) - 80))]
        ascii_name = bool(int.from_bytes(cell[6:8], "little") & 0x20)
        decoded_name = key_name.decode("latin-1" if ascii_name else "utf-16le", errors="replace")
        observations.extend((
            self._observation(artifact, "registry.root_key_name", decoded_name[:512]),
            self._observation(artifact, "registry.root_key_last_write", self._filetime_to_iso(cell[8:16])),
            self._observation(artifact, "registry.root_parent_offset", int.from_bytes(cell[20:24], "little")),
            self._observation(artifact, "registry.root_subkey_count", int.from_bytes(cell[24:28], "little")),
            self._observation(artifact, "registry.root_volatile_subkey_count", int.from_bytes(cell[28:32], "little")),
            self._observation(artifact, "registry.root_subkey_list_offset", int.from_bytes(cell[32:36], "little")),
            self._observation(artifact, "registry.root_value_count", int.from_bytes(cell[40:44], "little")),
            self._observation(artifact, "registry.root_value_list_offset", int.from_bytes(cell[44:48], "little")),
            self._observation(artifact, "registry.root_cell_size", -cell_size),
        ))
        subkey_count = int.from_bytes(cell[24:28], "little")
        subkey_list_offset = int.from_bytes(cell[32:36], "little")
        if subkey_count:
            subkey_inventory, subkey_error = self._registry_subkey_inventory(
                path, artifact.size, subkey_list_offset
            )
        else:
            subkey_inventory, subkey_error = [], None
        subkey_names = [str(item["name"]) for item in subkey_inventory]
        child_values: list[dict[str, object]] = []
        child_value_errors: list[str] = []
        # A second-level value inventory is intentionally limited to direct
        # root children.  It can reveal useful configuration names in small
        # standalone hives without turning generic triage into an unbounded
        # key-path traversal.
        execution_key_names = {
            "run", "runonce", "runonceex", "load", "shell", "userinit",
            "debugger", "startup", "command",
        }
        for child in subkey_inventory[:32]:
            value_count = child.get("value_count")
            value_list = child.get("value_list_offset")
            if not isinstance(value_count, int) or not isinstance(value_list, int) or value_count <= 0:
                continue
            child_name = str(child.get("name", "")).strip().lower()
            names, metadata, error = self._registry_value_names(
                path,
                artifact.size,
                value_list,
                value_count,
                recover_text_data=child_name in execution_key_names,
            )
            child_values.extend({"key": child["name"], **item} for item in metadata[:64])
            if error:
                child_value_errors.append(f"{child['name']}: {error}")
            if len(child_values) >= 256:
                child_values = child_values[:256]
                break
        observations.extend((
            self._observation(artifact, "registry.root_subkey_names", subkey_names),
            self._observation(artifact, "registry.root_subkeys", subkey_inventory),
            self._observation(artifact, "registry.root_child_values", child_values),
            self._observation(artifact, "registry.root_child_value_errors", child_value_errors),
            self._observation(artifact, "registry.root_subkey_names_truncated", len(subkey_names) >= 256),
            self._observation(artifact, "registry.root_subkey_list_error", subkey_error, confidence=0.8),
        ))
        # Persistence keys normally live several levels below a hive root.
        # Follow only a small, explicit set of Windows paths: this is not a
        # general hive walker, and no attacker-controlled key name can make
        # triage explore an unrelated branch.  The resulting values retain
        # their complete key path so a later RegRipper run can corroborate
        # them against transaction logs.
        persistence_values, persistence_errors, persistence_truncated = self._registry_persistence_path_values(
            path, artifact.size, subkey_inventory
        )
        observations.extend((
            self._observation(artifact, "registry.persistence_path_values", persistence_values),
            self._observation(artifact, "registry.persistence_path_errors", persistence_errors, confidence=0.8),
            self._observation(artifact, "registry.persistence_path_truncated", persistence_truncated),
        ))
        value_count = int.from_bytes(cell[40:44], "little")
        value_list_offset = int.from_bytes(cell[44:48], "little")
        value_names, value_metadata, value_error = self._registry_value_names(
            path, artifact.size, value_list_offset, value_count
        )
        observations.extend((
            self._observation(artifact, "registry.root_value_names", value_names),
            self._observation(artifact, "registry.root_values", value_metadata),
            self._observation(artifact, "registry.root_value_names_truncated", value_count > len(value_names)),
            self._observation(artifact, "registry.root_value_list_error", value_error, confidence=0.8),
        ))
        recovered_commands = [
            item for item in child_values
            if isinstance(item.get("data_text"), (str, list))
        ] + [
            item for item in persistence_values
            if isinstance(item.get("data_text"), (str, list))
        ]
        observations.append(
            self._observation(artifact, "registry.execution_value_data", recovered_commands)
        )
        hbin_count, hbin_valid, hbin_samples = self._registry_hbin_inventory(path, artifact.size)
        observations.extend((
            self._observation(artifact, "registry.hbin_count", hbin_count),
            self._observation(artifact, "registry.hbin_layout_valid", hbin_valid),
            self._observation(artifact, "registry.hbin_samples", hbin_samples),
        ))
        return observations

    @staticmethod
    def _registry_hbin_inventory(path: Path, size: int) -> tuple[int, bool, list[dict[str, int]]]:
        """Walk a small, validated prefix of hbin headers without cell traversal."""
        offset = 4096
        count = 0
        valid = True
        samples: list[dict[str, int]] = []
        try:
            with path.open("rb") as stream:
                while offset + 32 <= size and count < 512:
                    stream.seek(offset)
                    header = stream.read(32)
                    if len(header) != 32 or header[:4] != b"hbin":
                        valid = False
                        break
                    relative = int.from_bytes(header[4:8], "little")
                    block_size = int.from_bytes(header[8:12], "little")
                    if block_size < 4096 or block_size % 4096 or offset + block_size > size:
                        valid = False
                        break
                    if len(samples) < 100:
                        samples.append({"offset": offset, "relative_offset": relative, "size": block_size})
                    offset += block_size
                    count += 1
        except OSError:
            return count, False, samples
        return count, valid and (offset == size or count == 512), samples

    @staticmethod
    def _registry_subkey_inventory(
        path: Path, size: int, list_offset: int
    ) -> tuple[list[dict[str, object]], str | None]:
        """Resolve direct root NK metadata through validated list cells only.

        This follows at most ``ri → leaf-list → NK`` references.  It does not
        descend into child subkey lists, so malformed hive data cannot cause a
        recursive walk across the complete hive during generic triage.
        """
        if list_offset in {0xFFFFFFFF, 0xFFFFFFFE}:
            return [], None
        inventory: list[dict[str, object]] = []
        seen_lists: set[int] = set()
        try:
            with path.open("rb") as stream:
                def read_cell(offset: int, maximum: int = 32 * 1024) -> bytes | None:
                    absolute = 4096 + offset
                    if offset < 0 or absolute + 4 > size:
                        return None
                    stream.seek(absolute)
                    raw_size = stream.read(4)
                    if len(raw_size) != 4:
                        return None
                    cell_size = int.from_bytes(raw_size, "little", signed=True)
                    if cell_size >= -4 or -cell_size > maximum or absolute - cell_size > size:
                        return None
                    rest = stream.read(-cell_size - 4)
                    return raw_size + rest if len(rest) == -cell_size - 4 else None

                def add_nk(offset: int) -> None:
                    if len(inventory) >= 256:
                        return
                    cell = read_cell(offset, 4096)
                    if cell is None or len(cell) < 84 or cell[4:6] != b"nk":
                        return
                    name_length = int.from_bytes(cell[76:78], "little")
                    if name_length > len(cell) - 80:
                        return
                    ascii_name = bool(int.from_bytes(cell[6:8], "little") & 0x20)
                    name = cell[80:80 + name_length].decode("latin-1" if ascii_name else "utf-16le", errors="replace")
                    if name:
                        inventory.append({
                            "name": name[:512],
                            "offset": offset,
                            "last_write_time": GenericTriageEngine._filetime_to_iso(cell[8:16]),
                            "subkey_count": int.from_bytes(cell[24:28], "little"),
                            "subkey_list_offset": int.from_bytes(cell[32:36], "little"),
                            "value_count": int.from_bytes(cell[40:44], "little"),
                            "value_list_offset": int.from_bytes(cell[44:48], "little"),
                        })

                def walk_list(offset: int, depth: int = 0) -> None:
                    if len(inventory) >= 256 or depth > 2 or offset in seen_lists:
                        return
                    seen_lists.add(offset)
                    cell = read_cell(offset)
                    if cell is None or len(cell) < 8:
                        return
                    signature = cell[4:6]
                    count = int.from_bytes(cell[6:8], "little")
                    if count > 1024:
                        return
                    if signature == b"ri":
                        for index in range(min(count, (len(cell) - 8) // 4)):
                            walk_list(int.from_bytes(cell[8 + index * 4:12 + index * 4], "little"), depth + 1)
                    elif signature in {b"li", b"lf", b"lh"}:
                        stride = 4 if signature == b"li" else 8
                        for index in range(min(count, (len(cell) - 8) // stride)):
                            add_nk(int.from_bytes(cell[8 + index * stride:12 + index * stride], "little"))
                walk_list(list_offset)
        except OSError as exc:
            return inventory, str(exc)[:2_000]
        return inventory, None

    @staticmethod
    def _registry_persistence_path_values(
        path: Path, size: int, root_subkeys: list[dict[str, object]]
    ) -> tuple[list[dict[str, object]], list[str], bool]:
        """Recover small values from a fixed, bounded Windows persistence allowlist.

        Registry hives have arbitrary graph-like cell references.  This helper
        deliberately follows only prefixes of known persistence locations and
        limits nodes, list entries, values, and depth.  It never performs a
        complete key enumeration and delegates data recovery to the same
        single-cell REG_SZ guard used for direct-child Run keys.
        """
        targets: tuple[tuple[tuple[str, ...], set[str] | None], ...] = (
            (("software", "microsoft", "windows", "currentversion", "run"), None),
            (("software", "microsoft", "windows", "currentversion", "runonce"), None),
            (("software", "microsoft", "windows", "currentversion", "runonceex"), None),
            (("software", "microsoft", "windows", "currentversion", "policies", "explorer", "run"), None),
            (("software", "microsoft", "windows nt", "currentversion", "winlogon"), {"shell", "userinit"}),
            (("software", "microsoft", "windows", "currentversion", "image file execution options", "*"), {"debugger"}),
            (("system", "currentcontrolset", "control", "session manager"), {"bootexecute", "setupexecute"}),
            (("system", "controlset*", "control", "session manager"), {"bootexecute", "setupexecute"}),
        )
        values: list[dict[str, object]] = []
        errors: list[str] = []
        seen_nodes: set[int] = set()
        node_count = 0
        truncated = False

        def segment_matches(actual: str, expected: str) -> bool:
            return expected == "*" or (expected == "controlset*" and actual.startswith("controlset")) or actual == expected

        def matching_targets(key_path: tuple[str, ...]) -> list[tuple[tuple[str, ...], set[str] | None]]:
            return [
                target for target in targets
                if len(key_path) <= len(target[0])
                and all(segment_matches(actual, expected) for actual, expected in zip(key_path, target[0]))
            ]

        def visit(node: dict[str, object], key_path: tuple[str, ...]) -> None:
            nonlocal node_count, truncated
            if node_count >= 128 or len(values) >= 256:
                truncated = True
                return
            offset = node.get("offset")
            if not isinstance(offset, int) or offset in seen_nodes:
                return
            seen_nodes.add(offset)
            node_count += 1
            matched = matching_targets(key_path)
            if not matched:
                return
            for target_path, value_names in matched:
                if key_path != target_path:
                    continue
                value_count = node.get("value_count")
                value_list = node.get("value_list_offset")
                if not isinstance(value_count, int) or not isinstance(value_list, int) or value_count <= 0:
                    continue
                _, metadata, error = GenericTriageEngine._registry_value_names(
                    path, size, value_list, value_count,
                    recover_text_data=True,
                    recover_text_names=value_names,
                )
                if error:
                    errors.append(f"{'\\'.join(key_path)}: {error}")
                for item in metadata:
                    if value_names is not None and str(item.get("name", "")).casefold() not in value_names:
                        continue
                    values.append({"key_path": "\\".join(key_path), "key": node.get("name", ""), **item})
                    if len(values) >= 256:
                        truncated = True
                        return
                return
            # Continue only along a known target prefix.  Each child list is
            # validated by _registry_subkey_inventory before use.
            child_count = node.get("subkey_count")
            child_list = node.get("subkey_list_offset")
            if not isinstance(child_count, int) or not isinstance(child_list, int) or child_count <= 0:
                return
            children, error = GenericTriageEngine._registry_subkey_inventory(path, size, child_list)
            if error:
                errors.append(f"{'\\'.join(key_path)}: {error}")
            for child in children:
                child_name = str(child.get("name", "")).casefold()
                if child_name and matching_targets((*key_path, child_name)):
                    visit(child, (*key_path, child_name))

        for root in root_subkeys[:256]:
            root_name = str(root.get("name", "")).casefold()
            if root_name and matching_targets((root_name,)):
                visit(root, (root_name,))
        return values, errors[:128], truncated

    @staticmethod
    def _registry_value_names(
        path: Path,
        size: int,
        list_offset: int,
        count: int,
        *,
        recover_text_data: bool = False,
        recover_text_names: set[str] | None = None,
    ) -> tuple[list[str], list[dict[str, object]], str | None]:
        """Read a bounded VK-list inventory with optional safe string recovery.

        Registry value data may point at arbitrary-sized allocated cells.  The
        decision engine normally only needs value names, types, and declared
        sizes at this early triage stage, so it does not dereference those
        offsets.  The sole exception is a direct root child whose *key name*
        is execution-relevant (for example ``Run``): bounded REG_SZ-like data
        is recovered only after validating an allocated, non-indirect cell.
        The routine never follows ``db`` big-data records or any further cell
        reference chain.
        """
        if count == 0:
            return [], [], None
        if count > 256 or list_offset in {0xFFFFFFFF, 0xFFFFFFFE}:
            return [], [], "invalid or oversized value list"
        names: list[str] = []
        metadata: list[dict[str, object]] = []
        value_types = {
            0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
            4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK",
            7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
            10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
        }
        try:
            with path.open("rb") as stream:
                list_absolute = 4096 + list_offset
                if list_absolute + 4 + count * 4 > size:
                    return [], [], "value list exceeds evidence"
                stream.seek(list_absolute)
                cell_size = int.from_bytes(stream.read(4), "little", signed=True)
                if cell_size >= -(4 + count * 4) or list_absolute - cell_size > size:
                    return [], [], "invalid value-list cell size"
                offsets = [int.from_bytes(stream.read(4), "little") for _ in range(count)]
                for value_offset in offsets:
                    absolute = 4096 + value_offset
                    if absolute + 24 > size:
                        continue
                    stream.seek(absolute)
                    cell_size = int.from_bytes(stream.read(4), "little", signed=True)
                    fixed = stream.read(20)
                    if cell_size >= -24 or fixed[:2] != b"vk":
                        continue
                    name_length = int.from_bytes(fixed[2:4], "little")
                    if name_length > 1024 or absolute + 24 + name_length > size or -cell_size < 24 + name_length:
                        continue
                    raw = stream.read(name_length)
                    # VK flags are after type (not at the type field): cell
                    # header + vk + name + data length + data offset + type.
                    ascii_name = bool(int.from_bytes(fixed[16:18], "little") & 1)
                    name = raw.decode("latin-1" if ascii_name else "utf-16le", errors="replace") if raw else "(Default)"
                    names.append(name[:512])
                    stored_length = int.from_bytes(fixed[4:8], "little")
                    data_size = stored_length & 0x7FFFFFFF
                    value_type = int.from_bytes(fixed[12:16], "little")
                    item_metadata: dict[str, object] = {
                        "name": name[:512],
                        "type": value_types.get(value_type, f"REG_UNKNOWN_{value_type}"),
                        "type_code": value_type,
                        "data_size": data_size,
                        "data_inline": bool(stored_length & 0x80000000),
                    }
                    # Inline VK data lives in the fixed 4-byte data-offset
                    # field, so it can be safely represented without
                    # following a separately allocated untrusted cell.
                    if stored_length & 0x80000000:
                        inline = fixed[8:12][:data_size]
                        item_metadata["inline_data_hex"] = inline.hex()
                        if value_type == 4 and len(inline) == 4:
                            item_metadata["inline_value"] = int.from_bytes(inline, "little")
                        elif value_type == 5 and len(inline) == 4:
                            item_metadata["inline_value"] = int.from_bytes(inline, "big")
                    elif (
                        recover_text_data
                        and value_type in {1, 2, 7}
                        and (recover_text_names is None or name.casefold() in recover_text_names)
                    ):
                        recovered, recovery_error = GenericTriageEngine._registry_text_value_data(
                            stream,
                            size,
                            int.from_bytes(fixed[8:12], "little"),
                            data_size,
                            value_type,
                        )
                        if recovered is not None:
                            item_metadata["data_text"] = recovered
                        elif recovery_error:
                            item_metadata["data_recovery_error"] = recovery_error
                    metadata.append(item_metadata)
        except OSError as exc:
            return names, metadata, str(exc)[:2_000]
        return names, metadata, None

    @staticmethod
    def _registry_text_value_data(
        stream: BinaryIO,
        size: int,
        data_offset: int,
        data_size: int,
        value_type: int,
    ) -> tuple[str | list[str] | None, str | None]:
        """Safely decode one direct REG_SZ-like data cell.

        Registry's normal VK data offset is relative to the first hbin.  This
        helper accepts only a single allocated cell, rejects ``db`` indirect
        records, and has a small hard cap so a corrupted hive cannot cause an
        expensive or misleading read during generic triage.
        """
        maximum_data = 16 * 1024
        if data_size == 0:
            return "" if value_type != 7 else [], None
        if data_size > maximum_data or data_offset in {0xFFFFFFFF, 0xFFFFFFFE}:
            return None, "text value data is invalid or exceeds 16 KiB cap"
        absolute = 4096 + data_offset
        if absolute < 4096 or absolute + 4 > size:
            return None, "text value data offset exceeds evidence"
        stream.seek(absolute)
        raw_size = stream.read(4)
        if len(raw_size) != 4:
            return None, "text value data cell header is truncated"
        cell_size = int.from_bytes(raw_size, "little", signed=True)
        payload_capacity = -cell_size - 4
        if cell_size >= -4 or payload_capacity < data_size or absolute - cell_size > size:
            return None, "text value data cell is unallocated or too small"
        payload = stream.read(data_size)
        if len(payload) != data_size:
            return None, "text value data cell is truncated"
        # A db cell describes indirect big data.  Never chase its segment list
        # from generic triage, even when a malicious header claims REG_SZ.
        if payload[:2] == b"db":
            return None, "indirect Registry big-data cells are not recovered"
        if data_size % 2:
            return None, "UTF-16 Registry text data has odd byte length"
        decoded = payload.decode("utf-16le", errors="replace")
        if value_type == 7:
            return [entry for entry in decoded.rstrip("\x00").split("\x00") if entry][:128], None
        return decoded.rstrip("\x00")[:8_192], None

    def _inspect_evtx(self, artifact: Artifact, path: Path) -> list[Observation]:
        """Read EVTX file-header counters without decoding event records."""
        try:
            with path.open("rb") as stream:
                header = stream.read(4096)
        except OSError as exc:
            return [self._observation(artifact, "evtx.header_error", str(exc), confidence=0.8)]
        valid = len(header) >= 44 and header.startswith(b"ElfFile\x00")
        if not valid:
            return [self._observation(artifact, "evtx.header_valid", False)]
        header_size = int.from_bytes(header[32:36], "little")
        minor_version = int.from_bytes(header[36:38], "little")
        major_version = int.from_bytes(header[38:40], "little")
        header_block_size = int.from_bytes(header[40:42], "little")
        chunk_count = int.from_bytes(header[42:44], "little")
        chunks: list[dict[str, object]] = []
        chunk_errors: list[str] = []
        records: list[dict[str, object]] = []
        record_errors: list[str] = []
        # EVTX chunks are fixed 64 KiB. Inventory a finite prefix and never
        # decode BinXML records here; external Hayabusa/Chainsaw remains the
        # event parser.
        try:
            with path.open("rb") as stream:
                possible = min(chunk_count, max(0, (path.stat().st_size - 4096) // 65536), 256)
                for index in range(possible):
                    offset = 4096 + index * 65536
                    stream.seek(offset)
                    chunk = stream.read(512)
                    if len(chunk) < 128 or not chunk.startswith(b"ElfChnk\x00"):
                        chunk_errors.append(f"chunk {index}: invalid signature or truncated header")
                        continue
                    header_bytes = int.from_bytes(chunk[40:44], "little")
                    last_record_offset = int.from_bytes(chunk[44:48], "little")
                    free_space_offset = int.from_bytes(chunk[48:52], "little")
                    chunks.append({
                        "index": index,
                        "offset": offset,
                        "first_event_record_number": int.from_bytes(chunk[8:16], "little"),
                        "last_event_record_number": int.from_bytes(chunk[16:24], "little"),
                        "first_event_record_id": int.from_bytes(chunk[24:32], "little"),
                        "last_event_record_id": int.from_bytes(chunk[32:40], "little"),
                        "header_size": header_bytes,
                        "last_record_offset": last_record_offset,
                        "free_space_offset": free_space_offset,
                        "layout_valid": header_bytes in {512, 4096} and header_bytes <= last_record_offset <= free_space_offset <= 65536,
                    })
                    if header_bytes not in {512, 4096} or not (header_bytes <= last_record_offset <= 65536):
                        continue
                    cursor = header_bytes
                    while cursor < last_record_offset and len(records) < 500:
                        stream.seek(offset + cursor)
                        record = stream.read(24)
                        if len(record) < 24 or record[:4] != b"**\x00\x00":
                            record_errors.append(f"chunk {index}: invalid/truncated record at {cursor}")
                            break
                        record_size = int.from_bytes(record[4:8], "little")
                        if record_size < 24 or cursor + record_size > last_record_offset:
                            record_errors.append(f"chunk {index}: invalid record size at {cursor}")
                            break
                        stream.seek(offset + cursor + record_size - 4)
                        if int.from_bytes(stream.read(4), "little") != record_size:
                            record_errors.append(f"chunk {index}: record size mirror mismatch at {cursor}")
                            break
                        records.append({"chunk_index": index, "offset": offset + cursor, "size": record_size, "record_id": int.from_bytes(record[8:16], "little"), "timestamp": self._filetime_to_iso(record[16:24])})
                        cursor += record_size
        except OSError as exc:
            chunk_errors.append(str(exc)[:2_000])
        record_id_gaps = [
            {"previous_record_id": previous["record_id"], "record_id": current["record_id"], "previous_offset": previous["offset"], "offset": current["offset"]}
            for previous, current in zip(records, records[1:])
            if isinstance(previous.get("record_id"), int) and isinstance(current.get("record_id"), int)
            and current["record_id"] != previous["record_id"] + 1
        ][:100]
        return [
            self._observation(artifact, "evtx.header_valid", header_size in {128, 4096} and header_block_size in {4096, 65536}),
            self._observation(artifact, "evtx.first_chunk_number", int.from_bytes(header[8:16], "little")),
            self._observation(artifact, "evtx.last_chunk_number", int.from_bytes(header[16:24], "little")),
            self._observation(artifact, "evtx.next_record_identifier", int.from_bytes(header[24:32], "little")),
            self._observation(artifact, "evtx.header_size", header_size),
            self._observation(artifact, "evtx.version", f"{major_version}.{minor_version}"),
            self._observation(artifact, "evtx.header_block_size", header_block_size),
            self._observation(artifact, "evtx.chunk_count", chunk_count),
            self._observation(artifact, "evtx.chunks_inspected", len(chunks)),
            self._observation(artifact, "evtx.chunk_headers", chunks),
            self._observation(artifact, "evtx.chunk_header_errors", chunk_errors),
            self._observation(artifact, "evtx.records_inspected", len(records)),
            self._observation(artifact, "evtx.record_headers", records),
            self._observation(artifact, "evtx.record_header_errors", record_errors),
            self._observation(artifact, "evtx.record_id_gaps", record_id_gaps, confidence=0.8),
        ]

    def _inspect_pdf(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        sample_size = min(size, self.limits.max_string_scan_bytes)
        with path.open("rb") as stream:
            head = stream.read(min(sample_size, 8 * _MIB))
            tail_size = min(size, 8 * _MIB)
            stream.seek(max(0, size - tail_size))
            tail = stream.read(tail_size)
        eof_index = tail.rfind(b"%%EOF")
        eof_offset = size - tail_size + eof_index if eof_index >= 0 else None
        bytes_after = size - (eof_offset + 5) if eof_offset is not None else 0
        markers = {
            "javascript": head.count(b"/JavaScript") + head.count(b"/JS"),
            "open_action": head.count(b"/OpenAction"),
            "launch": head.count(b"/Launch"),
            "embedded_file": head.count(b"/EmbeddedFile"),
            "object_markers": head.count(b" obj"),
        }
        return [
            self._observation(artifact, "pdf.eof_found", eof_offset is not None),
            self._observation(artifact, "pdf.eof_offset", eof_offset),
            self._observation(artifact, "pdf.bytes_after_eof", bytes_after),
            self._observation(artifact, "pdf.markers", markers),
            self._observation(artifact, "pdf.javascript_marker_count", markers["javascript"]),
            self._observation(artifact, "pdf.open_action_marker_count", markers["open_action"]),
            self._observation(artifact, "pdf.embedded_file_marker_count", markers["embedded_file"]),
            self._observation(artifact, "pdf.object_marker_count", markers["object_markers"]),
        ]

    def _extension_observations(
        self, artifact: Artifact, detected_format: str | None
    ) -> list[Observation]:
        extension = Path(artifact.logical_name).suffix.lower()
        expected = _EXPECTED_EXTENSIONS.get(detected_format or "")
        mismatch = bool(expected is not None and extension not in expected)
        detail: dict[str, object] = {
            "extension": extension,
            "detected_format": detected_format or "unknown",
            "mismatch": mismatch,
        }
        if expected is not None:
            detail["expected_extensions"] = sorted(expected)
        return [
            self._observation(artifact, "artifact.extension", extension),
            self._observation(artifact, "extension.mismatch", mismatch),
            self._observation(artifact, "extension.analysis", detail),
        ]

    def _inspect_png(
        self, artifact: Artifact, path: Path, size: int
    ) -> list[Observation]:
        chunk_types: list[str] = []
        chunk_count = 0
        offset = 8
        iend_offset: int | None = None
        iend_end_offset: int | None = None
        structure_error: str | None = None
        width: int | None = None
        height: int | None = None
        bit_depth: int | None = None
        color_type: int | None = None
        max_chunks = 16_384
        crc_checked = 0
        crc_bytes = 0
        crc_failures: list[dict[str, object]] = []
        crc_truncated = False
        text_entries: list[dict[str, str]] = []
        text_truncated = False

        with path.open("rb") as stream:
            while offset + 12 <= size and chunk_count < max_chunks:
                stream.seek(offset)
                chunk_header = stream.read(8)
                if len(chunk_header) != 8:
                    structure_error = "truncated chunk header"
                    break
                length = int.from_bytes(chunk_header[:4], "big")
                raw_type = chunk_header[4:8]
                chunk_end = offset + 12 + length
                if chunk_end > size:
                    structure_error = (
                        f"chunk at {offset:#x} declares {length} data bytes past EOF"
                    )
                    break
                try:
                    chunk_type = raw_type.decode("ascii")
                except UnicodeDecodeError:
                    chunk_type = raw_type.hex()
                    structure_error = f"non-ASCII chunk type at {offset:#x}"
                chunk_count += 1
                if len(chunk_types) < 256:
                    chunk_types.append(chunk_type)
                if raw_type in {b"tEXt", b"zTXt", b"iTXt"}:
                    if length > 256 * 1024 or len(text_entries) >= 100:
                        text_truncated = True
                    else:
                        stream.seek(offset + 8)
                        payload = stream.read(length)
                        entry = self._parse_png_text_chunk(raw_type, payload)
                        if entry is not None:
                            text_entries.append(entry)
                # Native CRC checks make PNG structural evidence useful even
                # when pngcheck is not installed.  They are deliberately
                # capped so a forged IDAT length cannot turn generic triage
                # into a full multi-gigabyte validation pass.
                if length <= 8 * _MIB and crc_bytes + length <= 32 * _MIB:
                    stream.seek(offset + 8)
                    payload = stream.read(length)
                    stored_crc = stream.read(4)
                    if len(payload) != length or len(stored_crc) != 4:
                        structure_error = "truncated PNG chunk CRC"
                        break
                    calculated_crc = zlib.crc32(raw_type + payload) & 0xFFFFFFFF
                    if calculated_crc != int.from_bytes(stored_crc, "big") and len(crc_failures) < 100:
                        crc_failures.append({
                            "offset": offset,
                            "type": chunk_type,
                            "stored": f"0x{int.from_bytes(stored_crc, 'big'):08x}",
                            "calculated": f"0x{calculated_crc:08x}",
                        })
                    crc_checked += 1
                    crc_bytes += length
                else:
                    crc_truncated = True
                if raw_type == b"IEND":
                    iend_offset = offset
                    iend_end_offset = chunk_end
                    if length != 0:
                        structure_error = "IEND chunk has non-zero length"
                    break
                if raw_type == b"IHDR" and length == 13:
                    stream.seek(offset + 8)
                    ihdr = stream.read(13)
                    width = int.from_bytes(ihdr[0:4], "big")
                    height = int.from_bytes(ihdr[4:8], "big")
                    bit_depth = ihdr[8]
                    color_type = ihdr[9]
                offset = chunk_end

        if chunk_count >= max_chunks and iend_offset is None:
            structure_error = f"chunk inspection stopped at safety limit {max_chunks}"
        iend_found = iend_end_offset is not None
        bytes_after = size - iend_end_offset if iend_end_offset is not None else 0
        trailer_header = b""
        if iend_end_offset is not None and bytes_after:
            with path.open("rb") as stream:
                stream.seek(iend_end_offset)
                trailer_header = stream.read(min(64, bytes_after))

        known_chunks = {
            "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP",
            "sBIT", "sRGB", "tEXt", "zTXt", "iTXt", "bKGD", "hIST", "pHYs",
            "sPLT", "tIME", "eXIf",
        }
        unusual = sorted({item for item in chunk_types if item not in known_chunks})
        valid = iend_found and structure_error is None
        return [
            self._observation(artifact, "png.valid_signature", True),
            self._observation(artifact, "png.chunk_count", chunk_count),
            self._observation(artifact, "png.chunk_types", chunk_types),
            self._observation(artifact, "image.width", width),
            self._observation(artifact, "image.height", height),
            self._observation(artifact, "png.bit_depth", bit_depth),
            self._observation(artifact, "png.color_type", color_type),
            self._observation(artifact, "png.chunk_types_truncated", chunk_count > len(chunk_types)),
            self._observation(artifact, "png.crc_checked_chunk_count", crc_checked),
            self._observation(artifact, "png.crc_checked_bytes", crc_bytes),
            self._observation(artifact, "png.crc_failures", crc_failures),
            self._observation(artifact, "png.crc_valid", not crc_failures and structure_error is None),
            self._observation(artifact, "png.crc_validation_truncated", crc_truncated),
            self._observation(artifact, "png.unusual_chunk_types", unusual),
            self._observation(artifact, "png.text_entries", text_entries),
            self._observation(artifact, "png.text_entries_truncated", text_truncated),
            self._observation(artifact, "png.iend_found", iend_found),
            self._observation(artifact, "png.iend_offset", iend_offset),
            self._observation(artifact, "png.iend_end_offset", iend_end_offset),
            self._observation(artifact, "png.bytes_after_iend", bytes_after),
            self._observation(artifact, "png.trailer.header.hex", trailer_header.hex()),
            self._observation(artifact, "png.structure_valid", valid),
            self._observation(artifact, "png.structure_error", structure_error),
        ]

    @staticmethod
    def _parse_png_text_chunk(chunk_type: bytes, payload: bytes) -> dict[str, str] | None:
        """Decode one small PNG text chunk, with bounded zlib output."""
        keyword, separator, remainder = payload.partition(b"\x00")
        if not separator or not keyword or len(keyword) > 79:
            return None
        try:
            key = keyword.decode("latin-1")
            if chunk_type == b"tEXt":
                text = remainder.decode("latin-1", errors="replace")
            elif chunk_type == b"zTXt":
                if not remainder or remainder[0] != 0:
                    return None
                decoder = zlib.decompressobj()
                raw = decoder.decompress(remainder[1:], 65_537)
                if len(raw) > 65_536 or decoder.unconsumed_tail:
                    return None
                text = raw.decode("latin-1", errors="replace")
            else:  # iTXt
                if len(remainder) < 2 or remainder[0] not in {0, 1}:
                    return None
                compressed, method, rest = remainder[0], remainder[1], remainder[2:]
                _language, separator, rest = rest.partition(b"\x00")
                if not separator:
                    return None
                _translated, separator, raw = rest.partition(b"\x00")
                if not separator:
                    return None
                if compressed:
                    if method != 0:
                        return None
                    decoder = zlib.decompressobj()
                    raw = decoder.decompress(raw, 65_537)
                    if len(raw) > 65_536 or decoder.unconsumed_tail:
                        return None
                text = raw.decode("utf-8", errors="replace")
        except zlib.error:
            return None
        return {"type": chunk_type.decode("ascii"), "keyword": key[:512], "text": text[:65_536]}

    def _inspect_jpeg(
        self,
        artifact: Artifact,
        path: Path,
        size: int,
        scan: _ScanResult,
    ) -> list[Observation]:
        # EOI is intentionally searched with the same bounded sampling policy.
        regions = _sample_regions(size, self.limits.signature_scan_bytes)
        offsets: list[int] = []
        count = 0
        last_offset: int | None = None
        previous: int | None = None
        scanned = 0
        with path.open("rb") as stream:
            for start, length in regions:
                carry = b""
                consumed = 0
                stream.seek(start)
                remaining = length
                while remaining:
                    chunk = stream.read(min(_MIB, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                    scanned += len(chunk)
                    data = carry + chunk
                    data_offset = start + consumed - len(carry)
                    search_from = 0
                    while True:
                        found = data.find(b"\xff\xd9", search_from)
                        if found < 0:
                            break
                        absolute = data_offset + found
                        if absolute != previous:
                            count += 1
                            last_offset = absolute
                            previous = absolute
                            if len(offsets) < self.max_signature_offsets:
                                offsets.append(absolute)
                        search_from = found + 1
                    carry = data[-1:]
                    consumed += len(chunk)

        bytes_after = size - (last_offset + 2) if last_offset is not None else 0
        trailer_header = b""
        if last_offset is not None and bytes_after:
            with path.open("rb") as stream:
                stream.seek(last_offset + 2)
                trailer_header = stream.read(min(64, bytes_after))
        result = [
            self._observation(artifact, "jpeg.eoi_found", last_offset is not None),
            self._observation(artifact, "jpeg.eoi_offset", last_offset),
            self._observation(artifact, "jpeg.eoi_offsets", offsets),
            self._observation(artifact, "jpeg.eoi_count", count),
            self._observation(artifact, "jpeg.eoi_offsets_truncated", count > len(offsets)),
            self._observation(artifact, "jpeg.eoi_scan_scope", "full" if scanned == size else "sample"),
            self._observation(artifact, "jpeg.bytes_after_eoi", bytes_after),
            self._observation(artifact, "jpeg.trailer.header.hex", trailer_header.hex()),
        ]
        result.extend(self._jpeg_dimension_observations(artifact, path, size))
        return result

    def _inspect_gif(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        try:
            with path.open("rb") as stream:
                data = stream.read(min(size, self.limits.signature_scan_bytes))
        except OSError as exc:
            return [self._observation(artifact, "gif.read_error", str(exc), confidence=0.8)]
        if len(data) < 13 or not data.startswith((b"GIF87a", b"GIF89a")):
            return [self._observation(artifact, "gif.header_valid", False)]
        width = int.from_bytes(data[6:8], "little")
        height = int.from_bytes(data[8:10], "little")
        offset = 13
        packed = data[10]
        if packed & 0x80:
            offset += 3 * (1 << ((packed & 0x07) + 1))
        comments: list[str] = []
        extension_types: list[str] = []
        image_descriptors = 0
        structure_error: str | None = None
        trailer = -1

        def subblocks(start: int, *, capture: bool = False) -> tuple[int, bytes | None, str | None]:
            chunks: list[bytes] = []
            total = 0
            position = start
            for _ in range(4_096):
                if position >= len(data):
                    return position, None, "truncated GIF sub-block length"
                block_size = data[position]
                position += 1
                if block_size == 0:
                    return position, b"".join(chunks) if capture else None, None
                if position + block_size > len(data):
                    return position, None, "truncated GIF sub-block payload"
                if capture and total < 65_536:
                    take = min(block_size, 65_536 - total)
                    chunks.append(data[position:position + take])
                    total += take
                position += block_size
            return position, None, "GIF sub-block count exceeds 4096 cap"

        # Skip only documented block layouts.  The scanner never decodes LZW
        # image payloads, but it does validate their sub-block boundaries so
        # comment extensions and the actual trailer have reliable provenance.
        for _ in range(8_192):
            if offset >= len(data):
                break
            marker = data[offset]
            if marker == 0x3B:
                trailer = offset
                break
            if marker == 0x2C:  # Image Descriptor + optional local palette + LZW blocks.
                image_descriptors += 1
                if offset + 10 > len(data):
                    structure_error = "truncated GIF image descriptor"
                    break
                descriptor_packed = data[offset + 9]
                offset += 10
                if descriptor_packed & 0x80:
                    offset += 3 * (1 << ((descriptor_packed & 0x07) + 1))
                if offset >= len(data):
                    structure_error = "truncated GIF image data code-size"
                    break
                offset, _, structure_error = subblocks(offset + 1)
                if structure_error:
                    break
                continue
            if marker != 0x21 or offset + 2 > len(data):
                structure_error = f"unexpected GIF block marker 0x{marker:02x}"
                break
            label = data[offset + 1]
            label_names = {0xF9: "graphic_control", 0xFE: "comment", 0xFF: "application", 0x01: "plain_text"}
            extension_types.append(label_names.get(label, f"unknown_0x{label:02x}"))
            if label == 0xFE:
                offset, payload, structure_error = subblocks(offset + 2, capture=True)
                if payload is not None:
                    comments.append(payload.decode("utf-8", errors="replace")[:65_536])
                if structure_error:
                    break
                continue
            if label == 0xF9:
                if offset + 3 > len(data):
                    structure_error = "truncated GIF graphic-control extension"
                    break
                block_size = data[offset + 2]
                end = offset + 3 + block_size
                if end >= len(data) or data[end] != 0:
                    structure_error = "invalid GIF graphic-control extension terminator"
                    break
                offset = end + 1
                continue
            if label in {0xFF, 0x01}:
                if offset + 3 > len(data):
                    structure_error = "truncated GIF extension header"
                    break
                fixed_size = data[offset + 2]
                start = offset + 3 + fixed_size
                if start > len(data):
                    structure_error = "truncated GIF extension fixed data"
                    break
                offset, _, structure_error = subblocks(start)
                if structure_error:
                    break
                continue
            structure_error = f"unsupported GIF extension label 0x{label:02x}"
            break
        bytes_after = size - trailer - 1 if trailer >= 0 else 0
        return [
            self._observation(artifact, "gif.header_valid", True),
            self._observation(artifact, "image.width", width),
            self._observation(artifact, "image.height", height),
            self._observation(artifact, "gif.version", data[:6].decode("ascii")),
            self._observation(artifact, "gif.global_color_table", bool(data[10] & 0x80)),
            self._observation(artifact, "gif.image_descriptor_count", image_descriptors),
            self._observation(artifact, "gif.trailer_found", trailer >= 0),
            self._observation(artifact, "gif.bytes_after_trailer", bytes_after),
            self._observation(artifact, "gif.extension_types", extension_types[:1_000]),
            self._observation(artifact, "gif.comments", comments[:100]),
            self._observation(artifact, "gif.structure_error", structure_error, confidence=0.8),
        ]

    def _inspect_bmp(self, artifact: Artifact, header: bytes, size: int) -> list[Observation]:
        if len(header) < 26 or not header.startswith(b"BM"):
            return [self._observation(artifact, "bmp.header_valid", False)]
        declared_size = int.from_bytes(header[2:6], "little")
        pixel_offset = int.from_bytes(header[10:14], "little")
        dib_size = int.from_bytes(header[14:18], "little")
        width = int.from_bytes(header[18:22], "little", signed=True)
        height = int.from_bytes(header[22:26], "little", signed=True)
        return [
            self._observation(artifact, "bmp.header_valid", dib_size >= 12 and pixel_offset < size),
            self._observation(artifact, "bmp.declared_size", declared_size),
            self._observation(artifact, "bmp.pixel_offset", pixel_offset),
            self._observation(artifact, "bmp.dib_header_size", dib_size),
            self._observation(artifact, "image.width", width),
            self._observation(artifact, "image.height", abs(height)),
            self._observation(artifact, "bmp.top_down", height < 0),
            self._observation(artifact, "bmp.size_matches", declared_size == size),
        ]

    def _inspect_tiff(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        """Read first TIFF IFD scalar geometry with fixed entry/count bounds."""
        try:
            with path.open("rb") as stream:
                header = stream.read(8)
                if len(header) != 8 or header[:2] not in {b"II", b"MM"}:
                    return [self._observation(artifact, "tiff.header_valid", False)]
                endian = "little" if header[:2] == b"II" else "big"
                if int.from_bytes(header[2:4], endian) != 42:
                    return [self._observation(artifact, "tiff.header_valid", False)]
                ifd_offset = int.from_bytes(header[4:8], endian)
                if ifd_offset < 8 or ifd_offset + 2 > size:
                    return [self._observation(artifact, "tiff.header_valid", False)]
                stream.seek(ifd_offset)
                entry_count = int.from_bytes(stream.read(2), endian)
                if entry_count > 256 or ifd_offset + 2 + entry_count * 12 + 4 > size:
                    return [self._observation(artifact, "tiff.header_valid", False)]
                raw_entries = stream.read(entry_count * 12)
        except OSError as exc:
            return [self._observation(artifact, "tiff.read_error", str(exc), confidence=0.8)]
        type_sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8}
        tags: dict[str, object] = {}
        tag_names = {256: "width", 257: "height", 258: "bits_per_sample", 259: "compression", 262: "photometric", 273: "strip_offsets", 277: "samples_per_pixel", 278: "rows_per_strip", 279: "strip_byte_counts"}
        for index in range(entry_count):
            entry = raw_entries[index * 12:(index + 1) * 12]
            tag = int.from_bytes(entry[:2], endian)
            field_type = int.from_bytes(entry[2:4], endian)
            count = int.from_bytes(entry[4:8], endian)
            if tag not in tag_names or count == 0 or count > 32 or field_type not in type_sizes:
                continue
            byte_count = count * type_sizes[field_type]
            value_bytes = entry[8:12] if byte_count <= 4 else b""
            if byte_count > 4:
                value_offset = int.from_bytes(entry[8:12], endian)
                if value_offset + byte_count > size:
                    continue
                try:
                    with path.open("rb") as stream:
                        stream.seek(value_offset)
                        value_bytes = stream.read(byte_count)
                except OSError:
                    continue
            values: list[int] = []
            for element in range(count):
                start = element * type_sizes[field_type]
                raw = value_bytes[start:start + type_sizes[field_type]]
                if len(raw) != type_sizes[field_type]:
                    values = []
                    break
                if field_type in {1, 2, 6, 7}:
                    values.append(raw[0])
                elif field_type in {3, 8}:
                    values.append(int.from_bytes(raw, endian, signed=field_type == 8))
                elif field_type in {4, 9}:
                    values.append(int.from_bytes(raw, endian, signed=field_type == 9))
                else:
                    values = []
                    break
            if values:
                tags[tag_names[tag]] = values[0] if len(values) == 1 else values
        return [
            self._observation(artifact, "tiff.header_valid", True),
            self._observation(artifact, "tiff.byte_order", endian),
            self._observation(artifact, "tiff.first_ifd_offset", ifd_offset),
            self._observation(artifact, "tiff.ifd_entry_count", entry_count),
            self._observation(artifact, "tiff.tags", tags),
            self._observation(artifact, "image.width", tags.get("width")),
            self._observation(artifact, "image.height", tags.get("height")),
        ]

    def _jpeg_dimension_observations(self, artifact: Artifact, path: Path, size: int) -> list[Observation]:
        width: int | None = None
        height: int | None = None
        components: int | None = None
        comments: list[str] = []
        app_markers: dict[str, int] = {}
        app_segments: list[dict[str, object]] = []
        xmp_packets: list[dict[str, object]] = []
        icc_chunks: list[dict[str, int]] = []
        exif_entries: list[dict[str, object]] = []
        segment_error: str | None = None
        try:
            with path.open("rb") as stream:
                data = stream.read(min(size, 2 * _MIB))
            offset = 2
            while offset + 9 <= len(data):
                if data[offset] != 0xFF:
                    offset += 1
                    continue
                marker_offset = offset
                while offset < len(data) and data[offset] == 0xFF:
                    offset += 1
                if offset >= len(data):
                    break
                marker = data[offset]
                offset += 1
                if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
                    continue
                if offset + 2 > len(data):
                    break
                length = int.from_bytes(data[offset:offset + 2], "big")
                if length < 2 or offset + length > len(data):
                    segment_error = "JPEG segment exceeds bounded scan" if offset + length > len(data) else "invalid JPEG segment length"
                    break
                segment = data[offset + 2:offset + length]
                if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF} and length >= 8:
                    height = int.from_bytes(data[offset + 3:offset + 5], "big")
                    width = int.from_bytes(data[offset + 5:offset + 7], "big")
                    components = data[offset + 7]
                if 0xE0 <= marker <= 0xEF:
                    label = f"APP{marker - 0xE0}"
                    app_markers[label] = app_markers.get(label, 0) + 1
                    if len(app_segments) < 100:
                        identifier = segment[:64]
                        kind = (
                            "exif" if marker == 0xE1 and identifier.startswith(b"Exif\x00\x00")
                            else "xmp" if marker == 0xE1 and identifier.startswith(b"http://ns.adobe.com/xap/1.0/\x00")
                            else "icc_profile" if marker == 0xE2 and identifier.startswith(b"ICC_PROFILE\x00")
                            else "photoshop_irb" if marker == 0xED and identifier.startswith(b"Photoshop 3.0\x00")
                            else "jfif" if marker == 0xE0 and identifier.startswith(b"JFIF\x00")
                            else "unknown"
                        )
                        app_segments.append({
                            "marker": label, "offset": marker_offset, "length": len(segment), "kind": kind,
                            "identifier_hex": identifier.hex(),
                        })
                        if kind == "xmp" and len(xmp_packets) < 32:
                            xmp_packets.append({
                                "offset": marker_offset,
                                "text": segment[len(b"http://ns.adobe.com/xap/1.0/\x00"):].decode("utf-8", errors="replace")[:65_536],
                            })
                        if kind == "exif" and len(exif_entries) < 32:
                            tags, exif_error = self._jpeg_exif_tiff_tags(segment[6:])
                            exif_entries.append({"offset": marker_offset, "tags": tags, "error": exif_error})
                        if kind == "icc_profile" and len(icc_chunks) < 100:
                            icc_chunks.append({
                                "offset": marker_offset,
                                "sequence": segment[12] if len(segment) >= 13 else 0,
                                "count": segment[13] if len(segment) >= 14 else 0,
                                "payload_length": max(0, len(segment) - 14),
                            })
                elif marker == 0xFE and len(comments) < 100:
                    text = segment.decode("latin-1", errors="replace").strip()
                    if text:
                        comments.append(text[:4_000])
                if marker == 0xDA:  # Start Of Scan: following bytes are entropy-coded image data.
                    break
                offset += length
        except OSError:
            pass
        return [
            self._observation(artifact, "image.width", width),
            self._observation(artifact, "image.height", height),
            self._observation(artifact, "jpeg.component_count", components),
            self._observation(artifact, "jpeg.app_marker_counts", app_markers),
            self._observation(artifact, "jpeg.app_segments", app_segments),
            self._observation(artifact, "jpeg.xmp_packets", xmp_packets),
            self._observation(artifact, "jpeg.exif_entries", exif_entries),
            self._observation(artifact, "jpeg.icc_profile_chunks", icc_chunks),
            self._observation(artifact, "jpeg.icc_profile_valid", self._jpeg_icc_profile_error(icc_chunks) is None if icc_chunks else None),
            self._observation(artifact, "jpeg.icc_profile_error", self._jpeg_icc_profile_error(icc_chunks)),
            self._observation(artifact, "jpeg.comments", comments),
            self._observation(artifact, "jpeg.segment_scan_error", segment_error),
        ]

    @staticmethod
    def _jpeg_icc_profile_error(chunks: list[dict[str, int]]) -> str | None:
        if not chunks:
            return None
        counts = {item.get("count") for item in chunks}
        if len(counts) != 1:
            return "ICC_PROFILE chunks disagree on declared chunk count"
        count = next(iter(counts))
        if not isinstance(count, int) or count <= 0 or count > 100:
            return "ICC_PROFILE declared chunk count is outside 1..100"
        sequences = [item.get("sequence") for item in chunks]
        if any(not isinstance(sequence, int) or sequence <= 0 or sequence > count for sequence in sequences):
            return "ICC_PROFILE chunk sequence is outside declared bounds"
        if len(set(sequences)) != len(sequences):
            return "ICC_PROFILE contains duplicate chunk sequence numbers"
        if len(chunks) != count or set(sequences) != set(range(1, count + 1)):
            return "ICC_PROFILE chunk sequence is incomplete"
        return None

    @staticmethod
    def _jpeg_exif_tiff_tags(payload: bytes) -> tuple[dict[str, object], str | None]:
        if len(payload) < 8 or payload[:2] not in {b"II", b"MM"}:
            return {}, "EXIF TIFF header is missing or has invalid byte order"
        endian = "little" if payload[:2] == b"II" else "big"
        if int.from_bytes(payload[2:4], endian) != 42:
            return {}, "EXIF TIFF magic is invalid"
        ifd = int.from_bytes(payload[4:8], endian)
        if ifd < 8 or ifd + 2 > len(payload):
            return {}, "EXIF TIFF first IFD offset exceeds APP1 payload"
        count = int.from_bytes(payload[ifd:ifd + 2], endian)
        if count > 128 or ifd + 2 + count * 12 + 4 > len(payload):
            return {}, "EXIF TIFF first IFD entry bounds are invalid"
        names = {0x010F: "make", 0x0110: "model", 0x0112: "orientation", 0x0131: "software", 0x0132: "datetime"}
        tags: dict[str, object] = {}
        sizes = {2: 1, 3: 2, 4: 4}
        for index in range(count):
            entry = payload[ifd + 2 + index * 12:ifd + 14 + index * 12]
            tag, field_type, values = int.from_bytes(entry[:2], endian), int.from_bytes(entry[2:4], endian), int.from_bytes(entry[4:8], endian)
            if tag not in names or field_type not in sizes or values <= 0 or values > 512:
                continue
            byte_count = values * sizes[field_type]
            raw = entry[8:8 + byte_count] if byte_count <= 4 else payload[int.from_bytes(entry[8:12], endian):int.from_bytes(entry[8:12], endian) + byte_count]
            if len(raw) != byte_count:
                continue
            if field_type == 2:
                tags[names[tag]] = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")[:512]
            elif values == 1:
                tags[names[tag]] = int.from_bytes(raw, endian)
        return tags, None

    def _inspect_zip_headers(
        self,
        artifact: Artifact,
        path: Path,
        size: int,
        scan: _ScanResult,
    ) -> list[Observation]:
        names: list[str] = []
        encrypted = 0
        inspected = 0
        compression_methods: set[int] = set()
        declared_compressed = 0
        declared_uncompressed = 0

        with path.open("rb") as stream:
            for offset in scan.offsets.get("zip_local", []):
                if offset + 30 > size:
                    continue
                stream.seek(offset)
                fixed = stream.read(30)
                if len(fixed) != 30 or fixed[:4] != b"PK\x03\x04":
                    continue
                try:
                    (
                        _version,
                        flags,
                        method,
                        _mtime,
                        _mdate,
                        _crc,
                        compressed,
                        uncompressed,
                        name_length,
                        extra_length,
                    ) = struct.unpack("<HHHHHIIIHH", fixed[4:])
                except struct.error:
                    continue
                if name_length > 4096 or offset + 30 + name_length + extra_length > size:
                    continue
                raw_name = stream.read(name_length)
                encoding = "utf-8" if flags & 0x0800 else "cp437"
                name = raw_name.decode(encoding, errors="replace")
                inspected += 1
                if len(names) < 128:
                    names.append(name)
                if flags & 0x0001:
                    encrypted += 1
                compression_methods.add(method)
                declared_compressed += compressed
                declared_uncompressed += uncompressed

        lowered = {name.replace("\\", "/").lower() for name in names}
        ooxml_kind: str | None = None
        if "[content_types].xml" in lowered:
            if any(name.startswith("word/") for name in lowered):
                ooxml_kind = "docx"
            elif any(name.startswith("xl/") for name in lowered):
                ooxml_kind = "xlsx"
            elif any(name.startswith("ppt/") for name in lowered):
                ooxml_kind = "pptx"
            else:
                ooxml_kind = "ooxml"
        container_kind: str | None = None
        if "androidmanifest.xml" in lowered and "classes.dex" in lowered:
            container_kind = "apk"
        elif "meta-inf/manifest.mf" in lowered:
            container_kind = "jar"
        elif ooxml_kind:
            container_kind = ooxml_kind

        return [
            self._observation(artifact, "archive.zip.local_header_count", scan.counts.get("zip_local", 0)),
            self._observation(artifact, "archive.zip.central_header_count", scan.counts.get("zip_central", 0)),
            self._observation(artifact, "archive.zip.eocd_count", scan.counts.get("zip_eocd", 0)),
            self._observation(artifact, "archive.zip.entries_inspected", inspected),
            self._observation(artifact, "archive.zip.entry_names", names),
            self._observation(artifact, "archive.zip.entry_names_truncated", inspected > len(names)),
            self._observation(artifact, "archive.zip.encrypted_entries", encrypted),
            self._observation(artifact, "archive.zip.compression_methods", sorted(compression_methods)),
            self._observation(artifact, "archive.zip.declared_compressed_bytes", declared_compressed),
            self._observation(artifact, "archive.zip.declared_uncompressed_bytes", declared_uncompressed),
            self._observation(artifact, "archive.zip.ooxml_kind", ooxml_kind),
            self._observation(artifact, "archive.container_kind", container_kind),
        ]

    def _inspect_gzip_header(
        self, artifact: Artifact, header: bytes
    ) -> list[Observation]:
        valid = len(header) >= 10 and header[:3] == b"\x1f\x8b\x08"
        flags = header[3] if valid else None
        original_name: str | None = None
        comment: str | None = None
        header_complete = valid
        if valid:
            offset = 10
            if flags & 0x04:  # FEXTRA
                if offset + 2 > len(header):
                    header_complete = False
                else:
                    extra_size = int.from_bytes(header[offset:offset + 2], "little")
                    offset += 2 + extra_size
                    if offset > len(header):
                        header_complete = False
            def nul_field() -> str | None:
                nonlocal offset, header_complete
                end = header.find(b"\x00", offset)
                if end < 0:
                    header_complete = False
                    return None
                value = header[offset:end].decode("latin-1", errors="replace")[:2_000]
                offset = end + 1
                return value
            if header_complete and flags & 0x08:
                original_name = nul_field()
            if header_complete and flags & 0x10:
                comment = nul_field()
            if header_complete and flags & 0x02 and offset + 2 > len(header):
                header_complete = False
        os_names = {
            0: "fat", 3: "unix", 7: "macintosh", 11: "ntfs", 13: "acorn_riscos", 255: "unknown",
        }
        return [
            self._observation(artifact, "archive.gzip.valid_header", valid),
            self._observation(artifact, "archive.gzip.flags", flags),
            self._observation(artifact, "archive.gzip.mtime", int.from_bytes(header[4:8], "little") if valid else None),
            self._observation(artifact, "archive.gzip.xfl", header[8] if valid else None),
            self._observation(artifact, "archive.gzip.os", os_names.get(header[9], f"unknown_{header[9]}") if valid else None),
            self._observation(
                artifact,
                "archive.gzip.has_original_name",
                bool(flags is not None and flags & 0x08),
            ),
            self._observation(artifact, "archive.gzip.original_name", original_name),
            self._observation(artifact, "archive.gzip.comment", comment),
            self._observation(artifact, "archive.gzip.header_complete", header_complete),
        ]

    def _inspect_pe_header(
        self, artifact: Artifact, path: Path, header: bytes, size: int
    ) -> list[Observation]:
        pe_offset: int | None = None
        if len(header) >= 0x40:
            pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        valid = _valid_pe_signature(path, header, size)
        observations = [
            self._observation(artifact, "executable.dos_mz", True),
            self._observation(artifact, "executable.pe_header_offset", pe_offset),
            self._observation(artifact, "executable.pe.valid_signature", valid),
        ]
        if not valid or pe_offset is None:
            return observations
        try:
            with path.open("rb") as stream:
                stream.seek(pe_offset + 4)
                coff = stream.read(20)
                if len(coff) != 20:
                    return observations
                machine, sections, timestamp, _pointer, _symbols, optional_size, characteristics = struct.unpack("<HHIIIHH", coff)
                optional = stream.read(min(optional_size, 1024))
                section_table = pe_offset + 24 + optional_size
                section_records: list[dict[str, object]] = []
                for index in range(min(sections, 96)):
                    stream.seek(section_table + index * 40)
                    item = stream.read(40)
                    if len(item) != 40:
                        break
                    name = item[:8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                    virtual_size, virtual_address, raw_size, raw_offset, _reloc, _line, _nreloc, _nline, flags = struct.unpack("<IIIIIIHHI", item[8:])
                    section_records.append({
                        "name": name,
                        "virtual_address": virtual_address,
                        "virtual_size": virtual_size,
                        "raw_offset": raw_offset,
                        "raw_size": raw_size,
                        "executable": bool(flags & 0x20000000),
                        "writable": bool(flags & 0x80000000),
                        "within_image": raw_offset + raw_size <= size,
                    })
                optional_magic = int.from_bytes(optional[:2], "little") if len(optional) >= 2 else None
                data_directory_offset = 96 if optional_magic == 0x10B else 112 if optional_magic == 0x20B else None
                imports: list[str] = []
                import_directory_valid = False
                if data_directory_offset is not None and len(optional) >= data_directory_offset + 16:
                    import_rva, import_size = struct.unpack_from("<II", optional, data_directory_offset + 8)
                    def rva_to_offset(rva: int) -> int | None:
                        for section in section_records:
                            start = int(section["virtual_address"])
                            span = max(int(section["virtual_size"]), int(section["raw_size"]))
                            if start <= rva < start + span:
                                candidate = int(section["raw_offset"]) + rva - start
                                return candidate if candidate < size else None
                        return rva if rva < size else None
                    descriptor_offset = rva_to_offset(import_rva) if import_rva else None
                    if descriptor_offset is not None and import_size <= 16 * _MIB:
                        import_directory_valid = True
                        for index in range(min(256, import_size // 20 if import_size else 256)):
                            stream.seek(descriptor_offset + index * 20)
                            descriptor = stream.read(20)
                            if len(descriptor) != 20:
                                import_directory_valid = False
                                break
                            if descriptor == b"\x00" * 20:
                                break
                            name_rva = int.from_bytes(descriptor[12:16], "little")
                            name_offset = rva_to_offset(name_rva)
                            if name_offset is None:
                                import_directory_valid = False
                                continue
                            stream.seek(name_offset)
                            name = stream.read(260).split(b"\x00", 1)[0].decode("ascii", errors="replace")
                            if name:
                                imports.append(name[:260])
        except OSError:
            return observations
        machine_names = {0x014C: "x86", 0x8664: "x64", 0x01C0: "arm", 0xAA64: "arm64"}
        optional_magic = int.from_bytes(optional[:2], "little") if len(optional) >= 2 else None
        observations.extend((
            self._observation(artifact, "executable.pe.machine", machine_names.get(machine, f"0x{machine:04x}")),
            self._observation(artifact, "executable.pe.coff_timestamp", timestamp),
            self._observation(artifact, "executable.pe.section_count", sections),
            self._observation(artifact, "executable.pe.optional_magic", f"0x{optional_magic:04x}" if optional_magic is not None else None),
            self._observation(artifact, "executable.pe.characteristics", f"0x{characteristics:04x}"),
            self._observation(artifact, "executable.pe.sections", section_records),
            self._observation(artifact, "executable.pe.section_layout_valid", all(bool(item["within_image"]) for item in section_records) and len(section_records) == min(sections, 96)),
            self._observation(artifact, "executable.pe.import_directory_valid", import_directory_valid),
            self._observation(artifact, "executable.pe.imports", imports),
        ))
        return observations

    def _inspect_elf_header(
        self, artifact: Artifact, path: Path, header: bytes, size: int
    ) -> list[Observation]:
        if len(header) < 20 or not header.startswith(b"\x7fELF"):
            return [self._observation(artifact, "executable.elf.header_valid", False)]
        elf_class = header[4]
        data_encoding = header[5]
        if elf_class not in {1, 2} or data_encoding not in {1, 2}:
            return [self._observation(artifact, "executable.elf.header_valid", False)]
        endian = "<" if data_encoding == 1 else ">"
        try:
            with path.open("rb") as stream:
                raw = stream.read(64 if elf_class == 2 else 52)
            if elf_class == 1:
                values = struct.unpack(endian + "16sHHIIIIIHHHHHH", raw[:52])
                _ident, file_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = values
            else:
                values = struct.unpack(endian + "16sHHIQQQIHHHHHH", raw[:64])
                _ident, file_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = values
        except (OSError, struct.error):
            return [self._observation(artifact, "executable.elf.header_valid", False)]
        machine_names = {3: "x86", 40: "arm", 62: "x64", 183: "arm64"}
        type_names = {1: "relocatable", 2: "executable", 3: "shared_object", 4: "core"}
        minimum_phentsize = 56 if elf_class == 2 else 32
        program_table_valid = (
            phnum <= 256
            and phentsize >= minimum_phentsize
            and (phnum == 0 or phoff + phentsize * phnum <= size)
        )
        valid = ehsize == (64 if elf_class == 2 else 52) and phoff <= size and shoff <= size and program_table_valid
        program_headers: list[dict[str, object]] = []
        interpreter: str | None = None
        if valid and phnum:
            header_names = {
                1: "load", 2: "dynamic", 3: "interpreter", 4: "note", 6: "program_header",
                0x6474E551: "gnu_stack", 0x6474E552: "gnu_relro",
            }
            try:
                with path.open("rb") as stream:
                    for index in range(phnum):
                        stream.seek(phoff + index * phentsize)
                        raw_program = stream.read(phentsize)
                        if len(raw_program) < minimum_phentsize:
                            program_table_valid = False
                            break
                        if elf_class == 1:
                            program_type, file_offset, virtual_address, _physical_address, file_size, memory_size, permissions, alignment = struct.unpack(
                                endian + "IIIIIIII", raw_program[:32]
                            )
                        else:
                            program_type, permissions, file_offset, virtual_address, _physical_address, file_size, memory_size, alignment = struct.unpack(
                                endian + "IIQQQQQQ", raw_program[:56]
                            )
                        record = {
                            "index": index,
                            "type": header_names.get(program_type, f"0x{program_type:x}"),
                            "offset": file_offset,
                            "virtual_address": virtual_address,
                            "file_size": file_size,
                            "memory_size": memory_size,
                            "readable": bool(permissions & 4),
                            "writable": bool(permissions & 2),
                            "executable": bool(permissions & 1),
                            "within_image": file_offset + file_size <= size,
                            "alignment": alignment,
                        }
                        program_headers.append(record)
                        if program_type == 3 and interpreter is None and 0 < file_size <= 4_096 and file_offset + file_size <= size:
                            stream.seek(file_offset)
                            interpreter = stream.read(file_size).split(b"\x00", 1)[0].decode("utf-8", errors="replace")[:2_000]
            except (OSError, struct.error):
                program_table_valid = False
        return [
            self._observation(artifact, "executable.elf.header_valid", valid and program_table_valid),
            self._observation(artifact, "executable.elf.class", 64 if elf_class == 2 else 32),
            self._observation(artifact, "executable.elf.endianness", "little" if endian == "<" else "big"),
            self._observation(artifact, "executable.elf.type", type_names.get(file_type, f"0x{file_type:04x}")),
            self._observation(artifact, "executable.elf.machine", machine_names.get(machine, f"0x{machine:04x}")),
            self._observation(artifact, "executable.elf.entry_point", entry),
            self._observation(artifact, "executable.elf.program_header_count", phnum),
            self._observation(artifact, "executable.elf.section_header_count", shnum),
            self._observation(artifact, "executable.elf.program_header_layout_valid", program_table_valid),
            self._observation(artifact, "executable.elf.program_headers", program_headers),
            self._observation(artifact, "executable.elf.interpreter", interpreter),
        ]


# Short public name retained for callers that do not need to distinguish the
# generic engine from later profile-specific triage engines.
TriageEngine = GenericTriageEngine


def _format_from_header_bytes(header: bytes) -> str | None:
    if len(header) >= 11 and header[3:11] == b"EXFAT   ":
        return "exfat"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if header.startswith(b"BM"):
        return "bmp"
    if header.startswith((b"II\x2a\x00", b"MM\x00\x2a")):
        return "tiff"
    if header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if header.startswith(b"\x1f\x8b\x08"):
        return "gzip"
    if header.startswith(b"%PDF-"):
        return "pdf"
    if header.startswith(
        (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    ):
        return "pcap"
    if header.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng"
    if header.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if header.startswith(b"ANDROID BACKUP\n"):
        return "android_backup"
    if header.startswith(b"bplist00"):
        return "plist"
    if header.startswith(b"hsqs"):
        return "squashfs"
    if header.startswith(b"\x27\x05\x19\x56"):
        return "uimage"
    if header.startswith(b"ANDROID!"):
        return "android_boot"
    if header.startswith(b"ElfFile\x00"):
        return "evtx"
    if header.startswith(b"regf"):
        return "registry"
    if len(header) >= 20 and int.from_bytes(header[:4], "little") == 0x4C and header[4:20] == bytes.fromhex("0114020000000000C000000000000046"):
        return "lnk"
    if len(header) >= 8 and header[4:8] == b"SCCA":
        return "prefetch"
    if header.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
        return "ewf"
    if header.startswith((b"hibr", b"PAGE", b"MDMP")):
        return "memory"
    if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if header.startswith(b"\x7fELF"):
        return "elf"
    if header.startswith(b"MZ"):
        return "pe"
    if header.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    if header.startswith((b"070701", b"070702", b"070707")):
        return "cpio"
    if header.startswith(b"BZh"):
        return "bzip2"
    if header.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    return None


def _valid_pe_signature(path: Path, header: bytes, size: int) -> bool:
    if not header.startswith(b"MZ") or len(header) < 0x40:
        return False
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    # A very remote PE header is more likely a malicious/corrupt offset. This
    # cap also prevents pointless seeks on sparse multi-terabyte evidence.
    if pe_offset < 0x40 or pe_offset > min(size - 4, 16 * _MIB):
        return False
    with path.open("rb") as stream:
        stream.seek(pe_offset)
        return stream.read(4) == b"PE\x00\x00"


def _sample_regions(size: int, limit: int) -> list[tuple[int, int]]:
    if size <= 0:
        return []
    if size <= limit:
        return [(0, size)]
    part_lengths = [limit // 3, limit // 3, limit - 2 * (limit // 3)]
    starts = [0, max(0, (size - part_lengths[1]) // 2), size - part_lengths[2]]
    raw = sorted(
        (start, length)
        for start, length in zip(starts, part_lengths, strict=True)
        if length
    )
    merged: list[tuple[int, int]] = []
    for start, length in raw:
        end = min(size, start + length)
        if merged and start <= merged[-1][0] + merged[-1][1]:
            previous_start, previous_length = merged[-1]
            previous_end = previous_start + previous_length
            merged[-1] = (previous_start, max(previous_end, end) - previous_start)
        else:
            merged.append((start, end - start))
    return merged


def _iter_region_chunks(
    stream: BinaryIO, regions: list[tuple[int, int]], chunk_size: int = _MIB
) -> Iterator[tuple[bytes, int]]:
    for start, length in regions:
        stream.seek(start)
        remaining = length
        offset = start
        while remaining:
            chunk = stream.read(min(chunk_size, remaining))
            if not chunk:
                break
            yield chunk, offset
            offset += len(chunk)
            remaining -= len(chunk)


def _is_printable_ascii(value: int) -> bool:
    return 32 <= value <= 126


def _is_utf16_ascii_pair(data: bytes, index: int, little_endian: bool) -> bool:
    if little_endian:
        return _is_printable_ascii(data[index]) and data[index + 1] == 0
    return data[index] == 0 and _is_printable_ascii(data[index + 1])
