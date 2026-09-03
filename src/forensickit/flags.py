from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import io
import re
import urllib.parse
import zlib
from dataclasses import dataclass
from pathlib import Path

from .models import Artifact, FlagCandidate


@dataclass(frozen=True, slots=True)
class DecodedRegion:
    data: bytes
    chain: tuple[str, ...]
    source_location: str


class FlagHunter:
    """Bounded, evidence-driven flag search with auditable transform chains."""

    PRINTABLE = re.compile(rb"[\x20-\x7e]{8,4096}")
    BASE64 = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,4092}={0,2}(?![A-Za-z0-9+/=])")
    BASE32 = re.compile(rb"(?<![A-Z2-7=])[A-Z2-7]{8,4090}={0,6}(?![A-Z2-7=])")
    HEX = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,2048}(?![0-9A-Fa-f])")

    def __init__(self, patterns: list[str], max_scan_bytes: int = 64 * 1024 * 1024) -> None:
        self.patterns = [re.compile(pattern) for pattern in patterns]
        self.max_scan_bytes = max_scan_bytes

    def scan(self, path: Path, artifact: Artifact) -> list[FlagCandidate]:
        with path.open("rb") as stream:
            raw = stream.read(self.max_scan_bytes + 1)
        truncated = len(raw) > self.max_scan_bytes
        return self.scan_bytes(raw[: self.max_scan_bytes], artifact, truncated=truncated)

    def scan_bytes(
        self,
        raw: bytes,
        artifact: Artifact,
        *,
        source: str = "flag_hunter",
        location_prefix: str = "byte range 0..scan-limit",
        truncated: bool = False,
    ) -> list[FlagCandidate]:
        """Scan bounded derived bytes, including preserved tool output.

        Callers must enforce the byte cap before invoking this method.  Keeping
        the transform engine here rather than adding tool-specific regexes
        makes flags from pdf text, memory output, and other offline parsers
        follow the same deterministic evidence chain as raw artifacts.
        """
        raw = raw[: self.max_scan_bytes]
        regions = [DecodedRegion(raw, ("raw",), location_prefix)]
        compressed = self._whole_file_compression(raw)
        regions.extend(compressed)
        encoded = self._encoded_regions(raw)
        for region in compressed:
            encoded.extend(self._encoded_regions(region.data, chain=region.chain, location=region.source_location))
        regions.extend(encoded)
        # A single evidence-led follow-up transform catches common CTF chains
        # such as Base64(gzip(flag)) without recursively brute-forcing text.
        regions.extend(self._compressed_regions(encoded))

        candidates: list[FlagCandidate] = []
        seen: set[tuple[str, tuple[str, ...], str]] = set()
        for region in regions:
            for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
                try:
                    text = region.data.decode(encoding, errors="ignore")
                except (LookupError, UnicodeError):
                    continue
                for pattern in self.patterns:
                    for match in pattern.finditer(text):
                        value = match.group(0)
                        location = region.source_location
                        if region.chain == ("raw",) and encoding == "utf-8":
                            location = f"{location_prefix}; character offset {match.start()}" + (" (scan truncated)" if truncated else "")
                        chain = region.chain + ((encoding,) if encoding != "utf-8" else ())
                        key = (value, chain, location)
                        if key in seen:
                            continue
                        seen.add(key)
                        candidates.append(
                            FlagCandidate(
                                artifact_id=artifact.id,
                                value=value,
                                transform_chain=list(chain),
                                source=source,
                                location=location,
                                confidence=0.98 if chain == ("raw",) else 0.9,
                            )
                        )
        return candidates

    def _encoded_regions(
        self,
        raw: bytes,
        *,
        chain: tuple[str, ...] = ("raw",),
        location: str = "byte offset",
    ) -> list[DecodedRegion]:
        decoded: list[DecodedRegion] = []
        for match in self.BASE64.finditer(raw):
            blob = match.group(0)
            if len(blob) % 4:
                continue
            try:
                value = base64.b64decode(blob, validate=True)
            except (ValueError, binascii.Error):
                continue
            if self._potentially_interesting(value):
                decoded.append(DecodedRegion(value, (*chain, "base64"), f"{location} {match.start()}"))
        for match in self.BASE32.finditer(raw):
            blob = match.group(0)
            if len(blob) % 8:
                continue
            try:
                value = base64.b32decode(blob, casefold=False)
            except (ValueError, binascii.Error):
                continue
            if self._potentially_interesting(value):
                decoded.append(DecodedRegion(value, (*chain, "base32"), f"{location} {match.start()}"))
        for match in self.HEX.finditer(raw):
            try:
                value = bytes.fromhex(match.group(0).decode("ascii"))
            except ValueError:
                continue
            if self._potentially_interesting(value):
                decoded.append(DecodedRegion(value, (*chain, "hex"), f"{location} {match.start()}"))
        for match in self.PRINTABLE.finditer(raw):
            blob = match.group(0)
            if b"%" in blob:
                value = urllib.parse.unquote_to_bytes(blob.decode("ascii", errors="ignore"))
                if value != blob and self._potentially_interesting(value):
                    decoded.append(DecodedRegion(value, (*chain, "url_decode"), f"{location} {match.start()}"))
            text = blob.decode("ascii", errors="ignore")
            rotated = codecs.decode(text, "rot_13").encode()
            if rotated != blob and self._potentially_interesting(rotated):
                decoded.append(DecodedRegion(rotated, (*chain, "rot13"), f"{location} {match.start()}"))
        return decoded[:2_000]

    def _whole_file_compression(self, raw: bytes) -> list[DecodedRegion]:
        results: list[DecodedRegion] = []
        if raw.startswith(b"\x1f\x8b"):
            value = self._bounded_gzip(raw)
            if value is not None:
                results.append(DecodedRegion(value, ("raw", "gzip"), "whole artifact"))
        if len(raw) >= 2 and raw[0] == 0x78:
            value = self._bounded_zlib(raw)
            if value is not None:
                results.append(DecodedRegion(value, ("raw", "zlib"), "whole artifact"))
        return results

    def _compressed_regions(self, regions: list[DecodedRegion]) -> list[DecodedRegion]:
        results: list[DecodedRegion] = []
        for region in regions[:2_000]:
            value: bytes | None = None
            transform: str | None = None
            if region.data.startswith(b"\x1f\x8b"):
                value, transform = self._bounded_gzip(region.data), "gzip"
            elif len(region.data) >= 2 and region.data[0] == 0x78:
                value, transform = self._bounded_zlib(region.data), "zlib"
            if value is not None and transform is not None:
                results.append(DecodedRegion(value, (*region.chain, transform), region.source_location))
        return results[:1_000]

    def _bounded_gzip(self, payload: bytes) -> bytes | None:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as stream:
                value = stream.read(self.max_scan_bytes + 1)
            return value if len(value) <= self.max_scan_bytes else None
        except (OSError, EOFError):
            return None

    def _bounded_zlib(self, payload: bytes) -> bytes | None:
        try:
            decoder = zlib.decompressobj()
            value = decoder.decompress(payload, self.max_scan_bytes + 1)
            if len(value) > self.max_scan_bytes or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof:
                return None
            tail = decoder.flush()
            return value + tail if len(value) + len(tail) <= self.max_scan_bytes else None
        except zlib.error:
            return None

    def _potentially_interesting(self, value: bytes) -> bool:
        if not value or len(value) > self.max_scan_bytes:
            return False
        if value.startswith(b"\x1f\x8b") or (len(value) >= 2 and value[0] == 0x78):
            return True
        text = value.decode("utf-8", errors="ignore")
        return any(pattern.search(text) for pattern in self.patterns) or bool(self.PRINTABLE.search(value))
