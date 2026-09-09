from __future__ import annotations

import base64
import binascii
import codecs
from contextlib import contextmanager
from dataclasses import dataclass, field
import gzip
import hashlib
import io
from pathlib import Path
import re
import signal
import threading
import time
from typing import Iterator
import urllib.parse
import zlib

from .models import Artifact, FlagCandidate, SearchHit


class UnsafeRegexError(ValueError):
    """Raised when a user pattern cannot be executed with bounded risk."""


class _RegexDeadline(TimeoutError):
    pass


@dataclass(frozen=True, slots=True)
class DecodedRegion:
    data: bytes
    chain: tuple[str, ...]
    source_location: str
    source_offset: int | None = None
    source_end: int | None = None
    derived: bool = False
    ancestor_hashes: frozenset[str] = frozenset()


@dataclass(slots=True)
class SearchScanResult:
    flags: list[FlagCandidate] = field(default_factory=list)
    hits: list[SearchHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_bytes: int = 0
    truncated: bool = False


@dataclass(slots=True)
class _DecodeBudget:
    artifacts: int = 0
    decoded_bytes: int = 0
    seen: set[tuple[str, int | None, int | None, tuple[str, ...]]] = field(default_factory=set)


class FlagHunter:
    """Chunked, transform-aware offline flag and clue search.

    ``max_match_length`` is a character limit. File windows overlap by four
    times that value (at least 8 KiB) so UTF-8/UTF-16 and encoded candidates
    can cross a chunk boundary. Matches longer than the declared limit are
    intentionally not reported. Derived offsets are never presented as
    original evidence offsets; the encoded source range is retained instead.
    """

    PRINTABLE = re.compile(rb"[\x20-\x7e]{4,16384}")
    BASE64 = re.compile(rb"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,16380}={0,2}(?![A-Za-z0-9+/=])")
    BASE32 = re.compile(rb"(?<![A-Z2-7=])[A-Z2-7]{8,16376}={0,6}(?![A-Z2-7=])")
    HEX = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,8192}(?![0-9A-Fa-f])")

    def __init__(
        self,
        patterns: list[str],
        max_scan_bytes: int = 64 * 1024 * 1024,
        *,
        flag_prefixes: list[str] | None = None,
        exact_strings: list[str] | None = None,
        regex_patterns: list[str] | None = None,
        search_terms: list[str] | None = None,
        chunk_size: int = 1024 * 1024,
        max_match_length: int = 4_096,
        decode_depth: int = 3,
        max_decode_artifacts: int = 2_000,
        max_decoded_bytes: int = 64 * 1024 * 1024,
        scan_timeout: float = 20.0,
        regex_timeout: float = 0.1,
    ) -> None:
        if min(
            max_scan_bytes, chunk_size, max_match_length, decode_depth,
            max_decode_artifacts, max_decoded_bytes,
        ) <= 0 or scan_timeout <= 0 or regex_timeout <= 0:
            raise ValueError("flag-search limits must be positive")
        self.max_scan_bytes = int(max_scan_bytes)
        self.chunk_size = int(chunk_size)
        self.max_match_length = int(max_match_length)
        self.decode_depth = int(decode_depth)
        self.max_decode_artifacts = int(max_decode_artifacts)
        self.max_decoded_bytes = int(max_decoded_bytes)
        self.scan_timeout = float(scan_timeout)
        self.regex_timeout = float(regex_timeout)
        self.exact_strings = self._bounded_queries(exact_strings or [], "exact string")
        self.search_terms = self._bounded_queries(search_terms or [], "search term")

        prefix_patterns: list[str] = []
        for raw_prefix in flag_prefixes or []:
            prefix = raw_prefix.strip()
            if prefix.endswith("{"):
                prefix = prefix[:-1]
            if (
                not prefix or len(prefix) > 128
                or any(ord(character) < 0x20 for character in prefix)
            ):
                raise ValueError(f"invalid flag prefix: {raw_prefix!r}")
            prefix_patterns.append(
                rf"{re.escape(prefix)}\{{[^\r\n\x00]{{1,{min(512, self.max_match_length)}}}\}}"
            )
        self.flag_patterns = [
            (pattern, self._compile_safe(pattern))
            for pattern in dict.fromkeys([*patterns, *prefix_patterns])
        ]
        self.user_regex_patterns = [
            (pattern, self._compile_safe(pattern))
            for pattern in dict.fromkeys(regex_patterns or [])
        ]

    def scan(
        self,
        path: Path,
        artifact: Artifact,
        *,
        source: str = "flag_hunter",
        location_prefix: str | None = None,
        source_kind: str | None = None,
        discovered_path: str | None = None,
    ) -> list[FlagCandidate]:
        return self.scan_all(
            path, artifact, source=source, location_prefix=location_prefix,
            source_kind=source_kind, discovered_path=discovered_path,
        ).flags

    def scan_all(
        self,
        path: Path,
        artifact: Artifact,
        *,
        source: str = "flag_hunter",
        location_prefix: str | None = None,
        source_kind: str | None = None,
        discovered_path: str | None = None,
        include_filename: bool = True,
    ) -> SearchScanResult:
        """Scan a file without loading the configured scan range into RAM."""
        result = SearchScanResult()
        deadline = time.monotonic() + self.scan_timeout
        overlap = min(
            max(8_192, self.max_match_length * 4),
            max(1, self.chunk_size // 2),
        )
        prefix = location_prefix or f"file {artifact.logical_name}"
        kind = source_kind or (
            "extracted_evidence" if artifact.parent_id is not None else "original_evidence"
        )
        found_path = discovered_path or artifact.path
        carry = b""
        consumed = 0
        decode_budget = _DecodeBudget()
        try:
            with path.open("rb") as stream:
                while consumed < self.max_scan_bytes:
                    if time.monotonic() >= deadline:
                        result.truncated = True
                        result.warnings.append(
                            f"flag search time limit reached after {consumed} bytes"
                        )
                        break
                    chunk = stream.read(min(self.chunk_size, self.max_scan_bytes - consumed))
                    if not chunk:
                        break
                    window = carry + chunk
                    window_start = consumed - len(carry)
                    accept_after = consumed if consumed else window_start
                    partial = self._search_buffer(
                        window, artifact, source=source, location_prefix=prefix,
                        source_kind=kind, discovered_path=found_path,
                        base_offset=window_start, file_offsets=True,
                        deadline=deadline, decode_budget=decode_budget,
                    )
                    self._accept_window(result, partial, accept_after)
                    consumed += len(chunk)
                    carry = window[-overlap:]
                if stream.read(1):
                    result.truncated = True
                    result.warnings.append(
                        f"flag search byte limit reached ({self.max_scan_bytes} bytes)"
                    )
        except OSError as exc:
            result.warnings.append(f"flag search could not read {path}: {exc}")
        result.scanned_bytes = consumed
        if include_filename:
            name_result = self.scan_bytes_all(
                artifact.logical_name.encode("utf-8", errors="replace"), artifact,
                source=f"{source}:filename", location_prefix="artifact filename",
                source_kind="filename", discovered_path=found_path,
                allow_transforms=False,
            )
            result.flags.extend(name_result.flags)
            result.hits.extend(name_result.hits)
            result.warnings.extend(name_result.warnings)
        result.flags = self._group_flags(result.flags)
        result.hits = self._group_hits(result.hits)
        return result

    def scan_bytes(
        self,
        raw: bytes,
        artifact: Artifact,
        *,
        source: str = "flag_hunter",
        location_prefix: str = "byte range 0..scan-limit",
        truncated: bool = False,
        source_kind: str = "derived_record",
        discovered_path: str | None = None,
    ) -> list[FlagCandidate]:
        """Compatibility wrapper returning only flag candidates."""
        return self.scan_bytes_all(
            raw, artifact, source=source, location_prefix=location_prefix,
            truncated=truncated, source_kind=source_kind,
            discovered_path=discovered_path,
        ).flags

    def scan_bytes_all(
        self,
        raw: bytes,
        artifact: Artifact,
        *,
        source: str = "flag_hunter",
        location_prefix: str = "byte range 0..scan-limit",
        truncated: bool = False,
        source_kind: str = "derived_record",
        discovered_path: str | None = None,
        allow_transforms: bool = True,
    ) -> SearchScanResult:
        limited = raw[: self.max_scan_bytes]
        deadline = time.monotonic() + self.scan_timeout
        result = self._search_buffer(
            limited, artifact, source=source, location_prefix=location_prefix,
            source_kind=source_kind,
            discovered_path=discovered_path or artifact.path,
            base_offset=0, file_offsets=False, deadline=deadline,
            allow_transforms=allow_transforms, decode_budget=_DecodeBudget(),
        )
        result.scanned_bytes = len(limited)
        result.truncated = truncated or len(raw) > self.max_scan_bytes
        if result.truncated:
            result.warnings.append("derived-record flag search was truncated at its byte limit")
        result.flags = self._group_flags(result.flags)
        result.hits = self._group_hits(result.hits)
        return result

    def _search_buffer(
        self,
        raw: bytes,
        artifact: Artifact,
        *,
        source: str,
        location_prefix: str,
        source_kind: str,
        discovered_path: str,
        base_offset: int,
        file_offsets: bool,
        deadline: float,
        allow_transforms: bool = True,
        decode_budget: _DecodeBudget | None = None,
    ) -> SearchScanResult:
        digest = hashlib.sha256(raw).hexdigest()
        root = DecodedRegion(
            raw, ("raw",), location_prefix,
            source_offset=base_offset if file_offsets else None,
            source_end=base_offset + len(raw) if file_offsets else None,
            ancestor_hashes=frozenset({digest}),
        )
        regions = [root]
        warnings: list[str] = []
        if allow_transforms:
            regions.extend(self._derived_regions(
                root, deadline, warnings, decode_budget or _DecodeBudget()
            ))
        flags: list[FlagCandidate] = []
        hits: list[SearchHit] = []
        for region in regions:
            if time.monotonic() >= deadline:
                warnings.append("flag search time limit reached during decoded-region search")
                break
            region_flags, region_hits = self._search_region(
                region, artifact, source=source, source_kind=source_kind,
                discovered_path=discovered_path, file_offsets=file_offsets,
                truncated=False,
            )
            flags.extend(region_flags)
            hits.extend(region_hits)
        return SearchScanResult(flags=flags, hits=hits, warnings=list(dict.fromkeys(warnings)))

    def _search_region(
        self,
        region: DecodedRegion,
        artifact: Artifact,
        *,
        source: str,
        source_kind: str,
        discovered_path: str,
        file_offsets: bool,
        truncated: bool,
    ) -> tuple[list[FlagCandidate], list[SearchHit]]:
        flags: list[FlagCandidate] = []
        hits: list[SearchHit] = []
        byte_cursors: dict[tuple[str, int, str, str], int] = {}
        for encoding, phase, text in self._decoded_texts(region.data):
            for match_type, query, value, start, end in self._text_matches(text):
                if not value or len(value) > self.max_match_length:
                    continue
                encoded = value.encode(encoding, errors="ignore")
                cursor_key = (encoding, phase, match_type, query)
                relative = (
                    region.data.find(encoded, byte_cursors.get(cursor_key, phase))
                    if encoded else -1
                )
                if relative >= 0:
                    byte_cursors[cursor_key] = relative + len(encoded)
                raw_offset = None
                if (
                    not region.derived and file_offsets
                    and region.source_offset is not None and relative >= 0
                ):
                    raw_offset = region.source_offset + relative
                if region.derived:
                    location = (
                        f"{region.source_location}; decoded output character offset {start} "
                        "(not an original evidence offset)"
                    )
                elif raw_offset is not None:
                    location = f"byte offset {raw_offset}..{raw_offset + len(encoded)}"
                    if truncated:
                        location += " (scan truncated)"
                else:
                    location = f"{region.source_location}; character offset {start}"
                chain = list(region.chain)
                if encoding != "utf-8":
                    chain.append(encoding)
                context = self._context(text, start, end)
                occurrence = {
                    "artifact_id": artifact.id,
                    "artifact_depth": artifact.depth,
                    "origin_path": artifact.source_path or artifact.path,
                    "discovered_path": discovered_path,
                    "source": source,
                    "source_kind": source_kind,
                    "location": location,
                    "offset": raw_offset,
                    "encoding": encoding,
                    "transform_chain": chain,
                    "context": context,
                    "source_offset": (
                        raw_offset if raw_offset is not None else region.source_offset
                    ),
                    "source_end": (
                        raw_offset + len(encoded)
                        if raw_offset is not None else region.source_end
                    ),
                }
                if match_type == "flag":
                    flags.append(FlagCandidate(
                        artifact_id=artifact.id, value=value,
                        transform_chain=chain, source=source, location=location,
                        confidence=0.98 if chain == ["raw"] else 0.9,
                        encoding=encoding, context=context,
                        source_kind=source_kind,
                        origin_path=artifact.source_path or artifact.path,
                        discovered_path=discovered_path, offset=raw_offset,
                        locations=[occurrence], status="candidate",
                    ))
                else:
                    hits.append(SearchHit(
                        artifact_id=artifact.id, value=value, query=query,
                        match_type=match_type, source=source, location=location,
                        encoding=encoding, transform_chain=chain,
                        context=context, source_kind=source_kind,
                        origin_path=artifact.source_path or artifact.path,
                        discovered_path=discovered_path, offset=raw_offset,
                        locations=[occurrence],
                    ))
        return flags, hits

    def _text_matches(self, text: str) -> Iterator[tuple[str, str, str, int, int]]:
        seen: set[tuple[str, str, int, int]] = set()
        for query, pattern in self.flag_patterns:
            for match in self._timed_finditer(pattern, text):
                key = ("flag", query, match.start(), match.end())
                if key not in seen:
                    seen.add(key)
                    yield "flag", query, match.group(0), match.start(), match.end()
        for query in self.exact_strings:
            for start in self._literal_offsets(text, query, case_sensitive=True):
                end = start + len(query)
                key = ("exact", query, start, end)
                if key not in seen:
                    seen.add(key)
                    yield "exact", query, text[start:end], start, end
        for query in self.search_terms:
            for start in self._literal_offsets(text, query, case_sensitive=False):
                end = start + len(query)
                key = ("keyword", query, start, end)
                if key not in seen:
                    seen.add(key)
                    yield "keyword", query, text[start:end], start, end
        for query, pattern in self.user_regex_patterns:
            for match in self._timed_finditer(pattern, text):
                key = ("regex", query, match.start(), match.end())
                if key not in seen:
                    seen.add(key)
                    yield "regex", query, match.group(0), match.start(), match.end()

    def _derived_regions(
        self,
        root: DecodedRegion,
        deadline: float,
        warnings: list[str],
        budget: _DecodeBudget,
    ) -> list[DecodedRegion]:
        output: list[DecodedRegion] = []
        queue: list[tuple[DecodedRegion, int]] = [(root, 0)]
        while queue and budget.artifacts < self.max_decode_artifacts:
            region, depth = queue.pop(0)
            if depth >= self.decode_depth:
                continue
            if time.monotonic() >= deadline:
                warnings.append("flag decode time limit reached")
                break
            for candidate in self._decode_once(region):
                digest = hashlib.sha256(candidate.data).hexdigest()
                if digest in region.ancestor_hashes:
                    continue
                identity = (
                    digest, candidate.source_offset, candidate.source_end,
                    candidate.chain,
                )
                if identity in budget.seen:
                    continue
                if budget.decoded_bytes + len(candidate.data) > self.max_decoded_bytes:
                    warnings.append(
                        f"decoded-byte limit reached ({self.max_decoded_bytes} bytes)"
                    )
                    return output
                enriched = DecodedRegion(
                    candidate.data, candidate.chain, candidate.source_location,
                    candidate.source_offset, candidate.source_end, True,
                    frozenset((*region.ancestor_hashes, digest)),
                )
                output.append(enriched)
                queue.append((enriched, depth + 1))
                budget.seen.add(identity)
                budget.artifacts += 1
                budget.decoded_bytes += len(enriched.data)
                if budget.artifacts >= self.max_decode_artifacts:
                    warnings.append(
                        f"decoded-artifact limit reached ({self.max_decode_artifacts})"
                    )
                    break
        return output

    def _decode_once(self, region: DecodedRegion) -> Iterator[DecodedRegion]:
        raw = region.data
        for match in self.BASE64.finditer(raw):
            blob = match.group(0)
            if len(blob) % 4:
                continue
            try:
                value = base64.b64decode(blob, validate=True)
            except (ValueError, binascii.Error):
                continue
            candidate = self._decoded_candidate(region, match.start(), match.end(), value, "base64")
            if candidate is not None:
                yield candidate
        for match in self.BASE32.finditer(raw):
            blob = match.group(0)
            if len(blob) % 8:
                continue
            try:
                value = base64.b32decode(blob, casefold=False)
            except (ValueError, binascii.Error):
                continue
            candidate = self._decoded_candidate(region, match.start(), match.end(), value, "base32")
            if candidate is not None:
                yield candidate
        for match in self.HEX.finditer(raw):
            try:
                value = bytes.fromhex(match.group(0).decode("ascii"))
            except ValueError:
                continue
            candidate = self._decoded_candidate(region, match.start(), match.end(), value, "hex")
            if candidate is not None:
                yield candidate
        for match in self.PRINTABLE.finditer(raw):
            blob = match.group(0)
            if b"%" in blob:
                value = urllib.parse.unquote_to_bytes(blob.decode("ascii", errors="ignore"))
                candidate = self._decoded_candidate(
                    region, match.start(), match.end(), value, "url_decode"
                )
                if candidate is not None and value != blob:
                    yield candidate
            if "rot13" not in region.chain:
                text = blob.decode("ascii", errors="ignore")
                rotated = codecs.decode(text, "rot_13").encode()
                candidate = self._decoded_candidate(
                    region, match.start(), match.end(), rotated, "rot13",
                    require_direct_match=True,
                )
                if candidate is not None and rotated != blob:
                    yield candidate
        if raw.startswith(b"\x1f\x8b"):
            value = self._bounded_gzip(raw)
            candidate = self._decoded_candidate(region, 0, len(raw), value, "gzip")
            if candidate is not None:
                yield candidate
        if len(raw) >= 2 and raw[0] == 0x78:
            value = self._bounded_zlib(raw)
            candidate = self._decoded_candidate(region, 0, len(raw), value, "zlib")
            if candidate is not None:
                yield candidate

    def _decoded_candidate(
        self,
        parent: DecodedRegion,
        start: int,
        end: int,
        value: bytes | None,
        transform: str,
        *,
        require_direct_match: bool = False,
    ) -> DecodedRegion | None:
        if value is None or (
            not self._contains_target(value)
            if require_direct_match else not self._potentially_interesting(value)
        ):
            return None
        if not parent.derived and parent.source_offset is not None:
            source_start = parent.source_offset + start
            source_end = parent.source_offset + end
            location = f"encoded evidence byte range {source_start}..{source_end}"
        else:
            source_start = parent.source_offset
            source_end = parent.source_end
            location = (
                f"{parent.source_location}; {transform} input range {start}..{end} "
                "in derived data"
            )
        return DecodedRegion(
            value, (*parent.chain, transform), location,
            source_start, source_end, True, parent.ancestor_hashes,
        )

    def _potentially_interesting(self, value: bytes) -> bool:
        if not value or len(value) > self.max_decoded_bytes:
            return False
        if value.startswith(b"\x1f\x8b") or (len(value) >= 2 and value[0] == 0x78):
            return True
        if self.BASE64.search(value) or self.BASE32.search(value) or self.HEX.search(value):
            return True
        if self._contains_target(value):
            return True
        return bool(self.PRINTABLE.search(value))

    def _contains_target(self, value: bytes) -> bool:
        text = value.decode("utf-8", errors="ignore")
        if any(self._timed_finditer(pattern, text) for _, pattern in self.flag_patterns):
            return True
        if any(query in text for query in self.exact_strings):
            return True
        folded = text.casefold()
        if any(query.casefold() in folded for query in self.search_terms):
            return True
        return any(self._timed_finditer(pattern, text) for _, pattern in self.user_regex_patterns)

    def _bounded_gzip(self, payload: bytes) -> bytes | None:
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as stream:
                value = stream.read(self.max_decoded_bytes + 1)
            return value if len(value) <= self.max_decoded_bytes else None
        except (OSError, EOFError):
            return None

    def _bounded_zlib(self, payload: bytes) -> bytes | None:
        try:
            decoder = zlib.decompressobj()
            value = decoder.decompress(payload, self.max_decoded_bytes + 1)
            if (
                len(value) > self.max_decoded_bytes or decoder.unconsumed_tail
                or decoder.unused_data or not decoder.eof
            ):
                return None
            tail = decoder.flush()
            return value + tail if len(value) + len(tail) <= self.max_decoded_bytes else None
        except zlib.error:
            return None

    @staticmethod
    def _decoded_texts(raw: bytes) -> Iterator[tuple[str, int, str]]:
        yield "utf-8", 0, raw.decode("utf-8", errors="ignore")
        for encoding in ("utf-16-le", "utf-16-be"):
            for phase in (0, 1):
                if len(raw) - phase >= 2:
                    yield encoding, phase, raw[phase:].decode(encoding, errors="ignore")

    @staticmethod
    def _literal_offsets(text: str, query: str, *, case_sensitive: bool) -> Iterator[int]:
        haystack = text if case_sensitive else text.casefold()
        needle = query if case_sensitive else query.casefold()
        start = 0
        while needle:
            found = haystack.find(needle, start)
            if found < 0:
                break
            yield found
            start = found + max(1, len(needle))

    @staticmethod
    def _context(text: str, start: int, end: int) -> str:
        value = text[max(0, start - 48):min(len(text), end + 48)]
        return value.replace("\x00", "\\0").replace("\r", "\\r").replace("\n", "\\n")[:512]

    @staticmethod
    def _bounded_queries(values: list[str], label: str) -> list[str]:
        output: list[str] = []
        for value in values:
            if not value or len(value) > 4_096 or "\x00" in value:
                raise ValueError(f"{label} must contain 1..4096 non-NUL characters")
            if value not in output:
                output.append(value)
        return output

    def _compile_safe(self, pattern: str) -> re.Pattern[str]:
        if not pattern or len(pattern) > 1_024:
            raise UnsafeRegexError("regex must contain 1..1024 characters")
        try:
            parsed = re._parser.parse(pattern, 0)  # type: ignore[attr-defined]
            self._validate_regex_tree(parsed)
            return re.compile(pattern)
        except re.error as exc:
            raise UnsafeRegexError(f"invalid regex {pattern!r}: {exc}") from exc

    @classmethod
    def _validate_regex_tree(cls, tree, *, inside_repeat: bool = False) -> None:
        constants = re._constants  # type: ignore[attr-defined]
        repeat_ops = {
            constants.MAX_REPEAT, constants.MIN_REPEAT,
            getattr(constants, "POSSESSIVE_REPEAT", object()),
        }
        forbidden = {
            constants.GROUPREF, constants.GROUPREF_EXISTS,
            constants.ASSERT, constants.ASSERT_NOT,
        }
        for operation, argument in tree:
            if operation in forbidden:
                raise UnsafeRegexError("lookarounds, conditionals, and backreferences are disabled")
            if operation in repeat_ops:
                if inside_repeat:
                    raise UnsafeRegexError("nested repetition is disabled")
                _, _, child = argument
                if any(item[0] == constants.BRANCH for item in child):
                    raise UnsafeRegexError("repeated alternation is disabled")
                cls._validate_regex_tree(child, inside_repeat=True)
            elif operation == constants.SUBPATTERN:
                cls._validate_regex_tree(argument[-1], inside_repeat=inside_repeat)
            elif operation == constants.BRANCH:
                if inside_repeat:
                    raise UnsafeRegexError("repeated alternation is disabled")
                for branch in argument[1]:
                    cls._validate_regex_tree(branch, inside_repeat=inside_repeat)
            elif operation == constants.ATOMIC_GROUP:
                cls._validate_regex_tree(argument, inside_repeat=inside_repeat)

    def _timed_finditer(self, pattern: re.Pattern[str], text: str):
        with self._regex_deadline():
            try:
                return list(pattern.finditer(text))
            except _RegexDeadline:
                return []

    @contextmanager
    def _regex_deadline(self):
        if (
            threading.current_thread() is not threading.main_thread()
            or not hasattr(signal, "setitimer")
        ):
            yield
            return

        def expired(_signum, _frame):
            raise _RegexDeadline("regular expression time limit reached")

        previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, expired)
        previous_timer = signal.setitimer(signal.ITIMER_REAL, self.regex_timeout)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
            signal.signal(signal.SIGALRM, previous_handler)

    @staticmethod
    def _accept_window(target: SearchScanResult, partial: SearchScanResult, accept_after: int) -> None:
        def is_new(locations: list[dict[str, object]]) -> bool:
            if not locations:
                return True
            source_end = locations[0].get("source_end")
            return not isinstance(source_end, int) or source_end > accept_after

        target.flags.extend(item for item in partial.flags if is_new(item.locations))
        target.hits.extend(item for item in partial.hits if is_new(item.locations))
        target.warnings.extend(partial.warnings)

    @staticmethod
    def _group_flags(candidates: list[FlagCandidate]) -> list[FlagCandidate]:
        grouped: dict[str, FlagCandidate] = {}
        seen_locations: dict[str, set[str]] = {}
        for candidate in candidates:
            existing = grouped.get(candidate.value)
            if existing is None:
                grouped[candidate.value] = candidate
                existing = candidate
                seen_locations[candidate.value] = set()
            for location in candidate.locations:
                identity = repr(sorted(location.items()))
                if identity not in seen_locations[candidate.value]:
                    if existing is not candidate:
                        existing.locations.append(location)
                    seen_locations[candidate.value].add(identity)
            existing.confidence = max(existing.confidence, candidate.confidence)
            if (
                candidate is not existing
                and FlagHunter._location_priority(candidate.locations)
                > FlagHunter._location_priority(existing.locations[:1])
            ):
                candidate_locations = list(candidate.locations)
                candidate_identities = {
                    repr(sorted(location.items())) for location in candidate_locations
                }
                candidate.locations = candidate_locations + [
                    location for location in existing.locations
                    if repr(sorted(location.items())) not in candidate_identities
                ]
                candidate.confidence = existing.confidence
                grouped[candidate.value] = candidate
        return list(grouped.values())

    @staticmethod
    def _group_hits(hits: list[SearchHit]) -> list[SearchHit]:
        grouped: dict[tuple[str, str, str], SearchHit] = {}
        seen_locations: dict[tuple[str, str, str], set[str]] = {}
        for hit in hits:
            key = (hit.match_type, hit.query, hit.value)
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = hit
                existing = hit
                seen_locations[key] = set()
            for location in hit.locations:
                identity = repr(sorted(location.items()))
                if identity not in seen_locations[key]:
                    if existing is not hit:
                        existing.locations.append(location)
                    seen_locations[key].add(identity)
        return list(grouped.values())

    @staticmethod
    def _location_priority(locations: list[dict[str, object]]) -> tuple[int, int]:
        if not locations:
            return (-1, -1)
        location = locations[0]
        depth = location.get("artifact_depth")
        kind = str(location.get("source_kind") or "")
        kind_priority = {
            "derived_tool_output": 7,
            "derived_record": 6,
            "extracted_evidence": 5,
            "original_evidence": 4,
            "parsed_record": 3,
            "filename": 1,
            "program_log": 0,
        }.get(kind, 1)
        return (int(depth) if isinstance(depth, int) else 0, kind_priority)
