from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import lzma
import re
import shutil
import stat
import tarfile
import zipfile
import zlib
from email import policy
from email.parser import BytesParser
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .config import AnalysisLimits
from .models import Artifact, Finding, ToolRun, new_id
from .pcap import iter_ftp_auth_tls_transitions, iter_ftp_retr_objects, iter_http_response_objects, iter_imap_fetch_objects, iter_imap_starttls_transitions, iter_pop3_retr_objects, iter_pop3_stls_transitions, iter_smb2_close_operations, iter_smb2_create_operations, iter_smb2_directory_listings, iter_smb2_negotiate_operations, iter_smb2_read_objects, iter_smb2_set_info_operations, iter_smb2_write_objects, iter_smb3_transform_records, iter_smtp_bdat_objects, iter_smtp_data_objects, iter_smtp_starttls_transitions
from .workspace import CaseWorkspace, safe_name


@dataclass(slots=True)
class ExtractionResult:
    artifacts: list[Artifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    extracted_bytes: int = 0


class ExtractionManager:
    """Bounded built-in extraction used as a deterministic fallback."""

    def __init__(self, workspace: CaseWorkspace, limits: AnalysisLimits) -> None:
        self.workspace = workspace
        self.limits = limits
        self.extracted_bytes = 0

    def can_register(self, parent: Artifact, declared_size: int) -> str | None:
        if parent.depth >= self.limits.max_depth:
            return f"maximum recursion depth {self.limits.max_depth} reached"
        if len(self.workspace.database.artifacts()) >= self.limits.max_artifact_count:
            return f"maximum artifact count {self.limits.max_artifact_count} reached"
        if declared_size > self.limits.max_single_artifact_size:
            return f"child exceeds maximum single artifact size ({declared_size} bytes)"
        if self.extracted_bytes + declared_size > self.limits.max_extracted_bytes:
            return "maximum cumulative extracted bytes reached"
        return None

    def register_file(
        self,
        path: Path,
        parent: Artifact,
        logical_name: str,
        created_by_tool_run_id: str | None = None,
        *,
        delete_duplicate: bool = True,
    ) -> Artifact | None:
        size = path.stat().st_size
        reason = self.can_register(parent, size)
        if reason:
            return None
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        sha256 = digest.hexdigest()
        duplicate = self.workspace.database.artifact_by_hash(parent.case_id, sha256)
        if duplicate:
            if delete_duplicate:
                path.unlink(missing_ok=True)
            return None
        path.chmod(0o444)
        artifact = Artifact(
            id=new_id(),
            case_id=parent.case_id,
            parent_id=parent.id,
            path=self.workspace.relative(path),
            logical_name=logical_name,
            sha256=sha256,
            size=size,
            depth=parent.depth + 1,
            created_by_tool_run_id=created_by_tool_run_id,
        )
        self.workspace.database.add_artifact(artifact)
        self.extracted_bytes += size
        return artifact

    def register_tool_outputs(self, parent: Artifact, run: ToolRun) -> ExtractionResult:
        """Promote runner-enumerated files into lineage-preserving artifacts.

        The runner is authoritative for its own output directory, but this
        second check binds every promoted file to the exact tool-run UUID.
        Rejected outputs stay in the workspace for audit instead of being
        silently deleted.  A failed/timed-out tool may still produce useful
        partial carvings, so its artifacts are retained with explicit status
        provenance rather than discarded.
        """
        result = ExtractionResult()
        expected_root = self.workspace.path("extracted", run.id).resolve()
        for stored_path in run.generated_files:
            try:
                path = self.workspace.resolve_stored_path(stored_path)
            except (OSError, ValueError) as exc:
                result.errors.append(f"skipped tool output {stored_path!r}: invalid stored path ({exc})")
                continue
            if path.is_symlink() or not path.is_file() or (path != expected_root and expected_root not in path.parents):
                result.errors.append(f"skipped tool output {stored_path!r}: outside regular tool output scope")
                continue
            try:
                logical_name = str(path.relative_to(expected_root))
            except ValueError:
                result.errors.append(f"skipped tool output {stored_path!r}: output lineage mismatch")
                continue
            child = self.register_file(path, parent, logical_name, run.id, delete_duplicate=False)
            if child is None:
                result.errors.append(f"skipped tool output {logical_name!r}: duplicate or extraction limit")
                continue
            result.artifacts.append(child)
            result.extracted_bytes += child.size
        if result.artifacts:
            result.findings.append(
                Finding(
                    artifact_id=parent.id,
                    title=f"Registered {len(result.artifacts)} tool-generated artifact(s)",
                    category="tool_output_artifact",
                    severity="info",
                    confidence=1.0,
                    explanation=(
                        f"Output files from {run.tool} were promoted to child artifacts with tool-run provenance "
                        f"(status={run.status.value})."
                    ),
                    source="tool_output_registrar",
                    supporting_evidence=[f"tool_run:{run.id}", *[child.id for child in result.artifacts]],
                )
            )
        return result

    def extract_zip(self, artifact: Artifact) -> ExtractionResult:
        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        try:
            if not zipfile.is_zipfile(source):
                return result
        except OSError as exc:
            result.errors.append(f"ZIP probe failed for {artifact.logical_name}: {exc}")
            return result

        target_root = self.workspace.path("extracted", artifact.id, "builtin_zip")
        target_root.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(source) as archive:
                members = archive.infolist()
                if len(members) > self.limits.max_artifact_count:
                    result.errors.append(
                        f"ZIP has {len(members)} entries; limit is {self.limits.max_artifact_count}"
                    )
                    members = members[: self.limits.max_artifact_count]
                for index, member in enumerate(members):
                    if member.is_dir():
                        continue
                    reason = self._unsafe_member_reason(member)
                    if reason:
                        result.errors.append(f"skipped ZIP member {member.filename!r}: {reason}")
                        continue
                    reason = self.can_register(artifact, member.file_size)
                    if reason:
                        result.errors.append(f"skipped ZIP member {member.filename!r}: {reason}")
                        continue
                    relative = PurePosixPath(member.filename)
                    output_name = f"{index:05d}_{safe_name(relative.name)}"
                    output = target_root / output_name
                    try:
                        written = self._copy_member_bounded(archive, member, output)
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        output.unlink(missing_ok=True)
                        result.errors.append(f"failed ZIP member {member.filename!r}: {exc}")
                        continue
                    child = self.register_file(output, artifact, member.filename)
                    if child:
                        result.artifacts.append(child)
                        result.extracted_bytes += written
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            result.errors.append(f"ZIP extraction failed for {artifact.logical_name}: {exc}")

        if result.artifacts:
            result.findings.append(
                Finding(
                    artifact_id=artifact.id,
                    title=f"Extracted {len(result.artifacts)} ZIP member(s)",
                    category="archive_extraction",
                    severity="info",
                    confidence=1.0,
                    explanation="A structurally valid ZIP container was opened with the bounded built-in extractor.",
                    source="builtin_zip_extractor",
                    supporting_evidence=[child.id for child in result.artifacts],
                )
            )
        return result

    def extract_gzip(self, artifact: Artifact) -> ExtractionResult:
        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        try:
            with source.open("rb") as probe:
                if probe.read(2) != b"\x1f\x8b":
                    return result
        except OSError as exc:
            result.errors.append(f"gzip probe failed for {artifact.logical_name}: {exc}")
            return result
        expected_name = Path(artifact.logical_name).name
        if expected_name.lower().endswith((".gz", ".gzip")):
            expected_name = expected_name.rsplit(".", 1)[0]
        output = self.workspace.path("extracted", artifact.id, "builtin_gzip", safe_name(expected_name or "decompressed"))
        output.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with gzip.open(source, "rb") as reader, output.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    written += len(chunk)
                    if written > self.limits.max_single_artifact_size or self.extracted_bytes + written > self.limits.max_extracted_bytes:
                        raise RuntimeError("decompressed gzip data exceeds configured extraction limit")
                    writer.write(chunk)
        except (OSError, EOFError, RuntimeError) as exc:
            output.unlink(missing_ok=True)
            result.errors.append(f"gzip extraction failed for {artifact.logical_name}: {exc}")
            return result
        child = self.register_file(output, artifact, expected_name or "decompressed")
        if child:
            result.artifacts.append(child)
            result.extracted_bytes = written
            result.findings.append(
                Finding(
                    artifact_id=artifact.id,
                    title="Extracted gzip payload",
                    category="archive_extraction",
                    severity="info",
                    confidence=1.0,
                    explanation="A gzip stream was decompressed with configured extraction limits.",
                    source="builtin_gzip_extractor",
                    supporting_evidence=[child.id],
                )
            )
        return result

    def extract_tar(self, artifact: Artifact) -> ExtractionResult:
        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        try:
            if not tarfile.is_tarfile(source):
                return result
        except OSError as exc:
            result.errors.append(f"tar probe failed for {artifact.logical_name}: {exc}")
            return result
        target_root = self.workspace.path("extracted", artifact.id, "builtin_tar")
        target_root.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(source, "r:*") as archive:
                members = archive.getmembers()
                if len(members) > self.limits.max_artifact_count:
                    result.errors.append(
                        f"tar has {len(members)} entries; limit is {self.limits.max_artifact_count}"
                    )
                    members = members[: self.limits.max_artifact_count]
                for index, member in enumerate(members):
                    if not member.isfile():
                        if member.issym() or member.islnk():
                            result.errors.append(f"skipped TAR member {member.name!r}: link entry")
                        continue
                    if self._unsafe_name(member.name):
                        result.errors.append(f"skipped TAR member {member.name!r}: unsafe path")
                        continue
                    reason = self.can_register(artifact, member.size)
                    if reason:
                        result.errors.append(f"skipped TAR member {member.name!r}: {reason}")
                        continue
                    reader = archive.extractfile(member)
                    if reader is None:
                        result.errors.append(f"failed TAR member {member.name!r}: no data stream")
                        continue
                    output = target_root / f"{index:05d}_{safe_name(PurePosixPath(member.name).name)}"
                    written = 0
                    try:
                        with reader, output.open("xb") as writer:
                            while chunk := reader.read(1024 * 1024):
                                written += len(chunk)
                                if written > member.size + 1024 or written > self.limits.max_single_artifact_size:
                                    raise RuntimeError("tar member exceeded declared/safe size")
                                writer.write(chunk)
                    except (OSError, RuntimeError) as exc:
                        output.unlink(missing_ok=True)
                        result.errors.append(f"failed TAR member {member.name!r}: {exc}")
                        continue
                    child = self.register_file(output, artifact, member.name)
                    if child:
                        result.artifacts.append(child)
                        result.extracted_bytes += written
        except (OSError, tarfile.TarError) as exc:
            result.errors.append(f"tar extraction failed for {artifact.logical_name}: {exc}")
        if result.artifacts:
            result.findings.append(
                Finding(
                    artifact_id=artifact.id,
                    title=f"Extracted {len(result.artifacts)} TAR member(s)",
                    category="archive_extraction",
                    severity="info",
                    confidence=1.0,
                    explanation="A TAR container was opened with link and path traversal protections.",
                    source="builtin_tar_extractor",
                    supporting_evidence=[child.id for child in result.artifacts],
                )
            )
        return result

    def extract_cpio(self, artifact: Artifact) -> ExtractionResult:
        """Copy bounded regular-file ranges from native CPIO observations."""
        result = ExtractionResult()
        entry_observation = next(
            (
                observation
                for observation in self.workspace.database.observations(artifact.id)
                if observation.key == "archive.cpio.entries"
                and isinstance(observation.value, list)
            ),
            None,
        )
        if entry_observation is None:
            return result
        records = entry_observation.value
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_cpio")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"CPIO source open failed for {artifact.logical_name}: {exc}")
            return result
        with source_stream:
            for record_index, record in enumerate(records):
                if not isinstance(record, dict) or record.get("file_type") != "regular":
                    continue
                name = record.get("name")
                header_offset = record.get("header_offset")
                header_length = record.get("header_length")
                alignment = record.get("alignment")
                name_offset = record.get("name_offset")
                name_size = record.get("name_size_including_nul")
                data_offset = record.get("data_offset")
                data_length = record.get("data_length")
                magic = record.get("magic")
                stored_checksum = record.get("stored_checksum")
                if not isinstance(name, str) or not name or self._unsafe_name(name):
                    result.errors.append(f"skipped CPIO member {name!r}: unsafe path")
                    continue
                if (
                    isinstance(header_offset, bool) or not isinstance(header_offset, int)
                    or isinstance(header_length, bool) or not isinstance(header_length, int)
                    or isinstance(alignment, bool) or not isinstance(alignment, int)
                    or isinstance(name_offset, bool) or not isinstance(name_offset, int)
                    or isinstance(name_size, bool) or not isinstance(name_size, int)
                    or isinstance(data_offset, bool) or not isinstance(data_offset, int)
                    or isinstance(data_length, bool) or not isinstance(data_length, int)
                    or header_offset < 0 or name_offset != header_offset + header_length
                    or magic not in {"070701", "070702", "070707"}
                    or (magic == "070707" and (header_length != 76 or alignment != 2))
                    or (magic in {"070701", "070702"} and (header_length != 110 or alignment != 4))
                    or not 1 <= name_size <= 4_096
                    or data_offset != (
                        name_offset + name_size + (-(name_offset + name_size)) % alignment
                    )
                    or data_length < 0 or data_offset + data_length > artifact.size
                    or (
                        magic in {"070701", "070702"}
                        and (
                            isinstance(stored_checksum, bool)
                            or not isinstance(stored_checksum, int)
                        )
                    )
                    or (magic == "070707" and stored_checksum is not None)
                ):
                    result.errors.append(f"skipped CPIO member {name!r}: invalid observed byte range")
                    continue
                reason = self.can_register(artifact, data_length)
                if reason:
                    result.errors.append(f"skipped CPIO member {name!r}: {reason}")
                    continue
                try:
                    source_stream.seek(header_offset)
                    raw_header = source_stream.read(header_length)
                    if len(raw_header) != header_length or raw_header[:6].decode(
                        "ascii", errors="replace"
                    ) != magic:
                        raise RuntimeError("header no longer matches triage provenance")
                    if magic == "070707":
                        if any(byte not in b"01234567" for byte in raw_header[6:]):
                            raise RuntimeError("odc header has a non-octal field")
                        raw_mode = int(raw_header[18:24], 8)
                        raw_name_size = int(raw_header[59:65], 8)
                        raw_data_length = int(raw_header[65:76], 8)
                        raw_stored_checksum = None
                    else:
                        if any(
                            byte not in b"0123456789abcdefABCDEF"
                            for byte in raw_header[6:]
                        ):
                            raise RuntimeError("newc header has a non-hex field")
                        raw_mode = int(raw_header[14:22], 16)
                        raw_data_length = int(raw_header[54:62], 16)
                        raw_name_size = int(raw_header[94:102], 16)
                        raw_stored_checksum = int(raw_header[102:110], 16)
                    if (
                        raw_mode & 0o170000 != 0o100000
                        or raw_data_length != data_length
                        or raw_name_size != name_size
                        or raw_stored_checksum != stored_checksum
                    ):
                        raise RuntimeError("header fields no longer match triage provenance")
                    source_stream.seek(name_offset)
                    raw_name = source_stream.read(name_size)
                    if (
                        len(raw_name) != name_size
                        or not raw_name.endswith(b"\x00")
                        or raw_name[:-1].hex() != record.get("name_raw_hex")
                    ):
                        raise RuntimeError("pathname no longer matches triage provenance")
                except (OSError, RuntimeError, ValueError) as exc:
                    result.errors.append(f"skipped CPIO member {name!r}: {exc}")
                    continue
                target_root.mkdir(parents=True, exist_ok=True)
                output = target_root / f"{record_index:05d}_{safe_name(PurePosixPath(name).name)}"
                calculated_checksum = 0
                written = 0
                try:
                    source_stream.seek(data_offset)
                    with output.open("xb") as writer:
                        remaining = data_length
                        while remaining:
                            chunk = source_stream.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise RuntimeError("member data read ended before declared length")
                            writer.write(chunk)
                            written += len(chunk)
                            remaining -= len(chunk)
                            calculated_checksum = (
                                calculated_checksum + sum(chunk)
                            ) & 0xFFFFFFFF
                    if written != data_length:
                        raise RuntimeError("member data length mismatch")
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(f"failed CPIO member {name!r}: {exc}")
                    continue
                child = self.register_file(output, artifact, name)
                if child is None:
                    result.errors.append(
                        f"skipped CPIO member {name!r}: duplicate or extraction limit"
                    )
                    continue
                checksum_valid = (
                    calculated_checksum == stored_checksum if magic == "070702" else None
                )
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};source_observation_id:{entry_observation.id};"
                    f"source_observation_key:{entry_observation.key};"
                    f"format:{record.get('format')};header_offset:{header_offset};"
                    f"name_offset:{name_offset};data_offset:{data_offset};"
                    f"data_length:{data_length};stored_checksum:{stored_checksum};"
                    f"calculated_checksum:{calculated_checksum if magic == '070702' else None};"
                    f"checksum_valid:{checksum_valid};entry_record:{record}"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Extracted {len(result.artifacts)} CPIO regular-file member(s)",
                category="archive_extraction",
                severity="info",
                confidence=0.99,
                explanation=(
                    "Only regular files with relative non-traversing paths and exact image-bounded "
                    "CPIO ranges were copied. Directories, links, and device/special entries remain "
                    "metadata-only; CRC entries retain a byte-sum verdict computed while copying."
                ),
                source="builtin_cpio_extractor",
                supporting_evidence=evidence[:128],
            ))
        return result

    def extract_iso9660(self, artifact: Artifact) -> ExtractionResult:
        """Copy validated regular files from bounded active ISO directory traversal."""
        result = ExtractionResult()
        observations = self.workspace.database.observations(artifact.id)
        entry_observation = next(
            (
                observation
                for observation in observations
                if observation.key == "archive.iso9660.regular_files"
                and isinstance(observation.value, list)
            ),
            None,
        )
        if entry_observation is None:
            return result
        pvd_observation = next(
            (
                observation
                for observation in observations
                if observation.key == "archive.iso9660.primary_volume_descriptor"
                and isinstance(observation.value, dict)
            ),
            None,
        )
        if pvd_observation is None or pvd_observation.value.get("valid") is not True:
            result.errors.append("skipped ISO extraction: primary volume descriptor did not validate")
            return result
        pvd_block_size = pvd_observation.value.get("logical_block_size")
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_iso9660")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"ISO source open failed for {artifact.logical_name}: {exc}")
            return result
        with source_stream:
            for record_index, record in enumerate(entry_observation.value):
                if not isinstance(record, dict) or record.get("file_type") != "regular":
                    continue
                name = record.get("archive_path")
                if not isinstance(name, str) or not name or self._unsafe_name(name):
                    result.errors.append(f"skipped ISO member {name!r}: unsafe path")
                    continue
                if record.get("extraction_eligible") is not True:
                    if record.get(
                        "extraction_reconciled_to_rock_ridge_hard_link"
                    ) is True:
                        continue
                    if record.get("rock_ridge_symlink") is True:
                        result.errors.append(
                            f"skipped ISO member {name!r}: Rock Ridge symbolic link is metadata-only"
                        )
                    elif record.get("rock_ridge_zisofs") is True:
                        result.errors.append(
                            f"skipped ISO member {name!r}: zisofs compressed stream is metadata-only"
                        )
                    elif record.get("rock_ridge_non_regular") is True:
                        result.errors.append(
                            f"skipped ISO member {name!r}: Rock Ridge special file is metadata-only"
                        )
                    elif (
                        record.get("multi_extent") is True
                        or record.get("file_unit_size") not in {0, None}
                        or record.get("interleave_gap_size") not in {0, None}
                    ):
                        result.errors.append(
                            f"skipped ISO member {name!r}: unsupported multi-extent/interleaved layout"
                        )
                    else:
                        result.errors.append(
                            f"skipped ISO member {name!r}: directory record did not validate"
                        )
                    continue
                multi_extent = record.get("multi_extent") is True
                if multi_extent:
                    raw_segments = record.get("multi_extent_segments")
                    chain = record.get("multi_extent_chain")
                    if (
                        record.get("multi_extent_assembled") is not True
                        or not isinstance(chain, dict)
                        or chain.get("complete") is not True
                        or chain.get("extraction_eligible") is not True
                        or not isinstance(raw_segments, list)
                        or not 2 <= len(raw_segments) <= 128
                    ):
                        result.errors.append(
                            f"skipped ISO member {name!r}: invalid multi-extent chain provenance"
                        )
                        continue
                    segment_records = raw_segments
                    data_length = record.get("assembled_data_length")
                    if (
                        not isinstance(data_length, int) or isinstance(data_length, bool)
                        or data_length <= 0
                        or chain.get("total_data_length") != data_length
                    ):
                        result.errors.append(
                            f"skipped ISO member {name!r}: invalid assembled byte length"
                        )
                        continue
                else:
                    segment_records = [record]
                    data_length = record.get("data_length")
                if not isinstance(data_length, int) or isinstance(data_length, bool):
                    result.errors.append(f"skipped ISO member {name!r}: invalid observed byte range")
                    continue
                reason = self.can_register(artifact, data_length)
                if reason:
                    result.errors.append(f"skipped ISO member {name!r}: {reason}")
                    continue
                validated_segments: list[dict[str, int]] = []
                try:
                    expected_identifier = record.get("identifier_raw_hex")
                    previous_record_end: int | None = None
                    for segment_index, segment in enumerate(segment_records):
                        if not isinstance(segment, dict):
                            raise RuntimeError("invalid multi-extent segment provenance")
                        record_offset = segment.get("record_offset")
                        record_length = segment.get("record_length")
                        block_size = segment.get("logical_block_size")
                        extent_block = segment.get("extent_block")
                        extended_attribute_blocks = segment.get("extended_attribute_blocks")
                        data_offset = segment.get("data_offset")
                        segment_length = segment.get("data_length")
                        identifier_raw_hex = segment.get("identifier_raw_hex")
                        record_raw_hex = segment.get("record_raw_hex")
                        if (
                            isinstance(record_offset, bool) or not isinstance(record_offset, int)
                            or isinstance(record_length, bool) or not isinstance(record_length, int)
                            or isinstance(block_size, bool) or not isinstance(block_size, int)
                            or isinstance(extent_block, bool) or not isinstance(extent_block, int)
                            or isinstance(extended_attribute_blocks, bool)
                            or not isinstance(extended_attribute_blocks, int)
                            or isinstance(data_offset, bool) or not isinstance(data_offset, int)
                            or isinstance(segment_length, bool) or not isinstance(segment_length, int)
                            or not isinstance(identifier_raw_hex, str)
                            or not isinstance(record_raw_hex, str)
                            or record_offset < 0 or not 34 <= record_length <= 255
                            or block_size < 512 or block_size > 32_768
                            or block_size != pvd_block_size
                            or data_offset != (
                                extent_block + extended_attribute_blocks
                            ) * block_size
                            or segment_length <= 0
                            or data_offset + segment_length > artifact.size
                            or identifier_raw_hex != expected_identifier
                        ):
                            raise RuntimeError("invalid observed segment byte range")
                        if previous_record_end is not None:
                            next_block = (
                                (previous_record_end + block_size - 1) // block_size
                            ) * block_size
                            if record_offset not in {previous_record_end, next_block}:
                                raise RuntimeError(
                                    "multi-extent directory records are no longer adjacent"
                                )
                            if record_offset > previous_record_end:
                                source_stream.seek(previous_record_end)
                                padding = source_stream.read(
                                    record_offset - previous_record_end
                                )
                                if len(padding) != record_offset - previous_record_end or any(padding):
                                    raise RuntimeError(
                                        "multi-extent directory padding no longer validates"
                                    )
                        previous_record_end = record_offset + record_length
                        source_stream.seek(record_offset)
                        raw_record = source_stream.read(record_length)
                        identifier_length = raw_record[32] if len(raw_record) >= 33 else 0
                        raw_identifier = raw_record[33:33 + identifier_length]
                        expected_multi_extent = (
                            multi_extent and segment_index < len(segment_records) - 1
                        )
                        if (
                            len(raw_record) != record_length
                            or raw_record[0] != record_length
                            or raw_record.hex() != record_raw_hex
                            or raw_record[1] != extended_attribute_blocks
                            or 33 + identifier_length > record_length
                            or raw_identifier.hex() != identifier_raw_hex
                            or int.from_bytes(raw_record[2:6], "little") != extent_block
                            or int.from_bytes(raw_record[6:10], "big") != extent_block
                            or int.from_bytes(raw_record[10:14], "little") != segment_length
                            or int.from_bytes(raw_record[14:18], "big") != segment_length
                            or bool(raw_record[25] & 0x80) is not expected_multi_extent
                            or raw_record[25] & 0x02
                            or raw_record[26] != 0
                            or raw_record[27] != 0
                            or (
                                expected_multi_extent
                                and segment_length % block_size != 0
                            )
                        ):
                            raise RuntimeError("directory record no longer matches triage provenance")
                        continuation_areas = segment.get("susp_continuation_areas", [])
                        if not isinstance(continuation_areas, list):
                            raise RuntimeError("invalid SUSP continuation provenance")
                        for continuation_area in continuation_areas:
                            if not isinstance(continuation_area, dict):
                                raise RuntimeError("invalid SUSP continuation record")
                            continuation_offset = continuation_area.get("absolute_offset")
                            continuation_length = continuation_area.get("length")
                            continuation_sha256 = continuation_area.get("raw_sha256")
                            if (
                                not isinstance(continuation_offset, int)
                                or not isinstance(continuation_length, int)
                                or continuation_length <= 0
                                or continuation_offset < 0
                                or continuation_offset + continuation_length > artifact.size
                                or not isinstance(continuation_sha256, str)
                            ):
                                raise RuntimeError("invalid SUSP continuation byte range")
                            source_stream.seek(continuation_offset)
                            continuation_raw = source_stream.read(continuation_length)
                            if (
                                len(continuation_raw) != continuation_length
                                or hashlib.sha256(continuation_raw).hexdigest()
                                != continuation_sha256
                            ):
                                raise RuntimeError(
                                    "SUSP continuation area no longer matches triage provenance"
                                )
                        validated_segments.append({
                            "record_offset": record_offset,
                            "record_length": record_length,
                            "extent_block": extent_block,
                            "data_offset": data_offset,
                            "data_length": segment_length,
                        })
                    if sum(segment["data_length"] for segment in validated_segments) != data_length:
                        raise RuntimeError("assembled extent length no longer matches triage provenance")
                except (OSError, RuntimeError) as exc:
                    result.errors.append(f"skipped ISO member {name!r}: {exc}")
                    continue
                target_root.mkdir(parents=True, exist_ok=True)
                output = target_root / f"{record_index:05d}_{safe_name(name)}"
                written = 0
                try:
                    with output.open("xb") as writer:
                        for segment in validated_segments:
                            source_stream.seek(segment["data_offset"])
                            remaining = segment["data_length"]
                            while remaining:
                                chunk = source_stream.read(min(1024 * 1024, remaining))
                                if not chunk:
                                    raise RuntimeError(
                                        "file extent read ended before declared length"
                                    )
                                writer.write(chunk)
                                written += len(chunk)
                                remaining -= len(chunk)
                    if written != data_length:
                        raise RuntimeError("file extent length mismatch")
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(f"failed ISO member {name!r}: {exc}")
                    continue
                child = self.register_file(output, artifact, name)
                if child is None:
                    result.errors.append(
                        f"skipped ISO member {name!r}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};source_observation_id:{entry_observation.id};"
                    f"source_observation_key:{entry_observation.key};"
                    f"pvd_observation_id:{pvd_observation.id};"
                    f"pvd_observation_key:{pvd_observation.key};"
                    f"pvd_descriptor_offset:{pvd_observation.value.get('descriptor_offset')};"
                    f"record_offset:{record.get('record_offset')};"
                    f"record_length:{record.get('record_length')};"
                    f"logical_block_size:{record.get('logical_block_size')};"
                    f"extent_block:{record.get('extent_block')};"
                    f"extended_attribute_blocks:{record.get('extended_attribute_blocks')};"
                    f"data_offset:{record.get('data_offset')};data_length:{data_length};"
                    f"multi_extent:{multi_extent};segments:{validated_segments};"
                    f"archive_path:{name};"
                    f"containing_directory_identity:{record.get('containing_directory_identity')};"
                    f"directory_identity_lineage:{record.get('directory_identity_lineage')};"
                    f"rock_ridge_hard_link_group:"
                    f"{record.get('rock_ridge_hard_link_group')};"
                    f"archive_name_source:{record.get('archive_name_source')};"
                    f"joliet_alias:{record.get('joliet_alias')};"
                    f"joliet_containing_directory_identity:"
                    f"{record.get('joliet_containing_directory_identity')};"
                    f"joliet_directory_identity_lineage:"
                    f"{record.get('joliet_directory_identity_lineage')};"
                    f"directory_record:{record}"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Extracted {len(result.artifacts)} ISO 9660 regular file(s)",
                category="archive_extraction",
                severity="info",
                confidence=0.99,
                explanation=(
                    "Only regular files reached through bounded primary-volume directory traversal, "
                    "with matching both-endian extent/length fields, safe paths, and complete "
                    "image-bounded ranges were copied. Valid adjacent multi-extent chains are "
                    "assembled in record order; interleaved or incomplete layouts remain metadata-only."
                ),
                source="builtin_iso9660_extractor",
                supporting_evidence=evidence[:128],
            ))
        return result

    def extract_iso9660_boot_images(self, artifact: Artifact) -> ExtractionResult:
        """Copy only size-determinable bootable El Torito default images."""
        result = ExtractionResult()
        observation = next(
            (
                item for item in self.workspace.database.observations(artifact.id)
                if item.key == "archive.iso9660.el_torito_boot_images"
                and isinstance(item.value, list)
            ),
            None,
        )
        if observation is None:
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_el_torito")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"El Torito source open failed: {exc}")
            return result
        with source_stream:
            for index, record in enumerate(observation.value):
                if not isinstance(record, dict) or record.get("extraction_eligible") is not True:
                    continue
                output: Path | None = None
                name = record.get("logical_name")
                entry_offset = record.get("offset")
                entry_raw_hex = record.get("raw_hex")
                data_offset = record.get("data_offset")
                data_length = record.get("data_length")
                validation_entry = record.get("catalog_validation_entry")
                validation_offset = (
                    validation_entry.get("offset")
                    if isinstance(validation_entry, dict) else None
                )
                validation_raw_hex = (
                    validation_entry.get("raw_hex")
                    if isinstance(validation_entry, dict) else None
                )
                section_header = record.get("section_header")
                section_header_offset = (
                    section_header.get("offset")
                    if isinstance(section_header, dict) else None
                )
                section_header_raw_hex = (
                    section_header.get("raw_hex")
                    if isinstance(section_header, dict) else None
                )
                if (
                    not isinstance(name, str) or not name or self._unsafe_name(name)
                    or not isinstance(entry_offset, int) or entry_offset < 0
                    or not isinstance(entry_raw_hex, str)
                    or not isinstance(data_offset, int) or data_offset < 0
                    or not isinstance(data_length, int) or data_length <= 0
                    or data_offset + data_length > artifact.size
                    or not isinstance(validation_offset, int) or validation_offset < 0
                    or not isinstance(validation_raw_hex, str)
                ):
                    result.errors.append(f"skipped El Torito image {name!r}: invalid observed range")
                    continue
                reason = self.can_register(artifact, data_length)
                if reason:
                    result.errors.append(f"skipped El Torito image {name!r}: {reason}")
                    continue
                try:
                    source_stream.seek(validation_offset)
                    if source_stream.read(32).hex() != validation_raw_hex:
                        raise RuntimeError(
                            "catalog validation entry no longer matches triage provenance"
                        )
                    if isinstance(section_header_offset, int):
                        source_stream.seek(section_header_offset)
                        if source_stream.read(32).hex() != section_header_raw_hex:
                            raise RuntimeError(
                                "catalog section header no longer matches triage provenance"
                            )
                    source_stream.seek(entry_offset)
                    if source_stream.read(32).hex() != entry_raw_hex:
                        raise RuntimeError("catalog entry no longer matches triage provenance")
                    target_root.mkdir(parents=True, exist_ok=True)
                    output = target_root / f"{index:03d}_{safe_name(name)}"
                    source_stream.seek(data_offset)
                    written = 0
                    with output.open("xb") as writer:
                        remaining = data_length
                        while remaining:
                            chunk = source_stream.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise RuntimeError("boot-image read ended before declared length")
                            writer.write(chunk)
                            written += len(chunk)
                            remaining -= len(chunk)
                    if written != data_length:
                        raise RuntimeError("boot-image length mismatch")
                except (OSError, RuntimeError) as exc:
                    if output is not None:
                        output.unlink(missing_ok=True)
                    result.errors.append(f"failed El Torito image {name!r}: {exc}")
                    continue
                child = self.register_file(output, artifact, name)
                if child is None:
                    result.errors.append(
                        f"skipped El Torito image {name!r}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};source_observation_id:{observation.id};"
                    f"source_observation_key:{observation.key};catalog_entry_offset:{entry_offset};"
                    f"catalog_offset:{record.get('catalog_offset')};"
                    f"data_offset:{data_offset};data_length:{data_length};"
                    f"data_length_source:{record.get('data_length_source')};"
                    f"boot_record:{record.get('boot_record')};"
                    f"validation_entry:{record.get('catalog_validation_entry')};"
                    f"section_header:{record.get('section_header')};"
                    f"initial_entry:{record}"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Extracted {len(result.artifacts)} El Torito boot image(s)",
                category="boot_image_extraction",
                severity="info",
                confidence=0.99,
                explanation=(
                    "Only bootable default catalog entries with a valid validation checksum/key, "
                    "an exact catalog record, a deterministic no-emulation or floppy size, and a "
                    "complete ISO-bounded range were copied."
                ),
                source="builtin_el_torito_extractor",
                supporting_evidence=evidence[:16],
            ))
        return result

    def extract_single_stream(self, artifact: Artifact) -> ExtractionResult:
        source = self.workspace.resolve_stored_path(artifact.path)
        try:
            with source.open("rb") as probe:
                header = probe.read(6)
        except OSError as exc:
            return ExtractionResult(errors=[f"compressed-stream probe failed for {artifact.logical_name}: {exc}"])
        opener = None
        suffixes: tuple[str, ...] = ()
        kind = ""
        if header.startswith(b"BZh"):
            opener, suffixes, kind = bz2.open, (".bz2", ".tbz", ".tbz2"), "bzip2"
        elif header.startswith(b"\xfd7zXZ\x00"):
            opener, suffixes, kind = lzma.open, (".xz", ".txz"), "xz"
        if opener is None:
            return ExtractionResult()
        result = ExtractionResult()
        name = Path(artifact.logical_name).name
        lower = name.lower()
        for suffix in suffixes:
            if lower.endswith(suffix):
                name = name[: -len(suffix)]
                break
        output = self.workspace.path("extracted", artifact.id, f"builtin_{kind}", safe_name(name or "decompressed"))
        output.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with opener(source, "rb") as reader, output.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    written += len(chunk)
                    if written > self.limits.max_single_artifact_size or self.extracted_bytes + written > self.limits.max_extracted_bytes:
                        raise RuntimeError(f"decompressed {kind} data exceeds configured extraction limit")
                    writer.write(chunk)
        except (OSError, EOFError, lzma.LZMAError, RuntimeError) as exc:
            output.unlink(missing_ok=True)
            result.errors.append(f"{kind} extraction failed for {artifact.logical_name}: {exc}")
            return result
        child = self.register_file(output, artifact, name or "decompressed")
        if child:
            result.artifacts.append(child)
            result.extracted_bytes = written
            result.findings.append(
                Finding(
                    artifact_id=artifact.id,
                    title=f"Extracted {kind} payload",
                    category="archive_extraction",
                    severity="info",
                    confidence=1.0,
                    explanation=f"A {kind} stream was decompressed with configured extraction limits.",
                    source=f"builtin_{kind}_extractor",
                    supporting_evidence=[child.id],
                )
            )
        return result

    def extract_pcap_http(self, artifact: Artifact) -> ExtractionResult:
        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_pcap_http")
        target_root.mkdir(parents=True, exist_ok=True)
        extracted_objects: list[tuple[Artifact, object]] = []
        decoded_objects: list[tuple[Artifact, object]] = []
        multipart_objects: list[tuple[Artifact, object]] = []
        ftp_objects: list[tuple[Artifact, object]] = []
        smtp_objects: list[tuple[Artifact, object]] = []
        smtp_bdat_objects: list[tuple[Artifact, object]] = []
        pop3_objects: list[tuple[Artifact, object]] = []
        imap_objects: list[tuple[Artifact, object]] = []
        smtp_starttls_transitions: list[object] = []
        imap_starttls_transitions: list[object] = []
        pop3_stls_transitions: list[object] = []
        ftp_auth_tls_transitions: list[object] = []
        smb2_create_operations: list[object] = []
        smb2_negotiate_operations: list[object] = []
        smb2_write_objects: list[tuple[Artifact, object]] = []
        smb2_read_objects: list[tuple[Artifact, object]] = []
        smb2_close_operations: list[object] = []
        smb2_set_info_operations: list[object] = []
        smb2_directory_listings: list[tuple[Artifact, object]] = []
        smb3_transform_records: list[object] = []
        smtp_attachments: list[tuple[Artifact, Artifact, str, str | None, str | None, str | None]] = []
        pop3_attachments: list[tuple[Artifact, Artifact, str, str | None, str | None, str | None]] = []
        imap_attachments: list[tuple[Artifact, Artifact, str, str | None, str | None, str | None]] = []
        try:
            for index, response in enumerate(iter_http_response_objects(
                source, max_objects=min(100, self.limits.max_artifact_count),
                max_body_bytes=self.limits.max_single_artifact_size,
            )):
                reason = self.can_register(artifact, len(response.body))
                if reason:
                    result.errors.append(f"skipped HTTP object {response.logical_name!r}: {reason}")
                    continue
                output = target_root / f"{index:05d}_{safe_name(response.logical_name)}"
                output.write_bytes(response.body)
                child = self.register_file(output, artifact, response.logical_name)
                if child:
                    result.artifacts.append(child)
                    extracted_objects.append((child, response))
                    result.extracted_bytes += len(response.body)
                    if response.decoded_content_encoding:
                        decoded_objects.append((child, response))
                    if response.multipart_part_index is not None:
                        multipart_objects.append((child, response))
                    if response.decode_error:
                        result.errors.append(f"HTTP object {response.logical_name!r}: {response.decode_error}")
                    if response.multipart_decode_error:
                        result.errors.append(f"HTTP multipart part {response.logical_name!r}: {response.multipart_decode_error}")
        except OSError as exc:
            result.errors.append(f"PCAP HTTP extraction failed: {exc}")
        try:
            for index, response in enumerate(iter_ftp_retr_objects(
                source, max_objects=min(32, self.limits.max_artifact_count),
                max_body_bytes=self.limits.max_single_artifact_size,
            )):
                reason = self.can_register(artifact, len(response.body))
                if reason:
                    result.errors.append(f"skipped FTP RETR object {response.logical_name!r}: {reason}")
                    continue
                output = target_root / f"ftp_{index:05d}_{safe_name(response.logical_name)}"
                output.write_bytes(response.body)
                child = self.register_file(output, artifact, response.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(response.body)
                    ftp_objects.append((child, response))
        except OSError as exc:
            result.errors.append(f"PCAP FTP extraction failed: {exc}")
        try:
            ftp_auth_tls_transitions = list(iter_ftp_auth_tls_transitions(source))
        except OSError as exc:
            result.errors.append(f"PCAP FTP AUTH TLS scan failed: {exc}")
        try:
            smb3_transform_records = list(iter_smb3_transform_records(source))
        except OSError as exc:
            result.errors.append(f"PCAP SMB3 transform scan failed: {exc}")
        try:
            smb2_negotiate_operations = list(iter_smb2_negotiate_operations(source))
        except OSError as exc:
            result.errors.append(f"PCAP SMB2 NEGOTIATE scan failed: {exc}")
        try:
            smb2_create_operations = list(iter_smb2_create_operations(source))
        except OSError as exc:
            result.errors.append(f"PCAP SMB2 CREATE scan failed: {exc}")
        try:
            for index, uploaded in enumerate(iter_smb2_write_objects(source, max_body_bytes=self.limits.max_single_artifact_size)):
                reason = self.can_register(artifact, len(uploaded.body))
                if reason:
                    result.errors.append(f"skipped SMB2 WRITE object {uploaded.logical_name!r}: {reason}")
                    continue
                output = target_root / f"smb2_write_{index:05d}_{safe_name(uploaded.logical_name)}"
                output.write_bytes(uploaded.body)
                child = self.register_file(output, artifact, uploaded.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(uploaded.body)
                    smb2_write_objects.append((child, uploaded))
        except OSError as exc:
            result.errors.append(f"PCAP SMB2 WRITE extraction failed: {exc}")
        try:
            for index, downloaded in enumerate(iter_smb2_read_objects(source, max_body_bytes=self.limits.max_single_artifact_size)):
                reason = self.can_register(artifact, len(downloaded.body))
                if reason:
                    result.errors.append(f"skipped SMB2 READ object {downloaded.logical_name!r}: {reason}")
                    continue
                output = target_root / f"smb2_read_{index:05d}_{safe_name(downloaded.logical_name)}"
                output.write_bytes(downloaded.body)
                child = self.register_file(output, artifact, downloaded.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(downloaded.body)
                    smb2_read_objects.append((child, downloaded))
        except OSError as exc:
            result.errors.append(f"PCAP SMB2 READ extraction failed: {exc}")
        try:
            smb2_close_operations = list(iter_smb2_close_operations(source))
        except OSError as exc:
            result.errors.append(f"PCAP SMB2 CLOSE scan failed: {exc}")
        try:
            smb2_set_info_operations = list(iter_smb2_set_info_operations(source))
        except OSError as exc:
            result.errors.append(f"PCAP SMB2 SET_INFO scan failed: {exc}")
        try:
            for index, listing in enumerate(iter_smb2_directory_listings(source)):
                reason = self.can_register(artifact, len(listing.body))
                if reason:
                    result.errors.append(f"skipped SMB2 directory listing {listing.logical_name!r}: {reason}")
                    continue
                output = target_root / f"smb2_listing_{index:05d}_{safe_name(listing.logical_name)}"
                output.write_bytes(listing.body)
                child = self.register_file(output, artifact, listing.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(listing.body)
                    smb2_directory_listings.append((child, listing))
        except OSError as exc:
            result.errors.append(f"PCAP SMB2 QUERY_DIRECTORY extraction failed: {exc}")
        try:
            for index, message in enumerate(iter_smtp_data_objects(source, max_body_bytes=self.limits.max_single_artifact_size)):
                if self.can_register(artifact, len(message.body)):
                    continue
                output = target_root / f"smtp_{index:05d}_{safe_name(message.logical_name)}"
                output.write_bytes(message.body)
                child = self.register_file(output, artifact, message.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(message.body)
                    smtp_objects.append((child, message))
                    try:
                        parsed = BytesParser(policy=policy.default).parsebytes(message.body)
                        for part_index, part in enumerate(parsed.walk()):
                            disposition = part.get_content_disposition()
                            content_id = part.get("Content-ID")
                            if part_index >= 32 or (disposition != "attachment" and not (disposition == "inline" and content_id)):
                                continue
                            if part.get_content_type() == "message/rfc822":
                                nested = part.get_payload()
                                payload = nested[0].as_bytes(policy=policy.default) if isinstance(nested, list) and len(nested) == 1 else None
                            else:
                                payload = part.get_payload(decode=True)
                            if not isinstance(payload, bytes) or self.can_register(child, len(payload)):
                                continue
                            name = _smtp_attachment_name(part, part_index)
                            attachment_path = target_root / f"smtp_attachment_{index:05d}_{part_index:02d}_{safe_name(name)}"
                            attachment_path.write_bytes(payload)
                            attachment = self.register_file(attachment_path, child, name)
                            if attachment:
                                result.artifacts.append(attachment)
                                result.extracted_bytes += len(payload)
                                smtp_attachments.append((child, attachment, part.get_content_type(), part.get("Content-Transfer-Encoding"), disposition, content_id))
                    except (ValueError, OSError):
                        result.errors.append(f"SMTP MIME attachment parsing failed for {message.logical_name!r}")
        except OSError as exc:
            result.errors.append(f"PCAP SMTP extraction failed: {exc}")
        try:
            for index, message in enumerate(iter_smtp_bdat_objects(source, max_body_bytes=self.limits.max_single_artifact_size)):
                if self.can_register(artifact, len(message.body)):
                    continue
                output = target_root / f"smtp_bdat_{index:05d}_{safe_name(message.logical_name)}"
                output.write_bytes(message.body)
                child = self.register_file(output, artifact, message.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(message.body)
                    smtp_bdat_objects.append((child, message))
                    try:
                        parsed = BytesParser(policy=policy.default).parsebytes(message.body)
                        for part_index, part in enumerate(parsed.walk()):
                            disposition = part.get_content_disposition()
                            content_id = part.get("Content-ID")
                            if part_index >= 32 or (disposition != "attachment" and not (disposition == "inline" and content_id)):
                                continue
                            if part.get_content_type() == "message/rfc822":
                                nested = part.get_payload()
                                payload = nested[0].as_bytes(policy=policy.default) if isinstance(nested, list) and len(nested) == 1 else None
                            else:
                                payload = part.get_payload(decode=True)
                            if not isinstance(payload, bytes) or self.can_register(child, len(payload)):
                                continue
                            name = _smtp_attachment_name(part, part_index)
                            attachment_path = target_root / f"smtp_bdat_attachment_{index:05d}_{part_index:02d}_{safe_name(name)}"
                            attachment_path.write_bytes(payload)
                            attachment = self.register_file(attachment_path, child, name)
                            if attachment:
                                result.artifacts.append(attachment)
                                result.extracted_bytes += len(payload)
                                smtp_attachments.append((child, attachment, part.get_content_type(), part.get("Content-Transfer-Encoding"), disposition, content_id))
                    except (ValueError, OSError):
                        result.errors.append(f"SMTP BDAT MIME attachment parsing failed for {message.logical_name!r}")
        except OSError as exc:
            result.errors.append(f"PCAP SMTP BDAT extraction failed: {exc}")
        try:
            for index, message in enumerate(iter_pop3_retr_objects(source, max_body_bytes=self.limits.max_single_artifact_size)):
                if self.can_register(artifact, len(message.body)):
                    continue
                output = target_root / f"pop3_retr_{index:05d}_{safe_name(message.logical_name)}"
                output.write_bytes(message.body)
                child = self.register_file(output, artifact, message.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(message.body)
                    pop3_objects.append((child, message))
                    try:
                        parsed = BytesParser(policy=policy.default).parsebytes(message.body)
                        for part_index, part in enumerate(parsed.walk()):
                            disposition = part.get_content_disposition()
                            content_id = part.get("Content-ID")
                            if part_index >= 32 or (disposition != "attachment" and not (disposition == "inline" and content_id)):
                                continue
                            if part.get_content_type() == "message/rfc822":
                                nested = part.get_payload()
                                payload = nested[0].as_bytes(policy=policy.default) if isinstance(nested, list) and len(nested) == 1 else None
                            else:
                                payload = part.get_payload(decode=True)
                            if not isinstance(payload, bytes) or self.can_register(child, len(payload)):
                                continue
                            name = _smtp_attachment_name(part, part_index)
                            attachment_path = target_root / f"pop3_attachment_{index:05d}_{part_index:02d}_{safe_name(name)}"
                            attachment_path.write_bytes(payload)
                            attachment = self.register_file(attachment_path, child, name)
                            if attachment:
                                result.artifacts.append(attachment)
                                result.extracted_bytes += len(payload)
                                pop3_attachments.append((child, attachment, part.get_content_type(), part.get("Content-Transfer-Encoding"), disposition, content_id))
                    except (ValueError, OSError):
                        result.errors.append(f"POP3 MIME attachment parsing failed for {message.logical_name!r}")
        except OSError as exc:
            result.errors.append(f"PCAP POP3 extraction failed: {exc}")
        try:
            pop3_stls_transitions = list(iter_pop3_stls_transitions(source))
        except OSError as exc:
            result.errors.append(f"PCAP POP3 STLS scan failed: {exc}")
        try:
            for index, message in enumerate(iter_imap_fetch_objects(source, max_body_bytes=self.limits.max_single_artifact_size)):
                if self.can_register(artifact, len(message.body)):
                    continue
                output = target_root / f"imap_fetch_{index:05d}_{safe_name(message.logical_name)}"
                output.write_bytes(message.body)
                child = self.register_file(output, artifact, message.logical_name)
                if child:
                    result.artifacts.append(child)
                    result.extracted_bytes += len(message.body)
                    imap_objects.append((child, message))
                    try:
                        parsed = BytesParser(policy=policy.default).parsebytes(message.body)
                        for part_index, part in enumerate(parsed.walk()):
                            disposition = part.get_content_disposition()
                            content_id = part.get("Content-ID")
                            if part_index >= 32 or (disposition != "attachment" and not (disposition == "inline" and content_id)):
                                continue
                            if part.get_content_type() == "message/rfc822":
                                nested = part.get_payload()
                                payload = nested[0].as_bytes(policy=policy.default) if isinstance(nested, list) and len(nested) == 1 else None
                            else:
                                payload = part.get_payload(decode=True)
                            if not isinstance(payload, bytes) or self.can_register(child, len(payload)):
                                continue
                            name = _smtp_attachment_name(part, part_index)
                            attachment_path = target_root / f"imap_attachment_{index:05d}_{part_index:02d}_{safe_name(name)}"
                            attachment_path.write_bytes(payload)
                            attachment = self.register_file(attachment_path, child, name)
                            if attachment:
                                result.artifacts.append(attachment)
                                result.extracted_bytes += len(payload)
                                imap_attachments.append((child, attachment, part.get_content_type(), part.get("Content-Transfer-Encoding"), disposition, content_id))
                    except (ValueError, OSError):
                        result.errors.append(f"IMAP MIME attachment parsing failed for {message.logical_name!r}")
        except OSError as exc:
            result.errors.append(f"PCAP IMAP extraction failed: {exc}")
        try:
            imap_starttls_transitions = list(iter_imap_starttls_transitions(source))
        except OSError as exc:
            result.errors.append(f"PCAP IMAP STARTTLS scan failed: {exc}")
        try:
            smtp_starttls_transitions = list(iter_smtp_starttls_transitions(source))
            for transition in smtp_starttls_transitions:
                result.errors.append(
                    f"SMTP STARTTLS transition {transition.source}:{transition.source_port}->{transition.destination}:{transition.destination_port} "
                    f"at packets {transition.command_packet_index}/{transition.ready_response_packet_index}; native plaintext recovery suppressed"
                )
        except OSError as exc:
            result.errors.append(f"PCAP SMTP STARTTLS scan failed: {exc}")
        if extracted_objects:
            result.findings.append(Finding(
                artifact_id=artifact.id, title=f"Extracted {len(extracted_objects)} HTTP object(s)",
                category="pcap_http_extraction", severity="info", confidence=0.9,
                explanation="Complete length-delimited or chunked HTTP response bodies were recovered from bounded classic-PCAP TCP reassembly.",
                source="builtin_pcap_http_extractor",
                supporting_evidence=[
                    (
                        f"child_artifact_id={child.id};logical_name={response.logical_name};"
                        f"flow={response.source or ''}:{response.source_port or ''}->"
                        f"{response.destination or ''}:{response.destination_port or ''};"
                        f"packet_indices={','.join(map(str, response.packet_indices))};"
                        f"packet_provenance_complete={response.packet_provenance_complete};"
                        f"request_method={response.request_method or ''};request_host={response.request_host or ''};"
                        f"request_target={response.request_target or ''};"
                        f"request_packet_indices={','.join(map(str, response.request_packet_indices))};"
                        f"request_packet_provenance_complete={response.request_packet_provenance_complete}"
                    )
                    for child, response in extracted_objects
                ],
            ))
        for child, response in decoded_objects:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title="Decoded HTTP content-encoded object",
                category="pcap_http_content_decoding",
                severity="info",
                confidence=0.9,
                explanation="A bounded HTTP response Content-Encoding chain was decoded before child-artifact registration; the child retains the decoded bytes while the finding preserves the original encoding and sizes.",
                source="builtin_pcap_http_extractor",
                supporting_evidence=[
                    f"child_artifact_id={child.id}",
                    f"logical_name={response.logical_name}",
                    f"content_encoding={','.join(response.content_encoding)}",
                    f"decoded_in_reverse_order={','.join(response.decoded_content_encoding)}",
                    f"encoded_size={response.encoded_size}",
                    f"decoded_size={len(response.body)}",
                    f"flow={response.source or ''}:{response.source_port or ''}->{response.destination or ''}:{response.destination_port or ''}",
                    f"packet_indices={','.join(map(str, response.packet_indices))}",
                    f"packet_provenance_complete={response.packet_provenance_complete}",
                    f"request_method={response.request_method or ''}",
                    f"request_host={response.request_host or ''}",
                    f"request_target={response.request_target or ''}",
                    f"request_packet_indices={','.join(map(str, response.request_packet_indices))}",
                    f"request_packet_provenance_complete={response.request_packet_provenance_complete}",
                ],
            ))
        for child, response in multipart_objects:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title="Extracted HTTP multipart response part",
                category="pcap_http_multipart_extraction",
                severity="info",
                confidence=0.9,
                explanation="A complete multipart HTTP response part was recovered from a declared boundary and registered as an independent child artifact.",
                source="builtin_pcap_http_extractor",
                supporting_evidence=[
                    f"child_artifact_id={child.id}",
                    f"multipart_part_index={response.multipart_part_index}",
                    f"logical_name={response.logical_name}",
                    f"content_type={response.content_type or ''}",
                    f"content_disposition={response.content_disposition or ''}",
                    f"content_transfer_encoding={response.multipart_content_transfer_encoding or ''}",
                    f"decoded_content_transfer_encoding={response.decoded_multipart_content_transfer_encoding or ''}",
                    f"content_transfer_decode_error={response.multipart_decode_error or ''}",
                    f"flow={response.source or ''}:{response.source_port or ''}->{response.destination or ''}:{response.destination_port or ''}",
                    f"packet_indices={','.join(map(str, response.packet_indices))}",
                    f"packet_provenance_complete={response.packet_provenance_complete}",
                    f"request_method={response.request_method or ''}",
                    f"request_host={response.request_host or ''}",
                    f"request_target={response.request_target or ''}",
                    f"request_packet_indices={','.join(map(str, response.request_packet_indices))}",
                    f"request_packet_provenance_complete={response.request_packet_provenance_complete}",
                ],
            ))
        for child, response in ftp_objects:
            result.findings.append(Finding(
                artifact_id=artifact.id, title=f"Extracted FTP {response.transfer_command} data object",
                category="pcap_ftp_retr_extraction", severity="info", confidence=0.9,
                explanation="A bounded FTP transfer was correlated from its control command, exact inverse PASV response, and observed data flow.",
                source="builtin_pcap_ftp_extractor",
                supporting_evidence=[
                    f"child_artifact_id={child.id}", f"logical_name={response.logical_name}",
                    f"transfer_command={response.transfer_command}",
                    f"flow={response.source}:{response.source_port}->{response.destination}:{response.destination_port}",
                    f"packet_indices={','.join(map(str, response.packet_indices))}",
                    f"retr_command_packet_index={response.command_packet_index}",
                    f"data_endpoint_setup_packet_index={response.endpoint_setup_packet_index}",
                    f"completion_code={response.completion_code if response.completion_code is not None else ''}",
                    f"completion_packet_index={response.completion_packet_index if response.completion_packet_index is not None else ''}",
                ],
            ))
        for child, message in smtp_objects:
            result.findings.append(Finding(artifact_id=artifact.id, title="Extracted SMTP DATA message", category="pcap_smtp_data_extraction", severity="info", confidence=0.9, explanation="A complete SMTP DATA body followed an exact DATA/354 control exchange.", source="builtin_pcap_smtp_extractor", supporting_evidence=[f"child_artifact_id={child.id}", f"packet_indices={','.join(map(str, message.packet_indices))}", f"data_command_packet_index={message.data_command_packet_index}", f"ready_response_packet_index={message.ready_response_packet_index}", f"acceptance_code={message.acceptance_code if message.acceptance_code is not None else ''}", f"acceptance_packet_index={message.acceptance_packet_index if message.acceptance_packet_index is not None else ''}", f"forwarding_code={message.forwarding_code if message.forwarding_code is not None else ''}", f"forwarding_packet_index={message.forwarding_packet_index if message.forwarding_packet_index is not None else ''}", f"rejection_code={message.rejection_code if message.rejection_code is not None else ''}", f"rejection_packet_index={message.rejection_packet_index if message.rejection_packet_index is not None else ''}"]))
        for child, message in smtp_bdat_objects:
            result.findings.append(Finding(artifact_id=artifact.id, title="Extracted SMTP BDAT message", category="pcap_smtp_bdat_extraction", severity="info", confidence=0.9, explanation="Exact declared SMTP BDAT chunk lengths formed a complete LAST message.", source="builtin_pcap_smtp_extractor", supporting_evidence=[f"child_artifact_id={child.id}", f"packet_indices={','.join(map(str, message.packet_indices))}", f"bdat_command_packet_indices={','.join(map(str, message.command_packet_indices))}", f"final_response_code={message.final_response_code if message.final_response_code is not None else ''}", f"final_response_packet_index={message.final_response_packet_index if message.final_response_packet_index is not None else ''}"]))
        for child, message in pop3_objects:
            result.findings.append(Finding(artifact_id=artifact.id, title="Extracted POP3 RETR message", category="pcap_pop3_retr_extraction", severity="info", confidence=0.9, explanation="A complete POP3 RETR multiline response followed an exact RETR/+OK control exchange.", source="builtin_pcap_pop3_extractor", supporting_evidence=[f"child_artifact_id={child.id}", f"packet_indices={','.join(map(str, message.packet_indices))}", f"retr_command_packet_index={message.retr_command_packet_index}", f"positive_response_packet_index={message.positive_response_packet_index}"]))
        for child, message in imap_objects:
            result.findings.append(Finding(artifact_id=artifact.id, title="Extracted IMAP FETCH message", category="pcap_imap_fetch_extraction", severity="info", confidence=0.9, explanation="A complete declared IMAP FETCH message literal ended with its matching tagged OK response.", source="builtin_pcap_imap_extractor", supporting_evidence=[f"child_artifact_id={child.id}", f"packet_indices={','.join(map(str, message.packet_indices))}", f"fetch_command_packet_index={message.fetch_command_packet_index}", f"literal_response_packet_index={message.literal_response_packet_index}", f"completion_packet_index={message.completion_packet_index}"]))
        for transition in smtp_starttls_transitions:
            result.findings.append(Finding(artifact_id=artifact.id, title="Observed SMTP STARTTLS transition", category="pcap_smtp_starttls_transition", severity="info", confidence=0.95, explanation="STARTTLS and its exact inverse 220 response were observed; subsequent bytes on this flow were not interpreted as plaintext SMTP.", source="builtin_pcap_smtp_extractor", supporting_evidence=[f"flow={transition.source}:{transition.source_port}->{transition.destination}:{transition.destination_port}", f"starttls_command_packet_index={transition.command_packet_index}", f"ready_response_packet_index={transition.ready_response_packet_index}"]))
        for transition in imap_starttls_transitions:
            result.findings.append(Finding(artifact_id=artifact.id, title="Observed IMAP STARTTLS transition", category="pcap_imap_starttls_transition", severity="info", confidence=0.95, explanation="A tagged STARTTLS command and exact inverse tagged OK response were observed; subsequent bytes on this flow were not interpreted as plaintext IMAP.", source="builtin_pcap_imap_extractor", supporting_evidence=[f"tag={transition.tag}", f"flow={transition.source}:{transition.source_port}->{transition.destination}:{transition.destination_port}", f"starttls_command_packet_index={transition.command_packet_index}", f"ready_response_packet_index={transition.ready_response_packet_index}"]))
        for transition in pop3_stls_transitions:
            result.findings.append(Finding(artifact_id=artifact.id, title="Observed POP3 STLS transition", category="pcap_pop3_stls_transition", severity="info", confidence=0.95, explanation="An STLS command and exact inverse +OK response were observed; subsequent bytes on this flow were not interpreted as plaintext POP3.", source="builtin_pcap_pop3_extractor", supporting_evidence=[f"flow={transition.source}:{transition.source_port}->{transition.destination}:{transition.destination_port}", f"stls_command_packet_index={transition.command_packet_index}", f"ready_response_packet_index={transition.ready_response_packet_index}"]))
        for transition in ftp_auth_tls_transitions:
            result.findings.append(Finding(artifact_id=artifact.id, title="Observed FTP AUTH TLS transition", category="pcap_ftp_auth_tls_transition", severity="info", confidence=0.95, explanation="An AUTH TLS command and exact inverse 234 response were observed; subsequent control/data state on this endpoint pair was not interpreted as plaintext FTP.", source="builtin_pcap_ftp_extractor", supporting_evidence=[f"flow={transition.source}:{transition.source_port}->{transition.destination}:{transition.destination_port}", f"auth_tls_command_packet_index={transition.command_packet_index}", f"ready_response_packet_index={transition.ready_response_packet_index}"]))
        for transform in smb3_transform_records:
            result.findings.append(Finding(artifact_id=artifact.id, title=f"Observed SMB3 {transform.transform_type} transform", category="pcap_smb3_transform", severity="info", confidence=0.95, explanation="A complete bounded Direct TCP SMB3 transform header was inventoried with packet provenance. Protected or compressed payload bytes were not decoded.", source="builtin_pcap_smb3_parser", supporting_evidence=[f"transform_type={transform.transform_type}", f"declared_original_size={transform.declared_original_size}", f"flags=0x{transform.flags:04x}", f"framed_size={transform.framed_size}", f"transformed_payload_size={transform.transformed_payload_size}", f"session_id={transform.session_id if transform.session_id is not None else ''}", f"signature_hex={transform.signature_hex or ''}", f"nonce_hex={transform.nonce_hex or ''}", f"compression_algorithm={transform.compression_algorithm if transform.compression_algorithm is not None else ''}", f"compression_algorithm_name={transform.compression_algorithm_name or ''}", f"data_offset={transform.data_offset if transform.data_offset is not None else ''}", f"flow={transform.source}:{transform.source_port}->{transform.destination}:{transform.destination_port}", f"packet_indices={','.join(map(str, transform.packet_indices))}"]))
        for operation in smb2_negotiate_operations:
            result.findings.append(Finding(artifact_id=artifact.id, title="Observed SMB2 NEGOTIATE exchange", category="pcap_smb2_negotiate_operation", severity="info", confidence=0.95, explanation="A bounded SMB2 NEGOTIATE request was inventoried and correlated with its exact inverse response when present. GUIDs and FILETIMEs remain raw wire evidence.", source="builtin_pcap_smb2_parser", supporting_evidence=[f"offered_dialects={','.join(f'0x{item:04x}' for item in operation.offered_dialects)}", f"offered_dialect_names={','.join(operation.offered_dialect_names)}", f"request_security_mode=0x{operation.request_security_mode:04x}", f"request_signing_enabled={bool(operation.request_security_mode & 1)}", f"request_signing_required={bool(operation.request_security_mode & 2)}", f"request_capabilities=0x{operation.request_capabilities:08x}", f"client_guid_hex={operation.client_guid_hex}", f"request_context_count={operation.request_context_count}", f"message_id={operation.message_id}", f"flow={operation.source}:{operation.source_port}->{operation.destination}:{operation.destination_port}", f"packet_indices={','.join(map(str, operation.packet_indices))}", f"response_status={f'0x{operation.response_status:08x}' if operation.response_status is not None else ''}", f"selected_dialect={f'0x{operation.selected_dialect:04x}' if operation.selected_dialect is not None else ''}", f"selected_dialect_name={operation.selected_dialect_name or ''}", f"selected_dialect_offered={operation.selected_dialect in operation.offered_dialects if operation.selected_dialect is not None else ''}", f"response_security_mode={f'0x{operation.response_security_mode:04x}' if operation.response_security_mode is not None else ''}", f"response_signing_enabled={bool(operation.response_security_mode & 1) if operation.response_security_mode is not None else ''}", f"response_signing_required={bool(operation.response_security_mode & 2) if operation.response_security_mode is not None else ''}", f"response_capabilities={f'0x{operation.response_capabilities:08x}' if operation.response_capabilities is not None else ''}", f"server_guid_hex={operation.server_guid_hex or ''}", f"max_transact_size={operation.max_transact_size if operation.max_transact_size is not None else ''}", f"max_read_size={operation.max_read_size if operation.max_read_size is not None else ''}", f"max_write_size={operation.max_write_size if operation.max_write_size is not None else ''}", f"system_filetime={operation.system_filetime if operation.system_filetime is not None else ''}", f"server_start_filetime={operation.server_start_filetime if operation.server_start_filetime is not None else ''}", f"response_context_count={operation.response_context_count if operation.response_context_count is not None else ''}", f"response_packet_indices={','.join(map(str, operation.response_packet_indices))}"]))
        for operation in smb2_create_operations:
            result.findings.append(Finding(artifact_id=artifact.id, title="Observed SMB2 CREATE request", category="pcap_smb2_create_operation", severity="info", confidence=0.92, explanation="A complete bounded SMB2 CREATE request exposed a declared UTF-16LE path and protocol identifiers. Exact inverse TREE_CONNECT/CREATE responses are correlated when present; paths are metadata only and were not opened.", source="builtin_pcap_smb2_parser", supporting_evidence=[f"filename={operation.filename}", f"share_path={operation.share_path or ''}", f"message_id={operation.message_id}", f"session_id={operation.session_id}", f"tree_id={operation.tree_id}", f"desired_access=0x{operation.desired_access:08x}", f"create_disposition={operation.create_disposition}", f"create_options=0x{operation.create_options:08x}", f"flow={operation.source}:{operation.source_port}->{operation.destination}:{operation.destination_port}", f"packet_indices={','.join(map(str, operation.packet_indices))}", f"response_status={f'0x{operation.response_status:08x}' if operation.response_status is not None else ''}", f"persistent_file_id={operation.persistent_file_id if operation.persistent_file_id is not None else ''}", f"volatile_file_id={operation.volatile_file_id if operation.volatile_file_id is not None else ''}", f"response_packet_indices={','.join(map(str, operation.response_packet_indices))}", f"tree_connect_packet_indices={','.join(map(str, operation.tree_connect_packet_indices))}", f"tree_connect_response_packet_indices={','.join(map(str, operation.tree_connect_response_packet_indices))}"]))
        for child, uploaded in smb2_write_objects:
            result.findings.append(Finding(artifact_id=artifact.id, title="Recovered SMB2 WRITE upload", category="pcap_smb2_write_extraction", severity="info", confidence=0.94, explanation="Contiguous SMB2 WRITE requests beginning at file offset zero were linked to a successful CREATE FileId and exact successful WRITE responses before child registration. When a successful CLOSE was captured, its EndOfFile exactly matched the recovered length.", source="builtin_pcap_smb2_parser", supporting_evidence=[f"child_artifact_id={child.id}", f"logical_name={child.logical_name}", f"share_path={uploaded.share_path or ''}", f"smb_path={uploaded.smb_path}", f"persistent_file_id={uploaded.persistent_file_id}", f"volatile_file_id={uploaded.volatile_file_id}", f"flow={uploaded.source}:{uploaded.source_port}->{uploaded.destination}:{uploaded.destination_port}", f"message_ids={','.join(map(str, uploaded.message_ids))}", f"packet_indices={','.join(map(str, uploaded.packet_indices))}", f"response_packet_indices={','.join(map(str, uploaded.response_packet_indices))}", f"close_end_of_file={uploaded.close_end_of_file if uploaded.close_end_of_file is not None else ''}", f"close_size_match={len(uploaded.body) == uploaded.close_end_of_file if uploaded.close_end_of_file is not None else ''}", f"close_packet_indices={','.join(map(str, uploaded.close_packet_indices))}", f"close_response_packet_indices={','.join(map(str, uploaded.close_response_packet_indices))}"]))
        for child, downloaded in smb2_read_objects:
            result.findings.append(Finding(artifact_id=artifact.id, title="Recovered SMB2 READ download", category="pcap_smb2_read_extraction", severity="info", confidence=0.94, explanation="Contiguous successful SMB2 READ responses beginning at file offset zero were linked to requests for a successful CREATE FileId before child registration. When a successful CLOSE was captured, its EndOfFile exactly matched the recovered length.", source="builtin_pcap_smb2_parser", supporting_evidence=[f"child_artifact_id={child.id}", f"logical_name={child.logical_name}", f"share_path={downloaded.share_path or ''}", f"smb_path={downloaded.smb_path}", f"persistent_file_id={downloaded.persistent_file_id}", f"volatile_file_id={downloaded.volatile_file_id}", f"flow={downloaded.source}:{downloaded.source_port}->{downloaded.destination}:{downloaded.destination_port}", f"message_ids={','.join(map(str, downloaded.message_ids))}", f"request_packet_indices={','.join(map(str, downloaded.request_packet_indices))}", f"packet_indices={','.join(map(str, downloaded.packet_indices))}", f"close_end_of_file={downloaded.close_end_of_file if downloaded.close_end_of_file is not None else ''}", f"close_size_match={len(downloaded.body) == downloaded.close_end_of_file if downloaded.close_end_of_file is not None else ''}", f"close_packet_indices={','.join(map(str, downloaded.close_packet_indices))}", f"close_response_packet_indices={','.join(map(str, downloaded.close_response_packet_indices))}"]))
        for operation in smb2_close_operations:
            result.findings.append(Finding(artifact_id=artifact.id, title="Observed SMB2 CLOSE lifecycle", category="pcap_smb2_close_operation", severity="info", confidence=0.92, explanation="A bounded SMB2 CLOSE request was tied to a successful CREATE FileId and correlated with its exact inverse response when present. Raw FILETIME values remain independently reviewable evidence.", source="builtin_pcap_smb2_parser", supporting_evidence=[f"filename={operation.filename}", f"share_path={operation.share_path or ''}", f"persistent_file_id={operation.persistent_file_id}", f"volatile_file_id={operation.volatile_file_id}", f"message_id={operation.message_id}", f"flow={operation.source}:{operation.source_port}->{operation.destination}:{operation.destination_port}", f"packet_indices={','.join(map(str, operation.packet_indices))}", f"response_status={f'0x{operation.response_status:08x}' if operation.response_status is not None else ''}", f"response_packet_indices={','.join(map(str, operation.response_packet_indices))}", f"creation_filetime={operation.creation_filetime if operation.creation_filetime is not None else ''}", f"last_access_filetime={operation.last_access_filetime if operation.last_access_filetime is not None else ''}", f"last_write_filetime={operation.last_write_filetime if operation.last_write_filetime is not None else ''}", f"change_filetime={operation.change_filetime if operation.change_filetime is not None else ''}", f"allocation_size={operation.allocation_size if operation.allocation_size is not None else ''}", f"end_of_file={operation.end_of_file if operation.end_of_file is not None else ''}", f"file_attributes={f'0x{operation.file_attributes:08x}' if operation.file_attributes is not None else ''}"]))
        for operation in smb2_set_info_operations:
            result.findings.append(Finding(artifact_id=artifact.id, title=f"Observed SMB2 SET_INFO {operation.operation}", category="pcap_smb2_set_info_operation", severity="low", confidence=0.9, explanation="A bounded SMB2 SET_INFO file mutation request was tied to a successful CREATE FileId and correlated with its exact inverse response when present. The requested mutation is evidence only and was not applied locally.", source="builtin_pcap_smb2_parser", supporting_evidence=[f"operation={operation.operation}", f"filename={operation.filename}", f"share_path={operation.share_path or ''}", f"target_filename={operation.target_filename or ''}", f"replace_if_exists={operation.replace_if_exists if operation.replace_if_exists is not None else ''}", f"delete_pending={operation.delete_pending if operation.delete_pending is not None else ''}", f"persistent_file_id={operation.persistent_file_id}", f"volatile_file_id={operation.volatile_file_id}", f"message_id={operation.message_id}", f"session_id={operation.session_id}", f"tree_id={operation.tree_id}", f"flow={operation.source}:{operation.source_port}->{operation.destination}:{operation.destination_port}", f"packet_indices={','.join(map(str, operation.packet_indices))}", f"response_status={f'0x{operation.response_status:08x}' if operation.response_status is not None else ''}", f"response_packet_indices={','.join(map(str, operation.response_packet_indices))}"]))
        for child, listing in smb2_directory_listings:
            result.findings.append(Finding(artifact_id=artifact.id, title="Recovered SMB2 directory listing", category="pcap_smb2_directory_listing_extraction", severity="info", confidence=0.93, explanation=f"A complete SMB2 {listing.information_class_name} response was tied to a successful directory CREATE FileId and registered as a bounded UTF-8 listing child. Rich metadata values, when present, remain raw evidence.", source="builtin_pcap_smb2_parser", supporting_evidence=[f"child_artifact_id={child.id}", f"logical_name={child.logical_name}", f"share_path={listing.share_path or ''}", f"directory_path={listing.directory_path}", f"pattern={listing.pattern or ''}", f"information_class={listing.information_class}", f"information_class_name={listing.information_class_name}", f"entry_count={len(listing.entries)}", f"metadata_fields={'file_index' if listing.information_class == 12 else 'file_index,creation_filetime,last_access_filetime,last_write_filetime,change_filetime,end_of_file,allocation_size,file_attributes,ea_size,short_name,file_id'}", f"persistent_file_id={listing.persistent_file_id}", f"volatile_file_id={listing.volatile_file_id}", f"message_id={listing.message_id}", f"flow={listing.source}:{listing.source_port}->{listing.destination}:{listing.destination_port}", f"request_packet_indices={','.join(map(str, listing.request_packet_indices))}", f"packet_indices={','.join(map(str, listing.packet_indices))}"]))
        for message_child, attachment, content_type, transfer_encoding, disposition, content_id in smtp_attachments:
            result.findings.append(Finding(artifact_id=message_child.id, title="Extracted SMTP MIME attachment", category="pcap_smtp_mime_attachment_extraction", severity="info", confidence=0.9, explanation="A declared SMTP MIME attachment or Content-ID inline object was decoded and registered beneath its recovered message.", source="builtin_pcap_smtp_extractor", supporting_evidence=[f"message_artifact_id={message_child.id}", f"child_artifact_id={attachment.id}", f"logical_name={attachment.logical_name}", f"content_type={content_type}", f"content_transfer_encoding={transfer_encoding or ''}", f"content_disposition={disposition or ''}", f"content_id={content_id or ''}"]))
        for message_child, attachment, content_type, transfer_encoding, disposition, content_id in pop3_attachments:
            result.findings.append(Finding(artifact_id=message_child.id, title="Extracted POP3 MIME attachment", category="pcap_pop3_mime_attachment_extraction", severity="info", confidence=0.9, explanation="A declared POP3 MIME attachment or Content-ID inline object was decoded and registered beneath its recovered message.", source="builtin_pcap_pop3_extractor", supporting_evidence=[f"message_artifact_id={message_child.id}", f"child_artifact_id={attachment.id}", f"logical_name={attachment.logical_name}", f"content_type={content_type}", f"content_transfer_encoding={transfer_encoding or ''}", f"content_disposition={disposition or ''}", f"content_id={content_id or ''}"]))
        for message_child, attachment, content_type, transfer_encoding, disposition, content_id in imap_attachments:
            result.findings.append(Finding(artifact_id=message_child.id, title="Extracted IMAP MIME attachment", category="pcap_imap_mime_attachment_extraction", severity="info", confidence=0.9, explanation="A declared IMAP MIME attachment or Content-ID inline object was decoded and registered beneath its recovered message.", source="builtin_pcap_imap_extractor", supporting_evidence=[f"message_artifact_id={message_child.id}", f"child_artifact_id={attachment.id}", f"logical_name={attachment.logical_name}", f"content_type={content_type}", f"content_transfer_encoding={transfer_encoding or ''}", f"content_disposition={disposition or ''}", f"content_id={content_id or ''}"]))
        return result
    def extract_pdf_embedded(self, artifact: Artifact) -> ExtractionResult:
        """Recover simple, length-delimited PDF EmbeddedFile streams safely.

        Full PDF object resolution remains the job of pdf-parser, but CTF
        samples frequently carry an inline EmbeddedFile stream.  This narrow
        fallback only accepts a nearby numeric /Length and a small allow-list
        of reversible filters, so it never guesses stream boundaries or runs
        active PDF content.
        """
        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        scan_limit = min(self.limits.max_string_scan_bytes, self.limits.max_single_artifact_size)
        try:
            with source.open("rb") as stream:
                data = stream.read(scan_limit + 1)
        except OSError as exc:
            result.errors.append(f"PDF embedded-file scan failed for {artifact.logical_name}: {exc}")
            return result
        if len(data) > scan_limit:
            data = data[:scan_limit]
            result.errors.append(f"PDF embedded-file scan limited to {scan_limit} bytes")
        if not data.startswith(b"%PDF-"):
            return result

        target_root = self.workspace.path("extracted", artifact.id, "builtin_pdf_embedded")
        target_root.mkdir(parents=True, exist_ok=True)
        # The prefix begins at /Type, while the preceding dictionary opening
        # is not needed: PDF dictionaries are parsed only for fixed tokens.
        pattern = re.compile(
            rb"/Type\s*/EmbeddedFile(?P<dictionary>.{0,65536}?)stream[\t \r]*\n",
            re.DOTALL,
        )
        for index, match in enumerate(pattern.finditer(data)):
            dictionary = match.group("dictionary")
            length_match = re.search(rb"/Length\s+(\d+)\b", dictionary)
            if length_match is None:
                result.errors.append(f"skipped PDF EmbeddedFile #{index}: indirect or missing /Length")
                continue
            declared_size = int(length_match.group(1))
            reason = self.can_register(artifact, declared_size)
            if reason:
                result.errors.append(f"skipped PDF EmbeddedFile #{index}: {reason}")
                continue
            stream_start = match.end()
            stream_end = stream_start + declared_size
            if stream_end > len(data):
                result.errors.append(f"skipped PDF EmbeddedFile #{index}: stream exceeds bounded scan")
                continue
            payload = data[stream_start:stream_end]
            try:
                payload = self._decode_pdf_stream(payload, dictionary)
            except (ValueError, zlib.error) as exc:
                result.errors.append(f"skipped PDF EmbeddedFile #{index}: {exc}")
                continue
            reason = self.can_register(artifact, len(payload))
            if reason:
                result.errors.append(f"skipped decoded PDF EmbeddedFile #{index}: {reason}")
                continue
            output = target_root / f"{index:05d}_embedded.bin"
            try:
                output.write_bytes(payload)
            except OSError as exc:
                result.errors.append(f"failed PDF EmbeddedFile #{index}: {exc}")
                continue
            child = self.register_file(output, artifact, f"pdf_embedded_{index:04d}.bin")
            if child:
                result.artifacts.append(child)
                result.extracted_bytes += child.size
        if result.artifacts:
            result.findings.append(
                Finding(
                    artifact_id=artifact.id,
                    title=f"Extracted {len(result.artifacts)} PDF embedded file(s)",
                    category="pdf_embedded_file",
                    severity="medium",
                    confidence=0.9,
                    explanation="Length-delimited /EmbeddedFile streams were recovered without executing PDF content.",
                    source="builtin_pdf_embedded_extractor",
                    supporting_evidence=[child.id for child in result.artifacts],
                )
            )
        return result

    def extract_android_backup(self, artifact: Artifact) -> ExtractionResult:
        """Recover an unencrypted Android Backup payload into a child artifact."""
        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        try:
            with source.open("rb") as stream:
                header_lines = [stream.readline(128) for _ in range(4)]
        except OSError as exc:
            result.errors.append(f"Android backup read failed for {artifact.logical_name}: {exc}")
            return result
        if len(header_lines) != 4 or header_lines[0] != b"ANDROID BACKUP\n":
            return result
        compressed = header_lines[2].strip()
        encryption = header_lines[3].strip().lower()
        if compressed not in {b"0", b"1"}:
            result.errors.append("Android backup has invalid compression header")
            return result
        if encryption != b"none":
            result.errors.append("Android backup payload is encrypted; no password guessing is attempted")
            return result
        output = self.workspace.path("extracted", artifact.id, "builtin_android_backup", "backup_payload.tar")
        output.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with source.open("rb") as stream, output.open("xb") as target:
                for _ in range(4):
                    stream.readline(128)
                if compressed == b"0":
                    while chunk := stream.read(1024 * 1024):
                        written += len(chunk)
                        if written > self.limits.max_single_artifact_size or self.extracted_bytes + written > self.limits.max_extracted_bytes:
                            raise RuntimeError("Android backup payload exceeds extraction limits")
                        target.write(chunk)
                else:
                    decoder = zlib.decompressobj()
                    while compressed_chunk := stream.read(1024 * 1024):
                        pending = compressed_chunk
                        while pending:
                            before = pending
                            chunk = decoder.decompress(pending, 1024 * 1024)
                            pending = decoder.unconsumed_tail
                            if not chunk and pending == before:
                                raise RuntimeError("Android backup decompressor made no progress")
                            written += len(chunk)
                            if written > self.limits.max_single_artifact_size or self.extracted_bytes + written > self.limits.max_extracted_bytes:
                                raise RuntimeError("Android backup payload exceeds extraction limits")
                            target.write(chunk)
                    tail = decoder.flush()
                    written += len(tail)
                    if written > self.limits.max_single_artifact_size or self.extracted_bytes + written > self.limits.max_extracted_bytes or decoder.unused_data or not decoder.eof:
                        raise RuntimeError("Android backup stream is oversized or has trailing data")
                    target.write(tail)
        except (OSError, RuntimeError, zlib.error) as exc:
            output.unlink(missing_ok=True)
            result.errors.append(f"Android backup extraction failed: {exc}")
            return result
        child = self.register_file(output, artifact, "backup_payload.tar")
        if child:
            result.artifacts.append(child)
            result.extracted_bytes = written
            result.findings.append(Finding(
                artifact_id=artifact.id, title="Extracted unencrypted Android backup payload",
                category="android_backup_extraction", severity="info", confidence=1.0,
                explanation="The plaintext Android Backup header declared no encryption; its bounded payload was recovered for recursive archive analysis.",
                source="builtin_android_backup_extractor", supporting_evidence=[child.id],
            ))
        return result

    def extract_android_boot(self, artifact: Artifact) -> ExtractionResult:
        """Carve validated legacy Android boot kernel/ramdisk components.

        Android boot image v0-v2 places a fixed header at offset zero and
        page-aligns kernel/ramdisk payloads.  Later formats differ, so this
        fallback only proceeds when the legacy page geometry and both bounded
        component ranges are unambiguous.
        """
        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        try:
            with source.open("rb") as stream:
                header = stream.read(64)
        except OSError as exc:
            result.errors.append(f"Android boot image read failed: {exc}")
            return result
        if len(header) < 40 or not header.startswith(b"ANDROID!"):
            return result
        kernel_size = int.from_bytes(header[8:12], "little")
        ramdisk_size = int.from_bytes(header[16:20], "little")
        page_size = int.from_bytes(header[36:40], "little")
        if page_size not in {2048, 4096, 8192, 16384, 32768, 65536}:
            result.errors.append("Android boot image uses unsupported legacy page size")
            return result
        kernel_offset = page_size
        ramdisk_offset = kernel_offset + ((kernel_size + page_size - 1) // page_size) * page_size
        components = (("kernel", kernel_offset, kernel_size), ("ramdisk", ramdisk_offset, ramdisk_size))
        target_root = self.workspace.path("extracted", artifact.id, "builtin_android_boot")
        target_root.mkdir(parents=True, exist_ok=True)
        for index, (name, offset, declared_size) in enumerate(components):
            if declared_size == 0:
                continue
            reason = self.can_register(artifact, declared_size)
            if reason:
                result.errors.append(f"skipped Android boot {name}: {reason}")
                continue
            if offset < page_size or offset + declared_size > artifact.size:
                result.errors.append(f"skipped Android boot {name}: declared range exceeds evidence")
                continue
            output = target_root / f"{index:02d}_{name}.bin"
            written = 0
            try:
                with source.open("rb") as reader, output.open("xb") as writer:
                    reader.seek(offset)
                    while written < declared_size:
                        chunk = reader.read(min(1024 * 1024, declared_size - written))
                        if not chunk:
                            raise RuntimeError("truncated Android boot component")
                        writer.write(chunk)
                        written += len(chunk)
            except (OSError, RuntimeError) as exc:
                output.unlink(missing_ok=True)
                result.errors.append(f"Android boot {name} extraction failed: {exc}")
                continue
            child = self.register_file(output, artifact, f"android_boot_{name}.bin")
            if child:
                result.artifacts.append(child)
                result.extracted_bytes += child.size
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id, title=f"Extracted {len(result.artifacts)} Android boot component(s)",
                category="android_boot_extraction", severity="info", confidence=0.95,
                explanation="Validated legacy Android boot page geometry was used to carve kernel/ramdisk components for recursive analysis.",
                source="builtin_android_boot_extractor", supporting_evidence=[child.id for child in result.artifacts],
            ))
        return result

    def extract_ntfs_resident_data(self, artifact: Artifact) -> ExtractionResult:
        """Promote validated sampled-record resident `$DATA` into child evidence."""
        result = ExtractionResult()
        samples = next(
            (
                observation.value
                for observation in self.workspace.database.observations(artifact.id)
                if observation.key == "filesystem.ntfs.mft_sample_records"
                and isinstance(observation.value, list)
            ),
            [],
        )
        if not samples:
            return result
        target_root = self.workspace.path("extracted", artifact.id, "builtin_ntfs_resident")
        evidence: list[str] = []
        extracted_count = 0
        for record in samples[:256]:
            if (
                not isinstance(record, dict)
                or record.get("signature_valid") is not True
                or record.get("bounds_valid") is not True
                or record.get("usa_fixup_valid") is not True
                or record.get("directory") is True
            ):
                continue
            record_number = record.get("record_number")
            if not isinstance(record_number, int):
                continue
            names = record.get("file_names")
            logical_base = next(
                (name for name in names if isinstance(name, str) and name and "\x00" not in name),
                f"mft_record_{record_number}",
            ) if isinstance(names, list) else f"mft_record_{record_number}"
            streams = record.get("resident_data_attributes")
            if not isinstance(streams, list):
                continue
            for stream in streams[:16]:
                if extracted_count >= 256 or not isinstance(stream, dict):
                    break
                value_length = stream.get("value_length")
                encoded = stream.get("data_hex")
                if (
                    not isinstance(value_length, int) or value_length <= 0
                    or value_length > min(4096, self.limits.max_single_artifact_size)
                    or not isinstance(encoded, str) or len(encoded) != value_length * 2
                    or len(encoded) > 8192
                ):
                    result.errors.append(
                        f"skipped NTFS record {record_number} resident DATA: invalid bounded value encoding"
                    )
                    continue
                try:
                    payload = bytes.fromhex(encoded)
                except ValueError:
                    result.errors.append(
                        f"skipped NTFS record {record_number} resident DATA: invalid hexadecimal value"
                    )
                    continue
                reason = self.can_register(artifact, len(payload))
                if reason:
                    result.errors.append(f"skipped NTFS record {record_number} resident DATA: {reason}")
                    continue
                stream_name = stream.get("stream_name")
                logical_name = (
                    f"{logical_base}:{stream_name}"
                    if isinstance(stream_name, str) and stream_name else logical_base
                )[:1_024]
                attribute_id = stream.get("attribute_id")
                if not isinstance(attribute_id, int):
                    attribute_id = 0
                storage_name = (
                    f"record_{record_number:08d}_attr_{attribute_id:04d}_"
                    f"{safe_name(logical_base)}"
                    + (f"__ads__{safe_name(stream_name)}" if isinstance(stream_name, str) and stream_name else "")
                )
                output = target_root / storage_name
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        writer.write(payload)
                except FileExistsError:
                    result.errors.append(
                        f"skipped NTFS record {record_number} resident DATA: deterministic output already exists"
                    )
                    continue
                except OSError as exc:
                    result.errors.append(f"failed NTFS record {record_number} resident DATA write: {exc}")
                    continue
                child = self.register_file(output, artifact, logical_name)
                if child is None:
                    result.errors.append(
                        f"skipped NTFS record {record_number} resident DATA: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                extracted_count += 1
                evidence.append(
                    f"child:{child.id};record:{record_number};attribute:{stream.get('attribute_id')};"
                    f"stream:{stream_name or 'unnamed'};deleted:{bool(record.get('deleted'))};"
                    f"resident_value_offset:{stream.get('resident_value_offset')};"
                    f"mft_physical_segments:{record.get('physical_segments')}"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} resident NTFS data stream(s)",
                category="ntfs_resident_data_recovery",
                severity="info",
                confidence=0.97,
                explanation=(
                    "Resident `$DATA` bytes were copied only from bounded sampled FILE records after signature, record bounds, USA fixup, and resident-value bounds validation. "
                    "Each child retains its MFT record/attribute, deletion state, stream name, and source mapping provenance."
                ),
                source="builtin_ntfs_resident_extractor",
                supporting_evidence=evidence[:256],
            ))
        return result

    def extract_ntfs_nonresident_data(self, artifact: Artifact) -> ExtractionResult:
        """Recover complete VCN-zero sampled streams, including logical zero ranges."""
        result = ExtractionResult()
        observations = self.workspace.database.observations(artifact.id)
        samples = next(
            (
                observation.value for observation in observations
                if observation.key == "filesystem.ntfs.mft_sample_records"
                and isinstance(observation.value, list)
            ),
            [],
        )
        bytes_per_sector = next(
            (
                observation.value for observation in observations
                if observation.key == "filesystem.ntfs.bytes_per_sector"
                and isinstance(observation.value, int)
            ),
            None,
        )
        sectors_per_cluster = next(
            (
                observation.value for observation in observations
                if observation.key == "filesystem.ntfs.sectors_per_cluster"
                and isinstance(observation.value, int)
            ),
            None,
        )
        if not samples or bytes_per_sector is None or sectors_per_cluster is None:
            return result
        cluster_size = bytes_per_sector * sectors_per_cluster
        if cluster_size <= 0 or cluster_size > 2 * 1024 * 1024:
            result.errors.append("skipped NTFS nonresident DATA: invalid cluster geometry")
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_ntfs_nonresident")
        evidence: list[str] = []
        extracted_count = 0
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"NTFS nonresident DATA source open failed: {exc}")
            return result
        with source_stream:
            for record in samples[:256]:
                if (
                    not isinstance(record, dict)
                    or record.get("signature_valid") is not True
                    or record.get("bounds_valid") is not True
                    or record.get("usa_fixup_valid") is not True
                    or record.get("directory") is True
                ):
                    continue
                record_number = record.get("record_number")
                if not isinstance(record_number, int):
                    continue
                names = record.get("file_names")
                logical_base = next(
                    (name for name in names if isinstance(name, str) and name and "\x00" not in name),
                    f"mft_record_{record_number}",
                ) if isinstance(names, list) else f"mft_record_{record_number}"
                streams = record.get("nonresident_data_attributes")
                joined_streams = record.get("joined_nonresident_data_attributes")
                streams = (
                    (joined_streams if isinstance(joined_streams, list) else [])
                    + (streams if isinstance(streams, list) else [])
                )
                if not streams:
                    continue
                for stream in streams[:16]:
                    if extracted_count >= 256 or not isinstance(stream, dict):
                        break
                    flags = stream.get("attribute_flags")
                    real_size = stream.get("real_size")
                    initialized_size = stream.get("initialized_size")
                    allocated_size = stream.get("allocated_size")
                    highest_vcn = stream.get("highest_vcn")
                    runs = stream.get("data_runs")
                    if (
                        # Compression and encryption require format-aware
                        # decoding.  Sparse attributes are safe here because
                        # sparse runs and uninitialized bytes have deterministic
                        # NTFS zero-fill semantics.
                        not isinstance(flags, int) or flags & 0x4001
                        or stream.get("lowest_vcn") != 0
                        or not isinstance(real_size, int) or real_size <= 0
                        or real_size > self.limits.max_single_artifact_size
                        or not isinstance(initialized_size, int) or not 0 <= initialized_size <= real_size
                        or not isinstance(allocated_size, int) or allocated_size < 0
                        or not isinstance(highest_vcn, int)
                        or not isinstance(runs, list) or not runs or len(runs) > 64
                    ):
                        continue
                    expected_vcn = 0
                    mapped_runs: list[dict[str, int | None]] = []
                    physical_capacity = 0
                    mapping_valid = True
                    for run in runs:
                        if not isinstance(run, dict):
                            mapping_valid = False
                            break
                        vcn, count, lcn = run.get("vcn"), run.get("cluster_count"), run.get("lcn")
                        if (
                            not isinstance(vcn, int) or vcn != expected_vcn
                            or not isinstance(count, int) or count <= 0
                            or (lcn is not None and (not isinstance(lcn, int) or lcn < 0))
                        ):
                            mapping_valid = False
                            break
                        length = count * cluster_size
                        logical_offset = vcn * cluster_size
                        physical_offset = None
                        if lcn is not None:
                            physical_offset = lcn * cluster_size
                            if physical_offset < 0 or physical_offset + length > artifact.size:
                                mapping_valid = False
                                break
                            physical_capacity += length
                        mapped_runs.append({
                            "vcn": vcn, "lcn": lcn,
                            "physical_offset": physical_offset,
                            "logical_offset": logical_offset, "length": length,
                        })
                        expected_vcn += count
                    if (
                        not mapping_valid or expected_vcn - 1 != highest_vcn
                        or expected_vcn * cluster_size < real_size
                        or allocated_size != physical_capacity
                    ):
                        continue
                    reason = self.can_register(artifact, real_size)
                    if reason:
                        result.errors.append(
                            f"skipped NTFS record {record_number} nonresident DATA: {reason}"
                        )
                        continue
                    stream_name = stream.get("stream_name")
                    logical_name = (
                        f"{logical_base}:{stream_name}"
                        if isinstance(stream_name, str) and stream_name else logical_base
                    )[:1_024]
                    attribute_id = stream.get("attribute_id")
                    if not isinstance(attribute_id, int):
                        attribute_id = 0
                    storage_name = (
                        f"record_{record_number:08d}_attr_{attribute_id:04d}_{safe_name(logical_base)}"
                        + (f"__ads__{safe_name(stream_name)}" if isinstance(stream_name, str) and stream_name else "")
                    )
                    output = target_root / storage_name
                    output.parent.mkdir(parents=True, exist_ok=True)
                    logical_segments: list[dict[str, int | str]] = []
                    try:
                        with output.open("xb") as writer:
                            for run in mapped_runs:
                                logical_offset = int(run["logical_offset"])
                                if logical_offset >= real_size:
                                    break
                                mapped_length = min(int(run["length"]), real_size - logical_offset)
                                initialized_length = max(
                                    0, min(mapped_length, initialized_size - logical_offset)
                                )
                                if initialized_length:
                                    if run["lcn"] is None:
                                        self._write_zeros(writer, initialized_length)
                                        logical_segments.append({
                                            "vcn": int(run["vcn"]),
                                            "logical_offset": logical_offset,
                                            "length": initialized_length,
                                            "zero_fill_reason": "sparse_run",
                                        })
                                    else:
                                        physical_offset = int(run["physical_offset"])
                                        source_stream.seek(physical_offset)
                                        payload = source_stream.read(initialized_length)
                                        if len(payload) != initialized_length:
                                            raise RuntimeError("mapped cluster range is truncated")
                                        writer.write(payload)
                                        logical_segments.append({
                                            "vcn": int(run["vcn"]), "lcn": int(run["lcn"]),
                                            "physical_offset": physical_offset,
                                            "logical_offset": logical_offset,
                                            "length": initialized_length,
                                        })
                                uninitialized_length = mapped_length - initialized_length
                                if uninitialized_length:
                                    tail_offset = logical_offset + initialized_length
                                    self._write_zeros(writer, uninitialized_length)
                                    logical_segments.append({
                                        "logical_offset": tail_offset,
                                        "length": uninitialized_length,
                                        "zero_fill_reason": "uninitialized_tail",
                                    })
                            if writer.tell() != real_size:
                                raise RuntimeError("validated runs did not cover real size")
                    except (OSError, RuntimeError) as exc:
                        output.unlink(missing_ok=True)
                        result.errors.append(
                            f"failed NTFS record {record_number} nonresident DATA recovery: {exc}"
                        )
                        continue
                    child = self.register_file(output, artifact, logical_name)
                    if child is None:
                        result.errors.append(
                            f"skipped NTFS record {record_number} nonresident DATA: duplicate or extraction limit"
                        )
                        continue
                    result.artifacts.append(child)
                    result.extracted_bytes += child.size
                    extracted_count += 1
                    evidence.append(
                        f"child:{child.id};record:{record_number};attribute:{attribute_id};"
                        f"stream:{stream_name or 'unnamed'};deleted:{bool(record.get('deleted'))};"
                        f"real_size:{real_size};initialized_size:{initialized_size};"
                        f"allocated_size:{allocated_size};segments:{logical_segments}"
                        f";extents:{stream.get('extent_provenance') or []}"
                    )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} nonresident NTFS data stream(s)",
                category="ntfs_nonresident_data_recovery",
                severity="info",
                confidence=0.95,
                explanation=(
                    "Sampled FILE records supplied a complete VCN-zero run list whose uncompressed and unencrypted physical ranges, allocation, and real/initialized sizes validated against the immutable image. "
                    "Allocated initialized bytes were copied, sparse runs and the uninitialized tail were explicitly zero-filled, and the bounded logical result was registered as recursive child evidence."
                ),
                source="builtin_ntfs_nonresident_extractor",
                supporting_evidence=evidence[:256],
            ))
        return result

    def extract_fat12_deleted_files(self, artifact: Artifact) -> ExtractionResult:
        """Recover bounded FAT12 files using exact packed 12-bit chain decoding."""
        result = ExtractionResult()
        values = {
            observation.key: observation.value
            for observation in self.workspace.database.observations(artifact.id)
        }
        entries = values.get("filesystem.fat12.root.deleted_entries")
        subdirectory_entries = values.get("filesystem.fat12.root.subdirectory_deleted_entries")
        entries = (
            (entries if isinstance(entries, list) else [])
            + (subdirectory_entries if isinstance(subdirectory_entries, list) else [])
        )
        bytes_per_sector = values.get("filesystem.fat.bytes_per_sector")
        sectors_per_cluster = values.get("filesystem.fat.sectors_per_cluster")
        reserved_sectors = values.get("filesystem.fat.reserved_sector_count")
        fat_size = values.get("filesystem.fat.size_sectors")
        first_data_sector = values.get("filesystem.fat12.root.first_data_sector")
        cluster_count = values.get("filesystem.fat12.root.cluster_count")
        if not isinstance(entries, list) or not entries:
            return result
        if not all(isinstance(value, int) for value in (
            bytes_per_sector, sectors_per_cluster, reserved_sectors, fat_size,
            first_data_sector, cluster_count,
        )):
            result.errors.append("skipped FAT12 deleted content: missing validated geometry")
            return result
        cluster_size = bytes_per_sector * sectors_per_cluster
        if (
            bytes_per_sector not in {512, 1024, 2048, 4096}
            or sectors_per_cluster <= 0
            or sectors_per_cluster & (sectors_per_cluster - 1)
            or not 0 < cluster_size <= 2 * 1024 * 1024
            or reserved_sectors <= 0 or fat_size <= 0
            or first_data_sector <= 0 or not 0 < cluster_count < 4_085
        ):
            result.errors.append("skipped FAT12 deleted content: invalid validated geometry")
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        fat_offset = reserved_sectors * bytes_per_sector
        fat_end = fat_offset + fat_size * bytes_per_sector
        target_root = self.workspace.path("extracted", artifact.id, "builtin_fat12_deleted")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"FAT12 deleted content source open failed: {exc}")
            return result
        with source_stream:
            for entry in entries[:256]:
                if not isinstance(entry, dict):
                    continue
                size = entry.get("size")
                first_cluster = entry.get("first_cluster")
                attributes_text = entry.get("attributes")
                high_reserved = entry.get("fat12_cluster_high_reserved")
                try:
                    attributes = int(attributes_text, 16) if isinstance(attributes_text, str) else -1
                except ValueError:
                    attributes = -1
                if (
                    not isinstance(size, int) or not 0 < size <= 8 * 1024 * 1024
                    or size > self.limits.max_single_artifact_size
                    or not isinstance(first_cluster, int) or not 2 <= first_cluster < cluster_count + 2
                    or high_reserved != 0 or attributes < 0 or attributes & 0x18
                ):
                    continue
                required_clusters = (size + cluster_size - 1) // cluster_size
                if not 1 <= required_clusters <= 64:
                    continue
                chain: list[dict[str, int | str]] = []
                visited: set[int] = set()
                current_cluster = first_cluster
                chain_validation = "single_cluster_direct"
                chain_valid = True
                for cluster_index in range(required_clusters):
                    if (
                        current_cluster in visited
                        or not 2 <= current_cluster < cluster_count + 2
                    ):
                        chain_valid = False
                        break
                    visited.add(current_cluster)
                    physical_offset = (
                        first_data_sector + (current_cluster - 2) * sectors_per_cluster
                    ) * bytes_per_sector
                    if physical_offset < 0 or physical_offset + cluster_size > artifact.size:
                        chain_valid = False
                        break
                    segment: dict[str, int | str] = {
                        "cluster": current_cluster, "physical_offset": physical_offset,
                        "length": cluster_size,
                    }
                    chain.append(segment)
                    if required_clusters == 1:
                        break
                    fat_entry_offset = fat_offset + current_cluster + current_cluster // 2
                    if (
                        fat_entry_offset < fat_offset or fat_entry_offset + 2 > fat_end
                        or fat_entry_offset + 2 > artifact.size
                    ):
                        chain_valid = False
                        break
                    source_stream.seek(fat_entry_offset)
                    raw_next = source_stream.read(2)
                    if len(raw_next) != 2:
                        chain_valid = False
                        break
                    packed = int.from_bytes(raw_next, "little")
                    next_cluster = (
                        (packed >> 4) & 0x0FFF if current_cluster & 1
                        else packed & 0x0FFF
                    )
                    segment.update({
                        "fat_entry_offset": fat_entry_offset,
                        "fat_entry_raw": raw_next.hex(),
                        "next_cluster": next_cluster,
                    })
                    if cluster_index == required_clusters - 1:
                        if next_cluster < 0xFF8:
                            chain_valid = False
                        else:
                            chain_validation = "complete_fat12_chain_eoc"
                        break
                    if (
                        next_cluster < 2 or next_cluster >= cluster_count + 2
                        or next_cluster == 0xFF7 or 0xFF0 <= next_cluster <= 0xFF6
                        or next_cluster >= 0xFF8
                    ):
                        chain_valid = False
                        break
                    current_cluster = next_cluster
                if not chain_valid or len(chain) != required_clusters:
                    continue
                reason = self.can_register(artifact, size)
                if reason:
                    result.errors.append(
                        f"skipped FAT12 deleted entry {entry.get('entry_index')}: {reason}"
                    )
                    continue
                logical_name = next((
                    value for value in (
                        entry.get("long_name"), entry.get("reconstructed_short_name"),
                        entry.get("short_name"),
                    ) if isinstance(value, str) and value
                ), f"deleted_cluster_{first_cluster}")[:1_024]
                entry_index = entry.get("entry_index")
                output = target_root / (
                    f"entry_{entry_index if isinstance(entry_index, int) else 0:04d}_"
                    f"cluster_{first_cluster:04d}_{safe_name(logical_name)}"
                )
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        remaining = size
                        for segment in chain:
                            segment_length = int(segment["length"])
                            take = min(remaining, segment_length)
                            source_stream.seek(int(segment["physical_offset"]))
                            payload = source_stream.read(take)
                            if len(payload) != take:
                                raise RuntimeError("mapped FAT12 cluster bytes are truncated")
                            writer.write(payload)
                            remaining -= take
                        if remaining:
                            raise RuntimeError("validated FAT12 cluster chain did not cover declared size")
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(
                        f"failed FAT12 deleted entry {entry_index} recovery: {exc}"
                    )
                    continue
                child = self.register_file(output, artifact, logical_name)
                if child is None:
                    result.errors.append(
                        f"skipped FAT12 deleted entry {entry_index}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};entry_index:{entry_index};entry_offset:{entry.get('offset')};"
                    f"name:{logical_name};first_cluster:{first_cluster};"
                    f"physical_offset:{chain[0]['physical_offset']};cluster_chain:{chain};"
                    f"size:{size};attributes:{attributes_text};lfn_slot_offsets:{entry.get('lfn_slot_offsets')};"
                    f"directory_start_cluster:{entry.get('directory_start_cluster')};"
                    f"directory_cluster_lineage:{entry.get('directory_cluster_lineage')};"
                    f"directory_source_entry_offset:{entry.get('directory_source_entry_offset')};"
                    f"directory_short_name:{entry.get('directory_short_name')};"
                    f"directory_long_name:{entry.get('directory_long_name')};"
                    f"directory_lfn_slot_offsets:{entry.get('directory_lfn_slot_offsets')};"
                    f"directory_identity_lineage:{entry.get('directory_identity_lineage')};"
                    f"raw_entry:{entry.get('raw_hex')};chain_validation:{chain_validation};"
                    "allocation_state:unknown_deleted_cluster_may_be_reused"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} bounded deleted FAT12 file(s)",
                category="fat12_deleted_content_recovery", severity="info", confidence=0.68,
                explanation=(
                    "A strict FAT12 fixed-root candidate declared bounded nonzero content. Single-cluster candidates map directly; larger candidates require an exact, non-looping sequence of correctly packed 12-bit FAT entries and EOC after the final size-required cluster. "
                    "The recursively registered bytes retain every packed-entry offset/raw value and a deleted-cluster reuse caveat."
                ),
                source="builtin_fat12_deleted_extractor", supporting_evidence=evidence[:256],
            ))
        return result

    def extract_fat16_deleted_files(self, artifact: Artifact) -> ExtractionResult:
        """Recover bounded FAT16 deleted files directly or through an exact FAT chain."""
        result = ExtractionResult()
        values = {
            observation.key: observation.value
            for observation in self.workspace.database.observations(artifact.id)
        }
        entries = values.get("filesystem.fat16.root.deleted_entries")
        subdirectory_entries = values.get("filesystem.fat16.root.subdirectory_deleted_entries")
        entries = (
            (entries if isinstance(entries, list) else [])
            + (subdirectory_entries if isinstance(subdirectory_entries, list) else [])
        )
        if not entries:
            return result
        bytes_per_sector = values.get("filesystem.fat.bytes_per_sector")
        sectors_per_cluster = values.get("filesystem.fat.sectors_per_cluster")
        reserved_sectors = values.get("filesystem.fat.reserved_sector_count")
        fat_size = values.get("filesystem.fat.size_sectors")
        first_data_sector = values.get("filesystem.fat16.root.first_data_sector")
        cluster_count = values.get("filesystem.fat16.root.cluster_count")
        if not all(isinstance(value, int) for value in (
            bytes_per_sector, sectors_per_cluster, reserved_sectors, fat_size,
            first_data_sector, cluster_count,
        )):
            result.errors.append("skipped FAT16 deleted content: missing validated geometry")
            return result
        cluster_size = bytes_per_sector * sectors_per_cluster
        if (
            bytes_per_sector not in {512, 1024, 2048, 4096}
            or sectors_per_cluster <= 0
            or sectors_per_cluster & (sectors_per_cluster - 1)
            or not 0 < cluster_size <= 2 * 1024 * 1024
            or reserved_sectors <= 0 or fat_size <= 0
            or first_data_sector <= 0 or not 4_085 <= cluster_count < 65_525
        ):
            result.errors.append("skipped FAT16 deleted content: invalid validated geometry")
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        fat_offset = reserved_sectors * bytes_per_sector
        fat_end = fat_offset + fat_size * bytes_per_sector
        target_root = self.workspace.path("extracted", artifact.id, "builtin_fat16_deleted")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"FAT16 deleted content source open failed: {exc}")
            return result
        with source_stream:
            for entry in entries[:256]:
                if not isinstance(entry, dict):
                    continue
                size = entry.get("size")
                first_cluster = entry.get("first_cluster")
                attributes_text = entry.get("attributes")
                high_reserved = entry.get("fat16_cluster_high_reserved")
                try:
                    attributes = int(attributes_text, 16) if isinstance(attributes_text, str) else -1
                except ValueError:
                    attributes = -1
                if (
                    not isinstance(size, int) or not 0 < size <= 8 * 1024 * 1024
                    or size > self.limits.max_single_artifact_size
                    or not isinstance(first_cluster, int) or not 2 <= first_cluster < cluster_count + 2
                    or high_reserved != 0 or attributes < 0 or attributes & 0x18
                ):
                    continue
                required_clusters = (size + cluster_size - 1) // cluster_size
                if not 1 <= required_clusters <= 64:
                    continue
                chain: list[dict[str, int]] = []
                visited: set[int] = set()
                current_cluster = first_cluster
                chain_validation = "single_cluster_direct"
                chain_valid = True
                for cluster_index in range(required_clusters):
                    if (
                        current_cluster in visited
                        or not 2 <= current_cluster < cluster_count + 2
                    ):
                        chain_valid = False
                        break
                    visited.add(current_cluster)
                    physical_offset = (
                        first_data_sector + (current_cluster - 2) * sectors_per_cluster
                    ) * bytes_per_sector
                    if physical_offset < 0 or physical_offset + cluster_size > artifact.size:
                        chain_valid = False
                        break
                    chain.append({
                        "cluster": current_cluster, "physical_offset": physical_offset,
                        "length": cluster_size,
                    })
                    if required_clusters == 1:
                        break
                    fat_entry_offset = fat_offset + current_cluster * 2
                    if (
                        fat_entry_offset < fat_offset or fat_entry_offset + 2 > fat_end
                        or fat_entry_offset + 2 > artifact.size
                    ):
                        chain_valid = False
                        break
                    source_stream.seek(fat_entry_offset)
                    raw_next = source_stream.read(2)
                    if len(raw_next) != 2:
                        chain_valid = False
                        break
                    next_cluster = int.from_bytes(raw_next, "little")
                    if cluster_index == required_clusters - 1:
                        if next_cluster < 0xFFF8:
                            chain_valid = False
                        else:
                            chain_validation = "complete_fat16_chain_eoc"
                        break
                    if (
                        next_cluster < 2 or next_cluster >= cluster_count + 2
                        or next_cluster == 0xFFF7 or 0xFFF0 <= next_cluster <= 0xFFF6
                        or next_cluster >= 0xFFF8
                    ):
                        chain_valid = False
                        break
                    current_cluster = next_cluster
                if not chain_valid or len(chain) != required_clusters:
                    continue
                reason = self.can_register(artifact, size)
                if reason:
                    result.errors.append(
                        f"skipped FAT16 deleted entry {entry.get('entry_index')}: {reason}"
                    )
                    continue
                logical_name = next((
                    value for value in (
                        entry.get("long_name"), entry.get("reconstructed_short_name"),
                        entry.get("short_name"),
                    ) if isinstance(value, str) and value
                ), f"deleted_cluster_{first_cluster}")[:1_024]
                entry_index = entry.get("entry_index")
                output = target_root / (
                    f"entry_{entry_index if isinstance(entry_index, int) else 0:04d}_"
                    f"cluster_{first_cluster:05d}_{safe_name(logical_name)}"
                )
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        remaining = size
                        for segment in chain:
                            take = min(remaining, segment["length"])
                            source_stream.seek(segment["physical_offset"])
                            payload = source_stream.read(take)
                            if len(payload) != take:
                                raise RuntimeError("mapped FAT16 cluster bytes are truncated")
                            writer.write(payload)
                            remaining -= take
                        if remaining:
                            raise RuntimeError("validated FAT16 cluster chain did not cover declared size")
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(
                        f"failed FAT16 deleted entry {entry_index} recovery: {exc}"
                    )
                    continue
                child = self.register_file(output, artifact, logical_name)
                if child is None:
                    result.errors.append(
                        f"skipped FAT16 deleted entry {entry_index}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};entry_index:{entry_index};entry_offset:{entry.get('offset')};"
                    f"name:{logical_name};first_cluster:{first_cluster};"
                    f"physical_offset:{chain[0]['physical_offset']};cluster_chain:{chain};"
                    f"size:{size};attributes:{attributes_text};"
                    f"lfn_slot_offsets:{entry.get('lfn_slot_offsets')};"
                    f"directory_start_cluster:{entry.get('directory_start_cluster')};"
                    f"directory_cluster_lineage:{entry.get('directory_cluster_lineage')};"
                    f"directory_source_entry_offset:{entry.get('directory_source_entry_offset')};"
                    f"directory_short_name:{entry.get('directory_short_name')};"
                    f"directory_long_name:{entry.get('directory_long_name')};"
                    f"directory_lfn_slot_offsets:{entry.get('directory_lfn_slot_offsets')};"
                    f"directory_identity_lineage:{entry.get('directory_identity_lineage')};"
                    f"raw_entry:{entry.get('raw_hex')};chain_validation:{chain_validation};"
                    "allocation_state:unknown_deleted_cluster_may_be_reused"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} bounded deleted FAT16 file(s)",
                category="fat16_deleted_content_recovery", severity="info", confidence=0.7,
                explanation=(
                    "A fixed-root deleted regular-file entry declared bounded nonzero content. Single-cluster candidates map directly; larger candidates require an exact, non-looping, image-bounded FAT16 chain ending at EOC after the final required cluster. "
                    "Declared bytes were registered recursively without treating the current FAT state as deleted-file ownership proof."
                ),
                source="builtin_fat16_deleted_extractor", supporting_evidence=evidence[:256],
            ))
        return result

    def extract_fat32_deleted_single_cluster(self, artifact: Artifact) -> ExtractionResult:
        """Recover bounded deleted files directly or through a complete FAT chain."""
        result = ExtractionResult()
        observations = self.workspace.database.observations(artifact.id)
        values = {observation.key: observation.value for observation in observations}
        root_entries = values.get("filesystem.fat.deleted_short_entries")
        subdirectory_entries = values.get("filesystem.fat.subdirectory_deleted_entries")
        entries = (
            (root_entries if isinstance(root_entries, list) else [])
            + (subdirectory_entries if isinstance(subdirectory_entries, list) else [])
        )
        if not entries:
            return result
        bytes_per_sector = values.get("filesystem.fat.bytes_per_sector")
        sectors_per_cluster = values.get("filesystem.fat.sectors_per_cluster")
        reserved = values.get("filesystem.fat.reserved_sector_count")
        fat_count = values.get("filesystem.fat.count")
        fat_size = values.get("filesystem.fat.size_sectors")
        if not all(isinstance(value, int) for value in (
            bytes_per_sector, sectors_per_cluster, reserved, fat_count, fat_size
        )):
            return result
        cluster_size = bytes_per_sector * sectors_per_cluster
        first_data_sector = reserved + fat_count * fat_size
        observed_active_fat_offset = values.get("filesystem.fat.root.active_fat_offset")
        fat_offset = (
            observed_active_fat_offset
            if isinstance(observed_active_fat_offset, int)
            else reserved * bytes_per_sector
        )
        fat_end = fat_offset + fat_size * bytes_per_sector
        if (
            bytes_per_sector not in {512, 1024, 2048, 4096}
            or sectors_per_cluster <= 0 or cluster_size <= 0 or cluster_size > 2 * 1024 * 1024
            or reserved <= 0 or not 1 <= fat_count <= 4 or fat_size <= 0
        ):
            result.errors.append("skipped FAT32 deleted content: invalid filesystem geometry")
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_fat32_deleted")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"FAT32 deleted content source open failed: {exc}")
            return result
        with source_stream:
            for entry in entries[:256]:
                if not isinstance(entry, dict):
                    continue
                size = entry.get("size")
                first_cluster = entry.get("first_cluster")
                attributes_text = entry.get("attributes")
                try:
                    attributes = int(attributes_text, 16) if isinstance(attributes_text, str) else -1
                except ValueError:
                    attributes = -1
                if (
                    not isinstance(size, int) or size <= 0
                    or size > self.limits.max_single_artifact_size or size > 8 * 1024 * 1024
                    or not isinstance(first_cluster, int) or first_cluster < 2
                    or entry.get("fat32_cluster_high_reserved", 0) != 0
                    or attributes < 0 or attributes & 0x18
                ):
                    continue
                required_clusters = (size + cluster_size - 1) // cluster_size
                if required_clusters > 64:
                    continue
                chain: list[dict[str, int]] = []
                current_cluster = first_cluster
                visited: set[int] = set()
                chain_valid = True
                chain_validation = "single_cluster_direct"
                for cluster_index in range(required_clusters):
                    if current_cluster in visited or current_cluster < 2:
                        chain_valid = False
                        break
                    visited.add(current_cluster)
                    cluster_sector = first_data_sector + (current_cluster - 2) * sectors_per_cluster
                    physical_offset = cluster_sector * bytes_per_sector
                    if physical_offset < 0 or physical_offset + cluster_size > artifact.size:
                        chain_valid = False
                        break
                    chain.append({
                        "cluster": current_cluster, "physical_offset": physical_offset,
                        "length": cluster_size,
                    })
                    if required_clusters == 1:
                        break
                    fat_entry_offset = fat_offset + current_cluster * 4
                    if fat_entry_offset < fat_offset or fat_entry_offset + 4 > fat_end or fat_entry_offset + 4 > artifact.size:
                        chain_valid = False
                        break
                    source_stream.seek(fat_entry_offset)
                    raw_next = source_stream.read(4)
                    if len(raw_next) != 4:
                        chain_valid = False
                        break
                    next_cluster = int.from_bytes(raw_next, "little") & 0x0FFFFFFF
                    if cluster_index == required_clusters - 1:
                        if next_cluster < 0x0FFFFFF8:
                            chain_valid = False
                        else:
                            chain_validation = "complete_fat_chain_eoc"
                        break
                    if (
                        next_cluster < 2 or next_cluster == 0x0FFFFFF7
                        or 0x0FFFFFF0 <= next_cluster <= 0x0FFFFFF6
                        or next_cluster >= 0x0FFFFFF8
                    ):
                        chain_valid = False
                        break
                    current_cluster = next_cluster
                if not chain_valid or len(chain) != required_clusters:
                    continue
                reason = self.can_register(artifact, size)
                if reason:
                    result.errors.append(
                        f"skipped FAT32 deleted entry {entry.get('entry_index')}: {reason}"
                    )
                    continue
                logical_name = next(
                    (
                        value for value in (
                            entry.get("long_name"), entry.get("reconstructed_short_name"),
                            entry.get("short_name"),
                        )
                        if isinstance(value, str) and value
                    ),
                    f"deleted_cluster_{first_cluster}",
                )[:1_024]
                entry_index = entry.get("entry_index")
                output = target_root / (
                    f"entry_{entry_index if isinstance(entry_index, int) else 0:04d}_"
                    f"cluster_{first_cluster:08d}_{safe_name(logical_name)}"
                )
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        remaining = size
                        for segment in chain:
                            take = min(remaining, segment["length"])
                            source_stream.seek(segment["physical_offset"])
                            payload = source_stream.read(take)
                            if len(payload) != take:
                                raise RuntimeError("mapped FAT32 cluster bytes are truncated")
                            writer.write(payload)
                            remaining -= take
                        if remaining:
                            raise RuntimeError("validated FAT32 cluster chain did not cover declared size")
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(
                        f"failed FAT32 deleted entry {entry_index} recovery: {exc}"
                    )
                    continue
                child = self.register_file(output, artifact, logical_name)
                if child is None:
                    result.errors.append(
                        f"skipped FAT32 deleted entry {entry_index}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};entry_index:{entry_index};entry_offset:{entry.get('offset')};"
                    f"name:{logical_name};first_cluster:{first_cluster};"
                    f"physical_offset:{chain[0]['physical_offset']};cluster_chain:{chain};"
                    f"size:{size};attributes:{attributes_text};lfn_slot_offsets:{entry.get('lfn_slot_offsets')};"
                    f"raw_entry:{entry.get('raw_hex')};"
                    f"directory_start_cluster:{entry.get('directory_start_cluster')};"
                    f"directory_cluster_lineage:{entry.get('directory_cluster_lineage')};"
                    f"directory_source_entry_offset:{entry.get('directory_source_entry_offset')};"
                    f"directory_short_name:{entry.get('directory_short_name')};"
                    f"directory_long_name:{entry.get('directory_long_name')};"
                    f"directory_lfn_slot_offsets:{entry.get('directory_lfn_slot_offsets')};"
                    f"directory_identity_lineage:{entry.get('directory_identity_lineage')};"
                    f"chain_validation:{chain_validation};"
                    "allocation_state:unknown_deleted_cluster_may_be_reused"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} bounded deleted FAT32 file(s)",
                category="fat_deleted_content_recovery",
                severity="info",
                confidence=0.72,
                explanation=(
                    "Each deleted regular-file entry declared bounded nonzero content. Single-cluster candidates map directly; larger files require an exact, non-looping, image-bounded FAT chain ending at EOC after the final required cluster. "
                    "Only declared bytes were registered recursively; because deletion permits cluster reuse, recovered content is a cautious candidate rather than proof it still belongs to that entry."
                ),
                source="builtin_fat32_deleted_extractor",
                supporting_evidence=evidence[:256],
            ))
        return result

    def extract_ext_root_regular_files(self, artifact: Artifact) -> ExtractionResult:
        """Recover complete bounded active regular files from validated ext directories."""
        result = ExtractionResult()
        entries = next((
            observation.value
            for observation in self.workspace.database.observations(artifact.id)
            if observation.key == "filesystem.ext.root.recoverable_regular_files"
            and isinstance(observation.value, list)
        ), [])
        if not entries:
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_ext_root")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"ext root source open failed: {exc}")
            return result
        with source_stream:
            for entry in entries[:128]:
                if not isinstance(entry, dict):
                    continue
                size = entry.get("size")
                segments = entry.get("data_segments")
                if not isinstance(size, int) or not 0 < size <= 8 * 1024 * 1024 or not isinstance(segments, list):
                    continue
                normalized: list[dict[str, int]] = []
                expected_logical = 0
                for segment in segments[:64]:
                    if not isinstance(segment, dict) or not all(
                        isinstance(segment.get(key), int)
                        for key in ("logical_offset", "physical_offset", "length")
                    ):
                        normalized = []
                        break
                    logical_offset = int(segment["logical_offset"])
                    physical_offset = int(segment["physical_offset"])
                    length = int(segment["length"])
                    if (
                        logical_offset != expected_logical or length <= 0
                        or physical_offset < 0 or physical_offset + length > artifact.size
                        or expected_logical + length > size
                    ):
                        normalized = []
                        break
                    normalized.append({
                        "logical_offset": logical_offset,
                        "physical_offset": physical_offset,
                        "length": length,
                    })
                    expected_logical += length
                if not normalized or expected_logical != size:
                    continue
                reason = self.can_register(artifact, size)
                if reason:
                    result.errors.append(f"skipped ext inode {entry.get('inode')}: {reason}")
                    continue
                name = str(entry.get("name") or f"inode_{entry.get('inode')}")[:1_024]
                source_offset = entry.get("directory_entry_offset")
                offset_label = source_offset if isinstance(source_offset, int) else int(entry.get("inode", 0))
                output = target_root / f"entry_{offset_label:012d}_{safe_name(name)}"
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        for segment in normalized:
                            source_stream.seek(segment["physical_offset"])
                            payload = source_stream.read(segment["length"])
                            if len(payload) != segment["length"]:
                                raise RuntimeError("truncated ext data segment")
                            writer.write(payload)
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(f"failed ext inode {entry.get('inode')} recovery: {exc}")
                    continue
                child = self.register_file(output, artifact, name)
                if child is None:
                    result.errors.append(f"skipped ext inode {entry.get('inode')}: duplicate or limit")
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};name:{name};directory_entry_offset:{source_offset};"
                    f"inode:{entry.get('inode')};inode_offset:{entry.get('inode_offset')};"
                    f"inode_mode:{entry.get('inode_mode')};inode_flags:{entry.get('inode_flags')};"
                    f"link_count:{entry.get('link_count')};mapping_mode:{entry.get('mapping_mode')};"
                    f"mapping_provenance:{entry.get('mapping_provenance')};"
                    f"directory_inode:{entry.get('directory_inode')};"
                    f"directory_inode_offset:{entry.get('directory_inode_offset')};"
                    f"directory_path:{entry.get('directory_path')};"
                    f"directory_inode_lineage:{entry.get('directory_inode_lineage')};"
                    f"directory_source_entry_offset:{entry.get('directory_source_entry_offset')};"
                    f"directory_block_lineage:{entry.get('directory_block_lineage')};"
                    f"size:{size};data_segments:{normalized};source_data_segments:{segments}"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} bounded active ext file(s)",
                category="ext_root_file_recovery", severity="info", confidence=0.96,
                explanation=(
                    "Validated active root/subdirectory entries resolved to allocated regular-file inodes with complete initialized depth-zero/one/two extent-tree or direct/single-indirect mappings. "
                    "Only image-bounded declared bytes were registered as recursive children; intermediate-index/leaf/indirect-pointer/data offsets are preserved while sparse, deeper-tree, double-indirect, deleted, and incomplete mappings are excluded."
                ),
                source="builtin_ext_root_extractor", supporting_evidence=evidence[:128],
            ))
        return result

    def extract_exfat_deleted_contiguous(self, artifact: Artifact) -> ExtractionResult:
        """Recover checksum-validated bounded deleted exFAT file content."""
        result = ExtractionResult()
        values = {
            observation.key: observation.value
            for observation in self.workspace.database.observations(artifact.id)
        }
        root_entries = values.get("filesystem.exfat.deleted_file_sets")
        subdirectory_entries = values.get("filesystem.exfat.subdirectory_deleted_file_sets")
        entries = [
            item
            for collection in (root_entries, subdirectory_entries)
            if isinstance(collection, list)
            for item in collection
        ]
        bytes_per_sector = values.get("filesystem.exfat.bytes_per_sector")
        cluster_size = values.get("filesystem.exfat.cluster_size")
        sectors_per_cluster = values.get("filesystem.exfat.sectors_per_cluster")
        heap_offset = values.get("filesystem.exfat.cluster_heap_offset_sectors")
        fat_offset_sectors = values.get("filesystem.exfat.fat_offset_sectors")
        fat_length_sectors = values.get("filesystem.exfat.fat_length_sectors")
        volume_cluster_count = values.get("filesystem.exfat.cluster_count")
        if not entries or not all(isinstance(value, int) for value in (
            bytes_per_sector, cluster_size, sectors_per_cluster, heap_offset, volume_cluster_count,
            fat_offset_sectors, fat_length_sectors,
        )):
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, "builtin_exfat_deleted")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"exFAT deleted source open failed: {exc}")
            return result
        with source_stream:
            for entry in entries[:256]:
                if not isinstance(entry, dict) or entry.get("checksum_valid_after_in_use_restore") is not True:
                    continue
                try:
                    stream_flags = int(str(entry.get("stream_flags")), 16)
                    attributes = int(str(entry.get("attributes")), 16)
                except ValueError:
                    continue
                first_cluster = entry.get("first_cluster")
                data_length = entry.get("data_length")
                valid_length = entry.get("valid_data_length")
                if (
                    attributes & 0x10
                    or not isinstance(first_cluster, int) or first_cluster < 2
                    or not isinstance(data_length, int) or not 0 < data_length <= 8 * 1024 * 1024
                    or not isinstance(valid_length, int) or not 0 <= valid_length <= data_length
                ):
                    continue
                required_clusters = (data_length + cluster_size - 1) // cluster_size
                if required_clusters > 64:
                    continue
                segments: list[dict[str, int]] = []
                current = first_cluster
                visited: set[int] = set()
                mapping_valid = True
                mapping_mode = "nofatchain_contiguous" if stream_flags & 0x02 else "fat_chain_eoc"
                fat_byte_offset = fat_offset_sectors * bytes_per_sector
                fat_byte_end = fat_byte_offset + fat_length_sectors * bytes_per_sector
                for cluster_index in range(required_clusters):
                    if current in visited or not 2 <= current < volume_cluster_count + 2:
                        mapping_valid = False
                        break
                    visited.add(current)
                    physical_offset = (
                        heap_offset + (current - 2) * sectors_per_cluster
                    ) * bytes_per_sector
                    if physical_offset < 0 or physical_offset + cluster_size > artifact.size:
                        mapping_valid = False
                        break
                    segments.append({"cluster": current, "physical_offset": physical_offset, "length": cluster_size})
                    if stream_flags & 0x02:
                        current += 1
                        continue
                    fat_entry_offset = fat_byte_offset + current * 4
                    if fat_entry_offset < fat_byte_offset or fat_entry_offset + 4 > fat_byte_end or fat_entry_offset + 4 > artifact.size:
                        mapping_valid = False
                        break
                    source_stream.seek(fat_entry_offset)
                    next_cluster = int.from_bytes(source_stream.read(4), "little")
                    if cluster_index == required_clusters - 1:
                        if next_cluster < 0xFFFFFFF8:
                            mapping_valid = False
                        break
                    if next_cluster < 2 or next_cluster == 0xFFFFFFF7 or 0xFFFFFFF0 <= next_cluster <= 0xFFFFFFF6 or next_cluster >= 0xFFFFFFF8:
                        mapping_valid = False
                        break
                    current = next_cluster
                if not mapping_valid or len(segments) != required_clusters:
                    continue
                physical_capacity = required_clusters * cluster_size
                reason = self.can_register(artifact, data_length)
                if reason:
                    result.errors.append(f"skipped exFAT deleted entry {entry.get('entry_index')}: {reason}")
                    continue
                name = str(entry.get("name") or f"deleted_cluster_{first_cluster}")[:1_024]
                source_offset = entry.get("offset")
                offset_label = source_offset if isinstance(source_offset, int) else int(entry.get("entry_index", 0))
                output = target_root / f"entry_{offset_label:012d}_{safe_name(name)}"
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        remaining = valid_length
                        for segment in segments:
                            if not remaining:
                                break
                            take = min(remaining, segment["length"])
                            source_stream.seek(segment["physical_offset"])
                            payload = source_stream.read(take)
                            if len(payload) != take:
                                raise RuntimeError("contiguous exFAT valid-data bytes are truncated")
                            writer.write(payload)
                            remaining -= take
                        self._write_zeros(writer, data_length - valid_length)
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(f"failed exFAT deleted entry {entry.get('entry_index')} recovery: {exc}")
                    continue
                child = self.register_file(output, artifact, name)
                if child is None:
                    result.errors.append(f"skipped exFAT deleted entry {entry.get('entry_index')}: duplicate or limit")
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};entry_offset:{entry.get('offset')};entry_offsets:{entry.get('entry_offsets')};"
                    f"name:{name};first_cluster:{first_cluster};cluster_count:{required_clusters};"
                    f"mapping_mode:{mapping_mode};physical_offset:{segments[0]['physical_offset']};"
                    f"segments:{segments};physical_capacity:{physical_capacity};"
                    f"data_length:{data_length};valid_data_length:{valid_length};"
                    f"zero_fill_offset:{valid_length};zero_fill_length:{data_length - valid_length};"
                    f"set_checksum:{entry.get('stored_set_checksum')};stream_flags:{entry.get('stream_flags')};"
                    f"directory_start_cluster:{entry.get('directory_start_cluster')};"
                    f"directory_cluster_lineage:{entry.get('directory_cluster_lineage')};"
                    f"directory_source_entry_offset:{entry.get('directory_source_entry_offset')};"
                    f"allocation_state:{entry.get('allocation_bitmap_state', 'unknown_deleted_clusters_may_be_reused')};"
                    f"allocation_reuse_warning:{entry.get('allocation_reuse_warning')};"
                    "allocation_interpretation:current_bitmap_state_is_not_deleted_file_ownership"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} bounded deleted exFAT file(s)",
                category="exfat_deleted_content_recovery", severity="info", confidence=0.74,
                explanation=(
                    "Checksum-validated inactive regular-file sets use either complete bounded NoFatChain contiguous allocation or an exact non-looping FAT chain ending at EOC. Bytes through ValidDataLength were copied and the logical tail through DataLength was zero-filled. "
                    "A validated allocation bitmap can warn that candidate clusters are currently allocated, but that current state is not treated as proof of deleted-file ownership. Children remain cautious recovery candidates."
                ),
                source="builtin_exfat_deleted_extractor", supporting_evidence=evidence[:256],
            ))
        return result

    def extract_fat_active_files(self, artifact: Artifact) -> ExtractionResult:
        """Recover bounded active FAT regular files through exact EOC chains."""
        result = ExtractionResult()
        values = {
            observation.key: observation.value
            for observation in self.workspace.database.observations(artifact.id)
        }
        variant = values.get("filesystem.fat.variant")
        fat_bits = 12 if variant == "fat12" else 16 if variant == "fat16" else 32 if variant == "fat32" else 0
        entries = (
            values.get("filesystem.fat.root.recoverable_regular_files")
            if fat_bits == 32 else values.get(f"filesystem.fat{fat_bits}.root.recoverable_regular_files")
            if fat_bits else None
        )
        bytes_per_sector = values.get("filesystem.fat.bytes_per_sector")
        sectors_per_cluster = values.get("filesystem.fat.sectors_per_cluster")
        reserved_sectors = values.get("filesystem.fat.reserved_sector_count")
        fat_size = values.get("filesystem.fat.size_sectors")
        fat_count = values.get("filesystem.fat.count")
        first_data_sector = (
            reserved_sectors + fat_count * fat_size
            if fat_bits == 32 and all(isinstance(value, int) for value in (reserved_sectors, fat_count, fat_size))
            else values.get(f"filesystem.fat{fat_bits}.root.first_data_sector") if fat_bits else None
        )
        cluster_count = (
            values.get("filesystem.fat32.cluster_count")
            if fat_bits == 32 else values.get(f"filesystem.fat{fat_bits}.root.cluster_count")
            if fat_bits else None
        )
        if not isinstance(entries, list) or not entries:
            return result
        if not all(isinstance(value, int) for value in (
            bytes_per_sector, sectors_per_cluster, reserved_sectors,
            fat_size, first_data_sector, cluster_count,
        )):
            result.errors.append(f"skipped active FAT{fat_bits} files: missing validated geometry")
            return result
        cluster_size = bytes_per_sector * sectors_per_cluster
        fat_offset = (
            values.get("filesystem.fat.root.active_fat_offset")
            if fat_bits == 32 else reserved_sectors * bytes_per_sector
        )
        if not isinstance(fat_offset, int):
            result.errors.append(f"skipped active FAT{fat_bits} files: missing active FAT offset")
            return result
        fat_end = fat_offset + fat_size * bytes_per_sector
        if (
            bytes_per_sector not in {512, 1024, 2048, 4096}
            or sectors_per_cluster <= 0 or sectors_per_cluster & (sectors_per_cluster - 1)
            or not 0 < cluster_size <= 2 * 1024 * 1024
            or reserved_sectors <= 0 or fat_size <= 0 or first_data_sector <= 0
            or (fat_bits == 12 and not 0 < cluster_count < 4_085)
            or (fat_bits == 16 and not 4_085 <= cluster_count < 65_525)
            or (fat_bits == 32 and cluster_count < 65_525)
        ):
            result.errors.append(f"skipped active FAT{fat_bits} files: invalid validated geometry")
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path("extracted", artifact.id, f"builtin_fat{fat_bits}_active")
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"active FAT{fat_bits} source open failed: {exc}")
            return result
        eoc_minimum = 0xFF8 if fat_bits == 12 else 0xFFF8 if fat_bits == 16 else 0x0FFFFFF8
        with source_stream:
            for entry_index, entry in enumerate(entries[:256]):
                if not isinstance(entry, dict):
                    continue
                size = entry.get("size")
                first_cluster = entry.get("first_cluster")
                high_reserved = entry.get(f"fat{fat_bits}_cluster_high_reserved")
                if (
                    not isinstance(size, int) or not 0 < size <= 8 * 1024 * 1024
                    or size > self.limits.max_single_artifact_size
                    or not isinstance(first_cluster, int) or not 2 <= first_cluster < cluster_count + 2
                    or high_reserved != 0
                ):
                    continue
                required_clusters = (size + cluster_size - 1) // cluster_size
                if not 1 <= required_clusters <= 64:
                    continue
                chain: list[dict[str, object]] = []
                visited: set[int] = set()
                current = first_cluster
                valid = True
                for cluster_index in range(required_clusters):
                    if current in visited or not 2 <= current < cluster_count + 2:
                        valid = False
                        break
                    visited.add(current)
                    physical_offset = (
                        first_data_sector + (current - 2) * sectors_per_cluster
                    ) * bytes_per_sector
                    fat_entry_offset = (
                        fat_offset + current + current // 2
                        if fat_bits == 12 else fat_offset + current * 2
                        if fat_bits == 16 else fat_offset + current * 4
                    )
                    fat_entry_width = 4 if fat_bits == 32 else 2
                    if (
                        physical_offset < 0 or physical_offset + cluster_size > artifact.size
                        or fat_entry_offset < fat_offset or fat_entry_offset + fat_entry_width > fat_end
                        or fat_entry_offset + fat_entry_width > artifact.size
                    ):
                        valid = False
                        break
                    source_stream.seek(fat_entry_offset)
                    raw_next = source_stream.read(fat_entry_width)
                    if len(raw_next) != fat_entry_width:
                        valid = False
                        break
                    packed = int.from_bytes(raw_next, "little")
                    next_cluster = (
                        (packed >> 4) & 0x0FFF if fat_bits == 12 and current & 1
                        else packed & 0x0FFF if fat_bits == 12
                        else packed if fat_bits == 16 else packed & 0x0FFFFFFF
                    )
                    chain.append({
                        "cluster": current, "physical_offset": physical_offset,
                        "length": cluster_size, "fat_entry_offset": fat_entry_offset,
                        "fat_entry_raw": raw_next.hex(), "next_cluster": next_cluster,
                    })
                    if cluster_index == required_clusters - 1:
                        if next_cluster < eoc_minimum:
                            valid = False
                        break
                    if next_cluster < 2 or next_cluster >= cluster_count + 2 or next_cluster >= eoc_minimum:
                        valid = False
                        break
                    current = next_cluster
                if not valid or len(chain) != required_clusters:
                    continue
                reason = self.can_register(artifact, size)
                if reason:
                    result.errors.append(
                        f"skipped active FAT{fat_bits} file at {entry.get('offset')}: {reason}"
                    )
                    continue
                logical_name = next((
                    value for value in (entry.get("long_name"), entry.get("short_name"))
                    if isinstance(value, str) and value
                ), f"ACTIVE_CLUSTER_{first_cluster:08d}.bin")[:1_024]
                output = target_root / (
                    f"entry_{entry_index:04d}_cluster_{first_cluster:08d}_{safe_name(logical_name)}"
                )
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        remaining = size
                        for segment in chain:
                            take = min(remaining, int(segment["length"]))
                            source_stream.seek(int(segment["physical_offset"]))
                            payload = source_stream.read(take)
                            if len(payload) != take:
                                raise RuntimeError("mapped active FAT cluster is truncated")
                            writer.write(payload)
                            remaining -= take
                        if remaining:
                            raise RuntimeError("active FAT chain did not cover declared logical size")
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(
                        f"failed active FAT{fat_bits} file at {entry.get('offset')}: {exc}"
                    )
                    continue
                child = self.register_file(output, artifact, logical_name)
                if child is None:
                    result.errors.append(
                        f"skipped active FAT{fat_bits} file at {entry.get('offset')}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};variant:FAT{fat_bits};entry_offset:{entry.get('offset')};"
                    f"short_name:{entry.get('short_name')};long_name:{entry.get('long_name')};"
                    f"lfn_slot_offsets:{entry.get('lfn_slot_offsets')};size:{size};"
                    f"first_cluster:{first_cluster};cluster_chain:{chain};"
                    f"directory_start_cluster:{entry.get('directory_start_cluster')};"
                    f"directory_cluster_lineage:{entry.get('directory_cluster_lineage')};"
                    f"directory_source_entry_offset:{entry.get('directory_source_entry_offset')};"
                    f"directory_short_name:{entry.get('directory_short_name')};"
                    f"directory_long_name:{entry.get('directory_long_name')};"
                    f"directory_lfn_slot_offsets:{entry.get('directory_lfn_slot_offsets')};"
                    f"directory_identity_lineage:{entry.get('directory_identity_lineage')};"
                    "chain_validation:exact_size_required_chain_eoc;allocation_state:active_directory_reference"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Recovered {len(result.artifacts)} active FAT{fat_bits} regular file(s)",
                category=f"fat{fat_bits}_active_file_recovery", severity="info", confidence=0.96,
                explanation=(
                    "A validated active root/subdirectory entry supplied a bounded nonzero logical size and optional checksum-valid intact LFN. "
                    "Only unique image-bounded FAT chains with exactly the size-required cluster count and an EOC marker on the final cluster were copied and registered recursively."
                ),
                source=f"builtin_fat{fat_bits}_active_file_extractor",
                supporting_evidence=evidence[:256],
            ))
        return result

    def extract_fat_lost_chains(self, artifact: Artifact) -> ExtractionResult:
        """Materialize only complete image-bounded anonymous FAT lost chains."""
        result = ExtractionResult()
        values = {
            observation.key: observation.value
            for observation in self.workspace.database.observations(artifact.id)
        }
        variant = values.get("filesystem.fat.variant")
        fat_bits = 12 if variant == "fat12" else 16 if variant == "fat16" else 32 if variant == "fat32" else 0
        inventory = values.get(f"filesystem.fat{fat_bits}.lost_chains") if fat_bits else None
        if not isinstance(inventory, dict) or inventory.get("available") is not True:
            return result
        chains = inventory.get("chains")
        bytes_per_sector = values.get("filesystem.fat.bytes_per_sector")
        sectors_per_cluster = values.get("filesystem.fat.sectors_per_cluster")
        if (
            not isinstance(chains, list) or not chains
            or not isinstance(bytes_per_sector, int) or bytes_per_sector not in {512, 1024, 2048, 4096}
            or not isinstance(sectors_per_cluster, int) or sectors_per_cluster <= 0
            or sectors_per_cluster & (sectors_per_cluster - 1)
        ):
            return result
        cluster_size = bytes_per_sector * sectors_per_cluster
        if not 0 < cluster_size <= 2 * 1024 * 1024:
            return result
        deleted_starts: set[int] = set()
        for key in (
            "filesystem.fat.deleted_short_entries",
            "filesystem.fat.subdirectory_deleted_entries",
            f"filesystem.fat{fat_bits}.root.deleted_entries",
            f"filesystem.fat{fat_bits}.root.subdirectory_deleted_entries",
        ):
            entries = values.get(key)
            if not isinstance(entries, list):
                continue
            deleted_starts.update(
                entry["first_cluster"] for entry in entries
                if isinstance(entry, dict) and isinstance(entry.get("first_cluster"), int)
            )
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path(
            "extracted", artifact.id, f"builtin_fat{fat_bits}_lost_chains",
        )
        evidence: list[str] = []
        skipped_deleted_starts: list[int] = []
        total_candidate_bytes = 0
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"FAT{fat_bits} lost-chain source open failed: {exc}")
            return result
        with source_stream:
            for chain_index, candidate in enumerate(chains[:32]):
                if not isinstance(candidate, dict) or candidate.get("complete_eoc_chain") is not True:
                    continue
                start_cluster = candidate.get("start_cluster")
                segments = candidate.get("cluster_chain")
                if not isinstance(start_cluster, int) or start_cluster in deleted_starts:
                    if isinstance(start_cluster, int) and start_cluster in deleted_starts:
                        skipped_deleted_starts.append(start_cluster)
                    continue
                if not isinstance(segments, list) or not 1 <= len(segments) <= 64:
                    continue
                normalized: list[dict[str, object]] = []
                valid = True
                for segment_index, segment in enumerate(segments):
                    if not isinstance(segment, dict):
                        valid = False
                        break
                    cluster = segment.get("cluster")
                    data_offset = segment.get("data_offset")
                    data_length = segment.get("data_length")
                    next_cluster = segment.get("next_cluster")
                    if (
                        not isinstance(cluster, int) or cluster < 2
                        or not isinstance(data_offset, int) or data_offset < 0
                        or data_length != cluster_size
                        or data_offset + cluster_size > artifact.size
                        or segment.get("data_within_supplied_image") is not True
                        or not isinstance(next_cluster, int)
                        or any(item.get("cluster") == cluster for item in normalized)
                    ):
                        valid = False
                        break
                    if segment_index + 1 < len(segments):
                        following = segments[segment_index + 1]
                        if not isinstance(following, dict) or following.get("cluster") != next_cluster:
                            valid = False
                            break
                    normalized.append(dict(segment))
                eoc_minimum = 0xFF8 if fat_bits == 12 else 0xFFF8 if fat_bits == 16 else 0x0FFFFFF8
                if (
                    not valid or len(normalized) != len(segments)
                    or normalized[0].get("cluster") != start_cluster
                    or not isinstance(normalized[-1].get("next_cluster"), int)
                    or int(normalized[-1]["next_cluster"]) < eoc_minimum
                ):
                    continue
                size = len(normalized) * cluster_size
                if size > 8 * 1024 * 1024 or total_candidate_bytes + size > 8 * 1024 * 1024:
                    result.errors.append(
                        f"skipped FAT{fat_bits} lost chain {start_cluster}: 8-MiB lost-chain extraction bound"
                    )
                    continue
                reason = self.can_register(artifact, size)
                if reason:
                    result.errors.append(f"skipped FAT{fat_bits} lost chain {start_cluster}: {reason}")
                    continue
                logical_name = f"FAT{fat_bits}_LOST_CHAIN_{start_cluster:08d}.bin"
                output = target_root / f"chain_{chain_index:04d}_cluster_{start_cluster:08d}.bin"
                output.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with output.open("xb") as writer:
                        for segment in normalized:
                            source_stream.seek(int(segment["data_offset"]))
                            payload = source_stream.read(cluster_size)
                            if len(payload) != cluster_size:
                                raise RuntimeError("mapped lost-chain cluster is truncated")
                            writer.write(payload)
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(f"failed FAT{fat_bits} lost chain {start_cluster}: {exc}")
                    continue
                child = self.register_file(output, artifact, logical_name)
                if child is None:
                    result.errors.append(
                        f"skipped FAT{fat_bits} lost chain {start_cluster}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                total_candidate_bytes += child.size
                evidence.append(
                    f"child:{child.id};variant:FAT{fat_bits};start_cluster:{start_cluster};"
                    f"size:{child.size};cluster_chain:{normalized};termination:eoc;"
                    "logical_size:unknown_full_clusters_include_final_cluster_slack;"
                    "directory_ownership:not_inferred;source_scope:bounded_validated_active_entries"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Materialized {len(result.artifacts)} anonymous FAT{fat_bits} lost-chain candidate(s)",
                category=f"fat{fat_bits}_lost_chain_recovery", severity="info", confidence=0.64,
                explanation=(
                    "Only EOC-terminated candidates with every recorded full cluster inside the immutable image were copied under artifact/count and an additional 8-MiB total bound. "
                    "No filename or logical length is known, so each anonymous child includes the entire final cluster (possibly slack) and remains a recursive forensic lead rather than proof of deletion or ownership."
                ),
                source=f"builtin_fat{fat_bits}_lost_chain_extractor",
                supporting_evidence=[
                    *evidence[:128],
                    f"skipped_candidate_starts_with_deleted_entry_metadata:{sorted(set(skipped_deleted_starts))[:128]}",
                ],
            ))
        return result

    def extract_validated_partitions(self, artifact: Artifact) -> ExtractionResult:
        """Copy complete small partition extents after native table/boot validation."""
        result = ExtractionResult()
        candidates: list[dict[str, object]] = []
        candidate_keys = {
            "disk.mbr.partition_filesystems",
            "disk.mbr.logical_partition_filesystems",
            "disk.gpt.partition_filesystems",
        }
        for observation in self.workspace.database.observations(artifact.id):
            if observation.key not in candidate_keys:
                continue
            records = observation.value
            if not isinstance(records, list):
                continue
            candidates.extend(
                {
                    **record,
                    "source_observation_key": observation.key,
                    "source_observation_id": observation.id,
                }
                for record in records
                if isinstance(record, dict)
            )
        if not candidates:
            return result
        source = self.workspace.resolve_stored_path(artifact.path)
        target_root = self.workspace.path(
            "extracted", artifact.id, "builtin_partitions",
        )
        seen_extents: set[tuple[int, int]] = set()
        evidence: list[str] = []
        try:
            source_stream = source.open("rb")
        except OSError as exc:
            result.errors.append(f"partition source open failed: {exc}")
            return result
        with source_stream:
            for candidate_index, candidate in enumerate(candidates[:64]):
                validation = candidate.get("validation")
                offset = candidate.get("partition_offset")
                size = candidate.get("declared_partition_bytes")
                available = candidate.get("available_partition_bytes")
                detected = candidate.get("detected_filesystem")
                if (
                    not isinstance(validation, dict) or validation.get("valid") is not True
                    or not isinstance(detected, str) or not detected
                    or not isinstance(offset, int) or offset < 0
                    or not isinstance(size, int) or size <= 0
                    or available != size
                    or candidate.get("partition_entry_valid") is not True
                    or candidate.get("partition_within_supplied_image") is not True
                    or offset + size > artifact.size
                ):
                    continue
                if candidate.get("partition_extent_ambiguous") is True:
                    result.errors.append(
                        "skipped ambiguous validated partition "
                        f"{candidate.get('partition_extent_identity') or 'unknown'} "
                        f"at offset {offset}: overlaps {candidate.get('partition_extent_conflict_count')} "
                        "other declared partition extent(s)"
                    )
                    continue
                extent = (offset, size)
                if extent in seen_extents:
                    continue
                seen_extents.add(extent)
                reason = self.can_register(artifact, size)
                if reason:
                    result.errors.append(
                        f"skipped validated partition at offset {offset}: {reason}"
                    )
                    continue
                table = candidate.get("partition_table")
                raw_identity_index: object
                if table == "gpt":
                    raw_identity_index = candidate.get("gpt_partition_index")
                    identity_prefix, identity_width = "gpt", 3
                elif table == "mbr_logical":
                    raw_identity_index = candidate.get("logical_partition_index")
                    identity_prefix, identity_width = "mbr_logical", 3
                else:
                    raw_identity_index = candidate.get("slot")
                    identity_prefix, identity_width = "mbr_primary", 2
                identity_index = (
                    raw_identity_index
                    if isinstance(raw_identity_index, int)
                    and not isinstance(raw_identity_index, bool)
                    and raw_identity_index > 0
                    else candidate_index + 1
                )
                identity = f"{identity_prefix}_{identity_index:0{identity_width}d}"
                logical_name = f"{identity}_{detected}.img"
                output = target_root / safe_name(logical_name)
                output.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                try:
                    source_stream.seek(offset)
                    with output.open("xb") as writer:
                        remaining = size
                        while remaining:
                            chunk = source_stream.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise RuntimeError("validated partition extent read ended early")
                            writer.write(chunk)
                            written += len(chunk)
                            remaining -= len(chunk)
                    if written != size:
                        raise RuntimeError("validated partition extent size mismatch")
                except (OSError, RuntimeError) as exc:
                    output.unlink(missing_ok=True)
                    result.errors.append(
                        f"failed validated partition at offset {offset}: {exc}"
                    )
                    continue
                child = self.register_file(output, artifact, logical_name)
                if child is None:
                    result.errors.append(
                        f"skipped validated partition at offset {offset}: duplicate or extraction limit"
                    )
                    continue
                result.artifacts.append(child)
                result.extracted_bytes += child.size
                evidence.append(
                    f"child:{child.id};source_observation_id:{candidate.get('source_observation_id')};"
                    f"source_observation_key:{candidate.get('source_observation_key')};"
                    f"table:{table or 'mbr_primary'};offset:{offset};length:{size};"
                    f"detected_filesystem:{detected};partition_record:{candidate}"
                )
        if result.artifacts:
            result.findings.append(Finding(
                artifact_id=artifact.id,
                title=f"Materialized {len(result.artifacts)} validated partition extent(s)",
                category="validated_partition_extraction", severity="info", confidence=0.99,
                explanation=(
                    "Only complete supplied-image extents whose partition entry and format-specific boot structure validated were copied under artifact/count/byte/depth limits. "
                    "Each immutable child retains its exact MBR, EBR, or CRC-gated GPT record and byte range, then re-enters ordinary recursive analysis without mounting."
                ),
                source="builtin_partition_extent_extractor",
                supporting_evidence=evidence[:64],
            ))
        return result

    @staticmethod
    def _write_zeros(writer, length: int) -> None:
        """Write an already-budgeted logical zero range without a large allocation."""
        block = b"\x00" * min(1024 * 1024, length)
        remaining = length
        while remaining:
            take = min(remaining, len(block))
            writer.write(block[:take])
            remaining -= take

    def extract_supported(self, artifact: Artifact) -> ExtractionResult:
        ntfs_result = self.extract_ntfs_resident_data(artifact)
        ntfs_nonresident = self.extract_ntfs_nonresident_data(artifact)
        ntfs_result.artifacts.extend(ntfs_nonresident.artifacts)
        ntfs_result.findings.extend(ntfs_nonresident.findings)
        ntfs_result.errors.extend(ntfs_nonresident.errors)
        ntfs_result.extracted_bytes += ntfs_nonresident.extracted_bytes
        if ntfs_result.artifacts or ntfs_result.errors:
            return ntfs_result
        fat_results = (
            self.extract_fat32_deleted_single_cluster(artifact),
            self.extract_fat16_deleted_files(artifact),
            self.extract_fat12_deleted_files(artifact),
            self.extract_fat_active_files(artifact),
            self.extract_fat_lost_chains(artifact),
        )
        combined_fat_result = ExtractionResult()
        for fat_result in fat_results:
            combined_fat_result.artifacts.extend(fat_result.artifacts)
            combined_fat_result.findings.extend(fat_result.findings)
            combined_fat_result.errors.extend(fat_result.errors)
            combined_fat_result.extracted_bytes += fat_result.extracted_bytes
        if combined_fat_result.artifacts or combined_fat_result.errors:
            return combined_fat_result
        exfat_result = self.extract_exfat_deleted_contiguous(artifact)
        if exfat_result.artifacts or exfat_result.errors:
            return exfat_result
        ext_result = self.extract_ext_root_regular_files(artifact)
        if ext_result.artifacts or ext_result.errors:
            return ext_result
        partition_result = self.extract_validated_partitions(artifact)
        if partition_result.artifacts or partition_result.errors:
            return partition_result
        if artifact.artifact_type == "pcap" or any(item.artifact_type == "pcap" for item in artifact.classifications):
            pcap_result = self.extract_pcap_http(artifact)
            if pcap_result.artifacts or pcap_result.errors:
                return pcap_result
        if artifact.artifact_type == "pdf" or any(item.artifact_type == "pdf" for item in artifact.classifications):
            pdf_result = self.extract_pdf_embedded(artifact)
            if pdf_result.artifacts or pdf_result.errors:
                return pdf_result
        if artifact.artifact_type == "android" or any(item.artifact_type == "android" for item in artifact.classifications):
            android_result = self.extract_android_backup(artifact)
            if android_result.artifacts or android_result.errors:
                return android_result
        if artifact.artifact_type == "firmware" or any(item.artifact_type == "firmware" for item in artifact.classifications):
            android_boot_result = self.extract_android_boot(artifact)
            if android_boot_result.artifacts or android_boot_result.errors:
                return android_boot_result
        zip_result = self.extract_zip(artifact)
        if zip_result.artifacts or zip_result.errors:
            return zip_result
        gzip_result = self.extract_gzip(artifact)
        if gzip_result.artifacts or gzip_result.errors:
            return gzip_result
        cpio_result = self.extract_cpio(artifact)
        if cpio_result.artifacts or cpio_result.errors:
            return cpio_result
        iso_result = self.extract_iso9660(artifact)
        el_torito_result = self.extract_iso9660_boot_images(artifact)
        if (
            iso_result.artifacts or iso_result.errors
            or el_torito_result.artifacts or el_torito_result.errors
        ):
            iso_result.artifacts.extend(el_torito_result.artifacts)
            iso_result.findings.extend(el_torito_result.findings)
            iso_result.errors.extend(el_torito_result.errors)
            iso_result.extracted_bytes += el_torito_result.extracted_bytes
            return iso_result
        tar_result = self.extract_tar(artifact)
        if tar_result.artifacts or tar_result.errors:
            return tar_result
        stream_result = self.extract_single_stream(artifact)
        if stream_result.artifacts or stream_result.errors:
            return stream_result
        return self.extract_pcap_http(artifact)

    def _decode_pdf_stream(self, payload: bytes, dictionary: bytes) -> bytes:
        """Apply a deliberately small safe filter subset to a PDF stream."""
        filters = re.findall(rb"/(FlateDecode|ASCIIHexDecode|ASCII85Decode|RunLengthDecode)", dictionary)
        if b"/Filter" in dictionary and not filters:
            raise ValueError("unsupported PDF stream filter")
        result = payload
        for filter_name in filters:
            if filter_name == b"FlateDecode":
                result = self._bounded_zlib_decompress(result)
            elif filter_name == b"ASCIIHexDecode":
                encoded = re.sub(rb"\s+", b"", result).split(b">", 1)[0]
                if len(encoded) % 2:
                    encoded += b"0"
                result = bytes.fromhex(encoded.decode("ascii"))
            elif filter_name == b"ASCII85Decode":
                result = base64.a85decode(result, adobe=True, ignorechars=b" \t\r\n\x0b\x0c")
            elif filter_name == b"RunLengthDecode":
                result = self._decode_pdf_run_length(result, self.limits.max_single_artifact_size)
            if len(result) > self.limits.max_single_artifact_size:
                raise ValueError("decoded PDF stream exceeds safe limit")
        return result

    @staticmethod
    def _decode_pdf_run_length(payload: bytes, maximum: int) -> bytes:
        output = bytearray()
        offset = 0
        while offset < len(payload):
            length = payload[offset]
            offset += 1
            if length == 128:
                return bytes(output)
            if length < 128:
                count = length + 1
                if offset + count > len(payload):
                    raise ValueError("truncated PDF RunLengthDecode literal")
                output.extend(payload[offset:offset + count])
                offset += count
            else:
                if offset >= len(payload):
                    raise ValueError("truncated PDF RunLengthDecode repeat")
                output.extend(payload[offset:offset + 1] * (257 - length))
                offset += 1
            if len(output) > maximum:
                raise ValueError("PDF RunLengthDecode output exceeds safe limit")
        raise ValueError("PDF RunLengthDecode missing EOD marker")

    def _bounded_zlib_decompress(self, payload: bytes) -> bytes:
        decoder = zlib.decompressobj()
        output = bytearray()
        pending = payload
        while pending:
            remaining = self.limits.max_single_artifact_size - len(output)
            if remaining <= 0:
                raise ValueError("FlateDecode output exceeds safe limit")
            before = pending
            chunk = decoder.decompress(pending, min(1024 * 1024, remaining))
            pending = decoder.unconsumed_tail
            output.extend(chunk)
            if not chunk and pending == before:
                raise ValueError("FlateDecode made no progress")
        remaining = self.limits.max_single_artifact_size - len(output)
        if remaining <= 0:
            raise ValueError("FlateDecode output exceeds safe limit")
        output.extend(decoder.flush(remaining))
        if len(output) > self.limits.max_single_artifact_size or decoder.unused_data or not decoder.eof:
            raise ValueError("FlateDecode output is incomplete, oversized, or contains trailing data")
        return bytes(output)

    @staticmethod
    def _unsafe_name(name: str) -> bool:
        path = PurePosixPath(name.replace("\\", "/"))
        return (
            path.is_absolute()
            or re.match(r"^[A-Za-z]:/", str(path)) is not None
            or ".." in path.parts
        )

    def carve_appended_zip(self, artifact: Artifact, offset: int) -> ExtractionResult:
        """Carve a validated non-zero ZIP payload while retaining parent lineage."""

        result = ExtractionResult()
        source = self.workspace.resolve_stored_path(artifact.path)
        if offset <= 0 or offset >= artifact.size:
            result.errors.append(f"invalid embedded ZIP offset: {offset}")
            return result
        carved_size = artifact.size - offset
        reason = self.can_register(artifact, carved_size)
        if reason:
            result.errors.append(f"cannot carve ZIP at {offset:#x}: {reason}")
            return result
        target_root = self.workspace.path("extracted", artifact.id, "builtin_carve")
        target_root.mkdir(parents=True, exist_ok=True)
        output = target_root / f"offset_{offset:016x}.zip"
        try:
            with source.open("rb") as reader, output.open("xb") as writer:
                reader.seek(offset)
                shutil.copyfileobj(reader, writer, length=1024 * 1024)
            if not zipfile.is_zipfile(output):
                output.unlink(missing_ok=True)
                result.errors.append(f"PK signature at {offset:#x} is not a valid ZIP container")
                return result
            child = self.register_file(
                output,
                artifact,
                f"{Path(artifact.logical_name).name}.offset_{offset:x}.zip",
            )
            if child is None:
                return result
            result.artifacts.append(child)
            result.extracted_bytes = child.size
            result.findings.append(
                Finding(
                    artifact_id=artifact.id,
                    title="Validated appended ZIP payload",
                    category="embedded_archive",
                    severity="high",
                    confidence=0.99,
                    explanation=f"Data beginning at offset {offset:#x} opened as a valid ZIP container.",
                    source="builtin_zip_carver",
                    supporting_evidence=[f"offset={offset}", child.id],
                )
            )
        except (OSError, zipfile.BadZipFile) as exc:
            output.unlink(missing_ok=True)
            result.errors.append(f"ZIP carve failed at {offset:#x}: {exc}")
        return result

    def _copy_member_bounded(self, archive: zipfile.ZipFile, member: zipfile.ZipInfo, output: Path) -> int:
        output.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        try:
            with archive.open(member) as reader, output.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    written += len(chunk)
                    if written > member.file_size + 1024 or written > self.limits.max_single_artifact_size:
                        raise RuntimeError("decompressed member exceeded declared/safe size")
                    writer.write(chunk)
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        return written

    @staticmethod
    def _unsafe_member_reason(member: zipfile.ZipInfo) -> str | None:
        path = PurePosixPath(member.filename.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            return "unsafe path"
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            return "symbolic link"
        if member.flag_bits & 0x1:
            return "encrypted member (password required)"
        return None


def _smtp_attachment_name(part: object, part_index: int) -> str:
    """Accept only bounded RFC 2231/5987-decoded names from the MIME parser."""
    getter = getattr(part, "get_filename", None)
    name = getter() if callable(getter) else None
    if isinstance(name, str) and name and len(name) <= 255 and "\x00" not in name:
        return name
    return f"smtp_attachment_{part_index:02d}.bin"
