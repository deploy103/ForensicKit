from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


ARCHIVE_TYPES = {
    "archive", "container", "zip", "7z", "rar", "tar", "cpio", "gzip", "gz", "bzip2", "xz",
    "cab", "iso", "iso9660", "jar", "apk", "ooxml",
}


class ArchiveProfile(BaseProfile):
    name = "archive"
    priority = 800

    def match_reasons(self, context: ProfileContext) -> list[str]:
        reasons: list[str] = []
        matched_types = context.artifact_types & ARCHIVE_TYPES
        if matched_types:
            reasons.append(f"classification includes archive/container type: {sorted(matched_types)}")
        if context.format_is(*ARCHIVE_TYPES):
            reasons.append(f"observed archive format is {context.format}")
        mime = (context.artifact.mime or "").lower()
        if any(marker in mime for marker in ("zip", "rar", "7z", "tar", "cpio", "gzip", "compressed", "archive")):
            reasons.append(f"MIME indicates an archive: {context.artifact.mime}")
        return reasons

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.append(
            self.recommendation(
                "sevenzip",
                (AnalysisMode.AUTO, AnalysisMode.DEEP),
                "list and validate archive structure before extraction",
                110,
            )
        )
        encrypted = context.truthy(
            "archive.encrypted", "archive.password_protected", "archive.zip.encrypted_entries",
            "zip.encrypted", "sevenzip.encrypted"
        )
        if encrypted:
            reason = "archive metadata marks at least one entry as encrypted"
            result.findings.append(
                self.finding(
                    context,
                    title="Password-protected archive content",
                    category="encrypted_container",
                    confidence=0.98,
                    explanation="Extraction requires a locally supplied or evidence-derived passphrase.",
                    evidence=[reason],
                    severity="medium",
                )
            )

        declared_compressed = context.number("archive.zip.declared_compressed_bytes")
        declared_uncompressed = context.number("archive.zip.declared_uncompressed_bytes")
        if declared_compressed is not None and declared_uncompressed is not None and declared_compressed >= 0:
            ratio = declared_uncompressed / max(1, declared_compressed)
            if declared_uncompressed >= 64 * 1024 * 1024 and ratio >= 100:
                result.findings.append(
                    self.finding(
                        context,
                        title="Archive has an extreme declared expansion ratio",
                        category="archive_bomb_risk",
                        confidence=0.9,
                        explanation="ZIP local headers declare a large uncompressed payload relative to compressed bytes. Built-in extraction limits remain active.",
                        evidence=[f"declared_uncompressed={int(declared_uncompressed)}", f"ratio={ratio:.1f}:1"],
                        severity="medium",
                    )
                )

        suspicious = context.truthy(
            "archive.polyglot", "archive.malformed", "archive.trailing_data",
            "embedded.signature_found", "structure.embedded_data",
        )
        if suspicious:
            result.recommendations.append(
                self.recommendation(
                    "binwalk3",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "container has structural or embedded-signature anomalies",
                    85,
                )
            )
        elif context.format_is("iso", "apk", "jar", "ooxml"):
            result.recommendations.append(
                self.recommendation(
                    "binwalk3",
                    (AnalysisMode.DEEP,),
                    f"deep inspection can identify nested content in {context.format} container",
                    45,
                )
            )
        tar_invalid = next((value for value in context.values("archive.tar.invalid_checksums") if isinstance(value, list)), [])
        tar_error = next((value for value in context.values("archive.tar.structure_error") if isinstance(value, str) and value), None)
        if tar_invalid or tar_error:
            result.findings.append(
                self.finding(
                    context, title="TAR member header integrity anomaly", category="archive_structure_anomaly",
                    confidence=0.92,
                    explanation="Bounded native TAR header triage found a checksum mismatch or member range that cannot fit within the evidence.",
                    evidence=[str(item)[:1_000] for item in tar_invalid[:20]] + ([tar_error] if tar_error else []),
                )
            )
        cpio_invalid = next(
            (value for value in context.values("archive.cpio.invalid_checksums") if isinstance(value, list)),
            [],
        )
        cpio_error = next(
            (
                value for value in context.values("archive.cpio.structure_error")
                if isinstance(value, str) and value
            ),
            None,
        )
        cpio_consistent = next(
            (
                value for value in context.values("archive.cpio.format_consistent")
                if isinstance(value, bool)
            ),
            True,
        )
        cpio_entries = next(
            (value for value in context.values("archive.cpio.entries") if isinstance(value, list)),
            [],
        )
        cpio_nonzero_newc_checksums = [
            item for item in cpio_entries
            if isinstance(item, dict)
            and item.get("format") == "newc"
            and item.get("checksum_field_zero") is False
        ]
        if cpio_invalid or cpio_error or cpio_consistent is False or cpio_nonzero_newc_checksums:
            result.findings.append(
                self.finding(
                    context,
                    title="CPIO member structure or integrity anomaly",
                    category="archive_structure_anomaly",
                    confidence=0.97,
                    explanation=(
                        "Bounded native odc/newc/CRC parsing found a malformed range/header, mixed entry formats, "
                        "a CRC byte-sum mismatch, or a nonzero checksum field in a non-CRC newc entry."
                    ),
                    evidence=(
                        [str(item)[:2_000] for item in cpio_invalid[:16]]
                        + [str(item)[:2_000] for item in cpio_nonzero_newc_checksums[:16]]
                        + ([f"format_consistent={cpio_consistent}"] if cpio_consistent is False else [])
                        + ([cpio_error] if cpio_error else [])
                    ),
                    severity="medium",
                )
            )
        unsafe_cpio_entries = [
            item for item in cpio_entries
            if isinstance(item, dict) and item.get("path_safe") is False
        ]
        if unsafe_cpio_entries:
            result.findings.append(
                self.finding(
                    context,
                    title="CPIO contains unsafe member path(s)",
                    category="archive_unsafe_member_path",
                    confidence=0.99,
                    explanation=(
                        "One or more CPIO names are absolute or contain a parent-directory component. "
                        "The built-in extractor will retain their metadata but never materialize them."
                    ),
                    evidence=[str(item)[:2_000] for item in unsafe_cpio_entries[:16]],
                    severity="medium",
                )
            )
        iso_signature = context.truthy("archive.iso9660.signature")
        iso_pvd = next(
            (
                value for value in context.values("archive.iso9660.primary_volume_descriptor")
                if isinstance(value, dict)
            ),
            {},
        )
        iso_descriptor_error = next(
            (
                value for value in context.values("archive.iso9660.descriptor_error")
                if isinstance(value, str) and value
            ),
            None,
        )
        iso_root_error = next(
            (
                value for value in context.values("archive.iso9660.root_directory_error")
                if isinstance(value, str) and value
            ),
            None,
        )
        iso_terminator = next(
            (
                value for value in context.values("archive.iso9660.descriptor_terminator_found")
                if isinstance(value, bool)
            ),
            False,
        )
        if iso_signature and (
            iso_pvd.get("valid") is not True
            or iso_descriptor_error
            or iso_root_error
            or not iso_terminator
        ):
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 volume or root-directory structure anomaly",
                    category="archive_structure_anomaly",
                    confidence=0.98,
                    explanation=(
                        "The fixed-location descriptor sequence, primary-volume both-endian fields, "
                        "declared volume bounds, root directory record, or a bounded root entry did not validate."
                    ),
                    evidence=(
                        [f"primary_volume_descriptor={iso_pvd}"]
                        + ([f"descriptor_error={iso_descriptor_error}"] if iso_descriptor_error else [])
                        + ([f"root_directory_error={iso_root_error}"] if iso_root_error else [])
                        + (["descriptor_terminator_found=False"] if not iso_terminator else [])
                    ),
                    severity="medium",
                )
            )
        iso_traversal_errors = next(
            (
                value for value in context.values(
                    "archive.iso9660.directory_traversal_errors"
                )
                if isinstance(value, list)
            ),
            [],
        )
        iso_traversal_truncated = next(
            (
                value for value in context.values(
                    "archive.iso9660.directory_traversal_truncated"
                )
                if isinstance(value, bool)
            ),
            False,
        )
        if iso_signature and (iso_traversal_errors or iso_traversal_truncated):
            traversal_metrics = []
            for key in (
                "archive.iso9660.directory_scan_bytes",
                "archive.iso9660.directory_scan_byte_limit",
                "archive.iso9660.directory_limit",
                "archive.iso9660.subdirectory_count",
            ):
                values = context.values(key)
                if values:
                    traversal_metrics.append(f"{key}={values[0]}")
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 directory traversal was incomplete or ambiguous",
                    category="iso9660_directory_traversal_anomaly",
                    confidence=0.97,
                    explanation=(
                        "A bounded active-directory walk encountered a shared/cyclic extent, "
                        "directory consistency failure, malformed record, read problem, or a "
                        "configured byte, entry, or directory limit. Affected branches remain "
                        "metadata-only rather than being inferred or recursively extracted."
                    ),
                    evidence=(
                        [str(item)[:2_000] for item in iso_traversal_errors[:16]]
                        + [f"directory_traversal_truncated={iso_traversal_truncated}"]
                        + traversal_metrics
                    ),
                    severity="medium",
                )
            )
        iso_susp_errors = next(
            (
                value for value in context.values("archive.iso9660.susp_errors")
                if isinstance(value, list)
            ),
            [],
        )
        if iso_susp_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 SUSP/Rock Ridge metadata anomaly",
                    category="iso9660_susp_anomaly",
                    confidence=0.97,
                    explanation=(
                        "An inline SUSP entry failed framing/version/both-endian validation, or "
                        "RRIP supplied an unsafe/inconsistent name or POSIX file type. Raw system-use "
                        "bytes remain evidence and the affected metadata is not trusted for extraction."
                    ),
                    evidence=[str(item)[:2_000] for item in iso_susp_errors[:16]],
                    severity="medium",
                )
            )
        joliet_descriptors = next(
            (
                value for value in context.values("archive.iso9660.joliet_descriptors")
                if isinstance(value, list)
            ),
            [],
        )
        invalid_joliet_descriptors = [
            item for item in joliet_descriptors
            if isinstance(item, dict) and item.get("valid") is not True
        ]
        joliet_traversal_errors = next(
            (
                value for value in context.values("archive.iso9660.joliet_traversal_errors")
                if isinstance(value, list)
            ),
            [],
        )
        joliet_reconciliation_errors = next(
            (
                value for value in context.values(
                    "archive.iso9660.joliet_reconciliation_errors"
                )
                if isinstance(value, list)
            ),
            [],
        )
        joliet_truncated = next(
            (
                value for value in context.values(
                    "archive.iso9660.joliet_traversal_truncated"
                )
                if isinstance(value, bool)
            ),
            False,
        )
        if (
            invalid_joliet_descriptors
            or joliet_traversal_errors
            or joliet_reconciliation_errors
            or joliet_truncated
        ):
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 Joliet namespace anomaly or ambiguity",
                    category="iso9660_joliet_anomaly",
                    confidence=0.97,
                    explanation=(
                        "A Joliet supplementary descriptor/UCS-2BE directory record failed "
                        "validation, its bounded tree walk was incomplete, or an extent could not "
                        "be uniquely reconciled with the primary namespace. Ambiguous names do not "
                        "drive duplicate extraction."
                    ),
                    evidence=(
                        [str(item)[:2_000] for item in invalid_joliet_descriptors[:8]]
                        + [str(item)[:2_000] for item in joliet_traversal_errors[:8]]
                        + [str(item)[:2_000] for item in joliet_reconciliation_errors[:8]]
                        + (["joliet_traversal_truncated=True"] if joliet_truncated else [])
                    ),
                    severity="medium",
                )
            )
        iso_entries = next(
            (
                value for value in context.values("archive.iso9660.directory_entries")
                if isinstance(value, list)
            ),
            [],
        )
        unsafe_iso_entries = [
            item for item in iso_entries
            if isinstance(item, dict)
            and (
                item.get("path_safe") is False
                or item.get("rock_ridge_name_path_safe") is False
            )
        ]
        if unsafe_iso_entries:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 contains unsafe member name(s)",
                    category="archive_unsafe_member_path",
                    confidence=0.99,
                    explanation=(
                        "An ISO identifier or Rock Ridge alternate name is absolute, drive-rooted, "
                        "contains a path separator, or contains a parent component. It remains "
                        "metadata-only."
                    ),
                    evidence=[str(item)[:2_000] for item in unsafe_iso_entries[:16]],
                    severity="medium",
                )
            )
        iso_symlinks = [
            item for item in iso_entries
            if isinstance(item, dict) and item.get("rock_ridge_symlink") is True
        ]
        if iso_symlinks:
            result.findings.append(
                self.finding(
                    context,
                    title="Rock Ridge symbolic link metadata retained without traversal",
                    category="archive_link_metadata",
                    confidence=0.99,
                    explanation=(
                        "RRIP PX/SL metadata identifies one or more symbolic links. Their raw target "
                        "components are inventoried, but the native extractor never follows or "
                        "materializes them."
                    ),
                    evidence=[str(item)[:2_000] for item in iso_symlinks[:16]],
                    severity="info",
                )
            )
        unsupported_iso_entries = [
            item for item in iso_entries
            if isinstance(item, dict)
            and item.get("file_type") == "regular"
            and (
                item.get("multi_extent") is True
                or item.get("file_unit_size") not in {0, None}
                or item.get("interleave_gap_size") not in {0, None}
            )
        ]
        if unsupported_iso_entries:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 file uses an unsupported multi-extent/interleaved layout",
                    category="archive_unsupported_layout",
                    confidence=0.99,
                    explanation=(
                        "The entry remains fully inventoried, but the native extractor requires one "
                        "non-interleaved extent and will not infer missing extent joins."
                    ),
                    evidence=[str(item)[:2_000] for item in unsupported_iso_entries[:16]],
                    severity="info",
                )
            )
        return result
