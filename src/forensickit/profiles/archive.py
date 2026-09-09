from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


ARCHIVE_TYPES = {
    "archive", "container", "zip", "7z", "rar", "tar", "cpio", "gzip", "gz", "bzip2", "xz",
    "cab", "iso", "iso9660", "udf", "jar", "apk", "ooxml",
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
                        "Bounded native binary/odc/newc/CRC parsing found a malformed range/header, "
                        "mixed format or binary byte order, a CRC byte-sum mismatch, or a nonzero "
                        "checksum field in a non-CRC newc entry."
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
        cpio_hard_link_groups = next(
            (
                value for value in context.values("archive.cpio.hard_link_groups")
                if isinstance(value, list)
            ),
            [],
        )
        cpio_hard_link_errors = next(
            (
                value for value in context.values("archive.cpio.hard_link_errors")
                if isinstance(value, list)
            ),
            [],
        )
        reconciled_cpio_hard_links = [
            item for item in cpio_hard_link_groups
            if isinstance(item, dict) and item.get("reconciled") is True
        ]
        if reconciled_cpio_hard_links:
            result.findings.append(
                self.finding(
                    context,
                    title="CPIO hard-link inode aliases reconciled",
                    category="archive_hard_link_metadata",
                    confidence=0.99,
                    explanation=(
                        "Regular-file records with the same archive/device/inode and a consistent "
                        "link count contain exactly one data-bearing member. Only that canonical "
                        "payload may become a child; aliases remain metadata and no host hard link "
                        "is created."
                    ),
                    evidence=[
                        str(item)[:2_000]
                        for item in reconciled_cpio_hard_links[:16]
                    ],
                    severity="info",
                )
            )
        if cpio_hard_link_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="CPIO hard-link inode group is ambiguous or inconsistent",
                    category="cpio_hard_link_anomaly",
                    confidence=0.98,
                    explanation=(
                        "A shared archive/device/inode has conflicting link counts or metadata, "
                        "too many observed aliases, or does not contain exactly one data-bearing "
                        "member. Every member in the group remains metadata-only."
                    ),
                    evidence=[
                        str(item)[:2_000] for item in cpio_hard_link_errors[:16]
                    ],
                    severity="medium",
                )
            )
        cpio_symlinks = [
            item for item in cpio_entries
            if isinstance(item, dict)
            and item.get("file_type") == "symlink"
            and item.get("symlink_target_validation") == "valid"
        ]
        if cpio_symlinks:
            result.findings.append(
                self.finding(
                    context,
                    title="CPIO symbolic-link targets inventoried",
                    category="archive_symlink_metadata",
                    confidence=0.99,
                    explanation=(
                        "Bounded UTF-8 symbolic-link payloads retain exact offsets, lengths, "
                        "hashes, decoded targets, and traversal safety metadata. Links remain "
                        "evidence-only and are never followed or created on the host."
                    ),
                    evidence=[str(item)[:2_000] for item in cpio_symlinks[:16]],
                    severity="info",
                )
            )
        unsafe_cpio_symlinks = [
            item for item in cpio_symlinks
            if item.get("symlink_target_safe") is False
        ]
        if unsafe_cpio_symlinks:
            result.findings.append(
                self.finding(
                    context,
                    title="CPIO symbolic link has an unsafe target path",
                    category="archive_unsafe_link_target",
                    confidence=0.99,
                    explanation=(
                        "A decoded symbolic-link target is absolute, drive-rooted, or contains "
                        "a parent-directory component. It is retained only as metadata."
                    ),
                    evidence=[
                        str(item)[:2_000] for item in unsafe_cpio_symlinks[:16]
                    ],
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
                        "The built-in extractor retains their metadata but never materializes them."
                    ),
                    evidence=[str(item)[:2_000] for item in unsafe_cpio_entries[:16]],
                    severity="medium",
                )
            )
        udf_detected = context.truthy("archive.udf.detected")
        udf_valid = context.truthy("archive.udf.valid")
        udf_errors = next(
            (
                value for value in context.values("archive.udf.errors")
                if isinstance(value, list)
            ),
            [],
        )
        if udf_valid:
            udf_evidence: list[str] = []
            for key in (
                "archive.udf.revision_identifier",
                "archive.udf.active_anchor",
                "archive.udf.volume_descriptor_comparison",
                "archive.udf.file_set",
            ):
                values = context.values(key)
                if values:
                    udf_evidence.append(f"{key}={values[0]}"[:2_000])
            result.findings.append(
                self.finding(
                    context,
                    title="UDF volume descriptor copies validated",
                    category="archive_udf_metadata",
                    confidence=0.99,
                    explanation=(
                        "The bounded BEA/NSR/TEA recognition sequence, anchor pointer, "
                        "descriptor-tag checksums/CRCs, partition maps, and main/reserve "
                        "volume descriptor semantics agree. No UDF file content is yet "
                        "materialized by the native parser."
                    ),
                    evidence=udf_evidence,
                    severity="info",
                )
            )
            udf_file_set = next(
                (
                    value for value in context.values("archive.udf.file_set")
                    if isinstance(value, dict) and value.get("valid") is True
                ),
                None,
            )
            if udf_file_set is not None:
                result.findings.append(
                    self.finding(
                        context,
                        title="UDF file set and bounded directory tree validated",
                        category="archive_udf_file_set_metadata",
                        confidence=0.99,
                        explanation=(
                            "A validated Type-1 partition map resolves the LVD file-set "
                            "address to an exact FSD and directory File Entry/Extended "
                            "File Entry. Its short/long allocation descriptors resolve exact "
                            "root-directory extents whose bounded FID tags, CRC coverage, CS0 "
                            "names, padding, and parent record agree. Active child FE/EFE tags, "
                            "types, and allocation metadata are checked through a bounded nested "
                            "directory tree without reading or materializing file content."
                        ),
                        evidence=[str(udf_file_set)[:2_000]],
                        severity="info",
                    )
                )
        elif udf_detected:
            result.findings.append(
                self.finding(
                    context,
                    title="UDF anchor or volume descriptor structure is inconsistent",
                    category="udf_structure_anomaly",
                    confidence=0.98,
                    explanation=(
                        "A recognized UDF volume failed anchor range, descriptor-tag "
                        "checksum/CRC/location, partition/LVD framing, termination, "
                        "main/reserve semantics, FSD/root ICB, or root FID validation. "
                        "Native file traversal remains disabled."
                    ),
                    evidence=[str(item)[:2_000] for item in udf_errors[:16]],
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
        extended_attributes = next(
            (
                value for value in context.values(
                    "archive.iso9660.extended_attributes"
                )
                if isinstance(value, list)
            ),
            [],
        )
        extended_attribute_errors = next(
            (
                value for value in context.values(
                    "archive.iso9660.extended_attribute_errors"
                )
                if isinstance(value, list)
            ),
            [],
        )
        valid_extended_attributes = [
            item for item in extended_attributes
            if isinstance(item, dict) and item.get("valid") is True
        ]
        if valid_extended_attributes:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 extended-attribute records validated",
                    category="archive_extended_attribute_metadata",
                    confidence=0.99,
                    explanation=(
                        "One or more ECMA-119 extended-attribute block ranges passed bounded "
                        "both-endian, permission, time, record-format, version, reserved, and "
                        "variable-field checks. Opaque system/application use bytes retain exact "
                        "hash provenance; eligible file data begins only after the complete record."
                    ),
                    evidence=[
                        str(item)[:2_000]
                        for item in valid_extended_attributes[:16]
                    ],
                    severity="info",
                )
            )
        if extended_attribute_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 extended-attribute record is malformed or unsupported",
                    category="iso9660_extended_attribute_anomaly",
                    confidence=0.98,
                    explanation=(
                        "An extended-attribute range, fixed field, variable field, padding, "
                        "directory-record flag relationship, or configured resource bound failed "
                        "validation. Affected regular-file extents remain metadata-only."
                    ),
                    evidence=[
                        str(item)[:2_000]
                        for item in extended_attribute_errors[:16]
                    ],
                    severity="medium",
                )
            )
        rock_ridge_zisofs = next(
            (
                value for value in context.values(
                    "archive.iso9660.rock_ridge_zisofs"
                )
                if isinstance(value, list)
            ),
            [],
        )
        rock_ridge_zisofs_errors = next(
            (
                value for value in context.values(
                    "archive.iso9660.rock_ridge_zisofs_errors"
                )
                if isinstance(value, list)
            ),
            [],
        )
        valid_rock_ridge_zisofs = [
            item for item in rock_ridge_zisofs
            if isinstance(item, dict) and item.get("valid") is True
        ]
        if valid_rock_ridge_zisofs:
            result.findings.append(
                self.finding(
                    context,
                    title="Rock Ridge zisofs compression metadata validated",
                    category="archive_compression_metadata",
                    confidence=0.99,
                    explanation=(
                        "An RRIP ZF declaration matches a bounded zisofs header and monotonic "
                        "block-pointer table. Exact metadata offsets and hashes are retained, "
                        "including zero-fill blocks. Triage itself does not decompress data; an "
                        "eligible stream may be materialized only after the native extractor "
                        "independently revalidates every declaration and exact block output."
                    ),
                    evidence=[
                        str(item)[:2_000]
                        for item in valid_rock_ridge_zisofs[:16]
                    ],
                    severity="info",
                )
            )
        if rock_ridge_zisofs_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="Rock Ridge zisofs metadata is inconsistent or malformed",
                    category="iso9660_zisofs_anomaly",
                    confidence=0.98,
                    explanation=(
                        "An RRIP ZF claim, zisofs header, stored range, or bounded block-pointer "
                        "table failed validation. The compressed stream remains evidence-only and "
                        "is never speculatively decompressed."
                    ),
                    evidence=[
                        str(item)[:2_000]
                        for item in rock_ridge_zisofs_errors[:16]
                    ],
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
        el_torito_errors = next(
            (
                value for value in context.values("archive.iso9660.el_torito_errors")
                if isinstance(value, list)
            ),
            [],
        )
        el_torito_hard_disks = next(
            (
                value for value in context.values(
                    "archive.iso9660.el_torito_hard_disk_images"
                )
                if isinstance(value, list)
            ),
            [],
        )
        if el_torito_hard_disks:
            result.findings.append(
                self.finding(
                    context,
                    title="El Torito hard-disk-emulation MBR metadata retained",
                    category="archive_boot_disk_metadata",
                    confidence=0.98,
                    explanation=(
                        "A hard-disk-emulation catalog entry points to a bounded MBR sector. Its "
                        "signature, partition records, absolute ISO ranges, overlaps, and minimum "
                        "partition-covered length are inventoried, but MBR geometry does not declare "
                        "the complete embedded-image boundary, so no child is created."
                    ),
                    evidence=[str(item)[:2_000] for item in el_torito_hard_disks[:16]],
                    severity=(
                        "info"
                        if all(
                            isinstance(item, dict)
                            and isinstance(item.get("hard_disk_mbr"), dict)
                            and item["hard_disk_mbr"].get("valid") is True
                            for item in el_torito_hard_disks
                        )
                        else "medium"
                    ),
                )
            )
        if el_torito_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="El Torito boot catalog or image range anomaly",
                    category="iso9660_el_torito_anomaly",
                    confidence=0.98,
                    explanation=(
                        "A declared boot catalog failed its validation-entry checksum/key or default "
                        "entry/range checks, or a hard-disk-emulation MBR was malformed. The catalog "
                        "remains raw evidence, and no unbounded or size-indeterminate boot image is "
                        "materialized."
                    ),
                    evidence=[str(item)[:2_000] for item in el_torito_errors[:16]],
                    severity="medium",
                )
            )
        path_tables = next(
            (
                value for value in context.values("archive.iso9660.path_tables")
                if isinstance(value, list)
            ),
            [],
        )
        path_table_comparison = next(
            (
                value for value in context.values(
                    "archive.iso9660.path_table_comparison"
                )
                if isinstance(value, dict)
            ),
            {},
        )
        path_table_reconciliation = next(
            (
                value for value in context.values(
                    "archive.iso9660.path_table_reconciliation"
                )
                if isinstance(value, list)
            ),
            [],
        )
        invalid_path_tables = [
            table for table in path_tables
            if isinstance(table, dict) and table.get("valid") is not True
        ]
        unreconciled_path_entries = [
            item for item in path_table_reconciliation
            if isinstance(item, dict) and item.get("reconciled") is not True
        ]
        if path_tables and (
            invalid_path_tables
            or path_table_comparison.get("consistent") is not True
            or unreconciled_path_entries
        ):
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 path-table copy or directory reconciliation anomaly",
                    category="iso9660_path_table_anomaly",
                    confidence=0.97,
                    explanation=(
                        "One or more bounded path-table copies failed framing/range/parent checks, "
                        "the mandatory little- and big-endian tables differ, or a directory extent "
                        "and its extended-attribute length/data start did not uniquely match the "
                        "validated active directory walk. Divergent tables are never selected as "
                        "authoritative."
                    ),
                    evidence=(
                        [f"comparison={path_table_comparison}"]
                        + [str(item)[:2_000] for item in invalid_path_tables[:8]]
                        + [str(item)[:2_000] for item in unreconciled_path_entries[:8]]
                    ),
                    severity="medium",
                )
            )
        joliet_path_tables = next(
            (
                value for value in context.values(
                    "archive.iso9660.joliet_path_tables"
                )
                if isinstance(value, list)
            ),
            [],
        )
        joliet_path_table_comparison = next(
            (
                value for value in context.values(
                    "archive.iso9660.joliet_path_table_comparison"
                )
                if isinstance(value, dict)
            ),
            {},
        )
        joliet_path_table_reconciliation = next(
            (
                value for value in context.values(
                    "archive.iso9660.joliet_path_table_reconciliation"
                )
                if isinstance(value, list)
            ),
            [],
        )
        invalid_joliet_path_tables = [
            table for table in joliet_path_tables
            if isinstance(table, dict) and table.get("valid") is not True
        ]
        unreconciled_joliet_path_entries = [
            item for item in joliet_path_table_reconciliation
            if isinstance(item, dict) and item.get("reconciled") is not True
        ]
        if joliet_path_tables and (
            invalid_joliet_path_tables
            or joliet_path_table_comparison.get("consistent") is not True
            or unreconciled_joliet_path_entries
        ):
            result.findings.append(
                self.finding(
                    context,
                    title="Joliet path-table copy or directory reconciliation anomaly",
                    category="iso9660_joliet_path_table_anomaly",
                    confidence=0.97,
                    explanation=(
                        "One or more bounded Joliet path-table copies failed framing, strict "
                        "UCS-2BE, range, or parent checks; cross-endian copies differ; or an "
                        "extent/name/XAR data start did not uniquely match the validated active "
                        "Joliet directory walk. No divergent copy is selected as authoritative."
                    ),
                    evidence=(
                        [f"comparison={joliet_path_table_comparison}"]
                        + [str(item)[:2_000] for item in invalid_joliet_path_tables[:8]]
                        + [
                            str(item)[:2_000]
                            for item in unreconciled_joliet_path_entries[:8]
                        ]
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
        rock_ridge_device_entries = [
            item for item in iso_entries
            if isinstance(item, dict) and item.get("rock_ridge_devices")
        ]
        if rock_ridge_device_entries:
            result.findings.append(
                self.finding(
                    context,
                    title="Rock Ridge device-number metadata retained without materialization",
                    category="archive_device_metadata",
                    confidence=0.99,
                    explanation=(
                        "RRIP PN metadata supplies both-endian device-number components. They are "
                        "preserved only as archive evidence; the native extractor never creates a "
                        "device node."
                    ),
                    evidence=[str(item)[:2_000] for item in rock_ridge_device_entries[:16]],
                    severity="info",
                )
            )
        rock_ridge_hard_link_groups = next(
            (
                value for value in context.values(
                    "archive.iso9660.rock_ridge_hard_link_groups"
                )
                if isinstance(value, list)
            ),
            [],
        )
        rock_ridge_hard_link_errors = next(
            (
                value for value in context.values(
                    "archive.iso9660.rock_ridge_hard_link_errors"
                )
                if isinstance(value, list)
            ),
            [],
        )
        if rock_ridge_hard_link_groups:
            result.findings.append(
                self.finding(
                    context,
                    title="Rock Ridge hard-link identity metadata retained",
                    category="archive_hard_link_metadata",
                    confidence=0.98,
                    explanation=(
                        "Validated PX serial and link-count fields group regular-file directory "
                        "records within this ISO. Exact shared extent sequences permit one canonical "
                        "copy with alternate paths retained as evidence; no host hard link is created "
                        "or followed."
                    ),
                    evidence=[
                        str(item)[:2_000]
                        for item in rock_ridge_hard_link_groups[:16]
                    ],
                    severity="info",
                )
            )
        if rock_ridge_hard_link_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="Rock Ridge hard-link metadata is incomplete or contradictory",
                    category="iso9660_rock_ridge_hard_link_anomaly",
                    confidence=0.97,
                    explanation=(
                        "A regular-file PX claim lacks a serial, has an invalid link count, exceeds its "
                        "declared member count, disagrees across aliases, or maps one serial to different "
                        "extent, extended-attribute, or zisofs semantic identities. Such records are "
                        "not reconciled as hard-link aliases."
                    ),
                    evidence=[
                        str(item)[:2_000]
                        for item in rock_ridge_hard_link_errors[:16]
                    ],
                    severity="medium",
                )
            )
        rock_ridge_relocations = next(
            (
                value for value in context.values(
                    "archive.iso9660.rock_ridge_relocations"
                )
                if isinstance(value, list)
            ),
            [],
        )
        if rock_ridge_relocations:
            unresolved_relocations = [
                record for record in rock_ridge_relocations
                if isinstance(record, dict)
                and any(
                    isinstance(link, dict)
                    and link.get("uniquely_reconciled") is not True
                    for role in ("child_links", "parent_links")
                    for link in record.get(role, [])
                )
            ]
            result.findings.append(
                self.finding(
                    context,
                    title="Rock Ridge relocated-directory metadata retained without traversal",
                    category="archive_relocated_directory_metadata",
                    confidence=0.98,
                    explanation=(
                        "RRIP CL/PL/RE metadata describes relocated directory relationships. "
                        "References are compared only with already validated directory extents; no "
                        "relocation link is followed or used to infer an extraction path."
                    ),
                    evidence=[str(item)[:2_000] for item in rock_ridge_relocations[:16]],
                    severity="medium" if unresolved_relocations else "info",
                )
            )
        multi_extent_chains = next(
            (
                value for value in context.values(
                    "archive.iso9660.multi_extent_chains"
                )
                if isinstance(value, list)
            ),
            [],
        )
        multi_extent_errors = next(
            (
                value for value in context.values(
                    "archive.iso9660.multi_extent_errors"
                )
                if isinstance(value, list)
            ),
            [],
        )
        assembled_multi_extents = [
            item for item in multi_extent_chains
            if isinstance(item, dict)
            and item.get("complete") is True
            and item.get("extraction_eligible") is True
        ]
        if assembled_multi_extents:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 multi-extent files validated for ordered assembly",
                    category="archive_multi_extent_metadata",
                    confidence=0.99,
                    explanation=(
                        "Adjacent, identifier/version-consistent regular-file records form complete "
                        "non-interleaved chains. Each image-bounded extent and any associated XAR "
                        "retains exact provenance; record format/attributes and fixed record length "
                        "are consistent across file sections before copying in recorded order."
                    ),
                    evidence=[str(item)[:2_000] for item in assembled_multi_extents[:16]],
                    severity="info",
                )
            )
        if multi_extent_errors:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 multi-extent chain is incomplete or inconsistent",
                    category="iso9660_multi_extent_anomaly",
                    confidence=0.98,
                    explanation=(
                        "A multi-extent leader was not followed by a bounded, adjacent, matching final "
                        "record, a segment failed range/layout validation, or per-section extended "
                        "attributes violated required record metadata consistency. The chain remains "
                        "metadata-only and is never partially materialized."
                    ),
                    evidence=[str(item)[:2_000] for item in multi_extent_errors[:16]],
                    severity="medium",
                )
            )
        unsupported_iso_entries = [
            item for item in iso_entries
            if isinstance(item, dict)
            and item.get("file_type") == "regular"
            and (
                (
                    item.get("multi_extent") is True
                    and item.get("multi_extent_assembled") is not True
                )
                or item.get("file_unit_size") not in {0, None}
                or item.get("interleave_gap_size") not in {0, None}
            )
        ]
        if unsupported_iso_entries:
            result.findings.append(
                self.finding(
                    context,
                    title="ISO 9660 file uses an unsupported incomplete/interleaved layout",
                    category="archive_unsupported_layout",
                    confidence=0.99,
                    explanation=(
                        "The entry remains fully inventoried, but the native extractor requires either "
                        "one non-interleaved extent or a complete adjacent multi-extent chain and will "
                        "not infer missing joins."
                    ),
                    evidence=[str(item)[:2_000] for item in unsupported_iso_entries[:16]],
                    severity="info",
                )
            )
        return result
