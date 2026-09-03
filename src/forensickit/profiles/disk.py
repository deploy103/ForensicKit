from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


DISK_TYPES = {
    "disk", "disk_image", "filesystem", "filesystem_image", "raw_disk", "ewf", "e01",
    "vhd", "vhdx", "qcow", "qcow2",
}


class DiskProfile(BaseProfile):
    """Initial partition/filesystem plan based only on classification and signatures."""

    name = "disk"
    priority = 700

    def match_reasons(self, context: ProfileContext) -> list[str]:
        reasons: list[str] = []
        matched_types = context.artifact_types & DISK_TYPES
        if matched_types:
            reasons.append(f"classification includes disk/filesystem type: {sorted(matched_types)}")
        if context.truthy(
            "signature.partition_table", "disk.mbr_signature", "disk.gpt_signature",
            "filesystem.signature_detected", "disk.ewf_signature",
        ):
            reasons.append("partition/filesystem image signature observation is present")
        magic = (context.artifact.magic or "").lower()
        # A Squashfs firmware payload is itself a filesystem but should first
        # be routed through its firmware profile/binwalk, not blindly treated
        # as a whole-disk image for mmls/fls.
        if not context.classified_as("firmware") and any(marker in magic for marker in ("filesystem", "disk image", "ewf", "partition")):
            reasons.append(f"magic identifies disk/filesystem evidence: {context.artifact.magic}")
        return reasons

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        exfat_main_boot = next(
            (value for value in context.values("filesystem.exfat.boot_regions.main") if isinstance(value, dict)), {}
        )
        exfat_backup_boot = next(
            (value for value in context.values("filesystem.exfat.boot_regions.backup") if isinstance(value, dict)), {}
        )
        if exfat_main_boot and exfat_backup_boot and any(
            item.get(key) is not True
            for item in (exfat_main_boot, exfat_backup_boot)
            for key in ("checksum_valid", "checksum_repeated", "boot_signature_valid", "extended_boot_signatures_valid", "reserved_sector_zero")
        ):
            result.findings.append(self.finding(
                context,
                title="exFAT main or backup boot region failed structural validation",
                category="exfat_boot_region_anomaly", confidence=0.98,
                explanation=(
                    "One of the two complete 12-sector boot regions has a bad rotate checksum, non-repeated checksum sector, boot/extended-sector signature, or reserved-sector value. "
                    "The exact region metadata is retained; verify the volume before relying on its filesystem geometry."
                ),
                evidence=[str(exfat_main_boot)[:2_000], str(exfat_backup_boot)[:2_000]], severity="medium",
            ))
        exfat_boot_match = next(
            iter(context.values("filesystem.exfat.boot_regions.immutable_fields_match")), None
        )
        if exfat_boot_match is False:
            result.findings.append(self.finding(
                context,
                title="exFAT main and backup boot regions diverge",
                category="exfat_backup_boot_mismatch", confidence=0.98,
                explanation=(
                    "Both regions are compared across their first 11 sectors while excluding only mutable VolumeFlags and PercentInUse bytes. "
                    "The first exact main/backup byte offsets are retained; separately valid checksums show that the divergent copies are internally self-consistent, not which copy is authoritative."
                ),
                evidence=[str(next(iter(context.values("filesystem.exfat.boot_regions.first_immutable_difference")), None))],
                severity="medium",
            ))
        exfat_deleted_root = next(
            (value for value in context.values("filesystem.exfat.deleted_file_sets") if isinstance(value, list)), []
        )
        exfat_deleted_subdirectories = next(
            (
                value for value in context.values("filesystem.exfat.subdirectory_deleted_file_sets")
                if isinstance(value, list)
            ),
            [],
        )
        exfat_deleted = [*exfat_deleted_root, *exfat_deleted_subdirectories]
        if exfat_deleted:
            result.findings.append(self.finding(
                context, title=f"{len(exfat_deleted)} deleted exFAT file set(s) validated",
                category="exfat_deleted_file_entry", confidence=0.94,
                explanation=(
                    "Inactive primary, stream, and filename entries form complete bounded sets whose stored checksum validates after restoring deletion-cleared InUse bits. "
                    "Stored name hashes are revalidated only when the volume upcase-table checksum and complete 65,536-code-unit mapping validate. Allocation-bitmap bits are retained only as current reuse warnings, never as proof of deleted-file ownership."
                ),
                evidence=[str(item)[:2_000] for item in exfat_deleted[:128]], severity="info",
            ))
            bitmap_reuse = [
                item for item in exfat_deleted
                if isinstance(item, dict) and item.get("allocation_reuse_warning") is True
            ]
            if bitmap_reuse:
                result.findings.append(self.finding(
                    context,
                    title=f"{len(bitmap_reuse)} deleted exFAT candidate(s) reference currently allocated clusters",
                    category="exfat_deleted_cluster_reuse_warning", confidence=0.92,
                    explanation=(
                        "The checksum-validated active allocation bitmap currently marks at least one cluster referenced by each deleted entry as allocated. "
                        "This is a reuse/inconsistency warning about present filesystem state, not proof that the current bytes still belong to the deleted file; bounded recovery may still preserve them as a cautious candidate."
                    ),
                    evidence=[str(item)[:2_000] for item in bitmap_reuse[:128]], severity="low",
                ))
            name_hash_mismatches = [
                item for item in exfat_deleted
                if isinstance(item, dict) and item.get("name_hash_validation") == "mismatch"
            ]
            if name_hash_mismatches:
                result.findings.append(self.finding(
                    context,
                    title=f"{len(name_hash_mismatches)} deleted exFAT candidate name hash mismatch(es)",
                    category="exfat_deleted_name_hash_mismatch", confidence=0.96,
                    explanation=(
                        "The volume upcase table passed its stored checksum and expanded to a complete UTF-16 mapping, but the recomputed case-insensitive filename hash differs from the stored stream-extension value. "
                        "The entry-set checksum still validates separately; treat the filename metadata as inconsistent and verify it with another filesystem parser."
                    ),
                    evidence=[str(item)[:2_000] for item in name_hash_mismatches[:128]], severity="low",
                ))
        exfat_directories = next(
            (
                value for value in context.values("filesystem.exfat.subdirectory_inventory")
                if isinstance(value, list)
            ),
            [],
        )
        if exfat_directories:
            result.findings.append(self.finding(
                context,
                title=f"{len(exfat_directories)} active exFAT subdirectory allocation(s) validated",
                category="exfat_active_subdirectory_inventory", confidence=0.94,
                explanation=(
                    "Active directory file sets passed entry-set checksum, stream/name sequencing, length, volume/image, and bounded allocation checks. "
                    "NoFatChain directories use complete contiguous extents; FAT directories require an exact non-looping chain ending at EOC, with physical lineage retained."
                ),
                evidence=[str(item)[:2_000] for item in exfat_directories[:32]], severity="info",
            ))
        exfat_directory_errors = next(
            (
                value for value in context.values("filesystem.exfat.subdirectory_errors")
                if isinstance(value, list)
            ),
            [],
        )
        if exfat_directory_errors:
            result.findings.append(self.finding(
                context,
                title="exFAT active-subdirectory traversal ended incompletely",
                category="exfat_subdirectory_chain_anomaly", confidence=0.91,
                explanation=(
                    "A candidate active directory exceeded shared resource bounds or referenced an invalid, looping, or already-used cluster. "
                    "Only fully validated directory allocations were parsed; deleted directories were never traversal sources."
                ),
                evidence=[str(item)[:2_000] for item in exfat_directory_errors[:128]], severity="low",
            ))
        ext_root_entries = next(
            (
                value for value in context.values("filesystem.ext.root.directory_entries")
                if isinstance(value, list)
            ),
            [],
        )
        if ext_root_entries:
            result.findings.append(self.finding(
                context,
                title=f"{len(ext_root_entries)} bounded ext root directory entry/entries validated",
                category="ext_root_directory_inventory", confidence=0.94,
                explanation=(
                    "Group-zero descriptor and inode-table geometry mapped allocated root inode 2 through either a depth-zero initialized ext4 extent set or bounded ext2/3 direct pointers. "
                    "Each structurally valid active directory record retains its inode, type, logical offset, and exact physical evidence offset."
                ),
                evidence=[str(item)[:2_000] for item in ext_root_entries[:256]], severity="info",
            ))
        ext_subdirectories = next(
            (
                value for value in context.values("filesystem.ext.root.subdirectory_inventory")
                if isinstance(value, list)
            ),
            [],
        )
        if ext_subdirectories:
            result.findings.append(self.finding(
                context,
                title=f"{len(ext_subdirectories)} active ext subdirectory allocation(s) validated",
                category="ext_active_subdirectory_inventory", confidence=0.94,
                explanation=(
                    "Allocated directory inodes referenced by validated parent entries were traversed breadth-first under shared directory/block/byte limits. "
                    "Every accepted directory retains its inode ancestry, source entry, complete initialized mapping, and physical block lineage; repeated inodes or shared blocks are not traversed."
                ),
                evidence=[str(item)[:2_000] for item in ext_subdirectories[:32]], severity="info",
            ))
        ext_subdirectory_errors = next(
            (
                value for value in context.values("filesystem.ext.root.subdirectory_errors")
                if isinstance(value, list)
            ),
            [],
        )
        if ext_subdirectory_errors:
            result.findings.append(self.finding(
                context,
                title="ext active-subdirectory traversal ended incompletely",
                category="ext_subdirectory_mapping_anomaly", confidence=0.9,
                explanation=(
                    "A referenced directory inode failed allocation, mapping, shared-block, structural, or resource-bound validation. "
                    "Only fully validated directory blocks were inventoried and no missing membership was inferred."
                ),
                evidence=[str(item)[:2_000] for item in ext_subdirectory_errors[:128]], severity="low",
            ))
        ext_root_error = next(iter(context.values("filesystem.ext.root.error")), None)
        if isinstance(ext_root_error, str) and ext_root_error:
            result.findings.append(self.finding(
                context,
                title="Native ext root-directory mapping unavailable",
                category="ext_root_mapping_anomaly", confidence=0.88,
                explanation=(
                    "The supplied ext superblock was identifiable, but bounded group descriptor, root inode, mapping, or directory structure validation failed. "
                    "No directory membership was inferred from the invalid mapping; use fsck/SleuthKit against a copy for verification."
                ),
                evidence=[ext_root_error[:2_000]], severity="low",
            ))
        mirror_available = context.truthy("filesystem.ntfs.mft_mirror.available")
        mirror_match = next(iter(context.values("filesystem.ntfs.mft_mirror.primary_match")), None)
        if mirror_available and mirror_match is False:
            result.findings.append(self.finding(
                context,
                title="NTFS primary MFT and MFT mirror record zero diverge",
                category="ntfs_mft_mirror_mismatch", confidence=0.97,
                explanation=(
                    "The boot-declared primary and mirror FILE record zero each passed independent signature, bounds, and USA validation, but their USA-fixed logical record bytes or allocated sizes differ. "
                    "The first differing logical byte is retained; verify filesystem consistency before relying on either copy."
                ),
                evidence=[
                    f"mirror_offset={context.number('filesystem.ntfs.mft_mirror.offset')}; "
                    f"first_difference={context.number('filesystem.ntfs.mft_mirror.first_difference_offset')}"
                ],
                severity="medium",
            ))
        backup_boot_match = next(iter(context.values("filesystem.ntfs.backup_boot.primary_match")), None)
        if backup_boot_match is False:
            result.findings.append(self.finding(
                context,
                title="NTFS primary and backup boot sectors diverge",
                category="ntfs_backup_boot_mismatch", confidence=0.98,
                explanation=(
                    "Both the primary boot record and final-sector NTFS backup have valid OEM signatures and end markers, but their 512-byte boot-record content differs. "
                    "The exact backup byte offset and first differing logical byte are retained for filesystem-tool verification."
                ),
                evidence=[
                    f"backup_offset={context.number('filesystem.ntfs.backup_boot.offset')}; "
                    f"first_difference={context.number('filesystem.ntfs.backup_boot.first_difference_offset')}"
                ],
                severity="medium",
            ))
        deleted_fat_entries = next(
            (
                value for value in context.values("filesystem.fat.deleted_short_entries")
                if isinstance(value, list)
            ),
            [],
        )
        fat_chain_errors = next(
            (
                value for value in context.values("filesystem.fat.root.chain_errors")
                if isinstance(value, list)
            ),
            [],
        )
        if fat_chain_errors:
            result.findings.append(self.finding(
                context,
                title="FAT32 root-directory chain ended abnormally",
                category="fat_directory_chain_anomaly", confidence=0.9,
                explanation=(
                    "Bounded root traversal encountered a loop, free/reserved/bad cluster, FAT bounds, image bounds, or truncated read before a normal end-of-chain marker. "
                    "Entries from fully read clusters remain usable, but directory completeness requires filesystem-tool verification."
                ),
                evidence=[str(item)[:2_000] for item in fat_chain_errors[:64]],
                severity="low",
            ))
        if deleted_fat_entries:
            result.findings.append(self.finding(
                context,
                title=f"{len(deleted_fat_entries)} deleted FAT32 root entry candidate(s) recovered",
                category="fat_deleted_directory_entry", confidence=0.88,
                explanation=(
                    "A bounds-validated FAT32 root cluster contained deleted non-LFN directory entries. "
                    "The first short-name character is irrecoverable and shown as `?`; cluster/size/timestamps are metadata leads only because no FAT chain or content was followed."
                ),
                evidence=[str(item)[:2_000] for item in deleted_fat_entries[:128]],
                severity="info",
            ))
            linked_lfn = [
                item for item in deleted_fat_entries
                if isinstance(item, dict) and isinstance(item.get("long_name"), str)
            ]
            if linked_lfn:
                result.findings.append(self.finding(
                    context,
                    title=f"{len(linked_lfn)} deleted FAT32 long-name chain(s) validated",
                    category="fat_deleted_lfn_entry", confidence=0.93,
                    explanation=(
                        "Contiguous LFN slots were linked to deleted short entries only after slot structure, shared checksum, physical/stored order, UTF-16 terminator/padding, and a unique bounded reconstruction of the missing short-name first byte validated. "
                        "Destroyed ordinal bytes are explicitly marked as physically inferred."
                    ),
                    evidence=[str(item)[:2_000] for item in linked_lfn[:128]],
                    severity="info",
                ))
        subdirectory_deleted = next(
            (
                value for value in context.values("filesystem.fat.subdirectory_deleted_entries")
                if isinstance(value, list)
            ),
            [],
        )
        if subdirectory_deleted:
            result.findings.append(self.finding(
                context,
                title=f"{len(subdirectory_deleted)} deleted FAT32 subdirectory entry candidate(s) recovered",
                category="fat_subdirectory_deleted_entry", confidence=0.88,
                explanation=(
                    "Deleted entries were inventoried inside bounded FAT chains referenced by active directory entries. "
                    "Each candidate retains its containing directory's cluster lineage and exact physical entry offset; deleted directory entries themselves were not traversed because their allocation may have been reused."
                ),
                evidence=[str(item)[:2_000] for item in subdirectory_deleted[:128]],
                severity="info",
            ))
        qcow_header = next((value for value in context.values("disk.qcow2.header") if isinstance(value, dict)), {})
        vhd_footer = next((value for value in context.values("disk.vhd.footer") if isinstance(value, dict)), {})
        virtual_disk = context.format_is("vhd", "qcow2") or bool(qcow_header.get("valid")) or bool(vhd_footer.get("signature"))
        partitioned = context.truthy("disk.mbr_signature", "disk.gpt_signature", "signature.partition_table")
        direct_filesystem = context.truthy("filesystem.signature_detected")
        if not virtual_disk:
            if partitioned or not direct_filesystem:
                result.recommendations.append(
                    self.recommendation(
                        "sleuthkit_mmls",
                        (AnalysisMode.AUTO, AnalysisMode.DEEP),
                        "enumerate partition layout before filesystem-level operations",
                        115,
                    )
                )
            if direct_filesystem and not partitioned:
                result.recommendations.append(
                    self.recommendation(
                        "sleuthkit_fsstat",
                        (AnalysisMode.AUTO, AnalysisMode.DEEP),
                        "a filesystem signature starts at artifact offset zero, so filesystem metadata can be safely inventoried before deep listing",
                        85,
                    )
                )
                result.recommendations.append(
                    self.recommendation(
                        "sleuthkit_fls",
                        (AnalysisMode.DEEP,),
                        "a filesystem signature starts at artifact offset zero, so deep recursive/deleted-entry listing has an unambiguous base offset",
                        75,
                    )
                )
            elif partitioned:
                result.findings.append(self.finding(
                    context,
                    title="Filesystem listing is deferred until a partition offset is confirmed",
                    category="disk_partition_workflow",
                    confidence=0.95,
                    explanation="The image contains a partition table. Running fls at offset zero would inspect partition metadata instead of a filesystem, so mmls is selected first and its sector offset must drive follow-up listing.",
                    evidence=["partition_table=true"],
                    severity="info",
                ))
        else:
            result.findings.append(
                self.finding(
                    context,
                    title="Virtual disk container metadata identified",
                    category="virtual_disk_container",
                    confidence=0.95 if qcow_header.get("valid") or vhd_footer.get("valid") else 0.8,
                    explanation=(
                        "The artifact is a VHD/QCOW container rather than a directly addressable raw image. "
                        "Partition tools are intentionally not run against container bytes until an offline conversion or supported attachment step is available."
                    ),
                    evidence=[f"format={context.format}"], severity="info",
                )
            )
        if qcow_header and not qcow_header.get("valid", False):
            result.findings.append(self.finding(
                context, title="QCOW virtual disk header is structurally inconsistent", category="disk_container_anomaly",
                confidence=0.9,
                explanation="QCOW magic was present but fixed header fields or bounds failed validation.",
                evidence=[str(qcow_header)[:2_000]],
            ))
        if vhd_footer.get("signature") and not vhd_footer.get("valid", False):
            result.findings.append(self.finding(
                context, title="VHD footer checksum or metadata validation failed", category="disk_container_anomaly",
                confidence=0.92,
                explanation="The VHD footer cookie was present but its checksum or fixed metadata did not validate.",
                evidence=[str(vhd_footer)[:2_000]],
            ))
        if context.truthy("disk.ewf_signature"):
            result.recommendations.append(
                self.recommendation(
                    "ewfinfo",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "EWF signature detected; validate segment and media metadata before filesystem operations",
                    120,
                )
            )
        ewf_media_size = context.number("disk.ewf.media_size_bytes")
        ewf_segment_count = context.number("disk.ewf.segment_count")
        if ewf_media_size is not None or ewf_segment_count is not None:
            evidence = []
            if ewf_media_size is not None:
                evidence.append(f"reported_media_size_bytes={int(ewf_media_size)}")
            if ewf_segment_count is not None:
                evidence.append(f"reported_segment_count={int(ewf_segment_count)}")
            result.findings.append(self.finding(
                context, title="EWF container metadata recovered", category="ewf_metadata",
                confidence=0.9,
                explanation="ewfinfo reported container media metadata. Compare it with the supplied evidence size and preserve all raw tool output before drawing completeness conclusions.",
                evidence=evidence, severity="info",
            ))
        mbr_entries = next((value for value in context.values("disk.mbr.partitions") if isinstance(value, list)), [])
        gpt_entries = next((value for value in context.values("disk.gpt.partitions") if isinstance(value, list)), [])
        parser_entries = next((value for value in context.values("disk.partitions") if isinstance(value, list)), [])
        if (partitioned or parser_entries) and not virtual_disk:
            # Native MBR/GPT parsing already validated these LBAs against the
            # supplied image.  Each deep FLS task therefore receives its own
            # argv template value instead of accidentally inspecting offset 0.
            candidates = gpt_entries or mbr_entries or parser_entries
            for entry in candidates[:8]:
                if not isinstance(entry, dict):
                    continue
                native_entry = "first_lba" in entry or "start_lba" in entry
                if native_entry and entry.get("within_image") is not True:
                    continue
                description = str(entry.get("description", "")).lower()
                if not native_entry and any(marker in description for marker in ("unallocated", "meta", "primary table")):
                    continue
                raw_offset = entry.get("first_lba", entry.get("start_lba", entry.get("start")))
                try:
                    offset = int(raw_offset)
                except (TypeError, ValueError):
                    continue
                if offset <= 0:
                    continue
                result.recommendations.append(self.recommendation(
                    "sleuthkit_fls",
                    (AnalysisMode.DEEP,),
                    (
                        f"validated native partition metadata identifies filesystem candidate at sector offset {offset}"
                        if native_entry else f"mmls parsed partition metadata identifies filesystem candidate at sector offset {offset}"
                    ),
                    80,
                    command_mode="offset",
                    parameters={"partition_offset": str(offset)},
                ))
                result.recommendations.append(self.recommendation(
                    "sleuthkit_fsstat",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    (
                        f"validated native partition metadata identifies filesystem candidate at sector offset {offset}"
                        if native_entry else f"mmls parsed partition metadata identifies filesystem candidate at sector offset {offset}"
                    ),
                    85,
                    command_mode="offset",
                    parameters={"partition_offset": str(offset)},
                ))
        invalid_mbr = [entry for entry in mbr_entries if isinstance(entry, dict) and not entry.get("within_image", False)]
        if invalid_mbr:
            result.findings.append(
                self.finding(
                    context,
                    title="MBR partition extends outside the supplied image",
                    category="disk_partition_anomaly",
                    confidence=0.9,
                    explanation="A primary partition's declared LBA range is beyond the available evidence size, which can indicate truncation or a damaged partition table.",
                    evidence=[str(entry)[:1_000] for entry in invalid_mbr[:20]],
                )
            )
        gpt_header = next((value for value in context.values("disk.gpt.header") if isinstance(value, dict)), {})
        if gpt_header and not gpt_header.get("valid", False):
            result.findings.append(
                self.finding(
                    context,
                    title="GPT signature has an invalid header layout",
                    category="disk_partition_anomaly",
                    confidence=0.85,
                    explanation="EFI PART was present but key GPT header bounds were not structurally valid; validate the image with a partitioning tool before trusting offsets.",
                    evidence=[str(gpt_header)[:2_000]],
                )
            )
        if gpt_header.get("header_crc_valid") is False:
            result.findings.append(
                self.finding(
                    context,
                    title="GPT header CRC32 validation failed",
                    category="disk_partition_anomaly",
                    confidence=0.95,
                    explanation="The GPT header's stored CRC32 does not match its declared header bytes. Partition metadata should not be trusted without recovery/validation.",
                    evidence=[f"stored_crc={gpt_header.get('header_crc32')}"],
                )
            )
        if gpt_header.get("partition_entry_crc_valid") is False:
            result.findings.append(
                self.finding(
                    context,
                    title="GPT partition entry array CRC32 validation failed",
                    category="disk_partition_anomaly",
                    confidence=0.95,
                    explanation="The bounded complete GPT partition entry table was read, but its CRC32 did not match the header. Individual partition entries may be corrupted.",
                    evidence=[f"stored_crc={gpt_header.get('partition_entry_crc32')}"],
                )
            )
        mft_signature = next((value for value in context.values("filesystem.ntfs.mft0_valid_signature") if isinstance(value, bool)), None)
        mft_bounds = next((value for value in context.values("filesystem.ntfs.mft0_bounds_valid") if isinstance(value, bool)), None)
        mft_fixup = next((value for value in context.values("filesystem.ntfs.mft0_usa_fixup_valid") if isinstance(value, bool)), None)
        if mft_signature is False or mft_bounds is False:
            result.findings.append(
                self.finding(
                    context, title="NTFS MFT record zero is structurally inconsistent", category="filesystem_structure_anomaly",
                    confidence=0.9,
                    explanation="The NTFS boot-sector geometry located record zero, but its FILE signature or fixed header bounds did not validate.",
                    evidence=[f"mft0_signature_valid={mft_signature}", f"mft0_bounds_valid={mft_bounds}"],
                )
            )
        if mft_fixup is False:
            fixup_error = next((str(value) for value in context.values("filesystem.ntfs.mft0_usa_fixup_error") if value), "unspecified USA validation error")
            result.findings.append(
                self.finding(
                    context, title="NTFS MFT record zero update-sequence validation failed", category="filesystem_structure_anomaly",
                    confidence=0.92,
                    explanation=(
                        "The MFT record's update sequence array did not validate against its sector trailers. "
                        "Native attribute metadata was intentionally not trusted or parsed from this record."
                    ),
                    evidence=[f"usa_fixup_error={fixup_error}"],
                )
            )
        attribute_errors = [str(value) for value in context.values("filesystem.ntfs.mft0_attribute_errors") if isinstance(value, list) for value in value]
        if attribute_errors and attribute_errors != ["attributes not parsed because USA fixup did not validate"]:
            result.findings.append(
                self.finding(
                    context, title="NTFS MFT record zero attribute metadata is malformed", category="filesystem_structure_anomaly",
                    confidence=0.88,
                    explanation=(
                        "A bounded attribute walk stopped at an invalid header, name, or data-run boundary. "
                        "The finding preserves parser evidence only; it does not read filesystem clusters or recover content."
                    ),
                    evidence=attribute_errors[:20],
                )
            )
        attributes = next((value for value in context.values("filesystem.ntfs.mft0_attributes") if isinstance(value, list)), [])
        timestamp_mismatches = next(
            (value for value in context.values("filesystem.ntfs.mft0_timestamp_mismatches") if isinstance(value, list)), []
        )
        if timestamp_mismatches:
            result.findings.append(
                self.finding(
                    context, title="NTFS independently stored timestamp metadata differs", category="ntfs_timestamp_mismatch_lead",
                    confidence=0.64,
                    explanation=(
                        "STANDARD_INFORMATION and FILE_NAME retain separate NTFS FILETIME fields. "
                        "Their difference can have benign filesystem causes as well as anti-forensic relevance, so this is a verification lead rather than a timestomping conclusion."
                    ),
                    evidence=[str(item)[:2_000] for item in timestamp_mismatches[:16]], severity="low",
                )
            )
        sampled_records = next(
            (value for value in context.values("filesystem.ntfs.mft_sample_records") if isinstance(value, list)), []
        )
        sample_errors = next(
            (value for value in context.values("filesystem.ntfs.mft_sample_errors") if isinstance(value, list)), []
        )
        if sample_errors:
            result.findings.append(
                self.finding(
                    context, title="Bounded NTFS MFT record sampling stopped on a structural error", category="filesystem_structure_anomaly",
                    confidence=0.82,
                    explanation=(
                        "Native MFT sampling stopped when a validated data-run mapping, FILE header, or update-sequence boundary could not be safely used. "
                        "Previously sampled metadata remains available; confirm image completeness and filesystem structure with SleuthKit."
                    ),
                    evidence=[str(item)[:2_000] for item in sample_errors[:20]],
                )
            )
        sample_record_anomalies = next(
            (value for value in context.values("filesystem.ntfs.mft_sample_record_anomalies") if isinstance(value, list)), []
        )
        if sample_record_anomalies:
            result.findings.append(
                self.finding(
                    context, title="Sampled NTFS FILE record has invalid structural checks", category="filesystem_structure_anomaly",
                    confidence=0.86,
                    explanation=(
                        "One or more data-run-addressed MFT records had an invalid FILE signature, header bounds, or update-sequence validation. "
                        "Their attributes are not trusted by native triage; this is evidence of damaged, stale, or non-record data at the mapped range."
                    ),
                    evidence=[str(item)[:2_000] for item in sample_record_anomalies[:64]],
                )
            )
        special_attributes = [
            {"record_number": record.get("record_number"), "file_names": record.get("file_names"), "attributes": metadata.get("file_attribute_names")}
            for record in sampled_records
            if isinstance(record, dict) and isinstance(record.get("standard_information"), list)
            for metadata in record["standard_information"]
            if isinstance(metadata, dict)
            and isinstance(metadata.get("file_attribute_names"), list)
            and any(name in {"hidden", "system", "reparse_point", "compressed", "encrypted", "offline"} for name in metadata["file_attribute_names"])
        ]
        if special_attributes:
            result.findings.append(
                self.finding(
                    context, title="Sampled NTFS metadata has special file attributes", category="ntfs_special_file_attribute_lead",
                    confidence=0.7,
                    explanation=(
                        "A bounded sampled record's STANDARD_INFORMATION flags include hidden, system, reparse-point, compressed, encrypted, or offline state. "
                        "These flags are triage context only and do not by themselves establish concealment or maliciousness."
                    ),
                    evidence=[str(item)[:2_000] for item in special_attributes[:64]], severity="low",
                )
            )
        deleted_records = [
            item for item in sampled_records
            if isinstance(item, dict) and item.get("deleted") is True
        ]
        if deleted_records:
            result.findings.append(
                self.finding(
                    context, title="Deleted NTFS MFT record metadata sampled", category="ntfs_deleted_record_lead",
                    confidence=0.8,
                    explanation=(
                        "A FILE record with a valid update-sequence array was not marked in use. "
                        "Only bounded record headers and FILE_NAME metadata were sampled; content, data runs, and deleted-file recovery require filesystem-tool verification."
                    ),
                    evidence=[
                        (
                            f"record={item.get('record_number')}; names={item.get('file_names')}; "
                            f"physical_segments={item.get('physical_segments')}"
                        )[:2_000]
                        for item in deleted_records[:20]
                    ],
                    severity="info",
                )
            )
        index_root_entries = [
            entry
            for record in sampled_records
            if isinstance(record, dict) and isinstance(record.get("index_root_entries"), list)
            for entry in record["index_root_entries"]
            if isinstance(entry, dict)
        ]
        if index_root_entries:
            result.findings.append(
                self.finding(
                    context, title="NTFS resident directory index entries sampled", category="ntfs_directory_index_inventory",
                    confidence=0.84,
                    explanation=(
                        "Validated sampled MFT records contained resident `$I30` INDEX_ROOT entries. "
                        "This inventory does not traverse INDEX_ALLOCATION buffers, infer paths, or read referenced file content."
                    ),
                    evidence=[str(entry)[:2_000] for entry in index_root_entries[:128]], severity="info",
                )
            )
        index_allocation_entries = [
            entry
            for record in sampled_records
            if isinstance(record, dict) and isinstance(record.get("index_allocation_entries"), list)
            for entry in record["index_allocation_entries"]
            if isinstance(entry, dict)
        ]
        if index_allocation_entries:
            result.findings.append(
                self.finding(
                    context, title="NTFS nonresident directory index entries sampled",
                    category="ntfs_index_allocation_inventory", confidence=0.9,
                    explanation=(
                        "Validated sampled directory records referenced nonresident `$I30` INDX buffers. "
                        "Each entry passed physical run mapping, INDX bounds, update-sequence fixup, entry bounds, and FILE_NAME-key validation; buffer and physical-segment provenance is retained."
                    ),
                    evidence=[str(entry)[:2_000] for entry in index_allocation_entries[:128]],
                    severity="info",
                )
            )
        index_slack_entries = [
            entry
            for record in sampled_records
            if isinstance(record, dict) and isinstance(record.get("index_allocation_slack_entries"), list)
            for entry in record["index_allocation_slack_entries"]
            if isinstance(entry, dict)
        ]
        if index_slack_entries:
            result.findings.append(
                self.finding(
                    context, title="Possible stale NTFS directory entries recovered from INDX slack",
                    category="ntfs_index_slack_entry_lead", confidence=0.72,
                    explanation=(
                        "Unused bytes inside validated `$I30` allocation bounds contained aligned structures with plausible index-entry and FILE_NAME fields. "
                        "They are lower-confidence stale/deleted-entry candidates, not active directory membership; each retains its exact INDX buffer and physical-range provenance."
                    ),
                    evidence=[str(entry)[:2_000] for entry in index_slack_entries[:128]],
                    severity="low",
                )
            )
        parent_links = next(
            (value for value in context.values("filesystem.ntfs.mft_sample_parent_links") if isinstance(value, list)), []
        )
        sampled_parent_mismatches = [
            item for item in parent_links
            if isinstance(item, dict) and item.get("parent_sampled") is True and item.get("parent_sequence_matches") is False
        ]
        if sampled_parent_mismatches:
            result.findings.append(
                self.finding(
                    context, title="Sampled NTFS FILE_NAME parent reference has a sequence mismatch", category="ntfs_parent_reference_mismatch_lead",
                    confidence=0.68,
                    explanation=(
                        "A FILE_NAME parent reference resolved within the bounded MFT sample but its sequence number differs. "
                        "This can reflect stale/deleted metadata or record reuse; no full path is inferred and filesystem-tool verification is required."
                    ),
                    evidence=[str(item)[:2_000] for item in sampled_parent_mismatches[:50]], severity="low",
                )
            )
        index_links = next(
            (value for value in context.values("filesystem.ntfs.mft_sample_index_links") if isinstance(value, list)), []
        )
        index_mismatches = [
            item for item in index_links
            if isinstance(item, dict)
            and item.get("child_sampled") is True
            and (item.get("child_sequence_matches") is False or item.get("child_file_name_matches") is False)
        ]
        if index_mismatches:
            result.findings.append(
                self.finding(
                    context, title="Sampled NTFS directory index conflicts with referenced record", category="ntfs_directory_index_mismatch_lead",
                    confidence=0.7,
                    explanation=(
                        "A resident `$I30` entry resolved to a sampled record but its sequence number or FILE_NAME text differs. "
                        "This can result from stale directory metadata, deletion, or record reuse; verify with a full filesystem parser before drawing conclusions."
                    ),
                    evidence=[str(item)[:2_000] for item in index_mismatches[:50]], severity="low",
                )
            )
        attribute_list_links = next(
            (value for value in context.values("filesystem.ntfs.mft_sample_attribute_list_links") if isinstance(value, list)), []
        )
        attribute_list_mismatches = [
            item for item in attribute_list_links
            if isinstance(item, dict) and item.get("target_sampled") is True and item.get("target_sequence_matches") is False
        ]
        if attribute_list_mismatches:
            result.findings.append(
                self.finding(
                    context, title="Sampled NTFS attribute extent reference has a sequence mismatch", category="ntfs_attribute_list_mismatch_lead",
                    confidence=0.7,
                    explanation=(
                        "An ATTRIBUTE_LIST extent reference resolved inside the bounded MFT sample but the target record sequence differs. "
                        "This can reflect stale metadata or record reuse; extension parsing is intentionally deferred to a filesystem verifier."
                    ),
                    evidence=[str(item)[:2_000] for item in attribute_list_mismatches[:50]], severity="low",
                )
            )
        index_allocations = [
            attribute for attribute in attributes
            if isinstance(attribute, dict)
            and attribute.get("type_name") == "index_allocation"
            and attribute.get("nonresident") is True
        ]
        if index_allocations:
            result.findings.append(
                self.finding(
                    context, title="NTFS nonresident directory index allocation metadata recovered", category="ntfs_index_allocation_metadata",
                    confidence=0.84,
                    explanation=(
                        "The sampled MFT metadata declares nonresident `$I30` INDEX_ALLOCATION storage. "
                        "Only its bounded VCN, size, and run descriptors are recorded; native triage does not read or traverse index buffers."
                    ),
                    evidence=[
                        (
                            f"offset={item.get('offset')}; real_size={item.get('real_size')}; "
                            f"data_runs={item.get('data_runs')}"
                        )[:2_000]
                        for item in index_allocations[:20]
                    ],
                    severity="info",
                )
            )
        attribute_list_references = [
            reference for attribute in attributes
            if isinstance(attribute, dict) and attribute.get("type_name") == "attribute_list"
            and isinstance(attribute.get("extent_references"), list)
            for reference in attribute["extent_references"]
            if isinstance(reference, dict)
        ]
        if attribute_list_references:
            result.findings.append(
                self.finding(
                    context, title="NTFS MFT attribute extent references recovered", category="ntfs_attribute_list_inventory",
                    confidence=0.82,
                    explanation=(
                        "A resident `$ATTRIBUTE_LIST` identifies attribute extents in other MFT records. "
                        "The references are preserved for verification but extension records and data are not automatically resolved."
                    ),
                    evidence=[str(item)[:2_000] for item in attribute_list_references[:64]], severity="info",
                )
            )
        named_data = [
            attribute for attribute in attributes
            if isinstance(attribute, dict)
            and attribute.get("type_name") == "data"
            and isinstance(attribute.get("name"), str)
            and attribute["name"]
        ]
        if named_data:
            result.findings.append(
                self.finding(
                    context, title="Named NTFS DATA attribute observed in MFT record zero", category="ntfs_named_data_attribute",
                    confidence=0.86,
                    explanation=(
                        "The validated MFT record contains named DATA metadata (the NTFS mechanism used for alternate data streams). "
                        "Only bounded attribute and data-run metadata was inventoried; no stream bytes were read or extracted."
                    ),
                    evidence=[
                        (
                            f"name={attribute['name']!r}; nonresident={attribute.get('nonresident')}; "
                            f"real_size={attribute.get('real_size')}; data_runs={attribute.get('data_runs', [])}"
                        )[:2_000]
                        for attribute in named_data[:20]
                    ],
                    severity="info",
                )
            )
        return result
