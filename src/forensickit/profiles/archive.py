from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


ARCHIVE_TYPES = {
    "archive", "container", "zip", "7z", "rar", "tar", "cpio", "gzip", "gz", "bzip2", "xz",
    "cab", "iso", "jar", "apk", "ooxml",
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
                        "Bounded native newc/CRC parsing found a malformed range/header, mixed entry formats, "
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
        return result
