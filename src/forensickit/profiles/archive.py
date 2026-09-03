from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


ARCHIVE_TYPES = {
    "archive", "container", "zip", "7z", "rar", "tar", "gzip", "gz", "bzip2", "xz",
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
        if any(marker in mime for marker in ("zip", "rar", "7z", "tar", "gzip", "compressed", "archive")):
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
        return result
