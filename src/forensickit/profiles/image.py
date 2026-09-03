from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


IMAGE_TYPES = {"image", "png", "jpeg", "jpg", "gif", "bmp", "tiff", "webp"}


class ImageProfile(BaseProfile):
    name = "image"
    priority = 900

    def match_reasons(self, context: ProfileContext) -> list[str]:
        reasons: list[str] = []
        if context.artifact_types & IMAGE_TYPES:
            reasons.append(f"classification includes image type: {sorted(context.artifact_types & IMAGE_TYPES)}")
        if (context.artifact.mime or "").lower().startswith("image/"):
            reasons.append(f"MIME is {context.artifact.mime}")
        if context.format_is("png", "jpeg", "jpg", "gif", "bmp", "tiff", "webp"):
            reasons.append(f"observed image format is {context.format}")
        return reasons

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.append(
            self.recommendation(
                "exiftool",
                (AnalysisMode.AUTO, AnalysisMode.DEEP),
                "image metadata can expose editing history, comments, and embedded previews",
                90,
            )
        )
        if context.format_is("png"):
            result.recommendations.append(
                self.recommendation(
                    "pngcheck",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "PNG classification warrants chunk and CRC validation",
                    100,
                )
            )

        trailer_keys = (
            "png.bytes_after_iend", "jpeg.bytes_after_eoi", "image.bytes_after_end",
            "structure.trailing_bytes", "artifact.trailing_bytes",
        )
        trailing_bytes = context.number(*trailer_keys)
        if trailing_bytes is not None and trailing_bytes > 0:
            evidence = [f"{int(trailing_bytes)} trailing byte(s) exist after the image end marker"]
            result.findings.append(
                self.finding(
                    context,
                    title="Data exists after image end marker",
                    category="structural_anomaly",
                    confidence=0.92,
                    explanation="Trailing bytes can contain an appended archive or hidden payload.",
                    evidence=evidence,
                )
            )
            result.recommendations.extend(
                [
                    self.recommendation(
                        "binwalk3", (AnalysisMode.AUTO, AnalysisMode.DEEP), evidence[0], 110
                    ),
                    self.recommendation(
                        "sevenzip", (AnalysisMode.AUTO, AnalysisMode.DEEP),
                        "validate whether trailing data is an archive", 105,
                    ),
                ]
            )

        if context.truthy("embedded.pk_signature", "embedded.zip", "signature.zip_embedded"):
            reason = "an embedded PK/ZIP signature was observed in the image"
            result.findings.append(
                self.finding(
                    context,
                    title="Possible ZIP payload embedded in image",
                    category="embedded_archive",
                    confidence=0.97,
                    explanation="A ZIP signature inside an image strongly supports an embedded or appended archive hypothesis.",
                    evidence=[reason],
                    severity="high",
                )
            )
            result.recommendations.extend(
                [
                    self.recommendation("binwalk3", (AnalysisMode.AUTO, AnalysisMode.DEEP), reason, 120),
                    self.recommendation("sevenzip", (AnalysisMode.AUTO, AnalysisMode.DEEP), reason, 115),
                ]
            )
        gif_trailing = context.number("gif.bytes_after_trailer") or 0
        bmp_matches = next((value for value in context.values("bmp.size_matches") if isinstance(value, bool)), None)
        if gif_trailing > 0:
            result.findings.append(
                self.finding(
                    context, title="Data exists after GIF trailer", category="appended_data",
                    confidence=0.85,
                    explanation="Bytes follow the GIF trailer marker and may represent an appended payload.",
                    evidence=[f"{int(gif_trailing)} byte(s) after trailer"],
                )
            )
        if bmp_matches is False:
            result.findings.append(
                self.finding(
                    context, title="BMP declared size does not match evidence", category="structural_anomaly",
                    confidence=0.85,
                    explanation="The BMP file-size field differs from observed evidence size, indicating trailing data or truncation.",
                    evidence=["bmp.size_matches=false"],
                )
            )
        crc_failures = next((value for value in context.values("png.crc_failures") if isinstance(value, list)), [])
        if crc_failures:
            result.findings.append(
                self.finding(
                    context, title="PNG chunk CRC validation failed", category="image_integrity_anomaly",
                    confidence=0.97,
                    explanation="The bounded native PNG parser calculated one or more chunk CRC values that differ from stored values.",
                    evidence=[str(item)[:1_000] for item in crc_failures[:30]],
                )
            )
        jpeg_comments = next((value for value in context.values("jpeg.comments") if isinstance(value, list)), [])
        if jpeg_comments:
            result.findings.append(
                self.finding(
                    context, title="JPEG comment segment(s) recovered", category="image_metadata_lead",
                    confidence=0.88,
                    explanation="JPEG COM segments carry arbitrary creator-supplied bytes and are preserved as bounded textual observations for review.",
                    evidence=[str(item)[:2_000] for item in jpeg_comments[:50]], severity="info",
                )
            )
        jpeg_app_segments = next((value for value in context.values("jpeg.app_segments") if isinstance(value, list)), [])
        recognized_jpeg_metadata = [
            item for item in jpeg_app_segments
            if isinstance(item, dict) and item.get("kind") in {"exif", "xmp", "icc_profile", "photoshop_irb"}
        ]
        if recognized_jpeg_metadata:
            result.findings.append(
                self.finding(
                    context, title="JPEG application metadata segment(s) identified", category="image_metadata_lead",
                    confidence=0.88,
                    explanation=(
                        "JPEG APP segments advertise embedded EXIF, XMP, ICC, or Photoshop image-resource metadata. "
                        "The bounded native inventory retains segment provenance and identifier bytes; use ExifTool for full metadata decoding."
                    ),
                    evidence=[str(item)[:2_000] for item in recognized_jpeg_metadata[:100]], severity="info",
                )
            )
        icc_profile_valid = next((value for value in context.values("jpeg.icc_profile_valid") if isinstance(value, bool)), None)
        if icc_profile_valid is False:
            icc_error = next((str(value) for value in context.values("jpeg.icc_profile_error") if value), "unspecified ICC_PROFILE sequence error")
            result.findings.append(
                self.finding(
                    context, title="JPEG ICC_PROFILE application segments are structurally inconsistent", category="image_integrity_anomaly",
                    confidence=0.9,
                    explanation="JPEG APP2 ICC_PROFILE chunks disagree on count, sequence, or completeness; color-profile metadata should not be trusted without external validation.",
                    evidence=[icc_error],
                )
            )
        exif_entries = next((value for value in context.values("jpeg.exif_entries") if isinstance(value, list)), [])
        exif_metadata = [item for item in exif_entries if isinstance(item, dict) and isinstance(item.get("tags"), dict) and item["tags"]]
        exif_errors = [str(item.get("error")) for item in exif_entries if isinstance(item, dict) and item.get("error")]
        if exif_metadata:
            result.findings.append(self.finding(
                context, title="JPEG EXIF scalar metadata recovered", category="image_metadata_lead", confidence=0.88,
                explanation="Bounded APP1 TIFF parsing recovered IFD0 scalar metadata without rendering the image or traversing EXIF sub-IFDs.",
                evidence=[str(item)[:2_000] for item in exif_metadata[:32]], severity="info",
            ))
        if exif_errors:
            result.findings.append(self.finding(
                context, title="JPEG EXIF APP1 metadata is structurally inconsistent", category="image_integrity_anomaly", confidence=0.85,
                explanation="An EXIF APP1 segment did not satisfy bounded TIFF header or IFD bounds validation; its metadata was not trusted.",
                evidence=exif_errors[:32],
            ))
        png_text_entries = next((value for value in context.values("png.text_entries") if isinstance(value, list)), [])
        if png_text_entries:
            result.findings.append(
                self.finding(
                    context, title="PNG text chunk metadata recovered", category="image_metadata_lead",
                    confidence=0.9,
                    explanation="Bounded tEXt/zTXt/iTXt chunk decoding recovered creator-supplied metadata without invoking an image renderer.",
                    evidence=[str(item)[:2_000] for item in png_text_entries[:50]], severity="info",
                )
            )
        gif_comments = next((value for value in context.values("gif.comments") if isinstance(value, list)), [])
        if gif_comments:
            result.findings.append(
                self.finding(
                    context, title="GIF comment extension(s) recovered", category="image_metadata_lead",
                    confidence=0.88,
                    explanation="GIF comment extension sub-blocks contain arbitrary creator-supplied bytes and were structurally bounded before textual decoding.",
                    evidence=[str(item)[:2_000] for item in gif_comments[:50]], severity="info",
                )
            )
        return result


class SteganographyProfile(BaseProfile):
    name = "steganography"
    priority = 850

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("steganography", "stego"):
            return ["classification explicitly indicates steganography"]
        if context.format_is("png", "bmp", "jpeg", "jpg", "wav", "au"):
            return [f"{context.format} is supported by common local steganography analyzers"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        anomaly = context.truthy(
            "image.unusual_chunks", "image.unusual_palette", "image.channel_anomaly",
            "stego.suspected", "png.unusual_chunks", "png.unusual_chunk_types", "png.crc_failures",
        )
        if context.format_is("png", "bmp"):
            modes = (AnalysisMode.AUTO, AnalysisMode.DEEP) if anomaly else (AnalysisMode.DEEP,)
            reason = (
                "image structure/channel anomaly justifies bit-plane analysis"
                if anomaly else f"deep mode permits bounded bit-plane checks for {context.format}"
            )
            result.recommendations.append(self.recommendation("zsteg", modes, reason, 85 if anomaly else 55))
        if context.format_is("jpeg", "jpg", "bmp", "wav", "au"):
            result.recommendations.append(
                self.recommendation(
                    "steghide",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    f"{context.format} supports steghide metadata/capacity inspection",
                    70,
                )
            )
            if anomaly or context.truthy("steghide.embedded_data", "stego.password_candidate"):
                result.recommendations.append(
                    self.recommendation(
                        "stegseek",
                        (AnalysisMode.DEEP,),
                        "steganography evidence justifies bounded local passphrase recovery",
                        45,
                    )
                )
        if context.format_is("jpeg", "jpg"):
            result.recommendations.append(
                self.recommendation(
                    "outguess",
                    (AnalysisMode.DEEP,),
                    "deep JPEG steganography recovery with a locally installed outguess binary",
                    50,
                )
            )
        return result
