from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .models import Artifact, Classification, Observation


@dataclass(frozen=True, slots=True)
class _FormatInfo:
    artifact_type: str
    profile: str
    mime: str
    magic: str
    confidence: float


_FORMAT_INFO: dict[str, _FormatInfo] = {
    "png": _FormatInfo("image", "image", "image/png", "PNG image data", 0.99),
    "jpeg": _FormatInfo("image", "image", "image/jpeg", "JPEG image data", 0.99),
    "gif": _FormatInfo("image", "image", "image/gif", "GIF image data", 0.99),
    "bmp": _FormatInfo("image", "image", "image/bmp", "BMP image data", 0.99),
    "tiff": _FormatInfo("image", "image", "image/tiff", "TIFF image data", 0.99),
    "zip": _FormatInfo("archive", "archive", "application/zip", "Zip archive data", 0.99),
    "7z": _FormatInfo("archive", "archive", "application/x-7z-compressed", "7-zip archive data", 0.99),
    "gzip": _FormatInfo("archive", "archive", "application/gzip", "gzip compressed data", 0.99),
    "tar": _FormatInfo("archive", "archive", "application/x-tar", "tar archive", 0.98),
    "rar": _FormatInfo("archive", "archive", "application/vnd.rar", "RAR archive data", 0.99),
    "cpio": _FormatInfo("archive", "archive", "application/x-cpio", "ASCII cpio archive", 0.99),
    "iso9660": _FormatInfo("archive", "archive", "application/x-iso9660-image", "ISO 9660 filesystem image", 0.99),
    "bzip2": _FormatInfo("archive", "archive", "application/x-bzip2", "bzip2 compressed data", 0.98),
    "xz": _FormatInfo("archive", "archive", "application/x-xz", "XZ compressed data", 0.99),
    "ewf": _FormatInfo("disk", "disk", "application/x-ewf", "EWF forensic image", 0.99),
    "vhd": _FormatInfo("disk", "disk", "application/x-vhd", "Virtual Hard Disk image", 0.96),
    "qcow2": _FormatInfo("disk", "disk", "application/x-qemu-disk", "QCOW virtual disk image", 0.99),
    "memory": _FormatInfo("memory", "memory", "application/octet-stream", "memory dump", 0.85),
    "disk_mbr": _FormatInfo("disk", "disk", "application/octet-stream", "MBR disk image", 0.80),
    "disk_gpt": _FormatInfo("disk", "disk", "application/octet-stream", "GPT disk image", 0.90),
    "filesystem": _FormatInfo("filesystem", "disk", "application/octet-stream", "filesystem image", 0.85),
    "exfat": _FormatInfo("filesystem", "disk", "application/octet-stream", "exFAT filesystem image", 0.98),
    "evtx": _FormatInfo("evtx", "windows", "application/x-evtx", "Windows EVTX event log", 0.99),
    "registry": _FormatInfo("registry", "windows", "application/x-windows-registry", "Windows Registry hive", 0.99),
    "lnk": _FormatInfo("windows", "windows", "application/x-ms-shortcut", "Windows shell link", 0.99),
    "prefetch": _FormatInfo("windows", "windows", "application/octet-stream", "Windows Prefetch file", 0.97),
    "recycle_bin": _FormatInfo("windows", "windows", "application/octet-stream", "Windows Recycle Bin $I metadata", 0.96),
    "pdf": _FormatInfo("pdf", "pdf", "application/pdf", "PDF document", 0.99),
    "pcap": _FormatInfo("pcap", "pcap", "application/vnd.tcpdump.pcap", "packet capture data", 0.99),
    "pcapng": _FormatInfo("pcap", "pcap", "application/x-pcapng", "pcapng capture file", 0.99),
    "sqlite": _FormatInfo("sqlite", "sqlite", "application/vnd.sqlite3", "SQLite 3.x database", 0.99),
    "android_backup": _FormatInfo("android", "mobile", "application/x-android-backup", "Android backup", 0.99),
    "plist": _FormatInfo("generic", "generic", "application/x-plist", "Apple property list", 0.97),
    "ios_backup_info": _FormatInfo("ios", "mobile", "application/x-plist", "iOS backup Info.plist", 0.96),
    "ios_backup_manifest": _FormatInfo("ios", "mobile", "application/vnd.sqlite3", "iOS backup Manifest.db", 0.9),
    "squashfs": _FormatInfo("firmware", "firmware", "application/x-squashfs", "Squashfs filesystem image", 0.99),
    "uimage": _FormatInfo("firmware", "firmware", "application/x-u-boot-image", "U-Boot legacy image", 0.99),
    "android_boot": _FormatInfo("firmware", "firmware", "application/x-android-boot-image", "Android boot image", 0.99),
    "wav": _FormatInfo("audio", "media", "audio/wav", "WAV audio", 0.99),
    "mp3": _FormatInfo("audio", "media", "audio/mpeg", "MPEG audio", 0.96),
    "flac": _FormatInfo("audio", "media", "audio/flac", "FLAC audio", 0.99),
    "ogg": _FormatInfo("audio", "media", "audio/ogg", "Ogg media", 0.96),
    "isobmff": _FormatInfo("video", "media", "video/mp4", "ISO Base Media file", 0.94),
    "matroska": _FormatInfo("video", "media", "video/x-matroska", "Matroska media", 0.95),
    "avi": _FormatInfo("video", "media", "video/x-msvideo", "AVI video", 0.99),
    "ole": _FormatInfo("office", "office", "application/x-ole-storage", "OLE 2 Compound Document", 0.99),
    "elf": _FormatInfo("executable", "executable", "application/x-elf", "ELF executable or object", 0.99),
    "pe": _FormatInfo(
        "executable",
        "executable",
        "application/vnd.microsoft.portable-executable",
        "PE executable or object",
        0.98,
    ),
    "docx": _FormatInfo(
        "office",
        "office",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "Microsoft Word 2007+ document",
        0.99,
    ),
    "xlsx": _FormatInfo(
        "office",
        "office",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "Microsoft Excel 2007+ document",
        0.99,
    ),
    "pptx": _FormatInfo(
        "office",
        "office",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "Microsoft PowerPoint 2007+ document",
        0.99,
    ),
    "ooxml": _FormatInfo("office", "office", "application/zip", "OOXML package", 0.96),
    "apk": _FormatInfo(
        "android", "android", "application/vnd.android.package-archive", "Android APK package", 0.98
    ),
    "jar": _FormatInfo("archive", "archive", "application/java-archive", "Java archive data", 0.96),
    "text": _FormatInfo("text", "generic", "text/plain", "plain text data", 0.88),
    "empty": _FormatInfo("empty", "generic", "application/x-empty", "empty", 1.0),
    "unknown_binary": _FormatInfo(
        "unknown_binary", "unknown", "application/octet-stream", "data", 0.40
    ),
}


@dataclass(slots=True)
class IdentificationResult:
    """The explicit output of artifact identification.

    ``artifact`` is updated in place for persistence. ``observations`` are new
    normalized observations that the caller should add to its observation
    store alongside the triage observations.
    """

    artifact: Artifact
    primary: Classification
    classifications: list[Classification]
    observations: list[Observation]
    format: str
    profiles: list[str]


class IdentificationEngine:
    """Classify an artifact from deterministic triage observations.

    Extensions are never used as affirmative format evidence. Header magic,
    validated structures, and embedded signatures drive the confidence and
    reasons recorded for every classification.
    """

    def identify(
        self, artifact: Artifact, observations: Iterable[Observation]
    ) -> IdentificationResult:
        values = _ObservationValues(observations)
        format_name = self._select_format(artifact, values)
        info = _FORMAT_INFO[format_name]
        reason = self._primary_reason(format_name, values)
        primary = Classification(
            artifact_type=info.artifact_type,
            confidence=info.confidence,
            reason=reason,
            source="identification_engine",
        )

        classifications = [primary]
        self._add_secondary_classifications(
            artifact, format_name, values, classifications
        )
        classifications = _deduplicate_classifications(classifications)

        profiles = ["generic"]
        if info.profile != "generic":
            profiles.append(info.profile)
        for classification in classifications[1:]:
            profile = _profile_for_artifact_type(classification.artifact_type)
            if profile and profile not in profiles:
                profiles.append(profile)

        artifact.mime = info.mime
        artifact.magic = info.magic
        artifact.artifact_type = primary.artifact_type
        artifact.classifications = classifications

        normalized = [
            _observation(
                artifact,
                "artifact.format",
                format_name,
                confidence=primary.confidence,
            ),
            _observation(
                artifact,
                "artifact.profile",
                info.profile,
                confidence=primary.confidence,
            ),
            _observation(
                artifact,
                "artifact.profiles",
                profiles,
                confidence=primary.confidence,
            ),
            _observation(
                artifact,
                "artifact.type",
                artifact.artifact_type,
                confidence=primary.confidence,
            ),
            _observation(artifact, "artifact.mime", artifact.mime, confidence=primary.confidence),
            _observation(artifact, "artifact.magic", artifact.magic, confidence=primary.confidence),
            _observation(
                artifact,
                "artifact.classifications",
                [
                    {
                        "artifact_type": item.artifact_type,
                        "confidence": item.confidence,
                        "reason": item.reason,
                        "source": item.source,
                    }
                    for item in classifications
                ],
                confidence=primary.confidence,
            ),
        ]
        return IdentificationResult(
            artifact=artifact,
            primary=primary,
            classifications=classifications,
            observations=normalized,
            format=format_name,
            profiles=profiles,
        )

    # ``classify`` reads naturally in consumers that already own an Artifact.
    classify = identify

    def _select_format(self, artifact: Artifact, values: "_ObservationValues") -> str:
        size = values.get("artifact.size", artifact.size)
        if size == 0:
            return "empty"

        if values.get("windows.recycle_bin_valid") is True:
            return "recycle_bin"

        header_format = values.get("triage.detected_header_format")
        if header_format in _FORMAT_INFO and header_format != "unknown":
            if header_format == "plist" and values.get("mobile.ios_backup_info_plist") is True:
                return "ios_backup_info"
            if (
                header_format == "sqlite"
                and artifact.logical_name.lower() == "manifest.db"
                and isinstance(values.get("sqlite.tables"), list)
                and {str(item).lower() for item in values.get("sqlite.tables", [])} >= {"files", "properties"}
            ):
                return "ios_backup_manifest"
            if header_format == "zip":
                container_kind = values.get("archive.container_kind")
                if container_kind in {"docx", "xlsx", "pptx", "ooxml", "apk", "jar"}:
                    return str(container_kind)
                ooxml_kind = values.get("archive.zip.ooxml_kind")
                if ooxml_kind in {"docx", "xlsx", "pptx", "ooxml"}:
                    return str(ooxml_kind)
            return str(header_format)

        file_description = str(values.get("file.description", "")).lower()
        file_mime = str(values.get("file.mime_type", values.get("exiftool.mime_type", ""))).lower()
        file_signals = (
            ("pcapng", "pcapng"), ("tcpdump", "pcap"), ("pcap capture", "pcap"), ("packet capture", "pcap"),
            ("sqlite", "sqlite"), ("pdf document", "pdf"), ("png image", "png"),
            ("jpeg image", "jpeg"), ("zip archive", "zip"), ("7-zip", "7z"),
            ("cpio archive", "cpio"),
            ("iso 9660", "iso9660"),
            ("elf", "elf"), ("ms-dos executable", "pe"), ("compound document", "ole"),
            ("ewf", "ewf"),
        )
        for marker, format_name in file_signals:
            if marker in file_description or marker in file_mime:
                return format_name

        if values.get("disk.ewf_signature") is True:
            return "ewf"
        if isinstance(values.get("disk.vhd.footer"), dict) and values.get("disk.vhd_signature") is True:
            return "vhd"
        if isinstance(values.get("disk.qcow2.header"), dict) and values.get("disk.qcow2_signature") is True:
            return "qcow2"
        if values.get("signature.memory_dump") is True or values.get("memory.signature_detected") is True:
            return "memory"
        if values.get("disk.gpt_signature") is True:
            return "disk_gpt"
        if values.get("disk.mbr_signature") is True:
            return "disk_mbr"
        if values.get("filesystem.signature_detected") is True:
            return "filesystem"
        media_format = values.get("media.format")
        if media_format in _FORMAT_INFO:
            return str(media_format)
        # PDF readers allow a header within the first 1024 bytes. Preserve
        # that well-defined exception without treating arbitrary deep content
        # as the outer artifact format.
        pdf_offsets = values.get("signature.pdf.offsets", [])
        if isinstance(pdf_offsets, list) and pdf_offsets and pdf_offsets[0] <= 1024:
            return "pdf"

        printable_ratio = _as_float(values.get("content.printable_ratio"), 0.0)
        nul_ratio = _as_float(values.get("content.nul_ratio"), 1.0)
        if printable_ratio >= 0.85 and nul_ratio <= 0.01:
            return "text"
        return "unknown_binary"

    @staticmethod
    def _primary_reason(format_name: str, values: "_ObservationValues") -> str:
        if format_name == "empty":
            return "artifact has zero bytes"
        if format_name == "text":
            return (
                "sampled content is predominantly printable "
                f"(ratio={values.get('content.printable_ratio')}) with few NUL bytes"
            )
        if format_name == "unknown_binary":
            return "no supported outer-format signature or strong text structure was observed"
        if format_name in {"docx", "xlsx", "pptx", "ooxml", "apk", "jar"}:
            return f"ZIP local-entry names identify a {format_name} container"
        file_description = values.get("file.description")
        if isinstance(file_description, str) and file_description.strip():
            return f"external file/libmagic parser reported: {file_description[:300]}"
        if format_name in {"disk_mbr", "disk_gpt", "memory", "ewf"}:
            return f"disk/memory signature observation identified {format_name} evidence"
        return f"validated {format_name} header signature at offset 0"

    @staticmethod
    def _add_secondary_classifications(
        artifact: Artifact,
        format_name: str,
        values: "_ObservationValues",
        classifications: list[Classification],
    ) -> None:
        if format_name in {"docx", "xlsx", "pptx", "ooxml", "apk", "jar"}:
            classifications.append(
                Classification(
                    artifact_type="archive",
                    confidence=0.78,
                    reason=f"{format_name} is structurally a ZIP container",
                    source="identification_engine",
                )
            )

        embedded_zip_offsets = values.get("embedded.zip.offsets", [])
        if values.get("embedded.pk_signature") is True and embedded_zip_offsets:
            confidence = 0.78
            reason = f"ZIP signature observed inside outer {format_name} artifact"
            if format_name == "png" and _as_int(values.get("png.bytes_after_iend")) > 0:
                confidence = 0.97
                reason = "ZIP signature and data were observed after the PNG IEND trailer"
            elif format_name == "jpeg" and _as_int(values.get("jpeg.bytes_after_eoi")) > 0:
                confidence = 0.96
                reason = "ZIP signature and data were observed after the JPEG EOI marker"
            classifications.append(
                Classification(
                    artifact_type="archive",
                    confidence=confidence,
                    reason=reason,
                    source="identification_engine",
                )
            )

        if format_name == "png":
            bytes_after = _as_int(values.get("png.bytes_after_iend"))
            unusual = values.get("png.unusual_chunk_types", [])
            if bytes_after > 0 or (isinstance(unusual, list) and unusual):
                reasons = []
                if bytes_after > 0:
                    reasons.append(f"{bytes_after} bytes follow IEND")
                if unusual:
                    reasons.append(f"unusual chunks: {', '.join(map(str, unusual))}")
                classifications.append(
                    Classification(
                        artifact_type="steganography",
                        confidence=0.90 if bytes_after else 0.65,
                        reason="; ".join(reasons),
                        source="identification_engine",
                    )
                )
        elif format_name == "jpeg" and _as_int(values.get("jpeg.bytes_after_eoi")) > 0:
            classifications.append(
                Classification(
                    artifact_type="steganography",
                    confidence=0.86,
                    reason=f"{values.get('jpeg.bytes_after_eoi')} bytes follow JPEG EOI",
                    source="identification_engine",
                )
            )

        # Deep signatures still provide useful secondary hypotheses for an
        # otherwise unknown/text outer artifact.
        if format_name in {"unknown_binary", "text"}:
            embedded = values.get("embedded.signatures", [])
            if isinstance(embedded, list):
                formats = sorted(
                    {
                        str(item.get("format"))
                        for item in embedded
                        if isinstance(item, dict) and item.get("format")
                    }
                )
                for embedded_format in formats:
                    artifact_type = _artifact_type_for_embedded_format(embedded_format)
                    if artifact_type:
                        classifications.append(
                            Classification(
                                artifact_type=artifact_type,
                                confidence=0.62,
                                reason=f"embedded {embedded_format} signature observed",
                                source="identification_engine",
                            )
                        )


class _ObservationValues:
    def __init__(self, observations: Iterable[Observation]) -> None:
        self._values: dict[str, Any] = {}
        for observation in observations:
            self._values[observation.key] = observation.value

    def get(self, key: str, default: Any = None) -> Any:
        return self._values.get(key, default)


def _observation(
    artifact: Artifact, key: str, value: object, *, confidence: float
) -> Observation:
    return Observation(
        artifact_id=artifact.id,
        key=key,
        value=value,
        source="identification_engine",
        confidence=confidence,
    )


def _deduplicate_classifications(
    classifications: list[Classification],
) -> list[Classification]:
    result: list[Classification] = []
    index_by_type: dict[str, int] = {}
    for classification in classifications:
        existing_index = index_by_type.get(classification.artifact_type)
        if existing_index is None:
            index_by_type[classification.artifact_type] = len(result)
            result.append(classification)
        elif classification.confidence > result[existing_index].confidence:
            result[existing_index] = classification
    return result


def _profile_for_artifact_type(artifact_type: str) -> str | None:
    return {
        "image": "image",
        "steganography": "steganography",
        "archive": "archive",
        "pcap": "pcap",
        "pdf": "pdf",
        "office": "office",
        "sqlite": "sqlite",
        "executable": "executable",
        "firmware": "firmware",
        "audio": "media",
        "video": "media",
        "android": "mobile",
        "ios": "mobile",
        "evtx": "windows",
        "registry": "windows",
        "unknown_binary": "unknown",
    }.get(artifact_type)


def _artifact_type_for_embedded_format(format_name: str) -> str | None:
    if format_name in {"zip", "7z", "gzip", "rar", "cpio", "iso9660", "bzip2", "xz"}:
        return "archive"
    if format_name in {"png", "jpeg"}:
        return "image"
    if format_name in {"pcap", "pcapng"}:
        return "pcap"
    if format_name == "pdf":
        return "pdf"
    if format_name == "ole":
        return "office"
    if format_name == "sqlite":
        return "sqlite"
    if format_name in {"elf", "pe"}:
        return "executable"
    return None


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
