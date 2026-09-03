from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


class FirmwareProfile(BaseProfile):
    """Plan bounded firmware carving only after a concrete image signature."""

    name = "firmware"
    priority = 675

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("firmware") or context.format_is("squashfs", "uimage", "android_boot"):
            return ["firmware/container signature classification is present"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.append(self.recommendation(
            "binwalk3", (AnalysisMode.AUTO, AnalysisMode.DEEP),
            "firmware header warrants signature inventory before any selective extraction", 105,
        ))
        valid = context.truthy("firmware.squashfs_valid", "firmware.uimage_valid", "firmware.android_boot_valid")
        if not valid:
            result.findings.append(self.finding(
                context, title="Firmware header has inconsistent declared bounds", category="firmware_structure_anomaly",
                confidence=0.85,
                explanation="A firmware magic was present but its fixed header fields were inconsistent with the supplied file size.",
                evidence=["header validation failed"],
            ))
        header_crc_valid = next((value for value in context.values("firmware.uimage.header_crc_valid") if isinstance(value, bool)), None)
        payload_crc_valid = next((value for value in context.values("firmware.uimage.payload_crc_valid") if isinstance(value, bool)), None)
        if header_crc_valid is False or payload_crc_valid is False:
            result.findings.append(self.finding(
                context, title="U-Boot legacy image CRC validation failed", category="firmware_integrity_anomaly",
                confidence=0.96,
                explanation="The U-Boot header CRC or bounded payload CRC did not match the stored value. Firmware bytes may be corrupt or intentionally modified.",
                evidence=[f"header_crc_valid={header_crc_valid}", f"payload_crc_valid={payload_crc_valid}"],
            ))
        return result
