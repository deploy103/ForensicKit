from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


class GenericProfile(BaseProfile):
    name = "generic"
    priority = 1000

    def match_reasons(self, context: ProfileContext) -> list[str]:
        return ["generic triage applies to every artifact"]

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.append(
            self.recommendation(
                "file",
                (AnalysisMode.AUTO, AnalysisMode.DEEP),
                "confirm signature-derived type with libmagic output",
                100,
            )
        )

        metadata_types = {
            "image", "png", "jpeg", "jpg", "gif", "bmp", "tiff",
            "pdf", "office", "audio", "video",
        }
        if context.artifact_types & metadata_types or (context.artifact.mime or "").startswith(
            ("image/", "audio/", "video/")
        ):
            result.recommendations.append(
                self.recommendation(
                    "exiftool",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "classified artifact type commonly carries useful metadata",
                    80,
                )
            )

        embedded = context.truthy(
            "embedded.signature_found",
            "embedded.signatures_found",
            "embedded.pk_signature",
            "structure.embedded_data",
        )
        high_entropy = context.number(
            "entropy", "entropy.shannon", "artifact.entropy", "generic.entropy"
        )
        is_unknown = context.classified_as("unknown", "binary", "unknown_binary")
        if embedded or is_unknown or (high_entropy is not None and high_entropy >= 7.5):
            reasons: list[str] = []
            if embedded:
                reasons.append("embedded signature/data observation exists")
            if is_unknown:
                reasons.append("artifact remains an unknown binary")
            if high_entropy is not None and high_entropy >= 7.5:
                reasons.append(f"entropy is high ({high_entropy:.3g})")
            result.recommendations.append(
                self.recommendation(
                    "binwalk3",
                    (AnalysisMode.DEEP,),
                    "; ".join(reasons),
                    65,
                )
            )
            if embedded or is_unknown:
                result.recommendations.extend(
                    [
                        self.recommendation(
                            "foremost",
                            (AnalysisMode.DEEP,),
                            "deep carving is justified by embedded signatures or an unclassified binary",
                            45,
                        ),
                        self.recommendation(
                            "scalpel",
                            (AnalysisMode.DEEP,),
                            "deep signature carving provides an independent bounded recovery path",
                            40,
                        ),
                    ]
                )
        return result
