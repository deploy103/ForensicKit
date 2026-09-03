from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


class MediaProfile(BaseProfile):
    """Metadata and container-consistency triage for audio/video evidence."""

    name = "media"
    priority = 660

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("audio", "video"):
            return ["audio/video signature classification is present"]
        if context.exists("media.format"):
            return ["media container header was parsed"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        result.recommendations.append(self.recommendation(
            "exiftool", (AnalysisMode.AUTO, AnalysisMode.DEEP),
            "media containers commonly contain title, encoder, timestamp, and geolocation metadata", 85,
        ))
        size_matches = next((value for value in context.values("media.wav.size_matches") if isinstance(value, bool)), None)
        if size_matches is False:
            result.findings.append(self.finding(
                context, title="WAV RIFF size does not match the evidence file", category="media_structure_anomaly",
                confidence=0.9,
                explanation="The RIFF header's declared file length differs from the observed size, suggesting trailing data or truncation.",
                evidence=["media.wav.size_matches=false"],
            ))
        wav_valid = next((value for value in context.values("media.wav.structure_valid") if isinstance(value, bool)), None)
        if wav_valid is False:
            result.findings.append(self.finding(
                context, title="WAV RIFF chunk layout is structurally inconsistent", category="media_structure_anomaly",
                confidence=0.9,
                explanation="A bounded WAV chunk or LIST/INFO tag exceeded declared RIFF container bounds.",
                evidence=["media.wav.structure_valid=false"],
            ))
        wav_info = next((value for value in context.values("media.wav.info_tags") if isinstance(value, dict)), None)
        if wav_info:
            result.findings.append(self.finding(
                context, title="WAV LIST/INFO metadata recovered", category="media_metadata",
                confidence=0.88,
                explanation="Bounded RIFF LIST/INFO parsing recovered creator-supplied WAV metadata without decoding audio frames.",
                evidence=[f"{key}={value}" for key, value in list(wav_info.items())[:30]], severity="info",
            ))
        isobmff_valid = next((value for value in context.values("media.isobmff.structure_valid") if isinstance(value, bool)), None)
        if isobmff_valid is False:
            result.findings.append(self.finding(
                context, title="ISO-BMFF atom layout is structurally inconsistent", category="media_structure_anomaly",
                confidence=0.9,
                explanation="A top-level ISO Base Media atom declared an invalid size or exceeded the available file bounds.",
                evidence=["media.isobmff.structure_valid=false"],
            ))
        movie_header = next((value for value in context.values("media.isobmff.movie_header") if isinstance(value, dict)), None)
        if movie_header and movie_header.get("valid"):
            duration = movie_header.get("duration_seconds")
            result.findings.append(self.finding(
                context, title="ISO-BMFF movie timing metadata recovered", category="media_metadata",
                confidence=0.9,
                explanation="The bounded `moov/mvhd` parser recovered container timing metadata without decoding media streams.",
                evidence=[f"duration_seconds={duration}", f"timescale={movie_header.get('timescale')}"], severity="info",
            ))
        matroska_valid = next((value for value in context.values("media.matroska.structure_valid") if isinstance(value, bool)), None)
        if matroska_valid is False:
            result.findings.append(self.finding(
                context, title="Matroska EBML layout is structurally inconsistent", category="media_structure_anomaly",
                confidence=0.9,
                explanation="A bounded EBML element size or header exceeded the supplied evidence; no codec payload was interpreted.",
                evidence=["media.matroska.structure_valid=false"],
            ))
        matroska_info = next((value for value in context.values("media.matroska.info") if isinstance(value, dict)), None)
        if matroska_info:
            evidence = [f"{key}={value}" for key, value in matroska_info.items() if key in {
                "title", "muxing_app", "writing_app", "duration_seconds", "timecode_scale"
            }]
            if evidence:
                result.findings.append(self.finding(
                    context, title="Matroska container metadata recovered", category="media_metadata",
                    confidence=0.88,
                    explanation="The bounded EBML Info parser recovered non-codec container metadata for review.",
                    evidence=evidence[:20], severity="info",
                ))
        avi_valid = next((value for value in context.values("media.avi.structure_valid") if isinstance(value, bool)), None)
        avi_size_matches = next((value for value in context.values("media.avi.size_matches") if isinstance(value, bool)), None)
        if avi_valid is False or avi_size_matches is False:
            evidence = []
            if avi_valid is False:
                evidence.append("media.avi.structure_valid=false")
            if avi_size_matches is False:
                evidence.append("media.avi.size_matches=false")
            result.findings.append(self.finding(
                context, title="AVI RIFF container size/layout is inconsistent", category="media_structure_anomaly",
                confidence=0.9,
                explanation="The AVI RIFF parser found a declared size mismatch or a chunk extending outside the valid container bounds.",
                evidence=evidence,
            ))
        avi_header = next((value for value in context.values("media.avi.main_header") if isinstance(value, dict)), None)
        if avi_header:
            result.findings.append(self.finding(
                context, title="AVI main header metadata recovered", category="media_metadata",
                confidence=0.9,
                explanation="The fixed AVIMAINHEADER was parsed without decoding video or audio data.",
                evidence=[f"{key}={value}" for key, value in avi_header.items()], severity="info",
            ))
        return result
