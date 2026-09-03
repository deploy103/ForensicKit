from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..models import Artifact, Finding, Observation
from .archive import ArchiveProfile
from .base import Profile, ProfileContext, ProfileResult, ToolRecommendation
from .disk import DiskProfile
from .document import OfficeProfile, PdfProfile, SqliteProfile
from .executable import ExecutableProfile
from .firmware import FirmwareProfile
from .generic import GenericProfile
from .image import ImageProfile, SteganographyProfile
from .memory import MemoryProfile
from .media import MediaProfile
from .mobile import MobileProfile
from .pcap import PcapProfile
from .windows import WindowsProfile


@dataclass(slots=True)
class ProfileEvaluationResult:
    profile_results: list[ProfileResult] = field(default_factory=list)
    recommendations: list[ToolRecommendation] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def profiles(self) -> list[str]:
        return [result.profile for result in self.profile_results if result.matched]

    @property
    def active_profiles(self) -> frozenset[str]:
        return frozenset(self.profiles)

    @property
    def reasons(self) -> dict[str, list[str]]:
        return {
            result.profile: list(result.reasons)
            for result in self.profile_results
            if result.matched
        }


def merge_recommendations(
    recommendations: Iterable[ToolRecommendation],
) -> list[ToolRecommendation]:
    """Deduplicate by canonical tool, union modes, retain all reasons and max priority."""

    grouped: dict[tuple[str, str, tuple[tuple[str, str], ...]], ToolRecommendation] = {}
    reason_lists: dict[tuple[str, str, tuple[tuple[str, str], ...]], list[str]] = {}
    for recommendation in recommendations:
        key = (
            recommendation.tool.lower(),
            recommendation.command_mode,
            tuple(sorted(recommendation.parameters.items())),
        )
        current = grouped.get(key)
        if current is None:
            grouped[key] = recommendation
            reason_lists[key] = [recommendation.reason]
            continue
        reasons = reason_lists[key]
        if recommendation.reason not in reasons:
            reasons.append(recommendation.reason)
        grouped[key] = ToolRecommendation(
            tool=current.tool,
            allowed_modes=current.allowed_modes | recommendation.allowed_modes,
            reason=" | ".join(reasons),
            priority=max(current.priority, recommendation.priority),
            command_mode=current.command_mode,
            parameters=current.parameters,
        )

    # Stable forensic plans: priority first, then canonical tool name.
    return sorted(
        grouped.values(),
        key=lambda item: (-item.priority, item.tool.lower(), item.command_mode, tuple(sorted(item.parameters.items()))),
    )


class ProfileEngine:
    """Pure profile dispatcher. It never probes or executes an external tool."""

    def __init__(self, profiles: Iterable[Profile] | None = None) -> None:
        defaults: tuple[Profile, ...] = (
            GenericProfile(),
            ImageProfile(),
            SteganographyProfile(),
            ArchiveProfile(),
            PcapProfile(),
            PdfProfile(),
            OfficeProfile(),
            SqliteProfile(),
            WindowsProfile(),
            MemoryProfile(),
            DiskProfile(),
            MobileProfile(),
            ExecutableProfile(),
            FirmwareProfile(),
            MediaProfile(),
        )
        selected = tuple(profiles) if profiles is not None else defaults
        names: set[str] = set()
        for profile in selected:
            if profile.name in names:
                raise ValueError(f"duplicate profile name: {profile.name}")
            names.add(profile.name)
        self.profiles = tuple(sorted(selected, key=lambda profile: (-profile.priority, profile.name)))

    def evaluate(
        self,
        artifact: Artifact,
        observations: Iterable[Observation] = (),
    ) -> ProfileEvaluationResult:
        context = ProfileContext(artifact, tuple(observations))
        result = ProfileEvaluationResult()
        recommendations: list[ToolRecommendation] = []
        for profile in self.profiles:
            try:
                profile_result = profile.evaluate(context)
            except Exception as exc:  # A faulty optional profile must not abort a case.
                result.errors.append(f"profile {profile.name}: {type(exc).__name__}: {exc}")
                continue
            if not profile_result.matched:
                continue
            result.profile_results.append(profile_result)
            result.observations.extend(profile_result.observations)
            result.findings.extend(profile_result.findings)
            recommendations.extend(profile_result.recommendations)
        result.recommendations = merge_recommendations(recommendations)
        return result


__all__ = [
    "ArchiveProfile",
    "BaseProfile",
    "DiskProfile",
    "OfficeProfile",
    "PdfProfile",
    "GenericProfile",
    "ExecutableProfile",
    "FirmwareProfile",
    "ImageProfile",
    "MemoryProfile",
    "MediaProfile",
    "MobileProfile",
    "PcapProfile",
    "Profile",
    "ProfileContext",
    "ProfileEngine",
    "ProfileEvaluationResult",
    "ProfileResult",
    "SteganographyProfile",
    "SqliteProfile",
    "ToolRecommendation",
    "WindowsProfile",
    "merge_recommendations",
]


# Re-exported here to keep the public profile API in one module.
from .base import BaseProfile  # noqa: E402  (intentional public re-export)
