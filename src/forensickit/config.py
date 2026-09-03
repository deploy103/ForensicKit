from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AnalysisLimits:
    max_depth: int = 4
    max_artifact_count: int = 1_000
    max_extracted_bytes: int = 2 * 1024 * 1024 * 1024
    max_single_artifact_size: int = 512 * 1024 * 1024
    per_tool_timeout: int = 180
    jobs: int = 2
    max_strings: int = 2_000
    max_string_scan_bytes: int = 64 * 1024 * 1024
    signature_scan_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        positive = (
            "max_depth",
            "max_artifact_count",
            "max_extracted_bytes",
            "max_single_artifact_size",
            "per_tool_timeout",
            "jobs",
            "max_strings",
            "max_string_scan_bytes",
            "signature_scan_bytes",
        )
        for name in positive:
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(slots=True)
class ForensicKitConfig:
    limits: AnalysisLimits = field(default_factory=AnalysisLimits)
    recursive: bool = True
    extract: bool = True
    flag_patterns: list[str] = field(
        default_factory=lambda: [r"CTF\{[^\r\n\x00]{1,512}\}", r"FLAG\{[^\r\n\x00]{1,512}\}"]
    )
    tool_catalog: Path | None = None
    rules_path: Path | None = None
    tool_allowlist: list[str] = field(default_factory=list)
    category_filter: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["tool_catalog"] = str(self.tool_catalog) if self.tool_catalog else None
        result["rules_path"] = str(self.rules_path) if self.rules_path else None
        return result
