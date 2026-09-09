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
    memory_jobs: int = 1
    tool_max_memory_bytes: int = 6 * 1024 * 1024 * 1024
    tool_max_output_file_bytes: int = 2 * 1024 * 1024 * 1024
    tool_max_generated_files: int = 1_000
    tool_max_generated_bytes: int = 2 * 1024 * 1024 * 1024
    planner_cpu_units: int = 2
    planner_max_ram_bytes: int = 6 * 1024 * 1024 * 1024
    max_strings: int = 2_000
    max_string_scan_bytes: int = 64 * 1024 * 1024
    signature_scan_bytes: int = 128 * 1024 * 1024
    flag_max_scan_bytes: int = 2 * 1024 * 1024 * 1024
    flag_scan_chunk_bytes: int = 1024 * 1024
    flag_max_match_length: int = 4_096
    flag_decode_depth: int = 3
    flag_max_decode_artifacts: int = 2_000
    flag_max_decoded_bytes: int = 64 * 1024 * 1024
    flag_scan_timeout: float = 20.0
    regex_match_timeout: float = 0.1

    def __post_init__(self) -> None:
        positive = (
            "max_depth",
            "max_artifact_count",
            "max_extracted_bytes",
            "max_single_artifact_size",
            "per_tool_timeout",
            "jobs",
            "memory_jobs",
            "tool_max_memory_bytes",
            "tool_max_output_file_bytes",
            "tool_max_generated_files",
            "tool_max_generated_bytes",
            "planner_cpu_units",
            "planner_max_ram_bytes",
            "max_strings",
            "max_string_scan_bytes",
            "signature_scan_bytes",
            "flag_max_scan_bytes",
            "flag_scan_chunk_bytes",
            "flag_max_match_length",
            "flag_decode_depth",
            "flag_max_decode_artifacts",
            "flag_max_decoded_bytes",
            "flag_scan_timeout",
            "regex_match_timeout",
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
        default_factory=lambda: [
            r"CTF\{[^{}\r\n\x00]{1,512}\}",
            r"FLAG\{[^{}\r\n\x00]{1,512}\}",
        ]
    )
    flag_prefixes: list[str] = field(default_factory=list)
    exact_strings: list[str] = field(default_factory=list)
    regex_patterns: list[str] = field(default_factory=list)
    search_terms: list[str] = field(default_factory=list)
    memory_pids: list[int] = field(default_factory=list)
    tool_catalog: Path | None = None
    rules_path: Path | None = None
    tool_allowlist: list[str] = field(default_factory=list)
    category_filter: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["tool_catalog"] = str(self.tool_catalog) if self.tool_catalog else None
        result["rules_path"] = str(self.rules_path) if self.rules_path else None
        return result
