from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml


# Templates are argv arrays on purpose.  A formatted path always remains one argv
# element even when it contains spaces or shell metacharacters.
_COMMAND_TEMPLATES: dict[str, dict[str, tuple[str, ...]]] = {
    "file": {
        "default": ("{executable}", "--brief", "{evidence}"),
        "mime": ("{executable}", "--brief", "--mime-type", "{evidence}"),
    },
    "exiftool": {
        "default": ("{executable}", "-j", "-G1", "-a", "-s", "{evidence}"),
    },
    "binwalk3": {
        "default": ("{executable}", "{evidence}"),
        "deep": ("{executable}", "--extract", "--directory", "{output_dir}", "{evidence}"),
        "extract": ("{executable}", "--extract", "--directory", "{output_dir}", "{evidence}"),
    },
    "sevenzip": {
        "default": ("{executable}", "l", "-slt", "--", "{evidence}"),
        "extract": ("{executable}", "x", "-y", "-bd", "-o{output_dir}", "--", "{evidence}"),
        "deep": ("{executable}", "x", "-y", "-bd", "-o{output_dir}", "--", "{evidence}"),
    },
    "pngcheck": {
        "default": ("{executable}", "-vt", "{evidence}"),
    },
    "zsteg": {
        "default": ("{executable}", "{evidence}"),
        "deep": ("{executable}", "-a", "{evidence}"),
    },
    "steghide": {
        "default": ("{executable}", "info", "{evidence}", "-p", ""),
    },
    "stegseek": {
        "default": ("{executable}", "--seed", "{evidence}"),
    },
    "outguess": {
        "default": ("{executable}", "-r", "{evidence}", "{output_dir}/outguess.bin"),
    },
    "foremost": {
        "default": (
            "{executable}", "-i", "{evidence}", "-o", "{output_dir}/foremost",
        ),
        "extract": (
            "{executable}", "-i", "{evidence}", "-o", "{output_dir}/foremost",
        ),
    },
    "scalpel": {
        "default": ("{executable}", "{evidence}", "-o", "{output_dir}/scalpel"),
        "extract": ("{executable}", "{evidence}", "-o", "{output_dir}/scalpel"),
    },
    "bulk_extractor": {
        "default": ("{executable}", "-o", "{output_dir}/bulk_extractor", "{evidence}"),
        "extract": ("{executable}", "-o", "{output_dir}/bulk_extractor", "{evidence}"),
    },
    "tshark": {
        # Object export is part of the deterministic AUTO pipeline: every
        # exported object is bounded by the runner/ExtractionManager and is
        # recursively triaged as evidence.  Deep mode retains the same safe
        # export semantics while profiles may add further tools.
        "default": ("{executable}", "-n", "-r", "{evidence}", "--export-objects", "http,{output_dir}", "-q", "-z", "io,phs"),
        "deep": ("{executable}", "-n", "-r", "{evidence}", "--export-objects", "http,{output_dir}", "-q", "-z", "io,phs"),
    },
    "capinfos": {
        "default": ("{executable}", "-M", "{evidence}"),
    },
    "sleuthkit_mmls": {
        "default": ("{executable}", "{evidence}"),
    },
    "sleuthkit_fls": {
        "default": ("{executable}", "-r", "-p", "{evidence}"),
        "offset": ("{executable}", "-r", "-p", "-o", "{partition_offset}", "{evidence}"),
    },
    "sleuthkit_fsstat": {
        "default": ("{executable}", "{evidence}"),
        "offset": ("{executable}", "-o", "{partition_offset}", "{evidence}"),
    },
    "ewfinfo": {
        "default": ("{executable}", "{evidence}"),
    },
    "volatility3": {
        "default": ("{executable}", "-f", "{evidence}", "banners.Banners"),
        "deep": ("{executable}", "-f", "{evidence}", "banners.Banners"),
    },
    "volatility3_windows_pslist": {
        "default": ("{executable}", "-f", "{evidence}", "windows.pslist.PsList"),
    },
    "volatility3_windows_psscan": {
        "default": ("{executable}", "-f", "{evidence}", "windows.psscan.PsScan"),
    },
    "volatility3_windows_pstree": {
        "default": ("{executable}", "-f", "{evidence}", "windows.pstree.PsTree"),
    },
    "volatility3_windows_cmdline": {
        "default": ("{executable}", "-f", "{evidence}", "windows.cmdline.CmdLine"),
    },
    "volatility3_windows_netscan": {
        "default": ("{executable}", "-f", "{evidence}", "windows.netscan.NetScan"),
    },
    "volatility3_windows_handles": {
        "default": ("{executable}", "-f", "{evidence}", "windows.handles.Handles"),
    },
    "volatility3_windows_filescan": {
        "default": ("{executable}", "-f", "{evidence}", "windows.filescan.FileScan"),
    },
    "volatility3_windows_dlllist": {
        "default": ("{executable}", "-f", "{evidence}", "windows.dlllist.DllList"),
    },
    "volatility3_windows_malfind": {
        "default": ("{executable}", "-f", "{evidence}", "windows.malfind.Malfind"),
    },
    "volatility3_windows_dumpfiles": {
        "physaddr": ("{executable}", "-f", "{evidence}", "windows.dumpfiles.DumpFiles", "--physaddr", "{file_object_offset}"),
    },
    "volatility3_linux_pslist": {
        "default": ("{executable}", "-f", "{evidence}", "linux.pslist.PsList"),
    },
    "volatility3_linux_psaux": {
        "default": ("{executable}", "-f", "{evidence}", "linux.psaux.PsAux"),
    },
    "volatility3_linux_sockstat": {
        "default": ("{executable}", "-f", "{evidence}", "linux.sockstat.Sockstat"),
    },
    "pdfid": {
        "default": ("{executable}", "{evidence}"),
    },
    "pdfinfo": {
        "default": ("{executable}", "-meta", "{evidence}"),
    },
    "pdftotext": {
        "default": ("{executable}", "-enc", "UTF-8", "-nopgbrk", "{evidence}", "-"),
    },
    "qpdf": {
        "default": ("{executable}", "--check", "{evidence}"),
    },
    "pdfdetach": {
        # pdfdetach saves all attachments in its cwd; ToolRunner sets that to
        # the UUID-scoped generated output directory.
        "default": ("{executable}", "-saveall", "{evidence}"),
    },
    "pdfimages": {
        "default": ("{executable}", "-all", "{evidence}", "{output_dir}/image"),
    },
    "pdf_parser": {
        "default": ("{executable}", "--stats", "{evidence}"),
    },
    "olevba": {
        "default": ("{executable}", "--analysis", "{evidence}"),
    },
    "oledump": {
        "default": ("{executable}", "{evidence}"),
    },
    "regripper": {
        "default": ("{executable}", "-r", "{evidence}", "-a"),
    },
    "hayabusa": {
        "default": (
            "{executable}", "csv-timeline", "-f", "{evidence}", "-o",
            "{output_dir}/timeline.csv", "--no-wizard",
        ),
    },
    "chainsaw": {
        "default": ("{executable}", "dump", "{evidence}", "--json"),
    },
    "aleapp": {
        "default": ("{executable}", "-t", "fs", "-i", "{evidence}", "-o", "{output_dir}"),
        "zip": ("{executable}", "-t", "zip", "-i", "{evidence}", "-o", "{output_dir}"),
        "tar": ("{executable}", "-t", "tar", "-i", "{evidence}", "-o", "{output_dir}"),
        "gzip": ("{executable}", "-t", "gz", "-i", "{evidence}", "-o", "{output_dir}"),
    },
    "ileapp": {
        "default": ("{executable}", "-t", "fs", "-i", "{evidence}", "-o", "{output_dir}"),
        "zip": ("{executable}", "-t", "zip", "-i", "{evidence}", "-o", "{output_dir}"),
        "tar": ("{executable}", "-t", "tar", "-i", "{evidence}", "-o", "{output_dir}"),
        "gzip": ("{executable}", "-t", "gz", "-i", "{evidence}", "-o", "{output_dir}"),
    },
    "apktool": {
        "default": ("{executable}", "d", "-f", "-o", "{output_dir}/apktool", "{evidence}"),
        "deep": ("{executable}", "d", "-f", "-o", "{output_dir}/apktool", "{evidence}"),
    },
    "jadx": {
        "default": ("{executable}", "-d", "{output_dir}/jadx", "{evidence}"),
        "deep": ("{executable}", "-d", "{output_dir}/jadx", "{evidence}"),
    },
    "sqlite3": {
        "default": ("{executable}", "-readonly", "{evidence}", ".tables"),
        "schema": ("{executable}", "-readonly", "{evidence}", ".schema"),
    },
    "readelf": {
        "default": ("{executable}", "-W", "-h", "-l", "-d", "{evidence}"),
    },
}


_BUILTIN_METADATA: dict[str, dict[str, Any]] = {
    "file": {"executables": ["file"], "profiles": ["generic"], "parser": "file", "timeout": 15},
    "exiftool": {"executables": ["exiftool"], "profiles": ["generic", "image", "pdf", "office"], "parser": "exiftool", "timeout": 30},
    "binwalk3": {"executables": ["binwalk3", "binwalk"], "profiles": ["generic", "image", "firmware", "unknown"], "parser": "binwalk", "timeout": 120},
    "sevenzip": {"executables": ["7z", "7zz"], "profiles": ["archive", "generic"], "parser": "sevenzip", "timeout": 120},
    "pngcheck": {"executables": ["pngcheck"], "profiles": ["image", "steganography"], "parser": "pngcheck", "timeout": 30},
    "zsteg": {"executables": ["zsteg"], "profiles": ["image", "steganography"], "parser": "zsteg", "timeout": 120},
    "steghide": {"executables": ["steghide"], "profiles": ["steganography"], "timeout": 120},
    "stegseek": {"executables": ["stegseek"], "profiles": ["steganography"], "timeout": 300, "cost": "high"},
    "outguess": {"executables": ["outguess"], "profiles": ["steganography"], "timeout": 120},
    "foremost": {"executables": ["foremost"], "profiles": ["generic", "disk", "filesystem"], "timeout": 600, "cost": "high"},
    "scalpel": {"executables": ["scalpel"], "profiles": ["generic", "disk", "filesystem"], "timeout": 600, "cost": "high"},
    "bulk_extractor": {"executables": ["bulk_extractor"], "profiles": ["generic", "disk", "filesystem", "memory"], "timeout": 600, "cost": "high"},
    "tshark": {"executables": ["tshark"], "profiles": ["pcap"], "parser": "tshark", "timeout": 180},
    "capinfos": {"executables": ["capinfos"], "profiles": ["pcap"], "parser": "capinfos", "timeout": 30},
    "sleuthkit_mmls": {"executables": ["mmls"], "profiles": ["disk", "filesystem"], "timeout": 60, "parser": "sleuthkit_mmls"},
    "sleuthkit_fls": {"executables": ["fls"], "profiles": ["disk", "filesystem"], "timeout": 180, "parser": "sleuthkit_fls"},
    "sleuthkit_fsstat": {"executables": ["fsstat"], "profiles": ["disk", "filesystem"], "timeout": 90, "parser": "sleuthkit_fsstat"},
    "ewfinfo": {"executables": ["ewfinfo"], "profiles": ["disk"], "timeout": 60, "parser": "ewfinfo"},
    "volatility3": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_pslist": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_psscan": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_pstree": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_cmdline": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_netscan": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_handles": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_filescan": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_dlllist": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_malfind": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_windows_dumpfiles": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "generic", "generates_files": True},
    "volatility3_linux_pslist": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_linux_psaux": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "volatility3_linux_sockstat": {"executables": ["vol", "vol.py", "vol-offline"], "profiles": ["memory"], "timeout": 600, "cost": "high", "parser": "volatility3"},
    "pdfid": {"executables": ["pdfid.py", "pdfid"], "profiles": ["pdf"], "timeout": 30, "parser": "pdfid"},
    "pdfinfo": {"executables": ["pdfinfo"], "profiles": ["pdf"], "timeout": 30, "parser": "pdfinfo"},
    "pdftotext": {"executables": ["pdftotext"], "profiles": ["pdf"], "timeout": 60, "parser": "pdftotext"},
    "qpdf": {"executables": ["qpdf"], "profiles": ["pdf"], "timeout": 60, "parser": "qpdf"},
    "pdfdetach": {"executables": ["pdfdetach"], "profiles": ["pdf"], "timeout": 120, "parser": "generic"},
    "pdfimages": {"executables": ["pdfimages"], "profiles": ["pdf", "image", "steganography"], "timeout": 180, "cost": "medium", "parser": "generic"},
    "pdf_parser": {"executables": ["pdf-parser.py"], "profiles": ["pdf"], "timeout": 120, "parser": "pdf_parser"},
    "olevba": {"executables": ["olevba"], "profiles": ["office"], "timeout": 120, "parser": "olevba"},
    "oledump": {"executables": ["oledump.py"], "profiles": ["office"], "timeout": 120, "parser": "oledump"},
    "regripper": {"executables": ["regripper", "rip.pl"], "profiles": ["registry", "windows"], "timeout": 180, "parser": "regripper"},
    "hayabusa": {"executables": ["hayabusa"], "profiles": ["evtx", "windows"], "timeout": 600, "cost": "high"},
    "chainsaw": {"executables": ["chainsaw"], "profiles": ["evtx", "windows"], "timeout": 600, "cost": "high", "parser": "event_json"},
    "aleapp": {"executables": ["aleapp"], "profiles": ["android", "mobile"], "timeout": 900, "cost": "high", "parser": "leapp"},
    "ileapp": {"executables": ["ileapp"], "profiles": ["ios", "mobile"], "timeout": 900, "cost": "high", "parser": "leapp"},
    "apktool": {"executables": ["apktool"], "profiles": ["android", "mobile"], "accepts": ["apk"], "timeout": 300, "cost": "medium", "parser": "generic"},
    "jadx": {"executables": ["jadx"], "profiles": ["android", "mobile"], "accepts": ["apk"], "timeout": 600, "cost": "high", "parser": "generic"},
    "sqlite3": {"executables": ["sqlite3"], "profiles": ["sqlite", "mobile"], "timeout": 60, "parser": "sqlite3"},
    "readelf": {"executables": ["readelf"], "profiles": ["executable"], "accepts": ["elf"], "timeout": 60, "parser": "readelf"},
}


_VERSION_PROBES: dict[str, tuple[str, ...]] = {
    "exiftool": ("-ver",),
    "sevenzip": ("i",),
    "sleuthkit_mmls": ("-V",),
    "sleuthkit_fls": ("-V",),
    "sleuthkit_fsstat": ("-V",),
    "regripper": ("-h",),
    "aleapp": ("--version",),
    "ileapp": ("--version",),
    "foremost": ("-V",),
    "scalpel": ("-V",),
    "bulk_extractor": ("-V",),
}


_GENERATING_TOOLS = {
    "binwalk3", "sevenzip", "foremost", "scalpel", "bulk_extractor", "tshark", "outguess",
    "hayabusa", "aleapp", "ileapp", "apktool", "jadx", "pdfdetach", "pdfimages", "volatility3_windows_dumpfiles",
}


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Declarative description of one external forensic program."""

    name: str
    executable_candidates: tuple[str, ...]
    profiles: tuple[str, ...] = ()
    accepts: tuple[str, ...] = ()
    priority: str = "P1"
    cost: str = "medium"
    timeout: float = 60.0
    parser: str = "generic"
    command_templates: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    version_probe: tuple[str, ...] = ("--version",)
    generates_files: bool = False

    @property
    def canonical_name(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class ToolAvailability:
    name: str
    available: bool
    executable: str | None
    version: str | None = None
    error: str | None = None


class ToolRegistry:
    """Loads the YAML seed and resolves installed executables deterministically."""

    def __init__(self, definitions: Iterable[ToolDefinition]) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        for definition in definitions:
            if definition.name in self._definitions:
                raise ValueError(f"duplicate tool definition: {definition.name}")
            self._definitions[definition.name] = definition

        self._aliases: dict[str, str] = {}
        for definition in self._definitions.values():
            for candidate in definition.executable_candidates:
                alias = Path(candidate).name
                self._aliases.setdefault(alias, definition.name)
        # Friendly SleuthKit aliases differ from the seed's canonical names.
        self._aliases.update({"mmls": "sleuthkit_mmls", "fls": "sleuthkit_fls", "fsstat": "sleuthkit_fsstat"})

    @classmethod
    def default(cls, catalog_path: Path | None = None) -> "ToolRegistry":
        if catalog_path is None:
            project_catalog = Path(__file__).resolve().parents[3] / "config" / "tool-catalog.yaml"
            if project_catalog.is_file():
                catalog_path = project_catalog
        return cls.from_yaml(catalog_path) if catalog_path else cls(cls._builtin_definitions())

    @classmethod
    def from_yaml(cls, catalog_path: Path | None) -> "ToolRegistry":
        raw_tools: Mapping[str, Any] = {}
        if catalog_path is not None:
            path = Path(catalog_path).expanduser().resolve(strict=True)
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, Mapping) or not isinstance(loaded.get("tools", {}), Mapping):
                raise ValueError(f"invalid tool catalog: {path}")
            raw_tools = loaded.get("tools", {})

        definitions: list[ToolDefinition] = []
        all_names = list(raw_tools)
        all_names.extend(name for name in _BUILTIN_METADATA if name not in raw_tools)
        for name in all_names:
            seed = dict(_BUILTIN_METADATA.get(name, {}))
            configured = raw_tools.get(name, {})
            if not isinstance(configured, Mapping):
                raise ValueError(f"tool definition must be a mapping: {name}")
            seed.update(configured)
            definitions.append(cls._make_definition(str(name), seed))
        return cls(definitions)

    @classmethod
    def _builtin_definitions(cls) -> list[ToolDefinition]:
        return [cls._make_definition(name, values) for name, values in _BUILTIN_METADATA.items()]

    @staticmethod
    def _make_definition(name: str, values: Mapping[str, Any]) -> ToolDefinition:
        executables = values.get("executables", (name,))
        if not isinstance(executables, (list, tuple)) or not executables:
            raise ValueError(f"tool {name!r} needs executable candidates")

        configured_templates = values.get("command_templates", values.get("commands"))
        templates: dict[str, tuple[str, ...]] = dict(_COMMAND_TEMPLATES.get(name, {}))
        if configured_templates is not None:
            if isinstance(configured_templates, (list, tuple)):
                configured_templates = {"default": configured_templates}
            if not isinstance(configured_templates, Mapping):
                raise ValueError(f"tool {name!r} commands must be an argv list or mode mapping")
            for mode, argv_value in configured_templates.items():
                argv = argv_value.get("argv") if isinstance(argv_value, Mapping) else argv_value
                if not isinstance(argv, (list, tuple)) or not all(isinstance(token, str) for token in argv):
                    raise ValueError(f"tool {name!r} command {mode!r} must be an argv list")
                templates[str(mode)] = tuple(argv)
        configured_modes = values.get("modes")
        if configured_modes is not None:
            if not isinstance(configured_modes, Mapping):
                raise ValueError(f"tool {name!r} modes must be a mapping")
            for mode, mode_value in configured_modes.items():
                argv = mode_value.get("argv", mode_value.get("command")) if isinstance(mode_value, Mapping) else mode_value
                if argv is None:
                    continue
                if not isinstance(argv, (list, tuple)) or not all(isinstance(token, str) for token in argv):
                    raise ValueError(f"tool {name!r} mode {mode!r} must contain an argv list")
                templates[str(mode)] = tuple(argv)
        if "default" not in templates:
            templates["default"] = ("{executable}", "{evidence}")

        probe = values.get("version_probe", _VERSION_PROBES.get(name, ("--version",)))
        if isinstance(probe, str):
            probe = (probe,)
        if not isinstance(probe, (list, tuple)) or not all(isinstance(arg, str) for arg in probe):
            raise ValueError(f"tool {name!r} version_probe must be an argv list")

        timeout = float(values.get("timeout", 60))
        if timeout <= 0:
            raise ValueError(f"tool {name!r} timeout must be positive")
        return ToolDefinition(
            name=name,
            executable_candidates=tuple(str(item) for item in executables),
            profiles=tuple(str(item) for item in values.get("profiles", ())),
            accepts=tuple(str(item) for item in values.get("accepts", ())),
            priority=str(values.get("priority", "P1")),
            cost=str(values.get("cost", "medium")),
            timeout=timeout,
            parser=str(values.get("parser", "generic")),
            command_templates=templates,
            version_probe=tuple(probe),
            generates_files=bool(values.get("generates_files", name in _GENERATING_TOOLS)),
        )

    def names(self) -> list[str]:
        return list(self._definitions)

    def definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())

    def get(self, name: str) -> ToolDefinition:
        canonical = name if name in self._definitions else self._aliases.get(name)
        if canonical is None or canonical not in self._definitions:
            raise KeyError(f"unknown tool: {name}")
        return self._definitions[canonical]

    def resolve_executable(self, tool: str | ToolDefinition) -> str | None:
        definition = self.get(tool) if isinstance(tool, str) else tool
        for candidate in definition.executable_candidates:
            resolved = shutil.which(candidate)
            if resolved:
                return str(Path(resolved).resolve())
        return None

    def is_available(self, tool: str | ToolDefinition) -> bool:
        return self.resolve_executable(tool) is not None

    def detect(
        self,
        tool: str | ToolDefinition,
        *,
        probe_version: bool = False,
        timeout: float = 2.0,
    ) -> ToolAvailability:
        definition = self.get(tool) if isinstance(tool, str) else tool
        if probe_version:
            return self.probe_version(definition, timeout=timeout)
        executable = self.resolve_executable(definition)
        return ToolAvailability(definition.name, executable is not None, executable)

    def probe_version(
        self,
        tool: str | ToolDefinition,
        *,
        timeout: float = 2.0,
    ) -> ToolAvailability:
        definition = self.get(tool) if isinstance(tool, str) else tool
        executable = self.resolve_executable(definition)
        if executable is None:
            return ToolAvailability(definition.name, False, None, error="executable not found")
        try:
            completed = subprocess.run(
                [executable, *definition.version_probe],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                timeout=max(0.05, min(timeout, 5.0)),
                check=False,
            )
            output = completed.stdout[:16_384].decode("utf-8", errors="replace").strip()
            version = next((line.strip() for line in output.splitlines() if line.strip()), None)
            error = None if completed.returncode == 0 else f"version probe exited {completed.returncode}"
            return ToolAvailability(definition.name, True, executable, version, error)
        except subprocess.TimeoutExpired:
            return ToolAvailability(definition.name, True, executable, error="version probe timed out")
        except OSError as exc:
            return ToolAvailability(definition.name, False, executable, error=str(exc))

    def detect_all(self, *, probe_versions: bool = False) -> list[ToolAvailability]:
        results: list[ToolAvailability] = []
        for definition in self._definitions.values():
            if probe_versions:
                results.append(self.probe_version(definition))
            else:
                executable = self.resolve_executable(definition)
                results.append(ToolAvailability(definition.name, executable is not None, executable))
        return results

    def build_command(
        self,
        tool: str | ToolDefinition,
        evidence_path: Path,
        *,
        mode: str = "default",
        output_directory: Path | None = None,
        executable: str | None = None,
        extra_args: Iterable[str] = (),
        template_values: Mapping[str, str] | None = None,
    ) -> list[str]:
        definition = self.get(tool) if isinstance(tool, str) else tool
        resolved = executable or self.resolve_executable(definition)
        if resolved is None:
            raise FileNotFoundError(f"tool executable not found: {definition.name}")
        template = definition.command_templates.get(mode)
        if template is None:
            template = definition.command_templates.get("default")
        if template is None:
            raise ValueError(f"tool has no command template: {definition.name}")

        evidence = str(Path(evidence_path).resolve(strict=True))
        output_dir = str(Path(output_directory).resolve()) if output_directory is not None else ""
        if any("{output_dir}" in token for token in template) and not output_dir:
            raise ValueError(f"command mode {mode!r} requires an output directory")
        fields = {"executable": str(Path(resolved).resolve()), "evidence": evidence, "output_dir": output_dir}
        if template_values:
            for key, value in template_values.items():
                if not key.replace("_", "").isalnum() or "\x00" in str(value):
                    raise ValueError("command template values must use identifier keys and NUL-free values")
                if key in fields:
                    raise ValueError(f"command template value may not override reserved field: {key}")
                fields[key] = str(value)
        try:
            argv = [token.format_map(fields) for token in template]
        except KeyError as exc:
            raise ValueError(f"unknown command placeholder for {definition.name}: {exc}") from exc
        argv.extend(str(arg) for arg in extra_args)
        if any("\x00" in arg for arg in argv):
            raise ValueError("command arguments may not contain NUL bytes")
        return argv


__all__ = ["ToolAvailability", "ToolDefinition", "ToolRegistry"]
