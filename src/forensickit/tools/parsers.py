from __future__ import annotations

import json
import re
import csv
import io
from dataclasses import dataclass, field
from typing import Callable

from ..models import Finding, Observation


@dataclass(slots=True)
class ParsedToolOutput:
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


ParserFunction = Callable[[str, str, str, int | None, str], ParsedToolOutput]


def _observation(
    artifact_id: str,
    key: str,
    value: object,
    source: str,
    confidence: float = 1.0,
) -> Observation:
    return Observation(
        artifact_id=artifact_id,
        key=key,
        value=value,
        source=source,
        confidence=confidence,
    )


def _finding(
    artifact_id: str,
    *,
    title: str,
    category: str,
    explanation: str,
    source: str,
    confidence: float,
    severity: str = "medium",
    evidence: list[str] | None = None,
) -> Finding:
    return Finding(
        artifact_id=artifact_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        explanation=explanation,
        source=source,
        supporting_evidence=evidence or [],
    )


def _nonempty_lines(text: str, *, maximum: int = 250) -> list[str]:
    return [line.strip()[:2_000] for line in text.splitlines() if line.strip()][:maximum]


def parse_generic(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    observations = [_observation(artifact_id, f"tool.{tool}.exit_code", exit_code, source)]
    lines = _nonempty_lines(stdout, maximum=40)
    if lines:
        observations.append(
            _observation(
                artifact_id,
                f"tool.{tool}.summary",
                lines,
                source,
                0.8,
            )
        )
    error_lines = _nonempty_lines(stderr, maximum=20)
    if error_lines:
        observations.append(
            _observation(artifact_id, f"tool.{tool}.stderr_summary", error_lines, source, 0.8)
        )
    return ParsedToolOutput(observations=observations)


def parse_file(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    description = next((line.strip() for line in stdout.splitlines() if line.strip()), "")
    # `file path` output may contain a prefix; --brief normally does not.
    if ": " in description and not description.lower().startswith(("http:", "https:")):
        description = description.split(": ", 1)[1]
    observations: list[Observation] = []
    if description:
        observations.append(_observation(artifact_id, "file.description", description[:4_096], source))
        if re.fullmatch(r"[-+.\w]+/[-+.\w]+(?:;.*)?", description):
            observations.append(
                _observation(artifact_id, "file.mime_type", description.split(";", 1)[0], source)
            )
    if stderr.strip():
        observations.append(
            _observation(artifact_id, "file.warning", _nonempty_lines(stderr, maximum=10), source, 0.8)
        )
    return ParsedToolOutput(observations=observations)


def _extract_json_document(text: str) -> object:
    decoder = json.JSONDecoder()
    starts = [index for index in (text.find("["), text.find("{")) if index >= 0]
    if not starts:
        raise ValueError("no JSON document in output")
    value, _ = decoder.raw_decode(text[min(starts):])
    return value


def parse_exiftool(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    value = _extract_json_document(stdout)
    if isinstance(value, list):
        metadata = value[0] if value else {}
    else:
        metadata = value
    if not isinstance(metadata, dict):
        raise ValueError("ExifTool JSON root is not an object")
    # Bound database/report growth while preserving all common scalar metadata.
    normalized = {
        str(key)[:200]: item if isinstance(item, (str, int, float, bool, type(None))) else str(item)[:2_000]
        for key, item in list(metadata.items())[:300]
    }
    observations = [_observation(artifact_id, "metadata.exiftool", normalized, source)]
    suffixes = {
        "FileType": "exiftool.file_type",
        "MIMEType": "exiftool.mime_type",
        "ImageWidth": "image.width",
        "ImageHeight": "image.height",
    }
    for suffix, key in suffixes.items():
        match = next((item for name, item in normalized.items() if name.split("]")[-1] == suffix), None)
        if match is not None:
            observations.append(_observation(artifact_id, key, match, source))

    warnings = [
        f"{key}: {item}" for key, item in normalized.items()
        if key.split("]")[-1].lower() in {"warning", "error"}
    ]
    findings: list[Finding] = []
    if warnings:
        observations.append(_observation(artifact_id, "exiftool.warnings", warnings, source, 0.9))
        findings.append(
            _finding(
                artifact_id,
                title="Metadata parser reported a structural warning",
                category="metadata_anomaly",
                explanation="ExifTool reported one or more warnings while parsing the artifact.",
                source=source,
                confidence=0.75,
                severity="low",
                evidence=warnings[:10],
            )
        )
    return ParsedToolOutput(observations, findings)


_BINWALK_ROW = re.compile(
    r"^\s*(?P<decimal>\d+)\s+(?P<hex>0x[0-9a-fA-F]+)\s+(?P<description>.+?)\s*$"
)


def parse_binwalk(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    signatures: list[dict[str, object]] = []
    for line in stdout.splitlines():
        match = _BINWALK_ROW.match(line)
        if not match:
            continue
        signatures.append(
            {
                "offset": int(match.group("decimal")),
                "hex_offset": match.group("hex").lower(),
                "description": match.group("description")[:2_000],
            }
        )
        if len(signatures) >= 500:
            break
    observations = [
        _observation(artifact_id, "binwalk.signature_count", len(signatures), source),
        _observation(artifact_id, "binwalk.signatures", signatures, source),
    ]
    embedded = [entry for entry in signatures if int(entry["offset"]) > 0]
    findings: list[Finding] = []
    if embedded:
        examples = [
            f"{entry['hex_offset']}: {entry['description']}" for entry in embedded[:10]
        ]
        findings.append(
            _finding(
                artifact_id,
                title=f"Binwalk found {len(embedded)} embedded signature(s)",
                category="embedded_data",
                explanation="Recognized data signatures occur after the start of the artifact.",
                source=source,
                confidence=0.85,
                evidence=examples,
            )
        )
    return ParsedToolOutput(observations, findings)


def parse_sevenzip(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    after_separator = False
    archive_properties: dict[str, str] = {}
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("----------"):
            if current:
                archive_properties.update(current)
                current = {}
            after_separator = True
            continue
        if not line:
            if current:
                if after_separator:
                    records.append(current)
                else:
                    archive_properties.update(current)
                current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value[:4_096]
    if current:
        if after_separator:
            records.append(current)
        else:
            archive_properties.update(current)

    entries = [
        {
            "path": record.get("Path", "")[:1_000],
            "size": int(record["Size"]) if record.get("Size", "").isdigit() else None,
            "packed_size": int(record["Packed Size"]) if record.get("Packed Size", "").isdigit() else None,
            "encrypted": record.get("Encrypted") == "+",
            "folder": record.get("Folder") == "+",
        }
        for record in records[:1_000]
        if record.get("Path")
    ]
    encrypted = any(bool(entry["encrypted"]) for entry in entries) or archive_properties.get("Encrypted") == "+"
    observations = [
        _observation(artifact_id, "archive.entry_count", len(entries), source),
        _observation(artifact_id, "archive.entries", entries, source),
        _observation(artifact_id, "archive.encrypted", encrypted, source),
    ]
    if "Type" in archive_properties:
        observations.append(_observation(artifact_id, "archive.type", archive_properties["Type"], source))
    findings: list[Finding] = []
    if encrypted:
        findings.append(
            _finding(
                artifact_id,
                title="Archive contains encrypted content",
                category="encrypted_archive",
                explanation="7-Zip marked the archive or at least one member as encrypted.",
                source=source,
                confidence=0.98,
                evidence=[str(entry["path"]) for entry in entries if entry["encrypted"]][:20],
            )
        )
    return ParsedToolOutput(observations, findings)


def parse_pngcheck(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    combined = "\n".join((stdout, stderr))
    chunks: list[dict[str, object]] = []
    chunk_re = re.compile(r"\bchunk\s+([A-Za-z0-9]{4})\s+at offset\s+(0x[0-9a-fA-F]+)", re.I)
    for match in chunk_re.finditer(combined):
        chunks.append({"type": match.group(1), "offset": int(match.group(2), 16)})
    problem_lines = [
        line.strip()[:2_000] for line in combined.splitlines()
        if re.search(r"\b(?:error|warning|invalid|corrupt|additional data)\b", line, re.I)
    ][:100]
    valid = exit_code == 0 and not problem_lines
    observations = [
        _observation(artifact_id, "pngcheck.valid", valid, source),
        _observation(artifact_id, "pngcheck.chunks", chunks[:500], source),
    ]
    if problem_lines:
        observations.append(_observation(artifact_id, "pngcheck.problems", problem_lines, source))
    findings: list[Finding] = []
    if problem_lines:
        appended = [line for line in problem_lines if re.search(r"additional data|after IEND", line, re.I)]
        findings.append(
            _finding(
                artifact_id,
                title="PNG structural anomaly reported",
                category="appended_data" if appended else "structural_anomaly",
                explanation="pngcheck reported structural warnings or errors.",
                source=source,
                confidence=0.9,
                evidence=problem_lines[:20],
            )
        )
    return ParsedToolOutput(observations, findings)


def parse_zsteg(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    results: list[dict[str, str]] = []
    for line in stdout.splitlines():
        if ".." not in line:
            continue
        channel, value = line.split("..", 1)
        value = value.strip()
        if not value or value.lower() in {"nothing", "none"}:
            continue
        results.append({"channel": channel.strip()[:200], "result": value[:2_000]})
        if len(results) >= 500:
            break
    observations = [
        _observation(artifact_id, "zsteg.result_count", len(results), source),
        _observation(artifact_id, "zsteg.results", results, source),
    ]
    interesting = [
        result for result in results
        if re.search(r"\b(?:text|file|flag|ctf|archive|executable|compressed)\b", result["result"], re.I)
    ]
    findings: list[Finding] = []
    if interesting:
        findings.append(
            _finding(
                artifact_id,
                title="Potential steganographic payload detected",
                category="steganography",
                explanation="zsteg reported one or more channels containing recognizable text or data.",
                source=source,
                confidence=0.75,
                evidence=[f"{item['channel']}: {item['result']}" for item in interesting[:20]],
            )
        )
    return ParsedToolOutput(observations, findings)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def parse_capinfos(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    properties: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized = _normalized_key(key)
        if normalized:
            properties[normalized] = value.strip()[:4_096]
    observations = [_observation(artifact_id, "pcap.capinfos", properties, source)]
    special = {
        "file_type": "pcap.file_type",
        "number_of_packets": "pcap.packet_count",
        "capture_duration": "pcap.capture_duration",
        "first_packet_time": "pcap.first_packet_time",
        "last_packet_time": "pcap.last_packet_time",
        "sha256": "pcap.sha256",
    }
    for input_key, output_key in special.items():
        value = properties.get(input_key)
        if value is None:
            continue
        normalized_value: object = value
        if input_key == "number_of_packets":
            match = re.search(r"\d+", value.replace(",", ""))
            normalized_value = int(match.group()) if match else value
        observations.append(_observation(artifact_id, output_key, normalized_value, source))
    return ParsedToolOutput(observations=observations)


_TSHARK_PROTOCOL = re.compile(
    r"^(?P<indent>\s*)(?P<protocol>[A-Za-z0-9_.-]+)\s+frames:(?P<frames>\d+)\s+bytes:(?P<bytes>\d+)",
    re.I,
)


def parse_tshark(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    protocols: list[dict[str, object]] = []
    for line in stdout.splitlines():
        match = _TSHARK_PROTOCOL.match(line)
        if not match:
            continue
        protocols.append(
            {
                "protocol": match.group("protocol").lower(),
                "frames": int(match.group("frames")),
                "bytes": int(match.group("bytes")),
                "depth": len(match.group("indent")) // 2,
            }
        )
        if len(protocols) >= 500:
            break
    observations = [
        _observation(artifact_id, "pcap.protocol_hierarchy", protocols, source),
        _observation(artifact_id, "pcap.protocols", sorted({str(item["protocol"]) for item in protocols}), source),
    ]
    malformed = [line.strip()[:2_000] for line in stderr.splitlines() if "malformed" in line.lower()][:50]
    findings: list[Finding] = []
    if malformed:
        observations.append(_observation(artifact_id, "pcap.malformed_packets", malformed, source, 0.8))
        findings.append(
            _finding(
                artifact_id,
                title="Malformed packet data reported",
                category="pcap_anomaly",
                explanation="tshark reported malformed packet data while dissecting the capture.",
                source=source,
                confidence=0.7,
                severity="low",
                evidence=malformed,
            )
        )
    return ParsedToolOutput(observations, findings)


def parse_sqlite3(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    # The safe default command is `.tables`; its whitespace-delimited output
    # is intentionally normalized without interpreting user SQL.
    tables = [token for token in re.split(r"\s+", stdout.strip()) if token]
    observations = [
        _observation(artifact_id, "sqlite.table_count", len(tables), source),
        _observation(artifact_id, "sqlite.tables", tables[:2_000], source),
    ]
    if stderr.strip():
        observations.append(_observation(artifact_id, "sqlite.warnings", _nonempty_lines(stderr), source, 0.8))
    return ParsedToolOutput(observations=observations)


def parse_pdfid(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    indicators: dict[str, int] = {}
    for line in stdout.splitlines():
        match = re.match(r"\s*(/[A-Za-z][A-Za-z0-9]*)\s+(\d+)", line)
        if match:
            indicators[match.group(1)] = int(match.group(2))
    observations = [_observation(artifact_id, "pdf.indicators", indicators, source)]
    active = {name: count for name, count in indicators.items() if name in {"/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch"} and count > 0}
    findings: list[Finding] = []
    if active:
        observations.append(_observation(artifact_id, "pdf.active_content", active, source, 0.95))
        findings.append(
            _finding(
                artifact_id,
                title="PDF active-content indicator detected",
                category="pdf_active_content",
                explanation="pdfid reported JavaScript, automatic action, or launch indicators requiring object-level inspection.",
                source=source,
                confidence=0.9,
                severity="medium",
                evidence=[f"{name}={count}" for name, count in active.items()],
            )
        )
    return ParsedToolOutput(observations, findings)


def parse_pdfinfo(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize Poppler's stable ``Key: Value`` document metadata output."""
    source = f"tool:{tool}"
    metadata: dict[str, str] = {}
    for line in stdout.splitlines()[:500]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            metadata[key[:200]] = value[:4_000]
    encrypted = next(
        (value.strip().lower() in {"yes", "true"} for key, value in metadata.items() if key.lower() == "encrypted"),
        False,
    )
    observations = [
        _observation(artifact_id, "pdf.info", metadata, source),
        _observation(artifact_id, "pdf.encrypted", encrypted, source),
    ]
    findings: list[Finding] = []
    if encrypted:
        findings.append(_finding(
            artifact_id, title="PDF is encrypted", category="pdf_encryption",
            explanation="pdfinfo reports that the document is encrypted; no password guessing is attempted automatically.",
            source=source, confidence=0.98, severity="info",
            evidence=[f"Encrypted={metadata.get('Encrypted', 'yes')}"],
        ))
    return ParsedToolOutput(observations, findings)


def parse_pdftotext(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Keep a bounded text lead while raw Poppler output stays in workspace logs."""
    source = f"tool:{tool}"
    text = stdout.replace("\x00", "")
    lines = _nonempty_lines(text, maximum=200)
    flag_like = re.findall(r"(?:CTF|FLAG)\{[^\r\n\x00]{1,512}\}", text, re.I)[:100]
    observations = [
        _observation(artifact_id, "pdf.text.character_count", len(text), source),
        _observation(artifact_id, "pdf.text.samples", lines, source, 0.9),
        _observation(artifact_id, "pdf.text.flag_like", flag_like, source, 0.95),
    ]
    findings: list[Finding] = []
    if flag_like:
        findings.append(_finding(
            artifact_id, title="PDF text extraction contains flag-like candidate", category="flag_candidate",
            explanation="pdftotext recovered a CTF/FLAG-shaped string. It is preserved as a finding and should be validated against the original document evidence chain.",
            source=source, confidence=0.9, severity="info", evidence=flag_like[:20],
        ))
    return ParsedToolOutput(observations, findings)


def parse_qpdf(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Classify qpdf --check diagnostics while preserving complete raw logs."""
    source = f"tool:{tool}"
    combined = "\n".join(part for part in (stdout, stderr) if part)
    lines = _nonempty_lines(combined, maximum=100)
    lowered = combined.casefold()
    has_error = exit_code not in {0, None} or bool(re.search(r"\b(?:error|damaged|invalid)\b", lowered))
    has_warning = not has_error and bool(re.search(r"\bwarning\b", lowered))
    status = "error" if has_error else "warning" if has_warning else "valid"
    observations = [
        _observation(artifact_id, "pdf.qpdf.check_status", status, source, 0.95),
        _observation(artifact_id, "pdf.qpdf.messages", lines, source, 0.85),
    ]
    findings: list[Finding] = []
    if status == "error":
        findings.append(_finding(
            artifact_id, title="qpdf reported PDF structural errors", category="pdf_structure_anomaly",
            explanation="qpdf --check found invalid or damaged PDF structure. Preserve its raw diagnostics and use object-level inspection before trusting extraction results.",
            source=source, confidence=0.92, evidence=lines[:30],
        ))
    elif status == "warning":
        findings.append(_finding(
            artifact_id, title="qpdf reported PDF structural warnings", category="pdf_structure_warning",
            explanation="qpdf --check completed with warnings; this is a triage lead that can explain parser discrepancies without proving tampering.",
            source=source, confidence=0.8, severity="low", evidence=lines[:30],
        ))
    return ParsedToolOutput(observations, findings)


def parse_pdf_parser(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize pdf-parser --stats/object listings without trusting PDF syntax."""
    source = f"tool:{tool}"
    objects = re.findall(r"(?m)^\s*obj\s+(\d+)\s+(\d+)\b", stdout)
    indicators = {
        name: len(re.findall(pattern, stdout, re.I))
        for name, pattern in {
            "javascript": r"/(?:JavaScript|JS)\b",
            "open_action": r"/(?:OpenAction|AA)\b",
            "launch": r"/Launch\b",
            "embedded_file": r"/(?:EmbeddedFile|Filespec)\b",
            "stream": r"\bstream\b",
        }.items()
    }
    observations = [
        _observation(artifact_id, "pdf.parser.object_count", len(objects), source),
        _observation(artifact_id, "pdf.parser.object_ids", [f"{number} {generation}" for number, generation in objects[:2_000]], source),
        _observation(artifact_id, "pdf.parser.indicators", indicators, source),
    ]
    active = {name: count for name, count in indicators.items() if name in {"javascript", "open_action", "launch"} and count}
    findings: list[Finding] = []
    if active:
        findings.append(_finding(
            artifact_id, title="pdf-parser reported active PDF objects", category="pdf_active_content",
            explanation="Object-level PDF parser output contains JavaScript, action, or launch indicators.",
            source=source, confidence=0.92, severity="medium",
            evidence=[f"{name}={count}" for name, count in active.items()],
        ))
    if indicators["embedded_file"]:
        findings.append(_finding(
            artifact_id, title="pdf-parser reported embedded-file objects", category="pdf_embedded_file",
            explanation="PDF object listing contains EmbeddedFile or Filespec markers; recovered streams should be recursively analyzed.",
            source=source, confidence=0.88, severity="medium",
            evidence=[f"embedded_file={indicators['embedded_file']}"],
        ))
    return ParsedToolOutput(observations, findings)


def parse_oledump(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Extract stream inventory and macro flags from oledump's text table."""
    source = f"tool:{tool}"
    streams: list[dict[str, str]] = []
    macro_streams: list[str] = []
    for line in stdout.splitlines():
        match = re.match(r"^\s*(\d+(?:/[A-Za-z0-9]+)?)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        index, remainder = match.groups()
        flag_match = re.match(r"^([A-Z!]{1,8})(?:\s{2,}|$)(.*)$", remainder)
        flags, description = flag_match.groups() if flag_match else ("", remainder)
        record = {"index": index, "flags": flags.strip(), "description": description[:2_000]}
        streams.append(record)
        if "M" in flags or re.search(r"\b(?:vba|macro)\b", description, re.I):
            macro_streams.append(f"{index}: {description[:1_000]}")
        if len(streams) >= 2_000:
            break
    observations = [
        _observation(artifact_id, "office.oledump.stream_count", len(streams), source),
        _observation(artifact_id, "office.oledump.streams", streams, source),
        _observation(artifact_id, "office.oledump.macro_streams", macro_streams[:200], source, 0.9),
    ]
    findings: list[Finding] = []
    if macro_streams:
        findings.append(_finding(
            artifact_id, title="oledump identified macro-capable streams", category="office_macro",
            explanation="oledump stream flags or names indicate VBA/macro content.", source=source,
            confidence=0.9, severity="medium", evidence=macro_streams[:50],
        ))
    return ParsedToolOutput(observations, findings)


def parse_regripper(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Preserve RegRipper key/timestamp leads in a compact normalized form."""
    source = f"tool:{tool}"
    lines = _nonempty_lines(stdout, maximum=2_000)
    timestamps = [
        line for line in lines
        if re.search(r"(?:lastwrite|last write|\bmtime\b|\bmodified\b)", line, re.I)
    ][:300]
    keys = [
        line for line in lines
        if re.search(r"(?:^key\b|\\(?:software|system|sam|ntuser|run(?:once)?)(?:\\|$))", line, re.I)
    ][:500]
    suspicious = [
        line for line in lines
        if re.search(r"(?:\\run(?:once)?\\|powershell|wscript|cscript|rundll32|mshta|encodedcommand)", line, re.I)
    ][:200]
    observations = [
        _observation(artifact_id, "registry.regripper.key_lines", keys, source, 0.85),
        _observation(artifact_id, "registry.regripper.timestamp_lines", timestamps, source, 0.85),
        _observation(artifact_id, "registry.regripper.suspicious_lines", suspicious, source, 0.9),
    ]
    findings: list[Finding] = []
    if suspicious:
        findings.append(_finding(
            artifact_id, title="RegRipper reported execution-relevant Registry values", category="registry_execution_lead",
            explanation="Registry output contains common autorun or script-execution indicators; retain the raw tool log for exact key/value context.",
            source=source, confidence=0.83, severity="medium", evidence=suspicious[:50],
        ))
    return ParsedToolOutput(observations, findings)


_WINDOWS_EVENT_CATEGORIES = {
    "104": "log_cleared",
    "1102": "log_cleared",
    "1149": "rdp_authentication",
    "4103": "powershell",
    "4104": "powershell",
    "4624": "logon_success",
    "4625": "logon_failure",
    "4648": "explicit_credentials",
    "4672": "privileged_logon",
    "4688": "process_creation",
    "4689": "process_exit",
    "4697": "service_install",
    "4698": "scheduled_task_change",
    "4699": "scheduled_task_change",
    "4700": "scheduled_task_change",
    "4701": "scheduled_task_change",
    "4702": "scheduled_task_change",
    "4720": "account_change",
    "4722": "account_change",
    "4725": "account_change",
    "4726": "account_change",
    "4728": "group_membership_change",
    "4732": "group_membership_change",
    "4756": "group_membership_change",
    "5001": "defender_change",
    "5007": "defender_change",
    "7045": "service_install",
}


def _event_json_records(text: str, *, maximum: int = 5_000) -> list[dict[str, object]]:
    """Accept a JSON document or JSONL without silently dropping later rows."""
    stripped = text.lstrip("\ufeff \t\r\n")
    if not stripped:
        return []
    candidates: list[object] = []
    try:
        document = json.loads(stripped)
    except json.JSONDecodeError:
        for line in stripped.splitlines()[: maximum * 2]:
            try:
                candidates.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(candidates) >= maximum:
                break
    else:
        if isinstance(document, list):
            candidates.extend(document[:maximum])
        elif isinstance(document, dict):
            nested = next(
                (
                    value for key, value in document.items()
                    if str(key).casefold() in {"events", "records", "results"}
                    and isinstance(value, list)
                ),
                None,
            )
            candidates.extend(nested[:maximum] if isinstance(nested, list) else [document])
    return [item for item in candidates[:maximum] if isinstance(item, dict)]


def _flatten_event_scalars(
    value: object,
    *,
    prefix: str = "",
    output: dict[str, object] | None = None,
    depth: int = 0,
    maximum: int = 300,
) -> dict[str, object]:
    """Flatten only bounded scalar event fields; never retain arbitrary objects."""
    if output is None:
        output = {}
    if len(output) >= maximum or depth > 7:
        return output
    if isinstance(value, dict):
        for key, item in list(value.items())[:100]:
            child = f"{prefix}.{str(key)[:160]}" if prefix else str(key)[:160]
            _flatten_event_scalars(
                item, prefix=child, output=output, depth=depth + 1, maximum=maximum,
            )
            if len(output) >= maximum:
                break
    elif isinstance(value, list):
        for index, item in enumerate(value[:100]):
            _flatten_event_scalars(
                item, prefix=f"{prefix}[{index}]", output=output,
                depth=depth + 1, maximum=maximum,
            )
            if len(output) >= maximum:
                break
    elif prefix and isinstance(value, (str, int, float, bool, type(None))):
        output[prefix[:500]] = value[:2_000] if isinstance(value, str) else value
    return output


def _event_named_values(value: object) -> dict[str, object]:
    """Recover common EVTX EventData Name/Value pairs from varying JSON schemas."""
    output: dict[str, object] = {}
    remaining = 200

    def visit(item: object, depth: int) -> None:
        nonlocal remaining
        if remaining <= 0 or depth > 7:
            return
        if isinstance(item, dict):
            keys = {
                re.sub(r"[^a-z0-9]", "", str(key).casefold()): value
                for key, value in list(item.items())[:100]
            }
            name = keys.get("name")
            field_value = next(
                (keys[key] for key in ("value", "text", "content") if key in keys),
                None,
            )
            if isinstance(name, (str, int)) and isinstance(
                field_value, (str, int, float, bool, type(None)),
            ):
                normalized_name = re.sub(r"[^a-z0-9]", "", str(name).casefold())
                if normalized_name and normalized_name not in output:
                    output[normalized_name] = (
                        field_value[:2_000] if isinstance(field_value, str) else field_value
                    )
                    remaining -= 1
            for key, child in list(item.items())[:100]:
                normalized_key = re.sub(r"[^a-z0-9]", "", str(key).casefold())
                if (
                    depth >= 2
                    and normalized_key not in {"name", "value", "text", "content"}
                    and isinstance(child, (str, int, float, bool, type(None)))
                    and normalized_key not in output
                ):
                    output[normalized_key] = child[:2_000] if isinstance(child, str) else child
                    remaining -= 1
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item[:100]:
                visit(child, depth + 1)

    visit(value, 0)
    return output


def _canonical_event_path(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _pick_event_value(flattened: dict[str, object], *aliases: str) -> object | None:
    canonical_aliases = tuple(
        tuple(_canonical_event_path(part) for part in alias.split("."))
        for alias in aliases
    )
    for alias in canonical_aliases:
        for path, value in flattened.items():
            path_parts = tuple(
                _canonical_event_path(re.sub(r"\[\d+\]$", "", part))
                for part in path.split(".")
            )
            if len(path_parts) >= len(alias) and path_parts[-len(alias):] == alias and value not in {None, ""}:
                return value
    return None


def _normalize_windows_event(item: dict[str, object], index: int) -> dict[str, object] | None:
    flattened = _flatten_event_scalars(item)
    named = _event_named_values(item)
    event_id_value = named.get("eventid")
    if event_id_value is None:
        event_id_value = _pick_event_value(
            flattened, "System.EventID", "EventID.value", "EventID", "EventCode",
        )
    match = re.search(r"\d{1,10}", str(event_id_value)) if event_id_value is not None else None
    event_id = match.group(0) if match and int(match.group(0)) <= 0xFFFFFFFF else None
    record_value = _pick_event_value(
        flattened, "System.EventRecordID", "EventRecordID", "RecordID",
    )
    record_match = re.search(r"\d{1,20}", str(record_value)) if record_value is not None else None
    record_id = int(record_match.group(0)) if record_match else None
    if event_id is None and record_id is None:
        return None

    def named_or_flat(named_keys: tuple[str, ...], *paths: str) -> object | None:
        value = next((named[key] for key in named_keys if key in named and named[key] not in {None, ""}), None)
        return value if value is not None else _pick_event_value(flattened, *paths)

    result: dict[str, object] = {
        "source_record_index": index,
        "event_id": event_id,
        "category": _WINDOWS_EVENT_CATEGORIES.get(event_id or "", "other"),
    }
    optional = {
        "event_record_id": record_id,
        "timestamp": _pick_event_value(flattened, "TimeCreated.SystemTime", "SystemTime", "Timestamp", "Datetime"),
        "provider": _pick_event_value(flattened, "Provider_attributes.Name", "Provider.Name", "ProviderName"),
        "channel": _pick_event_value(flattened, "System.Channel", "Channel"),
        "computer": _pick_event_value(flattened, "System.Computer", "Computer"),
        "user": named_or_flat(("subjectusername", "username", "user"), "SubjectUserName", "UserName"),
        "target_user": named_or_flat(("targetusername", "targetuser"), "TargetUserName", "TargetUser"),
        "process_id": named_or_flat(("newprocessid", "processid"), "NewProcessId", "ProcessId"),
        "parent_process_id": named_or_flat(("processid", "parentprocessid"), "ParentProcessId", "CreatorProcessId"),
        "process_path": named_or_flat(("newprocessname", "image", "processname"), "NewProcessName", "Image", "ProcessName"),
        "command_line": named_or_flat(("commandline",), "CommandLine"),
        "source_ip": named_or_flat(("ipaddress", "sourceip", "srcip"), "IpAddress", "SourceIp", "SrcIp"),
        "destination_ip": named_or_flat(("destinationip", "destip", "dstip"), "DestinationIp", "DestIp", "DstIp"),
        "service_name": named_or_flat(("servicename",), "ServiceName"),
        "task_name": named_or_flat(("taskname",), "TaskName"),
    }
    for key, value in optional.items():
        if value not in {None, ""}:
            result[key] = value[:2_000] if isinstance(value, str) else value
    return result


def parse_event_json(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize bounded JSON/JSONL Windows-event hunting output."""
    source = f"tool:{tool}"
    records: list[dict[str, object]] = []
    source_records = _event_json_records(stdout)
    event_ids: dict[str, int] = {}
    alerts: list[dict[str, object]] = []
    normalized_events: list[dict[str, object]] = []
    category_counts: dict[str, int] = {}
    for index, item in enumerate(source_records[:5_000]):
        flattened = _flatten_event_scalars(item)
        records.append(flattened)
        normalized_event = _normalize_windows_event(item, index)
        if normalized_event is not None:
            normalized_events.append(normalized_event)
            event_id = normalized_event.get("event_id")
            if event_id is not None:
                event_ids[str(event_id)] = event_ids.get(str(event_id), 0) + 1
            category = str(normalized_event["category"])
            category_counts[category] = category_counts.get(category, 0) + 1
        if any(
            marker in _canonical_event_path(key)
            for key in flattened
            for marker in ("sigma", "rule", "alert")
        ):
            alerts.append(flattened)
    observations = [
        _observation(artifact_id, "windows.event_hunt.record_count", len(records), source),
        _observation(artifact_id, "windows.event_hunt.event_ids", event_ids, source),
        _observation(artifact_id, "windows.event_hunt.category_counts", category_counts, source),
        _observation(artifact_id, "windows.event_hunt.normalized_events", normalized_events[:5_000], source, 0.95),
        _observation(artifact_id, "windows.event_hunt.alerts", alerts[:500], source, 0.9),
    ]
    findings: list[Finding] = []
    if normalized_events:
        findings.append(_finding(
            artifact_id, title=f"Normalized {len(normalized_events)} Windows event record(s)",
            category="windows_event_record_inventory",
            explanation="Bounded structured event output was normalized into Event ID, record identity, timestamp, actor, process, network, service, and task fields when explicitly present.",
            source=source, confidence=0.92, severity="info",
            evidence=[str(item)[:2_000] for item in normalized_events[:30]],
        ))
    classified = [item for item in normalized_events if item.get("category") != "other"]
    if classified:
        findings.append(_finding(
            artifact_id, title="Security-relevant Windows event classes recovered",
            category="windows_event_activity",
            explanation="Known Event IDs were categorized as investigation leads. The category does not by itself assert malicious activity; correlate the exact record with surrounding events and raw tool output.",
            source=source, confidence=0.9, severity="low",
            evidence=[str(item)[:2_000] for item in classified[:30]],
        ))
    if alerts:
        findings.append(_finding(
            artifact_id, title="Event hunting tool reported rule/alert records", category="windows_event_hunt_alert",
            explanation="Structured event-hunting output included rule, Sigma, or alert fields; inspect preserved raw output and generated timelines for context.",
            source=source, confidence=0.86, severity="medium",
            evidence=[str(item)[:2_000] for item in alerts[:30]],
        ))
    return ParsedToolOutput(observations, findings)


def parse_event_csv(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize generated Hayabusa-style CSV timelines within runner bounds."""
    source = f"tool:{tool}"
    try:
        reader = csv.DictReader(io.StringIO(stdout))
        records = []
        event_ids: dict[str, int] = {}
        alerts: list[dict[str, str]] = []
        normalized_events: list[dict[str, object]] = []
        category_counts: dict[str, int] = {}
        for index, row in enumerate(reader):
            normalized = {
                str(key)[:160]: str(value)[:2_000]
                for key, value in row.items() if key is not None and value is not None
            }
            if not normalized:
                continue
            records.append(normalized)
            event_id = next((value for key, value in normalized.items() if key.lower().replace("_", "") in {"eventid", "eventcode"}), None)
            if event_id:
                event_ids[event_id] = event_ids.get(event_id, 0) + 1
            normalized_event = _normalize_windows_event(normalized, index)
            if normalized_event is not None:
                normalized_events.append(normalized_event)
                category = str(normalized_event["category"])
                category_counts[category] = category_counts.get(category, 0) + 1
            if any(key.lower() in {"ruletitle", "ruletype", "level", "severity", "sigma"} and value for key, value in normalized.items()):
                alerts.append(normalized)
            if len(records) >= 5_000:
                break
    except csv.Error as exc:
        raise ValueError(f"invalid event CSV: {exc}") from exc
    observations = [
        _observation(artifact_id, "windows.event_timeline.record_count", len(records), source),
        _observation(artifact_id, "windows.event_timeline.event_ids", event_ids, source),
        _observation(artifact_id, "windows.event_timeline.category_counts", category_counts, source),
        _observation(artifact_id, "windows.event_timeline.normalized_events", normalized_events[:5_000], source, 0.95),
        _observation(artifact_id, "windows.event_timeline.alert_rows", alerts[:500], source, 0.9),
    ]
    findings: list[Finding] = []
    if normalized_events:
        findings.append(_finding(
            artifact_id, title=f"Normalized {len(normalized_events)} Windows timeline event(s)",
            category="windows_event_record_inventory",
            explanation="Bounded CSV timeline rows were normalized into Event ID, record identity, timestamp, actor, process, network, service, and task fields when explicitly present.",
            source=source, confidence=0.92, severity="info",
            evidence=[str(item)[:2_000] for item in normalized_events[:30]],
        ))
    classified = [item for item in normalized_events if item.get("category") != "other"]
    if classified:
        findings.append(_finding(
            artifact_id, title="Security-relevant Windows timeline classes recovered",
            category="windows_event_activity",
            explanation="Known Event IDs were categorized as investigation leads. The category does not by itself assert malicious activity; inspect surrounding timeline rows and preserved CSV output.",
            source=source, confidence=0.9, severity="low",
            evidence=[str(item)[:2_000] for item in classified[:30]],
        ))
    if alerts:
        findings.append(_finding(
            artifact_id, title="Event timeline contains rule/severity metadata", category="windows_event_timeline_lead",
            explanation="The generated CSV timeline includes rule or severity columns. Rows are normalized as leads while the original CSV remains a child artifact.",
            source=source, confidence=0.82, severity="low", evidence=[str(row)[:2_000] for row in alerts[:30]],
        ))
    return ParsedToolOutput(observations, findings)


def parse_leapp(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize bounded ALEAPP/iLEAPP JSON or CSV result exports.

    LEAPP output schemas change across versions, so this parser intentionally
    preserves a shallow, scalar-only record inventory rather than binding the
    engine to one report template.  The original generated report remains an
    artifact and is recursively triaged separately.
    """
    source = f"tool:{tool}"
    records: list[dict[str, object]] = []
    kind = "unknown"
    text = stdout.lstrip("\ufeff \t\r\n")
    try:
        if text.startswith(("{", "[")):
            document = json.loads(text)
            if isinstance(document, dict):
                candidate = next(
                    (value for key, value in document.items() if key.lower() in {"data", "records", "results", "artifacts"} and isinstance(value, list)),
                    [document],
                )
            else:
                candidate = document
            if isinstance(candidate, list):
                for item in candidate[:2_000]:
                    if isinstance(item, dict):
                        records.append({
                            str(key)[:160]: value if isinstance(value, (str, int, float, bool, type(None))) else str(value)[:2_000]
                            for key, value in list(item.items())[:100]
                        })
                kind = "json"
        elif "\n" in stdout and "," in stdout.splitlines()[0]:
            reader = csv.DictReader(io.StringIO(stdout))
            for row in reader:
                normalized = {
                    str(key)[:160]: str(value)[:2_000]
                    for key, value in row.items() if key is not None and value is not None
                }
                if normalized:
                    records.append(normalized)
                if len(records) >= 2_000:
                    break
            kind = "csv"
    except (ValueError, csv.Error, json.JSONDecodeError) as exc:
        return ParsedToolOutput(observations=[
            _observation(artifact_id, "mobile.leapp.parse_error", f"{type(exc).__name__}: {exc}"[:2_000], source, 0.8)
        ])
    observations = [
        _observation(artifact_id, "mobile.leapp.result_format", kind, source, 0.9),
        _observation(artifact_id, "mobile.leapp.record_count", len(records), source, 0.9),
        _observation(artifact_id, "mobile.leapp.records", records[:500], source, 0.85),
    ]
    return ParsedToolOutput(observations=observations)


def parse_bulk_extractor_feature_file(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize one generated bulk_extractor feature file, not raw carving data."""
    source = f"tool:{tool}"
    features: list[str] = []
    for line in stdout.splitlines():
        if not line or line.startswith("#"):
            continue
        # Feature files normally start with an offset then tab-delimited
        # values. Preserve only the final value as a compact lead.
        value = line.rsplit("\t", 1)[-1].strip()
        if value:
            features.append(value[:2_000])
        if len(features) >= 5_000:
            break
    observations = [
        _observation(artifact_id, "bulk_extractor.feature_count", len(features), source, 0.9),
        _observation(artifact_id, "bulk_extractor.features", features[:500], source, 0.8),
    ]
    return ParsedToolOutput(observations=observations)


def parse_olevba(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    lowered = stdout.lower()
    has_vba = any(marker in lowered for marker in ("vba macro", "vba p-code", "vba_p-code", "vba stomping", "contains macros")) and not any(
        marker in lowered for marker in ("no vba macros found", "no vba macro found", "no macros found")
    )
    suspicious = [
        line.strip()[:2_000]
        for line in stdout.splitlines()
        if re.search(r"\b(?:autoopen|document_open|shell|powershell|wscript|url download)\b", line, re.I)
    ][:100]
    observations = [
        _observation(artifact_id, "office.has_vba", has_vba, source),
        _observation(artifact_id, "office.suspicious_macro_lines", suspicious, source, 0.85),
    ]
    findings: list[Finding] = []
    if has_vba or suspicious:
        findings.append(
            _finding(
                artifact_id,
                title="Office macro content detected",
                category="office_macro",
                explanation="olevba reported VBA content or suspicious macro keywords.",
                source=source,
                confidence=0.9 if has_vba else 0.7,
                severity="medium",
                evidence=suspicious[:20],
            )
        )
    return ParsedToolOutput(observations, findings)


def parse_sleuthkit_mmls(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    partitions: list[dict[str, object]] = []
    pattern = re.compile(r"^\s*(\d+(?::\d+)?[:]?)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(.*?)\s*$")
    for line in stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        partitions.append({"slot": match.group(1), "start": int(match.group(2)), "end": int(match.group(3)), "length": int(match.group(4)), "description": match.group(5)[:1000]})
    observations = [
        _observation(artifact_id, "disk.partition_count", len(partitions), source),
        _observation(artifact_id, "disk.partitions", partitions[:500], source),
    ]
    return ParsedToolOutput(observations=observations)


def parse_sleuthkit_fls(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    entries = [line.strip()[:2000] for line in stdout.splitlines() if line.strip()][:10_000]
    deleted = [entry for entry in entries if "(deleted)" in entry.lower()]
    observations = [
        _observation(artifact_id, "filesystem.fls.entry_count", len(entries), source),
        _observation(artifact_id, "filesystem.fls.deleted_count", len(deleted), source),
        _observation(artifact_id, "filesystem.fls.deleted_samples", deleted[:500], source),
    ]
    findings: list[Finding] = []
    if deleted:
        findings.append(
            _finding(
                artifact_id,
                title=f"Filesystem listing includes {len(deleted)} deleted entry/entries",
                category="deleted_files",
                explanation="SleuthKit fls marked entries as deleted; targeted recovery may be warranted.",
                source=source,
                confidence=0.9,
                severity="info",
                evidence=deleted[:20],
            )
        )
    return ParsedToolOutput(observations, findings)


def parse_sleuthkit_fsstat(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize the stable, human-readable facts emitted by SleuthKit fsstat."""
    source = f"tool:{tool}"
    metadata: dict[str, str] = {}
    for line in stdout.splitlines()[:2_000]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = re.sub(r"\s+", " ", key).strip().casefold()
        value = re.sub(r"\s+", " ", value).strip()
        if key and value and len(metadata) < 200:
            metadata[key[:200]] = value[:2_000]
    filesystem_type = next(
        (value for key, value in metadata.items() if key in {"file system type", "filesystem type"}), None
    )
    observations = [
        _observation(artifact_id, "filesystem.fsstat.metadata", metadata, source, 0.9),
        _observation(artifact_id, "filesystem.fsstat.type", filesystem_type, source, 0.9),
    ]
    return ParsedToolOutput(observations=observations)


def parse_ewfinfo(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize key EWF metadata without assuming a particular ewf-tools release."""
    source = f"tool:{tool}"
    metadata: dict[str, str] = {}
    for line in stdout.splitlines()[:2_000]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = re.sub(r"\s+", " ", key).strip().casefold()
        value = re.sub(r"\s+", " ", value).strip()
        if key and value and len(metadata) < 250:
            metadata[key[:200]] = value[:2_000]
    media_size: int | None = None
    segment_count: int | None = None
    for key, value in metadata.items():
        if "media size" in key or "media size" in value.casefold():
            match = re.search(r"\(?\s*(\d+)\s+bytes?\s*\)?", value, re.I)
            if match:
                media_size = int(match.group(1))
                break
    for key, value in metadata.items():
        if "number of segments" in key or "segment files" in key:
            match = re.search(r"\d+", value)
            if match:
                segment_count = int(match.group(0))
                break
    observations = [
        _observation(artifact_id, "disk.ewf.metadata", metadata, source, 0.9),
        _observation(artifact_id, "disk.ewf.media_size_bytes", media_size, source, 0.9),
        _observation(artifact_id, "disk.ewf.segment_count", segment_count, source, 0.85),
    ]
    return ParsedToolOutput(observations=observations)


def parse_readelf(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    """Normalize non-executing ELF loader metadata from ``readelf`` output."""
    source = f"tool:{tool}"
    libraries = list(dict.fromkeys(re.findall(r"\(NEEDED\).*?\[([^\]]{1,1024})\]", stdout)))[:500]
    search_paths = list(dict.fromkeys(re.findall(r"\((?:RPATH|RUNPATH)\).*?\[([^\]]{1,4096})\]", stdout)))[:100]
    interpreter_match = re.search(r"Requesting program interpreter:\s*([^\]\r\n]+)", stdout, re.I)
    interpreter = interpreter_match.group(1).strip()[:2_000] if interpreter_match else None
    stack_lines = [line.strip()[:2_000] for line in stdout.splitlines() if "GNU_STACK" in line][:20]
    executable_stack = any(re.search(r"GNU_STACK.*\bRWE\b", line) for line in stack_lines)
    observations = [
        _observation(artifact_id, "executable.readelf.needed_libraries", libraries, source, 0.9),
        _observation(artifact_id, "executable.readelf.search_paths", search_paths, source, 0.9),
        _observation(artifact_id, "executable.readelf.interpreter", interpreter, source, 0.9),
        _observation(artifact_id, "executable.readelf.executable_stack", executable_stack, source, 0.9),
    ]
    findings: list[Finding] = []
    relative_paths = [path for path in search_paths if any(part in {".", ""} for part in path.split(":"))]
    if relative_paths:
        findings.append(_finding(
            artifact_id, title="ELF dynamic loader search path includes a relative component", category="executable_loader_path_lead",
            explanation="readelf reported RPATH/RUNPATH containing '.' or an empty component. Relative loader search paths can affect which local libraries are resolved at runtime.",
            source=source, confidence=0.86, severity="low", evidence=relative_paths[:30],
        ))
    return ParsedToolOutput(observations, findings)


def parse_volatility3(
    artifact_id: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    tool: str,
) -> ParsedToolOutput:
    source = f"tool:{tool}"
    info: dict[str, str] = {}
    processes: list[dict[str, str]] = []
    network_rows: list[dict[str, str]] = []
    command_rows: list[dict[str, str]] = []
    handle_rows: list[dict[str, str]] = []
    file_rows: list[dict[str, str]] = []
    module_rows: list[dict[str, str]] = []
    malfind_rows: list[dict[str, str]] = []
    plugin = tool.removeprefix("volatility3_").casefold() or "banners"
    structured_rows, structured_info = _volatility_structured_output(stdout)
    info.update(structured_info)
    for row in structured_rows:
        normalized = {str(key)[:200]: str(value)[:2_000] for key, value in row.items()}
        lowered = {key.lower().replace(" ", "").replace("_", "") for key in normalized}
        if "windows_info" in plugin:
            variable = next(
                (value for key, value in normalized.items() if key.casefold() in {"variable", "name", "field"}),
                None,
            )
            value = next(
                (value for key, value in normalized.items() if key.casefold() in {"value", "data"}),
                None,
            )
            if variable and value is not None and len(info) < 200:
                info[str(variable)[:200]] = str(value)[:2_000]
        if "pid" in lowered and "ppid" in lowered:
            if len(processes) < 1_000:
                processes.append(normalized)
        if any("localaddr" in key or "localaddress" in key for key in lowered) and any(
            "foreignaddr" in key or "foreignaddress" in key or "remoteaddr" in key or "remoteaddress" in key
            for key in lowered
        ):
            if len(network_rows) < 1_000:
                network_rows.append(normalized)
        if "pid" in lowered and any(
            key in {"args", "commandline", "command"} or "commandline" in key
            for key in lowered
        ):
            if len(command_rows) < 1_000:
                command_rows.append(normalized)
        if "handles" in plugin and len(handle_rows) < 1_000:
            handle_rows.append(normalized)
        if "filescan" in plugin and len(file_rows) < 1_000:
            file_rows.append(normalized)
        if "dlllist" in plugin and len(module_rows) < 1_000:
            module_rows.append(normalized)
        if "malfind" in plugin and len(malfind_rows) < 1_000:
            malfind_rows.append(normalized)
    lines = [line.rstrip() for line in stdout.splitlines() if line.strip()]
    if not structured_rows:
        for line in lines:
            if "\t" in line:
                key, value = line.split("\t", 1)
                if key.strip() and value.strip() and len(key) < 120:
                    info[key.strip()] = value.strip()[:2000]
            elif ":" in line and len(line) < 4000:
                key, value = line.split(":", 1)
                if key.strip() and value.strip():
                    info.setdefault(key.strip(), value.strip()[:2000])
    header_index = next((index for index, line in enumerate(lines) if re.search(r"\bPID\b", line) and re.search(r"\bPPID\b", line)), None)
    if header_index is not None:
        headers = re.split(r"\s{2,}|\t", lines[header_index].strip())
        for line in lines[header_index + 1:header_index + 2001]:
            values = re.split(r"\s{2,}|\t", line.strip())
            if len(values) < 2:
                continue
            if not structured_rows:
                processes.append({headers[index]: values[index][:500] for index in range(min(len(headers), len(values)))})
    network_header = next(
        (index for index, line in enumerate(lines) if re.search(r"\b(?:localaddr|local address)\b", line, re.I) and re.search(r"\b(?:foreignaddr|foreign address|remoteaddr)\b", line, re.I)),
        None,
    )
    if network_header is not None:
        headers = re.split(r"\s{2,}|\t", lines[network_header].strip())
        for line in lines[network_header + 1:network_header + 2001]:
            values = re.split(r"\s{2,}|\t", line.strip())
            if len(values) < 2:
                continue
            if not structured_rows:
                network_rows.append({headers[index]: values[index][:1_000] for index in range(min(len(headers), len(values)))})
    command_header = next(
        (index for index, line in enumerate(lines) if re.search(r"\bPID\b", line) and re.search(r"\b(?:Args|CommandLine|Command Line)\b", line, re.I)),
        None,
    )
    if command_header is not None:
        headers = re.split(r"\s{2,}|\t", lines[command_header].strip())
        for line in lines[command_header + 1:command_header + 2001]:
            values = re.split(r"\s{2,}|\t", line.strip(), maxsplit=max(1, len(headers) - 1))
            if len(values) < 2:
                continue
            if not structured_rows:
                command_rows.append({headers[index]: values[index][:2_000] for index in range(min(len(headers), len(values)))})
    table_targets: list[tuple[str, list[dict[str, str]], bool]] = []
    if "handles" in plugin:
        table_targets.append(("handle", handle_rows, True))
    elif "filescan" in plugin:
        table_targets.append(("name", file_rows, True))
    elif "dlllist" in plugin:
        table_targets.append(("pid", module_rows, False))
    elif "malfind" in plugin:
        table_targets.append(("pid", malfind_rows, False))
    for required, target, needs_offset in table_targets:
        if target:
            continue
        header_index = next(
            (index for index, line in enumerate(lines)
             if required in line.casefold() and (not needs_offset or "offset" in line.casefold())),
            None,
        )
        if header_index is None:
            continue
        headers = re.split(r"\s{2,}|\t", lines[header_index].strip())
        for line in lines[header_index + 1:header_index + 2001]:
            values = re.split(r"\s{2,}|\t", line.strip(), maxsplit=max(1, len(headers) - 1))
            if len(values) < 2:
                continue
            target.append({headers[index]: values[index][:2_000] for index in range(min(len(headers), len(values)))})
    observations = [
        _observation(artifact_id, "memory.volatility.plugin", tool.removeprefix("volatility3_") or "banners", source),
        _observation(artifact_id, "memory.volatility.info", info, source),
        _observation(artifact_id, "memory.volatility.process_count", len(processes), source),
        _observation(artifact_id, "memory.volatility.processes", processes[:1000], source),
        _observation(artifact_id, "memory.volatility.network_count", len(network_rows), source),
        _observation(artifact_id, "memory.volatility.network", network_rows[:1000], source),
        _observation(artifact_id, "memory.volatility.command_count", len(command_rows), source),
        _observation(artifact_id, "memory.volatility.commands", command_rows[:1000], source),
        _observation(artifact_id, "memory.volatility.handle_count", len(handle_rows), source),
        _observation(artifact_id, "memory.volatility.handles", handle_rows[:1000], source),
        _observation(artifact_id, "memory.volatility.file_count", len(file_rows), source),
        _observation(artifact_id, "memory.volatility.files", file_rows[:1000], source),
        _observation(artifact_id, "memory.volatility.module_count", len(module_rows), source),
        _observation(artifact_id, "memory.volatility.modules", module_rows[:1000], source),
        _observation(artifact_id, "memory.volatility.malfind_count", len(malfind_rows), source),
        _observation(artifact_id, "memory.volatility.malfind", malfind_rows[:1000], source),
    ]
    if "pslist" in plugin:
        observations.append(_observation(artifact_id, "memory.volatility.pslist", processes[:1000], source))
    if "psscan" in plugin:
        observations.append(_observation(artifact_id, "memory.volatility.psscan", processes[:1000], source))
    if "windows_info" in plugin:
        observations.append(_observation(artifact_id, "memory.volatility.kernel_info", info, source, 0.9))
    banner = next((value for key, value in info.items() if "kernel" in key.lower() or "banner" in key.lower()), None)
    if banner:
        observations.append(_observation(artifact_id, "memory.os_banner", banner, source, 0.9))
    failure = _classify_volatility_failure(stdout, stderr, exit_code)
    findings: list[Finding] = []
    if failure is not None:
        observations.append(_observation(
            artifact_id, "memory.volatility.failure", failure, source, 0.95,
        ))
        explanations = {
            "symbols_missing": (
                "Volatility could not satisfy a symbol-table requirement. Stage the matching "
                "Windows symbol table or Linux ISF in the offline symbol path and retry; this "
                "is distinct from evidence corruption."
            ),
            "image_or_layer_mismatch": (
                "Volatility could not construct or validate the required memory layer. Confirm "
                "that the input is a supported full-system image and that its architecture/image "
                "type matches the selected plugin."
            ),
            "plugin_or_argument_unsupported": (
                "The installed Volatility build rejected the plugin or one of its arguments. "
                "Review the recorded version and `vol --help`/plugin help on the prepared machine."
            ),
            "plugin_failed": (
                "The Volatility plugin failed for a reason not safely attributable to symbols or "
                "image-layer mismatch. Inspect preserved stdout/stderr before retrying."
            ),
        }
        findings.append(_finding(
            artifact_id,
            title=f"Volatility analysis incomplete: {failure['category']}",
            category="memory_volatility_failure",
            explanation=explanations[str(failure["category"])],
            source=source,
            confidence=0.95,
            severity="info",
            evidence=[str(item)[:2_000] for item in failure.get("detail", [])[:20]],
        ))
    return ParsedToolOutput(observations=observations, findings=findings)


def _classify_volatility_failure(
    stdout: str,
    stderr: str,
    exit_code: int | None,
) -> dict[str, object] | None:
    combined = f"{stderr}\n{stdout}"[:4 * 1024 * 1024]
    lowered = combined.casefold()
    category: str | None = None
    if any(marker in lowered for marker in (
        "symbol table", "symbol_table_name", "symbols are required",
        "isf file", "pdbconv", "pdb file", "missing symbols",
    )) or (
        "unsatisfied requirement" in lowered
        and any(marker in lowered for marker in ("kernel", "nt_symbols", "symbol"))
    ):
        category = "symbols_missing"
    elif any(marker in lowered for marker in (
        "translation layer requirement", "unable to validate the plugin requirements",
        "no suitable layers", "failed to construct", "invalid memory layer",
        "layer requirement",
    )):
        category = "image_or_layer_mismatch"
    elif any(marker in lowered for marker in (
        "unrecognized arguments", "invalid choice", "plugin not found",
        "invalid plugin", "unknown plugin", "the following arguments are required",
    )):
        category = "plugin_or_argument_unsupported"
    elif exit_code not in {None, 0}:
        category = "plugin_failed"
    if category is None:
        return None
    detail = _nonempty_lines(stderr, maximum=20)
    if not detail:
        detail = _nonempty_lines(stdout, maximum=20)
    return {"category": category, "exit_code": exit_code, "detail": detail}


def _volatility_structured_output(stdout: str) -> tuple[list[dict[str, object]], dict[str, str]]:
    """Accept Volatility JSON/JSONL renderers without requiring one version.

    Volatility 3 renderer layouts vary: some emit ``columns`` plus array
    ``rows`` while wrappers commonly emit a list of objects or JSONL.  This
    normalizer is deliberately small and does not recursively deserialize
    arbitrary nested structures.
    """
    maximum = 8 * 1024 * 1024
    if len(stdout.encode("utf-8", errors="ignore")) > maximum:
        return [], {}
    document: object | None = None
    text = stdout.strip()
    if text.startswith(("{", "[")):
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            pass
    if document is None:
        records: list[object] = []
        for line in stdout.splitlines()[:2_000]:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        document = records if records else None
    if isinstance(document, list):
        return [item for item in document[:1_000] if isinstance(item, dict)], {}
    if not isinstance(document, dict):
        return [], {}
    raw_rows = document.get("rows", document.get("data", document.get("items", [])))
    columns = document.get("columns", [])
    rows: list[dict[str, object]] = []
    if isinstance(raw_rows, list):
        for item in raw_rows[:1_000]:
            if isinstance(item, dict):
                rows.append(item)
            elif isinstance(item, (list, tuple)) and isinstance(columns, list):
                rows.append({str(columns[index]): value for index, value in enumerate(item[:len(columns)])})
    if rows:
        return rows, {}
    info = {
        str(key)[:200]: str(value)[:2_000]
        for key, value in list(document.items())[:200]
        if isinstance(value, (str, int, float, bool))
    }
    return [], info


class OutputParserRegistry:
    """Maps catalog parser ids to resilient, normalized output parsers."""

    def __init__(self) -> None:
        self._parsers: dict[str, ParserFunction] = {"generic": parse_generic}

    @classmethod
    def default(cls) -> "OutputParserRegistry":
        registry = cls()
        registry.register("file", parse_file)
        registry.register("exiftool", parse_exiftool)
        registry.register("binwalk", parse_binwalk)
        registry.register("sevenzip", parse_sevenzip)
        registry.register("pngcheck", parse_pngcheck)
        registry.register("zsteg", parse_zsteg)
        registry.register("capinfos", parse_capinfos)
        registry.register("tshark", parse_tshark)
        registry.register("sqlite3", parse_sqlite3)
        registry.register("pdfid", parse_pdfid)
        registry.register("pdfinfo", parse_pdfinfo)
        registry.register("pdftotext", parse_pdftotext)
        registry.register("qpdf", parse_qpdf)
        registry.register("pdf_parser", parse_pdf_parser)
        registry.register("olevba", parse_olevba)
        registry.register("oledump", parse_oledump)
        registry.register("regripper", parse_regripper)
        registry.register("event_json", parse_event_json)
        registry.register("event_csv", parse_event_csv)
        registry.register("leapp", parse_leapp)
        registry.register("bulk_extractor_feature", parse_bulk_extractor_feature_file)
        registry.register("sleuthkit_mmls", parse_sleuthkit_mmls)
        registry.register("sleuthkit_fls", parse_sleuthkit_fls)
        registry.register("sleuthkit_fsstat", parse_sleuthkit_fsstat)
        registry.register("ewfinfo", parse_ewfinfo)
        registry.register("readelf", parse_readelf)
        registry.register("volatility3", parse_volatility3)
        return registry

    def register(self, name: str, parser: ParserFunction) -> None:
        if not name:
            raise ValueError("parser name may not be empty")
        self._parsers[name] = parser

    def names(self) -> list[str]:
        return list(self._parsers)

    def parse(
        self,
        parser_name: str,
        *,
        artifact_id: str,
        stdout: str,
        stderr: str,
        exit_code: int | None,
        tool: str,
    ) -> ParsedToolOutput:
        parser = self._parsers.get(parser_name, self._parsers["generic"])
        try:
            return parser(artifact_id, stdout, stderr, exit_code, tool)
        except Exception as exc:  # Parser bugs must never terminate the case.
            result = parse_generic(artifact_id, stdout, stderr, exit_code, tool)
            result.observations.append(
                _observation(
                    artifact_id,
                    f"tool.{tool}.parser_error",
                    f"{type(exc).__name__}: {exc}"[:2_000],
                    f"parser:{parser_name}",
                    1.0,
                )
            )
            return result


DEFAULT_PARSER_REGISTRY = OutputParserRegistry.default()


def parse_output(
    parser_name: str,
    *,
    artifact_id: str,
    stdout: str,
    stderr: str = "",
    exit_code: int | None = 0,
    tool: str | None = None,
) -> ParsedToolOutput:
    return DEFAULT_PARSER_REGISTRY.parse(
        parser_name,
        artifact_id=artifact_id,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        tool=tool or parser_name,
    )


__all__ = [
    "DEFAULT_PARSER_REGISTRY",
    "OutputParserRegistry",
    "ParsedToolOutput",
    "parse_output",
]
