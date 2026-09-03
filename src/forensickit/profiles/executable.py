from __future__ import annotations

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


class ExecutableProfile(BaseProfile):
    """Structure-led executable triage without executing any sample."""

    name = "executable"
    priority = 680

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("executable") or context.format_is("pe", "elf"):
            return ["PE or ELF classification is present"]
        if context.truthy("executable.pe.valid_signature", "executable.elf.header_valid"):
            return ["validated executable header observation is present"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        if context.format_is("elf"):
            result.recommendations.append(self.recommendation(
                "readelf", (AnalysisMode.AUTO, AnalysisMode.DEEP),
                "inspect ELF headers, program headers, and dynamic-loader metadata without executing the sample",
                95,
            ))
        pe_sections = next((value for value in context.values("executable.pe.sections") if isinstance(value, list)), [])
        invalid = [item for item in pe_sections if isinstance(item, dict) and not item.get("within_image", False)]
        wx = [item for item in pe_sections if isinstance(item, dict) and item.get("writable") and item.get("executable")]
        if invalid:
            result.findings.append(self.finding(
                context, title="PE section range extends outside the evidence file", category="executable_structure_anomaly",
                confidence=0.9,
                explanation="At least one PE section declares raw data outside the supplied image, indicating truncation or a malformed layout.",
                evidence=[str(item)[:1_000] for item in invalid[:30]],
            ))
        if wx:
            result.findings.append(self.finding(
                context, title="PE contains writable executable section(s)", category="executable_wx_section",
                confidence=0.8,
                explanation="Writable-and-executable PE sections are not automatically malicious, but they are a high-value packing/injection triage lead.",
                evidence=[str(item.get("name", ""))[:512] for item in wx[:30]],
                severity="low",
            ))
        imports = next((value for value in context.values("executable.pe.imports") if isinstance(value, list)), [])
        network_imports = [name for name in imports if str(name).lower() in {"wininet.dll", "winhttp.dll", "urlmon.dll", "ws2_32.dll"}]
        if network_imports:
            result.findings.append(self.finding(
                context, title="PE imports Windows network-related library", category="executable_network_capability",
                confidence=0.8,
                explanation="Import-table inventory references a Windows networking library. This is a triage capability lead, not proof of malicious activity.",
                evidence=[str(name)[:512] for name in network_imports[:30]], severity="low",
            ))
        entropy = context.number("entropy.shannon")
        if entropy is not None and entropy >= 7.5:
            result.findings.append(self.finding(
                context, title="Executable has high sampled entropy", category="executable_packing_lead",
                confidence=0.7,
                explanation="High entropy can result from packing, encryption, or compressed resources; correlate it with section layout and strings.",
                evidence=[f"entropy={entropy:.4f}"], severity="low",
            ))
        elf_headers = next((value for value in context.values("executable.elf.program_headers") if isinstance(value, list)), [])
        elf_wx = [
            item for item in elf_headers
            if isinstance(item, dict) and item.get("type") == "load" and item.get("writable") and item.get("executable")
        ]
        elf_exec_stack = [
            item for item in elf_headers
            if isinstance(item, dict) and item.get("type") == "gnu_stack" and item.get("executable")
        ]
        if elf_wx:
            result.findings.append(self.finding(
                context, title="ELF contains writable executable load segment", category="executable_wx_segment",
                confidence=0.84,
                explanation="A PT_LOAD segment is both writable and executable, a high-value packing or injection triage lead.",
                evidence=[str(item)[:1_000] for item in elf_wx[:30]], severity="low",
            ))
        if elf_exec_stack:
            result.findings.append(self.finding(
                context, title="ELF requests an executable stack", category="executable_stack_policy",
                confidence=0.9,
                explanation="A GNU_STACK program header includes execute permission. This is an exploitability/compatibility lead, not proof of maliciousness.",
                evidence=[str(item)[:1_000] for item in elf_exec_stack[:10]], severity="low",
            ))
        interpreter = next((value for value in context.values("executable.elf.interpreter") if isinstance(value, str) and value), None)
        if interpreter:
            result.findings.append(self.finding(
                context, title="ELF dynamic loader path recovered", category="executable_runtime_metadata",
                confidence=0.94,
                explanation="The PT_INTERP program header identifies the runtime dynamic loader expected by this executable.",
                evidence=[interpreter], severity="info",
            ))
        readelf_paths = next((value for value in context.values("executable.readelf.search_paths") if isinstance(value, list)), [])
        if readelf_paths:
            result.findings.append(self.finding(
                context, title="ELF dynamic loader search path recovered", category="executable_runtime_metadata",
                confidence=0.9,
                explanation="readelf recovered RPATH/RUNPATH loader search metadata. It is preserved as evidence because local library resolution can change runtime behavior.",
                evidence=[str(path)[:2_000] for path in readelf_paths[:30]], severity="info",
            ))
        return result
