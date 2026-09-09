from __future__ import annotations

import re

from ..models import AnalysisMode
from .base import BaseProfile, ProfileContext, ProfileResult


MEMORY_TYPES = {"memory", "memory_dump", "ram", "ram_dump", "hiberfil", "crash_dump", "vmem"}


class MemoryProfile(BaseProfile):
    """Initial signature-backed Volatility plan; plugins are refined after banner parsing."""

    name = "memory"
    priority = 700

    def match_reasons(self, context: ProfileContext) -> list[str]:
        reasons: list[str] = []
        matched_types = context.artifact_types & MEMORY_TYPES
        if matched_types:
            reasons.append(f"classification includes memory image type: {sorted(matched_types)}")
        if context.truthy(
            "signature.memory_dump", "memory.signature_detected", "memory.windows_crash_signature",
            "memory.linux_banner",
        ):
            reasons.append("memory/crash-dump signature observation is present")
        magic = (context.artifact.magic or "").lower()
        if any(marker in magic for marker in ("hibernation", "crash dump", "memory dump")):
            reasons.append(f"magic identifies memory-related evidence: {context.artifact.magic}")
        return reasons

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        is_minidump = any(
            isinstance(value, bool) for value in context.values("memory.minidump_valid")
        )
        if not is_minidump:
            result.recommendations.append(
                self.recommendation(
                    "volatility3",
                    (AnalysisMode.AUTO, AnalysisMode.DEEP),
                    "full-system memory classification/signature warrants OS identification",
                    110,
                )
            )
        parsed_banners = [str(value).lower() for value in context.values("memory.os_banner", "memory.linux_banner") if value]
        is_linux = context.truthy("memory.linux_banner") or any("linux" in value for value in parsed_banners)
        is_linux = is_linux and not is_minidump
        is_windows = context.truthy(
            "memory.windows_crash_signature", "memory.hiberfil_signature"
        ) or context.number("memory.kdbg_offset") is not None or any("windows" in value for value in parsed_banners)
        is_windows = is_windows and not is_minidump
        if is_minidump:
            result.findings.append(self.finding(
                context,
                title="User-mode minidump scope identified",
                category="memory_minidump_scope",
                confidence=0.99,
                explanation=(
                    "MDMP is a selected user-process dump, not a full-system physical-memory image. "
                    "Full-system PsList/PsScan/NetScan/FileScan plugins are therefore not run automatically; "
                    "the bounded native stream parser reports only data actually present in this file."
                ),
                evidence=["memory.minidump_valid observation present"],
                severity="info",
            ))
        if is_linux:
            result.recommendations.extend([
                self.recommendation("volatility3_linux_pslist", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Linux banner supports process enumeration", 100),
                self.recommendation("volatility3_linux_psaux", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Linux banner supports command-line enumeration", 95),
                self.recommendation("volatility3_linux_sockstat", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Linux banner supports socket enumeration", 90),
            ])
        elif is_windows:
            result.recommendations.extend([
                self.recommendation("volatility3_windows_info", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Windows/KDBG evidence supports OS and kernel metadata recovery", 105),
                self.recommendation("volatility3_windows_pslist", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Windows/KDBG evidence supports process enumeration", 100),
                self.recommendation("volatility3_windows_psscan", (AnalysisMode.DEEP,), "Windows/KDBG evidence supports scan/list hidden-process comparison", 98),
                self.recommendation("volatility3_windows_pstree", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Windows/KDBG evidence supports parent-child process reconstruction", 95),
                self.recommendation("volatility3_windows_cmdline", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Windows/KDBG evidence supports command-line recovery", 90),
                self.recommendation("volatility3_windows_netscan", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Windows/KDBG evidence supports network socket enumeration", 90),
                self.recommendation("volatility3_windows_handles", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Windows/KDBG evidence supports process handle inventory", 85),
                self.recommendation("volatility3_windows_filescan", (AnalysisMode.DEEP,), "Windows/KDBG evidence supports file-object scan inventory", 85),
                self.recommendation("volatility3_windows_dlllist", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Windows/KDBG evidence supports loaded-module inventory", 84),
                self.recommendation("volatility3_windows_malfind", (AnalysisMode.DEEP,), "Windows/KDBG evidence supports suspicious executable-region triage", 80),
            ])
            requested_pids = []
            for value in context.values("memory.requested_pids"):
                if not isinstance(value, list):
                    continue
                for pid in value[:16]:
                    if isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid <= 0xFFFFFFFF and pid not in requested_pids:
                        requested_pids.append(pid)
            for pid in requested_pids:
                result.recommendations.extend([
                    self.recommendation(
                        "volatility3_windows_memmap", (AnalysisMode.DEEP,),
                        f"analyst selected PID {pid} for bounded process-memory extraction",
                        105, command_mode="pid_dump", parameters={"pid": str(pid)},
                    ),
                    self.recommendation(
                        "volatility3_windows_dlllist", (AnalysisMode.DEEP,),
                        f"analyst selected PID {pid} for module inventory and dump",
                        101, command_mode="pid_dump", parameters={"pid": str(pid)},
                    ),
                ])
        volatility_kernel_info = next(
            (value for value in context.values("memory.volatility.kernel_info") if isinstance(value, dict) and value), None
        )
        if volatility_kernel_info:
            result.findings.append(self.finding(
                context,
                title="Volatility recovered Windows OS and kernel metadata",
                category="memory_kernel_info",
                confidence=0.9,
                explanation=(
                    "The installed Volatility windows.info plugin reported bounded OS/kernel fields. "
                    "These values depend on successful layer and symbol resolution; the preserved JSON "
                    "tool output remains the reproducible source."
                ),
                evidence=[f"{key}={value}" for key, value in list(volatility_kernel_info.items())[:100]],
                severity="info",
            ))
        minidump_valid = next((value for value in context.values("memory.minidump_valid") if isinstance(value, bool)), None)
        if minidump_valid is False:
            result.findings.append(self.finding(
                context, title="Windows minidump directory is structurally invalid", category="memory_structure_anomaly",
                confidence=0.9,
                explanation="The minidump magic was present but its stream directory fell outside the supplied evidence or exceeded safe bounds.",
                evidence=["memory.minidump_valid=false"],
            ))
        minidump_system = next(
            (value for value in context.values("memory.minidump.system_info") if isinstance(value, dict)), None
        )
        if minidump_system:
            os_version = ".".join(
                str(minidump_system.get(name))
                for name in ("major_version", "minor_version", "build_number")
                if minidump_system.get(name) is not None
            )
            evidence = [
                f"architecture={minidump_system.get('architecture')}",
                f"processor_count={minidump_system.get('processor_count')}",
            ]
            if os_version:
                evidence.append(f"windows_version={os_version}")
            result.findings.append(self.finding(
                context, title="Windows minidump system metadata recovered", category="memory_minidump_metadata",
                confidence=0.92,
                explanation="The bounded SystemInfo stream identifies processor architecture and Windows version metadata for the supplied minidump.",
                evidence=evidence, severity="info",
            ))
        minidump_misc = next(
            (value for value in context.values("memory.minidump.misc_info") if isinstance(value, dict)), None
        )
        if minidump_misc:
            evidence = [
                f"process_id={minidump_misc.get('process_id')}",
                f"process_create_time={minidump_misc.get('process_create_time')}",
                f"user_cpu_seconds={minidump_misc.get('process_user_time_seconds')}",
                f"kernel_cpu_seconds={minidump_misc.get('process_kernel_time_seconds')}",
            ]
            if minidump_misc.get("size_valid") is False:
                evidence.append("declared_misc_info_size_invalid=true")
            result.findings.append(self.finding(
                context, title="Minidump process/timing metadata recovered", category="memory_minidump_process_metadata",
                confidence=0.9 if minidump_misc.get("size_valid") is not False else 0.78,
                explanation="The bounded MINIDUMP_MISC_INFO stream identifies the process represented by this user-mode dump and its recorded timing counters.",
                evidence=evidence, severity="info",
            ))
        minidump_comments = next(
            (value for value in context.values("memory.minidump.comments") if isinstance(value, list)), []
        )
        if minidump_comments:
            result.findings.append(self.finding(
                context, title="Minidump comment stream recovered", category="memory_minidump_comment",
                confidence=0.86,
                explanation="A bounded self-contained MINIDUMP_COMMENT_STREAM was decoded without reading process-memory addresses.",
                evidence=[str(item)[:2_000] for item in minidump_comments[:20]], severity="info",
            ))
        minidump_modules = next(
            (value for value in context.values("memory.minidump.modules") if isinstance(value, list)), []
        )
        unusual_modules = [
            item for item in minidump_modules
            if isinstance(item, dict)
            and re.search(r"(?:\\(?:users|temp|programdata)\\|/tmp/|\bdownloads\b)", str(item.get("name") or ""), re.I)
        ]
        if unusual_modules:
            result.findings.append(self.finding(
                context, title="Minidump module inventory includes a user-writable path", category="memory_module_lead",
                confidence=0.76,
                explanation="A loaded module path points to a user-writable or temporary location, which is a triage lead rather than proof of malicious execution.",
                evidence=[str(item)[:2_000] for item in unusual_modules[:30]], severity="low",
            ))
        minidump_unloaded_modules = next(
            (value for value in context.values("memory.minidump.unloaded_modules") if isinstance(value, list)), []
        )
        suspicious_unloaded_modules = [
            item for item in minidump_unloaded_modules
            if isinstance(item, dict)
            and re.search(r"(?:\\(?:users|temp|programdata)\\|/tmp/|\bdownloads\b)", str(item.get("name") or ""), re.I)
        ]
        if suspicious_unloaded_modules:
            result.findings.append(self.finding(
                context, title="Minidump unloaded-module inventory includes a user-writable path", category="memory_unloaded_module_lead",
                confidence=0.78,
                explanation="An unloaded module path points to a user-writable or temporary location. It is a bounded dump-metadata lead and does not establish execution by itself.",
                evidence=[str(item)[:2_000] for item in suspicious_unloaded_modules[:30]], severity="low",
            ))
        minidump_handles = next(
            (value for value in context.values("memory.minidump.handles") if isinstance(value, list)), []
        )
        suspicious_file_handles = [
            item for item in minidump_handles
            if isinstance(item, dict)
            and str(item.get("type_name") or "").casefold() in {"file", "section"}
            and re.search(r"(?:\\(?:users|temp|programdata)\\|/tmp/|\bdownloads\b)", str(item.get("object_name") or ""), re.I)
        ]
        if suspicious_file_handles:
            result.findings.append(self.finding(
                context, title="Minidump handle table references a user-writable file", category="memory_handle_lead",
                confidence=0.8,
                explanation="A self-contained minidump handle descriptor names a File or Section object in a user-writable location. Correlate it with loaded modules and process context before drawing conclusions.",
                evidence=[str(item)[:2_000] for item in suspicious_file_handles[:30]], severity="low",
            ))
        minidump_threads = next(
            (value for value in context.values("memory.minidump.threads") if isinstance(value, list)), []
        )
        invalid_thread_locations = [
            item for item in minidump_threads
            if isinstance(item, dict)
            and (item.get("stack_within_image") is False or item.get("context_within_image") is False)
        ]
        if invalid_thread_locations:
            result.findings.append(self.finding(
                context, title="Minidump thread location descriptor exceeds evidence", category="memory_structure_anomaly",
                confidence=0.88,
                explanation="A bounded MINIDUMP_THREAD stack or context descriptor points outside the supplied file, consistent with truncation or malformed metadata.",
                evidence=[str(item)[:2_000] for item in invalid_thread_locations[:30]],
            ))
        minidump_ranges = next(
            (value for value in context.values("memory.minidump.memory_ranges") if isinstance(value, list)), []
        )
        invalid_memory_ranges = [
            item for item in minidump_ranges
            if isinstance(item, dict) and item.get("within_image") is False
        ]
        if invalid_memory_ranges:
            result.findings.append(self.finding(
                context, title="Minidump memory range descriptor exceeds evidence", category="memory_structure_anomaly",
                confidence=0.88,
                explanation="A bounded MINIDUMP_MEMORY_LIST descriptor references bytes outside the supplied file, so downstream memory content should not be trusted as complete.",
                evidence=[str(item)[:2_000] for item in invalid_memory_ranges[:30]],
            ))
        minidump_memory64_ranges = next(
            (value for value in context.values("memory.minidump.memory64_ranges") if isinstance(value, list)), []
        )
        invalid_memory64_ranges = [
            item for item in minidump_memory64_ranges
            if isinstance(item, dict) and item.get("within_image") is False
        ]
        if invalid_memory64_ranges:
            result.findings.append(self.finding(
                context, title="Minidump Memory64 range descriptor exceeds evidence", category="memory_structure_anomaly",
                confidence=0.88,
                explanation="A MINIDUMP_MEMORY64_LIST range extends beyond the supplied evidence, so its contiguous memory-data mapping is incomplete or malformed.",
                evidence=[str(item)[:2_000] for item in invalid_memory64_ranges[:30]],
            ))
        minidump_memory_info = next(
            (value for value in context.values("memory.minidump.memory_info_ranges") if isinstance(value, list)), []
        )
        rwx_regions = [
            item for item in minidump_memory_info
            if isinstance(item, dict)
            and item.get("state") == "commit"
            and item.get("protect") in {"execute_readwrite", "execute_writecopy"}
        ]
        if rwx_regions:
            result.findings.append(self.finding(
                context, title="Minidump metadata includes committed writable executable memory", category="memory_rwx_lead",
                confidence=0.8,
                explanation="MINIDUMP_MEMORY_INFO_LIST reports committed executable-and-writable regions. They are a useful injection/shellcode triage lead, but JIT engines and legitimate software can create them.",
                evidence=[str(item)[:2_000] for item in rwx_regions[:50]], severity="low",
            ))
        minidump_exception = next(
            (value for value in context.values("memory.minidump.exception") if isinstance(value, dict)), None
        )
        if minidump_exception:
            exception_evidence = [
                f"thread_id={minidump_exception.get('thread_id')}",
                f"exception={minidump_exception.get('name')} ({minidump_exception.get('code')})",
                f"address={minidump_exception.get('address')}",
            ]
            if minidump_exception.get("context_within_image") is False:
                exception_evidence.append("context_descriptor_outside_evidence=true")
            result.findings.append(self.finding(
                context, title="Windows minidump exception metadata recovered", category="memory_minidump_exception",
                confidence=0.9 if minidump_exception.get("context_within_image") is not False else 0.82,
                explanation="The bounded exception stream identifies the crashing thread, exception class, and fault address; CPU context bytes are intentionally left for a debugger or Volatility.",
                evidence=exception_evidence, severity="info",
            ))
        volatility_network = next(
            (value for value in context.values("memory.volatility.network") if isinstance(value, list)), []
        )
        external_connections = [
            item for item in volatility_network
            if isinstance(item, dict)
            and any(
                marker not in {"", "*", "0.0.0.0", "::", "127.0.0.1", "::1"}
                for key, marker in item.items()
                if "foreign" in str(key).lower() or "remote" in str(key).lower()
            )
        ]
        if external_connections:
            result.findings.append(self.finding(
                context, title="Memory analysis recovered non-local network connection metadata", category="memory_network_lead",
                confidence=0.8,
                explanation="A Volatility network plugin reported remote endpoint metadata. This is a bounded parser lead; inspect the preserved tool output for full column context.",
                evidence=[str(item)[:2_000] for item in external_connections[:50]], severity="low",
            ))
        volatility_commands = next(
            (value for value in context.values("memory.volatility.commands") if isinstance(value, list)), []
        )
        suspicious_commands = [
            item for item in volatility_commands
            if isinstance(item, dict) and re.search(r"(?:powershell|cmd(?:\.exe)?|wscript|cscript|curl|wget|base64|-enc(?:odedcommand)?)", str(item), re.I)
        ]
        if suspicious_commands:
            result.findings.append(self.finding(
                context, title="Memory analysis recovered execution-relevant command line", category="memory_command_lead",
                confidence=0.78,
                explanation="A Volatility command-line plugin emitted a command containing common scripting, download, or encoding terms. It is a triage lead, not an execution verdict.",
                evidence=[str(item)[:2_000] for item in suspicious_commands[:50]], severity="low",
            ))
        pslist_rows = next(
            (value for value in context.values("memory.volatility.pslist") if isinstance(value, list)), []
        )
        psscan_rows = next(
            (value for value in context.values("memory.volatility.psscan") if isinstance(value, list)), []
        )
        listed_pids = {
            str(item.get("PID") or item.get("Pid") or item.get("pid"))
            for item in pslist_rows if isinstance(item, dict) and (item.get("PID") or item.get("Pid") or item.get("pid"))
        }
        scan_only = [
            item for item in psscan_rows
            if isinstance(item, dict)
            and str(item.get("PID") or item.get("Pid") or item.get("pid")) not in listed_pids
        ]
        if scan_only:
            result.findings.append(self.finding(
                context, title="Volatility process scan found entries absent from process list", category="memory_hidden_process_lead",
                confidence=0.78,
                explanation="PsScan recovered process records whose PID is absent from PsList. This can indicate terminated, hidden, or inconsistent process metadata and requires time/context validation.",
                evidence=[str(item)[:2_000] for item in scan_only[:50]], severity="low",
            ))
        process_by_pid: dict[str, dict[str, object]] = {}
        for row in pslist_rows:
            if not isinstance(row, dict):
                continue
            pid = self._volatility_value(row, "pid")
            if pid:
                process_by_pid[pid] = row
        expected_parents = {
            "smss.exe": {"system"},
            "csrss.exe": {"smss.exe"},
            "wininit.exe": {"smss.exe"},
            "winlogon.exe": {"smss.exe"},
            "services.exe": {"wininit.exe"},
            "lsass.exe": {"wininit.exe"},
            "svchost.exe": {"services.exe"},
        }
        parent_mismatches: list[dict[str, str]] = []
        for pid, row in process_by_pid.items():
            name = (
                self._volatility_value(row, "name")
                or self._volatility_value(row, "imagefilename")
                or self._volatility_value(row, "process")
            )
            ppid = self._volatility_value(row, "ppid")
            if not name or not ppid or name.casefold() not in expected_parents:
                continue
            parent = process_by_pid.get(ppid)
            if parent is None:
                continue
            parent_name = (
                self._volatility_value(parent, "name")
                or self._volatility_value(parent, "imagefilename")
                or self._volatility_value(parent, "process")
            )
            if parent_name and parent_name.casefold() not in expected_parents[name.casefold()]:
                parent_mismatches.append({
                    "pid": pid,
                    "process": name,
                    "ppid": ppid,
                    "observed_parent": parent_name,
                    "expected_parent_names": ",".join(sorted(expected_parents[name.casefold()])),
                })
        if parent_mismatches:
            result.findings.append(self.finding(
                context,
                title="Windows process parent relationship differs from a narrow system-process rule",
                category="memory_parent_relationship_lead",
                confidence=0.78,
                explanation=(
                    "A PsList PID/PPID relationship for a well-known Windows system process does not "
                    "match the displayed expected parent-name rule. PID reuse, acquisition timing, and "
                    "OS-version differences must be checked; this is not a malware verdict."
                ),
                evidence=[str(item) for item in parent_mismatches[:50]],
                severity="low",
            ))
        process_path_leads = [
            row for row in pslist_rows
            if isinstance(row, dict)
            and any(
                str(key).casefold().replace(" ", "") in {
                    "path", "filepath", "imagepath", "auditimagefilename",
                }
                and re.search(
                    r"(?:\\(?:users|temp|programdata)\\|/tmp/|\bdownloads\b)",
                    str(value), re.I,
                )
                for key, value in row.items()
            )
        ]
        if process_path_leads:
            result.findings.append(self.finding(
                context,
                title="Memory process inventory includes a user-writable image path",
                category="memory_process_path_lead",
                confidence=0.76,
                explanation=(
                    "A normalized process row contains an image path under a commonly user-writable "
                    "location. The exact row and plugin output are retained for validation; path alone "
                    "does not establish malicious execution."
                ),
                evidence=[str(item)[:2_000] for item in process_path_leads[:50]],
                severity="low",
            ))
        volatility_files = next(
            (value for value in context.values("memory.volatility.files") if isinstance(value, list)), []
        )
        writable_files = [
            item for item in volatility_files
            if isinstance(item, dict) and re.search(r"(?:\\(?:users|temp|programdata)\\|/tmp/|\bdownloads\b)", str(item), re.I)
        ]
        if writable_files:
            result.findings.append(self.finding(
                context, title="Volatility file scan recovered user-writable path metadata", category="memory_file_lead",
                confidence=0.74,
                explanation="A FileScan row references a user-writable or temporary path. It is an artifact-correlation lead, not proof that a process executed the file.",
                evidence=[str(item)[:2_000] for item in writable_files[:50]], severity="low",
            ))
        dump_offsets: list[str] = []
        for item in volatility_files:
            if not isinstance(item, dict):
                continue
            offset = next((str(value) for key, value in item.items() if str(key).casefold() in {"offset", "offset(p)"}), "")
            if re.fullmatch(r"0x[0-9a-f]{1,16}", offset.casefold()) and offset not in dump_offsets:
                dump_offsets.append(offset)
            if len(dump_offsets) >= 16:
                break
        for offset in dump_offsets:
            result.recommendations.append(self.recommendation(
                "volatility3_windows_dumpfiles", (AnalysisMode.DEEP,),
                f"FileScan recovered file-object offset {offset}; bounded dumpfiles follow-up can promote emitted bytes into recursive evidence",
                72, command_mode="physaddr", parameters={"file_object_offset": offset},
            ))
        volatility_modules = next(
            (value for value in context.values("memory.volatility.modules") if isinstance(value, list)), []
        )
        writable_modules = [
            item for item in volatility_modules
            if isinstance(item, dict) and re.search(r"(?:\\(?:users|temp|programdata)\\|/tmp/|\bdownloads\b)", str(item), re.I)
        ]
        if writable_modules:
            result.findings.append(self.finding(
                context, title="Volatility DLL inventory includes a user-writable module path", category="memory_module_lead",
                confidence=0.78,
                explanation="A DLLList row names a loaded module in a user-writable or temporary location. Validate its process, hash, and surrounding execution evidence.",
                evidence=[str(item)[:2_000] for item in writable_modules[:50]], severity="low",
            ))
        malfind_rows = next(
            (value for value in context.values("memory.volatility.malfind") if isinstance(value, list)), []
        )
        if malfind_rows:
            result.findings.append(self.finding(
                context, title="Volatility Malfind reported executable memory regions", category="memory_malfind_lead",
                confidence=0.78,
                explanation="Malfind returned one or more process memory regions for review. These results are triage leads; inspect the preserved plugin output and correlate with process/module evidence.",
                evidence=[str(item)[:2_000] for item in malfind_rows[:50]], severity="low",
            ))
        process_rows = [
            item for value in context.values("memory.volatility.pslist", "memory.volatility.psscan", "memory.volatility.processes")
            if isinstance(value, list) for item in value if isinstance(item, dict)
        ]
        all_commands = [
            item for value in context.values("memory.volatility.commands")
            if isinstance(value, list) for item in value if isinstance(item, dict)
        ]
        all_network = [
            item for value in context.values("memory.volatility.network")
            if isinstance(value, list) for item in value if isinstance(item, dict)
        ]
        all_handles = [
            item for value in context.values("memory.volatility.handles")
            if isinstance(value, list) for item in value if isinstance(item, dict)
        ]
        all_modules = [
            item for value in context.values("memory.volatility.modules")
            if isinstance(value, list) for item in value if isinstance(item, dict)
        ]
        correlated: dict[str, dict[str, object]] = {}

        def pid_for(row: dict[str, object]) -> str | None:
            for key, value in row.items():
                if str(key).casefold() == "pid" and str(value).strip():
                    return str(value).strip()[:32]
            return None

        def attach(rows: list[dict[str, object]], field: str) -> None:
            for row in rows[:1_000]:
                pid = pid_for(row)
                if pid is None:
                    continue
                record = correlated.setdefault(pid, {"pid": pid})
                values = record.setdefault(field, [])
                if isinstance(values, list) and len(values) < 32:
                    values.append({str(key)[:200]: str(value)[:2_000] for key, value in row.items()})

        attach(process_rows, "processes")
        attach(all_commands, "commands")
        attach(all_network, "network")
        attach(all_handles, "handles")
        attach(all_modules, "modules")
        modules_by_pid_and_path: dict[tuple[str, str], list[dict[str, object]]] = {}
        for module in all_modules[:1_000]:
            pid = pid_for(module)
            module_path = self._volatility_path(module, "path")
            if pid is None or module_path is None:
                continue
            modules_by_pid_and_path.setdefault((pid, module_path), []).append(module)
        for handle in all_handles[:1_000]:
            pid = pid_for(handle)
            handle_type_raw = self._volatility_value(handle, "type")
            handle_type = handle_type_raw.casefold() if handle_type_raw else None
            handle_path = self._volatility_path(handle, "name", "path")
            if pid is None or handle_path is None or handle_type not in {"file", "section"}:
                continue
            matching_modules = modules_by_pid_and_path.get((pid, handle_path), [])
            if not matching_modules:
                continue
            record = correlated.setdefault(pid, {"pid": pid})
            matches = record.setdefault("module_handle_path_matches", [])
            if not isinstance(matches, list):
                continue
            for module in matching_modules:
                match = {
                    "path": handle_path,
                    "handle_type": handle_type,
                    "handle_name": self._volatility_value(handle, "name") or "",
                    "module_name": self._volatility_value(module, "name") or "",
                    "module_path": self._volatility_value(module, "path") or "",
                }
                if match not in matches and len(matches) < 32:
                    matches.append(match)
        records = sorted(correlated.values(), key=lambda item: item["pid"])[:256]
        if records:
            result.observations.append(self.observation(context, "memory.process_correlations", records, 0.85))
        high_signal = [
            item for item in records
            if len([key for key in ("commands", "network", "handles", "modules") if item.get(key)]) >= 3
        ]
        if high_signal:
            result.findings.append(self.finding(
                context, title="Memory evidence correlates multiple Volatility artifact classes to one process", category="memory_process_correlation_lead",
                confidence=0.82,
                explanation="PID-keyed process, command, network, handle, or module records overlap across normalized Volatility outputs. This is a correlation lead; inspect each preserved tool run before attribution.",
                evidence=[str(item)[:2_000] for item in high_signal[:50]], severity="low",
            ))
        module_handle_matches = [
            item for item in records if isinstance(item.get("module_handle_path_matches"), list)
            and item["module_handle_path_matches"]
        ]
        if module_handle_matches:
            result.findings.append(self.finding(
                context,
                title="Volatility handle and loaded-module paths correlate to a PID",
                category="memory_module_handle_correlation_lead",
                confidence=0.9,
                explanation=(
                    "A File or Section handle path exactly matches a DLLList module path under the same PID. "
                    "This is a process-scoped forensic lead based on preserved plugin rows, not proof of execution or injection."
                ),
                evidence=[str(item)[:2_000] for item in module_handle_matches[:50]],
                severity="low",
            ))
        return result

    @staticmethod
    def _volatility_value(row: dict[str, object], wanted_key: str) -> str | None:
        for key, value in row.items():
            if str(key).casefold() == wanted_key and str(value).strip():
                return str(value).strip()[:2_000]
        return None

    @classmethod
    def _volatility_path(cls, row: dict[str, object], *keys: str) -> str | None:
        for key in keys:
            value = cls._volatility_value(row, key)
            if value is None:
                continue
            # Volatility can prefix an NT path with ``\\??\\``.  Only normalize
            # this spelling and slash/case differences; broad basename matching
            # would create misleading process-to-module correlations.
            normalized = value.replace("/", "\\").casefold()
            if normalized.startswith("\\\\?\\"):
                normalized = normalized[4:]
            if normalized.startswith("\\??\\"):
                normalized = normalized[4:]
            return normalized
        return None
