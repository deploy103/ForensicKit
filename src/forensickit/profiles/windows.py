from __future__ import annotations

from datetime import UTC, datetime, timedelta
import re

from ..models import AnalysisMode, Observation
from .base import BaseProfile, ProfileContext, ProfileResult


_EVENT_ACTIVITY_WEIGHTS = {
    "logon_failure": 1,
    "explicit_credentials": 1,
    "privileged_logon": 1,
    "process_creation": 1,
    "powershell": 2,
    "service_install": 3,
    "scheduled_task_change": 2,
    "account_change": 2,
    "group_membership_change": 2,
    "rdp_authentication": 1,
    "log_cleared": 4,
    "defender_change": 3,
}


def _event_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # Never order timezone-free tool output by inventing a local timezone.
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _deduplicate_normalized_events(events: list[dict[str, object]]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for event in events[:10_000]:
        record_id = event.get("event_record_id")
        if isinstance(record_id, str) and record_id.isdigit():
            record_id = int(record_id)
        if isinstance(record_id, int):
            key: tuple[object, ...] = ("record", record_id)
        else:
            key = (
                "fields", event.get("event_id"), event.get("timestamp"),
                event.get("category"), event.get("target_user"), event.get("source_ip"),
                event.get("process_path"), event.get("service_name"), event.get("task_name"),
            )
        if key in seen:
            continue
        seen.add(key)
        output.append(event)
    return output


def _windows_event_activity_clusters(
    events: list[dict[str, object]],
    record_headers: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Sessionize explicit UTC/offset timestamps and score only evidenced event classes."""
    header_by_id = {
        item.get("record_id"): item
        for item in record_headers
        if isinstance(item, dict) and isinstance(item.get("record_id"), int)
    }
    timed = [
        (timestamp, event)
        for event in _deduplicate_normalized_events(events)
        if (timestamp := _event_datetime(event.get("timestamp"))) is not None
        and event.get("category") != "other"
    ]
    timed.sort(key=lambda item: (
        item[0], str(item[1].get("event_record_id", "")),
        int(item[1].get("source_record_index", 0) or 0),
    ))
    sessions: list[list[tuple[datetime, dict[str, object]]]] = []
    current: list[tuple[datetime, dict[str, object]]] = []
    for timestamp, event in timed:
        if current and (
            timestamp - current[-1][0] > timedelta(minutes=15)
            or timestamp - current[0][0] > timedelta(hours=1)
        ):
            sessions.append(current)
            current = []
        current.append((timestamp, event))
    if current:
        sessions.append(current)

    output: list[dict[str, object]] = []
    for session in sessions:
        if len(session) < 2:
            continue
        category_counts: dict[str, int] = {}
        for _, event in session:
            category = str(event.get("category"))
            category_counts[category] = category_counts.get(category, 0) + 1
        score = sum(
            _EVENT_ACTIVITY_WEIGHTS.get(category, 0) * min(count, 2)
            for category, count in category_counts.items()
        )
        reasons = [
            f"{category} x{count} contributed {_EVENT_ACTIVITY_WEIGHTS.get(category, 0) * min(count, 2)}"
            for category, count in sorted(category_counts.items())
            if _EVENT_ACTIVITY_WEIGHTS.get(category, 0)
        ]
        categories = set(category_counts)
        failure_positions = [
            index for index, (_, event) in enumerate(session)
            if event.get("category") == "logon_failure"
        ]
        success_positions = [
            index for index, (_, event) in enumerate(session)
            if event.get("category") == "logon_success"
        ]
        if len(failure_positions) >= 3 and any(
            index > failure_positions[2] for index in success_positions
        ):
            score += 3
            reasons.append("three or more failed logons followed by a nearby successful logon contributed 3")
        if "process_creation" in categories and categories & {"service_install", "scheduled_task_change"}:
            score += 4
            reasons.append("process creation and a nearby service/task persistence event contributed 4")
        if {"powershell", "process_creation"} <= categories:
            score += 2
            reasons.append("PowerShell and process creation in the same activity window contributed 2")
        if "log_cleared" in categories and categories & {"process_creation", "service_install", "scheduled_task_change", "powershell"}:
            score += 4
            reasons.append("log clearing near execution or persistence activity contributed 4")
        if "defender_change" in categories and "process_creation" in categories:
            score += 3
            reasons.append("Defender configuration change near process creation contributed 3")
        score = min(score, 20)
        level = "high" if score >= 14 else "elevated" if score >= 9 else "notable" if score >= 5 else "context"
        event_refs: list[dict[str, object]] = []
        for timestamp, event in session[:100]:
            record_id = event.get("event_record_id")
            if isinstance(record_id, str) and record_id.isdigit():
                record_id = int(record_id)
            header = header_by_id.get(record_id, {})
            reference = {
                "timestamp_utc": timestamp.isoformat(),
                "event_id": event.get("event_id"),
                "category": event.get("category"),
                "event_record_id": record_id,
                "record_offset": header.get("offset"),
                "source_record_index": event.get("source_record_index"),
            }
            for key in (
                "user", "target_user", "source_ip", "destination_ip", "process_id",
                "parent_process_id", "process_path", "command_line", "service_name", "task_name",
            ):
                if event.get(key) not in {None, ""}:
                    reference[key] = event[key]
            event_refs.append(reference)
        output.append({
            "start_utc": session[0][0].isoformat(),
            "end_utc": session[-1][0].isoformat(),
            "event_count": len(session),
            "category_counts": dict(sorted(category_counts.items())),
            "score": score,
            "level": level,
            "score_reasons": reasons,
            "events": event_refs,
        })
        if len(output) >= 200:
            break
    return output


def _usn_rename_pairs(records: list[dict[str, object]]) -> list[dict[str, object]]:
    """Pair only physically adjacent old/new V2 records with exact FRN lineage."""
    pairs: list[dict[str, object]] = []
    for old, new in zip(records[:9_999], records[1:10_000]):
        old_reasons = old.get("reason_names")
        new_reasons = new.get("reason_names")
        old_usn, new_usn = old.get("usn"), new.get("usn")
        old_length = old.get("record_length")
        file_record = old.get("file_record_number")
        file_sequence = old.get("file_sequence_number")
        if (
            not isinstance(old_reasons, list) or "rename_old_name" not in old_reasons
            or not isinstance(new_reasons, list) or "rename_new_name" not in new_reasons
            or not isinstance(old_usn, int) or not isinstance(new_usn, int)
            or not isinstance(old_length, int) or new_usn != old_usn + old_length
            or not isinstance(file_record, int) or not isinstance(file_sequence, int)
            or file_record != new.get("file_record_number")
            or file_sequence != new.get("file_sequence_number")
        ):
            continue
        pairs.append({
            "file_record_number": old.get("file_record_number"),
            "file_sequence_number": old.get("file_sequence_number"),
            "old_name": old.get("file_name"),
            "new_name": new.get("file_name"),
            "old_parent_record_number": old.get("parent_record_number"),
            "old_parent_sequence_number": old.get("parent_sequence_number"),
            "new_parent_record_number": new.get("parent_record_number"),
            "new_parent_sequence_number": new.get("parent_sequence_number"),
            "old_usn": old_usn,
            "new_usn": new_usn,
            "old_offset": old.get("offset"),
            "new_offset": new.get("offset"),
            "old_timestamp": old.get("timestamp"),
            "new_timestamp": new.get("timestamp"),
        })
        if len(pairs) >= 2_000:
            break
    return pairs


class WindowsProfile(BaseProfile):
    name = "windows"
    priority = 740

    def match_reasons(self, context: ProfileContext) -> list[str]:
        if context.classified_as("evtx", "registry", "windows"):
            return ["Windows artifact signature classification is present"]
        if context.truthy("windows.evtx_signature", "windows.registry_signature", "windows.lnk_signature", "windows.prefetch_signature", "windows.jumplist_signature"):
            return ["Windows artifact structure marker is present"]
        if context.truthy("ntfs.usn_journal_detected"):
            return ["Explicitly named NTFS `$UsnJrnl:$J` stream was parsed"]
        return []

    def analyze(self, context: ProfileContext) -> ProfileResult:
        result = ProfileResult(profile=self.name, matched=True)
        jump_list_kind = next(
            (value for value in context.values("jumplist.kind") if isinstance(value, str)), None
        )
        jump_list_destinations = next(
            (value for value in context.values("jumplist.destinations") if isinstance(value, list)), []
        )
        jump_list_streams = next(
            (value for value in context.values("jumplist.link_streams") if isinstance(value, list)), []
        )
        if context.truthy("jumplist.valid") and jump_list_kind:
            application_id = next(
                (value for value in context.values("jumplist.application_id") if isinstance(value, str)), None
            )
            evidence = [f"kind={jump_list_kind}"]
            if application_id:
                evidence.append(f"application_id={application_id}")
            evidence.extend(str(item)[:2_000] for item in jump_list_destinations[:100])
            evidence.extend(str(item)[:2_000] for item in jump_list_streams[:100])
            result.findings.append(self.finding(
                context,
                title="Windows Jump List records recovered",
                category="windows_jumplist",
                confidence=0.92,
                explanation=(
                    "A structurally validated Automatic Destinations CFB/DestList or Custom Destinations shortcut sequence was parsed. "
                    "Paths and access times are application-maintained usage leads, not proof that a target was executed. Embedded shortcuts can be extracted for ordinary LNK analysis."
                ),
                evidence=evidence,
                severity="info",
            ))
        usn_records = next(
            (value for value in context.values("ntfs.usn.records") if isinstance(value, list)), []
        )
        if usn_records:
            result.findings.append(self.finding(
                context,
                title=f"{len(usn_records)} bounded NTFS change-journal record(s) recovered",
                category="ntfs_usn_journal_inventory", confidence=0.94,
                explanation=(
                    "Aligned USN_RECORD_V2/V3/V4 structures were parsed from bounded beginning/end windows of an explicitly named `$UsnJrnl:$J` child. "
                    "Each event retains its exact stream offset and version-appropriate fields: V2/V3 timestamps and names, or V4 range extents, plus exact identifiers, USN, reason, and source metadata. Missing version fields and paths are not inferred."
                ),
                evidence=[str(item)[:2_000] for item in usn_records[:128]], severity="info",
            ))
            rename_pairs = _usn_rename_pairs([
                item for item in usn_records if isinstance(item, dict)
            ])
            if rename_pairs:
                result.observations.append(Observation(
                    artifact_id=context.artifact.id,
                    key="ntfs.usn.rename_pairs",
                    value=rename_pairs,
                    source="profile:windows",
                    confidence=0.94,
                ))
                result.findings.append(self.finding(
                    context,
                    title=f"{len(rename_pairs)} exact NTFS journal rename pair(s) correlated",
                    category="ntfs_usn_rename", confidence=0.94,
                    explanation=(
                        "A rename-old record was immediately followed by a rename-new record whose USN begins exactly after the old record length and whose file record/sequence are identical. "
                        "Both names, parents, timestamps, USNs, and stream offsets are retained; no full path is inferred."
                    ),
                    evidence=[str(item)[:2_000] for item in rename_pairs[:128]],
                    severity="info",
                ))
        if context.classified_as("evtx") or context.truthy("windows.evtx_signature"):
            result.recommendations.extend([
                self.recommendation("hayabusa", (AnalysisMode.DEEP,), "deep EVTX timeline and Sigma analysis", 100),
                self.recommendation("chainsaw", (AnalysisMode.AUTO, AnalysisMode.DEEP), "structured EVTX hunting and dump", 110),
            ])
            chunks = context.number("evtx.chunk_count")
            next_record = context.number("evtx.next_record_identifier")
            if chunks is not None or next_record is not None:
                evidence = []
                if chunks is not None:
                    evidence.append(f"chunk_count={int(chunks)}")
                if next_record is not None:
                    evidence.append(f"next_record_identifier={int(next_record)}")
                result.findings.append(
                    self.finding(
                        context,
                        title="EVTX file header inventory recovered",
                        category="evtx_header",
                        confidence=0.9,
                        explanation="Native EVTX header counters provide a bounded structural lead before external event parsing.",
                        evidence=evidence,
                        severity="info",
                    )
                )
            chunk_headers = next((value for value in context.values("evtx.chunk_headers") if isinstance(value, list)), [])
            invalid_chunks = [item for item in chunk_headers if isinstance(item, dict) and not item.get("layout_valid", False)]
            if invalid_chunks:
                result.findings.append(self.finding(
                    context, title="EVTX chunk header has inconsistent record/free-space bounds", category="evtx_structure_anomaly",
                    confidence=0.9,
                    explanation="A fixed EVTX chunk header declared invalid record or free-space offsets; the log may be truncated or structurally damaged.",
                    evidence=[str(item)[:1_500] for item in invalid_chunks[:30]],
                ))
            record_headers = next((value for value in context.values("evtx.record_headers") if isinstance(value, list)), [])
            if record_headers:
                result.findings.append(self.finding(
                    context, title="Bounded EVTX record headers recovered", category="evtx_record_inventory",
                    confidence=0.88,
                    explanation="Native framing validation recovered record IDs, FILETIME timestamps, sizes, and exact file offsets without attempting untrusted BinXML decoding.",
                    evidence=[str(item)[:1_500] for item in record_headers[:50]], severity="info",
                ))
            record_id_gaps = next((value for value in context.values("evtx.record_id_gaps") if isinstance(value, list)), [])
            if record_id_gaps:
                result.findings.append(self.finding(
                    context, title="EVTX record identifiers are discontinuous", category="evtx_record_continuity_anomaly",
                    confidence=0.72, explanation="Bounded valid record framing shows non-sequential record IDs. This can arise from cleared, exported, damaged, or partial logs and requires external verification.",
                    evidence=[str(item)[:1_500] for item in record_id_gaps[:50]], severity="low",
                ))
            normalized_events = [
                item
                for batch in context.values(
                    "windows.event_hunt.normalized_events",
                    "windows.event_timeline.normalized_events",
                )
                if isinstance(batch, list)
                for item in batch
                if isinstance(item, dict)
            ][:5_000]
            if normalized_events and record_headers and not context.exists("evtx.normalized_record_correlations"):
                headers_by_id = {
                    item.get("record_id"): item
                    for item in record_headers
                    if isinstance(item, dict) and isinstance(item.get("record_id"), int)
                }
                correlations: list[dict[str, object]] = []
                for event in normalized_events:
                    event_record_id = event.get("event_record_id")
                    if isinstance(event_record_id, str) and event_record_id.isdigit():
                        event_record_id = int(event_record_id)
                    header = headers_by_id.get(event_record_id)
                    if header is None:
                        continue
                    correlations.append({
                        "event_record_id": event_record_id,
                        "event_id": event.get("event_id"),
                        "category": event.get("category"),
                        "record_offset": header.get("offset"),
                        "record_size": header.get("size"),
                        "chunk_index": header.get("chunk_index"),
                        "native_timestamp": header.get("timestamp"),
                        "parser_timestamp": event.get("timestamp"),
                        "source_record_index": event.get("source_record_index"),
                    })
                    if len(correlations) >= 500:
                        break
                if correlations:
                    result.observations.append(Observation(
                        artifact_id=context.artifact.id,
                        key="evtx.normalized_record_correlations",
                        value=correlations,
                        source="profile:windows",
                        confidence=0.94,
                    ))
                    result.findings.append(self.finding(
                        context,
                        title="Normalized EVTX records correlated to native byte offsets",
                        category="evtx_record_content_correlation",
                        confidence=0.94,
                        explanation=(
                            "Structured parser records were joined to independently framed native EVTX records only by exact EventRecordID. "
                            "Each lead retains the immutable file offset, framed size, chunk index, Event ID, and both timestamp sources."
                        ),
                        evidence=[str(item)[:1_500] for item in correlations[:50]],
                        severity="info",
                    ))
            if normalized_events and not context.exists("windows.event_activity_clusters"):
                clusters = _windows_event_activity_clusters(normalized_events, record_headers)
                if clusters:
                    result.observations.append(Observation(
                        artifact_id=context.artifact.id,
                        key="windows.event_activity_clusters",
                        value=clusters,
                        source="profile:windows",
                        confidence=0.88,
                    ))
                    notable = [item for item in clusters if int(item.get("score", 0)) >= 5]
                    if notable:
                        ranked = sorted(
                            notable,
                            key=lambda item: (-int(item.get("score", 0)), str(item.get("start_utc", ""))),
                        )
                        maximum_score = int(ranked[0].get("score", 0))
                        result.findings.append(self.finding(
                            context,
                            title=f"{len(notable)} evidence-weighted Windows activity cluster(s) require review",
                            category="windows_event_activity_cluster",
                            confidence=0.84,
                            explanation=(
                                "Normalized events with explicit timezone-aware timestamps were grouped only across gaps of at most 15 minutes "
                                "and windows of at most one hour. The bounded score is an explainable prioritization aid, not a maliciousness verdict."
                            ),
                            evidence=[str(item)[:2_000] for item in ranked[:20]],
                            severity="high" if maximum_score >= 14 else "medium" if maximum_score >= 9 else "low",
                        ))
        if context.classified_as("registry") or context.truthy("windows.registry_signature"):
            result.recommendations.append(self.recommendation("regripper", (AnalysisMode.AUTO, AnalysisMode.DEEP), "Registry hive plugin analysis", 110))
            mismatch = context.truthy("registry.sequence_mismatch")
            root_name = next((value for value in context.values("registry.root_key_name") if isinstance(value, str) and value), None)
            if mismatch:
                result.findings.append(self.finding(
                    context, title="Registry hive sequence numbers do not match", category="registry_recovery_lead",
                    confidence=0.9,
                    explanation="Primary and secondary sequence numbers differ, indicating the hive may require transaction-log recovery before final interpretation.",
                    evidence=["registry.sequence_mismatch=true"],
                ))
            if root_name:
                result.findings.append(self.finding(
                    context, title="Registry root key metadata recovered", category="registry_root_key",
                    confidence=0.88,
                    explanation="The base block's root NK cell was structurally parsed without enumerating untrusted subkey lists.",
                    evidence=[f"root_key={root_name}"], severity="info",
                ))
            root_values = next(
                (value for value in context.values("registry.root_values") if isinstance(value, list)), []
            )
            child_values = next(
                (value for value in context.values("registry.root_child_values") if isinstance(value, list)), []
            )
            execution_value_names = {
                "run", "runonce", "runonceex", "load", "shell", "userinit",
                "debugger", "startup", "powershell", "command",
            }
            execution_values = [
                item for item in [*root_values, *child_values]
                if isinstance(item, dict)
                and (
                    str(item.get("name", "")).strip().lower() in execution_value_names
                    or str(item.get("key", "")).strip().lower() in execution_value_names
                )
            ]
            if execution_values:
                result.findings.append(self.finding(
                    context,
                    title="Registry value inventory contains execution-relevant name",
                    category="registry_execution_lead",
                    confidence=0.72,
                    explanation=(
                        "Bounded root/direct-child VK metadata parsing recovered value names commonly used by persistence or execution settings. "
                        "The value data and full key path are intentionally not inferred during generic triage; use RegRipper for confirmation."
                    ),
                    evidence=[str(item)[:1_000] for item in execution_values[:30]],
                    severity="low",
                ))
            recovered_execution_data = next(
                (value for value in context.values("registry.execution_value_data") if isinstance(value, list)), []
            )
            if recovered_execution_data:
                command_evidence: list[str] = []
                for item in recovered_execution_data[:30]:
                    if not isinstance(item, dict):
                        command_evidence.append(str(item)[:2_000])
                        continue
                    key_path = str(item.get("key_path") or item.get("key") or "(unknown key)")
                    value_name = str(item.get("name") or "(Default)")
                    value_data = item.get("data_text")
                    if isinstance(value_data, list):
                        rendered_data = " | ".join(str(entry) for entry in value_data[:32])
                    else:
                        rendered_data = str(value_data)
                    command_evidence.append(f"{key_path}\\{value_name} = {rendered_data}"[:2_000])
                result.findings.append(self.finding(
                    context,
                    title="Registry execution-key command data recovered",
                    category="registry_execution_command",
                    confidence=0.9,
                    explanation=(
                        "A bounded, allocated Registry value-data cell under an allowlisted execution-relevant key path was decoded as REG_SZ-like text. "
                        "The result is a triage lead; confirm key path and transaction-log state with RegRipper."
                    ),
                    evidence=command_evidence,
                    severity="medium",
                ))
            amcache_records = next(
                (value for value in context.values("registry.amcache.records") if isinstance(value, list)), []
            )
            if amcache_records:
                kinds: dict[str, int] = {}
                for record in amcache_records:
                    if isinstance(record, dict):
                        kind = str(record.get("record_kind") or "unknown")
                        kinds[kind] = kinds.get(kind, 0) + 1
                result.findings.append(self.finding(
                    context,
                    title=f"{len(amcache_records)} bounded Amcache record(s) recovered",
                    category="windows_amcache_inventory",
                    confidence=0.9,
                    explanation=(
                        "Fixed, structurally resolved Amcache key paths supplied application/file inventory values, Registry cell offsets, and raw key last-write FILETIMEs. "
                        "Amcache presence can support that Windows inventoried a program or file, but does not by itself prove execution; a key last-write time is not treated as an execution time."
                    ),
                    evidence=[f"record_kinds={kinds}", *[str(item)[:2_000] for item in amcache_records[:100]]],
                    severity="info",
                ))
            shimcache_records = next(
                (value for value in context.values("registry.shimcache.records") if isinstance(value, list)), []
            )
            shimcache_detected = context.truthy("registry.shimcache.detected")
            if shimcache_records:
                result.findings.append(self.finding(
                    context,
                    title=f"{len(shimcache_records)} bounded Shimcache record(s) recovered",
                    category="windows_shimcache_inventory",
                    confidence=0.88,
                    explanation=(
                        "A fixed SYSTEM\\ControlSet*\\Control\\Session Manager\\AppCompatCache path and an allocated REG_BINARY value contained bounded 00ts/10ts entries. "
                        "The cached path and file last-modified FILETIME are retained with byte offsets. Entry presence, order, and timestamps do not alone prove execution or provide an execution time."
                    ),
                    evidence=[str(item)[:2_000] for item in shimcache_records[:100]],
                    severity="info",
                ))
            elif shimcache_detected:
                activity_errors = next(
                    (value for value in context.values("registry.activity_errors") if isinstance(value, list)), []
                )
                result.findings.append(self.finding(
                    context,
                    title="AppCompatCache value requires another Shimcache format parser",
                    category="windows_shimcache_unsupported_layout",
                    confidence=0.86,
                    explanation=(
                        "The fixed AppCompatCache Registry path and value were present, but the native bounded reader did not recognize a supported 00ts/10ts layout. "
                        "Use a compatible offline Registry/Registry Explorer or validated Shimcache parser and preserve the transaction-log state."
                    ),
                    evidence=[str(item)[:2_000] for item in activity_errors[:30]],
                    severity="low",
                ))
        recycle_bin_valid = next(
            (value for value in context.values("windows.recycle_bin_valid") if isinstance(value, bool)), None
        )
        if recycle_bin_valid:
            original_path = next(
                (value for value in context.values("windows.recycle_bin_original_path") if isinstance(value, str)), ""
            )
            original_size = context.number("windows.recycle_bin_original_size")
            deletion_time = next(
                (value for value in context.values("windows.recycle_bin_deletion_time") if isinstance(value, str) and value), None
            )
            evidence = [f"original_path={original_path}"]
            if original_size is not None:
                evidence.append(f"original_size={int(original_size)}")
            if deletion_time:
                evidence.append(f"deletion_time={deletion_time}")
            result.findings.append(self.finding(
                context, title="Windows Recycle Bin deletion metadata recovered", category="windows_recycle_bin",
                confidence=0.94,
                explanation="A bounded $I record decoded the original path, logical size, and deletion time. The paired $R content is not inferred or opened automatically.",
                evidence=evidence, severity="info",
            ))
        link_flags = next((value for value in context.values("lnk.link_flags") if isinstance(value, list)), [])
        if link_flags:
            result.findings.append(
                self.finding(
                    context,
                    title="Windows shortcut metadata recovered",
                    category="windows_lnk",
                    confidence=0.9,
                    explanation="The Shell Link header was structurally valid and exposes target-resolution fields for timeline review.",
                    evidence=[str(flag) for flag in link_flags[:30]],
                    severity="info",
                )
            )
            suspicious_link_flags = {"has_arguments", "run_with_shim_layer", "prefer_environment_path"}
            matched = [flag for flag in link_flags if flag in suspicious_link_flags]
            if matched:
                result.findings.append(
                    self.finding(
                        context,
                        title="Windows shortcut has execution-relevant link flags",
                        category="windows_lnk_execution",
                        confidence=0.78,
                        explanation="Arguments, shim-layer use, or environment-path preference can materially change shortcut execution and should be inspected in the full LinkInfo/StringData structures.",
                        evidence=matched,
                    )
                )
        arguments = next((value for value in context.values("lnk.arguments") if isinstance(value, str) and value), None)
        if arguments and re.search(r"(?:-encodedcommand|powershell|wscript|cscript|mshta|rundll32)", arguments, re.I):
            result.findings.append(self.finding(
                context, title="Windows shortcut arguments contain execution-relevant command", category="windows_lnk_execution",
                confidence=0.86,
                explanation="Bounded Shell Link StringData parsing recovered arguments associated with script or command execution. Validate the target and surrounding timeline context.",
                evidence=[arguments[:2_000]],
            ))
        target_path = next((value for value in context.values("lnk.target_path") if isinstance(value, str) and value), None)
        if target_path:
            result.findings.append(self.finding(
                context, title="Windows shortcut LinkInfo target path recovered", category="windows_lnk_target",
                confidence=0.9,
                explanation="A bounded LinkInfo structure supplied a local base path and common suffix. The target was decoded from the shortcut metadata without opening or executing it.",
                evidence=[target_path[:2_000]], severity="info",
            ))
        executable = next((value for value in context.values("prefetch.executable_name") if isinstance(value, str) and value), None)
        if executable:
            run_count = context.number("prefetch.run_count")
            size_matches = context.truthy("prefetch.size_matches_evidence")
            evidence = [f"executable={executable}"]
            if run_count is not None:
                evidence.append(f"run_count={int(run_count)}")
            result.findings.append(
                self.finding(
                    context,
                    title="Windows Prefetch execution record identified",
                    category="windows_prefetch",
                    confidence=0.85,
                    explanation="Prefetch header metadata identifies an executable that Windows recorded for launch optimization; validate timestamps with a dedicated parser when available.",
                    evidence=evidence,
                    severity="info",
                )
            )
            if not size_matches:
                result.findings.append(self.finding(
                    context, title="Prefetch declared size differs from supplied evidence", category="windows_prefetch_structure_anomaly",
                    confidence=0.82, explanation="The Prefetch header's declared file size differs from the immutable evidence size; this can indicate truncation, corruption, or an incomplete copy.",
                    evidence=[f"declared={int(context.number('prefetch.declared_file_size') or 0)}", f"actual={context.artifact.size}"], severity="low",
                ))
        return result
