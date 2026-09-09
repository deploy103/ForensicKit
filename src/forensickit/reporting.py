from __future__ import annotations

import csv
import html
import json
from dataclasses import asdict
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .workspace import CaseWorkspace
from .graph import ArtifactGraph


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_value(item) for item in value]
    return value


class ReportGenerator:
    _TIMELINE_FIELDS = (
        "artifact_id", "artifact_name", "timestamp", "timestamp_utc", "event_id",
        "category", "event_record_id", "record_offset", "record_hive_offset", "record_size", "chunk_index",
        "provider", "channel", "computer", "user", "target_user", "process_id",
        "parent_process_id", "process_path", "command_line", "source_ip", "destination_ip",
        "service_name", "task_name", "cluster_start_utc", "cluster_end_utc", "cluster_score",
        "cluster_level", "source_record_index", "sources", "source_observation_ids",
        "tool_run_ids", "raw_stdout_paths", "usn", "reason", "reason_names",
        "file_record_number", "file_sequence_number", "parent_record_number",
        "parent_sequence_number", "file_name", "file_attributes", "source_info", "security_id",
        "file_id_128", "parent_file_id_128",
        "mft_artifact_id", "mft_artifact_name", "mft_observation_id",
        "sample_file_names", "sample_deleted", "sample_physical_segments",
        "remaining_extents", "number_of_extents", "extent_size", "extents",
        "record_kind", "browser_family", "table", "row_id", "url", "title",
        "path", "search_term", "timestamp_raw", "timestamp_basis", "application_id",
        "registry_key_path", "registry_value_name", "registry_cache_format",
        "registry_record_name", "registry_program_id", "registry_file_id",
    )

    def generate(self, workspace: CaseWorkspace) -> tuple[Path, Path]:
        database = workspace.database
        case = workspace.case
        artifacts = database.artifacts()
        observations = database.observations()
        findings = database.findings()
        hypotheses = database.hypotheses()
        verifications = database.verifications()
        runs = database.tool_runs()
        flags = database.flags()
        search_hits = database.search_hits()
        errors = database.errors()
        graph = ArtifactGraph(artifacts)
        report = _json_value(
            {
                "schema_version": 4,
                "case": asdict(case),
                "artifacts": [asdict(item) for item in artifacts],
                "observations": [asdict(item) for item in observations],
                "hypotheses": [asdict(item) for item in hypotheses],
                "verifications": [asdict(item) for item in verifications],
                "findings": [asdict(item) for item in findings],
                "tool_runs": [asdict(item) for item in runs],
                "flag_candidates": [asdict(item) for item in flags],
                "search_hits": [asdict(item) for item in search_hits],
                "errors": [asdict(item) for item in errors],
                "artifact_graph": graph.as_mapping(),
            }
        )
        report["timeline"] = self._timeline_rows(report)
        json_path = workspace.path("reports", "report.json")
        markdown_path = workspace.path("reports", "report.md")
        timeline_path = workspace.path("reports", "timeline.csv")
        search_path = workspace.path("reports", "search_results.csv")
        html_path = workspace.path("reports", "report.html")
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        markdown_path.write_text(self._markdown(report), encoding="utf-8")
        html_path.write_text(self._html(report), encoding="utf-8")
        with timeline_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self._TIMELINE_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in report["timeline"]:
                writer.writerow({
                    key: self._csv_safe(row.get(key, "")) for key in self._TIMELINE_FIELDS
                })
        self._write_search_csv(search_path, report)
        return json_path, markdown_path

    @classmethod
    def _write_search_csv(cls, path: Path, report: dict[str, Any]) -> None:
        fields = (
            "result_type", "match_type", "query", "value", "status",
            "artifact_id", "origin_path", "discovered_path", "source_kind",
            "source", "location", "offset", "encoding", "transform_chain", "context",
        )
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for result_type, records in (
                ("flag_candidate", report.get("flag_candidates", [])),
                ("search_hit", report.get("search_hits", [])),
            ):
                for record in records:
                    locations = record.get("locations") or [record]
                    for location in locations:
                        row = {
                            "result_type": result_type,
                            "match_type": record.get("match_type", "flag"),
                            "query": record.get("query", ""),
                            "value": record.get("value", ""),
                            "status": record.get("status", ""),
                            "artifact_id": location.get("artifact_id", record.get("artifact_id", "")),
                            "origin_path": location.get("origin_path", record.get("origin_path", "")),
                            "discovered_path": location.get("discovered_path", record.get("discovered_path", "")),
                            "source_kind": location.get("source_kind", record.get("source_kind", "")),
                            "source": location.get("source", record.get("source", "")),
                            "location": location.get("location", record.get("location", "")),
                            "offset": location.get("offset", record.get("offset", "")),
                            "encoding": location.get("encoding", record.get("encoding", "")),
                            "transform_chain": " -> ".join(location.get("transform_chain", record.get("transform_chain", []))),
                            "context": location.get("context", record.get("context", "")),
                        }
                        writer.writerow({key: cls._csv_safe(value) for key, value in row.items()})

    @staticmethod
    def _event_identity(artifact_id: object, event: dict[str, Any]) -> tuple[object, ...]:
        record_id = event.get("event_record_id")
        if isinstance(record_id, str) and record_id.isdigit():
            record_id = int(record_id)
        if isinstance(record_id, int):
            return (artifact_id, "record", record_id)
        return (
            artifact_id, "fields", event.get("event_id"), event.get("timestamp") or event.get("timestamp_utc"),
            event.get("category"), event.get("target_user"), event.get("source_ip"),
            event.get("process_path"), event.get("service_name"), event.get("task_name"),
        )

    @staticmethod
    def _utc_timestamp(value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            return ""
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return ""
        if parsed.tzinfo is None:
            return ""
        return parsed.astimezone(UTC).isoformat()

    @classmethod
    def _timeline_rows(cls, report: dict[str, Any]) -> list[dict[str, Any]]:
        artifacts = {
            item.get("id"): item.get("logical_name", "")
            for item in report.get("artifacts", []) if isinstance(item, dict)
        }
        runs = {
            item.get("id"): item
            for item in report.get("tool_runs", []) if isinstance(item, dict)
        }
        correlations: dict[tuple[object, ...], dict[str, Any]] = {}
        usn_mft_correlations: dict[tuple[object, ...], tuple[dict[str, Any], dict[str, Any]]] = {}
        cluster_membership: dict[tuple[object, ...], dict[str, Any]] = {}
        for observation in report.get("observations", []):
            if not isinstance(observation, dict):
                continue
            artifact_id = observation.get("artifact_id")
            value = observation.get("value")
            if observation.get("key") == "evtx.normalized_record_correlations" and isinstance(value, list):
                for item in value[:500]:
                    if not isinstance(item, dict):
                        continue
                    correlations[cls._event_identity(artifact_id, item)] = item
            elif observation.get("key") == "correlation.usn_sampled_mft" and isinstance(value, list):
                for item in value[:2_000]:
                    if not isinstance(item, dict):
                        continue
                    identity = (
                        item.get("journal_artifact_id") or artifact_id,
                        "usn", item.get("usn"), item.get("journal_offset"),
                    )
                    usn_mft_correlations[identity] = (item, observation)
            elif observation.get("key") == "windows.event_activity_clusters" and isinstance(value, list):
                for cluster in value[:200]:
                    if not isinstance(cluster, dict) or not isinstance(cluster.get("events"), list):
                        continue
                    membership = {
                        "cluster_start_utc": cluster.get("start_utc"),
                        "cluster_end_utc": cluster.get("end_utc"),
                        "cluster_score": cluster.get("score"),
                        "cluster_level": cluster.get("level"),
                    }
                    for event in cluster["events"][:100]:
                        if isinstance(event, dict):
                            cluster_membership[cls._event_identity(artifact_id, event)] = {
                                **membership, "timestamp_utc": event.get("timestamp_utc"),
                            }

        rows_by_identity: dict[tuple[object, ...], dict[str, Any]] = {}
        source_lists: dict[tuple[object, ...], dict[str, list[str]]] = {}
        normalized_keys = {
            "windows.event_hunt.normalized_events",
            "windows.event_timeline.normalized_events",
        }
        copied_fields = set(cls._TIMELINE_FIELDS) - {
            "artifact_id", "artifact_name", "timestamp_utc", "sources",
            "source_observation_ids", "tool_run_ids", "raw_stdout_paths",
            "cluster_start_utc", "cluster_end_utc", "cluster_score", "cluster_level",
        }
        for observation in report.get("observations", []):
            if not isinstance(observation, dict) or observation.get("key") not in normalized_keys:
                continue
            events = observation.get("value")
            if not isinstance(events, list):
                continue
            artifact_id = observation.get("artifact_id")
            source = str(observation.get("source") or "")
            source_parts = source.rsplit(":", 1)
            run_id = source_parts[-1] if len(source_parts) == 2 and source_parts[-1] in runs else ""
            for event in events[:5_000]:
                if not isinstance(event, dict):
                    continue
                identity = cls._event_identity(artifact_id, event)
                row = rows_by_identity.setdefault(identity, {
                    "artifact_id": artifact_id,
                    "artifact_name": artifacts.get(artifact_id, ""),
                })
                for key in copied_fields:
                    if event.get(key) not in {None, ""} and row.get(key) in {None, ""}:
                        row[key] = event[key]
                row["timestamp_utc"] = row.get("timestamp_utc") or cls._utc_timestamp(event.get("timestamp"))
                correlation = correlations.get(identity, {})
                for key in ("record_offset", "record_size", "chunk_index"):
                    if correlation.get(key) not in {None, ""}:
                        row[key] = correlation[key]
                row.update({
                    key: value for key, value in cluster_membership.get(identity, {}).items()
                    if value not in {None, ""}
                })
                lists = source_lists.setdefault(identity, {
                    "sources": [], "source_observation_ids": [],
                    "tool_run_ids": [], "raw_stdout_paths": [],
                })
                for key, value in (
                    ("sources", source),
                    ("source_observation_ids", str(observation.get("id") or "")),
                    ("tool_run_ids", run_id),
                    ("raw_stdout_paths", str(runs.get(run_id, {}).get("stdout_path") or "")),
                ):
                    if value and value not in lists[key]:
                        lists[key].append(value)
        for observation in report.get("observations", []):
            if not isinstance(observation, dict) or observation.get("key") != "ntfs.usn.records":
                continue
            events = observation.get("value")
            if not isinstance(events, list):
                continue
            artifact_id = observation.get("artifact_id")
            source = str(observation.get("source") or "")
            for event in events[:10_000]:
                if not isinstance(event, dict):
                    continue
                identity = (artifact_id, "usn", event.get("usn"), event.get("offset"))
                row = rows_by_identity.setdefault(identity, {
                    "artifact_id": artifact_id,
                    "artifact_name": artifacts.get(artifact_id, ""),
                    "event_id": f"USN_RECORD_V{event.get('major_version', '?')}",
                    "category": "ntfs_usn",
                })
                row.update({
                    "timestamp": event.get("timestamp"),
                    "timestamp_utc": cls._utc_timestamp(event.get("timestamp")),
                    "record_offset": event.get("offset"),
                    "record_size": event.get("record_length"),
                    "usn": event.get("usn"),
                    "reason": event.get("reason"),
                    "reason_names": ";".join(
                        str(item) for item in event.get("reason_names", [])
                    ) if isinstance(event.get("reason_names"), list) else event.get("reason_names"),
                    "file_record_number": event.get("file_record_number"),
                    "file_sequence_number": event.get("file_sequence_number"),
                    "parent_record_number": event.get("parent_record_number"),
                    "parent_sequence_number": event.get("parent_sequence_number"),
                    "file_id_128": event.get("file_id_128"),
                    "parent_file_id_128": event.get("parent_file_id_128"),
                    "file_name": event.get("file_name"),
                    "file_attributes": event.get("file_attributes"),
                    "source_info": event.get("source_info"),
                    "security_id": event.get("security_id"),
                    "remaining_extents": event.get("remaining_extents"),
                    "number_of_extents": event.get("number_of_extents"),
                    "extent_size": event.get("extent_size"),
                    "extents": event.get("extents"),
                })
                correlation_pair = usn_mft_correlations.get(identity)
                if correlation_pair is not None:
                    correlation, correlation_observation = correlation_pair
                    mft_artifact_id = correlation.get("ancestor_artifact_id")
                    row.update({
                        "mft_artifact_id": mft_artifact_id,
                        "mft_artifact_name": artifacts.get(mft_artifact_id, ""),
                        "mft_observation_id": correlation.get("mft_observation_id"),
                        "sample_file_names": correlation.get("sample_file_names"),
                        "sample_deleted": correlation.get("sample_deleted"),
                        "sample_physical_segments": correlation.get("sample_physical_segments"),
                    })
                lists = source_lists.setdefault(identity, {
                    "sources": [], "source_observation_ids": [],
                    "tool_run_ids": [], "raw_stdout_paths": [],
                })
                for key, value in (
                    ("sources", source),
                    ("source_observation_ids", str(observation.get("id") or "")),
                ):
                    if value and value not in lists[key]:
                        lists[key].append(value)
                if correlation_pair is not None:
                    correlation_observation = correlation_pair[1]
                    for key, value in (
                        ("sources", str(correlation_observation.get("source") or "")),
                        ("source_observation_ids", str(correlation_observation.get("id") or "")),
                    ):
                        if value and value not in lists[key]:
                            lists[key].append(value)
        browser_families: dict[object, str] = {}
        application_ids: dict[object, str] = {}
        for observation in report.get("observations", []):
            if not isinstance(observation, dict):
                continue
            if observation.get("key") in {"browser.family", "browser.wal_family"} and isinstance(observation.get("value"), str):
                browser_families[observation.get("artifact_id")] = str(observation["value"])
            elif observation.get("key") == "jumplist.application_id" and isinstance(observation.get("value"), str):
                application_ids[observation.get("artifact_id")] = str(observation["value"])
        for observation in report.get("observations", []):
            if not isinstance(observation, dict) or observation.get("key") not in {
                "browser.records", "browser.wal_records", "jumplist.destinations",
                "registry.amcache.records", "registry.shimcache.records",
            }:
                continue
            records = observation.get("value")
            if not isinstance(records, list):
                continue
            artifact_id = observation.get("artifact_id")
            source = str(observation.get("source") or "")
            for index, record in enumerate(records[:5_000]):
                if not isinstance(record, dict):
                    continue
                observation_key = observation.get("key")
                if observation_key == "jumplist.destinations":
                    identity = (artifact_id, "jumplist", record.get("entry_id"), record.get("stream_offset"))
                    timestamp = record.get("last_access_time_utc")
                    row = rows_by_identity.setdefault(identity, {
                        "artifact_id": artifact_id, "artifact_name": artifacts.get(artifact_id, ""),
                        "event_id": "JUMPLIST_DESTLIST", "category": "windows_jumplist",
                        "record_kind": "destination", "row_id": record.get("entry_id"),
                        "record_offset": record.get("stream_offset"), "record_size": record.get("record_length"),
                        "path": record.get("path"), "computer": record.get("hostname"),
                        "timestamp": timestamp, "timestamp_utc": timestamp,
                        "timestamp_raw": record.get("last_access_time_raw_filetime"),
                        "timestamp_basis": "100ns intervals since 1601-01-01 UTC",
                        "application_id": application_ids.get(artifact_id, ""),
                    })
                elif observation_key in {"browser.records", "browser.wal_records"}:
                    kind = str(record.get("kind") or "browser_record")
                    identity = (
                        artifact_id, "browser", kind, record.get("table"),
                        record.get("row_id", index),
                    )
                    timestamp_key = (
                        "visit_time" if "visit_time_utc" in record else
                        "visit_date" if "visit_date_utc" in record else
                        "start_time" if "start_time_utc" in record else
                        "last_used" if "last_used_utc" in record else None
                    )
                    timestamp = record.get(f"{timestamp_key}_utc") if timestamp_key else None
                    row = rows_by_identity.setdefault(identity, {
                        "artifact_id": artifact_id, "artifact_name": artifacts.get(artifact_id, ""),
                        "event_id": f"BROWSER_{kind.upper()}", "category": "browser_activity",
                        "record_kind": kind, "browser_family": browser_families.get(artifact_id, ""),
                        "table": record.get("table"), "row_id": record.get("row_id"),
                        "url": record.get("url"), "title": record.get("title"),
                        "path": record.get("path"), "search_term": record.get("term") or record.get("value"),
                        "timestamp": timestamp, "timestamp_utc": timestamp,
                        "timestamp_raw": record.get(f"{timestamp_key}_raw") if timestamp_key else None,
                        "timestamp_basis": record.get(f"{timestamp_key}_basis") if timestamp_key else None,
                    })
                elif observation_key == "registry.amcache.records":
                    identity = (
                        artifact_id, "amcache", record.get("key_file_offset"),
                        record.get("key_path"),
                    )
                    timestamp = record.get("key_last_write_time_utc")
                    row = rows_by_identity.setdefault(identity, {
                        "artifact_id": artifact_id, "artifact_name": artifacts.get(artifact_id, ""),
                        "event_id": f"AMCACHE_{str(record.get('record_kind') or 'RECORD').upper()}",
                        "category": "windows_amcache", "record_kind": record.get("record_kind"),
                        "record_offset": record.get("key_file_offset"),
                        "record_hive_offset": record.get("key_hive_offset"),
                        "path": record.get("path"), "title": record.get("name"),
                        "timestamp": timestamp, "timestamp_utc": cls._utc_timestamp(timestamp),
                        "timestamp_raw": record.get("key_last_write_time_raw_filetime"),
                        "timestamp_basis": record.get("timestamp_basis"),
                        "registry_key_path": record.get("key_path"),
                        "registry_record_name": record.get("key_name"),
                        "registry_program_id": record.get("program_id"),
                        "registry_file_id": record.get("file_id"),
                    })
                else:
                    identity = (
                        artifact_id, "shimcache", record.get("value_hive_offset"),
                        record.get("entry_offset_in_value"),
                    )
                    timestamp = record.get("last_modified_time_utc")
                    row = rows_by_identity.setdefault(identity, {
                        "artifact_id": artifact_id, "artifact_name": artifacts.get(artifact_id, ""),
                        "event_id": "SHIMCACHE_ENTRY", "category": "windows_shimcache",
                        "record_kind": record.get("record_kind"),
                        "record_offset": record.get("entry_file_offset"),
                        "record_hive_offset": record.get("entry_hive_offset"),
                        "record_size": record.get("entry_size"), "path": record.get("path"),
                        "timestamp": timestamp, "timestamp_utc": cls._utc_timestamp(timestamp),
                        "timestamp_raw": record.get("last_modified_time_raw_filetime"),
                        "timestamp_basis": record.get("timestamp_basis"),
                        "registry_key_path": record.get("key_path"),
                        "registry_value_name": record.get("value_name"),
                        "registry_cache_format": record.get("cache_format"),
                    })
                lists = source_lists.setdefault(identity, {
                    "sources": [], "source_observation_ids": [],
                    "tool_run_ids": [], "raw_stdout_paths": [],
                })
                for key, value in (
                    ("sources", source),
                    ("source_observation_ids", str(observation.get("id") or "")),
                ):
                    if value and value not in lists[key]:
                        lists[key].append(value)
        rows: list[dict[str, Any]] = []
        for identity, row in rows_by_identity.items():
            for key, values in source_lists[identity].items():
                row[key] = ";".join(values)
            rows.append(row)
        rows.sort(key=lambda row: (
            0 if row.get("timestamp_utc") else 1,
            str(row.get("timestamp_utc") or row.get("timestamp") or ""),
            str(row.get("artifact_id") or ""),
            str(row.get("event_record_id") or ""),
            str(row.get("source_record_index") or ""),
        ))
        return rows[:10_000]

    @staticmethod
    def _csv_safe(value: object) -> object:
        """Prevent spreadsheet formula execution while JSON retains the original value."""
        if not isinstance(value, str):
            return value
        sanitized = value.replace("\x00", "")[:8_192]
        if sanitized.lstrip().startswith(("=", "+", "-", "@")):
            return f"'{sanitized}"
        return sanitized

    @staticmethod
    def _markdown(report: dict[str, Any]) -> str:
        case = report["case"]
        lines = [
            f"# ForensicKit Report: {case['name']}",
            "",
            f"- Case ID: `{case['id']}`",
            f"- Created: `{case['created_at']}`",
            f"- Workspace: `{case['workspace']}`",
            "",
            "## Flag candidates",
            "",
        ]
        flags = report["flag_candidates"]
        if flags:
            for flag in flags:
                chain = " → ".join(flag["transform_chain"])
                value = str(flag["value"]).replace("`", "\\`")
                locations = flag.get("locations") or [flag]
                lines.append(
                    f"- **`{value}`** — status `candidate`, {chain}; "
                    f"{len(locations)} preserved location(s). This is not an automatic answer verdict."
                )
                for location in locations[:50]:
                    lines.append(
                        "  - "
                        f"`{location.get('source_kind', 'unknown')}` · "
                        f"origin `{location.get('origin_path') or 'unknown'}` · "
                        f"found in `{location.get('discovered_path') or 'unknown'}` · "
                        f"{location.get('location') or 'location unknown'} · "
                        f"encoding `{location.get('encoding') or 'unknown'}` · "
                        f"chain `{' → '.join(location.get('transform_chain') or [])}` · "
                        f"context `{str(location.get('context') or '').replace('`', '\\`')}`"
                    )
        else:
            lines.append("No flag candidates detected.")
        lines.extend(["", "## Search hits", ""])
        if report.get("search_hits"):
            for hit in report["search_hits"]:
                locations = hit.get("locations") or [hit]
                lines.append(
                    f"- `{hit.get('match_type')}` query `{str(hit.get('query') or '').replace('`', '\\`')}` "
                    f"matched `{str(hit.get('value') or '').replace('`', '\\`')}` at {len(locations)} location(s)."
                )
                for location in locations[:50]:
                    lines.append(
                        f"  - `{location.get('source_kind', 'unknown')}` · "
                        f"`{location.get('discovered_path') or 'unknown'}` · "
                        f"{location.get('location') or 'location unknown'} · "
                        f"context `{str(location.get('context') or '').replace('`', '\\`')}`"
                    )
        else:
            lines.append("No exact-string, keyword, or explicit-regex hits requested/detected.")
        lines.extend(["", "## Analysis errors", ""])
        if report["errors"]:
            for error in report["errors"]:
                target = error.get("artifact_id") or "case"
                lines.append(f"- `{error['source']}` for `{target}`: {error['message']}")
        else:
            lines.append("No non-fatal analysis errors recorded.")
        plans = [
            observation["value"]
            for observation in report["observations"]
            if observation["key"] == "planner.tool_plan" and isinstance(observation["value"], dict)
        ]
        available_plans = [plan for plan in plans if plan.get("available")]
        missing_plans = [plan for plan in plans if not plan.get("available")]
        unverified = [
            item for item in report.get("verifications", [])
            if item.get("status") == "unverified"
        ]
        lines.extend(["", "## Recommended next steps", ""])
        if report["flag_candidates"]:
            lines.append("- Validate prominent flag candidates against their recorded artifact, source location, and transform chain.")
        if available_plans:
            tool_names = ", ".join(sorted({str(plan.get("tool")) for plan in available_plans}))
            lines.append(f"- Review or execute the available evidence-backed plans: `{tool_names}`.")
        if missing_plans:
            tool_names = ", ".join(sorted({str(plan.get("tool")) for plan in missing_plans}))
            lines.append(f"- If time permits, stage missing optional tools offline and rerun the relevant plans: `{tool_names}`.")
        if report["errors"]:
            lines.append("- Review the recorded non-fatal analysis errors before relying on incomplete extraction or parser output.")
        if unverified:
            lines.append(
                f"- Independently verify the {len(unverified)} unverified finding hypothesis/hypotheses; "
                "recorded supporting strings alone are not a completed verification."
            )
        if not report["flag_candidates"] and not available_plans and not missing_plans and not report["errors"] and not unverified:
            lines.append("- No follow-up is currently evidence-backed; inspect raw observations and preserved output before broadening scope.")
        lines.extend(["", "## Findings", ""])
        if report["findings"]:
            for finding in report["findings"]:
                lines.extend(
                    [
                        f"### {finding['title']}",
                        "",
                        f"- Category: `{finding['category']}`",
                        f"- Severity/confidence: `{finding['severity']}` / `{finding['confidence']:.2f}`",
                        f"- Source: `{finding['source']}`",
                        "",
                        finding["explanation"],
                        "",
                    ]
                )
        else:
            lines.extend(["No findings recorded.", ""])
        lines.extend(["## Investigation chain", ""])
        hypotheses_by_finding = {
            item.get("finding_id"): item for item in report.get("hypotheses", [])
        }
        verifications_by_finding = {
            item.get("finding_id"): item for item in report.get("verifications", [])
        }
        if report.get("findings"):
            for finding in report["findings"]:
                finding_id = finding.get("id")
                hypothesis = hypotheses_by_finding.get(finding_id)
                verification = verifications_by_finding.get(finding_id)
                if not hypothesis or not verification:
                    lines.extend([
                        f"### {finding.get('title')}", "",
                        f"- Finding ID: `{finding_id}`",
                        "- Chain status: `incomplete` (legacy or damaged case data)", "",
                    ])
                    continue
                lines.extend([
                    f"### {hypothesis.get('statement')}", "",
                    f"- Finding ID: `{finding_id}`",
                    f"- Artifact ID: `{hypothesis.get('artifact_id')}`",
                    f"- Hypothesis source/confidence: `{hypothesis.get('source')}` / "
                    f"`{float(hypothesis.get('confidence', 0.0)):.2f}`",
                    f"- Verification: `{verification.get('status')}`",
                    f"- Verification method: `{verification.get('method')}`",
                    f"- Verification source: `{verification.get('source')}`",
                    "",
                    str(hypothesis.get("rationale") or "No rationale recorded."),
                    "",
                    f"Verification conclusion: {verification.get('conclusion')}",
                    "",
                    "Evidence attached to this verification record:",
                ])
                evidence = verification.get("evidence") or []
                if evidence:
                    lines.extend(f"- {item}" for item in evidence)
                else:
                    lines.append("- No verification evidence recorded; this remains explicitly unverified.")
                lines.append("")
        else:
            lines.extend(["No hypothesis or verification records available.", ""])
        lines.extend(["## Artifacts", ""])
        for artifact in report["artifacts"]:
            parent = artifact["parent_id"] or "root evidence"
            lines.append(
                f"- `{artifact['logical_name']}` — `{artifact['artifact_type']}`, "
                f"SHA256 `{artifact['sha256']}`, parent `{parent}`"
            )
        lines.extend(["", "## Artifact lineage", ""])
        graph_mapping = report.get("artifact_graph", {})
        # JSON object keys stringify the root None key; report readers still
        # receive the canonical mapping while the human report remains clear.
        root_ids = graph_mapping.get(None, graph_mapping.get("null", []))
        if root_ids:
            by_id = {artifact["id"]: artifact for artifact in report["artifacts"]}
            def render(node_id: str, prefix: str = "") -> None:
                node = by_id.get(node_id)
                if not node:
                    return
                lines.append(f"{prefix}- `{node['logical_name']}` ({node['artifact_type']})")
                for child in graph_mapping.get(node_id, []):
                    render(child, prefix + "  ")
            for root_id in root_ids:
                render(root_id)
        else:
            lines.append("No artifact lineage recorded.")
        lines.extend(["", "## Tool runs", ""])
        for run in report["tool_runs"]:
            command = " ".join(run["command_argv"])
            lines.append(
                f"- `{run['tool']}` [{run['status']}] exit={run['exit_code']}: `{command}` "
                f"(stdout: `{run['stdout_path']}`)"
            )
        if not report["tool_runs"]:
            lines.append("No external tools executed.")
        lines.extend(["", "## Timeline", ""])
        timeline = report.get("timeline", [])
        if timeline:
            for event in timeline[:200]:
                timestamp = event.get("timestamp_utc") or event.get("timestamp") or "time unknown"
                if str(event.get("event_id", "")).startswith("USN_RECORD_V"):
                    identity = (
                        f"USN {event.get('usn')} / file ID {event.get('file_record_number') or event.get('file_id_128')} "
                        f"`{event.get('file_name') or ''}` / {event.get('reason_names') or event.get('reason')}"
                    )
                else:
                    identity = f"Event {event.get('event_id') or '?'} / record {event.get('event_record_id') or '?'}"
                offset = event.get("record_offset")
                offset_text = f" at byte `{offset}`" if offset is not None else ""
                cluster = (
                    f"; cluster score `{event.get('cluster_score')}` ({event.get('cluster_level')})"
                    if event.get("cluster_score") is not None else ""
                )
                mft_context = (
                    f"; exact MFT `{event.get('mft_artifact_name') or event.get('mft_artifact_id')}` "
                    f"names `{event.get('sample_file_names')}` deleted=`{event.get('sample_deleted')}`"
                    if event.get("mft_artifact_id") else ""
                )
                lines.append(
                    f"- `{timestamp}` — {identity} `{event.get('category') or 'other'}`{offset_text}{cluster}; "
                    f"artifact `{event.get('artifact_name') or event.get('artifact_id')}`{mft_context}"
                )
            if len(timeline) > 200:
                lines.append(f"- Timeline display truncated: {len(timeline) - 200} additional row(s) remain in `timeline.csv` and `report.json`.")
        else:
            lines.append("No normalized timeline events recorded.")
        lines.extend(["", "## Recommended / planned tools", ""])
        if plans:
            seen: set[tuple[str, str, str, tuple[tuple[str, str], ...]]] = set()
            for plan in plans:
                parameters = plan.get("parameters", {})
                parameter_items = tuple(sorted(
                    (str(name), str(value)) for name, value in parameters.items()
                )) if isinstance(parameters, dict) else ()
                key = (
                    str(plan.get("tool", "")),
                    str(plan.get("mode", "")),
                    str(plan.get("command_mode", "default")),
                    parameter_items,
                )
                if key in seen:
                    continue
                seen.add(key)
                availability = "available" if plan.get("available") else "missing"
                reasons = "; ".join(str(reason) for reason in plan.get("reasons", []))
                parameter_text = ", ".join(f"{name}={value}" for name, value in parameter_items)
                suffix = f"; parameters: `{parameter_text}`" if parameter_text else ""
                lines.append(
                    f"- `{key[0]}` ({availability}, analysis mode `{key[1]}`, command mode `{key[2]}`){suffix}: {reasons}"
                )
        else:
            lines.append("No tool plans recorded.")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _html(report: dict[str, Any]) -> str:
        """Render a dependency-free report with every evidence value escaped."""
        esc = lambda value: html.escape(str(value if value is not None else ""), quote=True)
        flag_rows: list[str] = []
        for flag in report.get("flag_candidates", []):
            locations = flag.get("locations") or [flag]
            detail = "".join(
                "<li>"
                f"source={esc(item.get('source_kind'))}; "
                f"origin={esc(item.get('origin_path'))}; "
                f"found in={esc(item.get('discovered_path'))}; "
                f"location={esc(item.get('location'))}; "
                f"encoding={esc(item.get('encoding'))}; "
                f"chain={esc(' → '.join(item.get('transform_chain') or []))}; "
                f"context=<code>{esc(item.get('context'))}</code>"
                "</li>"
                for item in locations[:50]
            )
            flag_rows.append(
                "<tr>"
                f"<td><code>{esc(flag.get('value'))}</code></td>"
                "<td>candidate (not automatically confirmed)</td>"
                f"<td><ul>{detail}</ul></td>"
                "</tr>"
            )
        hit_rows: list[str] = []
        for hit in report.get("search_hits", []):
            locations = hit.get("locations") or [hit]
            detail = "".join(
                "<li>"
                f"{esc(item.get('source_kind'))}; {esc(item.get('discovered_path'))}; "
                f"{esc(item.get('location'))}; context=<code>{esc(item.get('context'))}</code>"
                "</li>"
                for item in locations[:50]
            )
            hit_rows.append(
                "<tr>"
                f"<td>{esc(hit.get('match_type'))}</td>"
                f"<td><code>{esc(hit.get('query'))}</code></td>"
                f"<td><code>{esc(hit.get('value'))}</code></td>"
                f"<td><ul>{detail}</ul></td>"
                "</tr>"
            )
        findings_by_id = {
            item.get("id"): item for item in report.get("findings", [])
        }
        verifications_by_finding = {
            item.get("finding_id"): item
            for item in report.get("verifications", [])
        }
        chain_rows: list[str] = []
        for hypothesis in report.get("hypotheses", []):
            finding_id = hypothesis.get("finding_id")
            finding = findings_by_id.get(finding_id, {})
            verification = verifications_by_finding.get(finding_id, {})
            evidence = verification.get("evidence") or []
            evidence_items = "".join(
                f"<li><code>{esc(item)}</code></li>" for item in evidence
            ) or "<li>No verification evidence recorded; analyst verification is required.</li>"
            chain_rows.append(
                "<tr>"
                f"<td><code>{esc(finding_id)}</code><br>{esc(finding.get('title'))}</td>"
                f"<td>{esc(hypothesis.get('statement'))}<br>"
                f"<small>{esc(hypothesis.get('rationale'))}</small><br>"
                f"source=<code>{esc(hypothesis.get('source'))}</code></td>"
                f"<td><strong>{esc(verification.get('status') or 'missing')}</strong><br>"
                f"method=<code>{esc(verification.get('method'))}</code><br>"
                f"source=<code>{esc(verification.get('source'))}</code><br>"
                f"{esc(verification.get('conclusion'))}</td>"
                f"<td><ul>{evidence_items}</ul></td>"
                "</tr>"
            )
        artifact_rows = "".join(
            "<tr>"
            f"<td>{esc(item.get('logical_name'))}</td>"
            f"<td>{esc(item.get('artifact_type'))}</td>"
            f"<td><code>{esc(item.get('sha256'))}</code></td>"
            f"<td>{esc(item.get('source_path'))}</td>"
            "</tr>"
            for item in report.get("artifacts", [])
        )
        return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>ForensicKit report</title>
<style>body{font:14px system-ui,sans-serif;margin:2rem;line-height:1.4}table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{border:1px solid #bbb;padding:.45rem;vertical-align:top;text-align:left}code{white-space:pre-wrap;overflow-wrap:anywhere}ul{margin:.2rem;padding-left:1.2rem}.notice{padding:.7rem;background:#fff4cc}</style></head><body>""" + (
            f"<h1>ForensicKit report: {esc(report.get('case', {}).get('name'))}</h1>"
            "<p class=\"notice\">Flag strings are candidates for analyst validation, not automatically confirmed answers. "
            "Program logs and evidence-derived output are labelled separately.</p>"
            "<h2>Flag candidates</h2><table><thead><tr><th>Value</th><th>Status</th><th>Locations and provenance</th></tr></thead><tbody>"
            + ("".join(flag_rows) or "<tr><td colspan=\"3\">None detected</td></tr>")
            + "</tbody></table><h2>Search hits</h2><table><thead><tr><th>Type</th><th>Query</th><th>Value</th><th>Locations</th></tr></thead><tbody>"
            + ("".join(hit_rows) or "<tr><td colspan=\"4\">None detected</td></tr>")
            + "</tbody></table><h2>Investigation chain</h2><table><thead><tr><th>Finding</th><th>Hypothesis</th><th>Verification</th><th>Evidence</th></tr></thead><tbody>"
            + ("".join(chain_rows) or "<tr><td colspan=\"4\">No hypothesis or verification records</td></tr>")
            + "</tbody></table><h2>Artifacts</h2><table><thead><tr><th>Name</th><th>Type</th><th>SHA-256</th><th>Original path</th></tr></thead><tbody>"
            + artifact_rows
            + "</tbody></table></body></html>\n"
        )
