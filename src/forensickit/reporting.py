from __future__ import annotations

import csv
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
        "category", "event_record_id", "record_offset", "record_size", "chunk_index",
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
    )

    def generate(self, workspace: CaseWorkspace) -> tuple[Path, Path]:
        database = workspace.database
        case = workspace.case
        artifacts = database.artifacts()
        observations = database.observations()
        findings = database.findings()
        runs = database.tool_runs()
        flags = database.flags()
        errors = database.errors()
        graph = ArtifactGraph(artifacts)
        report = _json_value(
            {
                "schema_version": 2,
                "case": asdict(case),
                "artifacts": [asdict(item) for item in artifacts],
                "observations": [asdict(item) for item in observations],
                "findings": [asdict(item) for item in findings],
                "tool_runs": [asdict(item) for item in runs],
                "flag_candidates": [asdict(item) for item in flags],
                "errors": [asdict(item) for item in errors],
                "artifact_graph": graph.as_mapping(),
            }
        )
        report["timeline"] = self._timeline_rows(report)
        json_path = workspace.path("reports", "report.json")
        markdown_path = workspace.path("reports", "report.md")
        timeline_path = workspace.path("reports", "timeline.csv")
        json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        markdown_path.write_text(self._markdown(report), encoding="utf-8")
        with timeline_path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self._TIMELINE_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in report["timeline"]:
                writer.writerow({
                    key: self._csv_safe(row.get(key, "")) for key in self._TIMELINE_FIELDS
                })
        return json_path, markdown_path

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
                lines.append(f"- **`{flag['value']}`** — {chain}; {flag.get('location') or 'location unknown'}")
        else:
            lines.append("No flag candidates detected.")
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
        if not report["flag_candidates"] and not available_plans and not missing_plans and not report["errors"]:
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
