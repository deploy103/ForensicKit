from __future__ import annotations

import csv
import html
import json
import re
from dataclasses import asdict
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from .workspace import CaseWorkspace
from .graph import ArtifactGraph


_KO_NARRATIVE = {
    "Archive has an extreme declared expansion ratio": "압축 파일에 비정상적으로 높은 선언상 압축 해제 비율이 있습니다",
    "ZIP local headers declare a large uncompressed payload relative to compressed bytes. Built-in extraction limits remain active.": "ZIP 로컬 헤더가 압축된 크기에 비해 매우 큰 압축 해제 크기를 선언합니다. 내장 추출기의 안전 제한은 계속 적용됩니다.",
    "Data exists after image end marker": "이미지 종료 마커 뒤에 데이터가 존재합니다",
    "Trailing bytes can contain an appended archive or hidden payload.": "파일 끝의 추가 바이트에는 덧붙인 압축 파일이나 숨겨진 payload가 들어 있을 수 있습니다.",
    "Possible ZIP payload embedded in image": "이미지 내부에 ZIP payload가 삽입되었을 가능성이 있습니다",
    "A ZIP signature inside an image strongly supports an embedded or appended archive hypothesis.": "이미지 내부의 ZIP signature는 압축 파일이 삽입되었거나 뒤에 덧붙었다는 가설을 강하게 뒷받침합니다.",
    "Data exists after PNG IEND": "PNG IEND 뒤에 데이터가 존재합니다",
    "Possible ZIP payload embedded/appended to PNG": "PNG에 ZIP payload가 삽입되었거나 덧붙었을 가능성이 있습니다",
    "Executable has high sampled entropy": "실행 파일에서 높은 표본 entropy가 확인되었습니다",
    "High entropy can result from packing, encryption, or compressed resources; correlate it with section layout and strings.": "높은 entropy는 packing, 암호화 또는 압축된 resource 때문에 나타날 수 있습니다. section 구조 및 문자열과 함께 분석해야 합니다.",
    "Filesystem listing is deferred until a partition offset is confirmed": "partition offset을 확인할 때까지 filesystem 목록 조회를 보류합니다",
    "The image contains a partition table. Running fls at offset zero would inspect partition metadata instead of a filesystem, so mmls is selected first and its sector offset must drive follow-up listing.": "이미지에 partition table이 있습니다. offset 0에서 fls를 실행하면 filesystem이 아니라 partition metadata를 검사하게 되므로, 먼저 mmls로 sector offset을 확인한 뒤 그 값을 후속 목록 조회에 사용해야 합니다.",
    "QCOW virtual disk header is structurally inconsistent": "QCOW 가상 디스크 헤더의 구조가 일관되지 않습니다",
    "QCOW magic was present but fixed header fields or bounds failed validation.": "QCOW magic은 존재하지만 고정 헤더 필드 또는 범위 검증에 실패했습니다.",
    "A structurally valid ZIP container was opened with the bounded built-in extractor.": "구조적으로 유효한 ZIP 컨테이너를 안전 범위가 제한된 내장 추출기로 열었습니다.",
    "Supporting evidence is recorded, but no independent verification action has been performed.": "뒷받침하는 증거는 기록되었지만 독립적인 검증 작업은 수행되지 않았습니다.",
    "PNG classification warrants chunk and CRC validation": "PNG로 분류되었으므로 chunk와 CRC 검증이 필요합니다",
    "deep mode permits bounded bit-plane checks for png": "deep 모드에서는 PNG에 대해 범위가 제한된 bit-plane 검사를 수행할 수 있습니다",
    "list and validate archive structure before extraction": "추출 전에 압축 파일 구조를 조회하고 검증합니다",
    "deep carving is justified by embedded signatures or an unclassified binary": "삽입된 signature 또는 분류되지 않은 binary가 있으므로 deep carving을 수행할 근거가 있습니다",
    "deep signature carving provides an independent bounded recovery path": "deep signature carving은 독립적이며 범위가 제한된 복구 경로를 제공합니다",
    "artifact remains an unknown binary": "artifact가 알 수 없는 binary로 남아 있습니다",
    "classified artifact type commonly carries useful metadata": "분류된 artifact 유형에는 유용한 metadata가 포함되는 경우가 많습니다",
    "image metadata can expose editing history, comments, and embedded previews": "이미지 metadata에서 편집 이력, 주석 및 삽입된 미리보기를 확인할 수 있습니다",
    "confirm signature-derived type with libmagic output": "signature로 판별한 유형을 libmagic 출력으로 확인합니다",
    "enumerate partition layout before filesystem-level operations": "filesystem 수준 작업 전에 partition 구조를 조회합니다",
    "validated native partition metadata identifies filesystem candidate at sector offset 40": "검증된 기본 partition metadata에서 sector offset 40의 filesystem 후보를 확인했습니다",
    "validate whether trailing data is an archive": "파일 끝에 덧붙은 데이터가 압축 파일인지 검증합니다",
    "an embedded PK/ZIP signature was observed in the image": "이미지에서 삽입된 PK/ZIP signature가 관찰되었습니다",
    "No rationale recorded.": "기록된 판단 근거가 없습니다.",
}

_KO_STATUS = {
    "candidate": "후보",
    "available": "사용 가능",
    "missing": "미설치",
    "completed": "완료",
    "failed": "실패",
    "canceled": "취소됨",
    "unverified": "미검증",
    "supported": "지지됨",
    "refuted": "기각됨",
    "incomplete": "불완전",
    "not_performed": "수행 안 함",
}

_KO_SEVERITY = {
    "info": "정보",
    "low": "낮음",
    "medium": "중간",
    "high": "높음",
    "critical": "심각",
}


def _ko_status(value: object) -> str:
    text = str(value if value is not None else "")
    return _KO_STATUS.get(text, text)


def _ko_severity(value: object) -> str:
    text = str(value if value is not None else "")
    return _KO_SEVERITY.get(text, text)


def _ko_narrative(value: object) -> str:
    """한국어 보고서용 설명을 반환하되 증거 원문과 JSON은 변경하지 않는다."""
    text = str(value if value is not None else "")
    if not text or re.search(r"[가-힣]", text):
        return text
    known = _KO_NARRATIVE.get(text)
    if known is not None:
        return known
    if " | " in text:
        return " | ".join(_ko_narrative(part) for part in text.split(" | "))
    extracted = re.fullmatch(r"Extracted (\d+) ZIP member\(s\)", text)
    if extracted:
        return f"ZIP 구성원 {extracted.group(1)}개를 추출했습니다"
    entropy = re.fullmatch(r"entropy is high \(([^)]+)\)", text)
    if entropy:
        return f"entropy가 높습니다 ({entropy.group(1)})"
    if text.startswith("artifact remains an unknown binary; entropy is high ("):
        return text.replace(
            "artifact remains an unknown binary; entropy is high",
            "artifact가 알 수 없는 binary로 남아 있으며 entropy가 높습니다",
            1,
        )
    if text.startswith("embedded signature/data observation exists; entropy is high ("):
        match = re.fullmatch(
            r"embedded signature/data observation exists; entropy is high \(([^)]+)\)", text,
        )
        if match:
            return f"삽입된 signature/data 관찰값이 있으며 entropy가 높습니다 ({match.group(1)})"
    trailing = re.fullmatch(r"(\d+) trailing byte\(s\) exist after the image end marker", text)
    if trailing:
        return f"이미지 종료 마커 뒤에 추가 바이트 {trailing.group(1)}개가 존재합니다"
    rule = re.fullmatch(r"(?:Rule|rule) ([^:]+) fired because: (.+)", text)
    if rule:
        return f"규칙 `{rule.group(1)}`이 다음 조건 때문에 탐지되었습니다: `{rule.group(2)}`"
    rule_reason = re.fullmatch(r"rule ([^:]+): (.+)", text)
    if rule_reason:
        return f"규칙 `{rule_reason.group(1)}`의 조건이 충족되었습니다: `{rule_reason.group(2)}`"
    # 알 수 없는 확장 모듈의 문구도 영어 본문처럼 보이지 않도록 출처 데이터로 명확히 구분한다.
    return f"분석 모듈이 기록한 원문: `{text}`"


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
            f"# ForensicKit 분석 보고서: {case['name']}",
            "",
            f"- 사건 ID: `{case['id']}`",
            f"- 생성 시각: `{case['created_at']}`",
            f"- 작업 공간: `{case['workspace']}`",
            "",
            "## Flag 후보",
            "",
        ]
        flags = report["flag_candidates"]
        if flags:
            for flag in flags:
                chain = " → ".join(flag["transform_chain"])
                value = str(flag["value"]).replace("`", "\\`")
                locations = flag.get("locations") or [flag]
                lines.append(
                    f"- **`{value}`** — 상태 `후보`, 변환 과정 `{chain}`; "
                    f"발견 위치 {len(locations)}곳을 보존했습니다. 자동으로 정답 판정을 내린 값은 아닙니다."
                )
                for location in locations[:50]:
                    lines.append(
                        "  - "
                        f"종류 `{location.get('source_kind', '알 수 없음')}` · "
                        f"원본 `{location.get('origin_path') or '알 수 없음'}` · "
                        f"발견 파일 `{location.get('discovered_path') or '알 수 없음'}` · "
                        f"{location.get('location') or '위치 알 수 없음'} · "
                        f"인코딩 `{location.get('encoding') or '알 수 없음'}` · "
                        f"변환 과정 `{' → '.join(location.get('transform_chain') or [])}` · "
                        f"주변 문맥 `{str(location.get('context') or '').replace('`', '\\`')}`"
                    )
        else:
            lines.append("탐지된 Flag 후보가 없습니다.")
        lines.extend(["", "## 검색 결과", ""])
        if report.get("search_hits"):
            for hit in report["search_hits"]:
                locations = hit.get("locations") or [hit]
                lines.append(
                    f"- `{hit.get('match_type')}` 방식의 검색어 "
                    f"`{str(hit.get('query') or '').replace('`', '\\`')}`와 일치하는 값 "
                    f"`{str(hit.get('value') or '').replace('`', '\\`')}`을 {len(locations)}곳에서 찾았습니다."
                )
                for location in locations[:50]:
                    lines.append(
                        f"  - `{location.get('source_kind', '알 수 없음')}` · "
                        f"`{location.get('discovered_path') or '알 수 없음'}` · "
                        f"{location.get('location') or '위치 알 수 없음'} · "
                        f"주변 문맥 `{str(location.get('context') or '').replace('`', '\\`')}`"
                    )
        else:
            lines.append("요청되었거나 탐지된 exact-string, keyword 또는 명시적 regex 검색 결과가 없습니다.")
        lines.extend(["", "## 분석 오류", ""])
        if report["errors"]:
            for error in report["errors"]:
                target = error.get("artifact_id") or "사건 전체"
                lines.append(
                    f"- 대상 `{target}`, 출처 `{error['source']}`의 비치명적 오류: "
                    f"`{error['message']}`"
                )
        else:
            lines.append("기록된 비치명적 분석 오류가 없습니다.")
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
        lines.extend(["", "## 권장 후속 작업", ""])
        if report["flag_candidates"]:
            lines.append("- 주요 Flag 후보를 기록된 artifact, 원본 위치 및 변환 과정과 대조하여 검증하세요.")
        if available_plans:
            tool_names = ", ".join(sorted({str(plan.get("tool")) for plan in available_plans}))
            lines.append(f"- 증거에 근거한 다음 사용 가능 계획을 검토하거나 실행하세요: `{tool_names}`.")
        if missing_plans:
            tool_names = ", ".join(sorted({str(plan.get("tool")) for plan in missing_plans}))
            lines.append(f"- 필요하면 다음 미설치 선택 도구를 offline으로 준비한 뒤 관련 계획을 다시 실행하세요: `{tool_names}`.")
        if report["errors"]:
            lines.append("- 불완전한 추출 또는 parser 출력에 의존하기 전에 기록된 비치명적 분석 오류를 검토하세요.")
        if unverified:
            lines.append(
                f"- 미검증 finding 가설 {len(unverified)}개를 독립적으로 검증하세요. "
                "기록된 보조 문자열만으로는 검증이 완료된 것이 아닙니다."
            )
        if not report["flag_candidates"] and not available_plans and not missing_plans and not report["errors"] and not unverified:
            lines.append("- 현재 증거가 뒷받침하는 후속 작업이 없습니다. 범위를 넓히기 전에 원시 관찰값과 보존된 출력을 확인하세요.")
        lines.extend(["", "## 주요 분석 결과", ""])
        if report["findings"]:
            for finding in report["findings"]:
                lines.extend(
                    [
                        f"### {_ko_narrative(finding['title'])}",
                        "",
                        f"- 분류: `{finding['category']}`",
                        f"- 심각도/신뢰도: `{_ko_severity(finding['severity'])}` / `{finding['confidence']:.2f}`",
                        f"- 출처: `{finding['source']}`",
                        "",
                        _ko_narrative(finding["explanation"]),
                        "",
                    ]
                )
        else:
            lines.extend(["기록된 주요 분석 결과가 없습니다.", ""])
        lines.extend(["## 조사 및 검증 과정", ""])
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
                        f"### {_ko_narrative(finding.get('title'))}", "",
                        f"- Finding ID: `{finding_id}`",
                        "- 검증 과정 상태: `불완전` (이전 버전 또는 손상된 사건 데이터)", "",
                    ])
                    continue
                lines.extend([
                    f"### {_ko_narrative(hypothesis.get('statement'))}", "",
                    f"- Finding ID: `{finding_id}`",
                    f"- Artifact ID: `{hypothesis.get('artifact_id')}`",
                    f"- 가설 출처/신뢰도: `{hypothesis.get('source')}` / "
                    f"`{float(hypothesis.get('confidence', 0.0)):.2f}`",
                    f"- 검증 상태: `{_ko_status(verification.get('status'))}`",
                    f"- 검증 방법: `{_ko_status(verification.get('method'))}`",
                    f"- 검증 출처: `{verification.get('source')}`",
                    "",
                    _ko_narrative(hypothesis.get("rationale") or "No rationale recorded."),
                    "",
                    f"검증 결론: {_ko_narrative(verification.get('conclusion'))}",
                    "",
                    "이 검증 기록에 첨부된 증거:",
                ])
                evidence = verification.get("evidence") or []
                if evidence:
                    lines.extend(f"- {item}" for item in evidence)
                else:
                    lines.append("- 기록된 검증 증거가 없으므로 명시적인 미검증 상태로 유지됩니다.")
                lines.append("")
        else:
            lines.extend(["사용 가능한 가설 또는 검증 기록이 없습니다.", ""])
        lines.extend(["## Artifact 목록", ""])
        for artifact in report["artifacts"]:
            parent = artifact["parent_id"] or "최상위 증거"
            lines.append(
                f"- `{artifact['logical_name']}` — `{artifact['artifact_type']}`, "
                f"SHA-256 `{artifact['sha256']}`, 상위 artifact `{parent}`"
            )
        lines.extend(["", "## Artifact 계보", ""])
        graph_mapping = report.get("artifact_graph", {})
        # JSON object keys stringify the root None key; report readers still
        # receive the canonical mapping while the human report remains clear.
        root_ids = graph_mapping.get(
            None, graph_mapping.get("null", graph_mapping.get("None", [])),
        )
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
            lines.append("기록된 artifact 계보가 없습니다.")
        lines.extend(["", "## 도구 실행 기록", ""])
        for run in report["tool_runs"]:
            command = " ".join(run["command_argv"])
            lines.append(
                f"- `{run['tool']}` [상태: {_ko_status(run['status'])}] 종료 코드={run['exit_code']}: "
                f"`{command}` (표준 출력: `{run['stdout_path']}`)"
            )
        if not report["tool_runs"]:
            lines.append("실행된 외부 도구가 없습니다.")
        lines.extend(["", "## 타임라인", ""])
        timeline = report.get("timeline", [])
        if timeline:
            for event in timeline[:200]:
                timestamp = event.get("timestamp_utc") or event.get("timestamp") or "시각 알 수 없음"
                if str(event.get("event_id", "")).startswith("USN_RECORD_V"):
                    identity = (
                        f"USN {event.get('usn')} / 파일 ID {event.get('file_record_number') or event.get('file_id_128')} "
                        f"`{event.get('file_name') or ''}` / {event.get('reason_names') or event.get('reason')}"
                    )
                else:
                    identity = f"이벤트 {event.get('event_id') or '?'} / 레코드 {event.get('event_record_id') or '?'}"
                offset = event.get("record_offset")
                offset_text = f", byte offset `{offset}`" if offset is not None else ""
                cluster = (
                    f"; cluster 점수 `{event.get('cluster_score')}` ({event.get('cluster_level')})"
                    if event.get("cluster_score") is not None else ""
                )
                mft_context = (
                    f"; 정확한 MFT `{event.get('mft_artifact_name') or event.get('mft_artifact_id')}` "
                    f"이름 `{event.get('sample_file_names')}` 삭제 여부=`{event.get('sample_deleted')}`"
                    if event.get("mft_artifact_id") else ""
                )
                lines.append(
                    f"- `{timestamp}` — {identity} `{event.get('category') or '기타'}`{offset_text}{cluster}; "
                    f"artifact `{event.get('artifact_name') or event.get('artifact_id')}`{mft_context}"
                )
            if len(timeline) > 200:
                lines.append(
                    f"- 타임라인 표시를 줄였습니다. 추가 항목 {len(timeline) - 200}개는 "
                    "`timeline.csv`와 `report.json`에 남아 있습니다."
                )
        else:
            lines.append("기록된 정규화 타임라인 이벤트가 없습니다.")
        lines.extend(["", "## 권장 또는 계획된 도구", ""])
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
                availability = "사용 가능" if plan.get("available") else "미설치"
                reasons = "; ".join(_ko_narrative(reason) for reason in plan.get("reasons", []))
                parameter_text = ", ".join(f"{name}={value}" for name, value in parameter_items)
                suffix = f"; parameter: `{parameter_text}`" if parameter_text else ""
                lines.append(
                    f"- `{key[0]}` ({availability}, 분석 모드 `{key[1]}`, 명령 모드 `{key[2]}`){suffix}: {reasons}"
                )
        else:
            lines.append("기록된 도구 계획이 없습니다.")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _html(report: dict[str, Any]) -> str:
        """모든 증거 값을 escape한 독립 실행형 한국어 보고서를 생성한다."""
        esc = lambda value: html.escape(str(value if value is not None else ""), quote=True)
        flag_rows: list[str] = []
        for flag in report.get("flag_candidates", []):
            locations = flag.get("locations") or [flag]
            detail = "".join(
                "<li>"
                f"종류={esc(item.get('source_kind'))}; "
                f"원본={esc(item.get('origin_path'))}; "
                f"발견 파일={esc(item.get('discovered_path'))}; "
                f"위치={esc(item.get('location'))}; "
                f"인코딩={esc(item.get('encoding'))}; "
                f"변환 과정={esc(' → '.join(item.get('transform_chain') or []))}; "
                f"주변 문맥=<code>{esc(item.get('context'))}</code>"
                "</li>"
                for item in locations[:50]
            )
            flag_rows.append(
                "<tr>"
                f"<td><code>{esc(flag.get('value'))}</code></td>"
                "<td>후보 (자동 확인된 정답이 아님)</td>"
                f"<td><ul>{detail}</ul></td>"
                "</tr>"
            )
        hit_rows: list[str] = []
        for hit in report.get("search_hits", []):
            locations = hit.get("locations") or [hit]
            detail = "".join(
                "<li>"
                f"{esc(item.get('source_kind'))}; {esc(item.get('discovered_path'))}; "
                f"{esc(item.get('location'))}; 주변 문맥=<code>{esc(item.get('context'))}</code>"
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
            ) or "<li>기록된 검증 증거가 없습니다. 분석가의 검증이 필요합니다.</li>"
            chain_rows.append(
                "<tr>"
                f"<td><code>{esc(finding_id)}</code><br>{esc(_ko_narrative(finding.get('title')))}</td>"
                f"<td>{esc(_ko_narrative(hypothesis.get('statement')))}<br>"
                f"<small>{esc(_ko_narrative(hypothesis.get('rationale')))}</small><br>"
                f"출처=<code>{esc(hypothesis.get('source'))}</code></td>"
                f"<td><strong>{esc(_ko_status(verification.get('status') or 'missing'))}</strong><br>"
                f"방법=<code>{esc(_ko_status(verification.get('method')))}</code><br>"
                f"출처=<code>{esc(verification.get('source'))}</code><br>"
                f"{esc(_ko_narrative(verification.get('conclusion')))}</td>"
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
<html lang="ko"><head><meta charset="utf-8"><title>ForensicKit 분석 보고서</title>
<style>body{font:14px system-ui,sans-serif;margin:2rem;line-height:1.4}table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{border:1px solid #bbb;padding:.45rem;vertical-align:top;text-align:left}code{white-space:pre-wrap;overflow-wrap:anywhere}ul{margin:.2rem;padding-left:1.2rem}.notice{padding:.7rem;background:#fff4cc}</style></head><body>""" + (
            f"<h1>ForensicKit 분석 보고서: {esc(report.get('case', {}).get('name'))}</h1>"
            "<p class=\"notice\">Flag 문자열은 분석가가 검증해야 할 후보이며 자동으로 확인된 정답이 아닙니다. "
            "프로그램 로그와 증거에서 유래한 출력은 별도로 구분합니다.</p>"
            "<h2>Flag 후보</h2><table><thead><tr><th>값</th><th>상태</th><th>위치와 출처</th></tr></thead><tbody>"
            + ("".join(flag_rows) or "<tr><td colspan=\"3\">탐지된 항목 없음</td></tr>")
            + "</tbody></table><h2>검색 결과</h2><table><thead><tr><th>유형</th><th>검색어</th><th>값</th><th>위치</th></tr></thead><tbody>"
            + ("".join(hit_rows) or "<tr><td colspan=\"4\">탐지된 항목 없음</td></tr>")
            + "</tbody></table><h2>조사 및 검증 과정</h2><table><thead><tr><th>분석 결과</th><th>가설</th><th>검증</th><th>증거</th></tr></thead><tbody>"
            + ("".join(chain_rows) or "<tr><td colspan=\"4\">가설 또는 검증 기록 없음</td></tr>")
            + "</tbody></table><h2>Artifact 목록</h2><table><thead><tr><th>이름</th><th>유형</th><th>SHA-256</th><th>원본 경로</th></tr></thead><tbody>"
            + artifact_rows
            + "</tbody></table></body></html>\n"
        )
