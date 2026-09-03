from __future__ import annotations

from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
import ipaddress
import ntpath
import os
from pathlib import Path
import re

from .config import ForensicKitConfig
from .evidence import EvidenceManager
from .extraction import ExtractionManager
from .flags import FlagHunter
from .identification import IdentificationEngine
from .models import AnalysisError, AnalysisMode, AnalysisResult, Finding, Observation
from .planner import ToolPlanner
from .profiles import ProfileEngine
from .reporting import ReportGenerator
from .resources import default_rules_path, default_tool_catalog
from .rules import RuleEngine
from .tools import ToolRegistry, ToolRunner
from .triage import GenericTriageEngine
from .workspace import CaseWorkspace


class AnalysisEngine:
    """Evidence → observation → classification → rule/profile → tool → finding."""

    def __init__(self, config: ForensicKitConfig | None = None) -> None:
        self.config = config or ForensicKitConfig()
        self.registry = ToolRegistry.default(self.config.tool_catalog or default_tool_catalog())
        self.triage = GenericTriageEngine(self.config.limits)
        self.identification = IdentificationEngine()
        self.profiles = ProfileEngine()
        rules_path = self.config.rules_path or default_rules_path()
        self.rules = RuleEngine.from_yaml(rules_path) if rules_path else RuleEngine()

    def analyze(
        self,
        evidence: Path,
        workspace_base: Path,
        *,
        mode: AnalysisMode = AnalysisMode.TRIAGE,
        execute: bool | None = None,
    ) -> AnalysisResult:
        """Analyze one evidence file in a newly-created isolated case."""
        return self.analyze_many([evidence], workspace_base, mode=mode, execute=execute)

    def analyze_many(
        self,
        evidence_items: Iterable[Path],
        workspace_base: Path,
        *,
        mode: AnalysisMode = AnalysisMode.TRIAGE,
        execute: bool | None = None,
    ) -> AnalysisResult:
        """Analyze multiple independent root artifacts in one case workspace.

        A CTF often supplies a disk image plus sidecar logs, or a backup
        database plus separately exported payloads.  Keeping all supplied
        regular files in one case makes their hashes, findings, reports, and
        artifact graph available together without treating siblings as
        implicit children.  Each root still has ``parent_id=None`` and the
        evidence manager preserves/deduplicates every original independently.
        """
        input_paths = [Path(item) for item in evidence_items]
        sources = self._expand_evidence_inputs(input_paths)
        if not sources:
            raise ValueError("at least one evidence file is required")
        if execute is None:
            execute = mode in {AnalysisMode.AUTO, AnalysisMode.DEEP}
        case_name = input_paths[0].name if len(input_paths) == 1 else "multi-evidence"
        workspace = CaseWorkspace.create(workspace_base, case_name, self.config)
        try:
            evidence_manager = EvidenceManager(workspace)
            roots = []
            seen_root_ids: set[str] = set()
            for source in sources:
                root = evidence_manager.ingest(source)
                if root.id not in seen_root_ids:
                    roots.append(root)
                    seen_root_ids.add(root.id)
            result = AnalysisResult(case=workspace.case, root_artifact=roots[0], artifacts=[*roots])
            extraction = ExtractionManager(workspace, self.config.limits)
            for root in roots:
                self._analyze_artifact(workspace, result, root, mode, execute, extraction)
            self._correlate_case_roots(workspace, result)
            ReportGenerator().generate(workspace)
            return result
        finally:
            workspace.close()

    def _expand_evidence_inputs(self, inputs: Iterable[Path]) -> list[Path]:
        """Expand supplied evidence bundles without following symlinks.

        Mobile backups and some CTF evidence sets are directories rather than
        one monolithic file.  Treat every regular file inside an explicitly
        supplied directory as independent immutable root evidence so no
        payload is opened by path inference.  Enumeration has a deterministic
        relative-path order and is capped before ingestion by the ordinary
        case artifact limit.  Symlinks are deliberately ignored: their target
        could escape the user-selected evidence tree.
        """
        sources: list[Path] = []
        seen: set[Path] = set()
        limit = self.config.limits.max_artifact_count
        for item in inputs:
            requested = Path(item).expanduser()
            try:
                resolved = requested.resolve(strict=True)
            except OSError as exc:
                raise ValueError(f"evidence path cannot be resolved: {requested} ({exc})") from exc
            if resolved.is_file():
                if resolved not in seen:
                    sources.append(resolved)
                    seen.add(resolved)
                continue
            if not resolved.is_dir():
                raise ValueError(f"evidence is not a regular file or directory: {requested}")
            bundle_files: list[Path] = []
            for directory, directory_names, file_names in os.walk(resolved, followlinks=False):
                directory_names[:] = sorted(
                    name for name in directory_names if not (Path(directory) / name).is_symlink()
                )
                for name in sorted(file_names):
                    candidate = Path(directory, name)
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    bundle_files.append(candidate.resolve(strict=True))
                    if len(sources) + len(bundle_files) > limit:
                        raise ValueError(
                            f"evidence directory exceeds max_artifact_count ({limit}); "
                            "supply a smaller evidence subset or raise the configured limit"
                        )
            for candidate in bundle_files:
                if candidate not in seen:
                    sources.append(candidate)
                    seen.add(candidate)
        if len(sources) > limit:
            raise ValueError(f"supplied evidence exceeds max_artifact_count ({limit})")
        return sources

    def _analyze_artifact(self, workspace, result, artifact, mode, execute, extraction) -> None:
        path = workspace.resolve_stored_path(artifact.path)
        observations = self.triage.analyze(artifact, path)
        workspace.database.add_observations(observations)
        result.observations.extend(observations)
        dns_flags = self._scan_dns_txt_reassembly_flags(artifact, observations)
        if dns_flags:
            workspace.database.add_flags(dns_flags)
            result.flags.extend(dns_flags)
        packet_flags = self._scan_printable_pcap_payload_flags(artifact, observations)
        if packet_flags:
            workspace.database.add_flags(packet_flags)
            result.flags.extend(packet_flags)
        identified = self.identification.identify(artifact, observations)
        workspace.database.update_artifact_identification(artifact)
        workspace.database.add_observations(identified.observations)
        result.observations.extend(identified.observations)
        profile_result, rule_result = self._decide(
            artifact, [*observations, *identified.observations]
        )
        if profile_result.observations:
            workspace.database.add_observations(profile_result.observations)
            result.observations.extend(profile_result.observations)
        self._record_errors(workspace, result, artifact.id, profile_result.errors, "profile_engine")
        self._record_errors(
            workspace, result, artifact.id,
            [str(error) for error in rule_result.validation_errors], "rule_engine",
        )
        findings = [*profile_result.findings, *rule_result.findings]
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)
        finding_keys = {self._finding_key(finding) for finding in findings}
        recommendations = [*profile_result.recommendations, *rule_result.recommendations]
        plans = self._plan_tools(workspace, artifact, recommendations, mode)
        result.plans.extend(plans)
        self._record_plans(workspace, result, artifact.id, plans)
        if execute:
            runner = ToolRunner(workspace, self.registry, max_timeout=self.config.limits.per_tool_timeout)
            considered: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
            pending = plans
            # Parser observations are placed back into the decision engine. A
            # bounded second generation permits e.g. metadata/parser evidence
            # to recommend a new verifier without an unbounded tool cascade.
            for _generation in range(2):
                runnable = []
                for plan in pending:
                    plan_key = (plan.tool, plan.command_mode, tuple(sorted(plan.parameters.items())))
                    if plan_key in considered:
                        continue
                    considered.add(plan_key)
                    if not plan.available:
                        continue
                    runnable.append(plan)
                executions = self._run_plans(runner, artifact, runnable)
                # External processes can run concurrently, while parsing,
                # lineage promotion, and child analysis retain stable plan
                # order for reproducible reports across --jobs values.
                for plan, execution in executions:
                    result.tool_runs.append(execution.run)
                    result.observations.extend(execution.observations)
                    result.findings.extend(execution.findings)
                    if execution.run.error:
                        self._record_errors(
                            workspace, result, artifact.id,
                            [execution.run.error], f"tool_runner:{execution.run.tool}",
                        )
                    finding_keys.update(self._finding_key(finding) for finding in execution.findings)
                    output_flags = self._scan_tool_output_flags(workspace, artifact, execution.run)
                    if output_flags:
                        workspace.database.add_flags(output_flags)
                        result.flags.extend(output_flags)
                    generated = extraction.register_tool_outputs(artifact, execution.run)
                    if generated.findings:
                        workspace.database.add_findings(generated.findings)
                        result.findings.extend(generated.findings)
                        finding_keys.update(self._finding_key(finding) for finding in generated.findings)
                    if generated.errors:
                        self._record_errors(workspace, result, artifact.id, generated.errors, "tool_output_registrar")
                    for child in generated.artifacts:
                        result.artifacts.append(child)
                        self._analyze_artifact(workspace, result, child, mode, execute, extraction)
                parsed_observations = workspace.database.observations(artifact.id)
                refreshed = self.identification.identify(artifact, parsed_observations)
                workspace.database.update_artifact_identification(artifact)
                workspace.database.add_observations(refreshed.observations)
                result.observations.extend(refreshed.observations)
                parsed_observations.extend(refreshed.observations)
                post_profiles, post_rules = self._decide(artifact, parsed_observations)
                if post_profiles.observations:
                    workspace.database.add_observations(post_profiles.observations)
                    result.observations.extend(post_profiles.observations)
                    parsed_observations.extend(post_profiles.observations)
                post_findings = [
                    finding
                    for finding in [*post_profiles.findings, *post_rules.findings]
                    if self._finding_key(finding) not in finding_keys
                ]
                # Persisted finding IDs make this harmless when a structural
                # profile reaches the same conclusion more than once.
                if post_findings:
                    workspace.database.add_findings(post_findings)
                    result.findings.extend(post_findings)
                    finding_keys.update(self._finding_key(finding) for finding in post_findings)
                post_recommendations = [*post_profiles.recommendations, *post_rules.recommendations]
                next_pending = self._plan_tools(workspace, artifact, post_recommendations, mode)
                new_plans = [
                    plan for plan in next_pending
                    if (plan.tool, plan.command_mode, tuple(sorted(plan.parameters.items()))) not in considered
                ]
                result.plans.extend(new_plans)
                self._record_plans(workspace, result, artifact.id, new_plans)
                if not new_plans:
                    break
                pending = new_plans
        metadata_flags = self._scan_jpeg_xmp_flags(artifact, observations)
        if metadata_flags:
            workspace.database.add_flags(metadata_flags)
            result.flags.extend(metadata_flags)
        smtp_flags = self._scan_smtp_alternative_flags(path, artifact)
        if smtp_flags:
            workspace.database.add_flags(smtp_flags)
            result.flags.extend(smtp_flags)
        flags = FlagHunter(self.config.flag_patterns, self.config.limits.max_string_scan_bytes).scan(path, artifact)
        workspace.database.add_flags(flags)
        result.flags.extend(flags)
        if self.config.extract and self.config.recursive and mode in {AnalysisMode.AUTO, AnalysisMode.DEEP}:
            extracted = extraction.extract_supported(artifact)
            if extracted.errors:
                self._record_errors(
                    workspace, result, artifact.id,
                    [f"{artifact.logical_name}: {error}" for error in extracted.errors], "extraction_manager",
                )
            if extracted.findings:
                workspace.database.add_findings(extracted.findings)
                result.findings.extend(extracted.findings)
            if extracted.artifacts:
                result.artifacts.extend(extracted.artifacts)
                for child in extracted.artifacts:
                    self._analyze_artifact(workspace, result, child, mode, execute, extraction)

    def _decide(self, artifact, observations):
        profile_result = self.profiles.evaluate(artifact, observations)
        rule_result = self.rules.evaluate(
            artifact, observations, profiles=profile_result.active_profiles
        )
        return profile_result, rule_result

    def _plan_tools(self, workspace, artifact, recommendations, mode):
        """Apply explicit CLI scope filters after evidence-backed planning.

        Filters never manufacture a tool recommendation; they only narrow the
        normal deterministic plan.  ``--tool`` is matched against canonical
        registry names and ``--category`` against a definition's declared
        forensic profiles (for example ``image``, ``pcap``, or ``windows``).
        """
        plans = ToolPlanner(workspace, self.registry).plan(artifact, recommendations, mode)
        allowed_tools = {item.casefold() for item in self.config.tool_allowlist if item.strip()}
        categories = {item.casefold() for item in self.config.category_filter if item.strip()}
        if allowed_tools:
            plans = [plan for plan in plans if plan.tool.casefold() in allowed_tools]
        if categories:
            scoped = []
            for plan in plans:
                try:
                    profiles = {item.casefold() for item in self.registry.get(plan.tool).profiles}
                except KeyError:
                    continue
                if profiles & categories:
                    scoped.append(plan)
            plans = scoped
        return plans

    def _run_plans(self, runner, artifact, plans):
        """Run independent external plans with the configured job bound."""
        if not plans:
            return []

        def invoke(plan):
            return runner.run(
                plan.tool,
                artifact,
                mode=plan.command_mode,
                timeout=plan.timeout,
                template_values=plan.parameters,
            )

        workers = min(self.config.limits.jobs, len(plans))
        if workers <= 1:
            return [(plan, invoke(plan)) for plan in plans]
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="forensickit-tool") as pool:
            futures = [pool.submit(invoke, plan) for plan in plans]
            return [(plan, future.result()) for plan, future in zip(plans, futures)]

    @staticmethod
    def _correlate_case_roots(workspace, result) -> None:
        """Link supplied iOS backup payload roots to Manifest.db rows safely.

        iTunes/iOS backups name payload files using a 40-hex-character file
        ID.  When a user supplies both Manifest.db and one or more such files
        as independent roots, the association is strong and needs no path
        traversal, BLOB decoding, or lookup outside the case workspace.  We
        deliberately leave both inputs as roots: correlation is provenance,
        not an extraction parent-child claim.
        """
        artifacts = workspace.database.artifacts()
        roots = [artifact for artifact in artifacts if artifact.parent_id is None]
        AnalysisEngine._correlate_registry_transaction_logs(workspace, result, roots)
        AnalysisEngine._correlate_recycle_bin_pairs(workspace, result, roots)
        AnalysisEngine._correlate_windows_process_evidence(workspace, result, artifacts)
        AnalysisEngine._correlate_windows_execution_artifacts(workspace, result, artifacts)
        AnalysisEngine._correlate_windows_registry_execution(workspace, result, artifacts)
        AnalysisEngine._correlate_usn_mft_records(workspace, result, artifacts)
        root_by_file_id = {
            artifact.logical_name.casefold(): artifact
            for artifact in roots
            if re.fullmatch(r"[0-9a-fA-F]{40}", artifact.logical_name)
        }
        if not root_by_file_id:
            return
        observations_by_artifact: dict[str, list[Observation]] = {}
        for observation in workspace.database.observations():
            observations_by_artifact.setdefault(observation.artifact_id, []).append(observation)
        additions: list[Observation] = []
        findings: list[Finding] = []
        for manifest in roots:
            samples = next(
                (
                    observation.value
                    for observation in observations_by_artifact.get(manifest.id, [])
                    if observation.key == "mobile.ios_manifest_file_references" and isinstance(observation.value, list)
                ),
                next(
                    (
                        observation.value
                        for observation in observations_by_artifact.get(manifest.id, [])
                        if observation.key == "mobile.ios_manifest_file_samples" and isinstance(observation.value, list)
                    ),
                    [],
                ),
            )
            if not samples:
                continue
            links: list[dict[str, str]] = []
            for sample in samples:
                if not isinstance(sample, dict):
                    continue
                file_id = sample.get("file_id")
                if not isinstance(file_id, str):
                    continue
                payload = root_by_file_id.get(file_id.casefold())
                if payload is None:
                    continue
                link = {
                    "file_id": file_id,
                    "payload_artifact_id": payload.id,
                    "domain": str(sample.get("domain") or ""),
                    "relative_path": str(sample.get("relative_path") or ""),
                }
                links.append(link)
                additions.append(Observation(
                    artifact_id=payload.id,
                    key="mobile.ios_manifest_reference",
                    value={**link, "manifest_artifact_id": manifest.id},
                    source="ios_backup_correlator",
                    confidence=0.99,
                ))
            if not links:
                continue
            additions.append(Observation(
                artifact_id=manifest.id,
                key="mobile.ios_manifest_supplied_payloads",
                value=links,
                source="ios_backup_correlator",
                confidence=0.99,
            ))
            findings.append(Finding(
                artifact_id=manifest.id,
                title=f"Correlated {len(links)} supplied iOS backup payload file(s)",
                category="ios_backup_payload_correlation",
                severity="info",
                confidence=0.99,
                explanation=(
                    "Manifest.db file IDs exactly match independently supplied 40-hex payload root names. "
                    "The associations are recorded as case-level provenance; no payload path was inferred or opened outside this case."
                ),
                source="ios_backup_correlator",
                supporting_evidence=[
                    f"manifest:{manifest.id}",
                    *[f"{item['file_id']}→{item['payload_artifact_id']}" for item in links],
                ],
            ))
        if additions:
            workspace.database.add_observations(additions)
            result.observations.extend(additions)
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)

    @staticmethod
    def _correlate_usn_mft_records(workspace, result, artifacts) -> None:
        """Link V2 journal events only to exact sampled ancestor FILE identities."""
        by_id = {artifact.id: artifact for artifact in artifacts}
        observations_by_artifact: dict[str, list[Observation]] = {}
        for observation in workspace.database.observations():
            observations_by_artifact.setdefault(observation.artifact_id, []).append(observation)
        additions: list[Observation] = []
        findings: list[Finding] = []
        for journal in artifacts:
            journal_observation = next(
                (
                    observation for observation in observations_by_artifact.get(journal.id, [])
                    if observation.key == "ntfs.usn.records" and isinstance(observation.value, list)
                ),
                None,
            )
            if journal_observation is None:
                continue
            ancestor = by_id.get(journal.parent_id) if journal.parent_id else None
            mft_observation = None
            visited: set[str] = set()
            while ancestor is not None and ancestor.id not in visited and len(visited) < 16:
                visited.add(ancestor.id)
                mft_observation = next(
                    (
                        observation for observation in observations_by_artifact.get(ancestor.id, [])
                        if observation.key == "filesystem.ntfs.mft_sample_records"
                        and isinstance(observation.value, list)
                    ),
                    None,
                )
                if mft_observation is not None:
                    break
                ancestor = by_id.get(ancestor.parent_id) if ancestor.parent_id else None
            if ancestor is None or mft_observation is None:
                continue
            sampled = {
                item.get("record_number"): item
                for item in mft_observation.value
                if isinstance(item, dict)
                and isinstance(item.get("record_number"), int)
                and isinstance(item.get("sequence_number"), int)
                and item.get("signature_valid") is True
                and item.get("bounds_valid") is True
                and item.get("usa_fixup_valid") is True
            }
            links: list[dict[str, object]] = []
            for event in journal_observation.value[:10_000]:
                if not isinstance(event, dict):
                    continue
                record_number = event.get("file_record_number")
                sequence_number = event.get("file_sequence_number")
                sample = sampled.get(record_number) if isinstance(record_number, int) else None
                if not isinstance(sample, dict) or sample.get("sequence_number") != sequence_number:
                    continue
                links.append({
                    "journal_artifact_id": journal.id,
                    "ancestor_artifact_id": ancestor.id,
                    "journal_observation_id": journal_observation.id,
                    "mft_observation_id": mft_observation.id,
                    "usn": event.get("usn"),
                    "journal_offset": event.get("offset"),
                    "timestamp": event.get("timestamp"),
                    "reason": event.get("reason"),
                    "reason_names": event.get("reason_names"),
                    "journal_file_name": event.get("file_name"),
                    "record_number": record_number,
                    "sequence_number": sequence_number,
                    "sample_file_names": sample.get("file_names"),
                    "sample_deleted": sample.get("deleted"),
                    "sample_physical_segments": sample.get("physical_segments"),
                })
                if len(links) >= 2_000:
                    break
            if not links:
                continue
            additions.extend([
                Observation(
                    artifact_id=journal.id,
                    key="correlation.usn_sampled_mft",
                    value=links,
                    source="usn_mft_correlator",
                    confidence=0.97,
                ),
                Observation(
                    artifact_id=ancestor.id,
                    key="correlation.sampled_mft_usn",
                    value=links,
                    source="usn_mft_correlator",
                    confidence=0.97,
                ),
            ])
            findings.append(Finding(
                artifact_id=journal.id,
                title=f"Correlated {len(links)} USN event(s) to exact sampled MFT identities",
                category="ntfs_usn_mft_correlation",
                severity="info",
                confidence=0.97,
                explanation=(
                    "V2 journal file record and sequence numbers exactly match USA-validated FILE records sampled from the journal artifact's ancestor image. "
                    "The relationship retains both observation IDs, artifact lineage, stream offset, and physical MFT segments; names are context rather than match keys."
                ),
                source="usn_mft_correlator",
                supporting_evidence=[str(item)[:2_000] for item in links[:128]],
            ))
        if additions:
            workspace.database.add_observations(additions)
            result.observations.extend(additions)
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)

    @staticmethod
    def _correlate_windows_process_evidence(workspace, result, artifacts) -> None:
        """Link EVTX and memory process evidence only under two exact keys."""
        artifact_by_id = {artifact.id: artifact for artifact in artifacts}
        observations = workspace.database.observations()
        native_offsets: dict[tuple[str, int], int] = {}
        memory_records: list[tuple[object, Observation, dict[str, object]]] = []
        event_records: list[tuple[object, Observation, dict[str, object]]] = []
        for observation in observations:
            artifact = artifact_by_id.get(observation.artifact_id)
            if artifact is None or not isinstance(observation.value, list):
                continue
            if observation.key == "evtx.normalized_record_correlations":
                for item in observation.value[:500]:
                    if not isinstance(item, dict):
                        continue
                    record_id = AnalysisEngine._bounded_pid(item.get("event_record_id"))
                    offset = item.get("record_offset")
                    if record_id is not None and isinstance(offset, int):
                        native_offsets[(artifact.id, record_id)] = offset
            elif observation.key == "memory.process_correlations":
                for item in observation.value[:256]:
                    if isinstance(item, dict):
                        memory_records.append((artifact, observation, item))
            elif observation.key in {
                "windows.event_hunt.normalized_events",
                "windows.event_timeline.normalized_events",
            }:
                for item in observation.value[:5_000]:
                    if isinstance(item, dict):
                        event_records.append((artifact, observation, item))
        if not memory_records or not event_records:
            return

        additions_by_artifact: dict[str, list[dict[str, object]]] = {}
        seen: set[tuple[str, str, int, object, object]] = set()
        for event_artifact, event_observation, event in event_records[:10_000]:
            event_pid = AnalysisEngine._bounded_pid(event.get("process_id"))
            if event_pid is None:
                continue
            event_name = AnalysisEngine._windows_basename(event.get("process_path"))
            event_ips = {
                value for key in ("source_ip", "destination_ip")
                if (value := AnalysisEngine._endpoint_ip(event.get(key))) is not None
            }
            for memory_artifact, memory_observation, memory in memory_records[:2_000]:
                if memory_artifact.id == event_artifact.id:
                    continue
                memory_pid = AnalysisEngine._bounded_pid(memory.get("pid"))
                if memory_pid != event_pid:
                    continue
                memory_names: set[str] = set()
                for section in ("processes", "commands"):
                    rows = memory.get(section)
                    if not isinstance(rows, list):
                        continue
                    for row in rows[:32]:
                        if not isinstance(row, dict):
                            continue
                        for key, value in row.items():
                            if str(key).casefold() in {"name", "process", "image", "path"}:
                                name = AnalysisEngine._windows_basename(value)
                                if name:
                                    memory_names.add(name)
                memory_ips: set[str] = set()
                rows = memory.get("network")
                if isinstance(rows, list):
                    for row in rows[:32]:
                        if not isinstance(row, dict):
                            continue
                        for key, value in row.items():
                            if str(key).casefold().replace("_", "") in {
                                "localaddr", "localaddress", "foreignaddr", "foreignaddress",
                                "remoteaddr", "remoteaddress",
                            }:
                                address = AnalysisEngine._endpoint_ip(value)
                                if address:
                                    memory_ips.add(address)
                matched_names = sorted({event_name} & memory_names) if event_name else []
                matched_ips = sorted(event_ips & memory_ips)
                if not matched_names and not matched_ips:
                    continue
                key = (
                    event_artifact.id, memory_artifact.id, event_pid,
                    event.get("event_record_id"), event.get("source_record_index"),
                )
                if key in seen:
                    continue
                seen.add(key)
                record_id = AnalysisEngine._bounded_pid(event.get("event_record_id"))
                basis = ["exact_pid"]
                if matched_names:
                    basis.append("exact_process_basename")
                if matched_ips:
                    basis.append("exact_ip_endpoint")
                confidence = 0.92 if len(basis) == 3 else 0.88 if matched_names else 0.82
                link: dict[str, object] = {
                    "event_artifact_id": event_artifact.id,
                    "event_logical_name": event_artifact.logical_name,
                    "memory_artifact_id": memory_artifact.id,
                    "memory_logical_name": memory_artifact.logical_name,
                    "pid": event_pid,
                    "match_basis": basis,
                    "matched_process_names": matched_names,
                    "matched_ip_endpoints": matched_ips,
                    "event_id": event.get("event_id"),
                    "event_record_id": record_id,
                    "event_record_offset": native_offsets.get((event_artifact.id, record_id)) if record_id is not None else None,
                    "event_category": event.get("category"),
                    "event_timestamp": event.get("timestamp"),
                    "event_process_path": event.get("process_path"),
                    "event_command_line": event.get("command_line"),
                    "event_source_observation_id": event_observation.id,
                    "event_source": event_observation.source,
                    "memory_source_observation_id": memory_observation.id,
                    "memory_source": memory_observation.source,
                    "memory_evidence": {
                        section: memory.get(section, [])[:5]
                        for section in ("processes", "commands", "network")
                        if isinstance(memory.get(section), list)
                    },
                    "confidence": confidence,
                }
                additions_by_artifact.setdefault(event_artifact.id, []).append(link)
                additions_by_artifact.setdefault(memory_artifact.id, []).append(link)
                if len(seen) >= 500:
                    break
            if len(seen) >= 500:
                break
        if not additions_by_artifact:
            return
        additions: list[Observation] = []
        findings: list[Finding] = []
        for artifact_id, links in additions_by_artifact.items():
            is_event_side = any(link["event_artifact_id"] == artifact_id for link in links)
            additions.append(Observation(
                artifact_id=artifact_id,
                key=(
                    "correlation.evtx_memory_process"
                    if is_event_side else "correlation.memory_evtx_process"
                ),
                value=links[:500],
                source="windows_memory_correlator",
                confidence=max(float(link["confidence"]) for link in links),
            ))
            if is_event_side:
                findings.append(Finding(
                    artifact_id=artifact_id,
                    title=f"Correlated {len(links)} EVTX process event(s) with memory evidence",
                    category="windows_memory_process_correlation",
                    severity="low",
                    confidence=max(float(link["confidence"]) for link in links),
                    explanation=(
                        "An exact normalized PID plus an exact process basename or IP endpoint links EVTX and memory artifacts. "
                        "PID reuse and acquisition-time differences remain possible, so this is a cross-artifact verification lead rather than identity proof."
                    ),
                    source="windows_memory_correlator",
                    supporting_evidence=[str(link)[:3_000] for link in links[:30]],
                ))
        workspace.database.add_observations(additions)
        result.observations.extend(additions)
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)

    @staticmethod
    def _correlate_windows_execution_artifacts(workspace, result, artifacts) -> None:
        """Join EVTX process creation to supplied LNK/Prefetch metadata exactly."""
        artifact_by_id = {artifact.id: artifact for artifact in artifacts}
        all_observations = workspace.database.observations()
        observations_by_artifact: dict[str, list[Observation]] = {}
        event_records: list[tuple[object, Observation, dict[str, object]]] = []
        native_offsets: dict[tuple[str, int], int] = {}
        indicators: list[tuple[object, Observation, str, str]] = []
        for observation in all_observations:
            observations_by_artifact.setdefault(observation.artifact_id, []).append(observation)
            artifact = artifact_by_id.get(observation.artifact_id)
            if artifact is None:
                continue
            if observation.key in {
                "windows.event_hunt.normalized_events",
                "windows.event_timeline.normalized_events",
            } and isinstance(observation.value, list):
                for item in observation.value[:5_000]:
                    if isinstance(item, dict):
                        event_records.append((artifact, observation, item))
            elif observation.key == "evtx.normalized_record_correlations" and isinstance(observation.value, list):
                for item in observation.value[:500]:
                    if not isinstance(item, dict):
                        continue
                    record_id = AnalysisEngine._bounded_pid(item.get("event_record_id"))
                    offset = item.get("record_offset")
                    if record_id is not None and isinstance(offset, int):
                        native_offsets[(artifact.id, record_id)] = offset
            elif observation.key == "lnk.target_path":
                path = AnalysisEngine._windows_canonical_path(observation.value)
                if path:
                    indicators.append((artifact, observation, "lnk_target", path))
            elif observation.key == "prefetch.executable_name":
                name = AnalysisEngine._windows_basename(observation.value)
                if name:
                    indicators.append((artifact, observation, "prefetch_executable", name))
        if not event_records or not indicators:
            return

        additions_by_artifact: dict[str, list[dict[str, object]]] = {}
        seen: set[tuple[str, str, str, object, object]] = set()
        for event_artifact, event_observation, event in event_records[:10_000]:
            if event.get("category") != "process_creation" and str(event.get("event_id")) != "4688":
                continue
            event_path = AnalysisEngine._windows_canonical_path(event.get("process_path"))
            event_name = AnalysisEngine._windows_basename(event.get("process_path"))
            if event_path is None or event_name is None:
                continue
            record_id = AnalysisEngine._bounded_pid(event.get("event_record_id"))
            for evidence_artifact, indicator_observation, indicator_type, indicator in indicators:
                if evidence_artifact.id == event_artifact.id:
                    continue
                if indicator_type == "lnk_target":
                    if indicator != event_path:
                        continue
                    match_basis = "exact_windows_target_path"
                    confidence = 0.96
                else:
                    if indicator != event_name:
                        continue
                    match_basis = "exact_executable_basename"
                    confidence = 0.84
                key = (
                    event_artifact.id, evidence_artifact.id, indicator_type,
                    record_id, event.get("source_record_index"),
                )
                if key in seen:
                    continue
                seen.add(key)
                artifact_metadata: dict[str, object] = {}
                if indicator_type == "prefetch_executable":
                    wanted = {
                        "prefetch.executable_hash", "prefetch.run_count", "prefetch.version",
                        "prefetch.size_matches_evidence",
                    }
                    artifact_metadata = {
                        item.key.removeprefix("prefetch."): item.value
                        for item in observations_by_artifact.get(evidence_artifact.id, [])
                        if item.key in wanted
                    }
                link = {
                    "event_artifact_id": event_artifact.id,
                    "event_logical_name": event_artifact.logical_name,
                    "execution_artifact_id": evidence_artifact.id,
                    "execution_logical_name": evidence_artifact.logical_name,
                    "execution_artifact_type": indicator_type,
                    "match_basis": match_basis,
                    "matched_value": indicator,
                    "event_id": event.get("event_id"),
                    "event_record_id": record_id,
                    "event_record_offset": native_offsets.get((event_artifact.id, record_id)) if record_id is not None else None,
                    "event_timestamp": event.get("timestamp"),
                    "event_process_id": event.get("process_id"),
                    "event_process_path": event.get("process_path"),
                    "event_command_line": event.get("command_line"),
                    "event_source_observation_id": event_observation.id,
                    "event_source": event_observation.source,
                    "execution_source_observation_id": indicator_observation.id,
                    "execution_source": indicator_observation.source,
                    "execution_metadata": artifact_metadata,
                    "confidence": confidence,
                }
                additions_by_artifact.setdefault(event_artifact.id, []).append(link)
                additions_by_artifact.setdefault(evidence_artifact.id, []).append(link)
                if len(seen) >= 500:
                    break
            if len(seen) >= 500:
                break
        if not additions_by_artifact:
            return
        additions: list[Observation] = []
        findings: list[Finding] = []
        for artifact_id, links in additions_by_artifact.items():
            is_event_side = any(link["event_artifact_id"] == artifact_id for link in links)
            additions.append(Observation(
                artifact_id=artifact_id,
                key=(
                    "correlation.evtx_execution_artifacts"
                    if is_event_side else "correlation.execution_artifact_evtx"
                ),
                value=links[:500],
                source="windows_execution_correlator",
                confidence=max(float(link["confidence"]) for link in links),
            ))
            if is_event_side:
                findings.append(Finding(
                    artifact_id=artifact_id,
                    title=f"Correlated {len(links)} process event/execution artifact pair(s)",
                    category="windows_execution_artifact_correlation",
                    severity="info",
                    confidence=max(float(link["confidence"]) for link in links),
                    explanation=(
                        "A normalized process-creation event exactly matches an explicitly supplied LNK target path or Prefetch executable basename. "
                        "The association retains both immutable artifacts and parser observations; Prefetch basename-only matches remain lower-confidence leads."
                    ),
                    source="windows_execution_correlator",
                    supporting_evidence=[str(link)[:3_000] for link in links[:30]],
                ))
        workspace.database.add_observations(additions)
        result.observations.extend(additions)
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)

    @staticmethod
    def _correlate_windows_registry_execution(workspace, result, artifacts) -> None:
        """Join exact absolute Registry command paths to EVTX process creation."""
        artifact_by_id = {artifact.id: artifact for artifact in artifacts}
        all_observations = workspace.database.observations()
        observations_by_artifact: dict[str, list[Observation]] = {}
        event_records: list[tuple[object, Observation, dict[str, object]]] = []
        registry_paths: list[tuple[object, Observation, dict[str, object], str]] = []
        native_offsets: dict[tuple[str, int], int] = {}
        for observation in all_observations:
            observations_by_artifact.setdefault(observation.artifact_id, []).append(observation)
            artifact = artifact_by_id.get(observation.artifact_id)
            if artifact is None:
                continue
            if observation.key in {
                "windows.event_hunt.normalized_events",
                "windows.event_timeline.normalized_events",
            } and isinstance(observation.value, list):
                for item in observation.value[:5_000]:
                    if isinstance(item, dict):
                        event_records.append((artifact, observation, item))
            elif observation.key == "evtx.normalized_record_correlations" and isinstance(observation.value, list):
                for item in observation.value[:500]:
                    if not isinstance(item, dict):
                        continue
                    record_id = AnalysisEngine._bounded_pid(item.get("event_record_id"))
                    offset = item.get("record_offset")
                    if record_id is not None and isinstance(offset, int):
                        native_offsets[(artifact.id, record_id)] = offset
            elif observation.key == "registry.execution_value_data" and isinstance(observation.value, list):
                for item in observation.value[:256]:
                    if not isinstance(item, dict):
                        continue
                    for command_path in AnalysisEngine._registry_command_paths(item.get("data_text")):
                        registry_paths.append((artifact, observation, item, command_path))
                        if len(registry_paths) >= 512:
                            break
                    if len(registry_paths) >= 512:
                        break
        if not event_records or not registry_paths:
            return

        additions_by_artifact: dict[str, list[dict[str, object]]] = {}
        seen: set[tuple[str, str, object, str]] = set()
        for event_artifact, event_observation, event in event_records[:10_000]:
            if event.get("category") != "process_creation" and str(event.get("event_id")) != "4688":
                continue
            event_path = AnalysisEngine._windows_canonical_path(event.get("process_path"))
            if event_path is None:
                continue
            record_id = AnalysisEngine._bounded_pid(event.get("event_record_id"))
            for registry_artifact, registry_observation, value_record, command_path in registry_paths:
                if registry_artifact.id == event_artifact.id or command_path != event_path:
                    continue
                key = (event_artifact.id, registry_artifact.id, record_id, command_path)
                if key in seen:
                    continue
                seen.add(key)
                transaction_logs = next(
                    (
                        item.value for item in observations_by_artifact.get(registry_artifact.id, [])
                        if item.key == "registry.transaction_log_companions" and isinstance(item.value, list)
                    ),
                    [],
                )
                link = {
                    "event_artifact_id": event_artifact.id,
                    "event_logical_name": event_artifact.logical_name,
                    "registry_artifact_id": registry_artifact.id,
                    "registry_logical_name": registry_artifact.logical_name,
                    "match_basis": "exact_absolute_executable_path",
                    "matched_path": command_path,
                    "event_id": event.get("event_id"),
                    "event_record_id": record_id,
                    "event_record_offset": native_offsets.get((event_artifact.id, record_id)) if record_id is not None else None,
                    "event_timestamp": event.get("timestamp"),
                    "event_process_id": event.get("process_id"),
                    "event_process_path": event.get("process_path"),
                    "event_command_line": event.get("command_line"),
                    "registry_key_path": value_record.get("key_path") or value_record.get("key"),
                    "registry_value_name": value_record.get("name"),
                    "registry_value_type": value_record.get("type"),
                    "registry_value_data": value_record.get("data_text"),
                    "registry_transaction_logs": transaction_logs[:2],
                    "event_source_observation_id": event_observation.id,
                    "event_source": event_observation.source,
                    "registry_source_observation_id": registry_observation.id,
                    "registry_source": registry_observation.source,
                }
                additions_by_artifact.setdefault(event_artifact.id, []).append(link)
                additions_by_artifact.setdefault(registry_artifact.id, []).append(link)
                if len(seen) >= 500:
                    break
            if len(seen) >= 500:
                break
        if not additions_by_artifact:
            return
        additions: list[Observation] = []
        findings: list[Finding] = []
        for artifact_id, links in additions_by_artifact.items():
            is_event_side = any(link["event_artifact_id"] == artifact_id for link in links)
            additions.append(Observation(
                artifact_id=artifact_id,
                key=(
                    "correlation.evtx_registry_execution"
                    if is_event_side else "correlation.registry_evtx_execution"
                ),
                value=links[:500],
                source="windows_registry_execution_correlator",
                confidence=0.95,
            ))
            if is_event_side:
                findings.append(Finding(
                    artifact_id=artifact_id,
                    title=f"Correlated {len(links)} process event/Registry execution value pair(s)",
                    category="windows_registry_execution_correlation",
                    severity="medium",
                    confidence=0.95,
                    explanation=(
                        "A normalized EVTX process-creation path exactly matches a bounded absolute executable path recovered from an allowlisted Registry execution/persistence value. "
                        "This supports an execution-to-configuration relationship but does not establish when the Registry value was created."
                    ),
                    source="windows_registry_execution_correlator",
                    supporting_evidence=[str(link)[:3_000] for link in links[:30]],
                ))
        workspace.database.add_observations(additions)
        result.observations.extend(additions)
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)

    @staticmethod
    def _bounded_pid(value: object) -> int | None:
        if isinstance(value, bool) or value is None:
            return None
        text = str(value).strip().casefold()
        try:
            parsed = int(text, 0) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
        return parsed if 0 <= parsed <= 0xFFFFFFFF else None

    @staticmethod
    def _windows_basename(value: object) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        normalized = ntpath.basename(value.strip().replace("/", "\\")).casefold()
        return normalized[:512] if normalized and normalized not in {".", ".."} else None

    @staticmethod
    def _windows_canonical_path(value: object) -> str | None:
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            return None
        normalized = value.strip().replace("/", "\\")
        for prefix in ("\\\\?\\", "\\??\\"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        normalized = ntpath.normpath(normalized).casefold()
        return normalized[:4_096] if normalized not in {"", ".", ".."} else None

    @staticmethod
    def _registry_command_paths(value: object) -> list[str]:
        values = value if isinstance(value, list) else [value]
        output: list[str] = []
        pattern = re.compile(
            r'(?i)(?:"(?P<quoted>(?:[a-z]:\\|\\\\)[^"\r\n]{1,2048}?\.(?:exe|com|bat|cmd|ps1))"|'
            r'(?P<plain>(?:[a-z]:\\|\\\\)[^"\r\n]{1,2048}?\.(?:exe|com|bat|cmd|ps1)))'
        )
        for item in values[:32]:
            if not isinstance(item, str) or not item or "%" in item:
                continue
            for match in pattern.finditer(item[:8_192]):
                candidate = match.group("quoted") or match.group("plain")
                normalized = AnalysisEngine._windows_canonical_path(candidate)
                if normalized and normalized not in output:
                    output.append(normalized)
                if len(output) >= 16:
                    return output
        return output

    @staticmethod
    def _endpoint_ip(value: object) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip()
        if text.startswith("[") and "]" in text:
            text = text[1:text.index("]")]
        elif text.count(":") == 1 and "." in text:
            host, port = text.rsplit(":", 1)
            if port.isdigit():
                text = host
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None

    @staticmethod
    def _correlate_recycle_bin_pairs(workspace, result, roots) -> None:
        """Link only explicitly supplied `$I`/`$R` root pairs by exact suffix."""
        by_name = {artifact.logical_name.casefold(): artifact for artifact in roots}
        observations = {artifact.id: [] for artifact in roots}
        for observation in workspace.database.observations():
            observations.setdefault(observation.artifact_id, []).append(observation)
        additions: list[Observation] = []
        findings: list[Finding] = []
        for metadata in roots:
            name = metadata.logical_name
            if not name.casefold().startswith("$i") or len(name) < 3:
                continue
            valid = any(item.key == "windows.recycle_bin_valid" and item.value is True for item in observations.get(metadata.id, []))
            companion = by_name.get(("$r" + name[2:]).casefold())
            if not valid or companion is None:
                continue
            link = {"metadata_artifact_id": metadata.id, "content_artifact_id": companion.id, "metadata_logical_name": metadata.logical_name, "content_logical_name": companion.logical_name, "content_sha256": companion.sha256}
            additions.extend((
                Observation(artifact_id=metadata.id, key="windows.recycle_bin_content_companion", value=link, source="recycle_bin_correlator", confidence=0.99),
                Observation(artifact_id=companion.id, key="windows.recycle_bin_metadata_companion", value=link, source="recycle_bin_correlator", confidence=0.99),
            ))
            findings.append(Finding(
                artifact_id=metadata.id, title="Matched supplied Recycle Bin content companion", category="windows_recycle_bin_pair",
                severity="info", confidence=0.99,
                explanation="An explicitly supplied `$R` root has the exact suffix matching this valid `$I` metadata record. The association is case provenance only; neither file is opened by inferred path.",
                source="recycle_bin_correlator", supporting_evidence=[f"metadata:{metadata.id}", f"content:{companion.id}"],
            ))
        if additions:
            workspace.database.add_observations(additions)
            result.observations.extend(additions)
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)

    @staticmethod
    def _correlate_registry_transaction_logs(workspace, result, roots) -> None:
        """Record exact supplied hive/LOG1/LOG2 pairs without path inference.

        Registry replay needs a base hive plus its matching transaction logs.
        The files stay independent immutable roots: this records recovery-ready
        provenance only and never modifies a hive or invents a missing log.
        """
        by_name = {artifact.logical_name.casefold(): artifact for artifact in roots}
        observations_by_artifact: dict[str, list[Observation]] = {}
        for observation in workspace.database.observations():
            observations_by_artifact.setdefault(observation.artifact_id, []).append(observation)
        additions: list[Observation] = []
        findings: list[Finding] = []
        for hive in roots:
            canonical_name = hive.logical_name.casefold()
            if canonical_name.endswith((".log1", ".log2")):
                continue
            is_registry = hive.artifact_type == "registry" or any(
                observation.key == "windows.registry_signature" and observation.value is True
                for observation in observations_by_artifact.get(hive.id, [])
            )
            if not is_registry:
                continue
            logs = []
            for suffix, role in ((".log1", "LOG1"), (".log2", "LOG2")):
                log = by_name.get(f"{canonical_name}{suffix}")
                if log is None:
                    continue
                logs.append({
                    "role": role,
                    "logical_name": log.logical_name,
                    "artifact_id": log.id,
                    "sha256": log.sha256,
                })
                additions.append(Observation(
                    artifact_id=log.id,
                    key="registry.transaction_log_for",
                    value={
                        "hive_artifact_id": hive.id,
                        "hive_logical_name": hive.logical_name,
                        "role": role,
                    },
                    source="registry_transaction_log_correlator",
                    confidence=0.99,
                ))
            if not logs:
                continue
            additions.append(Observation(
                artifact_id=hive.id,
                key="registry.transaction_log_companions",
                value=logs,
                source="registry_transaction_log_correlator",
                confidence=0.99,
            ))
            findings.append(Finding(
                artifact_id=hive.id,
                title=f"Matched {len(logs)} supplied Registry transaction log companion(s)",
                category="registry_transaction_log_recovery",
                severity="info",
                confidence=0.99,
                explanation=(
                    "Exact supplied root names associate this hive with LOG1/LOG2 transaction logs. "
                    "Copy the matched set into a controlled recovery workspace and verify replay with a Registry-aware tool; "
                    "the original evidence remains immutable."
                ),
                source="registry_transaction_log_correlator",
                supporting_evidence=[
                    f"hive:{hive.id}",
                    *[f"{item['role']}:{item['artifact_id']}" for item in logs],
                ],
            ))
        if additions:
            workspace.database.add_observations(additions)
            result.observations.extend(additions)
        if findings:
            workspace.database.add_findings(findings)
            result.findings.extend(findings)

    def _scan_tool_output_flags(self, workspace, artifact, run) -> list:
        """Apply the same bounded transform-aware flag hunt to raw tool logs."""
        hunter = FlagHunter(self.config.flag_patterns, self.config.limits.max_string_scan_bytes)
        candidates = []
        for label, stored_path in (("stdout", run.stdout_path), ("stderr", run.stderr_path)):
            if not stored_path:
                continue
            try:
                path = workspace.resolve_stored_path(stored_path)
                with path.open("rb") as stream:
                    raw = stream.read(self.config.limits.max_string_scan_bytes + 1)
            except OSError:
                continue
            candidates.extend(hunter.scan_bytes(
                raw[: self.config.limits.max_string_scan_bytes],
                artifact,
                source=f"tool_output_flag_hunter:{run.tool}:{run.id}",
                location_prefix=f"tool run {run.id} {label}",
                truncated=len(raw) > self.config.limits.max_string_scan_bytes,
            ))
        return candidates

    def _scan_dns_txt_reassembly_flags(self, artifact, observations) -> list:
        """Hunt flags in bounded, provenance-bearing native DNS reconstructions."""
        hunter = FlagHunter(self.config.flag_patterns, self.config.limits.max_string_scan_bytes)
        candidates = []
        for observation in observations:
            if observation.key not in {"pcap.dns.txt_reassemblies", "pcap.dns.label_reassemblies"} or not isinstance(observation.value, list):
                continue
            kind = "dns_txt_fragment_reassembly" if observation.key.endswith("txt_reassemblies") else "dns_label_fragment_reassembly"
            for item in observation.value[:100]:
                if not isinstance(item, dict) or item.get("transform") not in {"base64", "hex"}:
                    continue
                decoded = item.get("decoded_text")
                if not isinstance(decoded, str) or not decoded:
                    continue
                source = str(item.get("source", "?"))[:200]
                destination = str(item.get("destination", "?"))[:200]
                packets = item.get("packet_indices", [])
                location = f"DNS TXT {source}->{destination}; packets {packets}"
                for candidate in hunter.scan_bytes(
                    decoded.encode("utf-8", errors="replace"), artifact,
                    source="dns_txt_fragment_flag_hunter", location_prefix=location,
                ):
                    candidate.transform_chain = [kind, str(item["transform"]), *candidate.transform_chain]
                    candidates.append(candidate)
        return candidates

    def _scan_printable_pcap_payload_flags(self, artifact, observations) -> list:
        hunter = FlagHunter(self.config.flag_patterns, self.config.limits.max_string_scan_bytes)
        candidates = []
        seen_payloads: set[tuple[str, object, str]] = set()
        for observation in observations:
            if observation.key not in {"pcap.udp.printable_payloads", "pcap.icmp.printable_payloads", "pcap.tcp.printable_payloads"} or not isinstance(observation.value, list):
                continue
            protocol = observation.key.split(".")[1]
            for item in observation.value[:500]:
                if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                    continue
                payload_key = (protocol, item.get("packet_index"), item["text"])
                if payload_key in seen_payloads:
                    continue
                seen_payloads.add(payload_key)
                location = f"{protocol} packet {item.get('packet_index', '?')} {item.get('source', '?')}->{item.get('destination', '?')}"
                candidates.extend(hunter.scan_bytes(item["text"].encode("utf-8", errors="replace"), artifact, source="pcap_payload_flag_hunter", location_prefix=location))
        return candidates

    def _scan_jpeg_xmp_flags(self, artifact, observations) -> list:
        """Hunt bounded JPEG XMP text with APP1 segment provenance."""
        hunter = FlagHunter(self.config.flag_patterns, self.config.limits.max_string_scan_bytes)
        candidates = []
        for observation in observations:
            if observation.key != "jpeg.xmp_packets" or not isinstance(observation.value, list):
                continue
            for packet in observation.value[:32]:
                if not isinstance(packet, dict) or not isinstance(packet.get("text"), str):
                    continue
                offset = packet.get("offset", "?")
                candidates.extend(hunter.scan_bytes(
                    packet["text"].encode("utf-8", errors="replace"), artifact,
                    source="jpeg_xmp_flag_hunter", location_prefix=f"JPEG APP1 XMP offset {offset}",
                ))
        return candidates

    def _scan_smtp_alternative_flags(self, path: Path, artifact) -> list:
        """Scan top-level multipart/alternative text parts with MIME provenance."""
        if not artifact.logical_name.lower().endswith(".eml") or artifact.size > self.config.limits.max_string_scan_bytes:
            return []
        try:
            message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        except (OSError, ValueError):
            return []
        if message.get_content_type() != "multipart/alternative":
            return []
        hunter = FlagHunter(self.config.flag_patterns, self.config.limits.max_string_scan_bytes)
        candidates = []
        seen_values: set[str] = set()
        for index, part in enumerate(message.iter_parts()):
            if index >= 16 or part.get_content_maintype() != "text":
                continue
            payload = part.get_payload(decode=True)
            if not isinstance(payload, bytes):
                continue
            for candidate in hunter.scan_bytes(payload, artifact, source="smtp_multipart_alternative_flag_hunter", location_prefix=f"SMTP multipart/alternative part {index} {part.get_content_type()}"):
                if candidate.value not in seen_values:
                    candidates.append(candidate)
                    seen_values.add(candidate.value)
        return candidates

    @staticmethod
    def _finding_key(finding) -> tuple[str, str, str, str]:
        return (finding.artifact_id, finding.title, finding.category, finding.source)

    @staticmethod
    def _record_plans(workspace, result, artifact_id, plans) -> None:
        if not plans:
            return
        observations = [
            Observation(
                artifact_id=artifact_id,
                key="planner.tool_plan",
                value={
                    "tool": plan.tool,
                    "mode": plan.mode.value,
                    "priority": plan.priority,
                    "available": plan.available,
                    "cost": plan.cost,
                    "command_mode": plan.command_mode,
                    "parameters": plan.parameters,
                    "timeout": plan.timeout,
                    "command_argv": plan.command_argv,
                    "reasons": plan.reasons,
                },
                source="tool_planner",
            )
            for plan in plans
        ]
        workspace.database.add_observations(observations)
        result.observations.extend(observations)

    @staticmethod
    def _record_errors(workspace, result, artifact_id: str | None, messages, source: str) -> None:
        normalized = [str(message)[:4_000] for message in messages if str(message)]
        if not normalized:
            return
        result.errors.extend(normalized)
        workspace.database.add_errors([
            AnalysisError(artifact_id=artifact_id, message=message, source=source)
            for message in normalized
        ])
