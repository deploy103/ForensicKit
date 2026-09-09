from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .models import AnalysisMode, Artifact, Finding, Observation, ToolRun, ToolRunStatus
from .profiles import ToolRecommendation, merge_recommendations


_OPERATORS = frozenset(
    {"equals", "not_equals", "greater_than", "less_than", "contains", "exists"}
)
_LOGICAL = frozenset({"all", "any"})
_OBSERVATION_ALIASES: dict[str, tuple[str, ...]] = {
    # ``artifact.format`` is the declarative rule vocabulary; the bounded
    # in-process triage engine records how it derived that value explicitly.
    "artifact.format": ("triage.detected_header_format", "file.format", "format"),
}


@dataclass(frozen=True, slots=True)
class RuleValidationError:
    location: str
    message: str
    rule_id: str | None = None

    def __str__(self) -> str:
        prefix = f"rule {self.rule_id}: " if self.rule_id else ""
        return f"{prefix}{self.location}: {self.message}"


@dataclass(frozen=True, slots=True)
class RuleFindingSpec:
    title: str
    category: str
    severity: str = "medium"
    confidence: float = 0.5
    explanation: str | None = None
    supporting_evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleObservationSpec:
    key: str
    value: Any
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class RuleConfidenceChange:
    target: str
    delta: float
    reason: str
    rule_id: str


@dataclass(frozen=True, slots=True)
class RuleActionSpec:
    kind: str
    target: str
    tool: str | None = None
    modes: frozenset[AnalysisMode] = frozenset({AnalysisMode.DEEP})
    command_mode: str = "default"
    parameters: Mapping[str, str] = field(default_factory=dict)
    priority: int = 70


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    id: str
    profiles: frozenset[str]
    when: Mapping[str, Any]
    findings: tuple[RuleFindingSpec, ...]
    recommend_auto: tuple[str, ...]
    recommend_deep: tuple[str, ...]
    observations: tuple[RuleObservationSpec, ...] = ()
    confidence_changes: tuple[tuple[str, float, str], ...] = ()
    actions: tuple[RuleActionSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class FiredRule:
    rule_id: str
    reasons: tuple[str, ...]


@dataclass(slots=True)
class RuleEvaluationResult:
    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    recommendations: list[ToolRecommendation] = field(default_factory=list)
    confidence_changes: list[RuleConfidenceChange] = field(default_factory=list)
    actions: list[RuleActionSpec] = field(default_factory=list)
    fired_rules: list[FiredRule] = field(default_factory=list)
    validation_errors: list[RuleValidationError] = field(default_factory=list)

    @property
    def fired_rule_ids(self) -> list[str]:
        return [rule.rule_id for rule in self.fired_rules]


@dataclass(frozen=True, slots=True)
class _ConditionResult:
    matched: bool
    reasons: tuple[str, ...] = ()


class RuleEngine:
    """Declarative, explainable and failure-isolated forensic rule evaluator."""

    def __init__(
        self,
        rules: Iterable[RuleDefinition] = (),
        validation_errors: Iterable[RuleValidationError] = (),
    ) -> None:
        self.rules = tuple(rules)
        self.validation_errors = tuple(validation_errors)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RuleEngine":
        source = Path(path)
        try:
            with source.open("r", encoding="utf-8") as stream:
                document = yaml.safe_load(stream)
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            error = RuleValidationError(str(source), f"unable to safely load YAML: {exc}")
            return cls(validation_errors=(error,))
        return cls.from_data(document, location=str(source))

    load = from_yaml

    @classmethod
    def from_data(cls, document: Any, *, location: str = "rules") -> "RuleEngine":
        errors: list[RuleValidationError] = []
        if document is None:
            return cls(validation_errors=(RuleValidationError(location, "document is empty"),))
        if isinstance(document, Mapping):
            raw_rules = document.get("rules")
        elif isinstance(document, list):
            raw_rules = document
        else:
            raw_rules = None
        if not isinstance(raw_rules, list):
            return cls(
                validation_errors=(RuleValidationError(location, "top-level 'rules' must be a list"),)
            )

        rules: list[RuleDefinition] = []
        seen: set[str] = set()
        for index, raw_rule in enumerate(raw_rules):
            entry_location = f"{location}.rules[{index}]"
            try:
                parsed, rule_errors = _parse_rule(raw_rule, entry_location)
            except Exception as exc:
                # Includes cyclic YAML aliases and excessive condition nesting.
                errors.append(
                    RuleValidationError(
                        entry_location,
                        f"rule validation failed safely: {type(exc).__name__}: {exc}",
                    )
                )
                continue
            errors.extend(rule_errors)
            if parsed is None:
                continue
            if parsed.id in seen:
                errors.append(RuleValidationError(entry_location, "duplicate rule id", parsed.id))
                continue
            seen.add(parsed.id)
            rules.append(parsed)
        return cls(rules, errors)

    def evaluate(
        self,
        artifact: Artifact,
        observations: Iterable[Observation] = (),
        profiles: Iterable[str] | None = None,
        findings: Iterable[Finding] = (),
        tool_runs: Iterable[ToolRun] = (),
        **kwargs: Any,
    ) -> RuleEvaluationResult:
        if profiles is None and "active_profiles" in kwargs:
            profiles = kwargs.pop("active_profiles")
        if kwargs:
            names = ", ".join(sorted(kwargs))
            raise TypeError(f"unexpected keyword argument(s): {names}")
        observation_index: dict[str, list[Any]] = {}
        for observation in observations:
            if observation.artifact_id == artifact.id:
                observation_index.setdefault(observation.key, []).append(observation.value)
        active_profiles = _infer_profiles(artifact, observation_index) if profiles is None else {
            str(profile).lower() for profile in profiles
        }
        active_profiles.add("generic")
        prior_findings = tuple(item for item in findings if item.artifact_id == artifact.id)
        prior_tool_runs = tuple(item for item in tool_runs if item.artifact_id == artifact.id)

        result = RuleEvaluationResult(validation_errors=list(self.validation_errors))
        recommendations: list[ToolRecommendation] = []
        for rule in self.rules:
            if rule.profiles and rule.profiles.isdisjoint(active_profiles):
                continue
            try:
                condition = _evaluate_condition(
                    rule.when, artifact, observation_index, active_profiles,
                    prior_findings, prior_tool_runs,
                )
            except Exception as exc:  # Validation should prevent this; isolate corrupted in-memory rules.
                result.validation_errors.append(
                    RuleValidationError("evaluation", f"{type(exc).__name__}: {exc}", rule.id)
                )
                continue
            if not condition.matched:
                continue

            fired = FiredRule(rule.id, condition.reasons)
            result.fired_rules.append(fired)
            explanation = f"Rule {rule.id} fired because: " + "; ".join(condition.reasons)
            for spec in rule.observations:
                result.observations.append(Observation(
                    artifact_id=artifact.id,
                    key=spec.key,
                    value=spec.value,
                    source=f"rule:{rule.id}",
                    confidence=spec.confidence,
                ))
            for target, delta, change_reason in rule.confidence_changes:
                change = RuleConfidenceChange(
                    target=target, delta=delta, reason=change_reason, rule_id=rule.id,
                )
                result.confidence_changes.append(change)
                result.observations.append(Observation(
                    artifact_id=artifact.id,
                    key="rule.confidence_change",
                    value={
                        "target": target,
                        "delta": delta,
                        "reason": change_reason,
                        "rule_id": rule.id,
                    },
                    source=f"rule:{rule.id}",
                    confidence=1.0,
                ))
            result.actions.extend(rule.actions)
            for action in rule.actions:
                result.observations.append(Observation(
                    artifact_id=artifact.id,
                    key=f"rule.{action.kind}_action",
                    value={
                        "target": action.target,
                        "tool": action.tool,
                        "modes": sorted(mode.value for mode in action.modes),
                        "command_mode": action.command_mode,
                        "parameters": dict(action.parameters),
                    },
                    source=f"rule:{rule.id}",
                    confidence=1.0,
                ))
            for finding_spec in rule.findings:
                evidence = list(
                    dict.fromkeys([*condition.reasons, *finding_spec.supporting_evidence])
                )
                result.findings.append(
                    Finding(
                        artifact_id=artifact.id,
                        title=finding_spec.title,
                        category=finding_spec.category,
                        severity=finding_spec.severity,
                        confidence=finding_spec.confidence,
                        explanation=finding_spec.explanation or explanation,
                        source=f"rule:{rule.id}",
                        supporting_evidence=evidence,
                    )
                )

            reason = f"rule {rule.id}: " + "; ".join(condition.reasons)
            auto_tools = set(rule.recommend_auto)
            for tool in rule.recommend_auto:
                recommendations.append(
                    ToolRecommendation(
                        tool,
                        frozenset({AnalysisMode.AUTO, AnalysisMode.DEEP}),
                        reason,
                        110,
                    )
                )
            for tool in rule.recommend_deep:
                # A tool present in auto and deep already has both modes from auto semantics.
                if tool in auto_tools:
                    continue
                recommendations.append(
                    ToolRecommendation(tool, frozenset({AnalysisMode.DEEP}), reason, 65)
                )
            for action in rule.actions:
                if action.tool is None:
                    continue
                recommendations.append(ToolRecommendation(
                    action.tool,
                    action.modes,
                    f"rule {rule.id} emitted {action.kind} action {action.target!r}: "
                    + "; ".join(condition.reasons),
                    action.priority,
                    command_mode=action.command_mode,
                    parameters=action.parameters,
                ))
        result.recommendations = merge_recommendations(recommendations)
        return result


def _parse_rule(
    raw_rule: Any,
    location: str,
) -> tuple[RuleDefinition | None, list[RuleValidationError]]:
    errors: list[RuleValidationError] = []
    if not isinstance(raw_rule, Mapping):
        return None, [RuleValidationError(location, "rule must be a mapping")]
    raw_id = raw_rule.get("id")
    rule_id = raw_id.strip() if isinstance(raw_id, str) else ""
    if not rule_id:
        errors.append(RuleValidationError(f"{location}.id", "id must be a non-empty string"))
        rule_id_for_error: str | None = None
    else:
        rule_id_for_error = rule_id

    profiles = _string_sequence(raw_rule.get("profiles", ()))
    if profiles is None:
        errors.append(
            RuleValidationError(f"{location}.profiles", "profiles must be a string list", rule_id_for_error)
        )
        profiles = ()

    when = raw_rule.get("when")
    errors.extend(_validate_condition(when, f"{location}.when", rule_id_for_error))

    emit = raw_rule.get("emit")
    findings: list[RuleFindingSpec] = []
    auto_tools: tuple[str, ...] = ()
    deep_tools: tuple[str, ...] = ()
    emitted_observations: list[RuleObservationSpec] = []
    confidence_changes: list[tuple[str, float, str]] = []
    actions: list[RuleActionSpec] = []
    if not isinstance(emit, Mapping):
        errors.append(RuleValidationError(f"{location}.emit", "emit must be a mapping", rule_id_for_error))
    else:
        raw_findings = emit.get("findings", [])
        if not isinstance(raw_findings, list):
            errors.append(
                RuleValidationError(
                    f"{location}.emit.findings", "findings must be a list", rule_id_for_error
                )
            )
        else:
            for index, raw_finding in enumerate(raw_findings):
                finding, finding_errors = _parse_finding(
                    raw_finding, f"{location}.emit.findings[{index}]", rule_id_for_error
                )
                errors.extend(finding_errors)
                if finding is not None:
                    findings.append(finding)
        raw_recommend = emit.get("recommend", {})
        if not isinstance(raw_recommend, Mapping):
            errors.append(
                RuleValidationError(
                    f"{location}.emit.recommend", "recommend must be a mapping", rule_id_for_error
                )
            )
        else:
            unknown_modes = set(raw_recommend) - {"auto", "deep"}
            if unknown_modes:
                errors.append(
                    RuleValidationError(
                        f"{location}.emit.recommend",
                        f"unsupported modes: {sorted(str(mode) for mode in unknown_modes)}",
                        rule_id_for_error,
                    )
                )
            parsed_auto = _string_sequence(raw_recommend.get("auto", ()))
            parsed_deep = _string_sequence(raw_recommend.get("deep", ()))
            if parsed_auto is None:
                errors.append(
                    RuleValidationError(
                        f"{location}.emit.recommend.auto", "auto must be a string list", rule_id_for_error
                    )
                )
            else:
                auto_tools = parsed_auto
            if parsed_deep is None:
                errors.append(
                    RuleValidationError(
                        f"{location}.emit.recommend.deep", "deep must be a string list", rule_id_for_error
                    )
                )
            else:
                deep_tools = parsed_deep

        raw_observations = emit.get("observations", [])
        if not isinstance(raw_observations, list):
            errors.append(RuleValidationError(
                f"{location}.emit.observations", "observations must be a list", rule_id_for_error
            ))
        else:
            for index, raw_observation in enumerate(raw_observations):
                spec, spec_errors = _parse_observation_spec(
                    raw_observation, f"{location}.emit.observations[{index}]", rule_id_for_error
                )
                errors.extend(spec_errors)
                if spec is not None:
                    emitted_observations.append(spec)

        raw_changes = emit.get("confidence_changes", [])
        if not isinstance(raw_changes, list):
            errors.append(RuleValidationError(
                f"{location}.emit.confidence_changes", "confidence_changes must be a list",
                rule_id_for_error,
            ))
        else:
            for index, raw_change in enumerate(raw_changes):
                change, change_errors = _parse_confidence_change(
                    raw_change, f"{location}.emit.confidence_changes[{index}]", rule_id_for_error
                )
                errors.extend(change_errors)
                if change is not None:
                    confidence_changes.append(change)

        for key, kind in (("parser_actions", "parser"), ("extractor_actions", "extractor")):
            raw_actions = emit.get(key, [])
            if not isinstance(raw_actions, list):
                errors.append(RuleValidationError(
                    f"{location}.emit.{key}", f"{key} must be a list", rule_id_for_error
                ))
                continue
            for index, raw_action in enumerate(raw_actions):
                action, action_errors = _parse_action(
                    raw_action, f"{location}.emit.{key}[{index}]", rule_id_for_error, kind
                )
                errors.extend(action_errors)
                if action is not None:
                    actions.append(action)

    if errors:
        return None, errors
    return (
        RuleDefinition(
            id=rule_id,
            profiles=frozenset(profile.lower() for profile in profiles),
            when=when,
            findings=tuple(findings),
            recommend_auto=auto_tools,
            recommend_deep=deep_tools,
            observations=tuple(emitted_observations),
            confidence_changes=tuple(confidence_changes),
            actions=tuple(actions),
        ),
        [],
    )


def _parse_finding(
    raw_finding: Any,
    location: str,
    rule_id: str | None,
) -> tuple[RuleFindingSpec | None, list[RuleValidationError]]:
    if not isinstance(raw_finding, Mapping):
        return None, [RuleValidationError(location, "finding must be a mapping", rule_id)]
    errors: list[RuleValidationError] = []
    title = raw_finding.get("title")
    category = raw_finding.get("category", "rule_match")
    severity = raw_finding.get("severity", "medium")
    confidence = raw_finding.get("confidence", 0.5)
    explanation = raw_finding.get("explanation")
    evidence = _string_sequence(raw_finding.get("supporting_evidence", ()))
    if not isinstance(title, str) or not title.strip():
        errors.append(RuleValidationError(f"{location}.title", "title must be a non-empty string", rule_id))
    if not isinstance(category, str) or not category.strip():
        errors.append(
            RuleValidationError(f"{location}.category", "category must be a non-empty string", rule_id)
        )
    if not isinstance(severity, str) or not severity.strip():
        errors.append(
            RuleValidationError(f"{location}.severity", "severity must be a non-empty string", rule_id)
        )
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        errors.append(
            RuleValidationError(f"{location}.confidence", "confidence must be between 0 and 1", rule_id)
        )
    if explanation is not None and not isinstance(explanation, str):
        errors.append(
            RuleValidationError(f"{location}.explanation", "explanation must be a string", rule_id)
        )
    if evidence is None:
        errors.append(
            RuleValidationError(
                f"{location}.supporting_evidence", "supporting_evidence must be a string list", rule_id
            )
        )
    if errors:
        return None, errors
    return (
        RuleFindingSpec(
            title=title.strip(),
            category=category.strip(),
            severity=severity.strip(),
            confidence=float(confidence),
            explanation=explanation.strip() if explanation else None,
            supporting_evidence=tuple(evidence or ()),
        ),
        [],
    )


def _parse_observation_spec(
    raw: Any, location: str, rule_id: str | None,
) -> tuple[RuleObservationSpec | None, list[RuleValidationError]]:
    if not isinstance(raw, Mapping):
        return None, [RuleValidationError(location, "observation must be a mapping", rule_id)]
    errors: list[RuleValidationError] = []
    key = raw.get("key", raw.get("type"))
    confidence = raw.get("confidence", 1.0)
    if not isinstance(key, str) or not key.strip():
        errors.append(RuleValidationError(f"{location}.key", "key must be a non-empty string", rule_id))
    if "value" not in raw:
        errors.append(RuleValidationError(f"{location}.value", "value is required", rule_id))
    if (
        isinstance(confidence, bool) or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        errors.append(RuleValidationError(
            f"{location}.confidence", "confidence must be between 0 and 1", rule_id
        ))
    if errors:
        return None, errors
    return RuleObservationSpec(key.strip(), raw["value"], float(confidence)), []


def _parse_confidence_change(
    raw: Any, location: str, rule_id: str | None,
) -> tuple[tuple[str, float, str] | None, list[RuleValidationError]]:
    if not isinstance(raw, Mapping):
        return None, [RuleValidationError(location, "confidence change must be a mapping", rule_id)]
    errors: list[RuleValidationError] = []
    target = raw.get("target")
    delta = raw.get("delta")
    reason = raw.get("reason")
    if not isinstance(target, str) or not target.strip():
        errors.append(RuleValidationError(f"{location}.target", "target must be a non-empty string", rule_id))
    if isinstance(delta, bool) or not isinstance(delta, (int, float)) or not -1 <= delta <= 1:
        errors.append(RuleValidationError(f"{location}.delta", "delta must be between -1 and 1", rule_id))
    if not isinstance(reason, str) or not reason.strip():
        errors.append(RuleValidationError(f"{location}.reason", "reason must be a non-empty string", rule_id))
    if errors:
        return None, errors
    return (target.strip(), float(delta), reason.strip()), []


def _parse_action(
    raw: Any, location: str, rule_id: str | None, kind: str,
) -> tuple[RuleActionSpec | None, list[RuleValidationError]]:
    if isinstance(raw, str):
        raw = {kind: raw}
    if not isinstance(raw, Mapping):
        return None, [RuleValidationError(location, f"{kind} action must be a mapping", rule_id)]
    errors: list[RuleValidationError] = []
    target = raw.get(kind, raw.get("target"))
    tool = raw.get("tool")
    modes = _string_sequence(raw.get("modes", ("deep",) if kind == "extractor" else ("auto", "deep")))
    command_mode = raw.get("command_mode", "extract" if kind == "extractor" else "default")
    parameters = raw.get("parameters", {})
    priority = raw.get("priority", 75 if kind == "extractor" else 80)
    if not isinstance(target, str) or not target.strip():
        errors.append(RuleValidationError(f"{location}.{kind}", "target must be a non-empty string", rule_id))
    if tool is not None and (not isinstance(tool, str) or not tool.strip()):
        errors.append(RuleValidationError(f"{location}.tool", "tool must be a non-empty string", rule_id))
    normalized_modes: set[AnalysisMode] = set()
    if modes is None or not modes:
        errors.append(RuleValidationError(f"{location}.modes", "modes must be a string list", rule_id))
    else:
        for mode in modes:
            try:
                normalized = AnalysisMode(mode.lower())
            except ValueError:
                errors.append(RuleValidationError(
                    f"{location}.modes", f"unsupported action mode: {mode}", rule_id
                ))
                continue
            if normalized not in {AnalysisMode.AUTO, AnalysisMode.DEEP}:
                errors.append(RuleValidationError(
                    f"{location}.modes", "actions only support auto/deep modes", rule_id
                ))
            else:
                normalized_modes.add(normalized)
    if (
        not isinstance(command_mode, str) or not command_mode.strip()
        or not command_mode.replace("_", "").replace("-", "").isalnum()
    ):
        errors.append(RuleValidationError(
            f"{location}.command_mode", "command_mode must be a simple identifier", rule_id
        ))
    if not isinstance(parameters, Mapping) or any(
        not isinstance(key, str) or not key.replace("_", "").isalnum()
        or not isinstance(value, (str, int, float)) or isinstance(value, bool)
        or "\x00" in str(value)
        for key, value in (parameters.items() if isinstance(parameters, Mapping) else ())
    ):
        errors.append(RuleValidationError(
            f"{location}.parameters", "parameters must map identifier keys to scalar values", rule_id
        ))
    if isinstance(priority, bool) or not isinstance(priority, int):
        errors.append(RuleValidationError(f"{location}.priority", "priority must be an integer", rule_id))
    if errors:
        return None, errors
    return RuleActionSpec(
        kind=kind,
        target=target.strip(),
        tool=tool.strip().lower() if isinstance(tool, str) else None,
        modes=frozenset(normalized_modes),
        command_mode=command_mode.strip().lower(),
        parameters={str(key): str(value) for key, value in parameters.items()},
        priority=priority,
    ), []


def _validate_condition(
    condition: Any,
    location: str,
    rule_id: str | None,
) -> list[RuleValidationError]:
    if not isinstance(condition, Mapping):
        return [RuleValidationError(location, "condition must be a mapping", rule_id)]
    logical_keys = set(condition) & _LOGICAL
    if logical_keys:
        if len(logical_keys) != 1 or len(condition) != 1:
            return [
                RuleValidationError(location, "logical condition must contain only one of all/any", rule_id)
            ]
        key = next(iter(logical_keys))
        children = condition[key]
        if not isinstance(children, list) or not children:
            return [RuleValidationError(f"{location}.{key}", f"{key} must be a non-empty list", rule_id)]
        errors: list[RuleValidationError] = []
        for index, child in enumerate(children):
            errors.extend(_validate_condition(child, f"{location}.{key}[{index}]", rule_id))
        return errors

    selectors = set(condition) & {
        "observation", "artifact_type", "profile", "mime", "magic", "finding", "tool_result"
    }
    if len(selectors) != 1:
        return [
            RuleValidationError(
                location,
                "leaf condition needs exactly one selector: "
                "observation/artifact_type/profile/mime/magic/finding/tool_result",
                rule_id,
            )
        ]
    selector = next(iter(selectors))
    if selector in {"finding", "tool_result"}:
        return _validate_prior_condition(condition, selector, location, rule_id)
    if selector == "observation":
        if not isinstance(condition[selector], str) or not condition[selector].strip():
            return [RuleValidationError(f"{location}.observation", "must be a non-empty string", rule_id)]
        operators = set(condition) & _OPERATORS
        unknown = set(condition) - {selector} - _OPERATORS
        if unknown:
            return [
                RuleValidationError(location, f"unsupported condition keys: {sorted(unknown)}", rule_id)
            ]
        if len(operators) != 1:
            return [RuleValidationError(location, "observation condition needs exactly one operator", rule_id)]
        operator = next(iter(operators))
        if operator == "exists" and not isinstance(condition[operator], bool):
            return [RuleValidationError(f"{location}.exists", "exists must be boolean", rule_id)]
        if operator in {"greater_than", "less_than"} and (
            isinstance(condition[operator], bool) or not isinstance(condition[operator], (int, float))
        ):
            return [
                RuleValidationError(f"{location}.{operator}", f"{operator} must be numeric", rule_id)
            ]
        return []

    if len(condition) != 1:
        return [RuleValidationError(location, f"{selector} condition does not take an operator", rule_id)]
    values = _string_sequence(condition[selector])
    if values is None or not values:
        return [
            RuleValidationError(f"{location}.{selector}", "must be a string or non-empty string list", rule_id)
        ]
    return []


def _evaluate_condition(
    condition: Mapping[str, Any],
    artifact: Artifact,
    observations: Mapping[str, Sequence[Any]],
    profiles: set[str],
    findings: Sequence[Finding],
    tool_runs: Sequence[ToolRun],
) -> _ConditionResult:
    if "all" in condition:
        children = [
            _evaluate_condition(child, artifact, observations, profiles, findings, tool_runs)
            for child in condition["all"]
        ]
        if not all(child.matched for child in children):
            return _ConditionResult(False)
        return _ConditionResult(True, tuple(reason for child in children for reason in child.reasons))
    if "any" in condition:
        children = [
            _evaluate_condition(child, artifact, observations, profiles, findings, tool_runs)
            for child in condition["any"]
        ]
        matched = [child for child in children if child.matched]
        if not matched:
            return _ConditionResult(False)
        return _ConditionResult(True, tuple(reason for child in matched for reason in child.reasons))

    if "observation" in condition:
        key = condition["observation"]
        values = list(observations.get(key, ()))
        for alias in _OBSERVATION_ALIASES.get(key, ()):
            values.extend(observations.get(alias, ()))
        operator = next(operator for operator in _OPERATORS if operator in condition)
        expected = condition[operator]
        matched = _match_values(values, operator, expected)
        if not matched:
            return _ConditionResult(False)
        rendered = _render_values(values) if values else "<absent>"
        return _ConditionResult(True, (f"observation {key} {operator} {expected!r} (actual {rendered})",))

    if "finding" in condition:
        matches = [item for item in findings if _finding_matches(item, condition["finding"])]
        expected_exists = condition["exists"]
        if bool(matches) is not expected_exists:
            return _ConditionResult(False)
        if not matches:
            return _ConditionResult(True, (f"prior finding {condition['finding']!r} is absent",))
        return _ConditionResult(True, (
            f"prior finding matched {matches[0].category!r} ({matches[0].id})",
        ))

    if "tool_result" in condition:
        matches = [item for item in tool_runs if _tool_result_matches(item, condition["tool_result"])]
        expected_exists = condition["exists"]
        if bool(matches) is not expected_exists:
            return _ConditionResult(False)
        if not matches:
            return _ConditionResult(True, (f"prior tool result {condition['tool_result']!r} is absent",))
        matched = matches[-1]
        return _ConditionResult(True, (
            f"prior tool result matched {matched.tool!r} status={matched.status.value} "
            f"exit_code={matched.exit_code!r} ({matched.id})",
        ))

    if "artifact_type" in condition:
        expected = set(_string_sequence(condition["artifact_type"]) or ())
        actual = {artifact.artifact_type, *(item.artifact_type for item in artifact.classifications)}
        matched_values = {value.lower() for value in actual} & {value.lower() for value in expected}
        return (
            _ConditionResult(True, (f"artifact type matched {sorted(matched_values)}",))
            if matched_values else _ConditionResult(False)
        )
    if "profile" in condition:
        expected = {value.lower() for value in (_string_sequence(condition["profile"]) or ())}
        matched_values = profiles & expected
        return (
            _ConditionResult(True, (f"active profile matched {sorted(matched_values)}",))
            if matched_values else _ConditionResult(False)
        )
    if "mime" in condition:
        expected = {value.lower() for value in (_string_sequence(condition["mime"]) or ())}
        actual = (artifact.mime or "").lower()
        return (
            _ConditionResult(True, (f"artifact MIME is {artifact.mime}",))
            if actual in expected else _ConditionResult(False)
        )
    expected = {value.lower() for value in (_string_sequence(condition["magic"]) or ())}
    actual_magic = (artifact.magic or "").lower()
    matched_magic = next((value for value in expected if value in actual_magic), None)
    return (
        _ConditionResult(True, (f"artifact magic contains {matched_magic!r}",))
        if matched_magic else _ConditionResult(False)
    )


def _validate_prior_condition(
    condition: Mapping[str, Any], selector: str, location: str, rule_id: str | None,
) -> list[RuleValidationError]:
    unknown = set(condition) - {selector, "exists"}
    if unknown:
        return [RuleValidationError(location, f"unsupported condition keys: {sorted(unknown)}", rule_id)]
    if not isinstance(condition.get("exists"), bool):
        return [RuleValidationError(
            f"{location}.exists", "prior-state condition requires a boolean exists operator", rule_id
        )]
    value = condition[selector]
    if isinstance(value, str):
        if value.strip():
            return []
        return [RuleValidationError(f"{location}.{selector}", "must not be empty", rule_id)]
    if not isinstance(value, Mapping) or not value:
        return [RuleValidationError(
            f"{location}.{selector}", "must be a non-empty string or mapping", rule_id
        )]
    allowed = (
        {"id", "title", "category", "severity", "source", "minimum_confidence"}
        if selector == "finding"
        else {"id", "tool", "status", "exit_code", "generated_files", "error"}
    )
    unknown_fields = set(value) - allowed
    if unknown_fields:
        return [RuleValidationError(
            f"{location}.{selector}", f"unsupported match fields: {sorted(unknown_fields)}", rule_id
        )]
    errors: list[RuleValidationError] = []
    for key, expected in value.items():
        if key == "minimum_confidence":
            if isinstance(expected, bool) or not isinstance(expected, (int, float)) or not 0 <= expected <= 1:
                errors.append(RuleValidationError(
                    f"{location}.{selector}.{key}", "must be between 0 and 1", rule_id
                ))
        elif key == "exit_code":
            if expected is not None and (isinstance(expected, bool) or not isinstance(expected, int)):
                errors.append(RuleValidationError(
                    f"{location}.{selector}.{key}", "must be an integer or null", rule_id
                ))
        elif key == "status":
            allowed_statuses = {status.value for status in ToolRunStatus}
            if not isinstance(expected, str) or expected.casefold() not in allowed_statuses:
                errors.append(RuleValidationError(
                    f"{location}.{selector}.{key}",
                    f"must be one of {sorted(allowed_statuses)}", rule_id,
                ))
        elif key == "generated_files":
            if not isinstance(expected, bool):
                errors.append(RuleValidationError(
                    f"{location}.{selector}.{key}", "must be boolean", rule_id
                ))
        elif key == "error":
            if not isinstance(expected, bool):
                errors.append(RuleValidationError(
                    f"{location}.{selector}.{key}", "must be boolean", rule_id
                ))
        elif not isinstance(expected, str) or not expected.strip():
            errors.append(RuleValidationError(
                f"{location}.{selector}.{key}", "must be a non-empty string", rule_id
            ))
    return errors


def _finding_matches(finding: Finding, expected: Any) -> bool:
    if isinstance(expected, str):
        wanted = expected.strip().casefold()
        return wanted in {
            finding.id.casefold(), finding.title.casefold(), finding.category.casefold(),
            finding.source.casefold(),
        }
    if not isinstance(expected, Mapping):
        return False
    for key, value in expected.items():
        if key == "minimum_confidence":
            if finding.confidence < float(value):
                return False
        elif str(getattr(finding, key, "")).casefold() != str(value).casefold():
            return False
    return True


def _tool_result_matches(run: ToolRun, expected: Any) -> bool:
    if isinstance(expected, str):
        return run.tool.casefold() == expected.strip().casefold()
    if not isinstance(expected, Mapping):
        return False
    for key, value in expected.items():
        if key == "status":
            if run.status.value.casefold() != str(value).casefold():
                return False
        elif key == "generated_files":
            if bool(run.generated_files) is not value:
                return False
        elif key == "error":
            if bool(run.error) is not value:
                return False
        elif key == "exit_code":
            if run.exit_code != value:
                return False
        elif str(getattr(run, key, "")).casefold() != str(value).casefold():
            return False
    return True


def _match_values(values: Sequence[Any], operator: str, expected: Any) -> bool:
    if operator == "exists":
        return bool(values) is expected
    if not values:
        return False
    if operator == "equals":
        return any(_equal(value, expected) for value in values)
    if operator == "not_equals":
        return all(not _equal(value, expected) for value in values)
    if operator == "greater_than":
        return any(_numeric_compare(value, expected, greater=True) for value in values)
    if operator == "less_than":
        return any(_numeric_compare(value, expected, greater=False) for value in values)
    return any(_contains(value, expected) for value in values)


def _equal(actual: Any, expected: Any) -> bool:
    if isinstance(expected, bool) and isinstance(actual, str):
        lowered = actual.strip().lower()
        if lowered in {"true", "yes", "1"}:
            actual = True
        elif lowered in {"false", "no", "0"}:
            actual = False
    return actual == expected


def _numeric_compare(actual: Any, expected: int | float, *, greater: bool) -> bool:
    if isinstance(actual, bool):
        return False
    try:
        actual_number = float(actual)
        expected_number = float(expected)
    except (TypeError, ValueError):
        return False
    return actual_number > expected_number if greater else actual_number < expected_number


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return expected in actual
    if isinstance(actual, bytes) and isinstance(expected, (bytes, bytearray)):
        return bytes(expected) in actual
    if isinstance(actual, Mapping):
        if isinstance(expected, Mapping):
            return all(key in actual and _equal(actual[key], value) for key, value in expected.items())
        return expected in actual
    if isinstance(actual, Sequence) and not isinstance(actual, (str, bytes, bytearray)):
        return any(_equal(value, expected) for value in actual)
    return False


def _render_values(values: Sequence[Any]) -> str:
    rendered = repr(values[0]) if len(values) == 1 else repr(list(values))
    return rendered if len(rendered) <= 240 else rendered[:237] + "..."


def _string_sequence(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, (list, tuple, set, frozenset)):
        return None
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return None
        normalized = item.strip()
        if normalized not in result:
            result.append(normalized)
    return tuple(result)


def _infer_profiles(
    artifact: Artifact,
    observations: Mapping[str, Sequence[Any]],
) -> set[str]:
    profiles = {"generic", artifact.artifact_type.lower()}
    profiles.update(item.artifact_type.lower() for item in artifact.classifications)
    for key in ("artifact.type", "artifact.profile", "artifact.profiles"):
        for value in observations.get(key, ()):
            if isinstance(value, str):
                profiles.add(value.lower())
            elif isinstance(value, (list, tuple, set, frozenset)):
                profiles.update(str(item).lower() for item in value if item)
    formats = {
        str(value).lower()
        for key in ("artifact.format", "triage.detected_header_format", "file.format", "format")
        for value in observations.get(key, ())
    }
    image_formats = {"png", "jpeg", "jpg", "gif", "bmp", "tiff", "webp"}
    archive_formats = {"zip", "7z", "rar", "tar", "gzip", "gz", "bzip2", "xz", "cab"}
    if formats & image_formats or "image" in profiles:
        profiles.update({"image", "steganography"})
    if formats & archive_formats or profiles & archive_formats:
        profiles.add("archive")
    if formats & {"pcap", "pcapng"} or profiles & {"pcap", "pcapng", "network_capture"}:
        profiles.add("pcap")
    if profiles & {"memory", "memory_dump", "ram_dump", "hiberfil", "crash_dump"}:
        profiles.add("memory")
    if profiles & {"disk", "disk_image", "filesystem", "filesystem_image", "ewf"}:
        profiles.add("disk")
    return profiles


__all__ = [
    "FiredRule",
    "RuleActionSpec",
    "RuleConfidenceChange",
    "RuleDefinition",
    "RuleEngine",
    "RuleEvaluationResult",
    "RuleFindingSpec",
    "RuleObservationSpec",
    "RuleValidationError",
]
