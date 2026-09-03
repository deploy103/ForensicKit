from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from .models import AnalysisMode, Artifact, Finding, Observation
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
class RuleDefinition:
    id: str
    profiles: frozenset[str]
    when: Mapping[str, Any]
    findings: tuple[RuleFindingSpec, ...]
    recommend_auto: tuple[str, ...]
    recommend_deep: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FiredRule:
    rule_id: str
    reasons: tuple[str, ...]


@dataclass(slots=True)
class RuleEvaluationResult:
    findings: list[Finding] = field(default_factory=list)
    recommendations: list[ToolRecommendation] = field(default_factory=list)
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

        result = RuleEvaluationResult(validation_errors=list(self.validation_errors))
        recommendations: list[ToolRecommendation] = []
        for rule in self.rules:
            if rule.profiles and rule.profiles.isdisjoint(active_profiles):
                continue
            try:
                condition = _evaluate_condition(
                    rule.when, artifact, observation_index, active_profiles
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

    selectors = set(condition) & {"observation", "artifact_type", "profile", "mime", "magic"}
    if len(selectors) != 1:
        return [
            RuleValidationError(
                location,
                "leaf condition needs exactly one selector: observation/artifact_type/profile/mime/magic",
                rule_id,
            )
        ]
    selector = next(iter(selectors))
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
) -> _ConditionResult:
    if "all" in condition:
        children = [_evaluate_condition(child, artifact, observations, profiles) for child in condition["all"]]
        if not all(child.matched for child in children):
            return _ConditionResult(False)
        return _ConditionResult(True, tuple(reason for child in children for reason in child.reasons))
    if "any" in condition:
        children = [_evaluate_condition(child, artifact, observations, profiles) for child in condition["any"]]
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
    "RuleDefinition",
    "RuleEngine",
    "RuleEvaluationResult",
    "RuleFindingSpec",
    "RuleValidationError",
]
