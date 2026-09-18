"""A small declarative rule DSL evaluated against every scored event.

Rules are stored as JSON so analysts can author them from the console without a
deploy. A rule's ``conditions`` object is a tree of nodes:

```jsonc
{
  "all": [                                   // also: "any", "not"
    {"field": "action", "op": "in", "value": ["sudo", "assume_role"]},
    {"field": "sensitivity_level", "op": "gte", "value": 4},
    {"field": "vectors.temporal", "op": "gt", "value": 70}
  ]
}
```

Supported operators: ``eq ne gt gte lt lte in not_in contains not_contains
startswith endswith matches between is_true is_false``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from app.engine.types import EventView, RuleView

MAX_DEPTH = 8


class RuleSyntaxError(ValueError):
    """Raised when a rule's condition tree is malformed."""


def _as_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _cmp(op: str, left: Any, right: Any) -> bool:
    ln, rn = _as_number(left), _as_number(right)
    if ln is None or rn is None:
        return False
    return {
        "gt": ln > rn,
        "gte": ln >= rn,
        "lt": ln < rn,
        "lte": ln <= rn,
    }[op]


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda left, right: str(left).lower() == str(right).lower(),
    "ne": lambda left, right: str(left).lower() != str(right).lower(),
    "gt": lambda left, right: _cmp("gt", left, right),
    "gte": lambda left, right: _cmp("gte", left, right),
    "lt": lambda left, right: _cmp("lt", left, right),
    "lte": lambda left, right: _cmp("lte", left, right),
    "in": lambda left, right: str(left).lower() in {str(v).lower() for v in _iterable(right)},
    "not_in": lambda left, right: str(left).lower() not in {str(v).lower() for v in _iterable(right)},
    "contains": lambda left, right: str(right).lower() in str(left).lower(),
    "not_contains": lambda left, right: str(right).lower() not in str(left).lower(),
    "startswith": lambda left, right: str(left).lower().startswith(str(right).lower()),
    "endswith": lambda left, right: str(left).lower().endswith(str(right).lower()),
    "matches": lambda left, right: bool(re.search(str(right), str(left), re.IGNORECASE)),
    "is_true": lambda left, _right: bool(left),
    "is_false": lambda left, _right: not bool(left),
    "between": lambda left, right: _between(left, right),
}


def _iterable(value: Any) -> list[Any]:
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _between(left: Any, right: Any) -> bool:
    bounds = _iterable(right)
    if len(bounds) != 2:
        return False
    ln, lo, hi = _as_number(left), _as_number(bounds[0]), _as_number(bounds[1])
    if None in (ln, lo, hi):
        return False
    return lo <= ln <= hi  # type: ignore[operator]


def build_fact_map(
    event: EventView,
    vector_scores: dict[str, float],
    raw_score: float,
    *,
    cumulative_risk: float = 0.0,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Flatten an event plus its scores into the namespace rules query."""
    facts: dict[str, Any] = {
        "event_type": event.event_type.value,
        "resource": event.resource,
        "action": event.action_key,
        "outcome": event.outcome,
        "sensitivity_level": event.sensitivity_level,
        "ip_address": event.ip_address,
        "country": event.country,
        "asn": event.asn or "",
        "device_id": event.device_id or "",
        "user_agent": event.user_agent or "",
        "bytes_transferred": event.bytes_transferred,
        "record_count": event.record_count,
        "is_off_hours": event.is_off_hours,
        "hour": event.occurred_at.hour,
        "weekday": event.occurred_at.weekday(),
        "is_weekend": event.occurred_at.weekday() >= 5,
        "context_tags": event.context_tags,
        "has_context_tag": bool(event.context_tags),
        "raw_score": raw_score,
        "cumulative_risk": cumulative_risk,
    }
    for name, value in vector_scores.items():
        facts[f"vectors.{name}"] = value
    if extra:
        facts.update(extra)
    return facts


def evaluate_node(node: dict[str, Any], facts: dict[str, Any], depth: int = 0) -> bool:
    """Recursively evaluate one condition node against the fact map."""
    if depth > MAX_DEPTH:
        raise RuleSyntaxError(f"Condition nesting exceeds the maximum depth of {MAX_DEPTH}.")
    if not isinstance(node, dict) or not node:
        return False

    if "all" in node:
        children = node["all"]
        if not isinstance(children, list):
            raise RuleSyntaxError("'all' must be a list of conditions.")
        return all(evaluate_node(c, facts, depth + 1) for c in children)
    if "any" in node:
        children = node["any"]
        if not isinstance(children, list):
            raise RuleSyntaxError("'any' must be a list of conditions.")
        return any(evaluate_node(c, facts, depth + 1) for c in children)
    if "not" in node:
        return not evaluate_node(node["not"], facts, depth + 1)

    field = node.get("field")
    op = node.get("op", "eq")
    if not field:
        raise RuleSyntaxError("A leaf condition requires a 'field'.")
    if op not in OPERATORS:
        raise RuleSyntaxError(f"Unknown operator '{op}'. Valid: {', '.join(sorted(OPERATORS))}.")
    if field not in facts:
        return False
    return OPERATORS[op](facts[field], node.get("value"))


def validate_conditions(conditions: dict[str, Any]) -> None:
    """Raise ``RuleSyntaxError`` if the tree cannot be evaluated. Used on rule save."""
    probe = dict.fromkeys(
        (
            "event_type",
            "resource",
            "action",
            "outcome",
            "sensitivity_level",
            "ip_address",
            "country",
            "asn",
            "device_id",
            "user_agent",
            "bytes_transferred",
            "record_count",
            "is_off_hours",
            "hour",
            "weekday",
            "is_weekend",
            "context_tags",
            "has_context_tag",
            "raw_score",
            "cumulative_risk",
        ),
        0,
    )
    evaluate_node(conditions, probe)


class RuleEngine:
    """Evaluates a compiled rule set against scored events."""

    def __init__(self, rules: list[RuleView] | None = None) -> None:
        self.rules: list[RuleView] = [r for r in (rules or []) if r.enabled]

    def match(
        self,
        event: EventView,
        vector_scores: dict[str, float],
        raw_score: float,
        *,
        cumulative_risk: float = 0.0,
        has_context: bool = False,
    ) -> list[RuleView]:
        """Return every enabled rule whose conditions hold for this event."""
        if not self.rules:
            return []
        facts = build_fact_map(event, vector_scores, raw_score, cumulative_risk=cumulative_risk)
        hits: list[RuleView] = []
        for rule in self.rules:
            if has_context and rule.suppress_when_context:
                continue
            try:
                if evaluate_node(rule.conditions, facts):
                    hits.append(rule)
            except RuleSyntaxError:
                # A single malformed rule must never break the whole pipeline.
                continue
        return hits

    @staticmethod
    def total_boost(hits: list[RuleView]) -> float:
        """Combine rule boosts with diminishing returns so stacked rules cannot
        trivially saturate the score."""
        boost = 0.0
        for i, rule in enumerate(sorted(hits, key=lambda r: -r.risk_boost)):
            boost += rule.risk_boost * (0.6**i)
        return round(min(45.0, boost), 2)
