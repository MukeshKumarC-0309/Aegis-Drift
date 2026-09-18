"""The declarative rule DSL."""

from __future__ import annotations

from datetime import datetime

import pytest

from app.core.enums import EventType
from app.engine.rules import (
    RuleEngine,
    RuleSyntaxError,
    build_fact_map,
    evaluate_node,
    validate_conditions,
)
from app.engine.types import EventView, RuleView

pytestmark = pytest.mark.unit

FACTS = {
    "action": "export_all",
    "resource": "crown_jewel_customer_pii_export",
    "sensitivity_level": 5,
    "record_count": 84_000,
    "is_off_hours": True,
    "is_weekend": False,
    "country": "RO",
    "vectors.geovelocity": 88.0,
    "vectors.privilege": 55.0,
    "context_tags": [],
}


class TestOperators:
    @pytest.mark.parametrize(
        ("node", "expected"),
        [
            ({"field": "action", "op": "eq", "value": "export_all"}, True),
            ({"field": "action", "op": "eq", "value": "EXPORT_ALL"}, True),  # case-insensitive
            ({"field": "action", "op": "ne", "value": "read"}, True),
            ({"field": "sensitivity_level", "op": "gte", "value": 5}, True),
            ({"field": "sensitivity_level", "op": "gt", "value": 5}, False),
            ({"field": "sensitivity_level", "op": "lt", "value": 3}, False),
            ({"field": "action", "op": "in", "value": ["read", "export_all"]}, True),
            ({"field": "action", "op": "not_in", "value": ["read"]}, True),
            ({"field": "resource", "op": "contains", "value": "crown_jewel"}, True),
            ({"field": "resource", "op": "startswith", "value": "crown"}, True),
            ({"field": "resource", "op": "endswith", "value": "export"}, True),
            ({"field": "resource", "op": "matches", "value": r"crown.*pii"}, True),
            ({"field": "is_off_hours", "op": "is_true"}, True),
            ({"field": "is_weekend", "op": "is_false"}, True),
            ({"field": "record_count", "op": "between", "value": [50_000, 100_000]}, True),
            ({"field": "record_count", "op": "between", "value": [1, 10]}, False),
        ],
    )
    def test_operator(self, node, expected):
        assert evaluate_node(node, FACTS) is expected

    def test_unknown_field_does_not_match(self):
        """A rule referencing a field the event lacks must fail closed, not crash."""
        assert evaluate_node({"field": "nonexistent", "op": "eq", "value": "x"}, FACTS) is False

    def test_non_numeric_comparison_is_false_not_an_error(self):
        assert evaluate_node({"field": "action", "op": "gt", "value": 5}, FACTS) is False


class TestCombinators:
    def test_all_requires_every_child(self):
        assert evaluate_node(
            {
                "all": [
                    {"field": "sensitivity_level", "op": "gte", "value": 4},
                    {"field": "is_off_hours", "op": "is_true"},
                ]
            },
            FACTS,
        )
        assert not evaluate_node(
            {
                "all": [
                    {"field": "sensitivity_level", "op": "gte", "value": 4},
                    {"field": "is_weekend", "op": "is_true"},
                ]
            },
            FACTS,
        )

    def test_any_requires_one_child(self):
        assert evaluate_node(
            {
                "any": [
                    {"field": "is_weekend", "op": "is_true"},
                    {"field": "vectors.geovelocity", "op": "gte", "value": 80},
                ]
            },
            FACTS,
        )

    def test_not_inverts(self):
        assert evaluate_node({"not": {"field": "is_weekend", "op": "is_true"}}, FACTS)

    def test_deep_nesting(self):
        assert evaluate_node(
            {
                "all": [
                    {
                        "any": [
                            {"field": "country", "op": "eq", "value": "RO"},
                            {"field": "country", "op": "eq", "value": "CN"},
                        ]
                    },
                    {"not": {"field": "sensitivity_level", "op": "lt", "value": 4}},
                ]
            },
            FACTS,
        )


class TestValidation:
    def test_unknown_operator_is_rejected(self):
        with pytest.raises(RuleSyntaxError, match="Unknown operator"):
            validate_conditions({"field": "action", "op": "nope", "value": 1})

    def test_missing_field_is_rejected(self):
        with pytest.raises(RuleSyntaxError, match="requires a 'field'"):
            validate_conditions({"op": "eq", "value": 1})

    def test_non_list_combinator_is_rejected(self):
        with pytest.raises(RuleSyntaxError, match="must be a list"):
            validate_conditions({"all": {"field": "action", "op": "eq", "value": "x"}})

    def test_excessive_nesting_is_rejected(self):
        node: dict = {"field": "action", "op": "eq", "value": "x"}
        for _ in range(12):
            node = {"all": [node]}
        with pytest.raises(RuleSyntaxError, match="nesting"):
            validate_conditions(node)


class TestRuleEngine:
    def _event(self) -> EventView:
        return EventView(
            id="e1",
            identity_id="idn_1",
            occurred_at=datetime(2026, 9, 17, 2, 30),
            event_type=EventType.NETWORK_EGRESS,
            resource="crown_jewel_customer_pii_export",
            action="export_all",
            sensitivity_level=5,
            is_off_hours=True,
            record_count=84_000,
        )

    def _rule(self, slug: str, boost: float, suppress: bool = True) -> RuleView:
        return RuleView(
            id=f"rul_{slug}",
            slug=slug,
            name=slug,
            severity="HIGH",
            conditions={"field": "sensitivity_level", "op": "gte", "value": 4},
            risk_boost=boost,
            suppress_when_context=suppress,
        )

    def test_matching_rule_is_returned(self):
        engine = RuleEngine([self._rule("crown-export", 30)])
        hits = engine.match(self._event(), {"privilege": 90.0}, 85.0)
        assert [h.slug for h in hits] == ["crown-export"]

    def test_context_suppresses_only_rules_that_allow_it(self):
        engine = RuleEngine(
            [
                self._rule("suppressible", 20, suppress=True),
                self._rule("never-suppressed", 30, suppress=False),
            ]
        )
        hits = engine.match(self._event(), {}, 85.0, has_context=True)
        assert [h.slug for h in hits] == ["never-suppressed"]

    def test_disabled_rules_are_excluded(self):
        rule = self._rule("off", 20)
        rule.enabled = False
        assert RuleEngine([rule]).match(self._event(), {}, 85.0) == []

    def test_malformed_rule_does_not_break_the_pipeline(self):
        """One bad rule must never stop the others from evaluating."""
        broken = self._rule("broken", 10)
        broken.conditions = {"field": "x", "op": "not_an_operator", "value": 1}
        good = self._rule("good", 10)

        hits = RuleEngine([broken, good]).match(self._event(), {}, 85.0)
        assert [h.slug for h in hits] == ["good"]

    def test_stacked_boosts_have_diminishing_returns(self):
        rules = [self._rule(f"r{i}", 30) for i in range(6)]
        hits = RuleEngine(rules).match(self._event(), {}, 85.0)

        assert len(hits) == 6
        boost = RuleEngine.total_boost(hits)
        assert boost <= 45.0  # hard cap
        assert boost < sum(r.risk_boost for r in rules)

    def test_fact_map_exposes_vectors_namespaced(self):
        facts = build_fact_map(self._event(), {"temporal": 82.0}, 70.0, cumulative_risk=40.0)
        assert facts["vectors.temporal"] == 82.0
        assert facts["cumulative_risk"] == 40.0
        assert facts["hour"] == 2
        assert facts["is_off_hours"] is True
