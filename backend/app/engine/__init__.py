"""Aegis Drift detection engine.

Pure, synchronous analytics with no database or framework dependencies. Layers:

* ``baseline``     — learns per-identity norms and scores single events on 8 vectors
* ``context``      — damps risk against approved business justifications
* ``rules``        — a declarative JSON rule DSL layered on top of the statistics
* ``sequence``     — correlates the event stream into a decaying risk trajectory
* ``peer``         — cohort statistics used as the control group
* ``mitre``        — maps observed behaviour onto ATT&CK techniques
* ``blast_radius`` — models reachable assets and regulatory exposure
* ``explain``      — renders the numeric verdict as an analyst-readable brief
* ``copilot``      — grounded Q&A over a pre-computed evidence bundle
"""

from app.engine.baseline import BaselineEngine
from app.engine.blast_radius import AssetView, BlastRadiusEngine
from app.engine.context import ContextEngine
from app.engine.copilot import CopilotEngine
from app.engine.explain import ExplainabilityEngine
from app.engine.mitre import coverage_matrix, map_techniques
from app.engine.peer import CohortMember, PeerEngine, cohort_key
from app.engine.rules import RuleEngine, RuleSyntaxError, validate_conditions
from app.engine.sequence import EngineConfig, SequenceEngine
from app.engine.types import (
    BaselineView,
    ContextView,
    CorrelationResult,
    EventView,
    IndicatorView,
    PeerStats,
    RuleView,
    ScoredEvent,
)

__all__ = [
    "AssetView",
    "BaselineEngine",
    "BaselineView",
    "BlastRadiusEngine",
    "CohortMember",
    "ContextEngine",
    "ContextView",
    "CopilotEngine",
    "CorrelationResult",
    "EngineConfig",
    "EventView",
    "ExplainabilityEngine",
    "IndicatorView",
    "PeerEngine",
    "PeerStats",
    "RuleEngine",
    "RuleSyntaxError",
    "RuleView",
    "ScoredEvent",
    "SequenceEngine",
    "cohort_key",
    "coverage_matrix",
    "map_techniques",
    "validate_conditions",
]
