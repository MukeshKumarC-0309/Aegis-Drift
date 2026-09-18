"""Conversion between SQLAlchemy rows and the engine's pure value objects."""

from __future__ import annotations

from app.core.enums import EventType
from app.db.models import Asset, Baseline, ContextRecord, DetectionRule, Identity, ThreatIndicator
from app.db.models import SecurityEvent as EventRow
from app.engine.blast_radius import AssetView
from app.engine.types import BaselineView, ContextView, EventView, IndicatorView, RuleView


def to_event_view(row: EventRow) -> EventView:
    return EventView(
        id=row.id,
        identity_id=row.identity_id,
        occurred_at=row.occurred_at,
        event_type=EventType(row.event_type),
        resource=row.resource,
        action=row.action,
        sensitivity_level=row.sensitivity_level,
        outcome=row.outcome,
        ip_address=row.ip_address,
        country=row.country,
        latitude=row.latitude,
        longitude=row.longitude,
        asn=row.asn,
        device_id=row.device_id,
        user_agent=row.user_agent,
        bytes_transferred=row.bytes_transferred,
        record_count=row.record_count,
        is_off_hours=row.is_off_hours,
        context_tags=list(row.context_tags or []),
        metadata=dict(row.event_metadata or {}),
    )


def to_baseline_view(identity: Identity, row: Baseline | None) -> BaselineView:
    """Build the engine's baseline view, falling back to a neutral prior when the
    identity has not yet been profiled."""
    if row is None:
        return BaselineView(
            identity_id=identity.id,
            username=identity.username,
            department=identity.department,
            role_title=identity.role_title,
            peer_group_id=identity.peer_group_id,
            hourly_distribution=dict.fromkeys(range(24), 1 / 24),
            dow_distribution=dict.fromkeys(range(7), 1 / 7),
        )
    return BaselineView(
        identity_id=identity.id,
        username=identity.username,
        department=identity.department,
        role_title=identity.role_title,
        peer_group_id=identity.peer_group_id,
        # JSON object keys round-trip as strings; the engine indexes by int.
        hourly_distribution={int(k): float(v) for k, v in (row.hourly_distribution or {}).items()},
        dow_distribution={int(k): float(v) for k, v in (row.dow_distribution or {}).items()},
        common_resources=list(row.common_resources or []),
        resource_frequencies={k: int(v) for k, v in (row.resource_frequencies or {}).items()},
        known_ip_prefixes=list(row.known_ip_prefixes or []),
        known_countries=list(row.known_countries or []),
        known_devices=list(row.known_devices or []),
        action_frequencies={k: int(v) for k, v in (row.action_frequencies or {}).items()},
        resource_entropy=row.resource_entropy,
        avg_daily_events=row.avg_daily_events,
        stddev_daily_events=row.stddev_daily_events,
        avg_daily_bytes=row.avg_daily_bytes,
        stddev_daily_bytes=row.stddev_daily_bytes,
        typical_max_sensitivity=row.typical_max_sensitivity,
        off_hours_ratio=row.off_hours_ratio,
        sample_event_count=row.sample_event_count,
        maturity=row.maturity,
    )


def apply_baseline_view(row: Baseline, view: BaselineView) -> Baseline:
    """Write a freshly computed baseline back onto its ORM row."""
    row.hourly_distribution = {str(k): v for k, v in view.hourly_distribution.items()}
    row.dow_distribution = {str(k): v for k, v in view.dow_distribution.items()}
    row.common_resources = view.common_resources
    row.resource_frequencies = view.resource_frequencies
    row.known_ip_prefixes = view.known_ip_prefixes
    row.known_countries = view.known_countries
    row.known_devices = view.known_devices
    row.action_frequencies = view.action_frequencies
    row.resource_entropy = view.resource_entropy
    row.avg_daily_events = view.avg_daily_events
    row.stddev_daily_events = view.stddev_daily_events
    row.avg_daily_bytes = view.avg_daily_bytes
    row.stddev_daily_bytes = view.stddev_daily_bytes
    row.typical_max_sensitivity = view.typical_max_sensitivity
    row.off_hours_ratio = view.off_hours_ratio
    row.sample_event_count = view.sample_event_count
    row.maturity = view.maturity
    row.version += 1
    return row


def to_context_view(row: ContextRecord) -> ContextView:
    return ContextView(
        id=row.id,
        identity_id=row.identity_id,
        context_type=str(row.context_type),
        title=row.title,
        description=row.description,
        ticket_reference=row.ticket_reference,
        valid_from=row.valid_from,
        valid_until=row.valid_until,
        damping_factor=row.damping_factor,
        target_resources=list(row.target_resources or []),
        allowed_actions=list(row.allowed_actions or []),
        approved_by=row.approved_by,
        is_active=row.is_active,
    )


def to_rule_view(row: DetectionRule) -> RuleView:
    return RuleView(
        id=row.id,
        slug=row.slug,
        name=row.name,
        severity=str(row.severity),
        conditions=dict(row.conditions or {}),
        risk_boost=row.risk_boost,
        mitre_techniques=list(row.mitre_techniques or []),
        recommended_actions=list(row.recommended_actions or []),
        suppress_when_context=row.suppress_when_context,
        enabled=row.enabled,
    )


def to_asset_view(row: Asset) -> AssetView:
    return AssetView(
        key=row.key,
        display_name=row.display_name,
        category=row.category,
        sensitivity_level=row.sensitivity_level,
        environment=row.environment,
        owner_team=row.owner_team,
        contains_pii=row.contains_pii,
        contains_phi=row.contains_phi,
        contains_cardholder_data=row.contains_cardholder_data,
        is_crown_jewel=row.is_crown_jewel,
        record_estimate=row.record_estimate,
        compliance_scopes=list(row.compliance_scopes or []),
    )


def to_indicator_view(row: ThreatIndicator) -> IndicatorView:
    return IndicatorView(
        indicator_type=str(row.indicator_type),
        value=row.value,
        confidence=row.confidence,
        severity=str(row.severity),
        source_feed=row.source_feed,
        description=row.description,
    )
