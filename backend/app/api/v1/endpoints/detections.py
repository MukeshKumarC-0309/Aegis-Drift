"""Detection rule authoring, testing and tuning."""

from __future__ import annotations

from fastapi import APIRouter, status
from sqlalchemy import or_, select

from app.api.deps import CurrentUser, DbSession, Pagination, RequireAnalyst
from app.core.enums import Severity
from app.core.exceptions import ConflictError, NotFoundError, ValidationError
from app.db.models import DetectionRule
from app.engine.rules import RuleSyntaxError, evaluate_node, validate_conditions
from app.schemas.common import Message, Page
from app.schemas.domain import RuleCreate, RuleRead, RuleTestRequest, RuleTestResult, RuleUpdate
from app.services import audit
from app.utils.query import apply_sort, paginate

router = APIRouter()

#: A representative event used when testing a rule without a real one.
SAMPLE_FACTS: dict = {
    "event_type": "API_CALL",
    "resource": "prod_customer_sql_replica",
    "action": "query_bulk",
    "outcome": "SUCCESS",
    "sensitivity_level": 4,
    "ip_address": "185.220.101.5",
    "country": "RO",
    "asn": "AS9009",
    "device_id": "unknown-device",
    "user_agent": "python-requests/2.28.1",
    "bytes_transferred": 320_000_000,
    "record_count": 84_000,
    "is_off_hours": True,
    "hour": 2,
    "weekday": 5,
    "is_weekend": True,
    "context_tags": [],
    "has_context_tag": False,
    "raw_score": 78.0,
    "cumulative_risk": 62.0,
    "vectors.temporal": 85.0,
    "vectors.resource": 92.0,
    "vectors.privilege": 55.0,
    "vectors.peer_divergence": 74.0,
    "vectors.geovelocity": 88.0,
    "vectors.volume": 81.0,
    "vectors.device": 58.0,
    "vectors.intel": 92.0,
}


@router.get("", response_model=Page[RuleRead], summary="List detection rules")
async def list_rules(
    db: DbSession,
    _: CurrentUser,
    params: Pagination,
    category: str | None = None,
    severity: Severity | None = None,
    enabled_only: bool = False,
    search: str | None = None,
) -> Page[RuleRead]:
    stmt = select(DetectionRule)
    if category:
        stmt = stmt.where(DetectionRule.category == category)
    if severity:
        stmt = stmt.where(DetectionRule.severity == severity)
    if enabled_only:
        stmt = stmt.where(DetectionRule.enabled.is_(True))
    if search:
        pattern = f"%{search.lower()}%"
        stmt = stmt.where(or_(DetectionRule.name.ilike(pattern), DetectionRule.description.ilike(pattern)))
    stmt = apply_sort(stmt, DetectionRule, params, "match_count")
    return await paginate(db, stmt, params, RuleRead.model_validate)


@router.get("/schema", summary="Rule DSL reference")
async def rule_schema(_: CurrentUser) -> dict:
    """Machine-readable description of the condition grammar, used by the rule builder."""
    from app.engine.rules import OPERATORS

    return {
        "operators": sorted(OPERATORS),
        "combinators": ["all", "any", "not"],
        "fields": [
            {"name": name, "type": type(value).__name__, "example": value}
            for name, value in sorted(SAMPLE_FACTS.items())
        ],
        "example": {
            "all": [
                {"field": "sensitivity_level", "op": "gte", "value": 4},
                {"field": "action", "op": "in", "value": ["export", "export_all"]},
                {
                    "any": [
                        {"field": "is_off_hours", "op": "is_true"},
                        {"field": "vectors.geovelocity", "op": "gte", "value": 70},
                    ]
                },
            ]
        },
    }


@router.get("/stats", summary="Rule performance")
async def rule_stats(db: DbSession, _: CurrentUser) -> dict:
    rules = (await db.execute(select(DetectionRule))).scalars().all()
    scored = []
    for rule in rules:
        judged = rule.true_positive_count + rule.false_positive_count
        precision = round(rule.true_positive_count / judged * 100, 1) if judged else None
        scored.append(
            {
                "id": rule.id,
                "slug": rule.slug,
                "name": rule.name,
                "category": rule.category,
                "severity": str(rule.severity),
                "enabled": rule.enabled,
                "match_count": rule.match_count,
                "true_positives": rule.true_positive_count,
                "false_positives": rule.false_positive_count,
                "precision": precision,
                "last_matched_at": rule.last_matched_at,
            }
        )
    noisy = [r for r in scored if r["precision"] is not None and r["precision"] < 50]
    return {
        "total": len(rules),
        "enabled": sum(1 for r in rules if r.enabled),
        "builtin": sum(1 for r in rules if r.is_builtin),
        "total_matches": sum(r.match_count for r in rules),
        "rules": sorted(scored, key=lambda r: -r["match_count"]),
        "tuning_candidates": sorted(noisy, key=lambda r: r["precision"] or 0)[:5],
    }


@router.post(
    "/test",
    response_model=RuleTestResult,
    summary="Test a rule before saving",
    description="Validates the condition tree and evaluates it against a representative "
    "event, optionally overridden field by field via `sample`.",
)
async def test_rule(payload: RuleTestRequest, _: CurrentUser) -> RuleTestResult:
    facts = {**SAMPLE_FACTS, **payload.sample}
    try:
        validate_conditions(payload.conditions)
    except RuleSyntaxError as exc:
        return RuleTestResult(valid=False, matched=False, error=str(exc), facts=facts)
    try:
        matched = evaluate_node(payload.conditions, facts)
    except RuleSyntaxError as exc:
        return RuleTestResult(valid=False, matched=False, error=str(exc), facts=facts)
    return RuleTestResult(valid=True, matched=matched, facts=facts)


@router.post("", response_model=RuleRead, status_code=status.HTTP_201_CREATED, summary="Create a rule")
async def create_rule(payload: RuleCreate, user: RequireAnalyst, db: DbSession) -> DetectionRule:
    exists = (
        await db.execute(select(DetectionRule.id).where(DetectionRule.slug == payload.slug))
    ).scalar_one_or_none()
    if exists:
        raise ConflictError(f"A rule with the slug '{payload.slug}' already exists.")

    try:
        validate_conditions(payload.conditions)
    except RuleSyntaxError as exc:
        raise ValidationError(str(exc), details={"field": "conditions"}) from exc

    rule = DetectionRule(**payload.model_dump(), is_builtin=False)
    db.add(rule)
    await db.flush()
    await audit.record(
        db,
        action="rule.created",
        target_type="rule",
        target_id=rule.id,
        actor=user,
        payload={"slug": rule.slug},
    )
    return rule


@router.get("/{rule_id}", response_model=RuleRead, summary="Fetch one rule")
async def get_rule(rule_id: str, db: DbSession, _: CurrentUser) -> DetectionRule:
    return await _resolve(db, rule_id)


@router.patch("/{rule_id}", response_model=RuleRead, summary="Update a rule")
async def update_rule(
    rule_id: str, payload: RuleUpdate, user: RequireAnalyst, db: DbSession
) -> DetectionRule:
    rule = await _resolve(db, rule_id)
    changes = payload.model_dump(exclude_unset=True)

    if "conditions" in changes:
        if rule.is_builtin:
            raise ConflictError("Built-in rule logic is immutable. Disable this rule and clone it instead.")
        try:
            validate_conditions(changes["conditions"])
        except RuleSyntaxError as exc:
            raise ValidationError(str(exc), details={"field": "conditions"}) from exc

    for field, value in changes.items():
        setattr(rule, field, value)
    await audit.record(
        db, action="rule.updated", target_type="rule", target_id=rule.id, actor=user, payload=changes
    )
    return rule


@router.delete("/{rule_id}", response_model=Message, summary="Delete a rule")
async def delete_rule(rule_id: str, user: RequireAnalyst, db: DbSession) -> Message:
    rule = await _resolve(db, rule_id)
    if rule.is_builtin:
        raise ConflictError("Built-in rules cannot be deleted. Disable it instead.")
    await db.delete(rule)
    await audit.record(
        db,
        action="rule.deleted",
        target_type="rule",
        target_id=rule_id,
        actor=user,
        payload={"slug": rule.slug},
    )
    return Message(message=f"Rule '{rule.slug}' deleted.")


async def _resolve(db, rule_id: str) -> DetectionRule:
    rule = (
        await db.execute(
            select(DetectionRule).where(or_(DetectionRule.id == rule_id, DetectionRule.slug == rule_id))
        )
    ).scalar_one_or_none()
    if rule is None:
        raise NotFoundError(f"No detection rule matches '{rule_id}'.")
    return rule
