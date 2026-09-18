# The detection engine

How SilentShift decides that an identity is drifting, and why it is built this way.

---

## 1. The premise

Per-event detection asks *"is this action bad?"*. For credential compromise the answer is almost
always "no, individually". An attacker with valid credentials performs valid operations; what
distinguishes them is the **trajectory** those operations trace over days.

So the engine asks a different question: *"is this identity behaving like itself?"* — and then
accumulates the answer over time.

This has a direct consequence for how it must be evaluated. A detector that fires on the
exfiltration chain is easy; a detector that fires on the chain **and stays silent on 24 normal
employees and one legitimate migration** is the hard part. Both are asserted in the test suite.

## 2. Baselines

Each identity's own history is the reference — not a global threshold, and not a policy.

| Learned | How | Used by |
|---|---|---|
| Circadian histogram | 24-bin hour distribution, Laplace-smoothed (α = 0.5) | temporal |
| Day-of-week distribution | 7-bin, same smoothing | temporal |
| Resource frequencies | Access counts per resource; top 40 retained | resource |
| Resource entropy | Normalised Shannon entropy of that distribution | baseline comparison |
| Network origins | Distinct /24 prefixes and countries | geo-velocity |
| Device fingerprints | Distinct device identifiers | device |
| Action frequencies | Counts per action verb | privilege |
| Daily volume | Mean and σ of events/day and bytes/day | volume |
| Sensitivity ceiling | **95th percentile**, not the max | resource |
| Off-hours ratio | Share of activity outside 07:00–20:00 | temporal |

**Why the 95th percentile rather than the maximum.** If an engineer touched one Tier-5 asset once
during an incident six months ago, a max-based ceiling would permanently accept Tier-5 access as
normal for them. The percentile lets a single outlier stay an outlier.

**Maturity.** Every baseline carries a maturity score from sample count and window span. Below
roughly 200 samples the distributions are too sparse to trust, so immaturity is surfaced in the UI
and *reduces the engine's stated confidence* rather than being hidden.

## 3. The eight vectors

Each returns 0–100 independently. Their normalised weights are tunable at runtime.

### Temporal (default weight 0.14)

Rarity of the event's hour under the identity's own histogram:

```
score = max(0, 1 − P(hour) × 12) × 100
```

The ×12 scaling puts "half as likely as uniform" at zero and vanishingly rare hours near 100.
Floors apply for explicit off-hours flags (0.72) and for weekend activity by a weekday-only identity
(0.68). An identity with an off-hours ratio below 1% that suddenly works at 02:00 floors at 0.85 —
for someone who has *never* done this, the first time is the most informative.

### Resource (0.22)

Novelty of the resource combined with any jump above the sensitivity ceiling:

```
novelty     = 8   (seen ≥5 times) | 28 (seen 1–4) | 68 (never)
sensitivity = min(100, 38 + 22 × (tier − ceiling))  when above the ceiling, else 10
score       = 0.42 × novelty + 0.58 × sensitivity   (+18 for novel high-value keywords)
```

Sensitivity is weighted above novelty: touching a *new* Tier-1 wiki page is unremarkable; touching a
*familiar-looking* Tier-5 vault is not.

### Privilege (0.20)

Weight of the action itself, discounted by how routinely this identity performs it.

```
anti-tamper actions  → 100  (unconditional)
privileged actions   → 88
mutating actions     → 52
read actions         → 12
```

An identity that has performed the action ≥10 times gets ×0.45; ≥3 times gets ×0.7. A DevOps
engineer assuming roles all day is not interesting. A finance analyst doing it once is.
Denied outcomes on privileged actions add +10 — probing for permissions you lack is itself a signal.

### Peer divergence (0.13)

The cohort is the control group. Cohorts key on department plus role with seniority stripped, so a
"Senior Frontend Engineer" and a "Frontend Engineer" compare directly. Cohorts smaller than three
members fall back to a department-wide cohort — coarser, but statistically meaningful.

Scores combine a department/resource forbidden-pairs table (engineering has no business in payroll),
divergence from resources the cohort shares, and sensitivity above the cohort mean.

### Geo-velocity (0.12)

Unfamiliar country (62) or unfamiliar /24 (45), plus impossible travel between consecutive
located events:

```
speed = haversine(previous, current) / Δt
speed > 900 km/h  → 80 + 20 × min(1, (speed − 900) / 3600)
speed > 495 km/h  → 55
```

900 km/h is roughly commercial cruise. Distances under 100 km are ignored — that is geolocation
noise, not travel.

### Volume (0.11)

Z-scored deviation of today's running event count and byte total against the identity's learned
mean and σ, with absolute floors for single large transfers (>500 MB → 88) and record counts
(>100k → 90). Staged collection shows here before egress does.

### Device (0.05)

Unrecognised device fingerprint → 58. Low weight because device identifiers are noisy in practice;
it corroborates rather than accuses.

### Threat intel (0.03)

IP, ASN or user-agent match against active indicators, scored at the indicator's confidence. Lowest
weight by design — intel is a strong *hint*, and the rule engine is the right place to act on it
decisively.

## 4. Fusion

```python
fused = Σ(vector_i × weight_i)

elevated = count(vector ≥ 45)
if elevated ≥ 4:  fused ×= 1.45
elif elevated == 3: fused ×= 1.30
elif elevated == 2: fused ×= 1.14
```

Independent dimensions agreeing is the point. Off-hours *alone* is weak; off-hours **and** novel
resource **and** privilege escalation **and** unfamiliar geography is a different claim entirely,
and the synergy multiplier says so.

## 5. Sequence correlation

The accumulator:

```
R(t_i) = R(t_{i−1}) · e^(−λ·Δt) + ΔR_i        λ = ln2 / T½   (default T½ = 48h)

ΔR_i = ((S_i − θ) / (100 − θ))^1.18 × 26 × A    for S_i > θ = 28
     = −3% of current                           otherwise
```

Three properties matter:

**Decay.** Risk halves every 48 hours of quiet. An account that had a strange week three months ago
is not permanently suspicious.

**Exponent > 1.** A mildly odd event contributes little; a severe one contributes
disproportionately. Linear accumulation would let a hundred boring events out-vote one catastrophe.

**Benign events actively reduce risk.** Normal behaviour rebuilds confidence rather than merely
failing to add.

### Streak amplification — `A`

```
A = 1 + min(1.1, 0.22 × (streak − 1))
A += 0.35  if the last 3+ anomalies have monotonically rising sensitivity
```

This is the whole thesis expressed as a number. Three *linked* anomalies are materially worse than
three unrelated ones, and a run climbing from Tier-2 through Tier-5 is the signature of deliberate
escalation — recon, then access, then exfiltration. A benign event resets the streak to zero.

### Severity floors

```
raw event score ≥ 92 → cumulative risk ≥ 76
                ≥ 80 → ≥ 56
                ≥ 68 → ≥ 34
```

A single act severe enough to be damning on its own must not be averaged away by a quiet history.
The floor applies to the damped score for damped risk and the raw score for raw risk, so context
still works as intended.

### State machine

| State | Default | Meaning |
|---|---|---|
| `STABLE` | < 28 | Inside the envelope |
| `EARLY_DRIFT` | 28–50 | Watch — usually a genuine role change |
| `ESCALATING` | 50–75 | Investigate now; intervention is cheapest here |
| `CRITICAL_TRANSITION` | ≥ 75 | Containment recommended |

**Drift velocity** is the risk change over the trailing 24 hours, normalised to points/day. It
separates "sitting at 60 and stable" from "passed through 60 on the way up" — the same score with
very different urgency.

## 6. Context damping

Damping is what makes the queue readable. It applies a factor scaled by match specificity:

| Specificity | Match | Effect |
|---|---|---|
| 3 | Event carries the ticket reference as a tag | Full declared factor |
| 2 | Resource is in the approval's scope | Full declared factor |
| 1 | Blanket approval, no resources listed | Factor + 0.25 (damps less) |
| 0 | No match, window lapsed, or action not permitted | No damping |

Factors are clamped to [0.10, 0.95] and damped scores floor at 4.0. **Nothing is ever fully
silenced** — a suppressed signal stays visible in trends, in the raw score, and in the alert record.
Suppressed alerts appear in the triage queue marked as suppressed rather than disappearing, so
damping decisions remain auditable.

### The anti-tamper floor

```python
if event.action in ANTI_TAMPER_ACTIONS:
    return DampingDecision(score=raw_score, is_damped=False, anti_tamper=True)
```

Checked **before contexts are loaded at all**. `delete_audit_logs`, `disable_logging`,
`dump_credentials`, `disable_mfa`, `exfiltrate`, `create_backdoor_user`, `rotate_root_key`.

There is no legitimate workflow in which a user deletes their own audit trail. Making this
unreachable by configuration — rather than a policy someone could set wrong — is the single most
important security property in the system, and it is tested against a maximally permissive blanket
approval for each action.

## 7. The rule layer

Statistics catch drift. Rules catch *known-bad*, deterministically. Rules are JSON so analysts
author them in the console without a deploy:

```jsonc
{
  "all": [
    { "field": "sensitivity_level", "op": "gte", "value": 4 },
    { "field": "action", "op": "in", "value": ["export", "export_all"] },
    { "any": [
      { "field": "is_off_hours", "op": "is_true" },
      { "field": "vectors.geovelocity", "op": "gte", "value": 70 }
    ]}
  ]
}
```

Combinators `all` / `any` / `not` (max depth 8); operators `eq ne gt gte lt lte in not_in contains
not_contains startswith endswith matches between is_true is_false`. Every event field plus every
vector score under `vectors.*` is queryable.

Matched rules add a bounded boost with diminishing returns — `Σ boost × 0.6^i`, capped at 45 — so
stacking rules cannot trivially saturate a score. A rule whose conditions are malformed is skipped,
never allowed to break the pipeline for every other rule.

Rules declare `suppress_when_context`. Anti-tamper and crown-jewel-export rules set it `false`: they
fire regardless of any approval.

## 8. Tuning

Everything above is adjustable at runtime from **Settings → Engine tuning** (admin only).

| Situation | Adjustment |
|---|---|
| Too many alerts | Raise `normal_threshold`, raise `threshold_early_drift`, shorten the half-life |
| Missing slow drift | Lengthen the half-life to 72–96h, lower `normal_threshold` |
| Noise from one dimension | Lower that vector's weight — the rest renormalise automatically |
| Bursty, high-tempo estate | Shorten the half-life to 12–24h so bursts dominate |

Thresholds must stay strictly ordered; the API rejects an out-of-order set rather than silently
reordering it. Weights are renormalised to sum to 1, so editing one rebalances the others instead of
inflating every score.

**Tuning is atomic.** The endpoint validates a candidate configuration and commits it only if every
check passes. A rejected request leaves the running engine completely untouched — including any
individually valid fields bundled into the same payload. This matters more than it sounds: the
earlier implementation mutated the live config before validating, so a refused change could quietly
raise the alerting threshold while the operator was told nothing had happened.

**Measure before and after.** The Detections page tracks per-rule precision from analyst
dispositions and surfaces rules below 50% as tuning candidates. Tuning without that feedback is
guessing.
