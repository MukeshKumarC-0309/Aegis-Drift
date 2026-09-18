"""End-to-end smoke test against a running SilentShift API.

Exercises the whole stack through HTTP — auth, RBAC, ingestion, the detection
engine, explainability, response and export — and asserts the product claims
rather than just checking for 200s.

    python scripts/smoke_test.py [base_url]

Exits non-zero on the first failed expectation, so it works as a deployment gate.
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SILENTSHIFT_URL", "http://127.0.0.1:8000")).rstrip("/")
API = f"{BASE}/api/v1"
token = None
fails = []

def call(method, path, body=None, raw=False, expect=None, auth=True):
    url = path if path.startswith("http") else API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if auth and token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            payload = r.read()
            if expect and r.status != expect:
                fails.append(f"{method} {path}: got {r.status}, expected {expect}")
            return r.status, (payload.decode() if raw else json.loads(payload))
    except urllib.error.HTTPError as e:
        payload = e.read().decode()
        if expect and e.code != expect:
            fails.append(f"{method} {path}: got {e.code}, expected {expect} — {payload[:160]}")
        elif not expect:
            fails.append(f"{method} {path}: HTTP {e.code} — {payload[:160]}")
        return e.code, payload

def ok(label, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {label}{(' — ' + detail) if detail else ''}")
    if not cond:
        fails.append(label)

print(f"\nSilentShift smoke test against {BASE}")
print("\n=== AUTH ===")
ADMIN_EMAIL = os.environ.get("SILENTSHIFT_ADMIN_EMAIL", "admin@silentshift.io")
ADMIN_PASSWORD = os.environ.get("SILENTSHIFT_ADMIN_PASSWORD", "ChangeMe_S1lentShift!")

_, tok = call("POST", "/auth/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
token = tok["access_token"] if isinstance(tok, dict) else None
ok("login returns a token pair", bool(token))
call("POST", "/auth/login", {"email": ADMIN_EMAIL, "password": "wrong"}, expect=401)
ok("wrong password rejected", True)
call("GET", "/identities", auth=False, expect=401)
ok("unauthenticated request rejected", True)
_, me = call("GET", "/auth/me")
ok("profile resolves role", me.get("role") == "admin", f"role={me.get('role')}")

print("\n=== ESTATE ===")
_, est = call("GET", "/simulator/estate")
ok("estate populated", est["identities"] == 24 and est["events"] > 8000, str(est))
_, ids = call("GET", "/identities?page_size=5")
ok("identities paginated", len(ids["items"]) == 5 and ids["meta"]["total"] == 24,
   f"total={ids['meta']['total']}")
_, assets = call("GET", "/catalog/assets/summary")
ok("asset catalogue classified", assets["crown_jewels"] > 0 and assets["total_records"] > 0,
   f"{assets['total']} assets, {assets['crown_jewels']} crown jewels, {assets['total_records']:,} records")

print("\n=== BASELINE QUALITY (control group must be quiet) ===")
_, all_ids = call("GET", "/identities?page_size=50")
_, existing_alerts = call("GET", "/alerts?page_size=1")
noisy = [i for i in all_ids["items"] if i["transition_state"] != "STABLE"]
fresh_estate = existing_alerts["meta"]["total"] == 0

if fresh_estate:
    # The assertion that matters: on a freshly seeded estate, nothing should be
    # drifting. A detector that alerts on normal behaviour is worse than none.
    ok("seeded estate is quiet before scenarios", len(noisy) == 0,
       f"{len(noisy)} non-stable: {[i['username'] for i in noisy]}")
else:
    print(f"  SKIP  estate already exercised ({existing_alerts['meta']['total']} alerts present) — "
          "the quiet-control check only means something on a fresh deployment")

print("\n=== SCENARIOS (engine regression harness) ===")
_, scenarios = call("GET", "/simulator/scenarios")
ok("six scenarios registered", len(scenarios) == 6, f"{len(scenarios)}")
results = []
for s in scenarios:
    _, r = call("POST", f"/simulator/scenarios/{s['id']}/run", {})
    if not isinstance(r, dict):
        fails.append(f"scenario {s['id']} failed: {r}")
        continue
    results.append(r)
    match = r["outcome_matches_expectation"]
    print(f"  {'PASS' if match else 'FAIL'}  {s['id']:20} {r['risk_before']:5.1f} -> {r['risk_after']:5.1f}  "
          f"{r['state_after']:20} (expected {s['expected_state']})"
          + ("  [damped]" if r["damping_applied"] else "")
          + ("  [ANTI-TAMPER]" if r["anti_tamper_triggered"] else ""))
    if not match:
        fails.append(f"scenario {s['id']}: got {r['state_after']}, expected {s['expected_state']}")

print("\n=== DETECTION BEHAVIOUR ===")
by_id = {r["scenario"]["id"]: r for r in results}
if "compromised_admin" in by_id:
    ok("anti-tamper pierces on-call context", by_id["compromised_admin"]["anti_tamper_triggered"])
if "project_switcher" in by_id:
    ps = by_id["project_switcher"]
    ok("approved change ticket suppresses the alert", ps["damping_applied"] and ps["risk_after"] < 28,
       f"risk={ps['risk_after']}")

print("\n=== INVESTIGATION ===")
_, inv = call("GET", "/identities/alex.mercer/investigation")
ok("investigation payload assembled", "explanation" in inv and "blast_radius" in inv)
ok("narrative generated", len(inv["explanation"]["narrative"]) > 200,
   f"{len(inv['explanation']['narrative'])} chars")
ok("findings evidenced", len(inv["explanation"]["key_findings"]) > 0,
   f"{len(inv['explanation']['key_findings'])} findings")
ok("MITRE techniques mapped", len(inv["explanation"]["mitre_techniques"]) > 0,
   f"{len(inv['explanation']['mitre_techniques'])} techniques")
ok("counter-evidence stated", isinstance(inv["explanation"]["counter_evidence"], list))
ok("blast radius quantified", inv["blast_radius"]["records_at_risk"] > 0,
   f"{inv['blast_radius']['records_at_risk']:,} records, {inv['blast_radius']['estimated_exposure_display']}")
ok("timeline present", len(inv["timeline"]) > 0, f"{len(inv['timeline'])} points")
ok("peer cohort compared", inv["explanation"]["peer_comparison"].get("available") is True,
   str(inv["explanation"]["peer_comparison"].get("cohort")))

print("\n=== COPILOT ===")
for q, want in [("Why was this flagged?", "why_flagged"),
                ("What data could they reach?", "what_accessed"),
                ("What regulatory obligations apply?", "compliance"),
                ("Bake me a cake", "unknown")]:
    _, a = call("POST", "/identities/alex.mercer/copilot", {"identity_id": "alex.mercer", "question": q})
    ok(f"copilot: {q!r}", a.get("intent") == want, f"intent={a.get('intent')}")

print("\n=== ALERTS / CASES / RESPONSE ===")
_, alerts = call("GET", "/alerts?open_only=true&page_size=20")
ok("alerts raised", alerts["meta"]["total"] > 0, f"{alerts['meta']['total']} open")
first = alerts["items"][0] if alerts["items"] else None
if first:
    ok("alert carries identity context", first.get("username") is not None, first.get("username"))
    _, case = call("POST", "/cases", {"title": "E2E investigation", "priority": "P2",
                                      "severity": "HIGH", "alert_ids": [first["id"]],
                                      "primary_identity_id": first["identity_id"]})
    ok("case opened with reference", case.get("reference", "").startswith("SS-"), case.get("reference"))
    call("POST", f"/cases/{case['id']}/entries", {"body": "Reviewed the timeline."})
    _, detail = call("GET", f"/cases/{case['id']}")
    ok("case timeline records entries", len(detail["entries"]) >= 2, f"{len(detail['entries'])} entries")

_, pbs = call("GET", "/response/playbooks")
ok("playbooks available", len(pbs) == 4, f"{len(pbs)}")
_, dry = call("POST", "/response/playbooks/confirmed-account-compromise/run",
              {"identity_id": "sarah.connor", "dry_run": True})
ok("playbook dry-run plans without enforcing", dry["dry_run"] and len(dry["steps"]) == 6,
   f"{len(dry['steps'])} steps planned")
_, act = call("POST", "/response/identities/sarah.connor/actions",
              {"action": "STEP_UP_MFA", "notes": "E2E verification"})
ok("containment action executed", act.get("outcome") == "SUCCEEDED")

print("\n=== RULES ===")
_, rs = call("GET", "/detections/stats")
ok("builtin rules loaded", rs["total"] == 12 and rs["enabled"] == 12, f"{rs['total']} rules")
_, t1 = call("POST", "/detections/test",
             {"conditions": {"all": [{"field": "sensitivity_level", "op": "gte", "value": 4},
                                     {"field": "is_off_hours", "op": "is_true"}]}})
ok("rule tester matches a true condition", t1["valid"] and t1["matched"])
_, t2 = call("POST", "/detections/test", {"conditions": {"field": "bogus", "op": "nope", "value": 1}})
ok("rule tester rejects a bad operator", not t2["valid"], t2.get("error", "")[:60])
_, newrule = call("POST", "/detections", {
    "slug": "e2e-test-rule", "name": "E2E test rule",
    "description": "Created by the end-to-end suite.",
    "conditions": {"field": "record_count", "op": "gte", "value": 999999},
    "risk_boost": 5.0})
ok("custom rule created", newrule.get("slug") == "e2e-test-rule")
call("DELETE", f"/detections/{newrule['id']}")
_, builtin = call("GET", "/detections/audit-log-destruction")
code, _ = call("PATCH", f"/detections/{builtin['id']}",
               {"conditions": {"field": "action", "op": "eq", "value": "x"}}, expect=409)
ok("builtin rule logic is immutable", code == 409)

print("\n=== ANALYTICS / EXPORT ===")
_, ov = call("GET", "/analytics/overview")
ok("overview reflects scenarios", ov["kpis"]["critical_identities"] > 0,
   f"{ov['kpis']['critical_identities']} critical, health {ov['kpis']['fleet_health_score']}")
_, mx = call("GET", "/analytics/mitre/coverage")
ok("ATT&CK coverage computed", mx["observed_count"] > 0,
   f"{mx['observed_count']}/{mx['catalog_size']} techniques ({mx['coverage_percentage']}%)")
_, em = call("GET", "/analytics/metrics")
ok("executive metrics computed", "mttd_hours" in em and len(em["compliance"]) == 5,
   f"MTTD {em['mttd_hours']}h, {len(em['compliance'])} frameworks")
code, doss = call("GET", "/export/identities/alex.mercer/dossier.md", raw=True)
ok("forensic dossier renders", code == 200 and "SHA-256" in doss, f"{len(doss)} chars")
code, csv = call("GET", "/export/identities/alex.mercer/events.csv", raw=True)
ok("CSV export renders", code == 200 and csv.count("\n") > 10, f"{csv.count(chr(10))} rows")

print("\n=== TUNING GUARDRAILS ===")
code, _ = call("PUT", "/analytics/hyperparameters",
               {"threshold_early_drift": 80, "threshold_escalating": 50, "recompute": False},
               expect=422)
ok("out-of-order thresholds rejected", code == 422)
code, _ = call("PUT", "/analytics/hyperparameters",
               {"vector_weights": {"nonsense": 1.0}, "recompute": False}, expect=422)
ok("unknown vector weight rejected", code == 422)

print("\n=== HEALTH ===")
code, h = call("GET", f"{BASE}/health")
ok("health reports healthy", h["status"] == "healthy", str(h["checks"]))
code, m = call("GET", f"{BASE}/metrics", raw=True)
ok("prometheus metrics exposed", "silentshift_http_requests_total" in m)

print("\n" + "=" * 70)
if fails:
    print(f"FAILURES ({len(fails)}):")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("ALL END-TO-END CHECKS PASSED")
