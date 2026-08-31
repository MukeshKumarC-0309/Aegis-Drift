# SilentShift: Context-Aware Behavioral Security & Threat Transition System

> **Hackathon Solution**: Detect subtle, low-and-slow account compromise and insider threats through multi-signal behavioral baselines, temporal sequence correlation, and context-aware false positive suppression.

---

## 1. Executive Summary & Problem Alignment

Modern sophisticated threats—whether compromised credentials, malicious insiders, or lateral privilege escalation—rarely announce themselves with brute-force alarms. Instead, an account may behave normally for weeks or months, then slowly or suddenly drift into anomalous resource access, off-hours queries, or sensitive privilege actions.

Individual events appear low-risk or benign in isolation. However, viewed as a **sequence over time**, small deviations compound into high-risk threat transitions. Furthermore, benign organizational changes (such as role transfers, emergency on-call shifts, or approved change tickets) trigger flood of false positive alerts if the system lacks contextual intelligence.

**SilentShift** solves this with a 4-pillar analytical architecture:
1. **Multi-Signal Dimensional Baselines**: Continuous probabilistic modeling across Circadian/Temporal profiles, Shannon Resource Access Entropy, Privilege Sensitivity Tiers, and Peer-Group Homology.
2. **Temporal Sequence Correlation & Drift Velocity**: Sliding-window risk accumulation with exponential decay half-life and state transition tracking (`STABLE` $\rightarrow$ `EARLY_DRIFT` $\rightarrow$ `ESCALATING` $\rightarrow$ `CRITICAL_TRANSITION`).
3. **Context-Aware Adaptive Damping**: Native integration of organizational authorizations (approved Jira/ServiceNow tickets, HR role updates, scheduled maintenance windows) that dynamically suppresses false positives while strictly enforcing anti-tamper security floors.
4. **Transparent Explainability (XAI) & SOC Investigation Workbench**: A dedicated 5-tab interface delivering natural language briefs ("Why was this flagged?"), multi-vector feature attributions, peer cohort benchmarks, and MITRE ATT&CK-aligned response playbooks.

---

## 2. Multi-Tab User Interface Design

To prevent information clutter and deliver a crisp user experience, the interface is separated into **5 dedicated tabs**:

1. **Command Center (Fleet Posture)**: Executive KPIs, Fleet Threat Transition Spectrum, Dominant Drift Vector Polar Chart, and Prioritized Triage Feed.
2. **Shift Triage & Alert Queue**: Full enterprise identity matrix with search, status filtering, velocity indicators, and context badges.
3. **Investigator Workbench**: Deep forensic breakdown for any account:
   - Interactive Dual-Axis Chrono Timeline (Baseline vs. Single Event Anomaly vs. Cumulative Risk Curve)
   - Multi-Vector Radar Attribution (Temporal, Resource Entropy, Privilege Escalation, Peer Divergence)
   - Plain-Language Automated SOC Narrative (XAI)
   - Peer Cohort Homology Benchmark
   - MITRE ATT&CK Matrix Alignment
   - Forensic Event Stream
   - One-Click Triage Actions (Enforce Step-Up MFA, Quarantine Session, Update Baseline)
4. **Context & Policy Management**: Live Enterprise Authorization Registry and Analytical Hyperparameter Tuner (Sliding-window half-life, vector weights).
5. **Live Threat Simulator & Ingestion**: One-click execution of 4 hackathon attack scenarios and interactive real-time telemetry injector.

---

## 3. Mathematical & Algorithmic Foundations

### A. Circadian & Temporal Anomaly
For an event occurring at hour $h \in [0, 23]$ and day $d \in [0, 6]$:
$$P(h \mid \text{baseline}) = \frac{C(h) + \alpha}{N + 24\alpha}$$
$$\text{Score}_{\text{temporal}} = \min\left(100, \max\left(0, 1.0 - 12 \cdot P(h)\right) \times 100\right)$$

### B. Resource Access Entropy & Sensitivity
$$\text{Entropy } H = -\sum_{i=1}^M p_i \log_2(p_i)$$
$$\text{Score}_{\text{resource}} = 0.4 \cdot \text{Novelty} + 0.6 \cdot (\text{Sensitivity} - \text{Max}_{\text{base}})^+ \times 25$$

### C. Sliding-Window Temporal Accumulator with Exponential Decay
Between events $t_{i-1}$ and $t_i$:
$$R(t_i) = R(t_{i-1}) \cdot e^{-\lambda \Delta t} + \Delta R_i$$
$$\lambda = \frac{\ln(2)}{T_{1/2}} \quad (T_{1/2} = 48\text{ hours})$$
$$\Delta R_i = \left(\frac{S_i - \theta}{100 - \theta}\right)^{1.2} \times 22 \quad \text{for } S_i > \theta = 28$$

### D. Context-Aware Damping
$$\text{Risk}_{\text{final}} = \text{Risk}_{\text{raw}} \cdot \delta_{\text{ticket}} \quad (\delta \approx 0.25 - 0.35)$$
*Exemption*: Tampering operations (e.g., `delete_audit_logs`, `dump_credentials`) bypass damping unconditionally.

---

## 4. Pre-Built Demonstration Scenarios

1. **Scenario 1: The Slow Poisoner (Low-and-Slow Exfiltration)**
   - *Target*: `alex.mercer` (Senior Frontend Engineer)
   - *Behavior*: Gradually transitions from routine UI tasks to off-hours customer PII schema exploration, SQL queries, and crown-jewel bulk export.
   - *Detection*: Sequence correlation captures subtle multi-day drift into `CRITICAL_TRANSITION`.
2. **Scenario 2: The Compromised Admin (Credential Takeover & Lateral Pivot)**
   - *Target*: `sarah.connor` (Lead DevOps Engineer)
   - *Behavior*: Stolen credentials used from an external IP at 02:00 AM; attempts IAM privilege escalation and CloudTrail deletion. Anti-tamper overrides her normal on-call ticket and fires a Critical alert.
3. **Scenario 3: The Legitimate Project Switcher (Context-Aware False Positive Suppression)**
   - *Target*: `priya.patel` (Cloud Backend Architect)
   - *Behavior*: Transferred to Lead the "Project Titan" Data Lake migration. Accesses novel high-tier databases; context engine matches Change Ticket `CHG-2024-9182` and damps risk by 75%, avoiding alert fatigue.
4. **Scenario 4: Privilege Creep & Secret Vault Access**
   - *Target*: `elena.rostova` (Staff Data Scientist)
   - *Behavior*: Incremental accumulation of elevated cloud tokens and secret manager keys over several days.

---

## 5. Quick Start & Execution

### Prerequisites
- Python 3.10+
- Installed packages: `fastapi`, `uvicorn`, `scikit-learn`, `numpy`, `pandas`, `pydantic`

### Run the System
```powershell
python run.py
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### Run Automated Unit & Integration Tests
```powershell
$env:PYTHONPATH="backend"
python -m pytest tests/test_engine.py -v
```
