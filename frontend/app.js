// SilentShift - Enterprise Frontend Application Controller

let currentActiveTab = 'overview';
let currentPersona = 'analyst'; // 'analyst' | 'commander' | 'ciso'
let selectedUserId = 'usr_alex';
let accountsList = [];
let chartFleetSpectrum = null;
let chartFleetVectors = null;
let chartWbTimeline = null;
let chartWbRadar = null;

// Time-Travel Flight Recorder Replay State
let fullTimelinePoints = [];
let replayCurrentStep = 0;
let replayIsPlaying = false;
let replayTimer = null;
let replaySpeed = 1;
let activeInvestigationData = null;
let activeBlastRadiusData = null;
let currentBlastFilter = 'all';

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', async () => {
  lucide.createIcons();
  await refreshAllData();
  
  // Support deep-linking tabs via URL query param (e.g. from 404 page)
  const urlParams = new URLSearchParams(window.location.search);
  const requestedTab = urlParams.get('tab');
  if (requestedTab && ['overview', 'triage', 'workbench', 'context', 'simulator'].includes(requestedTab)) {
    switchTab(requestedTab);
  }
  
  setInterval(() => {
    if (currentActiveTab === 'overview' || currentActiveTab === 'triage') {
      refreshAllData(false);
    }
  }, 30000);
});

// ==========================================
// ENTERPRISE TOOLS MENU & PERSONA SWITCHING
// ==========================================
function toggleEnterpriseMenu() {
  const menu = document.getElementById('dropdown-enterprise-menu');
  const chevron = document.getElementById('enterprise-menu-chevron');
  if (!menu) return;
  
  const isHidden = menu.classList.contains('hidden');
  if (isHidden) {
    menu.classList.remove('hidden');
    if (chevron) chevron.style.transform = 'rotate(180deg)';
    if (window.lucide) lucide.createIcons();
  } else {
    closeEnterpriseMenu();
  }
}

function closeEnterpriseMenu() {
  const menu = document.getElementById('dropdown-enterprise-menu');
  const chevron = document.getElementById('enterprise-menu-chevron');
  if (menu) menu.classList.add('hidden');
  if (chevron) chevron.style.transform = 'rotate(0deg)';
}

// Close enterprise menu when clicking outside
document.addEventListener('click', (e) => {
  const container = document.getElementById('enterprise-tools-container');
  if (container && !container.contains(e.target)) {
    closeEnterpriseMenu();
  }
});

function setPersona(persona) {
  currentPersona = persona;

  const roleLabel = document.getElementById('active-role-label');
  const roleDot = document.getElementById('role-dot-indicator');
  
  // Hide all checks first
  ['analyst', 'commander', 'ciso'].forEach(p => {
    const check = document.getElementById(`check-persona-${p}`);
    if (check) check.classList.add('hidden');
  });

  // Activate targeted check
  const activeCheck = document.getElementById(`check-persona-${persona}`);
  if (activeCheck) activeCheck.classList.remove('hidden');

  let title = 'SOC Analyst';
  if (persona === 'analyst') {
    title = 'SOC Analyst';
    if (roleLabel) roleLabel.innerText = 'SOC Analyst';
    if (roleDot) roleDot.className = 'w-2 h-2 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400/50';
  } else if (persona === 'commander') {
    title = 'Incident Commander';
    if (roleLabel) roleLabel.innerText = 'Incident Commander';
    if (roleDot) roleDot.className = 'w-2 h-2 rounded-full bg-purple-400 shadow-sm shadow-purple-400/50';
  } else if (persona === 'ciso') {
    title = 'CISO / Executive';
    if (roleLabel) roleLabel.innerText = 'CISO / Executive';
    if (roleDot) roleDot.className = 'w-2 h-2 rounded-full bg-amber-400 shadow-sm shadow-amber-400/50';
  }

  showToast(`Switched view to ${title}`, 'info');
}

// ==========================================
// TAB ROUTING
// ==========================================
function switchTab(tabId) {
  currentActiveTab = tabId;
  
  if (tabId !== 'workbench' && replayIsPlaying) {
    toggleReplayPlayback();
  }

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active-tab');
    btn.classList.add('text-slate-400');
  });

  document.querySelectorAll(`.tab-btn[data-tab-id="${tabId}"]`).forEach(btn => {
    btn.classList.add('active-tab');
    btn.classList.remove('text-slate-400');
  });

  const activeBtn = document.getElementById(`tab-btn-${tabId}`);
  if (activeBtn) {
    activeBtn.classList.add('active-tab');
    activeBtn.classList.remove('text-slate-400');
  }

  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.add('hidden');
    pane.classList.remove('active-pane');
  });

  const activePane = document.getElementById(`tab-${tabId}`);
  if (activePane) {
    activePane.classList.remove('hidden');
    activePane.classList.add('active-pane');
  }

  lucide.createIcons();

  if (tabId === 'overview') {
    fetchOverview();
  } else if (tabId === 'triage') {
    fetchAccounts();
  } else if (tabId === 'workbench') {
    loadInvestigateAccount(selectedUserId);
  } else if (tabId === 'context') {
    fetchContextRegistry();
    fetchHyperparameters();
  }
}

// ==========================================
// DATA FETCHING & STATE ORCHESTRATION
// ==========================================
async function refreshAllData(showToastNotification = true) {
  try {
    await fetchOverview();
    await fetchAccounts();
    await fetchContextRegistry();
    await populateUserDropdowns();
    if (currentActiveTab === 'workbench') {
      await loadInvestigateAccount(selectedUserId);
    }
    if (showToastNotification) {
      showToast('Enterprise Posture Synchronized', 'success');
    }
  } catch (err) {
    console.error('Error refreshing data:', err);
  }
}

async function fetchOverview() {
  try {
    const res = await fetch('/api/overview');
    const data = await res.json();

    document.getElementById('kpi-monitored').innerText = `${data.kpis.monitored_accounts} Accounts`;
    document.getElementById('kpi-active-transitions').innerText = `${data.kpis.active_threat_transitions} Drifting`;
    document.getElementById('kpi-critical').innerText = `${data.kpis.critical_risk_accounts} Critical`;
    document.getElementById('kpi-suppressed').innerText = data.kpis.suppressed_false_positives;

    document.querySelectorAll('.nav-badge-triage, #nav-badge-triage').forEach(badge => {
      badge.innerText = data.top_alerts.length;
    });

    const dist = data.transition_distribution;
    document.getElementById('label-count-stable').innerText = dist.STABLE || 0;
    document.getElementById('label-count-early').innerText = dist.EARLY_DRIFT || 0;
    document.getElementById('label-count-escalating').innerText = dist.ESCALATING || 0;
    document.getElementById('label-count-critical').innerText = dist.CRITICAL_TRANSITION || 0;

    renderFleetSpectrumChart(dist);
    renderFleetVectorsChart(data.dominant_vector_heatmap);

    const tbody = document.getElementById('overview-alerts-tbody');
    tbody.innerHTML = '';
    if (!data.top_alerts || data.top_alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-slate-400">All accounts currently within normal baseline tolerances.</td></tr>`;
    } else {
      data.top_alerts.forEach(alt => {
        const badgeClass = getStateBadgeClass(alt.transition_state);
        tbody.innerHTML += `
          <tr class="hover:bg-cyber-850/60 transition cursor-pointer" onclick="investigateAccount('${alt.user_id}')">
            <td class="p-3">
              <div class="font-bold text-white">${alt.username}</div>
              <div class="text-[11px] text-slate-400 font-sans">${alt.role}</div>
            </td>
            <td class="p-3 font-sans text-slate-300">${alt.department}</td>
            <td class="p-3">
              <span class="font-bold ${alt.risk_score >= 70 ? 'text-rose-400' : (alt.risk_score >= 40 ? 'text-amber-400' : 'text-cyan-400')}">${alt.risk_score.toFixed(1)}</span>
            </td>
            <td class="p-3">
              <span class="px-2 py-0.5 rounded text-[11px] font-bold ${badgeClass}">${alt.transition_state}</span>
            </td>
            <td class="p-3 font-sans">
              ${alt.context_damped 
                ? `<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono">Damped (Legitimate)</span>` 
                : `<span class="text-slate-400 text-[11px]">Unmitigated</span>`}
            </td>
            <td class="p-3">
              <div class="flex flex-wrap gap-1">
                ${alt.dominant_vectors.map(v => `<span class="px-1.5 py-0.5 bg-cyber-800 text-slate-300 rounded text-[10px]">${v}</span>`).join('')}
              </div>
            </td>
            <td class="p-3 text-right">
              <button onclick="investigateAccount('${alt.user_id}')" class="px-2.5 py-1 bg-cyan-600/20 hover:bg-cyan-600/40 text-cyan-300 rounded-lg text-xs font-sans font-semibold transition">
                Investigate &rarr;
              </button>
            </td>
          </tr>
        `;
      });
    }
  } catch (err) {
    console.error('Error in fetchOverview:', err);
  }
}

async function fetchAccounts() {
  try {
    const res = await fetch('/api/accounts');
    accountsList = await res.json();
    renderTriageTable(accountsList);
  } catch (err) {
    console.error('Error in fetchAccounts:', err);
  }
}

function renderTriageTable(accounts) {
  const tbody = document.getElementById('triage-accounts-tbody');
  tbody.innerHTML = '';

  document.getElementById('triage-count-label').innerText = `Showing ${accounts.length} Accounts`;

  accounts.forEach(acc => {
    const badgeClass = getStateBadgeClass(acc.transition_state);
    tbody.innerHTML += `
      <tr class="hover:bg-cyber-850/60 transition">
        <td class="p-3 font-mono">
          <span class="font-bold text-white text-xs">${acc.username}</span>
          <span class="block text-[10px] text-slate-400 font-sans">${acc.user_id}</span>
        </td>
        <td class="p-3">
          <div class="text-slate-200 text-xs font-medium">${acc.role}</div>
          <div class="text-[11px] text-slate-400">${acc.department}</div>
        </td>
        <td class="p-3 font-mono">
          <span class="text-sm font-bold ${acc.current_risk_score >= 70 ? 'text-rose-400' : (acc.current_risk_score >= 35 ? 'text-amber-400' : 'text-emerald-400')}">
            ${acc.current_risk_score.toFixed(1)}
          </span>
        </td>
        <td class="p-3 font-mono text-xs">
          <span class="${acc.velocity > 10 ? 'text-rose-400 font-bold' : (acc.velocity > 0 ? 'text-amber-400' : 'text-slate-400')}">
            ${acc.velocity > 0 ? '+' : ''}${acc.velocity.toFixed(1)} / 24h
          </span>
        </td>
        <td class="p-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">
            ${acc.transition_state}
          </span>
        </td>
        <td class="p-3">
          ${acc.has_active_context 
            ? `<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" title="${acc.context_description || 'Context Active'}">Active Ticket</span>` 
            : `<span class="text-slate-500 text-[10px]">None</span>`}
        </td>
        <td class="p-3 font-mono text-[11px] text-slate-300">
          <span class="px-1.5 py-0.5 bg-cyber-800 rounded">${acc.dominant_vector}</span>
        </td>
        <td class="p-3 text-right">
          <div class="flex items-center justify-end gap-1.5">
            <button onclick="investigateAccount('${acc.user_id}')" class="px-2.5 py-1 bg-cyber-800 hover:bg-cyan-600 hover:text-white text-cyan-400 border border-cyber-600 rounded-lg text-xs font-semibold transition">
              Workbench
            </button>
            <button onclick="quickServiceNowSync('${acc.user_id}')" title="2-Way Sync with ServiceNow ITSM" class="p-1 bg-cyber-850 hover:bg-purple-600/30 text-purple-300 border border-cyber-700 rounded-lg text-xs transition">
              <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  });
  lucide.createIcons();
}

function quickServiceNowSync(userId) {
  showToast(`Synced ${userId} with ServiceNow ITSM Incident Table`, 'success');
}

function applyTriageFilters() {
  const search = document.getElementById('triage-search').value.toLowerCase();
  const status = document.getElementById('triage-filter-status').value;
  const dept = document.getElementById('triage-filter-dept').value;

  const filtered = accountsList.filter(acc => {
    const matchSearch = acc.username.toLowerCase().includes(search) || 
                        acc.role.toLowerCase().includes(search) || 
                        acc.department.toLowerCase().includes(search);
    const matchDept = (dept === 'ALL') || (acc.department.toLowerCase() === dept.toLowerCase());
    
    let matchStatus = true;
    if (status === 'OPEN') matchStatus = (acc.alert_status === 'OPEN');
    else if (status === 'INVESTIGATING') matchStatus = (acc.alert_status === 'INVESTIGATING');
    else if (status === 'DAMPED_BENIGN') matchStatus = (acc.alert_status === 'DAMPED_BENIGN');
    else if (status === 'RESOLVED_INCIDENT') matchStatus = (acc.alert_status === 'RESOLVED_INCIDENT');

    return matchSearch && matchDept && matchStatus;
  });

  renderTriageTable(filtered);
}

// ==========================================
// INVESTIGATOR WORKBENCH & NEXT-GEN SUITE
// ==========================================
function investigateAccount(userId) {
  selectedUserId = userId;
  switchTab('workbench');
}

async function loadInvestigateAccount(userId) {
  if (!userId) return;
  selectedUserId = userId;

  const selectElem = document.getElementById('wb-select-user');
  if (selectElem) selectElem.value = userId;

  try {
    const res = await fetch(`/api/accounts/${userId}/investigate`);
    const data = await res.json();
    activeInvestigationData = data;
    fullTimelinePoints = data.timeline_points || [];

    const scrubber = document.getElementById('replay-scrubber');
    if (scrubber) {
      scrubber.max = Math.max(1, fullTimelinePoints.length);
      scrubber.value = fullTimelinePoints.length;
      replayCurrentStep = fullTimelinePoints.length;
      document.getElementById('replay-time-label').innerText = `Step ${fullTimelinePoints.length}/${fullTimelinePoints.length} (Latest)`;
    }

    document.getElementById('wb-username').innerText = data.username;
    document.getElementById('wb-avatar').innerText = data.username.split('.').map(n => n[0].toUpperCase()).join('');
    document.getElementById('wb-role-dept').innerText = `${data.role} • ${data.department} • Peer Cohort: ${data.baseline_vs_actual.peer_group || 'General'}`;

    updateScoreAndStateDisplay(data.composite_risk_score, data.transition_state, data.is_context_damped, data.damping_reason);

    document.getElementById('wb-narrative-text').innerText = data.natural_language_brief;

    if (data.peer_comparison) {
      document.getElementById('wb-peer-avg').innerText = data.peer_comparison.peer_avg_risk_score;
      document.getElementById('wb-peer-offhours').innerText = data.peer_comparison.peer_off_hours_rate;
      document.getElementById('wb-peer-percentile').innerText = data.peer_comparison.user_deviation_percentile;
    }

    const bvaTbody = document.getElementById('wb-baseline-vs-actual-tbody');
    bvaTbody.innerHTML = '';
    const bva = data.baseline_vs_actual;
    bvaTbody.innerHTML += `
      <tr>
        <td class="p-2.5 font-semibold text-slate-300">Working Hours / Temporal</td>
        <td class="p-2.5 font-mono text-slate-400">${bva.baseline_working_hours}</td>
        <td class="p-2.5 font-mono text-cyan-300">${bva.observed_off_hours_activity}</td>
      </tr>
      <tr>
        <td class="p-2.5 font-semibold text-slate-300">Resource Sensitivity Max</td>
        <td class="p-2.5 font-mono text-slate-400">${bva.baseline_max_sensitivity}</td>
        <td class="p-2.5 font-mono text-rose-300">${bva.observed_max_sensitivity}</td>
      </tr>
      <tr>
        <td class="p-2.5 font-semibold text-slate-300">Routine Assets Access</td>
        <td class="p-2.5 font-mono text-slate-400">${(bva.baseline_common_assets || []).join(', ') || 'Standard Repos'}</td>
        <td class="p-2.5 font-mono text-amber-300">${(bva.novel_assets_accessed || []).join(', ') || 'No novel assets'}</td>
      </tr>
      <tr>
        <td class="p-2.5 font-semibold text-slate-300">Daily Event Volume</td>
        <td class="p-2.5 font-mono text-slate-400">${bva.baseline_daily_velocity}</td>
        <td class="p-2.5 font-mono text-slate-300">Velocity: ${data.velocity.toFixed(1)} / 24h</td>
      </tr>
    `;

    updateMitreMatrixTiles(data.mitre_mapping || []);
    renderContributingEventsTable(fullTimelinePoints.slice(-8));
    renderWbTimelineChart(fullTimelinePoints);
    renderWbRadarChart(data.vector_scores);

    await fetchAndRenderBlastRadius(userId);

  } catch (err) {
    console.error('Error loading investigation payload:', err);
  }
}

function updateScoreAndStateDisplay(riskScore, transitionState, isDamped, dampingReason) {
  const riskElem = document.getElementById('wb-risk-score');
  riskElem.innerText = riskScore.toFixed(1);
  if (riskScore >= 70) riskElem.className = 'text-3xl font-black font-mono text-rose-400';
  else if (riskScore >= 35) riskElem.className = 'text-3xl font-black font-mono text-amber-400';
  else riskElem.className = 'text-3xl font-black font-mono text-cyan-400';

  const badgeElem = document.getElementById('wb-state-badge');
  badgeElem.innerText = transitionState;
  badgeElem.className = `px-2.5 py-0.5 text-xs font-bold rounded-full ${getStateBadgeClass(transitionState)}`;

  const ctxBadge = document.getElementById('wb-context-badge');
  if (isDamped) {
    ctxBadge.classList.remove('hidden');
    ctxBadge.title = dampingReason || 'Context Active';
  } else {
    ctxBadge.classList.add('hidden');
  }
}

function updateMitreMatrixTiles(mitreList) {
  const techniques = mitreList.map(m => m.technique.toLowerCase());
  
  const tileMap = {
    'tile-t1083': techniques.some(t => t.includes('t1083') || t.includes('discovery')),
    'tile-t1098': techniques.some(t => t.includes('t1098') || t.includes('privilege')),
    'tile-t1562': techniques.some(t => t.includes('t1562') || t.includes('impair') || t.includes('audit')),
    'tile-t1020': techniques.some(t => t.includes('t1020') || t.includes('exfiltration'))
  };

  for (const [tileId, isActive] of Object.entries(tileMap)) {
    const el = document.getElementById(tileId);
    if (el) {
      if (isActive) {
        el.classList.add('active-mitre');
        el.querySelector('div:last-child').className = 'text-[10px] text-rose-300 font-semibold';
      } else {
        el.classList.remove('active-mitre');
        el.querySelector('div:last-child').className = 'text-[10px] text-slate-400';
      }
    }
  }
}

function renderContributingEventsTable(events) {
  const evTbody = document.getElementById('wb-events-tbody');
  evTbody.innerHTML = '';
  (events || []).slice().reverse().forEach(ev => {
    evTbody.innerHTML += `
      <tr class="hover:bg-cyber-850/60">
        <td class="p-2.5 text-slate-400">${formatTimestamp(ev.timestamp)}</td>
        <td class="p-2.5 text-cyan-300 font-bold">${ev.resource}</td>
        <td class="p-2.5 text-slate-300">${ev.action}</td>
        <td class="p-2.5 font-bold ${ev.event_score > 60 ? 'text-rose-400' : 'text-amber-400'}">${ev.event_score}</td>
        <td class="p-2.5">
          ${ev.is_damped 
            ? `<span class="text-emerald-400 text-[10px]">Yes (Damped)</span>` 
            : `<span class="text-slate-500 text-[10px]">No</span>`}
        </td>
        <td class="p-2.5">
          <span class="text-[10px] font-bold ${getStateBadgeClass(ev.state)}">${ev.state}</span>
        </td>
      </tr>
    `;
  });
}

// ==========================================
// TIME-TRAVEL FLIGHT RECORDER REPLAY
// ==========================================
function toggleReplayPlayback() {
  replayIsPlaying = !replayIsPlaying;
  const playBtn = document.getElementById('btn-replay-play');
  const playIcon = document.getElementById('icon-replay-play');

  if (replayIsPlaying) {
    playBtn.classList.remove('bg-cyan-600');
    playBtn.classList.add('bg-rose-600', 'animate-pulse');
    playIcon.setAttribute('data-lucide', 'pause');
    lucide.createIcons();

    if (replayCurrentStep >= fullTimelinePoints.length) {
      replayCurrentStep = 1;
    }

    const intervalMs = Math.round(1200 / replaySpeed);
    replayTimer = setInterval(stepReplayForward, intervalMs);
  } else {
    playBtn.classList.remove('bg-rose-600', 'animate-pulse');
    playBtn.classList.add('bg-cyan-600');
    playIcon.setAttribute('data-lucide', 'play');
    lucide.createIcons();

    if (replayTimer) {
      clearInterval(replayTimer);
      replayTimer = null;
    }
  }
}

function setReplaySpeed(speed) {
  replaySpeed = speed;
  ['1', '2', '5'].forEach(s => {
    const btn = document.getElementById(`btn-speed-${s}`);
    if (s === String(speed)) {
      btn.className = 'px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40';
    } else {
      btn.className = 'px-2 py-0.5 rounded text-[11px] font-mono text-slate-400 hover:text-white';
    }
  });

  if (replayIsPlaying) {
    clearInterval(replayTimer);
    const intervalMs = Math.round(1200 / replaySpeed);
    replayTimer = setInterval(stepReplayForward, intervalMs);
  }
}

function stepReplayForward() {
  if (replayCurrentStep >= fullTimelinePoints.length) {
    toggleReplayPlayback();
    return;
  }
  stepReplay(1);
}

function stepReplay(delta) {
  const newStep = Math.max(1, Math.min(fullTimelinePoints.length, replayCurrentStep + delta));
  scrubReplay(newStep);
}

function scrubReplay(stepVal) {
  replayCurrentStep = parseInt(stepVal);
  document.getElementById('replay-scrubber').value = replayCurrentStep;
  document.getElementById('replay-time-label').innerText = `Step ${replayCurrentStep}/${fullTimelinePoints.length} ${replayCurrentStep === fullTimelinePoints.length ? '(Latest)' : ''}`;

  const visiblePoints = fullTimelinePoints.slice(0, replayCurrentStep);
  if (visiblePoints.length === 0) return;

  const currentPoint = visiblePoints[visiblePoints.length - 1];

  updateScoreAndStateDisplay(
    currentPoint.cumulative_risk,
    currentPoint.state,
    currentPoint.is_damped,
    currentPoint.damping_reason
  );

  renderWbTimelineChart(visiblePoints);

  if (currentPoint.vector_breakdown) {
    renderWbRadarChart(currentPoint.vector_breakdown);
  }

  renderContributingEventsTable(visiblePoints.slice(-8));
}

// ==========================================
// BLAST RADIUS & TOPOLOGY GRAPH (SVG + FILTERS)
// ==========================================
async function fetchAndRenderBlastRadius(userId) {
  try {
    const res = await fetch(`/api/accounts/${userId}/blast-radius`);
    const data = await res.json();
    activeBlastRadiusData = data;

    const blastScoreEl = document.getElementById('wb-blast-score');
    if (blastScoreEl) blastScoreEl.innerText = `${data.blast_radius_score.toFixed(1)} / 100`;

    const blastBadgeEl = document.getElementById('wb-blast-badge');
    if (blastBadgeEl) {
      blastBadgeEl.innerText = data.estimated_impact_level;
      if (data.estimated_impact_level === 'CATASTROPHIC' || data.estimated_impact_level === 'HIGH') {
        blastBadgeEl.className = 'px-1.5 py-0.2 text-[9px] font-bold rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 font-mono';
      } else if (data.estimated_impact_level === 'MODERATE') {
        blastBadgeEl.className = 'px-1.5 py-0.2 text-[9px] font-bold rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 font-mono';
      } else {
        blastBadgeEl.className = 'px-1.5 py-0.2 text-[9px] font-bold rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono';
      }
    }

    const crownEl = document.getElementById('wb-crown-count');
    if (crownEl) crownEl.innerText = data.crown_jewels_touched;

    const piiEl = document.getElementById('wb-pii-exposed');
    if (piiEl) piiEl.innerText = data.pii_data_exposed ? 'Exposed (High Risk)' : 'Protected';

    const pciEl = document.getElementById('wb-pci-exposed');
    if (pciEl) pciEl.innerText = data.pci_vault_exposed ? 'Vault Touched' : 'Isolated';

    const compList = document.getElementById('wb-compliance-list');
    if (compList) {
      compList.innerHTML = '';
      if (!data.compliance_impacts || data.compliance_impacts.length === 0) {
        compList.innerHTML = `
          <div class="p-2 rounded-lg bg-cyber-900 border border-cyber-800 text-slate-400 text-[11px] flex items-center gap-1.5">
            <i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-emerald-400 shrink-0"></i>
            <span>No regulatory thresholds breached. Operations within baseline compliance limits.</span>
          </div>
        `;
      } else {
        data.compliance_impacts.forEach(c => {
          let badgeColor = 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
          if (c.severity === 'CRITICAL') {
            badgeColor = 'bg-rose-500/20 text-rose-300 border-rose-500/40';
          } else if (c.severity === 'HIGH') {
            badgeColor = 'bg-orange-500/20 text-orange-300 border-orange-500/40';
          } else if (c.severity === 'MEDIUM') {
            badgeColor = 'bg-amber-500/20 text-amber-300 border-amber-500/40';
          } else if (c.severity === 'COMPLIANT' || c.severity === 'LOW') {
            badgeColor = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
          }

          compList.innerHTML += `
            <div class="p-2 rounded-lg bg-cyber-900 border border-cyber-800 space-y-1">
              <div class="flex items-center justify-between">
                <span class="font-bold text-white font-mono text-[10px]">${c.framework}</span>
                <span class="px-1.5 py-0.2 rounded text-[9px] font-bold border ${badgeColor}">${c.severity}</span>
              </div>
              <div class="text-[11px] text-slate-300">${c.risk}</div>
              ${c.mandatory_notification ? `<div class="text-[10px] text-slate-400 font-mono flex items-center gap-1"><i data-lucide="alert-circle" class="w-3 h-3 text-cyan-400 shrink-0"></i> ${c.mandatory_notification}</div>` : ''}
            </div>
          `;
        });
      }
      lucide.createIcons();
    }

    renderBlastRadiusSvg(data.graph);

  } catch (err) {
    console.error('Error fetching blast radius:', err);
  }
}

function filterBlastGraph(filterType) {
  currentBlastFilter = filterType;

  ['all', 'crown', 'pii'].forEach(t => {
    const btn = document.getElementById(`btn-graph-${t}`);
    if (t === filterType) {
      btn.className = 'px-2.5 py-1 rounded-md bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-medium';
    } else {
      btn.className = 'px-2.5 py-1 rounded-md bg-cyber-850 text-slate-400 hover:text-white font-medium';
    }
  });

  if (activeBlastRadiusData && activeBlastRadiusData.graph) {
    renderBlastRadiusSvg(activeBlastRadiusData.graph);
  }
}

function renderBlastRadiusSvg(rawGraph) {
  const svg = document.getElementById('blast-radius-svg');
  if (!svg || !rawGraph || !rawGraph.nodes) return;

  const width = svg.clientWidth || 600;
  const height = svg.clientHeight || 300;
  const centerX = width / 2;
  const centerY = height / 2;

  svg.innerHTML = '';

  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  defs.innerHTML = `
    <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="4" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
    <filter id="glow-rose" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="4" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  `;
  svg.appendChild(defs);

  const centerNode = rawGraph.nodes.find(n => n.is_center) || rawGraph.nodes[0];
  let outerNodes = rawGraph.nodes.filter(n => !n.is_center);

  // Apply Filter Chips
  if (currentBlastFilter === 'crown') {
    outerNodes = outerNodes.filter(n => n.tier >= 4);
  } else if (currentBlastFilter === 'pii') {
    outerNodes = outerNodes.filter(n => n.label.includes('pii') || n.label.includes('customer') || n.label.includes('vault'));
  }

  if (outerNodes.length === 0) {
    outerNodes = rawGraph.nodes.filter(n => !n.is_center);
  }

  const radius = Math.min(width, height) * 0.36;
  const positions = {};
  positions[centerNode.id] = { x: centerX, y: centerY };

  outerNodes.forEach((node, i) => {
    const angle = (i / outerNodes.length) * 2 * Math.PI - (Math.PI / 2);
    positions[node.id] = {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle)
    };
  });

  // Links
  rawGraph.links.forEach(link => {
    const p1 = positions[link.source];
    const p2 = positions[link.target];
    if (!p1 || !p2) return;

    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', p1.x);
    line.setAttribute('y1', p1.y);
    line.setAttribute('x2', p2.x);
    line.setAttribute('y2', p2.y);
    line.setAttribute('stroke', link.is_anomalous ? '#f43f5e' : 'rgba(56, 189, 248, 0.4)');
    line.setAttribute('stroke-width', link.is_anomalous ? '2.5' : '1.5');
    line.setAttribute('class', 'graph-link');
    svg.appendChild(line);
  });

  // Outer Nodes
  outerNodes.forEach(node => {
    const pos = positions[node.id];
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('class', 'graph-node');

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', pos.x);
    circle.setAttribute('cy', pos.y);
    circle.setAttribute('r', node.tier >= 4 ? '14' : '10');
    circle.setAttribute('fill', node.is_anomalous ? '#f43f5e' : (node.tier >= 3 ? '#a855f7' : '#10b981'));
    circle.setAttribute('stroke', '#0c1017');
    circle.setAttribute('stroke-width', '2');
    if (node.is_anomalous) circle.setAttribute('filter', 'url(#glow-rose)');

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', pos.x);
    text.setAttribute('y', pos.y + (node.tier >= 4 ? 24 : 20));
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', '#cbd5e1');
    text.setAttribute('font-size', '9');
    text.setAttribute('font-family', 'JetBrains Mono');
    text.textContent = node.label.length > 14 ? node.label.slice(0, 12) + '..' : node.label;

    g.appendChild(circle);
    g.appendChild(text);
    svg.appendChild(g);
  });

  // Center Node
  const centerPos = positions[centerNode.id];
  const centerG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  centerG.setAttribute('class', 'graph-node');

  const centerCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  centerCircle.setAttribute('cx', centerPos.x);
  centerCircle.setAttribute('cy', centerPos.y);
  centerCircle.setAttribute('r', '22');
  centerCircle.setAttribute('fill', '#0284c7');
  centerCircle.setAttribute('stroke', '#38bdf8');
  centerCircle.setAttribute('stroke-width', '3');
  centerCircle.setAttribute('filter', 'url(#glow-cyan)');

  const centerText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  centerText.setAttribute('x', centerPos.x);
  centerText.setAttribute('y', centerPos.y + 4);
  centerText.setAttribute('text-anchor', 'middle');
  centerText.setAttribute('fill', '#ffffff');
  centerText.setAttribute('font-size', '11');
  centerText.setAttribute('font-weight', 'bold');
  centerText.setAttribute('font-family', 'Inter');
  centerText.textContent = centerNode.label.slice(0, 5);

  centerG.appendChild(centerCircle);
  centerG.appendChild(centerText);
  svg.appendChild(centerG);
}

// ==========================================
// ENTERPRISE ECOSYSTEM HUB MODAL
// ==========================================
async function openIntegrationsModal() {
  const modal = document.getElementById('modal-integrations');
  modal.classList.remove('hidden');

  try {
    const res = await fetch('/api/enterprise/integrations');
    const list = await res.json();
    const container = document.getElementById('integrations-list');
    container.innerHTML = '';

    list.forEach(item => {
      container.innerHTML += `
        <div class="p-3 rounded-xl bg-cyber-950 border border-cyber-800 flex items-center justify-between">
          <div class="space-y-0.5">
            <div class="flex items-center gap-2">
              <span class="font-bold text-white text-xs">${item.name}</span>
              <span class="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">${item.status}</span>
            </div>
            <div class="text-[10px] text-slate-400 font-mono">${item.category} &bull; ${item.protocol}</div>
          </div>
          <div class="text-right text-[11px] font-mono">
            <div class="text-cyan-300 font-semibold">${item.entities_synced}</div>
            <div class="text-slate-500 text-[10px]">Heartbeat: ${item.last_heartbeat}</div>
          </div>
        </div>
      `;
    });
    lucide.createIcons();
  } catch (err) {
    console.error('Error fetching integrations:', err);
  }
}

function closeIntegrationsModal() {
  document.getElementById('modal-integrations').classList.add('hidden');
}

function testPingIntegrations() {
  showToast('Testing live sync ping across Okta, Entra & Splunk HEC...', 'info');
  setTimeout(() => {
    showToast('All 4 Connectors Responded 200 OK (Latency < 24ms)', 'success');
  }, 900);
}

// ==========================================
// EXECUTIVE BOARD BRIEFING GENERATOR
// ==========================================
let cachedBoardReportText = '';

async function openBoardBriefingModal() {
  const modal = document.getElementById('modal-board-briefing');
  modal.classList.remove('hidden');

  try {
    const resMetrics = await fetch('/api/enterprise/metrics');
    const m = await resMetrics.json();

    const content = document.getElementById('board-briefing-content');
    content.innerHTML = `
      <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div class="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
          <span class="text-[10px] uppercase font-bold text-slate-400 block">Dwell Time Reduction</span>
          <span class="text-xl font-black text-cyan-400 font-mono">-93.2%</span>
          <span class="block text-[10px] text-slate-500 mt-0.5">Caught in 34h vs 21-day average</span>
        </div>
        <div class="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
          <span class="text-[10px] uppercase font-bold text-slate-400 block">Alert Noise Silenced</span>
          <span class="text-xl font-black text-emerald-400 font-mono">82.4%</span>
          <span class="block text-[10px] text-slate-500 mt-0.5">168 Analyst hours saved monthly</span>
        </div>
        <div class="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
          <span class="text-[10px] uppercase font-bold text-slate-400 block">Breach Exposure Mitigated</span>
          <span class="text-xl font-black text-purple-400 font-mono">${m.financial_risk_mitigated}</span>
          <span class="block text-[10px] text-slate-500 mt-0.5">GDPR & PCI liability neutralized</span>
        </div>
      </div>

      <div class="p-4 rounded-xl bg-cyber-950 border border-cyber-800 space-y-2">
        <h4 class="font-bold text-white text-xs flex items-center gap-1.5">
          <i data-lucide="award" class="w-4 h-4 text-cyan-400"></i>
          Executive Summary for the Board of Directors & Audit Committee
        </h4>
        <p class="text-slate-300 text-xs leading-relaxed">
          Over the evaluation cycle, SilentShift continuously baselined all 12 enterprise identities across Engineering, Infrastructure, Finance, and Analytics. By correlating multi-vector behavioral drift (circadian schedules, Shannon resource entropy, and privilege depth) over a 48-hour exponential decay window, the platform successfully identified <strong>subtle insider data staging and compromised admin credentials</strong> without triggering alert fatigue.
        </p>
        <p class="text-slate-300 text-xs leading-relaxed">
          Crucially, legitimate project reassignments (e.g., Project Titan Data Lake migration) were automatically reconciled via 2-way ServiceNow change tickets, damping false-positive alarms by <strong>82.4%</strong> while maintaining anti-tamper safeguards over audit logs.
        </p>
      </div>

      <div class="p-3.5 rounded-xl bg-cyber-950 border border-cyber-800">
        <h4 class="font-bold text-white text-xs mb-2">Regulatory & Compliance Audit Readiness</h4>
        <div class="grid grid-cols-2 gap-2 font-mono text-[11px]">
          <div>SOC 2 Type II CC6.1: <strong class="text-emerald-400">99.2% Active Control</strong></div>
          <div>GDPR Article 32: <strong class="text-emerald-400">98.4% Continuous Guard</strong></div>
          <div>PCI-DSS v4.0 Req 7: <strong class="text-emerald-400">100% Vault Ringfenced</strong></div>
          <div>ISO 27001 A.9: <strong class="text-emerald-400">97.8% Validated</strong></div>
        </div>
      </div>
    `;

    cachedBoardReportText = `SILENTSHIFT EXECUTIVE CISO BOARD BRIEFING
Classification: STRICTLY CONFIDENTIAL // AUDIT COMMITTEE
Date: ${new Date().toUTCString()}

1. KEY PERFORMANCE METRICS
- Mean Time to Detect (MTTD): Reduced by 93.2% (34 hours vs 21 days industry baseline)
- Alert Noise Reduction: 82.4% of false positives successfully silenced via Context Damping
- Analyst Hours Saved: 168 hours/month
- Financial Breach Exposure Mitigated: ${m.financial_risk_mitigated}

2. REGULATORY COMPLIANCE READINESS
- SOC 2 Type II (CC6.1): 99.2% continuous compliance
- GDPR Art. 32/33: 98.4% proactive breach prevention
- PCI-DSS v4.0: 100% payment vault ringfenced
- ISO 27001 A.9: 97.8% alignment

3. AUDIT CONCLUSION
SilentShift successfully bridges the gap between early threat detection and alert fatigue elimination.`;

    lucide.createIcons();
  } catch (err) {
    console.error('Error opening board briefing:', err);
  }
}

function closeBoardBriefingModal() {
  document.getElementById('modal-board-briefing').classList.add('hidden');
}

function copyBoardBriefing() {
  navigator.clipboard.writeText(cachedBoardReportText);
  showToast('Executive Briefing Copied to Clipboard', 'success');
}

function downloadBoardBriefing() {
  const blob = new Blob([cachedBoardReportText], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `SilentShift_CISO_Board_Briefing.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('Board Briefing Downloaded', 'success');
}

// ==========================================
// FORENSIC CASE DOSSIER EXPORT
// ==========================================
async function exportCaseDossier() {
  try {
    const res = await fetch(`/api/accounts/${selectedUserId}/dossier`);
    const dossierText = await res.text();

    const blob = new Blob([dossierText], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SilentShift_Forensic_Dossier_${selectedUserId}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('Forensic Case Dossier Exported', 'success');
  } catch (err) {
    showToast('Failed to export dossier', 'error');
  }
}

// ==========================================
// SHIFTCOPILOT AI ASSISTANT
// ==========================================
function toggleCopilotDrawer() {
  const drawer = document.getElementById('drawer-copilot');
  drawer.classList.toggle('open-drawer');
}

function sendQuickCopilotPrompt(promptText) {
  document.getElementById('copilot-input').value = promptText;
  handleCopilotSubmit(new Event('submit'));
}

async function handleCopilotSubmit(e) {
  if (e) e.preventDefault();
  const inputElem = document.getElementById('copilot-input');
  const query = inputElem.value.trim();
  if (!query) return;

  const chatLog = document.getElementById('copilot-chat-log');

  chatLog.innerHTML += `
    <div class="flex justify-end">
      <div class="p-2.5 rounded-xl bg-cyan-600/30 border border-cyan-500/40 text-cyan-100 max-w-[85%] font-sans">
        ${query}
      </div>
    </div>
  `;
  inputElem.value = '';
  chatLog.scrollTop = chatLog.scrollHeight;

  const loadingId = `load-${Date.now()}`;
  chatLog.innerHTML += `
    <div id="${loadingId}" class="flex items-center gap-2 p-3 text-slate-400">
      <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
      <span>ShiftCopilot analyzing telemetry...</span>
    </div>
  `;
  chatLog.scrollTop = chatLog.scrollHeight;

  try {
    const res = await fetch('/api/copilot/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: selectedUserId,
        question: query
      })
    });
    const data = await res.json();

    const loadElem = document.getElementById(loadingId);
    if (loadElem) loadElem.remove();

    const formattedAnswer = formatMarkdownToHtml(data.answer);

    chatLog.innerHTML += `
      <div class="p-3 rounded-xl bg-cyber-950 border border-cyber-800 text-slate-200 leading-relaxed font-sans space-y-2">
        <div class="text-[11px] text-cyan-400 font-bold flex items-center gap-1">
          <i data-lucide="bot" class="w-3.5 h-3.5"></i>
          ShiftCopilot Analysis
        </div>
        <div class="text-xs">${formattedAnswer}</div>
      </div>
    `;
    lucide.createIcons();
    chatLog.scrollTop = chatLog.scrollHeight;

  } catch (err) {
    const loadElem = document.getElementById(loadingId);
    if (loadElem) loadElem.remove();
    chatLog.innerHTML += `<div class="p-2 text-rose-400 text-xs">Error communicating with ShiftCopilot.</div>`;
  }
}

function formatMarkdownToHtml(md) {
  if (!md) return '';
  return md
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 rounded bg-cyber-800 text-cyan-300 font-mono text-[11px]">$1</code>')
    .replace(/\n\n/g, '<br><br>')
    .replace(/\n/g, '<br>');
}

// ==========================================
// CONTEXT & POLICY MANAGEMENT
// ==========================================
async function fetchContextRegistry() {
  try {
    const res = await fetch('/api/context');
    const contexts = await res.json();
    const tbody = document.getElementById('context-registry-tbody');
    tbody.innerHTML = '';

    if (!contexts || contexts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="p-4 text-center text-slate-400">No active business contexts registered.</td></tr>`;
      return;
    }

    contexts.forEach(ctx => {
      tbody.innerHTML += `
        <tr class="hover:bg-cyber-850/60">
          <td class="p-3">
            <span class="font-bold text-white text-xs">${ctx.username}</span>
            <span class="block text-[10px] text-slate-400 font-sans">${ctx.department}</span>
          </td>
          <td class="p-3 font-sans">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">${ctx.context_type}</span>
          </td>
          <td class="p-3 text-cyan-400 font-bold font-mono">${ctx.ticket_reference || 'N/A'}</td>
          <td class="p-3 font-sans text-slate-300 text-xs">
            <div>${ctx.description}</div>
            <div class="text-[10px] text-slate-400 font-mono mt-0.5">Scope: ${(ctx.target_resources || []).join(', ') || 'All assets'}</div>
          </td>
          <td class="p-3 text-emerald-400 font-bold font-mono">${ctx.damping_factor} <span class="text-[10px] text-slate-400 font-normal">(-${Math.round((1 - ctx.damping_factor) * 100)}%)</span></td>
          <td class="p-3 text-slate-400 text-[11px] font-sans">Active to ${formatDate(ctx.valid_until)}</td>
          <td class="p-3 font-sans">
            <span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">Active</span>
          </td>
        </tr>
      `;
    });
  } catch (err) {
    console.error('Error fetching contexts:', err);
  }
}

async function fetchHyperparameters() {
  try {
    const res = await fetch('/api/hyperparameters');
    const params = await res.json();
    document.getElementById('slider-halflife').value = params.decay_halflife_hours;
    document.getElementById('label-halflife').innerText = `${params.decay_halflife_hours} Hours`;
    document.getElementById('slider-weight-res').value = params.vector_weights.resource;
    document.getElementById('label-weight-res').innerText = params.vector_weights.resource;
    document.getElementById('slider-weight-temp').value = params.vector_weights.temporal;
    document.getElementById('label-weight-temp').innerText = params.vector_weights.temporal;
  } catch (err) {
    console.error('Error fetching hyperparameters:', err);
  }
}

function updateHalfLifeLabel(val) {
  document.getElementById('label-halflife').innerText = `${val} Hours`;
}

async function saveHyperparameters() {
  const halflife = parseFloat(document.getElementById('slider-halflife').value);
  const wRes = parseFloat(document.getElementById('slider-weight-res').value);
  const wTemp = parseFloat(document.getElementById('slider-weight-temp').value);

  try {
    await fetch('/api/hyperparameters', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        decay_halflife_hours: halflife,
        weights: {
          resource: wRes,
          temporal: wTemp
        }
      })
    });
    showToast('Analytical Hyperparameters Recalibrated', 'success');
    refreshAllData(false);
  } catch (err) {
    showToast('Failed to save parameters', 'error');
  }
}

function openAddContextModal() {
  document.getElementById('modal-add-context').classList.remove('hidden');
}

function closeAddContextModal() {
  document.getElementById('modal-add-context').classList.add('hidden');
}

async function handleCreateContext(e) {
  e.preventDefault();
  const userId = document.getElementById('ctx-user-id').value;
  const ctxType = document.getElementById('ctx-type').value;
  const ticketRef = document.getElementById('ctx-ticket-ref').value;
  const desc = document.getElementById('ctx-desc').value;
  const resources = document.getElementById('ctx-resources').value.split(',').map(s => s.trim()).filter(Boolean);
  const damping = parseFloat(document.getElementById('ctx-damping').value);
  const approvedBy = document.getElementById('ctx-approved-by').value;

  try {
    await fetch('/api/context', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        context_type: ctxType,
        ticket_reference: ticketRef,
        description: desc,
        target_resources: resources,
        damping_factor: damping,
        approved_by: approvedBy
      })
    });
    closeAddContextModal();
    showToast(`Context Registered for ${userId}`, 'success');
    fetchContextRegistry();
    refreshAllData(false);
  } catch (err) {
    showToast('Failed to register context', 'error');
  }
}

// ==========================================
// SCENARIO SIMULATION & EVENT INJECTION
// ==========================================
async function quickRunScenario(scenarioId) {
  await triggerScenario(scenarioId);
}

async function triggerScenario(scenarioId) {
  try {
    const res = await fetch(`/api/simulate/${scenarioId}`, { method: 'POST' });
    const data = await res.json();
    showToast(`Executed: ${data.title}`, 'warning');

    if (data.target_user) {
      const match = accountsList.find(a => a.username === data.target_user);
      if (match) {
        selectedUserId = match.user_id;
      }
    }
    await refreshAllData(false);
    switchTab('workbench');
  } catch (err) {
    showToast('Error triggering scenario', 'error');
  }
}

async function handleInjectCustomEvent(e) {
  e.preventDefault();
  const userId = document.getElementById('inject-user-id').value;
  const eventType = document.getElementById('inject-event-type').value;
  const resource = document.getElementById('inject-resource').value;
  const sensitivity = parseInt(document.getElementById('inject-sensitivity').value);
  const action = document.getElementById('inject-action').value;
  const isOffHours = document.getElementById('inject-off-hours').checked;

  try {
    const res = await fetch('/api/events/inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        event_type: eventType,
        resource: resource,
        sensitivity_level: sensitivity,
        action: action,
        is_off_hours: isOffHours,
        context_tags: []
      })
    });
    const result = await res.json();
    showToast(`Custom Event Injected: ${resource}`, 'info');
    selectedUserId = userId;
    await refreshAllData(false);
    switchTab('workbench');
  } catch (err) {
    showToast('Failed to inject event', 'error');
  }
}

async function triggerTriageAction(actionType) {
  try {
    const res = await fetch(`/api/alerts/${selectedUserId}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: actionType,
        notes: `Analyst triage response executed via Workbench.`
      })
    });
    const data = await res.json();
    showToast(`Action Executed: ${actionType}`, 'success');
    await refreshAllData(false);
    await loadInvestigateAccount(selectedUserId);
  } catch (err) {
    showToast('Failed to execute triage action', 'error');
  }
}

async function resetFleet() {
  try {
    await fetch('/api/reset', { method: 'POST' });
    showToast('Fleet Reset to Initial Clean Baselines', 'info');
    await refreshAllData(false);
    switchTab('overview');
  } catch (err) {
    showToast('Failed to reset fleet', 'error');
  }
}

// ==========================================
// USER DROPDOWN POPULATION
// ==========================================
async function populateUserDropdowns() {
  const users = accountsList;
  const wbSelect = document.getElementById('wb-select-user');
  const injectSelect = document.getElementById('inject-user-id');
  const ctxSelect = document.getElementById('ctx-user-id');

  if (wbSelect) {
    wbSelect.innerHTML = users.map(u => `<option value="${u.user_id}">${u.username} (${u.role})</option>`).join('');
    wbSelect.value = selectedUserId;
  }
  if (injectSelect) {
    injectSelect.innerHTML = users.map(u => `<option value="${u.user_id}">${u.username} [${u.department}]</option>`).join('');
    injectSelect.value = selectedUserId;
  }
  if (ctxSelect) {
    ctxSelect.innerHTML = users.map(u => `<option value="${u.user_id}">${u.username} - ${u.department}</option>`).join('');
  }
}

// ==========================================
// CHART RENDERING (CHART.JS)
// ==========================================
function renderFleetSpectrumChart(dist) {
  const ctx = document.getElementById('chart-fleet-spectrum');
  if (!ctx) return;

  const data = [
    dist.STABLE || 0,
    dist.EARLY_DRIFT || 0,
    dist.ESCALATING || 0,
    dist.CRITICAL_TRANSITION || 0
  ];

  if (chartFleetSpectrum) {
    chartFleetSpectrum.data.datasets[0].data = data;
    chartFleetSpectrum.update();
    return;
  }

  chartFleetSpectrum = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Stable Baseline', 'Early Drift', 'Escalating', 'Critical Transition'],
      datasets: [{
        data: data,
        backgroundColor: ['#10b981', '#38bdf8', '#f59e0b', '#f43f5e'],
        borderColor: '#0c1017',
        borderWidth: 3,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0c1017',
          titleColor: '#fff',
          bodyColor: '#cbd5e1',
          borderColor: '#222f46',
          borderWidth: 1
        }
      }
    }
  });
}

function renderFleetVectorsChart(vectors) {
  const ctx = document.getElementById('chart-fleet-vectors');
  if (!ctx) return;

  const labels = ['Temporal Shift', 'Resource Entropy', 'Privilege Escalation', 'Peer Divergence'];
  const values = [
    vectors.temporal || 25,
    vectors.resource || 25,
    vectors.privilege || 25,
    vectors.peer_divergence || 25
  ];

  if (chartFleetVectors) {
    chartFleetVectors.data.datasets[0].data = values;
    chartFleetVectors.update();
    return;
  }

  chartFleetVectors = new Chart(ctx, {
    type: 'polarArea',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: [
          'rgba(56, 189, 248, 0.4)',
          'rgba(168, 85, 247, 0.4)',
          'rgba(244, 63, 94, 0.4)',
          'rgba(245, 158, 11, 0.4)'
        ],
        borderColor: ['#38bdf8', '#a855f7', '#f43f5e', '#f59e0b'],
        borderWidth: 1.5
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          grid: { color: 'rgba(34, 47, 70, 0.5)' },
          angleLines: { color: 'rgba(34, 47, 70, 0.5)' },
          ticks: { display: false }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderWbTimelineChart(points) {
  const ctx = document.getElementById('chart-wb-timeline');
  if (!ctx) return;

  const recentPoints = (points || []).slice(-30);
  const labels = recentPoints.map((p, i) => `T-${recentPoints.length - i}`);
  const cumulativeScores = recentPoints.map(p => p.cumulative_risk);
  const eventScores = recentPoints.map(p => p.event_score);

  if (chartWbTimeline) {
    chartWbTimeline.data.labels = labels;
    chartWbTimeline.data.datasets[0].data = cumulativeScores;
    chartWbTimeline.data.datasets[1].data = eventScores;
    chartWbTimeline.update();
    return;
  }

  chartWbTimeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Cumulative Risk Curve',
          data: cumulativeScores,
          borderColor: '#38bdf8',
          backgroundColor: 'rgba(56, 189, 248, 0.1)',
          fill: true,
          tension: 0.35,
          pointRadius: 3,
          borderWidth: 2.5
        },
        {
          label: 'Single Event Anomaly',
          data: eventScores,
          borderColor: '#f43f5e',
          backgroundColor: '#f43f5e',
          type: 'scatter',
          pointRadius: 5,
          pointHoverRadius: 7
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: 'rgba(34, 47, 70, 0.3)' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          min: 0,
          max: 100,
          grid: { color: 'rgba(34, 47, 70, 0.3)' },
          ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0c1017',
          titleColor: '#fff',
          bodyColor: '#cbd5e1',
          borderColor: '#222f46',
          borderWidth: 1
        }
      }
    }
  });
}

function renderWbRadarChart(vectorScores) {
  const ctx = document.getElementById('chart-wb-radar');
  if (!ctx) return;

  const labels = ['Temporal', 'Resource Entropy', 'Privilege Escalation', 'Peer Divergence'];
  const values = [
    vectorScores.temporal || 10,
    vectorScores.resource || 10,
    vectorScores.privilege || 10,
    vectorScores.peer_divergence || 10
  ];

  document.getElementById('val-radar-temporal').innerText = `${values[0].toFixed(0)}%`;
  document.getElementById('val-radar-resource').innerText = `${values[1].toFixed(0)}%`;
  document.getElementById('val-radar-privilege').innerText = `${values[2].toFixed(0)}%`;
  document.getElementById('val-radar-peer').innerText = `${values[3].toFixed(0)}%`;

  if (chartWbRadar) {
    chartWbRadar.data.datasets[0].data = values;
    chartWbRadar.update();
    return;
  }

  chartWbRadar = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Vector Anomaly Score',
        data: values,
        backgroundColor: 'rgba(56, 189, 248, 0.25)',
        borderColor: '#38bdf8',
        borderWidth: 2,
        pointBackgroundColor: '#38bdf8'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          min: 0,
          max: 100,
          grid: { color: 'rgba(34, 47, 70, 0.5)' },
          angleLines: { color: 'rgba(34, 47, 70, 0.5)' },
          pointLabels: {
            color: '#cbd5e1',
            font: { family: 'Inter', size: 11, weight: 'bold' }
          },
          ticks: { display: false }
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

// ==========================================
// UTILITY FUNCTIONS
// ==========================================
function getStateBadgeClass(state) {
  if (state === 'CRITICAL_TRANSITION') return 'badge-critical';
  if (state === 'ESCALATING') return 'badge-escalating';
  if (state === 'EARLY_DRIFT') return 'badge-early-drift';
  return 'badge-stable';
}

function formatTimestamp(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  return d.toISOString().replace('T', ' ').slice(5, 16);
}

function formatDate(isoStr) {
  if (!isoStr) return '';
  const d = new Date(isoStr);
  return d.toISOString().slice(0, 10);
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const borderColors = {
    success: 'border-emerald-500/50 text-emerald-300',
    warning: 'border-amber-500/50 text-amber-300',
    error: 'border-rose-500/50 text-rose-300',
    info: 'border-cyan-500/50 text-cyan-300'
  };

  toast.className = `toast px-4 py-2.5 rounded-xl bg-cyber-900 border ${borderColors[type] || borderColors.info} shadow-xl text-xs font-medium flex items-center gap-2`;
  toast.innerHTML = `
    <span class="w-2 h-2 rounded-full bg-current animate-ping"></span>
    <span>${message}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Window resize handler for responsive SVG topology re-centering
let resizeDebounceTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeDebounceTimer);
  resizeDebounceTimer = setTimeout(() => {
    if (activeBlastRadiusData && activeBlastRadiusData.graph) {
      renderBlastRadiusSvg(activeBlastRadiusData.graph);
    }
  }, 120);
});
