/**
 * Explainable Adaptive IDS - Frontend Client Controller
 * Communicates with local loopback FastAPI backend using authenticated JSON requests.
 */

// Extract session token from URL parameters if provided
const urlParams = new URLSearchParams(window.location.search);
let sessionToken = urlParams.get("token") || "";

// State
let currentTab = "overview";
let pollingTimer = null;

// DOM Elements
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const modePill = document.getElementById("monitoring-mode-pill");
const statTotalFlows = document.getElementById("stat-total-flows");
const statAlerts = document.getElementById("stat-alerts");
const statNormal = document.getElementById("stat-normal");
const statDrift = document.getElementById("stat-drift");
const navAlertCount = document.getElementById("nav-alert-count");
const btnStart = document.getElementById("btn-start-monitoring");
const btnStop = document.getElementById("btn-stop-monitoring");
const selectMode = document.getElementById("select-mode");
const selectInterface = document.getElementById("select-interface");

/**
 * Perform authenticated request to local FastAPI backend.
 */
async function apiFetch(endpoint, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  if (sessionToken) {
    headers["X-Session-Token"] = sessionToken;
  }
  headers["Content-Type"] = "application/json";

  const response = await fetch(endpoint, {
    ...options,
    headers
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `HTTP Error ${response.status}`);
  }

  return response.json();
}

/**
 * Tab Navigation Switcher
 */
function switchTab(tabId) {
  currentTab = tabId;

  // Update nav buttons
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });

  // Update tab panes
  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === `tab-${tabId}`);
  });

  // Update topbar title
  const activeBtn = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
  if (activeBtn) {
    document.getElementById("current-tab-title").textContent = activeBtn.textContent.trim();
  }

  // Refresh tab-specific data
  if (tabId === "alerts") {
    loadAlerts();
  } else if (tabId === "history") {
    loadHistory();
  }
}

// Attach tab click listeners
document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

/**
 * Polling System Telemetry & Status
 */
async function refreshStatus() {
  try {
    const data = await apiFetch("/api/status");

    // Update status indicators
    statusDot.className = "dot online";
    statusText.textContent = "Backend Connected";

    // Update metric counters
    if (data.counts) {
      statTotalFlows.textContent = data.counts.total.toLocaleString();
      statAlerts.textContent = data.counts.malicious.toLocaleString();
      statNormal.textContent = data.counts.normal.toLocaleString();
      navAlertCount.textContent = data.counts.malicious;

      const alertPercent = data.counts.total > 0
        ? ((data.counts.malicious / data.counts.total) * 100).toFixed(1)
        : 0;
      document.getElementById("stat-alert-percent").textContent = `${alertPercent}% flagged malicious`;
    }

    // Update Monitoring Pill
    if (data.monitoring_active) {
      modePill.className = "mode-pill running";
      modePill.textContent = `RUNNING: ${data.monitoring_mode.toUpperCase()}`;
      btnStart.disabled = true;
      btnStop.disabled = false;
    } else {
      modePill.className = "mode-pill idle";
      modePill.textContent = "STATUS: IDLE";
      btnStart.disabled = false;
      btnStop.disabled = true;
    }

    // Update Drift Status
    statDrift.textContent = data.drift_status || "STABLE";

  } catch (err) {
    statusDot.className = "dot";
    statusText.textContent = "Backend Disconnected";
    console.error("Telemetry refresh error:", err);
  }
}

/**
 * Ingestion Controls
 */
btnStart.addEventListener("click", async () => {
  const mode = selectMode.value;
  const iface = selectInterface.value;

  try {
    btnStart.disabled = true;
    await apiFetch("/api/monitoring/start", {
      method: "POST",
      body: JSON.stringify({ mode, interface: iface })
    });
    await refreshStatus();
  } catch (err) {
    alert(`Failed to start monitoring: ${err.message}`);
    btnStart.disabled = false;
  }
});

btnStop.addEventListener("click", async () => {
  try {
    btnStop.disabled = true;
    await apiFetch("/api/monitoring/stop", {
      method: "POST"
    });
    await refreshStatus();
  } catch (err) {
    alert(`Failed to stop monitoring: ${err.message}`);
    btnStop.disabled = false;
  }
});

/**
 * Fetch and Render Alerts
 */
async function loadAlerts() {
  try {
    const data = await apiFetch("/api/events?is_malicious=1&limit=50");
    const tbody = document.getElementById("alerts-table-body");
    const overviewBody = document.getElementById("overview-alerts-body");

    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No threat alerts recorded yet.</td></tr>`;
      overviewBody.innerHTML = `<tr class="empty-row"><td colspan="7">No threat alerts recorded yet.</td></tr>`;
      return;
    }

    const rowsHtml = data.events.map(ev => `
      <tr>
        <td>#${ev.id}</td>
        <td>${ev.timestamp}</td>
        <td>${ev.src_ip}:${ev.src_port}</td>
        <td>${ev.dst_ip}:${ev.dst_port}</td>
        <td><strong>${ev.attack_category}</strong></td>
        <td><span class="badge" style="background:#da3633">${ev.severity}</span></td>
        <td>${(ev.confidence_score * 100).toFixed(1)}%</td>
        <td><button class="btn btn-secondary btn-sm" onclick="inspectEvent(${ev.id})">Inspect XAI</button></td>
      </tr>
    `).join("");

    tbody.innerHTML = rowsHtml;
    overviewBody.innerHTML = data.events.slice(0, 5).map(ev => `
      <tr>
        <td>${ev.timestamp}</td>
        <td>${ev.src_ip}</td>
        <td>${ev.dst_ip}</td>
        <td>${ev.protocol}</td>
        <td><strong>${ev.attack_category}</strong></td>
        <td>${(ev.confidence_score * 100).toFixed(1)}%</td>
        <td><button class="btn btn-secondary btn-sm" onclick="inspectEvent(${ev.id})">Explain</button></td>
      </tr>
    `).join("");

  } catch (err) {
    console.error("Failed to load alerts:", err);
  }
}

/**
 * Inspect individual event in Explainability view
 */
async function inspectEvent(eventId) {
  try {
    const ev = await apiFetch(`/api/events/${eventId}`);
    switchTab("explainability");

    const explanation = typeof ev.explanation_json === "string"
      ? JSON.parse(ev.explanation_json || "{}")
      : (ev.explanation_json || {});

    document.getElementById("xai-summary-text").textContent =
      explanation.summary || `Alert #${ev.id} flagged as ${ev.attack_category} with confidence ${(ev.confidence_score * 100).toFixed(1)}%.`;

    const featureBarsContainer = document.getElementById("xai-feature-bars");
    const features = explanation.top_features || [];

    if (features.length === 0) {
      featureBarsContainer.innerHTML = `<p class="placeholder-text">Detailed feature contribution values unavailable for this record.</p>`;
    } else {
      featureBarsContainer.innerHTML = features.map(f => {
        const isMaliciousPush = f.attribution > 0;
        const widthPct = Math.min(100, Math.abs(f.attribution * 100)).toFixed(1);
        return `
          <div class="xai-feature-row">
            <div class="xai-feature-meta">
              <strong>${f.name} (${f.value})</strong>
              <span>${isMaliciousPush ? "+Malicious" : "-Normal"} (${f.attribution.toFixed(3)})</span>
            </div>
            <div class="xai-bar-track">
              <div class="xai-bar-fill ${isMaliciousPush ? 'positive' : 'negative'}" style="width: ${widthPct}%"></div>
            </div>
          </div>
        `;
      }).join("");
    }
  } catch (err) {
    alert(`Could not load event explanation: ${err.message}`);
  }
}

/**
 * Initialize application client
 */
window.addEventListener("DOMContentLoaded", async () => {
  await refreshStatus();
  await loadAlerts();
  pollingTimer = setInterval(refreshStatus, 2500);
});
