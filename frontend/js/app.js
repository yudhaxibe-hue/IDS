/**
 * Explainable Adaptive IDS - Complete Desktop Client Controller
 * Communicates with local loopback FastAPI backend using authenticated JSON requests.
 */

// Extract session token from URL parameters
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
const permissionNoticeBox = document.getElementById("permission-notice-box");

/**
 * Perform authenticated request to local FastAPI backend.
 */
async function apiFetch(endpoint, options = {}) {
  const headers = options.headers ? { ...options.headers } : {};
  if (sessionToken) {
    headers["X-Session-Token"] = sessionToken;
  }
  if (!options.isRaw) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(endpoint, {
    ...options,
    headers
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `HTTP Error ${response.status}`);
  }

  return options.isRaw ? response : response.json();
}

/**
 * Tab Navigation Switcher
 */
function switchTab(tabId) {
  currentTab = tabId;

  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });

  document.querySelectorAll(".tab-pane").forEach(pane => {
    pane.classList.toggle("active", pane.id === `tab-${tabId}`);
  });

  const activeBtn = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
  if (activeBtn) {
    document.getElementById("current-tab-title").textContent = activeBtn.textContent.trim();
  }

  if (tabId === "alerts") {
    loadAlerts();
  } else if (tabId === "history") {
    loadHistory();
  } else if (tabId === "adaptation") {
    loadDriftData();
  } else if (tabId === "settings") {
    loadSettings();
  }
}

document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

/**
 * Load Network Capture Interfaces and Diagnostic Notes
 */
async function loadInterfaces() {
  try {
    const data = await apiFetch("/api/interfaces");
    selectInterface.innerHTML = "";

    data.interfaces.forEach(iface => {
      const opt = document.createElement("option");
      opt.value = iface.name;
      opt.textContent = `${iface.name} - ${iface.description}`;
      if (iface.is_default) opt.selected = true;
      selectInterface.appendChild(opt);
    });

    const perms = data.capture_permissions;
    if (perms && !perms.has_permission) {
      permissionNoticeBox.innerHTML = `
        <div class="notice-icon">⚠️</div>
        <div class="notice-text">
          <strong>Live Capture Notice:</strong> ${perms.diagnostic_note}<br>
          <small>${perms.resolution_instructions}</small>
        </div>
      `;
    }
  } catch (err) {
    console.warn("Could not load interfaces:", err);
  }
}

/**
 * Polling System Telemetry & Status
 */
async function refreshStatus() {
  try {
    const data = await apiFetch("/api/status");

    statusDot.className = "dot online";
    statusText.textContent = "Backend Connected";

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

    statDrift.textContent = data.drift_status || "STABLE";
    document.getElementById("model-version-pill").textContent = `MODEL: ${data.active_model_version || "v1.0.0-baseline"}`;

    if (currentTab === "overview") {
      loadOverviewAlerts();
    }
  } catch (err) {
    statusDot.className = "dot";
    statusText.textContent = "Backend Disconnected";
  }
}

/**
 * Monitoring Start / Stop Controls
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
 * Overview Recent Alerts
 */
async function loadOverviewAlerts() {
  try {
    const data = await apiFetch("/api/events?is_malicious=1&limit=5");
    const tbody = document.getElementById("overview-alerts-body");

    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No threat alerts recorded yet. Start monitoring to process flows.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.events.map(ev => `
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
    console.error("Failed to load overview alerts:", err);
  }
}

/**
 * Threat Alerts Table
 */
async function loadAlerts() {
  try {
    const data = await apiFetch("/api/events?is_malicious=1&limit=50");
    const tbody = document.getElementById("alerts-table-body");

    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No alerts flagged yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.events.map(ev => `
      <tr>
        <td>#${ev.id}</td>
        <td>${ev.timestamp}</td>
        <td>${ev.src_ip}:${ev.src_port}</td>
        <td>${ev.dst_ip}:${ev.dst_port}</td>
        <td><strong>${ev.attack_category}</strong></td>
        <td><span class="badge" style="background:${ev.severity === 'Critical' ? '#da3633' : '#d29922'}">${ev.severity}</span></td>
        <td>${(ev.confidence_score * 100).toFixed(1)}%</td>
        <td><button class="btn btn-secondary btn-sm" onclick="inspectEvent(${ev.id})">Inspect XAI</button></td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Failed to load alerts:", err);
  }
}

/**
 * Event History Table
 */
async function loadHistory() {
  try {
    const data = await apiFetch("/api/events?limit=50");
    const tbody = document.getElementById("history-table-body");

    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = `<tr class="empty-row"><td colspan="6">No flow records in local database.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.events.map(ev => `
      <tr>
        <td>${ev.timestamp}</td>
        <td>${ev.src_ip}:${ev.src_port} &rarr; ${ev.dst_ip}:${ev.dst_port} (${ev.protocol})</td>
        <td>${ev.packet_count}</td>
        <td>${ev.byte_count.toLocaleString()} B</td>
        <td><span style="color:${ev.is_malicious ? '#f85149' : '#3fb950'}">${ev.attack_category}</span></td>
        <td>${(ev.confidence_score * 100).toFixed(1)}%</td>
      </tr>
    `).join("");
  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

/**
 * Inspect individual event in Explainability view
 */
async function inspectEvent(eventId) {
  try {
    const explanation = await apiFetch(`/api/explain/${eventId}`);
    switchTab("explainability");

    document.getElementById("xai-summary-text").textContent =
      explanation.summary || `Alert #${eventId} explanation loaded.`;

    const featureBarsContainer = document.getElementById("xai-feature-bars");
    const features = explanation.top_features || [];

    if (features.length === 0) {
      featureBarsContainer.innerHTML = `<p class="placeholder-text">Detailed feature contribution values unavailable for this record.</p>`;
    } else {
      featureBarsContainer.innerHTML = features.map(f => {
        const isMaliciousPush = f.direction === "malicious";
        const widthPct = Math.min(100, Math.abs(f.attribution * 100)).toFixed(1);
        return `
          <div class="xai-feature-row">
            <div class="xai-feature-meta">
              <strong>${f.name}: ${f.value} ${f.unit}</strong>
              <span style="color:${isMaliciousPush ? '#f85149' : '#3fb950'}">
                ${isMaliciousPush ? '&uarr; Pushed to Malicious' : '&darr; Pushed to Normal'} (${f.attribution > 0 ? '+' : ''}${f.attribution})
              </span>
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
 * Concept Drift & Adaptation Tab Data
 */
async function loadDriftData() {
  try {
    const data = await apiFetch("/api/drift");
    const banner = document.getElementById("drift-banner");

    if (data.status === "DRIFT_DETECTED") {
      banner.className = "drift-status-banner alert";
      banner.innerHTML = `
        <span class="drift-icon">⚠️</span>
        <div class="drift-info">
          <h4>Distribution Status: DRIFT DETECTED</h4>
          <p>${data.summary}</p>
        </div>
      `;
    } else if (data.status === "WARNING") {
      banner.className = "drift-status-banner warning";
      banner.innerHTML = `
        <span class="drift-icon">⚡</span>
        <div class="drift-info">
          <h4>Distribution Status: WARNING</h4>
          <p>${data.summary}</p>
        </div>
      `;
    } else {
      banner.className = "drift-status-banner stable";
      banner.innerHTML = `
        <span class="drift-icon">🛡️</span>
        <div class="drift-info">
          <h4>Distribution Status: STABLE</h4>
          <p>${data.summary}</p>
        </div>
      `;
    }
  } catch (err) {
    console.error("Failed to load drift data:", err);
  }
}

/**
 * Rollback Active Model
 */
async function executeRollback() {
  if (!confirm("Are you sure you want to roll back the active model to the previously approved version?")) {
    return;
  }
  try {
    const res = await apiFetch("/api/adaptation/rollback", { method: "POST" });
    alert(res.message);
    await refreshStatus();
    await loadDriftData();
  } catch (err) {
    alert(`Rollback failed: ${err.message}`);
  }
}

/**
 * Export CSV Report
 */
async function exportCSV() {
  try {
    const resp = await apiFetch("/api/reports/csv", { isRaw: true });
    const blob = await resp.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `IDS_Events_Report_${new Date().toISOString().split("T")[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    alert(`Failed to export CSV: ${err.message}`);
  }
}

/**
 * Settings
 */
async function loadSettings() {
  try {
    const settings = await apiFetch("/api/settings");
    if (settings.alert_threshold) {
      document.getElementById("threshold-slider").value = settings.alert_threshold;
      document.getElementById("threshold-val").textContent = settings.alert_threshold;
    }
  } catch (err) {
    console.error("Failed to load settings:", err);
  }
}

document.getElementById("threshold-slider").addEventListener("input", (e) => {
  document.getElementById("threshold-val").textContent = e.target.value;
});

document.getElementById("threshold-slider").addEventListener("change", async (e) => {
  try {
    await apiFetch("/api/settings", {
      method: "POST",
      body: JSON.stringify({ alert_threshold: parseFloat(e.target.value) })
    });
  } catch (err) {
    alert(`Failed to save settings: ${err.message}`);
  }
});

/**
 * App Initialization
 */
window.addEventListener("DOMContentLoaded", async () => {
  await loadInterfaces();
  await refreshStatus();
  pollingTimer = setInterval(refreshStatus, 2500);
});
