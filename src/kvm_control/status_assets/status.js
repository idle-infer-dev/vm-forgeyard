const state = {
  socket: null,
  lastEventId: null,
  reconnectDelayMs: 1000,
  refreshTimer: null,
  snapshot: null,
};

const summaryStrip = document.getElementById("summary-strip");
const workInProgress = document.getElementById("work-in-progress");
const namespacesRoot = document.getElementById("namespaces");
const alertsRoot = document.getElementById("alerts");
const liveLogRoot = document.getElementById("live-log");
const connectionState = document.getElementById("connection-state");

async function loadSnapshot() {
  const response = await fetch("/status/api/snapshot", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`snapshot failed: ${response.status}`);
  }
  state.snapshot = await response.json();
  renderSnapshot();
}

function renderSnapshot() {
  const snapshot = state.snapshot;
  if (!snapshot) {
    return;
  }
  renderSummary(snapshot);
  renderWorkInProgress(snapshot);
  renderNamespaces(snapshot);
  renderAlerts(snapshot);
  renderLiveLog(snapshot.recent_events || []);
}

function renderSummary(snapshot) {
  const events = snapshot.recent_events || [];
  const errorCount = events.filter((event) => event.level === "error").length;
  const activeVms = Object.values(snapshot.vms || {}).flat().filter((vm) => vm.power_state === "running").length;
  const activeLocks = (snapshot.locks || []).filter((lock) => lock.holder_namespace).length;
  const cards = [
    ["Running VMs", activeVms],
    ["Active Runs", (snapshot.runs || []).length],
    ["Active Locks", activeLocks],
    ["Recent Errors", errorCount],
    ["Used RAM", `${snapshot.host_capacity.used_memory_mb} MB`],
    ["Used vCPUs", snapshot.host_capacity.used_vcpus],
  ];
  summaryStrip.innerHTML = cards.map(([label, value]) => `
    <article class="summary-card">
      <div class="label">${escapeHtml(label)}</div>
      <div class="value">${escapeHtml(String(value))}</div>
    </article>
  `).join("");
}

function renderWorkInProgress(snapshot) {
  const items = [];
  for (const operation of snapshot.active_operations || []) {
    items.push({
      level: operation.status === "running" ? "info" : "warning",
      summary: `${operation.action} ${operation.status}${operation.vm_id ? ` for ${operation.vm_id}` : ""}`,
      meta: operation.namespace || "no namespace",
      timestamp: operation.updated_at || operation.created_at,
    });
  }
  for (const run of snapshot.runs || []) {
    if (run.active_stage) {
      items.push({
        level: "info",
        summary: `run ${run.id} active stage ${run.active_stage.stage_id}`,
        meta: `${run.namespace} · ${run.workflow_name}`,
        timestamp: run.active_stage.started_at,
      });
    }
  }
  for (const lock of snapshot.locks || []) {
    if (lock.queued_count > 0) {
      items.push({
        level: "warning",
        summary: `${lock.queued_count} queued for lock ${lock.resource_id}`,
        meta: lock.holder_namespace ? `held by ${lock.holder_namespace}` : "unheld",
        timestamp: null,
      });
    }
  }
  for (const vm of Object.values(snapshot.vms || {}).flat()) {
    if (vm.power_state === "paused") {
      items.push({
        level: "warning",
        summary: `${vm.vm_id} paused`,
        meta: vm.pause_reason || "no pause reason",
        timestamp: null,
      });
    }
  }
  renderList(workInProgress, items, "No active work right now.");
}

function renderNamespaces(snapshot) {
  const namespaces = snapshot.namespaces || [];
  namespacesRoot.innerHTML = namespaces.map((namespace) => {
    const vms = snapshot.vms[namespace.namespace] || [];
    return `
      <section class="namespace-group">
        <div class="namespace-header">
          <h3>${escapeHtml(namespace.namespace)}</h3>
          <div class="meta">
            ${escapeHtml(`${namespace.running_vm_count} running · ${namespace.vm_count} total · ${namespace.active_run_count} runs · ${namespace.queued_lock_count} queued locks`)}
          </div>
        </div>
        <div class="vm-grid">
          ${vms.map(renderVmCard).join("") || `<div class="empty">No VMs in this namespace.</div>`}
        </div>
      </section>
    `;
  }).join("") || `<div class="empty">No namespaces available.</div>`;
}

function renderVmCard(vm) {
  const statusTag = vm.power_state === "running" ? "tag" : vm.power_state === "paused" ? "tag warn" : "tag";
  const readinessTag = vm.readiness_state === "failed" ? "tag error" : "tag";
  const chain = (vm.image_chain || []).filter(Boolean).map((item) => `<div class="kv">${escapeHtml(item)}</div>`).join("");
  return `
    <article class="vm-card">
      <div class="vm-head">
        <div>
          <div class="vm-title">${escapeHtml(vm.vm_id)}</div>
          <div class="vm-subtitle">${escapeHtml(`${vm.template_id} on ${vm.network_id}`)}</div>
        </div>
        <div class="tag-row">
          <span class="${statusTag}">${escapeHtml(vm.power_state)}</span>
          <span class="${readinessTag}">${escapeHtml(vm.readiness_state)}</span>
        </div>
      </div>
      <div class="metrics">
        <div class="metric"><div class="value">${escapeHtml(String(vm.memory_mb))} MB</div><div class="kv">RAM</div></div>
        <div class="metric"><div class="value">${escapeHtml(String(vm.vcpus))}</div><div class="kv">vCPU</div></div>
        <div class="metric"><div class="value">${escapeHtml(vm.reserved_ip)}</div><div class="kv">Reserved IP</div></div>
      </div>
      <div>
        <div class="kv">Status: ${escapeHtml(vm.status)}${vm.pause_reason ? ` · pause=${escapeHtml(vm.pause_reason)}` : ""}</div>
        <div class="kv">Layer2: ${escapeHtml(vm.layer2_presence)} · Layer3: ${escapeHtml(vm.layer3_presence)}</div>
      </div>
      <div>
        <div class="kv">Image chain</div>
        ${chain || `<div class="kv">No image chain visible.</div>`}
      </div>
    </article>
  `;
}

function renderAlerts(snapshot) {
  const alerts = (snapshot.recent_events || [])
    .filter((event) => event.level === "warning" || event.level === "error")
    .slice(0, 20)
    .map(toDisplayItem);
  renderList(alertsRoot, alerts, "No recent warnings or errors.");
}

function renderLiveLog(events) {
  const items = [...events].slice(-80).reverse().map(toDisplayItem);
  renderList(liveLogRoot, items, "No events yet.");
}

function renderList(root, items, emptyText) {
  if (!items.length) {
    root.innerHTML = `<div class="empty">${escapeHtml(emptyText)}</div>`;
    return;
  }
  root.innerHTML = items.map((item) => `
    <article class="${root === liveLogRoot ? "log-item" : "list-item"}">
      <div class="${root === liveLogRoot ? "log-item-header" : "list-item-header"}">
        <div class="summary">${escapeHtml(item.summary)}</div>
        <div class="timestamp">${escapeHtml(formatTimestamp(item.timestamp))}</div>
      </div>
      <div class="kv">${escapeHtml(item.meta || "")}</div>
    </article>
  `).join("");
}

function toDisplayItem(event) {
  const metaParts = [];
  if (event.namespace) metaParts.push(event.namespace);
  if (event.vm_id) metaParts.push(event.vm_id);
  if (event.run_id != null) metaParts.push(`run ${event.run_id}`);
  if (event.resource_id) metaParts.push(`lock ${event.resource_id}`);
  if (event.status) metaParts.push(event.status);
  return {
    level: event.level,
    summary: event.summary,
    meta: metaParts.join(" · "),
    timestamp: event.created_at,
  };
}

function connectSocket() {
  setConnection("Connecting…");
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const suffix = state.lastEventId == null ? "" : `?after_id=${encodeURIComponent(state.lastEventId)}`;
  const socket = new WebSocket(`${protocol}://${window.location.host}/status/ws${suffix}`);
  state.socket = socket;

  socket.addEventListener("open", () => {
    setConnection("Live updates connected.");
    state.reconnectDelayMs = 1000;
  });

  socket.addEventListener("message", (message) => {
    const event = JSON.parse(message.data);
    state.lastEventId = event.id;
    if (state.snapshot) {
      state.snapshot.recent_events = [...(state.snapshot.recent_events || []), event].slice(-120);
      renderLiveLog(state.snapshot.recent_events);
      renderAlerts(state.snapshot);
    }
    scheduleRefresh();
  });

  socket.addEventListener("close", () => {
    setConnection("Disconnected. Retrying…");
    scheduleReconnect();
  });

  socket.addEventListener("error", () => {
    socket.close();
  });
}

function scheduleRefresh() {
  window.clearTimeout(state.refreshTimer);
  state.refreshTimer = window.setTimeout(async () => {
    try {
      await loadSnapshot();
    } catch (error) {
      console.error(error);
    }
  }, 250);
}

function scheduleReconnect() {
  const delay = state.reconnectDelayMs;
  state.reconnectDelayMs = Math.min(state.reconnectDelayMs * 2, 10000);
  window.setTimeout(async () => {
    try {
      await loadSnapshot();
    } catch (error) {
      console.error(error);
    }
    connectSocket();
  }, delay);
}

function setConnection(message) {
  connectionState.textContent = message;
}

function formatTimestamp(value) {
  if (!value) {
    return "now";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function main() {
  try {
    await loadSnapshot();
    connectSocket();
  } catch (error) {
    console.error(error);
    setConnection("Failed to load snapshot.");
  }
}

main();
