const state = {
  snapshot: null,
  events: [],
  lastEventId: null,
  socket: null,
  reconnectDelayMs: 1000,
};

function byId(id) {
  return document.getElementById(id);
}

function fmtTime(value) {
  if (!value) return "n/a";
  try {
    return new Date(value).toLocaleTimeString();
  } catch {
    return value;
  }
}

function fmtBytes(bytes) {
  if (!bytes && bytes !== 0) return "n/a";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit > 1 ? 1 : 0)} ${units[unit]}`;
}

function badgeClass(level) {
  return `badge ${level || ""}`.trim();
}

function renderSummary(snapshot) {
  const capacity = snapshot.host_capacity;
  const runningVms = snapshot.namespaces.reduce((sum, ns) => sum + ns.running_vm_count, 0);
  const activeRuns = snapshot.runs.length;
  const activeLocks = snapshot.locks.filter((lock) => lock.holder_namespace).length;
  const errorCount = snapshot.recent_events.filter((event) => event.level === "error").length;
  const cards = [
    ["Running VMs", runningVms],
    ["Active Runs", activeRuns],
    ["Held Locks", activeLocks],
    ["Recent Errors", errorCount],
    ["Used Memory", `${capacity.used_memory_mb} / ${capacity.max_total_memory_mb} MB`],
    ["Used vCPUs", `${capacity.used_vcpus} / ${capacity.max_total_vcpus}`],
  ];
  byId("summary").innerHTML = cards.map(([label, value]) => `
    <article class="summary-card">
      <span class="muted">${label}</span>
      <strong>${value}</strong>
    </article>
  `).join("");
}

function renderWork(snapshot) {
  const pausedVms = Object.values(snapshot.vms).flat().filter((vm) => vm.power_state === "paused");
  const items = [];
  for (const op of snapshot.active_operations) {
    items.push(`
      <article class="work-item">
        <strong>${op.action} ${op.vm_id || ""}</strong>
        <div class="mini-list">${op.status} · ${fmtTime(op.updated_at)}${op.namespace ? ` · ${op.namespace}` : ""}</div>
      </article>
    `);
  }
  for (const run of snapshot.runs) {
    if (!run.active_stage) continue;
    items.push(`
      <article class="work-item">
        <strong>run ${run.id} · ${run.workflow_name}</strong>
        <div class="mini-list">${run.namespace} · stage ${run.active_stage.stage_id} · ${run.active_stage.name}</div>
      </article>
    `);
  }
  for (const lock of snapshot.locks) {
    if (!lock.queued_count) continue;
    items.push(`
      <article class="work-item">
        <strong>lock ${lock.resource_id}</strong>
        <div class="mini-list">${lock.queued_count} queued${lock.holder_namespace ? ` · held by ${lock.holder_namespace}` : ""}</div>
      </article>
    `);
  }
  for (const vm of pausedVms) {
    items.push(`
      <article class="work-item">
        <strong>${vm.vm_id}</strong>
        <div class="mini-list">paused${vm.pause_reason ? ` · ${vm.pause_reason}` : ""}</div>
      </article>
    `);
  }
  byId("work-in-progress").innerHTML = items.length ? items.join("") : `<div class="empty">Nothing active right now.</div>`;
}

function renderNamespaces(snapshot) {
  const target = byId("namespaces");
  const namespaceViews = snapshot.namespaces.map((ns) => {
    const vms = snapshot.vms[ns.namespace] || [];
    const vmCards = vms.map((vm) => `
      <article class="vm-card">
        <div class="vm-title">
          <div>
            <h3>${vm.vm_id}</h3>
            <div class="muted">${vm.template_id} · ${vm.network_id}</div>
          </div>
          <span class="vm-state">${vm.power_state} / ${vm.readiness_state}</span>
        </div>
        <div class="vm-meta">
          <div>RAM: ${vm.memory_mb} MB</div>
          <div>vCPUs: ${vm.vcpus}</div>
          <div>Reserved IP: ${vm.reserved_ip}</div>
          <div>Status: ${vm.status}</div>
        </div>
        <div class="mini-list">
          Base: ${vm.base_image || "n/a"}<br>
          Layer2: ${vm.layer2_presence} · ${vm.layer2_path}<br>
          Layer3: ${vm.layer3_presence} · ${vm.layer3_path}
        </div>
      </article>
    `).join("");
    const runList = snapshot.runs
      .filter((run) => run.namespace === ns.namespace)
      .map((run) => `run ${run.id} ${run.workflow_name}${run.active_stage ? ` · ${run.active_stage.stage_id}` : ""}`)
      .join("<br>");
    return `
      <section class="namespace-section">
        <div class="namespace-header">
          <div>
            <h3>${ns.namespace}</h3>
            <div class="namespace-stats">
              ${ns.running_vm_count} running · ${ns.vm_count} total · ${ns.active_run_count} runs
            </div>
          </div>
          <div class="namespace-stats">
            ${ns.granted_lock_count} granted locks · ${ns.queued_lock_count} queued locks
          </div>
        </div>
        <div class="vm-grid">${vmCards || `<div class="empty">No VMs.</div>`}</div>
        ${runList ? `<div class="mini-list">Runs:<br>${runList}</div>` : ""}
      </section>
    `;
  });
  target.innerHTML = namespaceViews.length ? namespaceViews.join("") : `<div class="empty">No namespaces yet.</div>`;
}

function renderAlerts(snapshot) {
  const alerts = snapshot.recent_events.filter((event) => event.level === "warning" || event.level === "error").slice(-12).reverse();
  byId("alerts").innerHTML = alerts.length ? alerts.map((event) => `
    <article class="alert-item ${event.level}">
      <strong>${event.summary}</strong>
      <div class="mini-list">${fmtTime(event.created_at)} · ${event.kind}${event.namespace ? ` · ${event.namespace}` : ""}</div>
    </article>
  `).join("") : `<div class="empty">No recent warnings or errors.</div>`;
}

function renderLog() {
  const rows = state.events.slice(-150).reverse().map((event) => `
    <div class="log-row">
      <div>${fmtTime(event.created_at)}</div>
      <div><span class="${badgeClass(event.level)}">${event.kind}</span></div>
      <div>${event.summary}</div>
    </div>
  `).join("");
  byId("live-log").innerHTML = rows || `<div class="empty">Waiting for events.</div>`;
}

function renderAll() {
  if (!state.snapshot) return;
  renderSummary(state.snapshot);
  renderWork(state.snapshot);
  renderNamespaces(state.snapshot);
  renderAlerts(state.snapshot);
  renderLog();
}

function mergeEvent(event) {
  state.lastEventId = event.id;
  state.events = [...state.events.filter((item) => item.id !== event.id), event].sort((left, right) => left.id - right.id);
  if (state.snapshot) {
    state.snapshot.recent_events = [...state.snapshot.recent_events.filter((item) => item.id !== event.id), event].sort((left, right) => left.id - right.id).slice(-120);
  }
  renderLog();
  renderAlerts(state.snapshot);
}

async function loadSnapshot() {
  const response = await fetch("/status/api/snapshot", { cache: "no-store" });
  state.snapshot = await response.json();
  state.events = [...state.snapshot.recent_events];
  state.lastEventId = state.events.length ? state.events[state.events.length - 1].id : null;
  renderAll();
}

function setSocketState(online) {
  const node = byId("socket-state");
  node.textContent = online ? "Live" : "Reconnecting";
  node.className = `socket-state ${online ? "online" : "offline"}`;
}

function connectSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const after = state.lastEventId != null ? `?after_id=${state.lastEventId}` : "";
  const socket = new WebSocket(`${protocol}//${window.location.host}/status/ws${after}`);
  state.socket = socket;

  socket.addEventListener("open", () => {
    setSocketState(true);
    state.reconnectDelayMs = 1000;
  });

  socket.addEventListener("message", (message) => {
    try {
      const event = JSON.parse(message.data);
      mergeEvent(event);
    } catch (error) {
      console.error("status websocket parse error", error);
    }
  });

  socket.addEventListener("close", async () => {
    setSocketState(false);
    try {
      await loadSnapshot();
    } catch (error) {
      console.error("snapshot refresh failed after disconnect", error);
    }
    window.setTimeout(connectSocket, state.reconnectDelayMs);
    state.reconnectDelayMs = Math.min(state.reconnectDelayMs * 2, 10000);
  });

  socket.addEventListener("error", (error) => {
    console.error("status websocket error", error);
    socket.close();
  });
}

window.addEventListener("load", async () => {
  try {
    await loadSnapshot();
  } catch (error) {
    console.error("failed to load status snapshot", error);
  }
  connectSocket();
});
