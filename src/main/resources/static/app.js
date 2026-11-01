const api = "/api/v1";
const authKey = "sentinelflow-auth";
let eventData = [];
let incidentData = [];
let toastTimer;

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}

function showToast(message) {
  const toast = document.querySelector("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("visible"), 2800);
}

function showAuth(message = "") {
  document.querySelector("#auth-overlay").hidden = false;
  document.querySelector("#auth-error").textContent = message;
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");
  const credentials = sessionStorage.getItem(authKey);
  if (credentials) headers.set("Authorization", `Basic ${credentials}`);
  const response = await fetch(`${api}${path}`, { ...options, headers });
  if (response.status === 401) {
    sessionStorage.removeItem(authKey);
    showAuth();
    throw new Error("AUTH_REQUIRED");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(response.status === 403 ? "Your account is not permitted to perform this action." : body.detail || body.message || `Request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

function formatTime(value) {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}

function renderEvents() {
  const query = document.querySelector("#event-search").value.trim().toLowerCase();
  const filtered = eventData.filter((event) => [event.eventType, event.username, event.sourceIp, event.outcome, event.detail]
    .some((value) => String(value).toLowerCase().includes(query)));
  const rows = document.querySelector("#event-rows");
  rows.innerHTML = filtered.length ? filtered.map((event) => `
    <tr>
      <td class="time-cell">${escapeHtml(formatTime(event.timestamp))}</td>
      <td class="event-cell">${escapeHtml(event.eventType)}<div class="event-detail">${escapeHtml(event.detail)}</div></td>
      <td class="identity-cell">${escapeHtml(event.username)}</td>
      <td class="identity-cell">${escapeHtml(event.sourceIp)}</td>
      <td><span class="outcome ${escapeHtml(event.outcome)}">${escapeHtml(event.outcome)}</span></td>
    </tr>`).join("") : '<tr><td colspan="5" class="loading">No events match this filter.</td></tr>';
  document.querySelector("#event-total").textContent = `${filtered.length} of ${eventData.length} events`;
  document.querySelector("#metric-events").textContent = eventData.length.toLocaleString();
}

function renderIncidents() {
  const container = document.querySelector("#incident-list");
  const pending = incidentData.reduce((total, incident) => total + incident.actions.filter((action) => action.approvalStatus === "PENDING").length, 0);
  document.querySelector("#metric-incidents").textContent = incidentData.length;
  document.querySelector("#metric-approvals").textContent = pending;
  document.querySelector("#incident-count").textContent = incidentData.length;
  document.querySelector("#queue-count").textContent = `${incidentData.length} OPEN`;
  container.innerHTML = incidentData.length ? incidentData.map((incident) => `
    <section class="incident-card" aria-label="Incident ${escapeHtml(incident.title)}">
      <div class="incident-top"><span class="severity">${escapeHtml(incident.severity)}</span><span class="incident-status">${escapeHtml(incident.status)}</span></div>
      <p class="incident-title">${escapeHtml(incident.title)}</p>
      <div class="incident-meta"><span>${escapeHtml(incident.username)} · ${escapeHtml(incident.sourceIp)}</span><span>${incident.evidenceEventIds.length} events</span></div>
      <div class="action-list">${incident.actions.map((action) => `
        <div class="action-row"><span>${escapeHtml(action.summary)}</span>${action.approvalStatus === "PENDING"
          ? `<span><button data-incident="${incident.id}" data-action="${action.id}" data-decision="APPROVED">Approve</button> <button data-incident="${incident.id}" data-action="${action.id}" data-decision="REJECTED">Reject</button></span>`
          : `<span class="action-status ${action.approvalStatus.toLowerCase()}">${escapeHtml(action.approvalStatus)}</span>`}</div>`).join("")}</div>
    </section>`).join("") : '<div class="empty-state"><span class="empty-icon">◎</span><strong>All quiet for now</strong><span>Run the demo scenario to create an incident.</span></div>';
}

async function refresh() {
  try {
    [eventData, incidentData] = await Promise.all([request("/events"), request("/incidents")]);
    renderEvents();
    renderIncidents();
  } catch (error) {
    if (error.message !== "AUTH_REQUIRED") showToast(`Could not connect to SentinelFlow: ${error.message}`);
  }
}

document.querySelector("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const username = form.elements.username.value.trim();
  const password = form.elements.password.value;
  sessionStorage.setItem(authKey, btoa(`${username}:${password}`));
  try {
    await request("/events");
    form.reset();
    document.querySelector("#auth-overlay").hidden = true;
    await refresh();
  } catch {
    sessionStorage.removeItem(authKey);
    showAuth("Sign-in failed. Check the username and password.");
  }
});

document.querySelector("#sign-out").addEventListener("click", () => {
  sessionStorage.removeItem(authKey);
  eventData = [];
  incidentData = [];
  renderEvents();
  renderIncidents();
  showAuth();
});

document.querySelector("#event-search").addEventListener("input", renderEvents);
document.querySelector("#run-scenario").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await request("/demo/suspicious-login", { method: "POST" });
    await refresh();
    showToast("Synthetic incident created. Review the proposed actions.");
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#incident-list").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-decision]");
  if (!button) return;
  button.disabled = true;
  try {
    await request(`/incidents/${button.dataset.incident}/actions/${button.dataset.action}/approval`, {
      method: "POST",
      body: JSON.stringify({ decision: button.dataset.decision }),
    });
    await refresh();
    showToast(`Mock action ${button.dataset.decision.toLowerCase()}. No external system was changed.`);
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
  }
});

refresh();