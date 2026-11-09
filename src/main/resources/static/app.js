const api = "/api/v1";
const authKey = "sentinelflow-auth";
let eventData = [];
let incidentData = [];
let sessionData = null;
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
  document.querySelector("#app-shell").hidden = true;
  document.querySelector("#auth-overlay").hidden = false;
  document.querySelector("#auth-error").textContent = message;
}

const views = {
  overview: {
    title: "Security overview",
    description: "A clear view of event activity and analyst decisions.",
    eyebrow: "WORKSPACE / OVERVIEW",
  },
  events: {
    title: "Event explorer",
    description: "Search and review the synthetic security event stream.",
    eyebrow: "TELEMETRY / EVENTS",
  },
  incidents: {
    title: "Incidents",
    description: "Review incident evidence and approve or reject proposed actions.",
    eyebrow: "TRIAGE / INCIDENTS",
  },
  rules: {
    title: "Detection rules",
    description: "Generate evidence-grounded detection rule drafts from incidents.",
    eyebrow: "DETECTION / RULES",
    featureTitle: "Detection rule drafts",
    featureDescription: "Local Ollama generation with analyst review before adoption.",
  },
  playbooks: {
    title: "Playbooks",
    description: "Generate investigation guidance from incident evidence and review it here.",
    eyebrow: "RESPONSE / PLAYBOOKS",
    featureTitle: "Investigation playbooks",
    featureDescription: "Local Ollama generation produces drafts; each step remains human-led.",
  },
};

function updateView() {
  const requestedView = window.location.hash.slice(1) || "overview";
  const view = views[requestedView] ? requestedView : "overview";
  const details = views[view];
  const isFeatureView = view === "rules" || view === "playbooks";
  const appShell = document.querySelector("#app-shell");
  appShell.dataset.view = view;
  document.querySelector("#breadcrumb-title").textContent = details.title;
  document.querySelector("#page-title").textContent = details.title;
  document.querySelector("#page-description").textContent = details.description;
  document.querySelector("#page-eyebrow").textContent = details.eyebrow;
  document.querySelector("#metrics").hidden = view !== "overview";
  document.querySelector("#content-grid").hidden = isFeatureView;
  document.querySelector("#content-grid").style.gridTemplateColumns = view === "events" || view === "incidents" ? "minmax(0, 1fr)" : "";
  document.querySelector("#events").hidden = view === "incidents";
  document.querySelector("#incidents").hidden = view === "events";
  document.querySelector("#feature-page").hidden = !isFeatureView;
  document.querySelector("#feature-eyebrow").textContent = details.eyebrow;
  document.querySelector("#feature-mark").textContent = view === "rules" ? "⌘" : "↗";
  document.querySelector("#feature-title").textContent = details.featureTitle || "";
  document.querySelector("#feature-description").textContent = details.featureDescription || "";
  document.querySelector("#rules-content").hidden = view !== "rules";
  document.querySelector("#playbooks-content").hidden = view !== "playbooks";
  if (isFeatureView && sessionData) refreshArtifacts();
  document.querySelector("#run-scenario").hidden = view !== "overview" && view !== "incidents";
  document.querySelectorAll(".nav-link[data-view]").forEach((link) => {
    const active = link.dataset.view === view;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
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
      <div class="incident-next-steps">
        <div class="next-steps-title">What to do next</div>
        <ol><li>Review the ${incident.evidenceEventIds.length} synthetic events and verify the identity, source IP, and sequence.</li>
        <li>${incident.actions.some((action) => action.approvalStatus === "PENDING") ? "Approve or reject each pending response below." : "Review the recorded response decisions."}</li>
        <li>Confirm no action remains pending. Decisions update this demo only; no external system is changed.</li></ol>
        <a class="text-link" href="#playbooks">Open the incident playbook</a>
      </div>
    </section>`).join("") : '<div class="empty-state"><span class="empty-icon">◎</span><strong>All quiet for now</strong><span>Run the demo scenario to create an incident.</span></div>';
}

function canReviewArtifacts() {
  return sessionData?.authorities?.some((role) => role === "ROLE_ANALYST" || role === "ROLE_ADMIN") ?? false;
}

function renderIncidentOptions() {
  const options = incidentData.map((incident) =>
    `<option value="${incident.id}">${escapeHtml(incident.title)} · ${escapeHtml(incident.username)}</option>`).join("");
  ["#rule-incident", "#playbook-incident"].forEach((selector) => {
    const select = document.querySelector(selector);
    const currentValue = select.value;
    select.innerHTML = options || '<option value="">Create an incident first</option>';
    if (incidentData.some((incident) => incident.id === currentValue)) select.value = currentValue;
    select.disabled = !canReviewArtifacts() || incidentData.length === 0;
  });
  ["#generate-rule", "#generate-playbook"].forEach((selector) => {
    document.querySelector(selector).hidden = !canReviewArtifacts();
  });
}

function renderArtifact(artifact) {
  const content = artifact.content;
  const source = incidentData.find((incident) => incident.id === artifact.incidentId);
  const details = artifact.type === "DETECTION_RULE"
    ? `<div class="artifact-fact"><span>SEVERITY</span><strong>${escapeHtml(content.severity)}</strong></div>
       <div class="artifact-fact"><span>DETECTION CONDITION</span><pre>${escapeHtml(content.query)}</pre></div>
       <div class="artifact-fact"><span>FALSE POSITIVES</span><p>${escapeHtml(content.falsePositiveGuidance)}</p></div>
       <div class="artifact-fact"><span>VALIDATION</span><ol class="artifact-steps">${(content.validationSteps || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ol></div>`
    : `<div class="artifact-fact"><span>OBJECTIVE</span><p>${escapeHtml(content.objective)}</p></div>
       <ol class="workflow-steps">${(content.steps || []).map((step) => `<li><strong>${escapeHtml(step.title)}</strong><span>${escapeHtml(step.instruction)} Expected: ${escapeHtml(step.expectedOutcome)}</span></li>`).join("")}</ol>
       <div class="artifact-fact"><span>SAFETY NOTES</span><ul class="artifact-steps">${(content.safetyNotes || []).map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul></div>`;
  const reviewControls = artifact.status === "DRAFT" && canReviewArtifacts()
    ? `<div class="artifact-review"><span>Analyst review</span><span><button data-artifact-id="${artifact.id}" data-decision="APPROVED">Approve draft</button><button data-artifact-id="${artifact.id}" data-decision="REJECTED">Reject draft</button></span></div>`
    : `<div class="artifact-review"><span>${artifact.reviewedBy ? `Reviewed by ${escapeHtml(artifact.reviewedBy)}` : "Awaiting analyst review"}</span><span class="action-status ${artifact.status.toLowerCase()}">${escapeHtml(artifact.status)}</span></div>`;
  return `<article class="artifact-card">
    <div class="artifact-card-top"><span class="artifact-kind">${artifact.type === "DETECTION_RULE" ? "DETECTION RULE" : "PLAYBOOK"}</span><span class="action-status ${artifact.status.toLowerCase()}">${escapeHtml(artifact.status)}</span></div>
    <h3>${escapeHtml(content.name)}</h3><p class="artifact-summary">${escapeHtml(artifact.type === "DETECTION_RULE" ? content.description : content.objective)}</p>
    <div class="artifact-source">From <a class="text-link" href="#incidents">${escapeHtml(source?.title || "Incident")}</a> · ${escapeHtml(formatTime(artifact.createdAt))}</div>
    ${details}${reviewControls}
  </article>`;
}

async function refreshArtifacts() {
  try {
    const [rules, playbooks] = await Promise.all([
      request("/ai/artifacts?type=DETECTION_RULE"),
      request("/ai/artifacts?type=PLAYBOOK"),
    ]);
    document.querySelector("#rules-artifact-list").innerHTML = rules.length
      ? rules.map(renderArtifact).join("")
      : '<div class="empty-state"><strong>No detection rule drafts</strong><span>Choose an incident above to generate one.</span></div>';
    document.querySelector("#playbooks-artifact-list").innerHTML = playbooks.length
      ? playbooks.map(renderArtifact).join("")
      : '<div class="empty-state"><strong>No playbook drafts</strong><span>Choose an incident above to generate one.</span></div>';
  } catch (error) {
    if (error.message !== "AUTH_REQUIRED") showToast(`Could not load generated artifacts: ${error.message}`);
  }
}

async function refresh() {
  try {
    [eventData, incidentData] = await Promise.all([request("/events"), request("/incidents")]);
    renderEvents();
    renderIncidents();
    renderIncidentOptions();
    await refreshArtifacts();
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
    const [, signedInSession] = await Promise.all([request("/events"), request("/session")]);
    sessionData = signedInSession;
    form.reset();
    document.querySelector("#auth-overlay").hidden = true;
    document.querySelector("#app-shell").hidden = false;
    const initials = username.split(/[ ._-]+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join("").toUpperCase();
    document.querySelector("#sign-out").textContent = initials || "SF";
    renderIncidentOptions();
    updateView();
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
  sessionData = null;
  renderEvents();
  renderIncidents();
  showAuth();
});

document.querySelector("#event-search").addEventListener("input", renderEvents);
window.addEventListener("hashchange", updateView);
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

async function generateArtifact(kind) {
  const select = document.querySelector(kind === "detection-rules" ? "#rule-incident" : "#playbook-incident");
  const button = document.querySelector(kind === "detection-rules" ? "#generate-rule" : "#generate-playbook");
  if (!select.value) return;
  button.disabled = true;
  button.textContent = "Generating…";
  try {
    await request(`/incidents/${select.value}/${kind}`, { method: "POST" });
    await refreshArtifacts();
    showToast(`${kind === "detection-rules" ? "Detection rule" : "Playbook"} saved as a draft for analyst review.`);
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = kind === "detection-rules" ? "Generate detection rule" : "Generate playbook";
  }
}

document.querySelector("#generate-rule").addEventListener("click", () => generateArtifact("detection-rules"));
document.querySelector("#generate-playbook").addEventListener("click", () => generateArtifact("playbooks"));
document.querySelector("#feature-page").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-artifact-id][data-decision]");
  if (!button) return;
  button.disabled = true;
  try {
    await request(`/ai/artifacts/${button.dataset.artifactId}/review`, {
      method: "POST",
      body: JSON.stringify({ decision: button.dataset.decision }),
    });
    await refreshArtifacts();
    showToast(`Draft ${button.dataset.decision.toLowerCase()}. No response action was executed.`);
  } catch (error) {
    showToast(error.message);
    button.disabled = false;
  }
});

async function startApp() {
  updateView();
  if (!sessionStorage.getItem(authKey)) {
    showAuth();
    return;
  }
  try {
    const [, signedInSession] = await Promise.all([request("/events"), request("/session")]);
    sessionData = signedInSession;
    document.querySelector("#auth-overlay").hidden = true;
    document.querySelector("#app-shell").hidden = false;
    renderIncidentOptions();
    await refresh();
  } catch (error) {
    if (error.message !== "AUTH_REQUIRED") {
      document.querySelector("#app-shell").hidden = false;
      showToast(`Could not connect to SentinelFlow: ${error.message}`);
    }
  }
}

startApp();