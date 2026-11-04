// WatchTower dashboard. Plain DOM, no dependencies, no build step.
//
// Everything from the API is data, including content captured from scanned
// hosts (titles, headers, evidence excerpts). It is only ever inserted with
// textContent or as attribute values set through the DOM, never as HTML.
"use strict";

const API = "/api/v1";
const TOKEN_KEY = "watchtower.token";
const PROJECT_KEY = "watchtower.project";
const REFRESH_MS = 10000;

const state = { token: null, projects: [], project: null, view: "overview", timer: null, cursor: {}, filters: {}, scanKey: null };

// ---- small DOM helpers -------------------------------------------------

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// replaceChildren with el()'s rules: nested arrays are flattened and null/false/undefined are skipped.
function fill(node, ...children) {
  node.replaceChildren(...el("div", {}, ...children).childNodes);
}

function text(value) {
  return value === undefined || value === null || value === "" ? "-" : String(value);
}

function when(iso) {
  if (!iso) return "-";
  const moment = new Date(iso);
  return isNaN(moment) ? String(iso) : moment.toLocaleString(undefined, { timeZoneName: "short" });
}

function badge(label, kind) {
  return el("span", { class: `badge ${kind}` }, label);
}

// Failed and cancelled runs never share the colour of success.
const RUN_KIND = { succeeded: "ok", partial: "warn", failed: "bad", cancelled: "muted", queued: "info", running: "info" };
const REMEDIATION = {
  verified_fixed: ["Fixed, verified by retest", "ok"],
  retest_failed: ["Retest failed: not verified", "bad"],
  retest_inconclusive: ["Retest inconclusive: not verified", "warn"],
  retest_pending: ["Retest pending", "info"],
  still_present: ["Still present after retest", "bad"],
  not_retested: ["Not retested", "muted"],
};
// Comparisons that mean a phase could not see what it was asked to look at.
const COMPARISON_KIND = { failed: "bad", uncertain: "bad", partial: "warn" };
const SEVERITY = { critical: "bad", high: "bad", medium: "warn", low: "info", info: "muted" };

function runBadge(status) {
  return badge(status.toUpperCase(), RUN_KIND[status] || "muted");
}

function remediationBadge(state) {
  const [label, kind] = REMEDIATION[state] || [state, "muted"];
  return badge(label, kind);
}

function notice(message, kind) {
  const box = document.getElementById("status");
  box.textContent = message || "";
  box.className = `status ${kind || ""}`;
}

// ---- API ---------------------------------------------------------------

class ApiError extends Error {
  constructor(status, body) {
    const detail = body && body.detail;
    super(typeof detail === "string" ? detail : Array.isArray(detail)
      ? detail.map((item) => item.msg || "Invalid input").join("; ") : `Request failed (${status})`);
    this.status = status;
  }
}

async function api(path, options = {}) {
  const response = await fetch(API + path, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${state.token}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    credentials: "omit",
    cache: "no-store",
  });
  if (response.status === 401) {
    signOut("Your token was rejected. Sign in again.");
    throw new ApiError(401, null);
  }
  if (options.raw) {
    if (!response.ok) throw new ApiError(response.status, null);
    return response;
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(response.status, body);
  return body;
}

function projectPath(suffix) {
  return `/projects/${encodeURIComponent(state.project.id)}${suffix}`;
}

function can(permission) {
  return state.project && state.project.permissions.includes(permission);
}

// ---- session -----------------------------------------------------------

function storage(action, key, value) {
  try {
    if (action === "get") return sessionStorage.getItem(key);
    if (action === "set") sessionStorage.setItem(key, value);
    if (action === "remove") sessionStorage.removeItem(key);
  } catch (_) {
    return null;
  }
  return null;
}

async function signIn(token) {
  if (!token) { notice("Paste your copied token to sign in.", "warn"); return; }
  const button = document.querySelector("#signin-form button[type=submit]");
  button.disabled = true;
  button.textContent = "Signing in…";
  state.token = token;
  try {
    state.projects = await api("/projects");
  } catch (error) {
    state.token = null;
    storage("remove", TOKEN_KEY);
    notice(error.status === 401 ? "Token not accepted. Run Copy-Dashboard-Token.cmd for your selected project and try again."
      : error instanceof TypeError ? "Cannot reach the server. Keep the dashboard terminal open and try again." : error.message, "bad");
    return;
  } finally {
    button.disabled = false;
    button.textContent = "Sign in";
  }
  if (!state.projects.length) {
    state.token = null;
    storage("remove", TOKEN_KEY);
    notice("This token has no projects. Copy the token for your selected terminal project.", "warn");
    return;
  }
  storage("set", TOKEN_KEY, token);
  const remembered = storage("get", PROJECT_KEY);
  state.project = state.projects.find((p) => p.id === remembered) || state.projects[0];
  const select = document.getElementById("project");
  select.replaceChildren(...state.projects.map((p) =>
    el("option", { value: p.id, selected: p.id === state.project.id }, `${p.name} (${p.role})`)));
  document.getElementById("signin").hidden = true;
  document.getElementById("nav").hidden = false;
  document.getElementById("view").hidden = false;
  notice("");
  show("overview");
}

function signOut(message) {
  storage("remove", TOKEN_KEY);
  state.token = null;
  state.project = null;
  clearInterval(state.timer);
  document.getElementById("signin").hidden = false;
  document.getElementById("nav").hidden = true;
  document.getElementById("view").hidden = true;
  document.getElementById("view").replaceChildren();
  notice(message || "", message ? "warn" : "");
}

// ---- views -------------------------------------------------------------

const views = {};

async function show(view, arg) {
  state.view = view;
  clearInterval(state.timer);
  for (const button of document.querySelectorAll("#nav button[data-view]")) {
    button.classList.toggle("active", button.dataset.view === view);
  }
  const root = document.getElementById("view");
  try {
    await views[view](root, arg);
  } catch (error) {
    if (error.status !== 401) notice(error.message, "bad");
  }
  if (["overview", "runs", "alerts"].includes(view)) {
    // The monitoring views follow live state.
    state.timer = setInterval(() => views[view](root, arg).catch(() => {}), REFRESH_MS);
  }
}

function heading(title, ...extra) {
  return el("div", { class: "heading" }, el("h1", {}, title), ...extra);
}

function tableOf(headers, rows, empty) {
  if (!rows.length) return el("p", { class: "empty" }, empty);
  return el("div", { class: "scroll" }, el("table", {},
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows)));
}

function runRow(run) {
  return el("tr", { class: run.status === "failed" ? "row-bad" : "" },
    el("td", { class: "mono" }, run.run_id.slice(0, 8)),
    el("td", {}, run.kind),
    el("td", {}, runBadge(run.status)),
    el("td", {}, when(run.created_at)),
    el("td", {}, run.phases.map((p) => el("span", { class: `chip ${COMPARISON_KIND[p.comparison] || ""}` }, `${p.phase}: ${p.comparison}`))),
    el("td", { class: "error" }, run.last_error || ""));
}

views.overview = async (root) => {
  const data = await api(projectPath("/overview"));
  const counts = data.counts;
  const open = counts.findings_by_status.open + counts.findings_by_status.triaged + (counts.findings_by_status.in_progress || 0);
  const pending = data.rules.filter((r) => !r.approved);
  root.replaceChildren(
    heading(data.project.name),
    data.scope
      ? el("div", { class: "panel" },
        el("h2", {}, `Authorized scope: revision ${data.scope.number}`),
        el("p", {}, data.scope.rules.filter((r) => r.effect === "include").map((r) => r.pattern).join(", ")),
        el("p", { class: "hint" }, `Authorized by ${data.scope.authorization.granted_by} `
          + `(${data.scope.authorization.kind}: ${data.scope.authorization.reference})`))
      : el("div", { class: "panel warn" }, el("h2", {}, "No authorized scope"),
        el("p", {}, "Nothing is scanned until an owner publishes a scope revision with its authorization.")),
    el("div", { class: "tiles" },
      tile("Assets", Object.values(counts.assets).reduce((a, b) => a + b, 0)),
      tile("Open findings", open, open ? "bad" : "ok"),
      tile("Resolved (verified)", counts.findings_by_status.resolved, "ok"),
      tile("Critical / high open", counts.open_findings_by_severity.critical + counts.open_findings_by_severity.high,
        counts.open_findings_by_severity.critical + counts.open_findings_by_severity.high ? "bad" : "")),
    pending.length
      ? el("div", { class: "panel warn" }, el("h2", {}, "Detection rules pending maintainer approval"),
        el("p", {}, "These rules are listed but never run, so they cannot open or resolve findings: "
          + pending.map((r) => r.id).join(", ")))
      : null,
    el("h2", {}, "Latest runs"),
    data.runs_available
      ? tableOf(["Run", "Kind", "Status", "Created", "Phases", "Error"], data.latest_runs.map(runRow), "No runs yet.")
      : el("p", { class: "empty" }, "The monitoring runtime is not installed on this server."));
};

function tile(label, value, kind) {
  return el("div", { class: `tile ${kind || ""}` }, el("div", { class: "value" }, String(value)),
    el("div", { class: "label" }, label));
}

views.runs = async (root) => {
  const page = await api(projectPath("/runs?limit=50"));
  const start = can("operate")
    ? el("button", {
      onclick: async () => {
        try {
          state.scanKey = state.scanKey || crypto.randomUUID();
          const run = await api(projectPath("/runs"), { method: "POST", body: { reason: "started from dashboard",
            idempotency_key: state.scanKey, reuse_active: true } });
          state.scanKey = null;
          notice(`Queued run ${run.run_id.slice(0, 8)}.`, "ok");
          show("runs");
        } catch (error) { notice(error.message, "bad"); }
      },
    }, "Start run")
    : null;
  root.replaceChildren(heading("Runs", start),
    tableOf(["Run", "Kind", "Status", "Created", "Phases", "Error"], page.items.map(runRow), "No runs yet."));
};

function describeChange(change) {
  const kind = change.type || "change";
  const key = change.key || change.target || "";
  const before = change.before;
  const after = change.after;
  const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
  if (kind.startsWith("finding.")) {
    const f = isObject(after) ? after : isObject(before) ? before : {};
    return `${kind} [${f.severity || "?"}] ${f.title || key} on ${f.host || "?"} (${f.check_id || "?"})`;
  }
  if (kind.startsWith("asset.")) return `${kind} ${key}`;
  const show = (value) => JSON.stringify(value === undefined ? null : value);
  if (isObject(before) && isObject(after)) {
    const names = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    const diffs = names.filter((n) => show(before[n]) !== show(after[n])).map((n) => `${n}: ${show(before[n])} -> ${show(after[n])}`);
    return `${kind} ${key} ${diffs.join("; ")}`;
  }
  return `${kind} ${key}: ${show(before)} -> ${show(after)}`;
}

views.alerts = async (root) => {
  const page = await api(projectPath("/alerts?limit=50"));
  root.replaceChildren(heading("Alerts"), page.items.length
    ? el("ul", { class: "feed" }, page.items.map((alert) => el("li", {},
      el("div", {}, badge(alert.event_type, alert.event_type === "monitor.run_failed" ? "bad" : "warn"), " ",
        when(alert.created_at), ` to ${alert.channel} (${alert.status})`,
        alert.last_error ? el("span", { class: "error" }, ` ${alert.last_error}`) : null),
      el("ul", {}, (alert.payload.changes || []).slice(0, 50).map((c) => el("li", { class: "mono" }, describeChange(c)))))))
    : el("p", { class: "empty" }, "No alerts yet."));
};

async function paged(root, title, path, render, headers, empty, controls = null) {
  const key = `${state.project.id}:${path}`;
  const cursors = state.cursor[key] || (state.cursor[key] = [null]);
  const cursor = cursors[cursors.length - 1];
  const separator = path.includes("?") ? "&" : "?";
  const page = await api(projectPath(path + separator + "limit=50" + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "")));
  const prev = el("button", { disabled: cursors.length < 2, onclick: () => { cursors.pop(); paged(root, title, path, render, headers, empty, controls); } }, "Previous");
  const next = el("button", { disabled: !page.next_cursor, onclick: () => { cursors.push(page.next_cursor); paged(root, title, path, render, headers, empty, controls); } }, "Next");
  root.replaceChildren(heading(title), ...(controls ? [controls] : []), tableOf(headers, page.items.map(render), empty), el("div", { class: "pager" }, prev, next));
}

function filtersFor(view, fields) {
  const key = `${state.project.id}:${view}`;
  const values = state.filters[key] || (state.filters[key] = {});
  const inputs = fields.map((name) => el("input", { name, placeholder: name, "aria-label": name, value: values[name] || "" }));
  const form = el("form", { class: "actions", onsubmit: (event) => {
    event.preventDefault();
    for (const input of inputs) values[input.name] = input.value.trim();
    show(view);
  } }, ...inputs, el("button", { type: "submit" }, "Filter"));
  const query = new URLSearchParams(Object.entries(values).filter(([, value]) => value));
  return { form, query: query.toString() };
}

async function exportReport(dataset, format) {
  try {
    const response = await api(projectPath(`/exports?dataset=${dataset}&format=${format}&limit=200`), { raw: true });
    const url = URL.createObjectURL(new Blob([await response.arrayBuffer()], { type: "application/octet-stream" }));
    const link = el("a", { href: url, download: `watchtower-${dataset}.${format}` });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    notice(response.headers.get("X-Next-Cursor") ? "Exported the first 200 records. Use paginated API/CLI exports for the remainder." : "Export downloaded.", "info");
  } catch (error) { notice(error.message, "bad"); }
}

views.assets = (root) => {
  const filters = filtersFor("assets", ["search", "owner", "tag", "technology"]);
  filters.form.append(el("button", { type: "button", onclick: () => exportReport("assets", "csv") }, "Export inventory CSV (up to 200)"));
  return paged(root, "Inventory", "/assets?" + filters.query, (asset) => {
  const http = asset.last_http || {};
  return el("tr", {},
    el("td", { class: "mono" }, el("button", { onclick: () => show("asset", asset.id) }, asset.value)),
    el("td", {}, asset.kind),
    el("td", {}, badge(asset.authorization, asset.authorization === "authorized" ? "ok" : "warn")),
    el("td", { class: "mono" }, asset.addresses.join(", ") || "-"),
    el("td", {}, text(http.status_code || http.outcome)),
    el("td", {}, text(http.title)),
    el("td", {}, when(asset.last_seen_at)));
}, ["Asset", "Kind", "Authorization", "Addresses", "HTTP", "Title", "Last seen"], "No assets yet.", filters.form);
};

views.findings = (root) => {
  const filters = filtersFor("findings", ["severity", "confidence", "priority", "status", "owner"]);
  filters.form.append(el("button", { type: "button", onclick: () => exportReport("findings", "json") }, "Export findings JSON (up to 200)"));
  return paged(root, "Findings", "/findings?" + filters.query, (finding) => el("tr", {
  class: "link", tabindex: 0,
  onclick: () => show("finding", finding.id),
  onkeydown: (event) => { if (event.key === "Enter") show("finding", finding.id); },
},
el("td", {}, badge(finding.severity, SEVERITY[finding.severity])),
el("td", {}, finding.status),
el("td", {}, remediationBadge(finding.remediation)),
el("td", {}, finding.title),
el("td", { class: "mono" }, finding.target + finding.location),
el("td", {}, when(finding.last_seen_at))),
["Severity", "Status", "Remediation", "Title", "Where", "Last seen"], "No findings.", filters.form);
};

views.finding = async (root, findingId) => {
  const f = await api(projectPath(`/findings/${encodeURIComponent(findingId)}`));
  const actions = el("div", { class: "actions" });
  if (can("operate")) {
    actions.append(el("button", {
      onclick: async () => {
        try {
          const run = await api(projectPath(`/findings/${encodeURIComponent(f.id)}/retest`), { method: "POST", body: {} });
          notice(`Retest queued as run ${run.run_id.slice(0, 8)}. Watch it under Runs.`, "ok");
        } catch (error) { notice(error.message, "bad"); }
      },
    }, "Request retest"));
    const choices = { open: ["triaged", "in_progress", "accepted_risk", "false_positive"], triaged: ["open", "in_progress", "accepted_risk", "false_positive"],
      in_progress: ["triaged", "accepted_risk", "false_positive"],
      accepted_risk: ["triaged"], false_positive: ["triaged"], resolved: [] }[f.status] || [];
    for (const status of choices) {
      actions.append(el("button", {
        class: "quiet",
        onclick: async () => {
          let reason = "";
          if (status === "accepted_risk" || status === "false_positive") {
            reason = window.prompt(`Reason for ${status.replace("_", " ")}:`) || "";
            if (!reason.trim()) return;
          }
          try {
            await api(projectPath(`/findings/${encodeURIComponent(f.id)}/status`), { method: "POST", body: { status, reason } });
            show("finding", f.id);
          } catch (error) { notice(error.message, "bad"); }
        },
      }, `Mark ${status.replace("_", " ")}`));
    }
    actions.append(el("button", { onclick: async () => {
      const owner = window.prompt("Owner", f.owner || "");
      if (owner === null) return;
      const remediation_notes = window.prompt("Remediation notes", f.remediation_notes || "");
      if (remediation_notes === null) return;
      const mitigation_notes = window.prompt("Temporary mitigation notes (separate from remediation)", f.mitigation_notes || "");
      if (mitigation_notes === null) return;
      try {
        await api(projectPath(`/findings/${f.id}`), { method: "PATCH", body: { owner, remediation_notes, mitigation_notes } });
        show("finding", f.id);
      } catch (error) { notice(error.message, "bad"); }
    } }, "Owner and notes"));
    actions.append(el("button", { onclick: async () => {
      try { await api(projectPath(`/findings/${f.id}/prioritize`), { method: "POST" }); show("finding", f.id); }
      catch (error) { notice(error.message, "bad"); }
    } }, "Recompute priority"));
    actions.append(el("button", { onclick: async () => {
      const priority = window.prompt("Priority override: P1-P4, or clear");
      if (!priority) return;
      const reason = window.prompt("Reason for override");
      if (!reason) return;
      try { await api(projectPath(`/findings/${f.id}`), { method: "PATCH", body: { priority, reason } }); show("finding", f.id); }
      catch (error) { notice(error.message, "bad"); }
    } }, "Override priority"));
  }
  const evidence = el("div", { class: "evidence" });
  root.replaceChildren(
    el("p", {}, el("button", { class: "quiet", onclick: () => show("findings") }, "Back to findings")),
    heading(f.title, badge(f.severity, SEVERITY[f.severity])),
    el("div", { class: "panel" },
      el("dl", { class: "facts" },
        fact("Where", f.target + f.location), fact("Check", `${f.check_id} v${f.rule_version} (${f.confidence})`),
        fact("Workflow status", f.status), fact("Remediation", remediationBadge(f.remediation)),
        fact("Owner", f.owner || "Unassigned"), fact("Remediation notes", f.remediation_notes || "-"),
        fact("Mitigation notes", f.mitigation_notes || "-"), fact("Risk acceptance expiry", when(f.risk_expires_at)),
        fact("Priority and reasons", JSON.stringify(f.priority_override || f.priority || { level: "not computed" })),
        fact("Detection", `${f.detection.state}, last outcome ${f.detection.last_outcome} at ${when(f.detection.last_outcome_at)}`),
        fact("First / last seen", `${when(f.first_seen_at)} / ${when(f.last_seen_at)}`),
        fact("Seen / recurred", `${f.occurrences} / ${f.recurrences}`),
        f.cves.length ? fact("CVEs", f.cves.join(", ")) : null),
      actions),
    el("h2", {}, "History"),
    tableOf(["When", "Event", "Details"], f.history.slice().reverse().map((event) => {
      const details = Object.entries(event).filter(([k, v]) => !["at", "event"].includes(k) && v !== null && v !== "");
      return el("tr", { class: /failed|inconclusive/.test(event.event) ? "row-bad" : "" },
        el("td", {}, when(event.at)), el("td", {}, event.event),
        el("td", { class: "mono" }, details.map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("  ")));
    }), "No history."),
    el("h2", {}, "Evidence"),
    f.evidence.length
      ? el("ul", { class: "feed" }, f.evidence.map((item) => el("li", {},
        `${when(item.created_at)}  ${item.size_bytes} bytes  ${item.description} `,
        el("button", { class: "quiet", onclick: () => viewEvidence(item, evidence) }, "View"),
        el("button", { class: "quiet", onclick: () => downloadEvidence(item) }, "Download"))))
      : el("p", { class: "empty" }, "No evidence stored."),
    evidence);
};

views.asset = async (root, assetId) => {
  const detail = await api(projectPath(`/assets/${encodeURIComponent(assetId)}`));
  const asset = detail.asset;
  const actions = el("div", { class: "actions" });
  if (can("operate")) actions.append(el("button", { onclick: async () => {
    const owner = window.prompt("Asset owner", asset.attributes.owner || "");
    if (owner === null) return;
    const tags = window.prompt("Tags, comma-separated", (asset.attributes.tags || []).join(","));
    if (tags === null) return;
    const importance = window.prompt("Importance: low, normal, high, critical", asset.attributes.importance || "normal");
    if (importance === null) return;
    try {
      await api(projectPath(`/assets/${asset.id}`), { method: "PATCH", body: { owner, tags: tags.split(",").map((v) => v.trim()).filter(Boolean), importance } });
      show("asset", asset.id);
    } catch (error) { notice(error.message, "bad"); }
  } }, "Edit owner, tags and importance"));
  root.replaceChildren(heading(asset.value), actions,
    el("pre", { class: "captured" }, JSON.stringify(asset.attributes, null, 2)),
    el("h2", {}, "Observation timeline"),
    tableOf(["When", "Kind", "Source", "Evidence"], detail.observations.map((o) => el("tr", {},
      el("td", {}, when(o.observed_at)), el("td", {}, o.kind), el("td", {}, o.source),
      el("td", {}, el("pre", { class: "captured" }, JSON.stringify(o.data, null, 2))))), "No observations."));
};

views.candidates = (root) => paged(root, "Candidate provenance (ownership does not grant permission)", "/candidates", (asset) => el("tr", {},
  el("td", {}, el("button", { onclick: () => show("asset", asset.id) }, asset.value)),
  el("td", {}, asset.attributes.ownership_state || "uncertain"),
  el("td", {}, asset.attributes.authorization_status || asset.authorization),
  el("td", {}, JSON.stringify(asset.attributes.provenance || {}))),
["Candidate", "Ownership", "Authorization", "Sources"], "No candidates.");

views.changes = (root) => paged(root, "Exposure changes", "/changes", (change) => {
  const ack = change.acknowledgement;
  return el("tr", {}, el("td", {}, when(change.created_at)), el("td", {}, change.target), el("td", {}, change.phase),
    el("td", {}, el("pre", { class: "captured" }, JSON.stringify(change.changes, null, 2))),
    el("td", {}, ack ? `Acknowledged: ${ack.reason}` : can("operate") ? el("button", { onclick: async () => {
      const reason = window.prompt("Acknowledgement reason");
      if (!reason || !reason.trim()) return;
      try { await api(projectPath(`/changes/${change.id}/acknowledge`), { method: "POST", body: { reason } }); show("changes"); }
      catch (error) { notice(error.message, "bad"); }
    } }, "Acknowledge") : "Unacknowledged"));
}, ["When", "Target", "Phase", "Before / after", "Acknowledgement"], "No changes since baseline.");

views.intelligence = async (root) => {
  const data = await api(projectPath("/intelligence?limit=50"));
  root.replaceChildren(heading("Threat intelligence"),
    el("p", { class: "hint" }, "Technology hints suggest applicability; these are review items, not confirmed vulnerabilities. No scan is automatically started."),
    tableOf(["Feed", "Freshness", "Last success", "Details"], data.feeds.map((f) => el("tr", {},
      el("td", {}, f.source), el("td", {}, badge(f.state, f.state === "fresh" ? "ok" : "warn")),
      el("td", {}, when(f.fetched_at)), el("td", {}, f.last_error || f.reason))), "No feed status."),
    tableOf(["Asset", "Advisory", "Product / version", "Applicability", "Reason"], data.items.map((r) => el("tr", {},
      el("td", {}, r.asset), el("td", {}, r.advisory_id), el("td", {}, `${r.product} ${r.version || "unknown"}`),
      el("td", {}, r.applicability), el("td", {}, r.reason))), "No applicable advisories in this inventory page. Missing feeds provide no assurance."),
    el("p", { class: "hint" }, data.next_asset ? `More assets remain after ${data.next_asset}; use intelligence correlate --after-asset for the next page.` : "All assets in this page reviewed."));
};

views.settings = async (root) => {
  const data = await api(projectPath("/settings"));
  root.replaceChildren(heading("Settings and coverage"),
    el("p", { class: "hint" }, "Read-only effective configuration. Change profiles/environment and restart services to apply settings. Rule approval remains a reviewed manifest change."),
    el("pre", { class: "captured" }, JSON.stringify(data, null, 2)));
};

function fact(label, value) {
  return [el("dt", {}, label), el("dd", {}, value)];
}

async function viewEvidence(item, target) {
  try {
    const data = await api(projectPath(`/evidence/${encodeURIComponent(item.id)}`));
    // Redacted content captured from the target, shown as inert text.
    target.replaceChildren(el("h3", {}, `Evidence ${item.id}`),
      el("pre", { class: "captured" }, JSON.stringify(data.content, null, 2)));
  } catch (error) { notice(error.message, "bad"); }
}

async function downloadEvidence(item) {
  try {
    const response = await api(projectPath(`/evidence/${encodeURIComponent(item.id)}/download`), { raw: true });
    const blob = new Blob([await response.arrayBuffer()], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const link = el("a", { href: url, download: `evidence-${item.id}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { notice(error.message, "bad"); }
}

views.scope = async (root) => {
  const scope = await api(projectPath("/scope"));
  const parts = [heading("Scope")];
  if (!scope.history.length) parts.push(el("p", { class: "empty" }, "No scope revisions published."));
  for (const revision of scope.history) {
    parts.push(el("div", { class: `panel ${revision.revocation ? "muted" : ""}` },
      el("h2", {}, `Revision ${revision.number} `, revision.revocation ? badge("REVOKED", "bad") : badge("in force", "ok")),
      el("p", { class: "hint" }, `${when(revision.created_at)}, ports ${revision.permitted_ports}, authorized by `
        + `${revision.authorization.granted_by} (${revision.authorization.kind}: ${revision.authorization.reference})`),
      el("p", { class: "hint" }, `Authorization window: ${when(revision.authorization.valid_from)} to ${when(revision.authorization.valid_until)}`),
      el("pre", { class: "mono" }, JSON.stringify(revision.execution_policy, null, 2)),
      el("ul", {}, revision.rules.map((r) => el("li", { class: "mono" }, `${r.effect} ${r.pattern}${r.ports ? " ports " + r.ports : ""}`))),
      revision.revocation ? el("p", { class: "error" }, `Revoked ${when(revision.revocation.revoked_at)}: ${revision.revocation.reason}`) : null));
  }
  if (can("manage_scope")) parts.push(publishForm());
  root.replaceChildren(...parts);
};

function publishForm() {
  const field = (id, label, attrs) => [el("label", { for: id }, label), el("input", { id, ...attrs })];
  const form = el("form", { class: "panel" },
    el("h2", {}, "Publish a new revision"),
    field("includes", "Include (comma-separated: example.com, *.example.com, 10.0.0.0/24)", { required: true }),
    field("excludes", "Exclude (optional)", {}),
    field("ports", "Permitted ports (optional, e.g. 80,443)", {}),
    el("label", { for: "auth-kind" }, "Authorization"),
    el("select", { id: "auth-kind" }, ["asset_owner", "contract", "internal_approval", "bug_bounty_program",
      "vulnerability_disclosure_program"].map((k) => el("option", { value: k }, k))),
    field("auth-ref", "Reference (program URL, contract id, approval ticket)", { required: true }),
    field("auth-by", "Granted by", { required: true }),
    el("details", {}, el("summary", {}, "Request limits and authorization window"),
      field("auth-from", "Valid from (optional, local time)", { type: "datetime-local" }),
      field("auth-until", "Valid until (optional, local time)", { type: "datetime-local" }),
      field("schemes", "Allowed schemes (comma-separated)", { value: "https,http", required: true }),
      field("allow-paths", "Allowed path prefixes (comma-separated)", { value: "/", required: true }),
      field("exclude-paths", "Excluded path prefixes (comma-separated)", {}),
      field("check-kinds", "Allowed check classes (http,component; empty disables checks)", { value: "http,component" }),
      field("request-budget", "Maximum target requests per run", { type: "number", min: "1", max: "10000000", value: "10000", required: true }),
      el("p", { class: "hint" }, "Discovery probes the first allowed path. Each rule's fixed path is checked independently; this does not crawl all paths.")),
    el("label", { class: "check" }, el("input", { id: "attest", type: "checkbox", required: true }),
      " I am authorized to test every included target under this authorization."),
    el("button", { type: "submit" }, "Publish"));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const list = (id) => form.querySelector(`#${id}`).value.split(",").map((v) => v.trim()).filter(Boolean);
    try {
      await api(projectPath("/scope"), {
        method: "POST",
        body: {
          includes: list("includes"), excludes: list("excludes"),
          permitted_ports: form.querySelector("#ports").value.trim() || null,
          authorization: { kind: form.querySelector("#auth-kind").value, reference: form.querySelector("#auth-ref").value,
            granted_by: form.querySelector("#auth-by").value,
            valid_from: form.querySelector("#auth-from").value ? new Date(form.querySelector("#auth-from").value).toISOString() : null,
            valid_until: form.querySelector("#auth-until").value ? new Date(form.querySelector("#auth-until").value).toISOString() : null },
          execution_policy: { allowed_schemes: list("schemes"), allowed_paths: list("allow-paths"),
            excluded_paths: list("exclude-paths"), allowed_check_kinds: list("check-kinds"),
            max_requests_per_run: Number(form.querySelector("#request-budget").value) },
          attest_authorized: form.querySelector("#attest").checked,
        },
      });
      notice("Scope revision published.", "ok");
      show("scope");
    } catch (error) { notice(error.message, "bad"); }
  });
  return form;
}

// ---- AI review -----------------------------------------------------------
//
// Optional, local-only AI review. Candidates, quotes, explanations and examples
// are untrusted data (they come from scanned sites and from a model) and are
// only ever inserted as text. The server enforces every permission; the
// buttons shown here only follow the role.

const MEMORY_SENTENCE = "Approved examples can guide future reviews in this project. This does not retrain the model.";
const AI_STATUS = { completed: "ok", partial: "warn", failed: "bad", cancelled: "muted", queued: "info", running: "info" };
const CATEGORY_LABELS = {
  dom_xss_sink: "DOM XSS sink", open_redirect: "Open redirect", sensitive_data_in_client: "Sensitive data in client",
  insecure_token_storage: "Insecure storage of tokens", weak_csp: "Weak CSP", cors_misconfiguration: "CORS misconfiguration",
  outdated_library: "Outdated library", exposed_endpoint: "Exposed endpoint", debug_artifact: "Debug or test artifact",
  other: "Other",
};
const CLAIM_LABELS = { observed_fact: "observed fact", model_inference: "model inference",
  user_reviewed: "user-reviewed conclusion", verified_by_check: "verified by an existing check" };

function aiBadge(status) {
  return badge(status.toUpperCase(), AI_STATUS[status] || "muted");
}

function categoryLabel(category) {
  return CATEGORY_LABELS[category] || category;
}

function aiTabs(active) {
  const tabs = [["ai", "Results"], ["aiMemory", "Approved examples"]];
  if (can("manage_memory")) tabs.splice(1, 0, ["aiPending", "Awaiting approval"]);
  tabs.push(["aiAdvanced", "Model status and Advanced"]);
  return el("div", { class: "controls" }, tabs.map(([view, label]) =>
    el("button", { class: view === active ? "active" : "", onclick: () => show(view) }, label)));
}

async function aiStart(kind) {
  try {
    if (kind === "collect") {
      if (!confirm("Collect in-scope pages and scripts for review? Third-party scripts are recorded, not fetched, and nothing is executed.")) return;
      const result = await api(projectPath("/ai/collections"), { method: "POST", body: { review: true } });
      notice(`Collection run ${result.run.run_id.slice(0, 8)} queued; a review follows. An AI worker must be running.`, "ok");
    } else {
      const status = await api(projectPath("/ai/status"));
      const result = await api(projectPath("/ai/reviews"), { method: "POST", body: { use_model: status.enabled } });
      notice(`Review ${String(result.analysis_id).slice(0, 8)} queued` + (status.enabled ? "." : " (pre-analysis only: AI is disabled)."), "ok");
    }
    show("ai");
  } catch (error) { notice(error.message, "bad"); }
}

async function aiPreview(root) {
  const plan = await api(projectPath("/ai/preview"), { method: "POST", body: {} });
  root.hidden = false;
  fill(root,
    el("h2", {}, "Preview what will be sent"),
    el("p", {}, plan.visible),
    tableOf(["Kind", "URL", "How it was obtained", "Bytes", "Redacted", "Sent"], plan.files.map((f) => el("tr", {},
      el("td", {}, f.kind), el("td", { class: "mono" }, f.url), el("td", {}, f.origin), el("td", {}, String(f.size_bytes)),
      el("td", {}, String(f.redactions)), el("td", {}, f.sent ? "yes" : "no"))), "Nothing to review yet."),
    el("p", { class: "hint" }, `${plan.chunks} chunk(s), about ${plan.token_estimate} tokens, ${plan.redactions} redaction(s). `
      + `Model ${plan.model}, ${plan.num_ctx}-token context. Content goes only to the configured local model.`),
    plan.files.length ? el("button", { onclick: () => aiStart("review") }, plan.enabled ? "Send to the local model" : "Run pre-analysis only") : null);
}

views.ai = async (root) => {
  const [status, results] = await Promise.all([api(projectPath("/ai/status")), api(projectPath("/ai/reviews?limit=50"))]);
  const previewBox = el("div", { class: "panel" });
  const actions = can("operate") ? el("div", { class: "controls" },
    el("button", { onclick: () => aiPreview(previewBox).catch((e) => notice(e.message, "bad")) }, "Review latest scan"),
    status.enabled ? el("button", { onclick: () => aiStart("collect") }, "Collect scripts for review") : null) : null;
  fill(root,
    heading("AI Review", badge(status.enabled ? "ENABLED" : "DISABLED", status.enabled ? "ok" : "muted")),
    aiTabs("ai"),
    status.enabled ? null : el("p", { class: "panel warn" }, "AI review is disabled. Pre-analysis still works; scans and findings are unaffected."),
    el("p", { class: "hint" }, `Model ${status.model}. Project memory: ${status.memory.approved} approved example(s). ${MEMORY_SENTENCE}`),
    actions, previewBox,
    tableOf(["Review", "Status", "Mode", "Supported", "Unsupported", "Outdated", "Created"], results.map((r) =>
      el("tr", { class: r.status === "failed" ? "row-bad" : "" },
        el("td", {}, el("button", { onclick: () => show("aiReview", r.id) }, r.id.slice(0, 8))),
        el("td", {}, aiBadge(r.status)), el("td", {}, r.mode === "model" ? "model" : "pre-analysis only"),
        el("td", {}, String(r.candidates.supported)), el("td", {}, String(r.candidates.unsupported)),
        el("td", {}, r.outdated ? badge("MAY BE OUTDATED", "warn") : ""), el("td", {}, when(r.created_at)))),
    "No AI reviews yet."));
  previewBox.hidden = true;
};

function highlighted(citation) {
  return el("div", { class: "citation" },
    el("div", { class: "hint" }, `line ${citation.line}${citation.line_end !== citation.line ? `-${citation.line_end}` : ""}, `
      + `bytes ${citation.byte_start}-${citation.byte_end}`
      + (citation.location_corrected ? ` (model said line ${citation.stated_line}; corrected)` : "")
      + (citation.contains_redaction ? ", contains redacted text" : "")),
    el("pre", {}, el("mark", {}, citation.quote)),
    el("div", { class: "hint mono" }, `redacted sha256 ${text(citation.redacted_sha256)} / original sha256 ${text(citation.original_sha256)}`));
}

function feedbackForm(candidate) {
  const form = el("form", { class: "panel" },
    el("h3", {}, "Your feedback"),
    el("label", {}, "Feedback",
      el("select", { name: "kind" },
        el("option", { value: "looks_correct" }, "Looks correct (your review, not a verification)"),
        el("option", { value: "false_positive" }, "False positive"),
        el("option", { value: "edit" }, "Edit analysis"))),
    el("label", {}, "Reason (required for a false positive: why does it not apply here?)", el("textarea", { name: "reason", maxlength: 4000 })),
    el("label", {}, "Corrected explanation (edit only)", el("textarea", { name: "explanation", maxlength: 4000 })),
    el("label", {}, "Corrected category (edit only)", el("select", { name: "category" },
      el("option", { value: "" }, "unchanged"),
      Object.entries(CATEGORY_LABELS).map(([value, label]) => el("option", { value }, label)))),
    el("label", {}, "When does it apply? (edit only)", el("input", { name: "applicability", maxlength: 4000 })),
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "memory" }), " Submit as a project-memory example for approval"),
    el("p", { class: "hint" }, MEMORY_SENTENCE),
    el("label", {}, "Context for the example (optional)", el("input", { name: "context", maxlength: 4000 })),
    el("button", { type: "submit" }, "Submit feedback"));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const value = (name) => form.elements[name].value.trim();
    try {
      const result = await api(projectPath(`/ai/candidates/${encodeURIComponent(candidate.id)}/feedback`), {
        method: "POST",
        body: { kind: value("kind"), reason: value("reason"), explanation: value("explanation") || null,
          category: value("category") || null, applicability: value("applicability") || null,
          submit_memory: form.elements.memory.checked, context: value("context") },
      });
      notice(result.example_id ? "Feedback recorded and submitted for approval. The finding's status is unchanged."
        : "Feedback recorded. The finding's status is unchanged.", "ok");
      show("aiReview", candidate.analysis);
    } catch (error) { notice(error.message, "bad"); }
  });
  return form;
}

function candidateCard(candidate, analysisId) {
  const data = candidate.data;
  return el("div", { class: `panel ${candidate.supported ? "" : "muted-panel"}` },
    el("h2", {}, candidate.supported ? "" : "Unsupported: ", data.title || candidate.title),
    el("p", {}, badge(categoryLabel(candidate.category), "info"), " ", badge(`confidence ${candidate.confidence}`, "muted"),
      " ", badge(`citations ${candidate.citation_status.replace("_", " ")}`, candidate.citation_status === "verified" ? "ok" : "warn")),
    candidate.supported ? null : el("p", { class: "hint" }, "No verified evidence, so this is not shown as an issue."),
    el("p", {}, data.explanation),
    el("p", { class: "hint" }, `Confidence reason: ${text(data.confidence_reason)}`),
    data.affected ? fact("Affected", data.affected) : null,
    (data.citations || []).map(highlighted),
    (data.removed_citations || []).length ? el("p", { class: "hint" }, `Removed ${data.removed_citations.length} citation(s) that were not found in the reviewed content.`) : null,
    el("div", {}, (data.claims || []).map((claim) => el("div", {}, badge(CLAIM_LABELS[claim.claim_type] || claim.claim_type, claim.claim_type === "observed_fact" ? "ok" : "muted"), " ", claim.text))),
    (data.assumptions || []).length ? el("div", {}, el("h3", {}, "Assumptions"), el("ul", {}, data.assumptions.map((a) => el("li", {}, a)))) : null,
    (data.missing_context || []).length ? el("div", {}, el("h3", {}, "Missing context"), el("ul", {}, data.missing_context.map((a) => el("li", {}, a)))) : null,
    (data.validation_steps || []).length ? el("div", {}, el("h3", {}, "Suggested manual checks (on your own site)"), el("ul", {}, data.validation_steps.map((a) => el("li", {}, a)))) : null,
    data.suggested_severity && data.suggested_severity !== "none"
      ? el("p", { class: "hint" }, `Suggested severity: ${data.suggested_severity} (unverified; never written to findings)`) : null,
    (data.flags || []).map((flag) => el("p", { class: "hint warn" }, flag)),
    candidate.matched_finding_id ? el("p", {}, el("button", { onclick: () => show("finding", candidate.matched_finding_id) }, "Related finding")) : null,
    (data.examples_used || []).length ? el("div", {}, el("h3", {}, "Project memory used"), el("ul", {}, data.examples_used.map((used) =>
      el("li", {}, `Example ${used.id.slice(0, 8)} revision ${used.revision}. Why it was used: ${text(used.why_retrieved)}. How it affected the result: ${text(used.effect)}`)))) : null,
    candidate.feedback.length ? el("div", {}, el("h3", {}, "Feedback"), el("ul", {}, candidate.feedback.map((f) =>
      el("li", {}, `${f.kind.replace("_", " ")} ${when(f.created_at)}` + (f.memory_state ? `, memory example ${f.memory_state}` : "") + (f.reason ? `: ${f.reason}` : ""))))) : null,
    can("operate") ? feedbackForm({ ...candidate, analysis: analysisId }) : null);
}

views.aiReview = async (root, id) => {
  const detail = await api(projectPath(`/ai/reviews/${encodeURIComponent(id)}`));
  const coverage = detail.coverage || {};
  const facts = (detail.preanalysis || {}).facts || [];
  const reanalyze = can("operate") ? el("button", { onclick: async () => {
    try {
      await api(projectPath("/ai/reviews"), { method: "POST", body: { reanalysis_of: detail.id } });
      notice("Reanalysis queued; this review stays unchanged.", "ok");
    } catch (error) { notice(error.message, "bad"); }
  } }, "Request reanalysis") : null;
  fill(root,
    heading(`AI review ${detail.id.slice(0, 8)}`, aiBadge(detail.status), reanalyze),
    aiTabs("ai"),
    detail.outdated ? el("p", { class: "panel warn" }, `May be outdated: ${text(detail.outdated_reason)}. Request a reanalysis to refresh it.`) : null,
    detail.error ? el("p", { class: "panel bad" }, detail.error) : null,
    el("div", { class: "panel" },
      el("h2", {}, "What this review could and could not see"),
      el("p", {}, coverage.visible || ""),
      el("ul", {}, [...(coverage.not_visible || []), ...(coverage.model_notes || []), coverage.redaction_note].filter(Boolean)
        .map((line) => el("li", {}, line))),
      (coverage.skipped || []).length ? el("p", { class: "hint" }, `${coverage.skipped.length} part(s) left out: `
        + coverage.skipped.slice(0, 5).map((s) => `${s.url || "scan evidence"} lines ${s.lines.join("-")} (${s.reason})`).join("; ")) : null,
      (coverage.conflicting_examples || []).length ? el("p", { class: "hint warn" }, "Conflicting approved examples were not used; an owner should review them.") : null,
      el("p", { class: "hint" }, `Model ${text(detail.model)}, prompt ${detail.prompt_version}, ${detail.mode === "model" ? "model review" : "pre-analysis only"}.`)),
    el("h2", {}, "Candidates"),
    detail.candidates.length ? detail.candidates.map((c) => candidateCard(c, detail.id)) : el("p", { class: "empty" }, "No candidates."),
    el("h2", {}, `Pre-analysis facts (${facts.length})`),
    el("p", { class: "hint" }, "Found by deterministic static checks before any model call. They are observations, not findings."),
    tableOf(["Category", "Fact", "Line", "Excerpt"], facts.slice(0, 200).map((f) => el("tr", {},
      el("td", {}, categoryLabel(f.category)), el("td", {}, f.detail), el("td", {}, text(f.line)),
      el("td", { class: "mono" }, f.excerpt || ""))), "No facts."),
    ((detail.preanalysis || {}).advisories || []).length ? el("div", {}, el("h2", {}, "Advisory matches (observed facts)"),
      tableOf(["Library", "Version", "Advisory", "Applicability", "Reason"], detail.preanalysis.advisories.map((a) => el("tr", {},
        el("td", {}, a.library), el("td", {}, text(a.version)), el("td", {}, a.advisory), el("td", {}, a.applicability),
        el("td", {}, a.reason))), "")) : null);
};

async function memoryActions(example) {
  const act = async (action, body) => {
    try {
      await api(projectPath(`/ai/memory/${encodeURIComponent(example.id)}/${action}`), { method: "POST", body: body || {} });
      notice(`Example ${action === "approve" ? "approved" : action + "d"}. Reviews that used it are marked as possibly outdated.`, "ok");
      show(example.status === "submitted" ? "aiPending" : "aiMemory");
    } catch (error) { notice(error.message, "bad"); }
  };
  if (!can("manage_memory")) return null;
  if (example.status === "submitted") {
    return el("div", { class: "controls" },
      el("button", { onclick: () => act("approve") }, "Approve"),
      el("button", { onclick: () => confirm("Approve your own submission? It is recorded as self-approved.") && act("approve", { self_approve: true }) }, "Self-approve"),
      el("button", { onclick: () => { const reason = prompt("Why is it rejected?"); if (reason) act("reject", { reason }); } }, "Reject"));
  }
  if (example.status === "approved") {
    return el("div", { class: "controls" },
      el("button", { onclick: () => act("disable", { reason: prompt("Reason (optional)") || "" }) }, "Disable"),
      el("button", { onclick: () => { const explanation = prompt("Corrected explanation", (example.content || {}).explanation || "");
        if (explanation) act("edit", { content: { explanation }, note: "edited in dashboard" }); } }, "Edit explanation"));
  }
  if (example.status === "disabled") {
    return el("div", { class: "controls" }, el("button", { onclick: () => act("enable") }, "Re-enable"));
  }
  return null;
}

async function memoryView(root, status, view, title) {
  const rows = await api(projectPath(`/ai/memory?status=${status}`));
  const details = el("div", {});
  root.replaceChildren(heading(title), aiTabs(view), el("p", { class: "hint" }, MEMORY_SENTENCE),
    tableOf(["Example", "Status", "Revision", "Verdict", "Category", "Title"], rows.map((row) => el("tr", {},
      el("td", {}, el("button", { onclick: () => memoryDetail(details, row.id) }, row.id.slice(0, 8))),
      el("td", {}, row.status + (row.self_approved ? " (self-approved)" : "")), el("td", {}, `r${row.current_revision}`),
      el("td", {}, (row.content || {}).verdict || ""), el("td", {}, categoryLabel((row.content || {}).category || "")),
      el("td", {}, (row.content || {}).title || ""))), status === "submitted" ? "Nothing awaits approval." : "No approved examples."),
    details);
}

async function memoryDetail(box, id) {
  const example = await api(projectPath(`/ai/memory/${encodeURIComponent(id)}`));
  const content = example.content || {};
  const conditions = example.conditions || {};
  box.replaceChildren(el("div", { class: "panel" },
    el("h2", {}, content.title || "Example"),
    fact("Verdict", content.verdict), fact("Category", categoryLabel(content.category || "")),
    fact("Explanation", content.explanation), fact("Reason", content.reason),
    el("h3", {}, "Code it applies to"), el("pre", {}, content.snippet || ""),
    el("h3", {}, "Applicability conditions"),
    fact("Path pattern", conditions.path_pattern), fact("Technologies", (conditions.technologies || []).map((t) => `${t.name} ${t.version_range}`).join(", ")),
    fact("Identifiers", (conditions.identifiers || []).join(", ")), fact("Context", conditions.context),
    fact("Review by", conditions.review_by), fact("Code fingerprint", conditions.fingerprint),
    await memoryActions(example),
    el("h3", {}, "History"),
    el("ul", {}, example.events.map((e) => el("li", {}, `${when(e.at)} ${e.action.replace("_", " ")} r${text(e.revision)}${e.reason ? ": " + e.reason : ""}`))),
    el("h3", {}, "Revisions"),
    el("ul", {}, example.revisions.map((r) => el("li", {}, `r${r.revision} ${when(r.created_at)}${r.note ? ": " + r.note : ""}`)))));
}

views.aiPending = (root) => memoryView(root, "submitted", "aiPending", "Memory awaiting approval");
views.aiMemory = (root) => memoryView(root, "approved", "aiMemory", "Approved examples");

views.aiAdvanced = async (root) => {
  const status = await api(projectPath("/ai/status"));
  const result = el("div", {});
  const check = el("button", { onclick: async () => {
    try {
      const report = await api(projectPath("/ai/check"), { method: "POST" });
      result.replaceChildren(el("div", { class: `panel ${report.ready ? "" : "warn"}` },
        el("h2", {}, report.outcome.replace(/_/g, " ").toUpperCase()), el("p", {}, report.message),
        report.installed_models.length ? fact("Installed models", report.installed_models.join(", ")) : null,
        report.guidance.map((line) => el("p", { class: "hint" }, line))));
    } catch (error) { notice(error.message, "bad"); }
  } }, "Check connection (sends no prompt)");
  const switches = [["retain_response_bodies", "Keep page HTML and inline scripts for review"],
    ["allow_source_maps", "Fetch in-scope source maps"], ["memory_require_second_reviewer", "Require a second reviewer for project memory"],
    ["review_changed_scripts", "Continuous monitoring: AI review changed scripts"]];
  root.replaceChildren(heading("Model status and Advanced"), aiTabs("aiAdvanced"),
    el("div", { class: "panel" }, el("h2", {}, "Model status"), fact("Endpoint", status.endpoint), fact("Model", status.model),
      fact("Context window", `${status.num_ctx} tokens`), check, result),
    el("div", { class: "panel" }, el("h2", {}, "Project switches"),
      el("p", { class: "hint" }, "Owner only. Changes are audited."),
      switches.map(([key, label]) => el("div", {}, `${label}: `, badge(status.project[key] ? "ON" : "OFF", status.project[key] ? "warn" : "muted"), " ",
        can("manage_project") ? el("button", { onclick: async () => {
          if (!confirm(`Turn "${label}" ${status.project[key] ? "off" : "on"}?`)) return;
          try {
            await api(projectPath("/ai/settings"), { method: "PATCH", body: { [key]: !status.project[key] } });
            show("aiAdvanced");
          } catch (error) { notice(error.message, "bad"); }
        } }, status.project[key] ? "Turn off" : "Turn on") : null))),
    el("div", { class: "panel" }, el("h2", {}, "Technical settings"),
      el("p", { class: "hint" }, "From the profile and .env (WATCHTOWER__AI__...)."),
      tableOf(["Setting", "Value"], Object.entries(status.advanced).map(([key, value]) => el("tr", {},
        el("td", { class: "mono" }, key), el("td", {}, String(value)))), "")));
};

// ---- start -------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("signin-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = document.getElementById("token");
    signIn(input.value.trim());
    input.value = "";
  });
  document.getElementById("signout").addEventListener("click", () => signOut());
  document.getElementById("project").addEventListener("change", (event) => {
    state.project = state.projects.find((p) => p.id === event.target.value);
    storage("set", PROJECT_KEY, state.project.id);
    state.cursor = {};
    show("overview");
  });
  for (const button of document.querySelectorAll("#nav button[data-view]")) {
    button.addEventListener("click", () => show(button.dataset.view));
  }
  const saved = storage("get", TOKEN_KEY);
  if (saved) signIn(saved);
});
