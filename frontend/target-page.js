// The target page: everything about one target, opened from its planet.
// Uses the same API calls and permission checks as the other views; data is
// filtered to the target with cosmos.js's matching rules.
"use strict";

const VISIT_KEY = "devilseyes.visited.";
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Remembered per browser so "new since last visit" survives reloads.
function lastVisit(id) {
  try {
    const previous = localStorage.getItem(VISIT_KEY + id);
    localStorage.setItem(VISIT_KEY + id, new Date().toISOString());
    return previous;
  } catch (_) {
    return null;
  }
}

function section(id, title, ...children) {
  return el("section", { id, class: "target-section panel glass", "aria-labelledby": `${id}-title` },
    el("h2", { id: `${id}-title` }, title), ...children);
}

function clientPager(box, items, render, headers, empty, size = 50) {
  let start = 0;
  const draw = () => {
    const prev = el("button", { disabled: start === 0, onclick: () => { start -= size; draw(); } }, "Previous");
    const next = el("button", { disabled: start + size >= items.length, onclick: () => { start += size; draw(); } }, "Next");
    fill(box, tableOf(headers, items.slice(start, start + size).map(render), empty),
      items.length > size ? el("div", { class: "pager" }, prev, next,
        el("span", { class: "hint" }, `${start + 1}-${Math.min(start + size, items.length)} of ${items.length}`)) : null);
  };
  draw();
}

async function aiPanel(box, status, results, mine) {
  const open = el("button", { class: "quiet", onclick: () => show("ai") }, "Open the AI Review tab");
  if (!status) {
    fill(box, el("p", { class: "empty" }, "AI review is not available on this server."), open);
    return;
  }
  const latest = results.find((r) => ["completed", "partial"].includes(r.status));
  const head = el("p", {}, badge(status.enabled ? "ENABLED" : "DISABLED", status.enabled ? "ok" : "muted"),
    ` Model ${status.model}. Reviews cover the whole project; candidates below are the ones affecting this target.`);
  if (!latest) {
    fill(box, head, el("p", { class: "empty" }, results.length
      ? "No AI review has finished yet." : "No AI review has run for this project yet."), open);
    return;
  }
  const detail = await api(projectPath(`/ai/reviews/${encodeURIComponent(latest.id)}`));
  const relevant = detail.candidates.filter((c) => mine((c.data || {}).affected || ""));
  fill(box, head,
    tableOf(["Review", "Status", "Mode", "Supported", "Created"], results.slice(0, 5).map((r) => el("tr", {},
      el("td", {}, el("button", { onclick: () => show("aiReview", r.id) }, r.id.slice(0, 8))),
      el("td", {}, aiBadge(r.status)), el("td", {}, r.mode === "model" ? "model" : "pre-analysis only"),
      el("td", {}, String(r.candidates.supported)), el("td", {}, when(r.created_at)))), ""),
    latest.outdated ? el("p", { class: "panel warn" }, "The latest review may be outdated. Request a reanalysis from its page.") : null,
    el("h3", {}, `Candidates from review ${latest.id.slice(0, 8)}`),
    relevant.length ? relevant.map((c) => candidateCard(c, detail.id))
      : el("p", { class: "empty" }, "The latest review found nothing about this target."),
    open);
}

views.target = async (root, arg) => {
  const project = state.projects.find((p) => p.id === arg.projectId);
  const back = el("button", { class: "back", onclick: () => show("overview") }, "← Back to universe");
  if (!project) {
    fill(root, el("div", { class: "target-page" }, back, heading("Target not available"),
      el("p", { class: "empty" }, "This target's project is not available to your token.")));
    return;
  }
  useProject(project.id);
  const target = String(arg.root).toLowerCase();
  const id = planetIdFor(project.id, target);
  fill(root, el("div", { class: "target-page" }, back, el("p", { class: "hint" }, `Loading ${target}…`)));

  const [snapshot, findings, runs, changes, alerts, aiStatus, aiResults] = await Promise.all([
    loadSnapshot(project, null),
    cosmosPages(projectPath("/findings"), 200, COSMOS_FINDING_PAGES),
    api(projectPath("/runs?limit=50")).catch(() => ({ items: [] })),
    api(projectPath("/changes?limit=200")).catch(() => ({ items: [] })),
    api(projectPath("/alerts?limit=50")).catch(() => ({ items: [] })),
    api(projectPath("/ai/status")).catch(() => null),
    api(projectPath("/ai/reviews?limit=20")).catch(() => []),
  ]);
  if (state.view !== "target") return;
  const overview = snapshot.overview;
  if (!snapshot.roots.includes(target)) {
    fill(root, el("div", { class: "target-page" }, back, heading(target),
      el("p", { class: "panel warn" }, "This target is no longer in the project's authorized scope.")));
    return;
  }
  const mine = (value) => rootFor(hostOf(value), snapshot) === target;
  const assets = snapshot.assets.filter((a) => mine(a.value));
  const allFindings = findings.items.filter((f) => mine(f.target));
  const open = allFindings.filter((f) => OPEN_STATUSES.includes(f.status));
  const bySeverity = (severity) => open.filter((f) => f.severity === severity).length;
  const resolved = allFindings.filter((f) => f.status === "resolved").length;
  const myChanges = changes.items.filter((c) => mine(c.target));
  const myRuns = runs.items.filter((r) => runTouches(r, target));
  const myAlerts = alerts.items.filter((a) => (a.payload.targets || []).some((t) => mine(t))
    || (a.payload.changes || []).some((c) => mine(c.target || c.key || ((c.after || c.before || {}).host) || "")));
  const visited = lastVisit(id);
  const fresh = myChanges.filter((c) => !visited || new Date(c.created_at) > new Date(visited)).length;
  const lastRun = myRuns[0];
  const severity = highestSeverity(open);
  root.dataset.glow = severity || "none";

  const start = can("operate") && overview.scope
    ? el("button", { class: "primary", onclick: () => startRun({ targets: [target] }, () => show("target", arg)) }, "Start run")
    : null;
  const findingBox = el("div", {});
  const sort = el("select", { "aria-label": "Sort findings" },
    el("option", { value: "severity" }, "Sort by severity"), el("option", { value: "recent" }, "Sort by last seen"));
  const drawFindings = () => {
    const sorted = allFindings.slice().sort(sort.value === "severity"
      ? (a, b) => (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) || (b.last_seen_at > a.last_seen_at ? 1 : -1)
      : (a, b) => (b.last_seen_at > a.last_seen_at ? 1 : -1));
    clientPager(findingBox, sorted, findingRow, FINDING_HEADERS, "No findings for this target.");
  };
  sort.addEventListener("change", drawFindings);
  const assetBox = el("div", {});
  const aiBox = el("div", {}, el("p", { class: "hint" }, "Loading AI review…"));
  const jump = (sectionId, label) => el("button", { class: "chip-link", onclick: () => {
    document.getElementById(sectionId).scrollIntoView({ behavior: motionAllowed() ? "smooth" : "auto", block: "start" });
  } }, label);

  fill(root, el("div", { class: "target-page" },
    el("div", { class: "target-top" }, back,
      el("nav", { class: "section-nav", "aria-label": "Sections" },
        jump("t-assets", "Assets"), jump("t-findings", "Findings"), jump("t-changes", "Changes"),
        jump("t-runs", "Runs"), jump("t-ai", "AI Review"))),
    el("header", { class: `target-header panel glass glow-${severity || "none"}` },
      el("p", { class: "eyebrow" }, `Target in ${project.name}`),
      el("div", { class: "heading" }, el("h1", {}, target), start),
      el("dl", { class: "facts" },
        overview.scope ? fact("Authorized scope", `Revision ${overview.scope.number}, authorized by ${overview.scope.authorization.granted_by} `
          + `(${overview.scope.authorization.kind}: ${overview.scope.authorization.reference})`) : null,
        fact("Last scan", lastRun ? el("span", {}, runBadge(lastRun.status), ` ${when(lastRun.finished_at || lastRun.created_at)}`) : "Not scanned yet"),
        snapshot.assetsComplete ? null : fact("Note", "Large inventory: counts cover the first 2,000 assets. Use Inventory search for the rest."))),
    el("div", { class: "tiles" },
      tile("Assets", assets.length),
      tile("Critical", bySeverity("critical"), bySeverity("critical") ? "bad" : ""),
      tile("High", bySeverity("high"), bySeverity("high") ? "bad" : ""),
      tile("Medium", bySeverity("medium"), bySeverity("medium") ? "warn" : ""),
      tile("Low / info", bySeverity("low") + bySeverity("info")),
      tile("Resolved (verified)", resolved, "ok"),
      tile(visited ? "New changes since last visit" : "Changes recorded", visited ? fresh : myChanges.length, fresh && visited ? "warn" : "")),
    section("t-assets", `Assets (${assets.length})`, assetBox),
    section("t-findings", `Findings (${allFindings.length}, ${open.length} open)`, el("div", { class: "actions" }, sort), findingBox),
    section("t-changes", "Exposure changes",
      tableOf(CHANGE_HEADERS, myChanges.map((c) => changeRow(c, () => show("target", arg))), "No exposure changes for this target.")),
    section("t-alerts", "Alerts", alertFeed(myAlerts, "No alerts for this target.")),
    section("t-runs", "Runs that touched this target",
      tableOf(["Run", "Kind", "Status", "Created", "Phases", "Error"], myRuns.map(runRow), "No runs yet.")),
    section("t-ai", "AI Review", aiBox),
    can("manage_scope") && can("manage_project") ? el("section", { class: "target-section panel glass danger" },
      el("h2", {}, "Remove this target"),
      el("p", {}, snapshot.roots.length === 1
        ? `Stops scanning ${target} for good and removes its planet, project and assets from view. `
          + "Nothing is erased: the history stays in the database, out of view."
        : `Takes ${target} out of ${project.name}'s scope, so it is no longer scanned and its planet leaves the universe. `
          + "The other targets keep running."),
      el("button", { class: "danger", onclick: () => removeTarget(project, target, snapshot) }, `Remove ${target}`)) : null));
  clientPager(assetBox, assets, assetRow, ASSET_HEADERS, "No assets discovered for this target yet.");
  drawFindings();
  aiPanel(aiBox, aiStatus, aiResults, mine).catch((error) => {
    fill(aiBox, el("p", { class: "error" }, error.message));
  });
};

document.addEventListener("keydown", (event) => {
  if (state.view !== "target" || event.key !== "Escape") return;
  if (event.target.closest("input, select, textarea")) return;
  show("overview");
});
