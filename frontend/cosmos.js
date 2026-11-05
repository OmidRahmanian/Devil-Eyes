// The universe view. Turns every visible project's authorized scope into
// planets, watches for new discoveries and sends pulses to the right planet,
// and drives the transitions into and out of a target page. Shares app.js's
// helpers; the 3D scene lives in universe/ and only ever receives plain data.
"use strict";

const COSMOS_ASSET_PAGES = 10;
const COSMOS_FINDING_PAGES = 5;
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const OPEN_STATUSES = ["open", "triaged", "in_progress"];
const PULSE_HEX = { asset: 0x4fd8ff, change: 0xffb23e, run: 0xf4f1ff,
  critical: 0xff3b3b, high: 0xff8a2a, medium: 0xf2c14e, low: 0x8fa6c4, info: 0x8fa6c4 };
const GLOW_CSS = { critical: "255, 59, 59", high: "255, 138, 42", medium: "242, 193, 78", low: "143, 166, 196",
  info: "95, 211, 200", none: "95, 211, 200" };
const MAX_PULSES_PER_POLL = 12;

const cosmos = {
  ui: null, mode: null, mounting: null, loading: null,
  snapshots: new Map(), planets: [], byId: new Map(),
  selected: null, hovered: null, lastTarget: null,
  hud: null, bursts: [], listOpen: false, pauseTimer: 0,
};

function motionAllowed() {
  return !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// ---- targets -------------------------------------------------------------

// Target roots exactly as the scanner sees them: host and subdomain include
// rules, with "*." dropped. IP and network rules only permit addresses.
function targetRoots(scope) {
  if (!scope) return [];
  const roots = new Set();
  for (const rule of scope.rules) {
    if (rule.effect !== "include" || !["host", "subdomains"].includes(rule.kind)) continue;
    const root = String(rule.pattern).replace(/^\*\./, "").toLowerCase();
    if (root && !/^[\d.]+$/.test(root) && !root.includes(":")) roots.add(root);
  }
  return [...roots].sort();
}

function hostOf(value) {
  const text = String(value || "").toLowerCase();
  if (text.includes("://")) {
    try { return new URL(text).hostname.replace(/^\[|\]$/g, ""); } catch (_) { return text; }
  }
  if (text.startsWith("[")) return text.slice(1, text.indexOf("]"));
  const service = text.split("/")[0];
  return (service.match(/:/g) || []).length === 1 ? service.split(":")[0] : service;
}

// The one rule deciding whether a host is part of a target.
function belongsTo(host, root) {
  return host === root || host.endsWith("." + root);
}

function planetIdFor(projectId, root) {
  return `${projectId}/${root || ""}`;
}

// Which root a host belongs to in a snapshot: by name, then by the addresses
// its hostnames resolved to, then the only root if there is just one.
function rootFor(host, snapshot) {
  for (const root of snapshot.roots) if (belongsTo(host, root)) return root;
  if (snapshot.addressRoots.has(host)) return snapshot.addressRoots.get(host);
  return snapshot.roots.length === 1 ? snapshot.roots[0] : null;
}

function runTouches(run, root) {
  return !run.targets.length || run.targets.some((t) => belongsTo(hostOf(t), root) || belongsTo(root, hostOf(t)));
}

function highestSeverity(findings) {
  return SEVERITY_ORDER.find((s) => findings.some((f) => f.severity === s)) || null;
}

// ---- data ----------------------------------------------------------------

async function cosmosPages(path, limit, max) {
  const items = [];
  let cursor = null;
  for (let i = 0; i < max; i++) {
    const page = await api(path + (path.includes("?") ? "&" : "?") + `limit=${limit}`
      + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""));
    items.push(...page.items);
    if (!page.next_cursor) return { items, complete: true };
    cursor = page.next_cursor;
  }
  return { items, complete: false };
}

async function loadSnapshot(project, previous) {
  const base = `/projects/${encodeURIComponent(project.id)}`;
  const overview = await api(base + "/overview");
  const signature = JSON.stringify([overview.counts, overview.latest_runs.map((r) => [r.run_id, r.status]),
    overview.scope && overview.scope.id, targetRoots(overview.scope)]);
  // Only an overview per project per poll; the lists reload when it changes.
  if (previous && previous.signature === signature) return { ...previous, project, overview };
  const [assets, findings, changes] = await Promise.all([
    cosmosPages(base + "/assets", 200, COSMOS_ASSET_PAGES),
    cosmosPages(base + "/findings?" + OPEN_STATUSES.map((s) => `status=${s}`).join("&"), 200, COSMOS_FINDING_PAGES),
    api(base + "/changes?limit=50").then((page) => page.items).catch(() => []),
  ]);
  const roots = targetRoots(overview.scope);
  const snapshot = { project, overview, signature, roots, addressRoots: new Map(), assets: assets.items,
    assetsComplete: assets.complete, findings: findings.items, changes, runs: overview.latest_runs };
  for (const asset of assets.items) {
    if (asset.kind !== "hostname") continue;
    const root = roots.find((r) => belongsTo(asset.value, r));
    if (root) for (const address of asset.addresses) snapshot.addressRoots.set(address, root);
  }
  return snapshot;
}

function planetsFrom(snapshots) {
  const planets = [];
  for (const project of state.projects) {
    const s = snapshots.get(project.id);
    if (!s) continue;
    const scanState = (root) => {
      const live = s.runs.filter((r) => ["queued", "running"].includes(r.status) && (!root || runTouches(r, root)));
      return live.some((r) => r.status === "running") ? "running" : live.length ? "queued" : null;
    };
    const running = (root) => Boolean(scanState(root));
    if (!s.roots.length) {
      const total = Object.values(s.overview.counts.assets).reduce((a, b) => a + b, 0);
      planets.push({ id: planetIdFor(project.id, ""), name: project.name, root: "", projectId: project.id,
        projectName: project.name, proto: true, assets: total, open: 0, severity: null, running: running(null), scan: scanState(null),
        moons: 0, lastScan: null });
      continue;
    }
    for (const root of s.roots) {
      const assets = s.assets.filter((a) => rootFor(hostOf(a.value), s) === root);
      const open = s.findings.filter((f) => rootFor(hostOf(f.target), s) === root);
      const touched = s.runs.filter((r) => runTouches(r, root));
      const finished = touched.map((r) => r.finished_at || r.created_at).filter(Boolean).sort();
      planets.push({ id: planetIdFor(project.id, root), name: root, root, projectId: project.id,
        projectName: project.name, proto: false, assets: assets.length, assetsComplete: s.assetsComplete,
        open: open.length, severity: highestSeverity(open), running: running(root), scan: scanState(root),
        moons: Math.max(0, assets.length - 1), lastScan: finished[finished.length - 1] || null });
    }
  }
  return planets;
}

function eventsBetween(previous, next) {
  const events = [];
  if (!previous || previous.signature === next.signature) return events;
  const planet = (host) => {
    const root = rootFor(host, next);
    return root ? planetIdFor(next.project.id, root) : null;
  };
  const seen = (list) => new Set(list.map((item) => item.id));
  const oldAssets = seen(previous.assets);
  for (const asset of next.assets) {
    if (!oldAssets.has(asset.id)) events.push({ planet: planet(hostOf(asset.value)), kind: "asset", label: "asset" });
  }
  const oldFindings = seen(previous.findings);
  for (const finding of next.findings) {
    if (!oldFindings.has(finding.id)) {
      events.push({ planet: planet(hostOf(finding.target)), kind: finding.severity, label: `${finding.severity} finding` });
    }
  }
  const oldChanges = seen(previous.changes);
  for (const change of next.changes) {
    if (!oldChanges.has(change.id)) events.push({ planet: planet(hostOf(change.target)), kind: "change", label: "exposure change" });
  }
  const oldRuns = new Map(previous.runs.map((r) => [r.run_id, r.status]));
  for (const run of next.runs) {
    if (oldRuns.get(run.run_id) === run.status) continue;
    const roots = next.roots.filter((root) => runTouches(run, root));
    for (const root of roots) events.push({ planet: planetIdFor(next.project.id, root), kind: "run", label: `scan ${run.status}` });
  }
  return events.filter((e) => e.planet);
}

async function refreshUniverse() {
  if (cosmos.loading) return cosmos.loading;
  cosmos.loading = (async () => {
    if (state.local) await refreshProjects();
    const results = await Promise.all(state.projects.map((project) =>
      loadSnapshot(project, cosmos.snapshots.get(project.id)).catch((error) => {
        if (error.status === 401) throw error;
        return cosmos.snapshots.get(project.id) || null;
      })));
    if (!signedIn()) return;
    const events = [];
    state.projects.forEach((project, i) => {
      const next = results[i];
      if (!next) return;
      events.push(...eventsBetween(cosmos.snapshots.get(project.id), next));
      cosmos.snapshots.set(project.id, next);
    });
    cosmos.planets = planetsFrom(cosmos.snapshots);
    cosmos.loaded = true;
    cosmos.byId = new Map(cosmos.planets.map((p) => [p.id, p]));
    if (cosmos.selected && !cosmos.byId.has(cosmos.selected)) cosmos.selected = null;
    if (cosmos.ui) cosmos.ui.setPlanets(cosmos.planets);
    renderHud();
    if (events.length) emitPulses(events);
  })();
  try {
    await cosmos.loading;
  } finally {
    cosmos.loading = null;
  }
}

// The open local dashboard owns every project, so projects made in the terminal appear here too.
async function refreshProjects() {
  const projects = (await api("/projects")).filter((p) => !p.archived);
  const ids = (list) => list.map((p) => p.id).join();
  if (ids(projects) === ids(state.projects)) return;
  state.projects = projects;
  const current = state.project && projects.find((p) => p.id === state.project.id);
  state.project = current || projects[0] || null;
  fillProjects();
}

function emitPulses(events) {
  const groups = new Map();
  for (const event of events) {
    if (!cosmos.byId.has(event.planet)) continue;
    if (!groups.has(event.planet)) groups.set(event.planet, []);
    groups.get(event.planet).push(event);
  }
  let delay = 0;
  let launched = 0;
  const lines = [];
  for (const [id, list] of groups) {
    // A burst becomes a few pulses plus one "+N" label, never N pulses.
    for (const event of list.slice(0, 3)) {
      if (launched >= MAX_PULSES_PER_POLL || !cosmos.ui) break;
      if (event.kind === "run") cosmos.ui.shimmer(id, delay);
      else cosmos.ui.pulse(id, PULSE_HEX[event.kind] || PULSE_HEX.asset, delay);
      delay += 0.35;
      launched += 1;
    }
    if (list.length > 3) burst(id, `+${list.length}`, delay);
    const counts = {};
    for (const event of list) counts[event.label] = (counts[event.label] || 0) + 1;
    lines.push(`${cosmos.byId.get(id).name}: ` + Object.entries(counts).map(([label, n]) => `${n} new ${label}${n > 1 ? "s" : ""}`).join(", "));
  }
  if (cosmos.hud && lines.length) cosmos.hud.live.textContent = lines.slice(0, 3).join(". ");
}

function burst(id, label, delay) {
  if (!cosmos.hud) return;
  setTimeout(() => {
    if (!cosmos.hud) return;
    const node = el("div", { class: "burst" }, label);
    cosmos.hud.bursts.append(node);
    const entry = { id, node };
    cosmos.bursts.push(entry);
    setTimeout(() => {
      node.remove();
      cosmos.bursts = cosmos.bursts.filter((b) => b !== entry);
    }, 2600);
  }, delay * 1000 + 1300);
}

// ---- mounting ------------------------------------------------------------

function cosmosStart() {
  if (cosmos.mounting) return cosmos.mounting;
  const host = document.getElementById("cosmos");
  cosmos.mounting = import("/static/universe/index.js")
    .then((module) => module.mountUniverse(host, {
      onPick: (id) => pickPlanet(id),
      onHover: (id) => { cosmos.hovered = id; },
      onFrame: placeOverlays,
      onMode: (mode) => {
        cosmos.mode = mode;
        host.dataset.mode = mode;
      },
    }))
    .then((ui) => {
      cosmos.ui = ui;
      if (cosmos.planets.length) ui.setPlanets(cosmos.planets);
      if (cosmos.selected) ui.select(cosmos.selected);
      return ui;
    })
    .catch(() => {
      // No universe at all (very old browser): the list view still works.
      cosmos.mode = "list";
      return null;
    });
  return cosmos.mounting;
}

function cosmosReset() {
  cosmos.snapshots.clear();
  cosmos.planets = [];
  cosmos.loaded = false;
  cosmos.byId = new Map();
  cosmos.selected = cosmos.hovered = cosmos.lastTarget = null;
  cosmos.hud = null;
  clearTimeout(cosmos.pauseTimer);
  const host = document.getElementById("cosmos");
  host.classList.remove("dim", "behind");
  document.body.classList.remove("universe-mode");
  if (cosmos.ui) {
    cosmos.ui.setPlanets([]);
    cosmos.ui.select(null);
    cosmos.ui.setActive(true);
  }
}

// ---- HUD -----------------------------------------------------------------

function legend() {
  const item = (kind, label) => el("li", {}, el("span", { class: `swatch sw-${kind}`, "aria-hidden": "true" }), label);
  return el("details", { class: "hud-legend" }, el("summary", {}, "Legend"),
    el("ul", {},
      item("asset", "New asset"), item("change", "Exposure change"), item("critical", "New critical / high finding"),
      item("medium", "New medium finding"), item("run", "Scan started or finished")),
    el("p", { class: "hint" }, "Planet size follows asset count; the glow follows the highest open severity. A spinning ring means a scan is running."));
}

function buildHud() {
  const hud = {
    label: el("div", { class: "planet-label", hidden: true, "aria-hidden": "true" }),
    card: el("div", { class: "name-card", hidden: true, role: "group", "aria-label": "Selected target" }),
    bursts: el("div", { class: "bursts", "aria-hidden": "true" }),
    live: el("div", { class: "sr-only", role: "status", "aria-live": "polite" }),
    summary: el("p", { class: "hud-summary" }),
    warnings: el("div", { class: "hud-warnings" }),
    list: el("ul", { class: "target-items" }),
    mode: el("p", { class: "hint hud-mode" }),
  };
  hud.listBox = el("nav", { class: "target-list", "aria-label": "Targets" }, el("h2", {}, "Targets"), hud.list);
  hud.listToggle = el("button", { class: "quiet", "aria-expanded": "false", onclick: () => toggleList() }, "List view");
  hud.box = el("div", { class: "universe-hud" },
    el("div", { class: "hud-top" }, el("h1", { class: "sr-only" }, "Universe"), hud.summary, hud.warnings, hud.mode),
    el("div", { class: "hud-controls" },
      el("button", { onclick: () => cosmos.ui && cosmos.ui.recentre() }, "Recentre"),
      el("button", { class: "primary", onclick: () => openAddTarget() }, "+ Add target"),
      hud.listToggle,
      el("button", { class: "quiet", onclick: () => show("summary") }, "Project summary")),
    hud.empty = el("div", { class: "universe-empty glass", hidden: true },
      el("h2", {}, "Your universe is empty"),
      el("p", {}, "Add a domain you are authorized to test. It becomes a planet, and Devils Eyes starts watching it."),
      el("button", { class: "primary", onclick: () => openAddTarget() }, "+ Add your first target")),
    legend(), hud.label, hud.card, hud.bursts, hud.live, hud.listBox);
  cosmos.hud = hud;
  return hud.box;
}

function toggleList(open = !cosmos.listOpen) {
  cosmos.listOpen = open;
  if (!cosmos.hud) return;
  cosmos.hud.listBox.classList.toggle("open", open);
  cosmos.hud.listToggle.setAttribute("aria-expanded", String(open));
  cosmos.hud.listToggle.textContent = open ? "Hide list" : "List view";
  if (open) {
    const first = cosmos.hud.list.querySelector("button");
    if (first) first.focus();
  }
}

function planetStats(planet) {
  if (planet.proto) return "No authorized scope";
  const assets = `${planet.assets}${planet.assetsComplete === false ? "+" : ""} asset${planet.assets === 1 ? "" : "s"}`;
  const open = `${planet.open} open finding${planet.open === 1 ? "" : "s"}`;
  return [assets, open, planet.scan === "queued" ? "scan queued" : planet.running ? "scan running" : planet.lastScan ? `last scan ${when(planet.lastScan)}` : "not scanned yet"].join(" · ");
}

function renderHud() {
  const hud = cosmos.hud;
  if (!hud) return;
  const targets = cosmos.planets.filter((p) => !p.proto);
  const assets = targets.reduce((sum, p) => sum + p.assets, 0);
  const open = targets.reduce((sum, p) => sum + p.open, 0);
  hud.summary.textContent = cosmos.planets.length
    ? `${targets.length} target${targets.length === 1 ? "" : "s"} · ${assets} assets · ${open} open findings`
    : cosmos.loaded ? "No targets yet" : "Mapping your universe…";
  const warnings = [];
  for (const s of cosmos.snapshots.values()) {
    if (!s.overview.scope) warnings.push(badge(`${s.project.name}: no authorized scope`, "warn"));
    const pending = s.overview.rules.filter((r) => !r.approved);
    if (pending.length && state.project && s.project.id === state.project.id) warnings.push(badge(`${pending.length} rule(s) pending approval`, "warn"));
  }
  hud.warnings.replaceChildren(...warnings.slice(0, 4));
  hud.empty.hidden = Boolean(cosmos.planets.length) || !signedIn();
  hud.mode.textContent = cosmos.mode === "fallback" ? "3D is unavailable here, so this is the 2D map." : cosmos.mode === "list" ? "The map is unavailable in this browser; use the list." : "";
  hud.list.replaceChildren(...cosmos.planets.map((planet) => el("li", {},
    el("button", {
      class: planet.id === cosmos.selected ? "active" : "",
      "data-planet": planet.id,
      "aria-label": `${planet.name}${planet.proto ? "" : `, project ${planet.projectName}`}. ${planetStats(planet)}${planet.severity ? `, highest open severity ${planet.severity}` : ""}`,
      onfocus: (event) => { if (event.target.matches(":focus-visible") && cosmos.selected !== planet.id) selectPlanet(planet.id); },
      onclick: () => pickPlanet(planet.id),
    }, el("span", { class: "item-name" }, planet.name),
    el("span", { class: "item-stats" }, planetStats(planet)),
    planet.severity ? badge(planet.severity, SEVERITY[planet.severity]) : null))));
  if (!cosmos.planets.length && signedIn()) hud.list.append(el("li", { class: "empty" }, "No targets yet."));
  renderCard();
}

function renderCard() {
  const hud = cosmos.hud;
  if (!hud) return;
  const planet = cosmos.byId.get(cosmos.selected);
  hud.card.hidden = !planet;
  if (!planet) return;
  fill(hud.card,
    el("button", { class: "quiet close", "aria-label": "Close", onclick: () => selectPlanet(null) }, "×"),
    el("p", { class: "eyebrow" }, planet.proto ? "Project" : `Target in ${planet.projectName}`),
    el("h2", {}, planet.name),
    el("p", { class: "card-stats" }, planetStats(planet)),
    planet.severity ? el("p", {}, badge(`highest open: ${planet.severity}`, SEVERITY[planet.severity])) : null,
    el("button", { class: "primary", onclick: () => enterTarget(planet.id) }, planet.proto ? "Open scope" : "Enter target"));
  hud.cardSize = null;
}

function selectPlanet(id) {
  cosmos.selected = id && cosmos.byId.has(id) ? id : null;
  if (cosmos.ui) cosmos.ui.select(cosmos.selected);
  if (!cosmos.hud) return;
  for (const button of cosmos.hud.list.querySelectorAll("button[data-planet]")) {
    button.classList.toggle("active", button.dataset.planet === cosmos.selected);
  }
  renderCard();
}

function pickPlanet(id) {
  if (id && id === cosmos.selected) enterTarget(id);
  else selectPlanet(id);
}

function enterTarget(id) {
  const planet = cosmos.byId.get(id);
  if (!planet) return;
  if (planet.proto) {
    useProject(planet.projectId);
    show("scope");
    return;
  }
  show("target", { projectId: planet.projectId, root: planet.root });
}

function cyclePlanet(step) {
  if (!cosmos.planets.length) return;
  const index = cosmos.planets.findIndex((p) => p.id === cosmos.selected);
  const next = cosmos.planets[(index + step + cosmos.planets.length) % cosmos.planets.length];
  selectPlanet(next.id);
  if (cosmos.listOpen && cosmos.hud) {
    const button = cosmos.hud.list.querySelector(`button[data-planet="${CSS.escape(next.id)}"]`);
    if (button) button.focus();
  }
}

function onCosmosKey(event) {
  if (state.view !== "overview" || !signedIn()) return;
  if (event.target.closest("input, select, textarea, details, .name-card")) return;
  if (["ArrowRight", "ArrowDown"].includes(event.key)) { event.preventDefault(); cyclePlanet(1); }
  else if (["ArrowLeft", "ArrowUp"].includes(event.key)) { event.preventDefault(); cyclePlanet(-1); }
  else if (event.key === "Enter" && cosmos.selected && !event.target.closest("button, a")) { event.preventDefault(); enterTarget(cosmos.selected); }
  else if (event.key === "Escape") {
    if (cosmos.listOpen) toggleList(false);
    else selectPlanet(null);
  }
}

function placeAt(node, x, y) {
  node.style.transform = `translate3d(${Math.round(x)}px, ${Math.round(y)}px, 0)`;
}

function placeOverlays() {
  const hud = cosmos.hud;
  const ui = cosmos.ui;
  if (!hud || !ui || state.view !== "overview") return;
  const hoverId = cosmos.hovered !== cosmos.selected ? cosmos.hovered : null;
  const hovered = hoverId && cosmos.byId.get(hoverId);
  const spot = hovered && ui.project(hoverId);
  hud.label.hidden = !spot || !spot.visible;
  if (spot && spot.visible) {
    if (hud.label.dataset.planet !== hoverId) {
      hud.label.dataset.planet = hoverId;
      fill(hud.label, el("strong", {}, hovered.name), hovered.open ? el("span", {}, ` ${hovered.open} open`) : null);
    }
    placeAt(hud.label, spot.x - hud.label.offsetWidth / 2, spot.y + spot.r + 10);
  }
  if (cosmos.selected && !hud.card.hidden && window.innerWidth > 640) {
    const s = ui.project(cosmos.selected);
    if (s) {
      if (!hud.cardSize) hud.cardSize = { w: hud.card.offsetWidth, h: hud.card.offsetHeight };
      const { w, h } = hud.cardSize;
      let x = s.x + s.r + 20;
      if (x + w > window.innerWidth - 16) x = s.x - s.r - 20 - w;
      const top = 72;
      placeAt(hud.card, Math.max(16, x), Math.min(Math.max(top, s.y - h / 2), window.innerHeight - h - 16));
    }
  }
  for (const entry of cosmos.bursts) {
    const s = ui.project(entry.id);
    if (s) placeAt(entry.node, s.x + s.r * 0.6, s.y - s.r - 28);
  }
}

// ---- the view and its transitions -------------------------------------------

views.overview = async (root) => {
  if (!cosmos.hud || !root.contains(cosmos.hud.box)) root.replaceChildren(buildHud());
  renderHud();
  await refreshUniverse();
  if (state.focusProject && cosmos.ui) cosmos.ui.focusProject(state.focusProject);
  state.focusProject = null;
  if (state.view === "overview") state.timer = setInterval(() => refreshUniverse().catch(() => {}), REFRESH_MS);
};

function floodTo(color, from, to, duration) {
  const flood = document.getElementById("flood");
  flood.style.background = `radial-gradient(circle at 50% 50%, rgba(${color}, 0.95), rgba(${color}, 0.55) 45%, rgba(2, 3, 8, 0.97))`;
  flood.hidden = false;
  const animation = flood.animate([{ opacity: from }, { opacity: to }], { duration, easing: "cubic-bezier(0.4, 0, 0.2, 1)", fill: "forwards" });
  return animation.finished.then(() => {
    if (to === 0) flood.hidden = true;
  }).catch(() => {});
}

function fadeOut(node, duration) {
  if (!node.childNodes.length) return Promise.resolve();
  return node.animate([{ opacity: 1 }, { opacity: 0 }], { duration, easing: "ease-in", fill: "forwards" })
    .finished.catch(() => {});
}

function glowOf(id) {
  const planet = cosmos.byId.get(id);
  return GLOW_CSS[(planet && planet.severity) || "none"] || GLOW_CSS.none;
}

// Runs before a view renders: plays the flight into a planet, the pull back
// out of it, or fades the universe behind other views.
async function cosmosBefore(from, to, arg) {
  const host = document.getElementById("cosmos");
  const root = document.getElementById("view");
  const ui = cosmos.ui || await cosmosStart();
  const motion = motionAllowed();
  clearTimeout(cosmos.pauseTimer);
  if (to === "overview") {
    document.body.classList.add("universe-mode");
    host.classList.remove("dim", "behind");
    if (ui) ui.setActive(true);
    if (from === "target" && cosmos.lastTarget && cosmos.byId.has(cosmos.lastTarget)) {
      const id = cosmos.lastTarget;
      await fadeOut(root, motion ? 220 : 100);
      root.replaceChildren();
      cosmos.hud = null;
      cosmos.selected = id;
      if (ui) {
        ui.select(id);
        if (motion) ui.leave(id);
      }
      floodTo(glowOf(id), motion ? 0.9 : 0.6, 0, motion ? 750 : 180);
    }
    return;
  }
  document.body.classList.remove("universe-mode");
  if (to === "target") {
    const id = planetIdFor(arg.projectId, arg.root);
    if (!cosmos.byId.has(id) && signedIn()) await refreshUniverse().catch(() => {});
    cosmos.lastTarget = id;
    if (from === "overview" && ui && cosmos.byId.has(id)) {
      if (cosmos.hud) cosmos.hud.box.classList.add("leaving");
      cosmos.selected = id;
      ui.select(id);
      if (motion) {
        const flight = ui.enter(id);
        await new Promise((resolve) => setTimeout(resolve, 650));
        await Promise.all([flight, floodTo(glowOf(id), 0, 0.92, 560)]);
      } else {
        await floodTo(glowOf(id), 0, 0.85, 160);
      }
    } else if (ui && cosmos.byId.has(id)) {
      ui.jumpInto(id);
    }
    host.classList.remove("dim");
    host.classList.add("behind");
    if (ui) cosmos.pauseTimer = setTimeout(() => ui.setActive(false), 50);
    return;
  }
  host.classList.remove("behind");
  host.classList.add("dim");
  // Let the fade finish, then stop rendering the hidden universe.
  if (ui) cosmos.pauseTimer = setTimeout(() => ui.setActive(false), 700);
}

// Runs after a view renders: the new page rises in and any flood clears.
function cosmosAfter(from, to) {
  const motion = motionAllowed();
  const root = document.getElementById("view");
  // A finished fade-out would otherwise keep holding the new page invisible.
  for (const animation of root.getAnimations()) animation.cancel();
  if (to === "target" && from !== "target") {
    const flood = document.getElementById("flood");
    if (!flood.hidden) floodTo(glowOf(cosmos.lastTarget), motion ? 0.92 : 0.85, 0, motion ? 650 : 150);
  }
  if (from === to && to !== "target") return;
  root.animate([{ opacity: 0, transform: "translateY(14px)" }, { opacity: 1, transform: "none" }],
    { duration: motion ? 380 : 120, easing: "cubic-bezier(0.2, 0.7, 0.2, 1)" });
}

document.addEventListener("keydown", onCosmosKey);
