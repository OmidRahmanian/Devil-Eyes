// Adding and removing targets from the dashboard. A target is a root domain in
// a project's authorized scope; each one is a planet. A new target can get its
// own new project (one planet per project) or join an existing project.
"use strict";

const AUTHORIZATION_KINDS = [["asset_owner", "I own these assets"], ["contract", "Contract or engagement"],
  ["internal_approval", "Internal approval"], ["bug_bounty_program", "Bug bounty program"],
  ["vulnerability_disclosure_program", "Vulnerability disclosure program"]];
const EXECUTION_KEYS = ["allowed_schemes", "allowed_paths", "excluded_paths", "allowed_check_kinds", "max_requests_per_run"];

// The hostname of a domain or website link, or null. The server validates it again.
function targetDomain(value) {
  const input = String(value || "").trim();
  if (!input) return null;
  let host;
  try {
    host = new URL(input.includes("://") ? input : "http://" + input).hostname;
  } catch (_) {
    return null;
  }
  host = host.toLowerCase().replace(/\.$/, "");
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) && !/^[\d.]+$/.test(host) ? host : null;
}

// A publish request that keeps everything else in `current` (the in-force revision) as it is.
function scopeRequest(current, includes, authorization, notes) {
  const policy = (current && current.execution_policy) || {};
  return {
    includes,
    excludes: current ? current.rules.filter((r) => r.effect === "exclude").map((r) => r.pattern) : [],
    permitted_ports: current ? current.permitted_ports : null,
    authorization,
    notes,
    execution_policy: Object.fromEntries(EXECUTION_KEYS.filter((k) => k in policy).map((k) => [k, policy[k]])),
    attest_authorized: true,
  };
}

function openAddTarget() {
  const field = (name, label, attrs, hint) => el("label", {}, label, el("input", { name, ...attrs }), hint ? el("span", { class: "hint" }, hint) : null);
  const owned = state.projects.filter((p) => p.permissions.includes("manage_scope"));
  const project = el("select", { name: "project" },
    el("option", { value: "" }, "A new project for this target (its own planet)"),
    owned.map((p) => el("option", { value: p.id }, `Add to ${p.name}`)));
  const kind = el("select", { name: "kind" }, AUTHORIZATION_KINDS.map(([value, label]) => el("option", { value }, label)));
  const form = el("form", { method: "dialog", class: "add-target-form" },
    el("h2", {}, "Add a target"),
    el("p", { class: "hint" }, "Only add domains you own or have written permission to test. Scans send real requests."),
    field("domain", "Domain or website link", { required: true, placeholder: "example.com", autocomplete: "off", spellcheck: "false" },
      "The hostname is used; URL paths are not scan boundaries."),
    el("label", {}, "Project", project),
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "subdomains" }), " Also discover and scan all of its subdomains"),
    el("fieldset", {}, el("legend", {}, "Permission to scan"),
      el("label", {}, "Authorization", kind),
      field("reference", "Reference (program link, contract or ticket)", { placeholder: "For your own assets this can stay empty" }),
      field("granted", "Granted by", { required: true, placeholder: "Your name or the approving organization" })),
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "attest", required: true }),
      " I am authorized to test this target under this authorization."),
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "scan", checked: true }), " Start a scan now"),
    el("div", { class: "actions" },
      el("button", { type: "submit", class: "primary" }, "Add target"),
      el("button", { type: "button", class: "quiet", onclick: () => dialog.close() }, "Cancel")));
  const dialog = el("dialog", { class: "add-target", "aria-label": "Add a target" }, form);
  dialog.addEventListener("close", () => dialog.remove());

  // Joining a project reuses the authorization already on record for it.
  project.addEventListener("change", async () => {
    if (!project.value) return;
    try {
      const scope = await api(`/projects/${encodeURIComponent(project.value)}/scope`);
      const auth = scope.current && scope.current.authorization;
      if (!auth) return;
      kind.value = auth.kind;
      form.elements.reference.value = auth.reference;
      form.elements.granted.value = auth.granted_by;
    } catch (_) { /* the form still works without the prefill */ }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const domain = targetDomain(form.elements.domain.value);
    if (!domain) {
      notice("Enter a domain such as example.com or a link such as https://example.com.", "warn");
      return;
    }
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    button.textContent = "Adding…";
    try {
      await addTarget(domain, {
        projectId: project.value, subdomains: form.elements.subdomains.checked, scan: form.elements.scan.checked,
        authorization: { kind: kind.value, granted_by: form.elements.granted.value.trim(),
          reference: form.elements.reference.value.trim() || `Asset ownership confirmed in the dashboard for ${domain}` },
      });
      dialog.close();
    } catch (error) {
      notice(error.message, "bad");
      button.disabled = false;
      button.textContent = "Add target";
    }
  });
  document.body.append(dialog);
  dialog.showModal();
  form.elements.domain.focus();
}

async function addTarget(domain, options) {
  let project = state.projects.find((p) => p.id === options.projectId);
  if (!project) {
    project = await api("/projects", { method: "POST", body: { name: domain } });
    state.projects = [...state.projects, project].sort((a, b) => a.slug.localeCompare(b.slug));
  }
  useProject(project.id);
  fillProjects();
  const current = (await api(projectPath("/scope"))).current;
  const includes = new Set(current ? current.rules.filter((r) => r.effect === "include").map((r) => r.pattern) : []);
  includes.add(domain);
  if (options.subdomains) includes.add("*." + domain);
  try {
    await api(projectPath("/scope"), { method: "POST",
      body: scopeRequest(current, [...includes], options.authorization, `added ${domain} from the dashboard`) });
  } catch (error) {
    if (!options.projectId) error.message += ` The project ${project.name} was created; choose "Add to ${project.name}" to try again.`;
    throw error;
  }
  let message = `Added ${domain}.`;
  if (options.scan) {
    await startRun({ targets: [domain] }, () => {});
    message += " Its scan is queued and starts in the dashboard window within a few seconds.";
  }
  if (state.view !== "overview") await show("overview");
  await refreshUniverse();
  selectPlanet(planetIdFor(project.id, domain));
  notice(message, "ok");
}

// Removes one target: its own project is archived, or it leaves a shared project's scope.
async function removeTarget(project, target, snapshot) {
  const typed = window.prompt(`Remove ${target}? Scanning stops and its planet leaves the universe. Type the domain to confirm.`);
  if (typed === null) return;
  if (typed.trim().toLowerCase() !== target) {
    notice("The domain did not match, so nothing was removed.", "warn");
    return;
  }
  if (snapshot.roots.length === 1) {
    if (await archiveNow(project)) notice(`Removed ${target}.`, "ok");
    return;
  }
  const current = snapshot.overview.scope;
  const includes = current.rules.filter((r) => r.effect === "include"
    && !(["host", "subdomains"].includes(r.kind) && r.pattern.replace(/^\*\./, "").toLowerCase() === target)).map((r) => r.pattern);
  const auth = current.authorization;
  try {
    await api(projectPath("/scope"), { method: "POST", body: scopeRequest(current, includes,
      { kind: auth.kind, reference: auth.reference, granted_by: auth.granted_by, valid_from: auth.valid_from,
        valid_until: auth.valid_until, notes: auth.notes }, `removed ${target} from the dashboard`) });
  } catch (error) {
    notice(error.message, "bad");
    return;
  }
  await show("overview");
  notice(`Removed ${target}. Its history stays in the project.`, "ok");
}
