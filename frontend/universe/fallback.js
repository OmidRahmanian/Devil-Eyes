// 2D fallback for browsers without WebGL (or after a lost context): the same
// sky drawn as an SVG constellation, with the same controller interface.
import { PALETTES, SEVERITY_GLOW, hash, paletteFor, place, planetRadius, random } from "./layout.js";

const NS = "http://www.w3.org/2000/svg";

function svg(tag, attrs, ...children) {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, String(value));
  node.append(...children);
  return node;
}

function hex(value) {
  return `#${value.toString(16).padStart(6, "0")}`;
}

function ease(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

export function createFallback(host, events, { motion: initialMotion }) {
  let motion = initialMotion;
  const root = svg("svg", { class: "cosmos-fallback", preserveAspectRatio: "xMidYMid slice", "aria-hidden": "true" });
  const defs = svg("defs");
  PALETTES.forEach((palette, i) => defs.append(svg("radialGradient", { id: `fb-planet-${i}`, cx: "35%", cy: "35%", r: "75%" },
    svg("stop", { offset: "0%", "stop-color": hex(palette.colors[2]) }),
    svg("stop", { offset: "55%", "stop-color": hex(palette.colors[1]) }),
    svg("stop", { offset: "100%", "stop-color": hex(palette.colors[0]) }))));
  defs.append(
    svg("radialGradient", { id: "fb-corona" },
      svg("stop", { offset: "0%", "stop-color": "#ff5a1f", "stop-opacity": "0.9" }),
      svg("stop", { offset: "45%", "stop-color": "#c4160c", "stop-opacity": "0.35" }),
      svg("stop", { offset: "100%", "stop-color": "#c4160c", "stop-opacity": "0" })),
    svg("radialGradient", { id: "fb-iris" },
      svg("stop", { offset: "0%", "stop-color": "#ffb52e" }),
      svg("stop", { offset: "55%", "stop-color": "#e8260f" }),
      svg("stop", { offset: "100%", "stop-color": "#4a0508" })),
    svg("radialGradient", { id: "fb-nebula", cx: "35%", cy: "55%", r: "60%" },
      svg("stop", { offset: "0%", "stop-color": "#5b4a26", "stop-opacity": "0.55" }),
      svg("stop", { offset: "45%", "stop-color": "#1d4f52", "stop-opacity": "0.3" }),
      svg("stop", { offset: "100%", "stop-color": "#020308", "stop-opacity": "0" })));
  const sky = svg("g");
  const world = svg("g");
  const links = svg("g", { class: "fb-links" });
  const bodies = svg("g");
  const sparks = svg("g");
  const pupil = svg("ellipse", { cx: 0, cy: 0, rx: 0.14, ry: 0.92, fill: "#000" });
  const eye = svg("g", { class: "fb-eye" },
    svg("circle", { r: 6, fill: "url(#fb-corona)" }),
    svg("circle", { r: 2, fill: "#0b0608", stroke: "#7a0c0c", "stroke-width": 0.08 }),
    svg("circle", { r: 1.2, fill: "url(#fb-iris)" }),
    pupil);
  world.append(links, eye, bodies, sparks);
  root.append(defs, sky, world);
  host.append(root);

  const rng = random(0xdecade);
  sky.append(svg("rect", { x: -200, y: -200, width: 400, height: 400, fill: "url(#fb-nebula)" }));
  for (let i = 0; i < 260; i++) {
    sky.append(svg("circle", { cx: (rng() - 0.5) * 120, cy: (rng() - 0.5) * 80, r: 0.04 + rng() ** 3 * 0.14,
      fill: rng() < 0.2 ? "#ffd9a8" : rng() < 0.4 ? "#a8c4ff" : "#ffffff", opacity: 0.35 + rng() * 0.6 }));
  }

  const planets = new Map();
  let selected = null;
  let hovered = null;
  const view = { x: 0, y: 0, w: 40, h: 24 };
  const home = { x: 0, y: 0, w: 40, h: 24 };
  let anim = null;
  let raf = 0;
  const pulses = [];

  function applyView() {
    root.setAttribute("viewBox", `${view.x - view.w / 2} ${view.y - view.h / 2} ${view.w} ${view.h}`);
  }

  function aspect() {
    return Math.max(0.3, host.clientWidth / Math.max(1, host.clientHeight));
  }

  function fit(members, cx, cy) {
    let halfW = 8;
    let halfH = 8;
    for (const p of members) {
      halfW = Math.max(halfW, Math.abs(p.x - cx) + p.r * 2.4 + 1);
      halfH = Math.max(halfH, Math.abs(p.y - cy) + p.r * 2.4 + 1);
    }
    const a = aspect();
    halfH *= 1.18;
    const h = Math.max(halfH * 2, (halfW * 2) / a);
    return { x: cx, y: cy, w: h * a, h };
  }

  function computeHome() {
    Object.assign(home, fit([...planets.values()], 0, 0));
  }

  function animateView(target, duration) {
    if (anim) anim.resolve();
    anim = null;
    if (!duration || !motion) {
      Object.assign(view, target);
      applyView();
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      anim = { from: { ...view }, to: { ...target }, t: 0, duration, resolve };
      loop();
    });
  }

  function selectionView(p) {
    const w = Math.max(home.w * 0.55, p.r * 14 * aspect());
    return { x: home.x + (p.x - home.x) * 0.55, y: home.y + (p.y - home.y) * 0.55, w, h: w / aspect() };
  }

  function insideView(p) {
    const h = p.r * 2.4;
    return { x: p.x, y: p.y, w: h * aspect(), h };
  }

  let last = 0;
  function loop() {
    if (raf) return;
    last = performance.now();
    const step = (now) => {
      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;
      if (anim) {
        anim.t = Math.min(1, anim.t + dt / anim.duration);
        const k = ease(anim.t);
        for (const key of ["x", "y", "w", "h"]) view[key] = anim.from[key] + (anim.to[key] - anim.from[key]) * k;
        applyView();
        if (anim.t >= 1) {
          const done = anim.resolve;
          anim = null;
          done();
        }
      }
      for (let i = pulses.length - 1; i >= 0; i--) {
        const pulse = pulses[i];
        pulse.age += dt;
        if (pulse.age < 0) continue;
        const t = Math.min(1, pulse.age / 1.35);
        const length = pulse.path.getTotalLength();
        const point = pulse.path.getPointAtLength(ease(t) * length * pulse.end);
        pulse.dot.setAttribute("cx", point.x);
        pulse.dot.setAttribute("cy", point.y);
        pulse.dot.setAttribute("opacity", "1");
        if (t >= 1) {
          pulse.dot.remove();
          flash(pulse.planet, pulse.color);
          pulses.splice(i, 1);
        }
      }
      events.onFrame();
      raf = anim || pulses.length ? requestAnimationFrame(step) : 0;
    };
    raf = requestAnimationFrame(step);
  }

  function flash(planet, color) {
    planet.halo.setAttribute("stroke", color);
    planet.node.classList.remove("fb-flash");
    void planet.node.getBBox();
    planet.node.classList.add("fb-flash");
    setTimeout(() => planet.halo.setAttribute("stroke", planet.glow), 900);
  }

  function build(data, spot) {
    const palette = PALETTES.indexOf(paletteFor(data.id));
    const r = data.proto ? 1.1 : planetRadius(data.assets || 0);
    const glow = hex(SEVERITY_GLOW[data.severity || "none"] || SEVERITY_GLOW.none);
    const path = svg("path", { class: "fb-link", fill: "none" });
    const halo = svg("circle", { r: r * 1.25, fill: "none", stroke: glow, "stroke-width": 0.18, opacity: 0.8 });
    const body = data.proto
      ? svg("circle", { r, fill: "none", stroke: "#9d8fc4", "stroke-width": 0.1, "stroke-dasharray": "0.15 0.25" })
      : svg("circle", { r, fill: `url(#fb-planet-${palette})` });
    const ring = svg("ellipse", { rx: r * 1.9, ry: r * 0.55, fill: "none", stroke: "#b3d4ff", "stroke-width": 0.08, class: "fb-ring" });
    const node = svg("g", { class: "fb-planet" }, ring, halo, body);
    links.append(path);
    bodies.append(node);
    return { id: data.id, data, node, path, halo, body, ring, glow, r, x: spot.x, y: -spot.y, end: 1 };
  }

  function position(planet, spot) {
    planet.x = spot.x;
    planet.y = -spot.y;
    planet.node.setAttribute("transform", `translate(${planet.x} ${planet.y})`);
    const length = Math.hypot(planet.x, planet.y);
    const bend = (hash(planet.id + "#bend") % 2 ? 1 : -1) * 0.28 * length;
    const nx = -planet.y / length;
    const ny = planet.x / length;
    const sx = (planet.x / length) * 1.8;
    const sy = (planet.y / length) * 1.8;
    planet.path.setAttribute("d", `M ${sx} ${sy} Q ${(sx + planet.x) / 2 + nx * bend} ${(sy + planet.y) / 2 + ny * bend} ${planet.x} ${planet.y}`);
    planet.end = Math.max(0.5, 1 - (planet.r * 1.2) / length);
  }

  function refreshClasses() {
    for (const planet of planets.values()) {
      planet.node.classList.toggle("fb-selected", planet.id === selected);
      planet.node.classList.toggle("fb-hovered", planet.id === hovered);
      planet.node.classList.toggle("fb-dim", Boolean(selected) && planet.id !== selected);
      planet.path.classList.toggle("fb-active", planet.id === selected || planet.id === hovered);
    }
  }

  function pointerTarget(event) {
    const node = event.target.closest ? event.target.closest(".fb-planet") : null;
    if (!node) return null;
    for (const planet of planets.values()) if (planet.node === node) return planet.id;
    return null;
  }

  root.addEventListener("click", (event) => events.onPick(pointerTarget(event)));
  root.addEventListener("pointermove", (event) => {
    const id = pointerTarget(event);
    if (id === hovered) return;
    hovered = id;
    refreshClasses();
    events.onHover(id);
    // The 2D map only redraws while animating, so place the label now.
    events.onFrame();
  });

  const observer = new ResizeObserver(() => {
    computeHome();
    if (!selected && !anim) animateView(home, 0);
    events.onFrame();
  });
  observer.observe(host);

  function find(id) {
    return id ? planets.get(id) || null : null;
  }

  return {
    kind: "fallback",
    setPlanets(list) {
      const ids = new Set(list.map((p) => p.id));
      let changed = false;
      for (const [id, planet] of planets) {
        if (ids.has(id)) continue;
        planet.node.remove();
        planet.path.remove();
        planets.delete(id);
        changed = true;
      }
      const spots = place(list.map((p) => p.id), aspect() >= 1.25 ? 1.78 : aspect() >= 0.8 ? 1 : 0.6);
      for (const data of list) {
        let planet = planets.get(data.id);
        if (!planet) {
          planet = build(data, spots.get(data.id));
          planets.set(data.id, planet);
          changed = true;
        }
        planet.data = data;
        planet.glow = hex(SEVERITY_GLOW[data.severity || "none"] || SEVERITY_GLOW.none);
        planet.halo.setAttribute("stroke", planet.glow);
        planet.ring.classList.toggle("fb-running", Boolean(data.running));
        position(planet, spots.get(data.id));
      }
      if (selected && !planets.has(selected)) selected = null;
      computeHome();
      if (changed && !selected) animateView(home, 0);
      refreshClasses();
    },
    select(id) {
      selected = find(id) ? id : null;
      refreshClasses();
      const planet = find(selected);
      return animateView(planet ? selectionView(planet) : home, 0.8);
    },
    pulse(id, color, delay) {
      const planet = find(id);
      if (!planet) return;
      const css = hex(color);
      if (!motion) { setTimeout(() => flash(planet, css), delay * 1000); return; }
      const dot = svg("circle", { r: 0.28, fill: css, class: "fb-pulse", opacity: 0 });
      sparks.append(dot);
      pulses.push({ planet, path: planet.path, dot, color: css, age: -delay, end: planet.end });
      loop();
    },
    shimmer(id, delay) {
      const planet = find(id);
      if (planet) setTimeout(() => flash(planet, "#f4f1ff"), delay * 1000);
    },
    focusProject(projectId) {
      const members = [...planets.values()].filter((p) => p.data.projectId === projectId);
      if (!members.length || selected) return;
      const cx = members.reduce((s, p) => s + p.x, 0) / members.length;
      const cy = members.reduce((s, p) => s + p.y, 0) / members.length;
      animateView(members.length === planets.size ? home : fit(members, cx, cy), 0.9);
    },
    recentre() {
      const planet = find(selected);
      return animateView(planet ? selectionView(planet) : home, 0.8);
    },
    enter(id) {
      const planet = find(id);
      return planet ? animateView(insideView(planet), 1.1) : Promise.resolve();
    },
    leave(id) {
      const planet = find(id);
      if (!planet) return animateView(home, 0.9);
      animateView(insideView(planet), 0);
      return animateView(selectionView(planet), 1.0);
    },
    jumpInto(id) {
      const planet = find(id);
      if (planet) animateView(insideView(planet), 0);
    },
    project(id) {
      const planet = find(id);
      if (!planet) return null;
      const box = root.getBoundingClientRect();
      const host_ = host.getBoundingClientRect();
      // preserveAspectRatio "slice": one scale fits the larger ratio.
      const scale = Math.max(box.width / view.w, box.height / view.h);
      const x = box.width / 2 + (planet.x - view.x) * scale + box.left - host_.left;
      const y = box.height / 2 + (planet.y - view.y) * scale + box.top - host_.top;
      return { x, y, r: planet.r * 1.25 * scale, visible: true };
    },
    setActive() {},
    setMotion(value) { motion = value; },
    dispose() {
      cancelAnimationFrame(raf);
      observer.disconnect();
      root.remove();
    },
  };
}
