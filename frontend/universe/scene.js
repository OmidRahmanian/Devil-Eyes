// The WebGL universe: renderer, camera rig, picking, transitions and the
// render loop. It knows nothing about the API; cosmos.js feeds it plain data.
import * as THREE from "../vendor/three.module.min.js";
import { createBackground } from "./background.js";
import { createEye } from "./eye.js";
import { Planet, createPlanetResources } from "./planets.js";
import { createPulses } from "./pulses.js";
import { place } from "./layout.js";

// Every shader writes display colours directly, so no conversions anywhere.
THREE.ColorManagement.enabled = false;

const FOV = 50;
const HOME_PITCH = 0.1;
const LIMITS = { yaw: 0.6, pitchMin: -0.35, pitchMax: 0.55 };

function easeInOutCubic(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

function detectTier(renderer) {
  const gl = renderer.getContext();
  let name = "";
  const info = gl.getExtension("WEBGL_debug_renderer_info");
  if (info) name = String(gl.getParameter(info.UNMASKED_RENDERER_WEBGL) || "");
  const software = /swiftshader|llvmpipe|software|basic render/i.test(name);
  const small = Math.min(window.screen.width, window.screen.height) < 700;
  const weak = (navigator.hardwareConcurrency || 4) <= 4;
  return software || small || weak ? "low" : "high";
}

export function createScene(host, events, { motion: initialMotion }) {
  let motion = initialMotion;
  const renderer = new THREE.WebGLRenderer({
    antialias: window.devicePixelRatio < 1.5, alpha: false, stencil: false, powerPreference: "high-performance",
  });
  const tier = detectTier(renderer);
  const maxRatio = tier === "low" ? 1.25 : 2;
  let pixelRatio = Math.min(window.devicePixelRatio || 1, maxRatio);
  renderer.setPixelRatio(pixelRatio);
  renderer.outputColorSpace = THREE.LinearSRGBColorSpace;
  renderer.setClearColor(0x020308, 1);
  const canvas = renderer.domElement;
  canvas.className = "cosmos-canvas";
  host.append(canvas);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 1200);
  const background = createBackground(renderer, tier);
  const eye = createEye(tier);
  const resources = createPlanetResources(tier);
  resources.pixelRatio.value = pixelRatio;
  const pulses = createPulses(resources.pixelRatio);
  const planetLayer = new THREE.Group();
  const filamentLayer = new THREE.Group();
  scene.add(background.group, filamentLayer, eye.group, planetLayer, pulses.group);
  background.setPixelRatio(pixelRatio);
  background.setMotion(motion);

  const planets = new Map();
  let order = [];
  let initialized = false;
  let selected = null;
  let hovered = null;
  let watched = null;
  let watchUntil = 0;
  let layoutAspect = 0;
  const scheduled = [];

  // Camera rig: the camera orbits `focus` at `distance`, damped toward `goal`.
  const rig = { focus: new THREE.Vector3(), distance: 60, yaw: 0, pitch: HOME_PITCH };
  const goal = { focus: new THREE.Vector3(), distance: 60, yaw: 0, pitch: HOME_PITCH };
  const home = { focus: new THREE.Vector3(), distance: 40 };
  let tween = null;

  function snapshot(source) {
    return { focus: source.focus.clone(), distance: source.distance, yaw: source.yaw, pitch: source.pitch };
  }

  function applyRig() {
    const cp = Math.cos(rig.pitch);
    camera.position.set(Math.sin(rig.yaw) * cp, Math.sin(rig.pitch), Math.cos(rig.yaw) * cp)
      .multiplyScalar(rig.distance).add(rig.focus);
    camera.lookAt(rig.focus);
  }

  function animateTo(to, duration) {
    if (tween) {
      tween.resolve();
      tween = null;
    }
    Object.assign(goal, { focus: to.focus.clone(), distance: to.distance, yaw: to.yaw, pitch: to.pitch });
    if (!duration) {
      Object.assign(rig, snapshot(goal));
      return Promise.resolve();
    }
    return new Promise((resolve) => { tween = { from: snapshot(rig), to: snapshot(goal), t: 0, duration, resolve }; });
  }

  function fitDistance(members, centre) {
    let halfW = 6;
    let halfH = 6;
    for (const p of members) {
      const reach = p.radius * 2.6 + 1.2;
      halfW = Math.max(halfW, Math.abs(p.group.position.x - centre.x) + reach);
      halfH = Math.max(halfH, Math.abs(p.group.position.y - centre.y) + reach);
    }
    const tan = Math.tan(THREE.MathUtils.degToRad(FOV / 2));
    // Leave headroom for the HUD above and below the sky.
    return Math.max(halfH * 1.18 / tan, halfW / (tan * camera.aspect), 16) + 2;
  }

  function computeHome() {
    home.focus.set(0, 0, 0);
    home.distance = fitDistance([...planets.values()], home.focus);
  }

  function homeView() {
    return { focus: home.focus, distance: home.distance, yaw: 0, pitch: HOME_PITCH };
  }

  function selectionView(planet) {
    const focus = home.focus.clone().lerp(planet.group.position, 0.55);
    return { focus, distance: Math.max(home.distance * 0.55, planet.radius * 9, 14), yaw: goal.yaw, pitch: goal.pitch };
  }

  function insideView(planet) {
    // Approach from the lit side so the planet fills the screen in its own light.
    const p = planet.group.position;
    const dir = p.clone().negate().normalize().multiplyScalar(1.6).add(new THREE.Vector3(0, 0.15, 1)).normalize();
    return {
      focus: p.clone(), distance: planet.radius * 2,
      yaw: THREE.MathUtils.clamp(Math.atan2(dir.x, dir.z), -1.2, 1.2), pitch: THREE.MathUtils.clamp(Math.asin(dir.y), -0.6, 0.6),
    };
  }

  function clampGoal() {
    goal.yaw = THREE.MathUtils.clamp(goal.yaw, -LIMITS.yaw, LIMITS.yaw);
    goal.pitch = THREE.MathUtils.clamp(goal.pitch, LIMITS.pitchMin, LIMITS.pitchMax);
    goal.distance = THREE.MathUtils.clamp(goal.distance, home.distance * 0.3, home.distance * 1.4);
  }

  // ---- sizing ----------------------------------------------------------

  function resize() {
    const width = Math.max(1, host.clientWidth);
    const height = Math.max(1, host.clientHeight);
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    const bucket = camera.aspect >= 1.25 ? 1.78 : camera.aspect >= 0.8 ? 1 : 0.6;
    if (bucket !== layoutAspect) {
      layoutAspect = bucket;
      relayout();
    }
    const atHome = !selected && !tween;
    computeHome();
    if (atHome) animateTo(homeView(), 0);
    if (!running) render();
  }

  function relayout() {
    const spots = place(order, layoutAspect);
    for (const [id, planet] of planets) planet.setPosition(spots.get(id));
  }

  // ---- picking ---------------------------------------------------------

  const projected = new THREE.Vector3();

  function screenOf(planet) {
    projected.copy(planet.group.position).project(camera);
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    const depth = camera.position.distanceTo(planet.group.position);
    const scale = height / 2 / (Math.tan(THREE.MathUtils.degToRad(FOV / 2)) * Math.max(depth, 0.01));
    return {
      x: (projected.x * 0.5 + 0.5) * width,
      y: (-projected.y * 0.5 + 0.5) * height,
      r: planet.pickRadius() * scale,
      visible: projected.z < 1 && projected.z > -1,
    };
  }

  function pick(x, y) {
    let best = null;
    let bestScore = Infinity;
    for (const planet of planets.values()) {
      const s = screenOf(planet);
      if (!s.visible) continue;
      const d = Math.hypot(s.x - x, s.y - y);
      if (d <= Math.max(s.r, 22) && d / Math.max(s.r, 1) < bestScore) {
        best = planet.id;
        bestScore = d / Math.max(s.r, 1);
      }
    }
    return best;
  }

  // ---- input -----------------------------------------------------------

  const pointers = new Map();
  let press = null;
  let pinch = 0;

  function localPoint(event) {
    const box = canvas.getBoundingClientRect();
    return { x: event.clientX - box.left, y: event.clientY - box.top };
  }

  function setHovered(id) {
    if (id === hovered) return;
    if (hovered && planets.has(hovered)) planets.get(hovered).setHover(false);
    hovered = id;
    if (id && planets.has(id)) planets.get(id).setHover(true);
    canvas.classList.toggle("pointing", Boolean(id));
    events.onHover(id);
  }

  function onPointerDown(event) {
    const point = localPoint(event);
    pointers.set(event.pointerId, point);
    canvas.setPointerCapture(event.pointerId);
    if (pointers.size === 1) press = { ...point, moved: false };
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      pinch = Math.hypot(a.x - b.x, a.y - b.y);
      if (press) press.moved = true;
    }
  }

  function onPointerMove(event) {
    const point = localPoint(event);
    if (!pointers.has(event.pointerId)) {
      if (event.pointerType === "mouse") setHovered(pick(point.x, point.y));
      return;
    }
    const last = pointers.get(event.pointerId);
    pointers.set(event.pointerId, point);
    if (pointers.size === 1 && press) {
      if (Math.hypot(point.x - press.x, point.y - press.y) > 5) press.moved = true;
      if (press.moved && !tween) {
        goal.yaw -= (point.x - last.x) * 0.0035;
        goal.pitch += (point.y - last.y) * 0.0035;
        clampGoal();
      }
    } else if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      const span = Math.hypot(a.x - b.x, a.y - b.y);
      if (pinch > 0 && !tween) {
        goal.distance *= pinch / span;
        clampGoal();
      }
      pinch = span;
    }
  }

  function onPointerUp(event) {
    const point = localPoint(event);
    pointers.delete(event.pointerId);
    if (pointers.size === 0 && press && !press.moved) events.onPick(pick(point.x, point.y));
    if (pointers.size === 0) press = null;
  }

  function onPointerCancel(event) {
    pointers.delete(event.pointerId);
    if (pointers.size === 0) press = null;
  }

  function onWheel(event) {
    event.preventDefault();
    if (tween) return;
    goal.distance *= Math.exp(event.deltaY * 0.0012);
    clampGoal();
  }

  canvas.addEventListener("pointerdown", onPointerDown);
  canvas.addEventListener("pointermove", onPointerMove);
  canvas.addEventListener("pointerup", onPointerUp);
  canvas.addEventListener("pointercancel", onPointerCancel);
  canvas.addEventListener("pointerleave", () => { if (!pointers.size) setHovered(null); });
  canvas.addEventListener("wheel", onWheel, { passive: false });

  // ---- loop ------------------------------------------------------------

  let running = false;
  let wanted = true;
  let raf = 0;
  let last = 0;
  let elapsed = 0;
  let frameSum = 0;
  let frameCount = 0;

  function update(dt) {
    elapsed += dt;
    for (let i = scheduled.length - 1; i >= 0; i--) {
      if (scheduled[i].at <= elapsed) scheduled.splice(i, 1)[0].run();
    }
    if (tween) {
      tween.t = Math.min(1, tween.t + dt / tween.duration);
      const k = easeInOutCubic(tween.t);
      rig.focus.lerpVectors(tween.from.focus, tween.to.focus, k);
      rig.distance = THREE.MathUtils.lerp(tween.from.distance, tween.to.distance, k);
      rig.yaw = THREE.MathUtils.lerp(tween.from.yaw, tween.to.yaw, k);
      rig.pitch = THREE.MathUtils.lerp(tween.from.pitch, tween.to.pitch, k);
      if (tween.t >= 1) {
        const done = tween.resolve;
        tween = null;
        done();
      }
    } else {
      const k = 1 - Math.exp(-dt * 6);
      rig.focus.lerp(goal.focus, k);
      rig.distance += (goal.distance - rig.distance) * k;
      rig.yaw += (goal.yaw - rig.yaw) * k;
      rig.pitch += (goal.pitch - rig.pitch) * k;
    }
    applyRig();
    if (watched && elapsed > watchUntil) watched = null;
    const focus = (hovered && planets.get(hovered)) || watched || (selected && planets.get(selected)) || null;
    eye.update(dt, elapsed, camera, focus ? focus.group.position : null, motion);
    for (const planet of planets.values()) planet.update(dt, elapsed, motion);
    pulses.update(dt, camera, (planet) => {
      eye.fire();
      watched = planet;
      watchUntil = elapsed + 1.6;
    });
    background.update(elapsed, camera, motion);
  }

  function render() {
    applyRig();
    renderer.render(scene, camera);
  }

  function adapt(dt) {
    // Drop resolution, never below 1x, if frames keep missing the budget.
    if (elapsed < 2 || pixelRatio <= 1) return;
    frameSum += dt;
    frameCount += 1;
    if (frameCount < 120) return;
    if (frameSum / frameCount > 0.024) {
      pixelRatio = Math.max(1, pixelRatio - 0.25);
      renderer.setPixelRatio(pixelRatio);
      resources.pixelRatio.value = pixelRatio;
      background.setPixelRatio(pixelRatio);
    }
    frameSum = 0;
    frameCount = 0;
  }

  function frame(now) {
    raf = requestAnimationFrame(frame);
    const dt = Math.min((now - last) / 1000, 0.05);
    last = now;
    update(dt);
    renderer.render(scene, camera);
    events.onFrame();
    adapt(dt);
  }

  function start() {
    if (running || !wanted || document.hidden) return;
    running = true;
    last = performance.now();
    raf = requestAnimationFrame(frame);
  }

  function stop() {
    running = false;
    cancelAnimationFrame(raf);
    raf = 0;
  }

  function onVisibility() {
    if (document.hidden) stop();
    else start();
  }
  document.addEventListener("visibilitychange", onVisibility);

  const observer = new ResizeObserver(() => resize());
  observer.observe(host);

  function onLost() {
    stop();
    events.onLost();
  }
  canvas.addEventListener("webglcontextlost", onLost);

  resize();
  animateTo({ focus: home.focus, distance: home.distance * 1.6, yaw: 0.25, pitch: 0.2 }, 0);
  animateTo(homeView(), motion ? 2.2 : 0);
  start();

  // ---- public API ------------------------------------------------------

  function find(id) {
    return id ? planets.get(id) || null : null;
  }

  return {
    kind: "webgl",
    setPlanets(list) {
      const fresh = initialized;
      const ids = new Set(list.map((p) => p.id));
      let changed = false;
      for (const [id, planet] of planets) {
        if (ids.has(id)) continue;
        changed = true;
        planetLayer.remove(planet.group);
        filamentLayer.remove(planet.filament);
        planet.dispose();
        planets.delete(id);
        if (selected === id) selected = null;
        if (hovered === id) hovered = null;
      }
      const added = list.some((p) => !planets.has(p.id));
      changed = changed || added;
      order = list.map((p) => p.id);
      const spots = place(order, layoutAspect || 1.78);
      for (const data of list) {
        const existing = planets.get(data.id);
        if (existing) {
          existing.setData(data);
          continue;
        }
        const planet = new Planet(data, spots.get(data.id), resources, { fresh });
        planets.set(data.id, planet);
        planetLayer.add(planet.group);
        filamentLayer.add(planet.filament);
      }
      if (added) relayout();
      initialized = initialized || list.length > 0;
      computeHome();
      // Re-frame only when the set of targets changes, never on a routine refresh.
      if (changed && !selected) animateTo(homeView(), motion ? 1.6 : 0);
      if (!running) render();
    },
    select(id) {
      for (const planet of planets.values()) {
        planet.setSelected(planet.id === id);
        planet.setDim(Boolean(id) && planet.id !== id);
      }
      selected = find(id) ? id : null;
      const planet = find(selected);
      return animateTo(planet ? selectionView(planet) : homeView(), motion ? 0.9 : 0);
    },
    pulse(id, hex, delay) {
      const planet = find(id);
      if (!planet) return;
      if (motion) pulses.launch(planet, hex, delay);
      else scheduled.push({ at: elapsed + delay, run: () => planet.flash(hex) });
    },
    shimmer(id, delay) {
      const planet = find(id);
      if (planet) scheduled.push({ at: elapsed + delay, run: () => planet.shimmer() });
    },
    focusProject(projectId) {
      const members = [...planets.values()].filter((p) => p.data.projectId === projectId);
      if (!members.length || selected) return;
      const centre = members.reduce((sum, p) => sum.add(p.group.position), new THREE.Vector3()).divideScalar(members.length);
      if (members.length === planets.size) centre.set(0, 0, 0);
      const distance = THREE.MathUtils.clamp(fitDistance(members, centre), home.distance * 0.45, home.distance);
      animateTo({ focus: centre, distance, yaw: 0, pitch: HOME_PITCH }, motion ? 1.1 : 0);
    },
    recentre() {
      return animateTo(selected ? selectionView(planets.get(selected)) : homeView(), motion ? 0.9 : 0);
    },
    enter(id) {
      const planet = find(id);
      if (!planet) return Promise.resolve();
      return animateTo(insideView(planet), motion ? 1.25 : 0);
    },
    leave(id) {
      const planet = find(id);
      if (!planet) return animateTo(homeView(), motion ? 1.1 : 0);
      animateTo(insideView(planet), 0);
      return animateTo(selectionView(planet), motion ? 1.15 : 0);
    },
    jumpInto(id) {
      const planet = find(id);
      if (!planet) return;
      animateTo(insideView(planet), 0);
      render();
    },
    project(id) {
      const planet = find(id);
      return planet ? screenOf(planet) : null;
    },
    setActive(value) {
      wanted = value;
      if (value) start();
      else stop();
    },
    setMotion(value) {
      motion = value;
      background.setMotion(value);
    },
    dispose() {
      stop();
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      canvas.removeEventListener("webglcontextlost", onLost);
      for (const planet of planets.values()) planet.dispose();
      planets.clear();
      background.dispose();
      eye.dispose();
      pulses.dispose();
      resources.dispose();
      renderer.dispose();
      canvas.remove();
    },
  };
}
