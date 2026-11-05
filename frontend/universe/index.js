// Entry point for the universe. Picks the WebGL scene, or the 2D fallback when
// WebGL is unavailable or its context is lost, behind one controller.
import { createFallback } from "./fallback.js";

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function webglAvailable() {
  try {
    const canvas = document.createElement("canvas");
    return Boolean(window.WebGLRenderingContext && (canvas.getContext("webgl2") || canvas.getContext("webgl")));
  } catch (_) {
    return false;
  }
}

export async function mountUniverse(host, events) {
  let controller = null;
  // Replayed onto a replacement controller after a lost context.
  let planets = [];
  let selected = null;
  let active = true;

  const motion = () => !reducedMotion.matches;
  const fallback = () => {
    if (controller) controller.dispose();
    controller = createFallback(host, events, { motion: motion() });
    controller.setPlanets(planets);
    if (selected) controller.select(selected);
    controller.setActive(active);
    events.onMode("fallback");
  };

  if (webglAvailable()) {
    try {
      const { createScene } = await import("./scene.js");
      controller = createScene(host, { ...events, onLost: fallback }, { motion: motion() });
      events.onMode("webgl");
    } catch (error) {
      controller = null;
    }
  }
  if (!controller) fallback();

  reducedMotion.addEventListener("change", () => controller.setMotion(motion()));

  return {
    get kind() { return controller.kind; },
    get motion() { return motion(); },
    setPlanets(list) { planets = list; controller.setPlanets(list); },
    select(id) { selected = id; return controller.select(id); },
    pulse(id, color, delay) { controller.pulse(id, color, delay); },
    shimmer(id, delay) { controller.shimmer(id, delay); },
    focusProject(projectId) { controller.focusProject(projectId); },
    recentre() { return controller.recentre(); },
    enter(id) { return controller.enter(id); },
    leave(id) { return controller.leave(id); },
    jumpInto(id) { controller.jumpInto(id); },
    project(id) { return controller.project(id); },
    setActive(value) { active = value; controller.setActive(value); },
  };
}

export { PULSE_COLOR, SEVERITY_GLOW } from "./layout.js";
