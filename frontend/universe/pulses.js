// Energy pulses that travel from the eye along a planet's filament, and the
// ripple a pulse leaves when it lands. Everything comes from fixed pools, so
// a burst of discoveries allocates nothing per frame.
import * as THREE from "../vendor/three.module.min.js";

const TRAIL = 14;
const POOL = 24;
const RIPPLES = 12;

const PULSE_VERTEX = /* glsl */ `
attribute vec3 aColor;
attribute float aAlpha;
attribute float aSize;
uniform float uPixelRatio;
varying vec3 vColor;
varying float vAlpha;
void main() {
  vec4 mv = modelViewMatrix * vec4(position, 1.0);
  gl_Position = projectionMatrix * mv;
  gl_PointSize = aSize * uPixelRatio * clamp(40.0 / -mv.z, 0.5, 3.0);
  vColor = aColor;
  vAlpha = aAlpha;
}`;

const PULSE_FRAGMENT = /* glsl */ `
varying vec3 vColor;
varying float vAlpha;
void main() {
  float d = length(gl_PointCoord - 0.5) * 2.0;
  float a = exp(-d * d * 5.0) * vAlpha;
  gl_FragColor = vec4((vColor + vec3(0.35) * exp(-d * d * 24.0)) * a, 1.0);
}`;

const RIPPLE_VERTEX = /* glsl */ `
varying vec2 vUv;
void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`;

const RIPPLE_FRAGMENT = /* glsl */ `
uniform vec3 uColor;
uniform float uProgress;
varying vec2 vUv;
void main() {
  float r = length(vUv - 0.5) * 2.0;
  float ring = exp(-pow((r - uProgress) * 14.0, 2.0));
  gl_FragColor = vec4(uColor * ring * (1.0 - uProgress) * 1.4, 1.0);
}`;

function easeInOut(t) {
  return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
}

export function createPulses(pixelRatio) {
  const count = POOL * TRAIL;
  const geometry = new THREE.BufferGeometry();
  const position = new THREE.BufferAttribute(new Float32Array(count * 3), 3).setUsage(THREE.DynamicDrawUsage);
  const color = new THREE.BufferAttribute(new Float32Array(count * 3), 3).setUsage(THREE.DynamicDrawUsage);
  const alpha = new THREE.BufferAttribute(new Float32Array(count), 1).setUsage(THREE.DynamicDrawUsage);
  const size = new THREE.BufferAttribute(new Float32Array(count), 1);
  for (let p = 0; p < POOL; p++) {
    for (let i = 0; i < TRAIL; i++) size.array[p * TRAIL + i] = i === 0 ? 26 : 16 * (1 - i / TRAIL) + 3;
  }
  geometry.setAttribute("position", position);
  geometry.setAttribute("aColor", color);
  geometry.setAttribute("aAlpha", alpha);
  geometry.setAttribute("aSize", size);
  const material = new THREE.ShaderMaterial({
    uniforms: { uPixelRatio: pixelRatio }, vertexShader: PULSE_VERTEX, fragmentShader: PULSE_FRAGMENT,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const points = new THREE.Points(geometry, material);
  points.frustumCulled = false;
  points.renderOrder = 5;

  const group = new THREE.Group();
  group.add(points);
  const rippleGeometry = new THREE.PlaneGeometry(1, 1);
  const ripples = [];
  for (let i = 0; i < RIPPLES; i++) {
    const uniforms = { uColor: { value: new THREE.Color() }, uProgress: { value: 0 } };
    const mesh = new THREE.Mesh(rippleGeometry, new THREE.ShaderMaterial({
      uniforms, vertexShader: RIPPLE_VERTEX, fragmentShader: RIPPLE_FRAGMENT,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    }));
    mesh.visible = false;
    group.add(mesh);
    ripples.push({ mesh, uniforms, age: Infinity, planet: null, size: 1 });
  }

  const slots = Array.from({ length: POOL }, () => ({ active: false }));
  const point = new THREE.Vector3();
  const tint = new THREE.Color();

  function ripple(planet, hex) {
    const free = ripples.reduce((best, r) => (r.age > best.age ? r : best), ripples[0]);
    free.age = 0;
    free.planet = planet;
    free.size = planet.radius * 5;
    free.uniforms.uColor.value.setHex(hex);
    free.mesh.visible = true;
  }

  return {
    group,
    // Queue a pulse after `delay` seconds; `onArrive` runs when it lands.
    launch(planet, hex, delay, onArrive) {
      const slot = slots.find((s) => !s.active) || slots.reduce((a, b) => (a.age > b.age ? a : b));
      Object.assign(slot, { active: true, planet, age: -delay, duration: 1.35, onArrive, launched: false });
      tint.setHex(hex);
      slot.color = [tint.r, tint.g, tint.b];
      slot.hex = hex;
    },
    active() { return slots.some((s) => s.active) || ripples.some((r) => r.age < 1); },
    update(dt, camera, onLaunch) {
      for (let p = 0; p < POOL; p++) {
        const slot = slots[p];
        const base = p * TRAIL;
        if (!slot.active) {
          for (let i = 0; i < TRAIL; i++) alpha.array[base + i] = 0;
          continue;
        }
        slot.age += dt;
        if (slot.age < 0) {
          for (let i = 0; i < TRAIL; i++) alpha.array[base + i] = 0;
          continue;
        }
        if (!slot.launched) { slot.launched = true; onLaunch(slot.planet); }
        const end = slot.planet.pulseEnd();
        const t = Math.min(1, slot.age / slot.duration);
        const head = easeInOut(t) * end;
        for (let i = 0; i < TRAIL; i++) {
          const u = Math.max(0, head - i * 0.016);
          slot.planet.curve.getPointAt(u, point);
          position.setXYZ(base + i, point.x, point.y, point.z);
          color.setXYZ(base + i, slot.color[0], slot.color[1], slot.color[2]);
          alpha.array[base + i] = (1 - i / TRAIL) * (t < 0.08 ? t / 0.08 : 1);
        }
        if (t >= 1) {
          slot.active = false;
          slot.planet.flash(slot.hex);
          ripple(slot.planet, slot.hex);
          if (slot.onArrive) slot.onArrive();
        }
      }
      position.needsUpdate = color.needsUpdate = alpha.needsUpdate = true;
      for (const r of ripples) {
        if (r.age >= 1) { r.mesh.visible = false; continue; }
        r.age += dt / 1.1;
        r.uniforms.uProgress.value = Math.min(1, r.age);
        r.mesh.position.copy(r.planet.group.position);
        r.mesh.quaternion.copy(camera.quaternion);
        r.mesh.scale.setScalar(r.size);
      }
    },
    clear() {
      for (const slot of slots) slot.active = false;
      for (const r of ripples) { r.age = Infinity; r.mesh.visible = false; }
    },
    dispose() {
      geometry.dispose();
      material.dispose();
      rippleGeometry.dispose();
      for (const r of ripples) r.mesh.material.dispose();
    },
  };
}
