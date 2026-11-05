// Planets: one per target. Size follows asset count, the atmosphere follows the
// highest open severity, a scanning ring spins while a run is active, and a
// filament ties every planet back to the eye.
import * as THREE from "../vendor/three.module.min.js";
import { NOISE } from "./glsl.js";
import { EYE_RADIUS } from "./eye.js";
import { SEVERITY_GLOW, hash, paletteFor, planetRadius, random } from "./layout.js";

const WORLD_VERTEX = /* glsl */ `
varying vec3 vObj;
varying vec3 vWorldPos;
varying vec3 vWorldNormal;
void main() {
  vObj = position;
  vec4 world = modelMatrix * vec4(position, 1.0);
  vWorldPos = world.xyz;
  vWorldNormal = normalize(mat3(modelMatrix) * normal);
  gl_Position = projectionMatrix * viewMatrix * world;
}`;

const SURFACE_FRAGMENT = /* glsl */ `
uniform vec3 uColA;
uniform vec3 uColB;
uniform vec3 uColC;
uniform vec3 uGlow;
uniform vec3 uFlashColor;
uniform float uSeed;
uniform float uBanded;
uniform float uDim;
uniform float uHighlight;
uniform float uFlash;
varying vec3 vObj;
varying vec3 vWorldPos;
varying vec3 vWorldNormal;
${NOISE}
void main() {
  vec3 s = normalize(vObj);
  vec3 p = s * 1.7 + vec3(uSeed);
  float n = fbm(p);
  float bands = 0.5 + 0.5 * sin(s.y * 9.0 + n * 5.0);
  float t = mix(n, bands * 0.8 + n * 0.2, uBanded);
  vec3 color = mix(uColA, uColB, smoothstep(0.32, 0.62, t));
  color = mix(color, uColC, smoothstep(0.6, 0.82, mix(fbm(p * 2.6), t, uBanded * 0.5)));
  vec3 N = normalize(vWorldNormal);
  vec3 L = normalize(-vWorldPos);
  vec3 V = normalize(cameraPosition - vWorldPos);
  float diffuse = max(dot(N, L), 0.0);
  float rim = pow(1.0 - max(dot(N, V), 0.0), 3.0);
  vec3 c = color * (0.16 + diffuse * 1.1 * vec3(1.0, 0.84, 0.8));
  c += uGlow * rim * (0.5 + uHighlight * 0.5) + uFlashColor * uFlash * (rim * 1.4 + 0.3);
  gl_FragColor = vec4(c * (1.0 - uDim * 0.6), 1.0);
}`;

const ATMOSPHERE_FRAGMENT = /* glsl */ `
uniform vec3 uGlow;
uniform vec3 uFlashColor;
uniform float uDim;
uniform float uHighlight;
uniform float uFlash;
uniform float uOpacity;
varying vec3 vWorldPos;
varying vec3 vWorldNormal;
void main() {
  vec3 N = normalize(vWorldNormal);
  vec3 V = normalize(cameraPosition - vWorldPos);
  vec3 L = normalize(-vWorldPos);
  float x = 1.0 - abs(dot(N, V));
  float halo = smoothstep(0.3, 0.55, x) * pow(1.0 - x, 1.3) * 2.2;
  float side = 0.45 + 0.55 * (dot(N, L) * 0.5 + 0.5);
  float a = halo * side * (0.8 + uHighlight * 0.8) * (1.0 - uDim * 0.65) * uOpacity;
  gl_FragColor = vec4(uGlow * a + uFlashColor * halo * uFlash * 1.8, 1.0);
}`;

const RING_VERTEX = /* glsl */ `
varying vec2 vPos;
void main() { vPos = position.xy; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`;

const RING_FRAGMENT = /* glsl */ `
uniform float uTime;
uniform float uVisible;
varying vec2 vPos;
void main() {
  float t = (length(vPos) - 1.5) / 0.7;
  float edges = smoothstep(0.0, 0.12, t) * smoothstep(1.0, 0.85, t);
  float bands = 0.55 + 0.45 * sin(t * 38.0);
  float sweep = pow(fract(atan(vPos.y, vPos.x) / 6.2831853 - uTime * 0.35), 6.0);
  float a = edges * (0.18 * bands + sweep * 0.9) * uVisible;
  gl_FragColor = vec4(vec3(0.7, 0.85, 1.0) * a, 1.0);
}`;

const MOON_FRAGMENT = /* glsl */ `
uniform float uDim;
varying vec3 vWorldPos;
varying vec3 vWorldNormal;
void main() {
  float diffuse = max(dot(normalize(vWorldNormal), normalize(-vWorldPos)), 0.0);
  gl_FragColor = vec4(vec3(0.62, 0.6, 0.7) * (0.14 + diffuse) * (1.0 - uDim * 0.6), 1.0);
}`;

const DUST_VERTEX = /* glsl */ `
attribute vec3 aSeed;
uniform float uTime;
uniform float uSpread;
uniform float uOpacity;
uniform float uPixelRatio;
varying float vAlpha;
void main() {
  float r = aSeed.x;
  float angle = aSeed.y + uTime * (0.25 + 0.5 * (1.0 - r));
  vec3 p = vec3(cos(angle) * r, aSeed.z * 0.25 * (1.0 - r * 0.5), sin(angle) * r) * uSpread;
  vec4 mv = modelViewMatrix * vec4(p, 1.0);
  gl_Position = projectionMatrix * mv;
  gl_PointSize = (2.0 + 3.0 * fract(aSeed.y * 7.0)) * uPixelRatio * clamp(30.0 / -mv.z, 0.3, 4.0);
  vAlpha = uOpacity * (1.0 - r * 0.6);
}`;

const DUST_FRAGMENT = /* glsl */ `
uniform vec3 uColor;
varying float vAlpha;
void main() {
  float d = length(gl_PointCoord - 0.5);
  gl_FragColor = vec4(uColor * smoothstep(0.5, 0.0, d) * vAlpha, 1.0);
}`;

const FILAMENT_VERTEX = /* glsl */ `
varying float vT;
void main() { vT = uv.x; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`;

const FILAMENT_FRAGMENT = /* glsl */ `
uniform vec3 uColor;
uniform vec3 uShimmerColor;
uniform float uGrow;
uniform float uActive;
uniform float uBase;
uniform float uTime;
uniform float uShimmer;
uniform float uShimmerPos;
uniform float uOpacity;
varying float vT;
void main() {
  if (vT > uGrow) discard;
  float ends = smoothstep(0.02, 0.12, vT) * smoothstep(1.0, 0.9, vT);
  float flow = 0.5 + 0.5 * sin(vT * 36.0 - uTime * 2.4);
  float a = (uBase + uActive * 0.6 * (0.7 + 0.3 * flow)) * ends;
  float s = exp(-pow((vT - uShimmerPos) * 7.0, 2.0)) * uShimmer;
  gl_FragColor = vec4((uColor * a + uShimmerColor * s * ends * 0.9) * uOpacity, 1.0);
}`;

const FILAMENT_COLOR = new THREE.Color(0.22, 0.42, 1.0);
const DUST_COUNT = 420;

export function createPlanetResources(tier) {
  const detail = tier === "low" ? [32, 24] : [56, 40];
  const sphere = new THREE.SphereGeometry(1, detail[0], detail[1]);
  // Only the selected planet is ever seen up close, so only it gets the fine mesh.
  const sphereFine = new THREE.SphereGeometry(1, 128, 96);
  const ring = new THREE.RingGeometry(1.5, 2.2, 96, 1);
  const moon = new THREE.SphereGeometry(1, 14, 10);
  const moonMaterial = new THREE.ShaderMaterial({ uniforms: { uDim: { value: 0 } }, vertexShader: WORLD_VERTEX, fragmentShader: MOON_FRAGMENT });
  const seeds = new Float32Array(DUST_COUNT * 3);
  const rng = random(0x5eed);
  for (let i = 0; i < DUST_COUNT; i++) seeds.set([Math.sqrt(rng()), rng() * Math.PI * 2, rng() * 2 - 1], i * 3);
  const dust = new THREE.BufferGeometry();
  // Positions come from aSeed in the shader; the position attribute only sizes the draw.
  dust.setAttribute("position", new THREE.BufferAttribute(new Float32Array(DUST_COUNT * 3), 3));
  dust.setAttribute("aSeed", new THREE.BufferAttribute(seeds, 3));
  return {
    sphere, sphereFine, ring, moon, moonMaterial, dust, pixelRatio: { value: 1 },
    dispose() { for (const item of [sphere, sphereFine, ring, moon, moonMaterial, dust]) item.dispose(); },
  };
}

function color(hex) {
  return new THREE.Color(hex);
}

function ease(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

function easeOutBack(t) {
  const c = 1.4;
  return 1 + (c + 1) * Math.pow(t - 1, 3) + c * Math.pow(t - 1, 2);
}

export class Planet {
  constructor(data, position, resources, { fresh }) {
    this.id = data.id;
    this.resources = resources;
    this.rng = random(hash(data.id));
    this.group = new THREE.Group();
    this.body = new THREE.Group();
    this.group.add(this.body);
    const palette = paletteFor(data.id);
    this.surfaceUniforms = {
      uColA: { value: color(palette.colors[0]) }, uColB: { value: color(palette.colors[1]) },
      uColC: { value: color(palette.colors[2]) }, uGlow: { value: color(SEVERITY_GLOW.none) }, uFlashColor: { value: color(0xffffff) },
      uSeed: { value: (hash(data.id) % 1000) / 37 }, uBanded: { value: palette.banded ? 1 : 0 },
      uDim: { value: 0 }, uHighlight: { value: 0 }, uFlash: { value: 0 },
    };
    this.surface = new THREE.Mesh(resources.sphere, new THREE.ShaderMaterial({
      uniforms: this.surfaceUniforms, vertexShader: WORLD_VERTEX, fragmentShader: SURFACE_FRAGMENT,
    }));
    this.surface.rotation.z = (this.rng() - 0.5) * 0.6;
    this.atmosphere = new THREE.Mesh(resources.sphere, new THREE.ShaderMaterial({
      uniforms: { ...this.surfaceUniforms, uOpacity: { value: 1 } },
      vertexShader: WORLD_VERTEX, fragmentShader: ATMOSPHERE_FRAGMENT,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    }));
    this.atmosphere.scale.setScalar(1.22);
    this.ringUniforms = { uTime: { value: 0 }, uVisible: { value: 0 } };
    this.ring = new THREE.Mesh(resources.ring, new THREE.ShaderMaterial({
      uniforms: this.ringUniforms, vertexShader: RING_VERTEX, fragmentShader: RING_FRAGMENT,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending, side: THREE.DoubleSide,
    }));
    this.ring.rotation.x = 1.15;
    this.ring.visible = false;
    this.body.add(this.surface, this.atmosphere, this.ring);

    this.moons = [];
    this.moonGroup = new THREE.Group();
    this.group.add(this.moonGroup);
    for (let i = 0; i < 5; i++) {
      const mesh = new THREE.Mesh(resources.moon, resources.moonMaterial);
      mesh.visible = false;
      this.moons.push({ mesh, phase: this.rng() * Math.PI * 2, speed: 0.25 + this.rng() * 0.35,
        tilt: (this.rng() - 0.5) * 0.9, size: 0.08 + this.rng() * 0.08 });
      this.moonGroup.add(mesh);
    }

    this.dustUniforms = {
      uTime: { value: 0 }, uSpread: { value: 1.3 }, uOpacity: { value: 0 },
      uPixelRatio: resources.pixelRatio, uColor: { value: new THREE.Color(0.62, 0.56, 0.78) },
    };
    this.dust = new THREE.Points(resources.dust, new THREE.ShaderMaterial({
      uniforms: this.dustUniforms, vertexShader: DUST_VERTEX, fragmentShader: DUST_FRAGMENT,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    }));
    this.dust.rotation.x = -1.1;
    this.dust.frustumCulled = false;
    this.group.add(this.dust);

    this.filamentUniforms = {
      uColor: { value: FILAMENT_COLOR }, uShimmerColor: { value: new THREE.Color(0.95, 0.93, 1.0) },
      uGrow: { value: 0 }, uActive: { value: 0 }, uBase: { value: 0.12 }, uTime: { value: 0 },
      uShimmer: { value: 0 }, uShimmerPos: { value: 0 }, uOpacity: { value: 1 },
    };
    this.filamentMaterial = new THREE.ShaderMaterial({
      uniforms: this.filamentUniforms, vertexShader: FILAMENT_VERTEX, fragmentShader: FILAMENT_FRAGMENT,
      transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    });
    this.filament = null;
    this.bend = (hash(data.id + "#bend") % 2 ? 1 : -1) * (0.22 + this.rng() * 0.14);

    this.radius = planetRadius(data.assets || 0);
    this.glow = color(SEVERITY_GLOW.none);
    this.targetGlow = color(SEVERITY_GLOW.none);
    this.hovered = false;
    this.selected = false;
    this.dimmed = false;
    this.shimmerAge = Infinity;
    // Brand-new targets condense out of dust; existing ones simply appear.
    this.formation = 0;
    this.formationTime = fresh ? 2.6 : 0.9;
    this.fresh = fresh;
    this.setPosition(position);
    this.setData(data);
  }

  setPosition(position) {
    this.group.position.set(position.x, position.y, position.z);
    const end = this.group.position.clone();
    const dir = end.clone().normalize();
    const start = dir.clone().multiplyScalar(EYE_RADIUS * 0.85);
    const length = start.distanceTo(end);
    const side = new THREE.Vector3().crossVectors(dir, new THREE.Vector3(0, 0, 1));
    if (side.lengthSq() < 1e-6) side.set(1, 0, 0);
    side.normalize();
    const control = start.clone().lerp(end, 0.5).addScaledVector(side, length * this.bend).add(new THREE.Vector3(0, 0, length * 0.08));
    this.curve = new THREE.QuadraticBezierCurve3(start, control, end);
    this.curveLength = this.curve.getLength();
    if (this.filament) {
      this.filament.geometry.dispose();
      this.filament.geometry = new THREE.TubeGeometry(this.curve, 64, 0.035, 5, false);
    } else {
      this.filament = new THREE.Mesh(new THREE.TubeGeometry(this.curve, 64, 0.035, 5, false), this.filamentMaterial);
      this.filament.frustumCulled = false;
    }
  }

  setData(data) {
    this.data = data;
    this.targetRadius = planetRadius(data.assets || 0);
    this.targetGlow.setHex(SEVERITY_GLOW[data.severity || "none"] || SEVERITY_GLOW.none);
    this.ring.visible = true;
    this.running = Boolean(data.running);
    this.moonCount = data.proto ? 0 : Math.min(5, data.moons || 0);
    this.filamentUniforms.uBase.value = data.proto ? 0.05 : 0.12;
  }

  setHover(value) { this.hovered = value; }
  setSelected(value) {
    this.selected = value;
    this.surface.geometry = this.atmosphere.geometry = value ? this.resources.sphereFine : this.resources.sphere;
  }
  setDim(value) { this.dimmed = value; }

  flash(hex) {
    this.surfaceUniforms.uFlash.value = 1;
    this.surfaceUniforms.uFlashColor.value.setHex(hex);
  }

  shimmer() { this.shimmerAge = 0; }

  // Where a pulse should stop: just outside the atmosphere.
  pulseEnd() {
    return Math.max(0.5, 1 - (this.radius * 1.15) / this.curveLength);
  }

  pickRadius() { return this.data.proto ? 1.3 : this.radius * 1.25; }

  update(dt, time, motion) {
    this.formation = Math.min(1, this.formation + dt / this.formationTime);
    const f = this.formation;
    const k = 1 - Math.exp(-dt * 3);
    this.radius += (this.targetRadius - this.radius) * k;
    this.glow.lerp(this.targetGlow, k);
    this.surfaceUniforms.uGlow.value.copy(this.glow);

    let bodyScale;
    if (this.data.proto) {
      bodyScale = 0;
      this.dustUniforms.uSpread.value = 1.3;
      this.dustUniforms.uOpacity.value = 0.6 * Math.min(1, f * 2) * (this.dimmed ? 0.4 : 1) * (this.hovered || this.selected ? 1.5 : 1);
    } else if (this.fresh) {
      // Dust swirls inward and the sphere condenses out of it.
      bodyScale = easeOutBack(Math.min(1, Math.max(0, (f - 0.35) / 0.65)));
      this.dustUniforms.uSpread.value = 3.2 * (1 - f) + 0.3;
      this.dustUniforms.uOpacity.value = Math.sin(Math.PI * f) * 0.9;
    } else {
      bodyScale = ease(f);
      this.dustUniforms.uOpacity.value = 0;
    }
    this.dust.visible = this.dustUniforms.uOpacity.value > 0.001;
    this.body.visible = bodyScale > 0.001;
    this.body.scale.setScalar(Math.max(0.001, this.radius * bodyScale));
    this.dustUniforms.uTime.value = motion ? time : 0;
    this.dust.scale.setScalar(this.data.proto ? 1 : this.radius);

    if (motion) this.surface.rotation.y += dt * 0.08;
    const u = this.surfaceUniforms;
    u.uDim.value += ((this.dimmed ? 1 : 0) - u.uDim.value) * k;
    u.uHighlight.value += ((this.hovered || this.selected ? 1 : 0) - u.uHighlight.value) * Math.min(1, dt * 6);
    u.uFlash.value = Math.max(0, u.uFlash.value - dt * 1.2);

    this.ringUniforms.uVisible.value += ((this.running ? 1 : 0) - this.ringUniforms.uVisible.value) * k;
    this.ring.visible = this.ringUniforms.uVisible.value > 0.01;
    this.ringUniforms.uTime.value = motion ? time : 0.3;

    for (let i = 0; i < this.moons.length; i++) {
      const moon = this.moons[i];
      moon.mesh.visible = i < this.moonCount && bodyScale > 0.5;
      if (!moon.mesh.visible) continue;
      const angle = moon.phase + (motion ? time * moon.speed : 0);
      const orbit = this.radius * (1.9 + i * 0.38);
      moon.mesh.position.set(Math.cos(angle) * orbit, Math.sin(angle) * orbit * Math.sin(moon.tilt), Math.sin(angle) * orbit * Math.cos(moon.tilt));
      moon.mesh.scale.setScalar(moon.size * (0.7 + this.radius * 0.3));
    }

    const fu = this.filamentUniforms;
    fu.uGrow.value = Math.min(1.001, this.fresh ? f * 1.2 : ease(f) * 1.001);
    fu.uActive.value += ((this.hovered || this.selected ? 1 : 0) + u.uFlash.value * 0.8 - fu.uActive.value) * Math.min(1, dt * 5);
    fu.uOpacity.value = this.dimmed ? 0.45 : 1;
    fu.uTime.value = motion ? time : 0;
    this.shimmerAge += dt;
    fu.uShimmer.value = this.shimmerAge < 1.8 ? Math.sin(Math.PI * this.shimmerAge / 1.8) : 0;
    fu.uShimmerPos.value = Math.min(1, this.shimmerAge / 1.6);
  }

  dispose() {
    this.surface.material.dispose();
    this.atmosphere.material.dispose();
    this.ring.material.dispose();
    this.dust.material.dispose();
    this.filamentMaterial.dispose();
    if (this.filament) this.filament.geometry.dispose();
  }
}
