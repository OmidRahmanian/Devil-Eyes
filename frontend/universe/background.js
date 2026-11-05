// Deep-space backdrop: a nebula baked once into an equirectangular texture,
// a dense starfield and a few bright stars with diffraction spikes.
import * as THREE from "../vendor/three.module.min.js";
import { NOISE } from "./glsl.js";
import { random } from "./layout.js";

// The galactic band runs diagonally across the default view, left of centre.
const BAND = /* glsl */ `
const vec3 BAND_NORMAL = vec3(-0.8237, 0.5354, 0.1647);
const vec3 BAND_AXIS = vec3(0.5449, 0.8384, 0.0);
const float BAND_OFFSET = 0.16;
`;

const BAKE_FRAGMENT = /* glsl */ `
varying vec2 vUv;
${NOISE}
${BAND}
void main() {
  float lon = (vUv.x - 0.5) * 6.2831853;
  float lat = (vUv.y - 0.5) * 3.1415926;
  vec3 dir = vec3(cos(lat) * sin(lon), sin(lat), -cos(lat) * cos(lon));
  float warp = fbm(dir * 3.0) - 0.5;
  float off = dot(dir, BAND_NORMAL) - BAND_OFFSET;
  float band = exp(-pow((off + warp * 0.24) / 0.30, 2.0));
  float along = dot(dir, BAND_AXIS);
  vec3 p = dir * 2.6;
  float clouds = fbm(p + vec3(3.1, 7.7, 1.3));
  float detail = fbm(p * 2.7 + vec3(11.0));
  float lanes = smoothstep(0.47, 0.72, fbm(p * 4.2 + vec3(5.0, 2.0, 9.0)));
  vec3 teal = vec3(0.08, 0.34, 0.36);
  vec3 olive = vec3(0.40, 0.39, 0.20);
  vec3 amber = vec3(0.52, 0.29, 0.12);
  vec3 violet = vec3(0.46, 0.22, 0.62);
  vec3 col = mix(teal, olive, smoothstep(-0.9, -0.3, along + (clouds - 0.5)));
  col = mix(col, amber, smoothstep(-0.35, 0.15, along + (detail - 0.5) * 0.6));
  col = mix(col, violet, smoothstep(0.3, 0.7, along + (clouds - 0.5) * 0.5));
  float density = band * smoothstep(0.25, 0.75, clouds * 0.7 + band * 0.5);
  density *= 1.0 - lanes * 0.8 * band;
  vec3 haze = vec3(0.09, 0.14, 0.40) * smoothstep(0.2, 0.9, dot(dir, normalize(vec3(0.9, -0.3, -0.5))))
    * (0.4 + clouds * 0.6) * 0.32;
  vec3 color = vec3(0.006, 0.008, 0.016);
  color += col * (density * 0.8 + band * 0.12) * (0.6 + detail * 0.8) + haze;
  color += col * pow(max(detail - 0.55, 0.0) * 2.2, 2.0) * band;
  color += (hash31(vec3(gl_FragCoord.xy, 1.0)) - 0.5) / 255.0;
  gl_FragColor = vec4(color, 1.0);
}`;

const QUAD_VERTEX = /* glsl */ `
varying vec2 vUv;
void main() { vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }`;

const SKY_VERTEX = /* glsl */ `
varying vec3 vDir;
void main() {
  vDir = normalize(position);
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`;

const SKY_FRAGMENT = /* glsl */ `
uniform sampler2D uMap;
uniform float uFade;
varying vec3 vDir;
void main() {
  vec3 d = normalize(vDir);
  vec2 uv = vec2(atan(d.x, -d.z) / 6.2831853 + 0.5, asin(clamp(d.y, -1.0, 1.0)) / 3.1415926 + 0.5);
  gl_FragColor = vec4(texture2D(uMap, uv).rgb * uFade, 1.0);
}`;

const STAR_VERTEX = /* glsl */ `
attribute float aSize;
attribute vec3 aColor;
attribute float aPhase;
uniform float uTime;
uniform float uPixelRatio;
uniform float uTwinkle;
varying vec3 vColor;
varying float vAlpha;
void main() {
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  vAlpha = 1.0 - uTwinkle * 0.4 * (0.5 + 0.5 * sin(uTime * (0.5 + aPhase * 1.6) + aPhase * 40.0));
  gl_PointSize = aSize * uPixelRatio;
  vColor = aColor;
}`;

const STAR_FRAGMENT = /* glsl */ `
varying vec3 vColor;
varying float vAlpha;
void main() {
  float d = length(gl_PointCoord - 0.5);
  float a = smoothstep(0.5, 0.0, d);
  gl_FragColor = vec4(vColor * a * a * vAlpha, 1.0);
}`;

const FLARE_FRAGMENT = /* glsl */ `
varying vec3 vColor;
varying float vAlpha;
void main() {
  vec2 c = (gl_PointCoord - 0.5) * 2.0;
  float r = length(c);
  float core = exp(-r * r * 30.0);
  float glow = exp(-r * 5.0) * 0.3;
  float spikes = exp(-abs(c.x) * 42.0) * exp(-abs(c.y) * 3.0) + exp(-abs(c.y) * 42.0) * exp(-abs(c.x) * 3.0);
  float a = (core + glow + spikes * 0.55) * smoothstep(1.0, 0.6, r) * vAlpha;
  gl_FragColor = vec4(vColor * a, 1.0);
}`;

const STAR_TINTS = [
  [0.82, 0.88, 1.0], [1.0, 1.0, 1.0], [1.0, 0.95, 0.82], [1.0, 0.78, 0.55],
  [0.62, 0.76, 1.0], [1.0, 0.6, 0.5], [0.9, 0.92, 1.0],
];

function bake(renderer, size) {
  const target = new THREE.WebGLRenderTarget(size, size / 2, {
    generateMipmaps: true, minFilter: THREE.LinearMipmapLinearFilter, magFilter: THREE.LinearFilter,
    depthBuffer: false,
  });
  const scene = new THREE.Scene();
  const geometry = new THREE.PlaneGeometry(2, 2);
  const material = new THREE.ShaderMaterial({ vertexShader: QUAD_VERTEX, fragmentShader: BAKE_FRAGMENT, depthTest: false });
  scene.add(new THREE.Mesh(geometry, material));
  renderer.setRenderTarget(target);
  renderer.render(scene, new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1));
  renderer.setRenderTarget(null);
  geometry.dispose();
  material.dispose();
  return target;
}

function towardBand(rng) {
  // A random direction, pulled toward the galactic band about half the time.
  const v = new THREE.Vector3(rng() * 2 - 1, rng() * 2 - 1, rng() * 2 - 1);
  while (v.lengthSq() < 1e-4) v.set(rng() * 2 - 1, rng() * 2 - 1, rng() * 2 - 1);
  v.normalize();
  if (rng() < 0.5) {
    const normal = new THREE.Vector3(-0.8237, 0.5354, 0.1647);
    const off = v.dot(normal) - 0.16;
    v.addScaledVector(normal, -off * (0.75 + rng() * 0.2)).normalize();
  }
  return v;
}

function starPoints({ count, rng, radius, sizes, material }) {
  const position = new Float32Array(count * 3);
  const color = new Float32Array(count * 3);
  const size = new Float32Array(count);
  const phase = new Float32Array(count);
  for (let i = 0; i < count; i++) {
    const dir = towardBand(rng);
    const r = radius[0] + rng() * (radius[1] - radius[0]);
    position.set([dir.x * r, dir.y * r, dir.z * r], i * 3);
    const tint = STAR_TINTS[Math.floor(rng() * STAR_TINTS.length)];
    const brightness = 0.35 + rng() ** 2 * 0.75;
    color.set(tint.map((c) => c * brightness), i * 3);
    size[i] = sizes(rng);
    phase[i] = rng();
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(position, 3));
  geometry.setAttribute("aColor", new THREE.BufferAttribute(color, 3));
  geometry.setAttribute("aSize", new THREE.BufferAttribute(size, 1));
  geometry.setAttribute("aPhase", new THREE.BufferAttribute(phase, 1));
  const points = new THREE.Points(geometry, material);
  points.frustumCulled = false;
  return points;
}

export function createBackground(renderer, tier) {
  const group = new THREE.Group();
  const baked = bake(renderer, tier === "low" ? 1024 : 2048);
  const skyGeometry = new THREE.SphereGeometry(500, 48, 24);
  const skyMaterial = new THREE.ShaderMaterial({
    uniforms: { uMap: { value: baked.texture }, uFade: { value: 1 } },
    vertexShader: SKY_VERTEX, fragmentShader: SKY_FRAGMENT,
    side: THREE.BackSide, depthWrite: false, depthTest: false,
  });
  const sky = new THREE.Mesh(skyGeometry, skyMaterial);
  sky.renderOrder = -10;
  sky.frustumCulled = false;

  const uniforms = {
    uTime: { value: 0 },
    uPixelRatio: { value: renderer.getPixelRatio() },
    uTwinkle: { value: 1 },
  };
  const starMaterial = new THREE.ShaderMaterial({
    uniforms, vertexShader: STAR_VERTEX, fragmentShader: STAR_FRAGMENT,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const flareMaterial = new THREE.ShaderMaterial({
    uniforms, vertexShader: STAR_VERTEX, fragmentShader: FLARE_FRAGMENT,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const rng = random(0xdecade);
  const stars = starPoints({
    count: tier === "low" ? 2600 : 7000, rng, radius: [300, 420], material: starMaterial,
    sizes: (r) => 1.2 + r() ** 3 * 2.6,
  });
  const flares = starPoints({
    count: tier === "low" ? 16 : 30, rng, radius: [260, 300], material: flareMaterial,
    sizes: (r) => 16 + r() * 22,
  });
  stars.renderOrder = -9;
  flares.renderOrder = -8;
  group.add(sky, stars, flares);

  return {
    group,
    setPixelRatio(ratio) { uniforms.uPixelRatio.value = ratio; },
    setMotion(enabled) { uniforms.uTwinkle.value = enabled ? 1 : 0; },
    update(time, camera, motion) {
      uniforms.uTime.value = time;
      sky.position.copy(camera.position);
      if (motion) {
        // A very slow drift so the sky never looks frozen.
        sky.rotation.y = time * 0.0025;
        stars.rotation.y = flares.rotation.y = time * 0.0025;
      }
    },
    dispose() {
      baked.dispose();
      skyGeometry.dispose();
      skyMaterial.dispose();
      for (const points of [stars, flares]) points.geometry.dispose();
      starMaterial.dispose();
      flareMaterial.dispose();
    },
  };
}
