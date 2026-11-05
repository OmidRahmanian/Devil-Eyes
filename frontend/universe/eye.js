// Devils Eyes itself: an obsidian eye with a burning slit-pupil iris and a
// corona. It breathes while idle and turns toward the planet it is watching.
import * as THREE from "../vendor/three.module.min.js";
import { NOISE } from "./glsl.js";

export const EYE_RADIUS = 2;

const EYE_VERTEX = /* glsl */ `
varying vec3 vObj;
varying vec3 vViewNormal;
void main() {
  vObj = position;
  vViewNormal = normalize(normalMatrix * normal);
  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
}`;

const EYE_FRAGMENT = /* glsl */ `
uniform float uTime;
uniform float uBreath;
uniform float uFire;
uniform float uDilate;
varying vec3 vObj;
varying vec3 vViewNormal;
${NOISE}
void main() {
  vec3 n = normalize(vObj);
  vec2 q = n.xy;
  float front = smoothstep(0.0, 0.25, n.z);
  float r = length(q);
  const float IRIS = 0.6;
  float iris = (1.0 - smoothstep(IRIS - 0.02, IRIS + 0.01, r)) * front;
  float width = 0.07 + uDilate * 0.05;
  float slit = (q.x * q.x) / (width * width) + (q.y * q.y) / 0.2116;
  float pupil = (1.0 - smoothstep(0.85, 1.0, slit)) * front;
  float angle = atan(q.y, q.x);
  float fibers = noise3(vec3(angle * 7.0, r * 9.0 - uTime * 0.15, uTime * 0.12));
  float fine = noise3(vec3(angle * 19.0, r * 3.0, 4.0 + uTime * 0.2));
  float rr = r / IRIS;
  vec3 irisColor = mix(vec3(1.0, 0.72, 0.18), vec3(0.95, 0.16, 0.06), smoothstep(0.1, 0.55, rr));
  irisColor = mix(irisColor, vec3(0.3, 0.02, 0.03), smoothstep(0.65, 1.0, rr));
  irisColor *= (0.65 + fibers * 0.7 + fine * 0.25) * (1.0 + uBreath * 0.25 + uFire * 0.9);
  irisColor += vec3(1.0, 0.45, 0.1) * exp(-max(slit - 1.0, 0.0) * 1.6) * 0.6 * (0.6 + uFire);
  float veins = smoothstep(0.62, 0.7, fbm(n * 5.0 + vec3(0.0, 0.0, uTime * 0.02)));
  vec3 sclera = vec3(0.035, 0.02, 0.03) + vec3(0.35, 0.02, 0.02) * veins * 0.35;
  vec3 color = mix(sclera, irisColor, iris);
  color = mix(color, vec3(0.0), pupil);
  vec3 vn = normalize(vViewNormal);
  color += vec3(0.55, 0.05, 0.04) * pow(1.0 - max(vn.z, 0.0), 3.0) * (0.7 + uBreath * 0.4);
  color += vec3(pow(max(dot(vn, normalize(vec3(-0.35, 0.45, 0.82))), 0.0), 90.0) * 0.85);
  gl_FragColor = vec4(color, 1.0);
}`;

const CORONA_VERTEX = /* glsl */ `
varying vec2 vUv;
void main() { vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`;

const CORONA_FRAGMENT = /* glsl */ `
uniform float uTime;
uniform float uBreath;
uniform float uFire;
varying vec2 vUv;
${NOISE}
void main() {
  vec2 c = (vUv - 0.5) * 2.0;
  float r = length(c);
  float angle = atan(c.y, c.x);
  float rays = noise3(vec3(angle * 6.0, uTime * 0.25, 0.0)) * 0.6 + noise3(vec3(angle * 17.0, uTime * 0.4, 3.0)) * 0.4;
  float core = exp(-pow(max(r - 0.33, 0.0) * 5.5, 1.2));
  float glow = exp(-r * 3.2);
  float a = (core * 0.85 + glow * (0.45 + rays * 0.8)) * (0.7 + uBreath * 0.35 + uFire * 0.8) * smoothstep(1.0, 0.7, r);
  vec3 color = mix(vec3(0.85, 0.1, 0.05), vec3(1.0, 0.5, 0.15), exp(-r * 4.0));
  gl_FragColor = vec4(color * a, 1.0);
}`;

export function createEye(tier) {
  const group = new THREE.Group();
  const uniforms = { uTime: { value: 0 }, uBreath: { value: 0 }, uFire: { value: 0 }, uDilate: { value: 0 } };
  const ballGeometry = new THREE.SphereGeometry(EYE_RADIUS, tier === "low" ? 40 : 64, tier === "low" ? 28 : 48);
  const ballMaterial = new THREE.ShaderMaterial({ uniforms, vertexShader: EYE_VERTEX, fragmentShader: EYE_FRAGMENT });
  const ball = new THREE.Mesh(ballGeometry, ballMaterial);
  const coronaGeometry = new THREE.PlaneGeometry(EYE_RADIUS * 6, EYE_RADIUS * 6);
  const coronaMaterial = new THREE.ShaderMaterial({
    uniforms, vertexShader: CORONA_VERTEX, fragmentShader: CORONA_FRAGMENT,
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
  });
  const corona = new THREE.Mesh(coronaGeometry, coronaMaterial);
  group.add(ball, corona);

  const aim = new THREE.Object3D();
  const look = new THREE.Vector3();
  const toCamera = new THREE.Vector3();
  const wander = new THREE.Vector3();
  let nextWander = 0;
  let fire = 0;

  return {
    group,
    fire() { fire = 1; },
    // `watch` is a world position to look toward, or null to look at the viewer.
    update(dt, time, camera, watch, motion) {
      uniforms.uTime.value = motion ? time : 0;
      uniforms.uBreath.value = motion ? 0.5 + 0.5 * Math.sin(time * 0.9) : 0.5;
      fire = Math.max(0, fire - dt * 1.6);
      uniforms.uFire.value = fire * fire;
      uniforms.uDilate.value += ((watch ? 1 : 0) - uniforms.uDilate.value) * Math.min(1, dt * 3);
      corona.quaternion.copy(camera.quaternion);

      toCamera.copy(camera.position).normalize();
      if (watch) {
        look.copy(watch).normalize().multiplyScalar(0.6).addScaledVector(toCamera, 0.55);
      } else {
        if (motion && time > nextWander) {
          // Small idle glances keep the eye alive.
          wander.set(Math.random() - 0.5, (Math.random() - 0.5) * 0.6, 0).multiplyScalar(0.35);
          nextWander = time + 2.5 + Math.random() * 3.5;
        }
        look.copy(toCamera);
        if (motion) look.add(wander);
      }
      aim.lookAt(look);
      ball.quaternion.slerp(aim.quaternion, 1 - Math.exp(-dt * 4));
    },
    dispose() {
      ballGeometry.dispose();
      ballMaterial.dispose();
      coronaGeometry.dispose();
      coronaMaterial.dispose();
    },
  };
}
