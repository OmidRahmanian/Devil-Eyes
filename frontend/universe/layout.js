// Deterministic placement. A planet's spot comes from a hash of its id, so the
// same targets always form the same sky, in the WebGL scene and the 2D fallback.

export function hash(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

// mulberry32: a tiny seeded generator.
export function random(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const EYE_CLEARANCE = 6.2;
const SPACING = 4.1;

// Returns Map(id -> {x, y, z}). `aspect` is width / height; wide screens spread
// planets sideways, tall screens stack them, like the reference sketch.
export function place(ids, aspect) {
  const sx = Math.sqrt(Math.min(Math.max(aspect, 0.55), 2.0));
  const sy = 1 / sx;
  const outer = Math.max(13.5, Math.sqrt(EYE_CLEARANCE ** 2 + (ids.length * 20) / Math.PI));
  const placed = [];
  const spots = new Map();
  for (const id of [...ids].sort()) {
    const rng = random(hash(id));
    let spot = null;
    for (let attempt = 0; attempt < 60 && !spot; attempt++) {
      const reach = outer + Math.floor(attempt / 15) * 2.5;
      const angle = rng() * Math.PI * 2;
      const radius = EYE_CLEARANCE + 0.6 + rng() * (reach - EYE_CLEARANCE);
      const candidate = { x: Math.cos(angle) * radius * sx, y: Math.sin(angle) * radius * sy, z: (rng() - 0.5) * 2.4 };
      if (Math.hypot(candidate.x, candidate.y) < EYE_CLEARANCE) continue;
      if (placed.every((p) => Math.hypot(p.x - candidate.x, p.y - candidate.y) >= SPACING)) spot = candidate;
    }
    if (!spot) {
      // Crowded sky: fall back to a spiral slot that cannot collide.
      const k = placed.length;
      const angle = k * 2.39996;
      const radius = outer + 2 + Math.sqrt(k) * 2.2;
      spot = { x: Math.cos(angle) * radius * sx, y: Math.sin(angle) * radius * sy, z: 0 };
    }
    placed.push(spot);
    spots.set(id, spot);
  }
  return spots;
}

// Display palettes: [shadow, mid, highlight] plus whether the planet is banded.
export const PALETTES = [
  { colors: [0x1b3a5c, 0x6fa8c9, 0xe6f2f7], banded: false },
  { colors: [0x5a3418, 0xc27c3e, 0xf0d29a], banded: false },
  { colors: [0x2a0a06, 0x8a2a12, 0xf2a33a], banded: false },
  { colors: [0x0b2545, 0x13667a, 0x8dd3c7], banded: false },
  { colors: [0x24123d, 0x6b3fa0, 0xc9a7e8], banded: true },
  { colors: [0x0e2f26, 0x2f7d5b, 0xb7e4a8], banded: false },
  { colors: [0x3b1d14, 0x9c4a2f, 0xe0a07a], banded: true },
  { colors: [0x1e2433, 0x56637a, 0xc7cfdb], banded: true },
  { colors: [0x3d2b12, 0xb88a3c, 0xf3e2b5], banded: true },
  { colors: [0x10202e, 0x2e6f8e, 0xf0b67f], banded: false },
];

export function paletteFor(id) {
  return PALETTES[hash(id + "#palette") % PALETTES.length];
}

// Atmosphere colours by highest open severity; calm teal when nothing is open.
export const SEVERITY_GLOW = {
  critical: 0xff3b3b,
  high: 0xff8a2a,
  medium: 0xf2c14e,
  low: 0x8fa6c4,
  info: 0x5fd3c8,
  none: 0x5fd3c8,
};

// Pulse colours by event kind (findings use their severity colour).
export const PULSE_COLOR = { asset: 0x4fd8ff, change: 0xffb23e, run: 0xf4f1ff };

export function planetRadius(assets) {
  return Math.min(1.6, Math.max(0.55, 0.55 + 0.3 * Math.log2(1 + assets)));
}
