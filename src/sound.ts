// Interface sounds, synthesized with the Web Audio API: no audio files, no dependencies.
//
// The rest of the app only calls play('name') (optionally with an OSI layer number, which
// picks the note). Everything about how a sound is made lives in this file.
//
// Browsers only let a page start audio after a user gesture, so the AudioContext is created
// on the first pointer or key press. Until then play() does nothing, which also means a
// deep-linked lesson animating on load stays silent.
import { store } from './store';

export type SoundName =
  | 'next' | 'prev' | 'play' | 'pause'
  | 'select' | 'field' | 'expand' | 'collapse'
  | 'open' | 'home' | 'theme' | 'toggle'
  | 'depart' | 'hop' | 'wrap' | 'unwrap' | 'arrive' | 'error';

const KEY = 'sound';
const VOLUME = 0.2;

// ---------------------------------------------------------------- enabled state

export function isEnabled(): boolean {
  return store.get(KEY) !== 'off';
}

export function setEnabled(on: boolean): void {
  store.set(KEY, on ? 'on' : 'off');
  if (!ctx || !master) return;
  // Silence anything already scheduled right away, not after it finishes.
  const now = ctx.currentTime;
  master.gain.cancelScheduledValues(now);
  master.gain.setValueAtTime(on ? VOLUME : 0, now);
  if (on && ctx.state === 'suspended') ctx.resume().catch(() => {});
}

// ---------------------------------------------------------------- throttling

/** Lets a key through at most once per `gap` milliseconds. */
export class Throttle {
  private last = new Map<string, number>();

  constructor(private gap: number) {}

  allow(key: string, now: number): boolean {
    const prev = this.last.get(key);
    if (prev !== undefined && now - prev < this.gap) return false;
    this.last.set(key, now);
    return true;
  }
}

// Holding an arrow key or clicking quickly through bytes repeats a sound every few ms.
const throttle = new Throttle(70);

// ---------------------------------------------------------------- audio graph

type Ctor = typeof AudioContext;
let ctx: AudioContext | null = null;
let master: GainNode | null = null;
let noiseBuf: AudioBuffer | null = null;

function unlock(): void {
  try {
    if (!ctx) {
      const AC: Ctor | undefined = window.AudioContext ?? (window as unknown as { webkitAudioContext?: Ctor }).webkitAudioContext;
      if (!AC) return;
      ctx = new AC();
      master = ctx.createGain();
      master.gain.value = isEnabled() ? VOLUME : 0;
      master.connect(ctx.destination);
    }
    if (ctx.state === 'suspended' && isEnabled()) ctx.resume().catch(() => {});
  } catch {
    ctx = null;
    master = null;
  }
}

if (typeof window !== 'undefined') {
  for (const ev of ['pointerdown', 'keydown', 'touchend']) window.addEventListener(ev, unlock, { capture: true, passive: true });
}

interface Tone {
  freq: number;
  /** Glide to this frequency over the tone's duration. */
  to?: number;
  dur: number;
  type?: OscillatorType;
  gain?: number;
  delay?: number;
  /** Optional low-pass cutoff to soften bright waveforms. */
  lp?: number;
}

function tone(o: Tone): void {
  const c = ctx!;
  const t0 = c.currentTime + 0.005 + (o.delay ?? 0);
  const osc = c.createOscillator();
  osc.type = o.type ?? 'sine';
  osc.frequency.setValueAtTime(o.freq, t0);
  if (o.to) osc.frequency.exponentialRampToValueAtTime(o.to, t0 + o.dur);
  const g = c.createGain();
  // Fast attack, exponential decay: a soft "tick" rather than a beep with hard edges.
  g.gain.setValueAtTime(0.0001, t0);
  g.gain.exponentialRampToValueAtTime(o.gain ?? 0.5, t0 + 0.006);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + o.dur);
  let out: AudioNode = g;
  osc.connect(g);
  if (o.lp) {
    const f = c.createBiquadFilter();
    f.type = 'lowpass';
    f.frequency.value = o.lp;
    g.connect(f);
    out = f;
  }
  out.connect(master!);
  osc.start(t0);
  osc.stop(t0 + o.dur + 0.02);
}

/** A puff of band-passed noise whose centre sweeps from `from` to `to` Hz. */
function noise(from: number, to: number, dur: number, gain: number): void {
  const c = ctx!;
  if (!noiseBuf) {
    noiseBuf = c.createBuffer(1, Math.ceil(c.sampleRate * 0.25), c.sampleRate);
    const d = noiseBuf.getChannelData(0);
    for (let i = 0; i < d.length; i++) d[i] = Math.random() * 2 - 1;
  }
  const t0 = c.currentTime + 0.005;
  const src = c.createBufferSource();
  src.buffer = noiseBuf;
  const f = c.createBiquadFilter();
  f.type = 'bandpass';
  f.Q.value = 1.4;
  f.frequency.setValueAtTime(from, t0);
  f.frequency.exponentialRampToValueAtTime(to, t0 + dur);
  const g = c.createGain();
  g.gain.setValueAtTime(0.0001, t0);
  g.gain.exponentialRampToValueAtTime(gain, t0 + dur * 0.35);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
  src.connect(f).connect(g).connect(master!);
  src.start(t0);
  src.stop(t0 + dur + 0.02);
}

// ---------------------------------------------------------------- the sounds

/** One note per OSI layer, from a major pentatonic scale so any two sound fine together. */
const LAYER_NOTE = [392, 392, 440, 523.3, 587.3, 659.3, 784, 880]; // index = OSI layer (1–7)
const note = (osi = 7) => LAYER_NOTE[Math.min(7, Math.max(1, Math.round(osi)))];

const SOUNDS: Record<SoundName, (osi?: number) => void> = {
  // Stepping: the same blip, forward a fourth above back.
  next: () => tone({ freq: 784, to: 880, dur: 0.05, type: 'triangle', gain: 0.35 }),
  prev: () => tone({ freq: 587.3, to: 523.3, dur: 0.05, type: 'triangle', gain: 0.35 }),
  play: () => {
    tone({ freq: 523.3, dur: 0.06, type: 'triangle', gain: 0.3 });
    tone({ freq: 784, dur: 0.08, type: 'triangle', gain: 0.3, delay: 0.055 });
  },
  pause: () => {
    tone({ freq: 784, dur: 0.06, type: 'triangle', gain: 0.3 });
    tone({ freq: 523.3, dur: 0.08, type: 'triangle', gain: 0.3, delay: 0.055 });
  },

  // Inspector
  select: () => tone({ freq: 1046.5, dur: 0.035, type: 'sine', gain: 0.3 }),
  field: (osi) => tone({ freq: note(osi) * 2, dur: 0.04, type: 'sine', gain: 0.32 }),
  expand: () => tone({ freq: 440, to: 660, dur: 0.06, type: 'sine', gain: 0.3 }),
  collapse: () => tone({ freq: 660, to: 440, dur: 0.06, type: 'sine', gain: 0.3 }),

  // Navigation and chrome
  open: () => {
    tone({ freq: 523.3, dur: 0.09, gain: 0.25 });
    tone({ freq: 659.3, dur: 0.09, gain: 0.25, delay: 0.04 });
    tone({ freq: 784, dur: 0.12, gain: 0.25, delay: 0.08 });
  },
  home: () => {
    tone({ freq: 784, dur: 0.08, gain: 0.25 });
    tone({ freq: 523.3, dur: 0.11, gain: 0.25, delay: 0.05 });
  },
  theme: () => {
    noise(3000, 900, 0.09, 0.18);
    tone({ freq: 330, dur: 0.07, gain: 0.2 });
  },
  toggle: () => tone({ freq: 880, dur: 0.05, type: 'triangle', gain: 0.3 }),

  // Stage animation
  depart: () => noise(500, 2400, 0.13, 0.22),
  hop: () => tone({ freq: 1568, dur: 0.03, type: 'sine', gain: 0.18 }),
  wrap: (osi) => tone({ freq: note(osi), to: note(osi) * 1.335, dur: 0.06, type: 'triangle', gain: 0.25, lp: 2400 }),
  unwrap: (osi) => tone({ freq: note(osi) * 1.335, to: note(osi), dur: 0.06, type: 'triangle', gain: 0.25, lp: 2400 }),
  arrive: () => {
    tone({ freq: 1046.5, dur: 0.14, gain: 0.22 });
    tone({ freq: 1568, dur: 0.12, gain: 0.12, delay: 0.01 });
  },
  // Low, muffled and falling: clearly "something went wrong", without being harsh.
  error: () => {
    tone({ freq: 233, dur: 0.09, type: 'square', gain: 0.22, lp: 900 });
    tone({ freq: 175, dur: 0.14, type: 'square', gain: 0.22, lp: 900, delay: 0.08 });
  },
};

/** Play a named sound. `osi` (1–7) picks the note for layer-specific sounds. */
export function play(name: SoundName, osi?: number): void {
  if (!ctx || !master || !isEnabled() || ctx.state === 'closed') return;
  // Layer sounds are keyed by layer so that wrapping ETH then IP isn't throttled away.
  if (!throttle.allow(osi === undefined ? name : `${name}:${osi}`, performance.now())) return;
  try {
    SOUNDS[name](osi);
  } catch {
    /* audio is decoration: never let it break the page */
  }
}
