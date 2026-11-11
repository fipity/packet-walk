// The sound module's non-audio logic: the on/off setting and repeat throttling.
// Runs under Node, where there is no AudioContext, so play() must quietly do nothing.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Throttle, isEnabled, play, setEnabled } from '../src/sound';

describe('enabled state', () => {
  let data: Map<string, string>;
  beforeEach(() => {
    data = new Map();
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it('defaults to on', () => {
    expect(isEnabled()).toBe(true);
  });

  it('persists the choice', () => {
    setEnabled(false);
    expect(data.get('sound')).toBe('off');
    expect(isEnabled()).toBe(false);
    setEnabled(true);
    expect(data.get('sound')).toBe('on');
    expect(isEnabled()).toBe(true);
  });

  it('reads a saved choice', () => {
    data.set('sound', 'off');
    expect(isEnabled()).toBe(false);
  });

  it('falls back to on when storage throws', () => {
    vi.stubGlobal('localStorage', {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
    });
    expect(() => setEnabled(false)).not.toThrow();
    expect(isEnabled()).toBe(true);
  });
});

describe('Throttle', () => {
  it('drops repeats inside the gap and allows them after it', () => {
    const t = new Throttle(70);
    expect(t.allow('next', 1000)).toBe(true);
    expect(t.allow('next', 1030)).toBe(false);
    expect(t.allow('next', 1069)).toBe(false);
    expect(t.allow('next', 1070)).toBe(true);
  });

  it('keeps a separate clock per key', () => {
    const t = new Throttle(70);
    expect(t.allow('wrap:2', 0)).toBe(true);
    expect(t.allow('wrap:3', 10)).toBe(true);
    expect(t.allow('wrap:2', 20)).toBe(false);
  });

  it('does not extend the gap when a repeat is dropped', () => {
    const t = new Throttle(70);
    t.allow('field', 0);
    t.allow('field', 60); // dropped
    expect(t.allow('field', 75)).toBe(true);
  });
});

describe('play without Web Audio', () => {
  it('is a silent no-op', () => {
    expect(() => play('next')).not.toThrow();
    expect(() => play('wrap', 3)).not.toThrow();
  });
});
