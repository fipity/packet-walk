import { describe, expect, it } from 'vitest';
import { LESSONS } from '../src/lessons';
import { isFailure } from '../src/failure';

const lesson = (id: string) => LESSONS.find((l) => l.id === id)!;

describe('isFailure', () => {
  it('flags the frame whose FCS no longer matches, but not the good one', () => {
    const [good, damaged] = lesson('physical').steps;
    expect(isFailure(good.packet)).toBe(false);
    expect(isFailure(damaged.packet)).toBe(true);
  });

  it('finds exactly the error packets across all lessons', () => {
    const failing = LESSONS.flatMap((l) => l.steps.map((s, i) => [l.id, i, s] as const))
      .filter(([, , s]) => isFailure(s.packet))
      .map(([id, i]) => `${id} #${i + 1}`);
    expect(failing).toContain('physical #2');
    expect(failing.map((f) => f.split(' ')[0]).sort()).toEqual(['modbus', 'physical', 'radius']);
  });
});
