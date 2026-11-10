// Minimal i18n. UI strings live in dictionaries below; lesson text uses the `Text` type
// (a plain string, or an object keyed by locale). Add a locale by adding a dictionary.
import type { Text } from './bytes';

const en = {
  tagline: 'See how the internet works, one packet at a time',
  lessons: 'Lessons',
  prev: 'Previous',
  next: 'Next',
  play: 'Play',
  pause: 'Pause',
  step: 'Step {n} of {total}',
  layers: 'Decoded layers',
  bytes: 'Raw bytes',
  bytesTotal: '{n} bytes',
  selectHint: 'Click a field or a byte to see what it means.',
  offset: 'Bytes {from}–{to}',
  source: 'Source code',
  license: 'Free and open source (MIT)',
  language: 'Language',
  nodeLaptop: 'Laptop',
  nodeRouter: 'Home router',
  nodeInternet: 'Internet',
  nodeDns: 'DNS resolver',
  nodeServer: 'www.example.com',
  keys: 'Tip: use ← and → to step, Space to play',
};

export type Key = keyof typeof en;

export const LOCALES: Record<string, { name: string; dir?: 'rtl'; strings: Partial<Record<Key, string>> }> = {
  en: { name: 'English', strings: en },
};

let current = 'en';

export function setLocale(code: string): void {
  current = LOCALES[code] ? code : 'en';
  document.documentElement.lang = current;
  document.documentElement.dir = LOCALES[current].dir ?? 'ltr';
}

export function getLocale(): string {
  return current;
}

export function t(key: Key, vars: Record<string, string | number> = {}): string {
  const s = LOCALES[current].strings[key] ?? en[key];
  return s.replace(/\{(\w+)\}/g, (_, k: string) => String(vars[k] ?? `{${k}}`));
}

export function tr(text: Text): string {
  return typeof text === 'string' ? text : text[current] ?? text.en ?? Object.values(text)[0] ?? '';
}
