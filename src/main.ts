import './style.css';
import { Diagram } from './diagram';
import { LESSONS } from './lessons';
import { LOCALES, getLocale, setLocale, t, tr } from './i18n';
import { hex8, type LayerKind, type Packet } from './bytes';

const REPO = 'https://github.com/fipity/packet-walk';

const state = { lesson: 0, step: 0, field: -1, playing: false };
let playTimer = 0;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;
const h = (tag: string, cls?: string, text?: string) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

function kindColor(kind: LayerKind): string {
  return `var(--k-${kind})`;
}

// ---------------------------------------------------------------- shell

const app = $('#app');
app.innerHTML = `
  <header class="top">
    <a class="brand" href="#/">
      <svg viewBox="0 0 32 32" aria-hidden="true"><rect x="3" y="9" width="26" height="16" rx="4"/><path d="M3 12 l13 8 l13 -8"/></svg>
      <span>packet-walk</span>
    </a>
    <span class="tagline"></span>
    <span class="spacer"></span>
    <label class="lang"><span class="sr"></span><select></select></label>
    <a class="gh" href="${REPO}" target="_blank" rel="noopener"></a>
  </header>
  <div class="layout">
    <nav class="sidebar"><h2></h2><ol class="lesson-list"></ol></nav>
    <main>
      <section class="lesson-head"><h1></h1><p class="intro"></p></section>
      <div class="stage"></div>
      <div class="controls">
        <button class="btn prev" type="button"></button>
        <button class="btn play primary" type="button"></button>
        <button class="btn next" type="button"></button>
        <span class="counter"></span>
        <ol class="dots"></ol>
      </div>
      <article class="step"><h2></h2><p></p></article>
      <section class="inspector">
        <div class="capture"></div>
        <div class="cols">
          <div class="pane"><h3 class="layers-title"></h3><div class="tree"></div></div>
          <div class="pane"><h3 class="bytes-title"></h3><div class="hex" role="grid"></div></div>
        </div>
        <div class="detail" aria-live="polite"></div>
      </section>
    </main>
  </div>
  <footer><span class="lic"></span> · <a href="${REPO}" target="_blank" rel="noopener" class="src"></a> · <span class="keys"></span></footer>
`;

const diagram = new Diagram();
$('.stage').append(diagram.el);

const langSel = $<HTMLSelectElement>('.lang select');
for (const [code, l] of Object.entries(LOCALES)) langSel.append(new Option(l.name, code));
$('.lang').hidden = Object.keys(LOCALES).length < 2;
langSel.addEventListener('change', () => {
  setLocale(langSel.value);
  try {
    localStorage.setItem('locale', langSel.value);
  } catch {
    /* storage unavailable */
  }
  renderChrome();
  render(false);
});

function renderChrome(): void {
  $('.tagline').textContent = t('tagline');
  $('.lang .sr').textContent = t('language');
  $('.gh').textContent = t('source');
  $('.sidebar h2').textContent = t('lessons');
  $('.prev').textContent = `← ${t('prev')}`;
  $('.next').textContent = `${t('next')} →`;
  $('.layers-title').textContent = t('layers');
  $('.bytes-title').textContent = t('bytes');
  $('.lic').textContent = t('license');
  $('.src').textContent = t('source');
  $('.keys').textContent = t('keys');
  diagram.relabel();

  const list = $('.lesson-list');
  list.replaceChildren(
    ...LESSONS.map((l, i) => {
      const li = h('li');
      const a = h('a', 'lesson-link') as HTMLAnchorElement;
      a.href = `#/${l.id}`;
      a.append(h('span', 'num', String(i + 1)), h('span', 'name', tr(l.title)));
      const chips = h('span', 'chips');
      for (const p of l.protocols) chips.append(h('span', 'chip', p));
      a.append(chips);
      li.append(a);
      return li;
    }),
  );
}

// ---------------------------------------------------------------- packet inspector

function innermostLayer(p: Packet, offset: number): number {
  let best = 0;
  p.layers.forEach((l, i) => {
    if (offset >= l.offset && offset < l.offset + l.length && l.depth >= p.layers[best].depth) best = i;
  });
  return best;
}

function renderPacket(p: Packet): void {
  const byteField = new Int32Array(p.bytes.length).fill(-1);
  p.fields.forEach((f, i) => {
    for (let j = f.offset; j < f.offset + f.length; j++) byteField[j] = i;
  });

  $('.capture').textContent = `${tr(currentStep().capture)} · ${t('bytesTotal', { n: p.bytes.length })} · ${p.layers
    .filter((l, i, arr) => arr.findIndex((x) => x.name === l.name) === i)
    .map((l) => l.name)
    .join(' › ')}`;

  // Layer tree
  const tree = $('.tree');
  tree.replaceChildren(
    ...p.layers.map((l, li) => {
      const d = h('details', 'layer') as HTMLDetailsElement;
      d.open = true;
      d.style.setProperty('--depth', String(l.depth));
      d.style.setProperty('--c', kindColor(l.kind));
      const s = h('summary');
      s.append(h('span', 'swatch'), h('span', 'lname', l.name), h('span', 'lsize', t('bytesTotal', { n: l.length })));
      d.append(s);
      p.fields.forEach((f, fi) => {
        if (f.layer !== li) return;
        const b = h('button', 'field') as HTMLButtonElement;
        b.type = 'button';
        b.dataset.f = String(fi);
        b.append(h('span', 'fname', f.name), h('span', 'fval', f.value));
        d.append(b);
      });
      return d;
    }),
  );

  // Hex dump
  const hex = $('.hex');
  const rows: HTMLElement[] = [];
  for (let r = 0; r < p.bytes.length; r += 16) {
    const row = h('div', 'row');
    row.append(h('span', 'off', r.toString(16).padStart(4, '0')));
    const hx = h('span', 'hx');
    const asc = h('span', 'asc');
    for (let i = r; i < Math.min(r + 16, p.bytes.length); i++) {
      const kind = p.layers[innermostLayer(p, i)].kind;
      const b = h('span', `b k-${kind}`, hex8(p.bytes[i]));
      b.dataset.f = String(byteField[i]);
      b.dataset.i = String(i);
      hx.append(b);
      const c = p.bytes[i];
      const a = h('span', `b k-${kind}`, c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '·');
      a.dataset.f = String(byteField[i]);
      asc.append(a);
    }
    row.append(hx, asc);
    rows.push(row);
  }
  hex.replaceChildren(...rows);
  selectField(state.field, p, false);
}

function selectField(fi: number, p: Packet, scroll: boolean): void {
  state.field = fi;
  document.querySelectorAll('.sel').forEach((e) => e.classList.remove('sel'));
  const detail = $('.detail');
  if (fi < 0 || !p.fields[fi]) {
    detail.replaceChildren(h('p', 'hint', t('selectHint')));
    return;
  }
  document.querySelectorAll(`[data-f="${fi}"]`).forEach((e) => e.classList.add('sel'));
  const f = p.fields[fi];
  const layerInfo = p.layers[f.layer];
  const bytes = Array.from(p.bytes.subarray(f.offset, f.offset + Math.min(f.length, 24)), hex8).join(' ') + (f.length > 24 ? ' …' : '');
  const head = h('div', 'dhead');
  head.style.setProperty('--c', kindColor(layerInfo.kind));
  head.append(h('span', 'swatch'), h('strong', '', f.name), h('span', 'dlayer', layerInfo.name));
  detail.replaceChildren(
    head,
    h('p', 'dval', f.value),
    ...(f.info ? [h('p', 'dinfo', f.info)] : []),
    h('p', 'draw', `${t('offset', { from: f.offset, to: f.offset + f.length - 1 })}: ${bytes}`),
  );
  if (scroll) {
    document.querySelector(`.hex [data-f="${fi}"]`)?.scrollIntoView({ block: 'nearest' });
    document.querySelector(`.tree [data-f="${fi}"]`)?.scrollIntoView({ block: 'nearest' });
  }
}

const inspector = $('.inspector');
inspector.addEventListener('click', (e) => {
  const el = (e.target as HTMLElement).closest<HTMLElement>('[data-f]');
  if (el) selectField(Number(el.dataset.f), currentStep().packet, true);
});
inspector.addEventListener('mouseover', (e) => {
  const el = (e.target as HTMLElement).closest<HTMLElement>('[data-f]');
  document.querySelectorAll('.hover').forEach((x) => x.classList.remove('hover'));
  if (el) document.querySelectorAll(`[data-f="${el.dataset.f}"]`).forEach((x) => x.classList.add('hover'));
});
inspector.addEventListener('mouseleave', () => document.querySelectorAll('.hover').forEach((x) => x.classList.remove('hover')));

// ---------------------------------------------------------------- lesson / step

const currentLesson = () => LESSONS[state.lesson];
const currentStep = () => currentLesson().steps[state.step];

function render(animate: boolean): void {
  const lesson = currentLesson();
  const step = currentStep();
  document.title = `${tr(lesson.title)} · packet-walk`;

  document.querySelectorAll('.lesson-link').forEach((a, i) => a.classList.toggle('current', i === state.lesson));
  diagram.relabel(lesson.labels);
  $('.lesson-head h1').textContent = tr(lesson.title);
  $('.intro').textContent = tr(lesson.intro);
  $('.step h2').textContent = tr(step.title);
  $('.step p').textContent = tr(step.text);
  $('.counter').textContent = t('step', { n: state.step + 1, total: lesson.steps.length });
  $<HTMLButtonElement>('.prev').disabled = state.step === 0;
  $<HTMLButtonElement>('.next').disabled = state.step === lesson.steps.length - 1 && state.lesson === LESSONS.length - 1;
  $('.play').textContent = state.playing ? `❚❚ ${t('pause')}` : `▶ ${t('play')}`;

  const dots = $('.dots');
  dots.replaceChildren(
    ...lesson.steps.map((s, i) => {
      const li = h('li');
      const a = h('a', i === state.step ? 'dot current' : 'dot') as HTMLAnchorElement;
      a.href = `#/${lesson.id}/${i + 1}`;
      a.title = tr(s.title);
      a.setAttribute('aria-label', tr(s.title));
      li.append(a);
      return li;
    }),
  );

  const p = step.packet;
  const outer = p.layers.reduce((a, l) => (l.depth > a.depth ? l : a), p.layers[0]);
  diagram.show(step.from, step.to, kindColor(outer.kind), animate && !reducedMotion.matches, () => {
    if (state.playing) schedulePlay();
  });
  renderPacket(p);
}

function go(lesson: number, step: number, animate = true): void {
  const changed = lesson !== state.lesson || step !== state.step;
  state.lesson = lesson;
  state.step = step;
  if (changed) state.field = -1;
  const target = `#/${LESSONS[lesson].id}/${step + 1}`;
  if (location.hash !== target) history.replaceState(null, '', target);
  render(animate);
}

function next(): boolean {
  const l = currentLesson();
  if (state.step < l.steps.length - 1) go(state.lesson, state.step + 1);
  else if (state.lesson < LESSONS.length - 1) go(state.lesson + 1, 0);
  else return false;
  return true;
}

function prev(): void {
  if (state.step > 0) go(state.lesson, state.step - 1);
}

function schedulePlay(): void {
  clearTimeout(playTimer);
  playTimer = window.setTimeout(() => {
    if (!state.playing) return;
    const l = currentLesson();
    if (state.step < l.steps.length - 1) go(state.lesson, state.step + 1);
    else setPlaying(false);
  }, 3500);
}

function setPlaying(on: boolean): void {
  state.playing = on;
  clearTimeout(playTimer);
  if (on) {
    if (state.step === currentLesson().steps.length - 1) go(state.lesson, 0);
    else go(state.lesson, state.step + 1);
  } else {
    render(false);
  }
}

$('.prev').addEventListener('click', () => {
  setPlayingQuiet(false);
  prev();
});
$('.next').addEventListener('click', () => {
  setPlayingQuiet(false);
  next();
});
$('.play').addEventListener('click', () => setPlaying(!state.playing));

function setPlayingQuiet(on: boolean): void {
  state.playing = on;
  clearTimeout(playTimer);
}

document.addEventListener('keydown', (e) => {
  if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === 'ArrowRight') {
    setPlayingQuiet(false);
    next();
  } else if (e.key === 'ArrowLeft') {
    setPlayingQuiet(false);
    prev();
  } else if (e.key === ' ' && !(e.target instanceof HTMLButtonElement)) {
    e.preventDefault();
    setPlaying(!state.playing);
  }
});

function fromHash(): void {
  const [, id, n] = location.hash.split('/');
  const li = Math.max(0, LESSONS.findIndex((l) => l.id === id));
  const si = Math.min(Math.max(0, (Number(n) || 1) - 1), LESSONS[li].steps.length - 1);
  setPlayingQuiet(false);
  go(li, si);
}

window.addEventListener('hashchange', fromHash);

// ---------------------------------------------------------------- boot

let saved: string | null = null;
try {
  saved = localStorage.getItem('locale');
} catch {
  /* storage unavailable */
}
const browser = navigator.language.split('-')[0];
setLocale(saved ?? (LOCALES[browser] ? browser : 'en'));
langSel.value = getLocale();
renderChrome();
fromHash();
