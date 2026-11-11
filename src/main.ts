import './style.css';
import { Diagram, chain } from './diagram';
import { LESSONS } from './lessons';
import { GROUPS } from './groups';
import { LOCALES, getLocale, setLocale, t, tr } from './i18n';
import { hex8, type LayerKind, type Packet } from './bytes';
import type { Lesson } from './lessons/network';
import { osiOf, renderModels } from './models';
import { store } from './store';

const REPO = 'https://github.com/fipity/packet-walk';

type View = 'home' | 'lesson' | 'models';
const state = { view: 'home' as View, lesson: 0, step: 0, field: -1, playing: false };
let playTimer = 0;
let heroTimer = 0;
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;
const h = (tag: string, cls?: string, text?: string) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const kindColor = (kind: LayerKind) => `var(--k-${kind})`;
const lessonIndex = (id: string) => LESSONS.findIndex((l) => l.id === id);
const groupOf = (id: string) => GROUPS.find((g) => g.ids.includes(id));

/** The kind of the deepest layer in a lesson's first packet, used to colour its card. */
function lessonKind(l: Lesson): LayerKind {
  const p = l.steps[0].packet;
  return p.layers.reduce((a, b) => (b.depth > a.depth ? b : a), p.layers[0]).kind;
}

// ---------------------------------------------------------------- shell

const app = $('#app');
app.innerHTML = `
  <header class="top">
    <a class="brand" href="#/">
      <svg viewBox="0 0 32 32" aria-hidden="true"><rect x="3" y="9" width="26" height="16" rx="4"/><path d="M3 12 l13 8 l13 -8"/></svg>
      <span>packet<b>-walk</b></span>
    </a>
    <a class="toplink all" href="#/"></a>
    <a class="toplink models-link" href="#/models"></a>
    <span class="spacer"></span>
    <label class="lang"><span class="sr"></span><select></select></label>
    <button class="icon-btn theme" type="button"></button>
    <a class="gh" href="${REPO}" target="_blank" rel="noopener"></a>
  </header>

  <section class="home" hidden>
    <div class="hero">
      <div class="hero-text">
        <p class="eyebrow"></p>
        <h1><span class="t1"></span><br><span class="grad t2"></span></h1>
        <p class="lede"></p>
        <div class="cta"><a class="btn primary go-start"></a><a class="btn go-load" href="#/page-load"></a><a class="btn go-models" href="#/models"></a></div>
        <ul class="stats"></ul>
      </div>
      <div class="hero-stage stage"></div>
    </div>
    <div class="groups"></div>
  </section>

  <div class="lesson-view layout" hidden>
    <nav class="sidebar"></nav>
    <main>
      <section class="lesson-head"><p class="crumb"></p><h1></h1><p class="intro"></p></section>
      <div class="stage lesson-stage"></div>
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
        <div class="plist" role="region"><table><thead><tr><th class="c-no"></th><th class="c-src"></th><th class="c-dst"></th><th class="c-proto"></th><th class="c-len"></th><th class="c-info"></th></tr></thead><tbody></tbody></table></div>
        <div class="cols">
          <div class="pane"><h3 class="layers-title"></h3><div class="tree"></div></div>
          <div class="pane"><h3 class="bytes-title"></h3><div class="hex"></div></div>
        </div>
        <div class="detail" aria-live="polite"></div>
      </section>
      <nav class="pager"></nav>
    </main>
  </div>

  <section class="models" hidden></section>

  <footer><span class="lic"></span> · <a href="${REPO}" target="_blank" rel="noopener" class="src"></a> · <span class="keys"></span></footer>
`;

const diagram = new Diagram('diagram');
$('.lesson-stage').append(diagram.el, diagram.caption);
const hero = new Diagram('diagram hero-diagram');
$('.hero-stage').append(hero.el, hero.caption);

// ---------------------------------------------------------------- theme & language

function applyTheme(theme: string): void {
  document.documentElement.dataset.theme = theme;
  const btn = $('.theme');
  btn.textContent = theme === 'dark' ? '☀' : '☾';
  btn.title = btn.ariaLabel = theme === 'dark' ? t('themeLight') : t('themeDark');
}
$('.theme').addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  store.set('theme', next);
  applyTheme(next);
});

const langSel = $<HTMLSelectElement>('.lang select');
for (const [code, l] of Object.entries(LOCALES)) langSel.append(new Option(l.name, code));
$('.lang').hidden = Object.keys(LOCALES).length < 2;
langSel.addEventListener('change', () => {
  setLocale(langSel.value);
  store.set('locale', langSel.value);
  renderChrome();
  route();
});

// ---------------------------------------------------------------- static chrome

function lessonLink(l: Lesson, cls: string): HTMLAnchorElement {
  const a = h('a', cls) as HTMLAnchorElement;
  a.href = `#/${l.id}`;
  a.style.setProperty('--c', kindColor(lessonKind(l)));
  return a;
}

function renderChrome(): void {
  $('.all').textContent = t('allLessons');
  $('.models-link').textContent = t('models');
  $('.go-models').textContent = t('ctaModels');
  $('.lang .sr').textContent = t('language');
  $('.gh').textContent = t('source');
  $('.prev').textContent = `← ${t('prev')}`;
  $('.next').textContent = `${t('next')} →`;
  $('.layers-title').textContent = t('layers');
  $('.bytes-title').textContent = t('bytes');
  $('.lic').textContent = t('license');
  $('.src').textContent = t('source');
  $('.keys').textContent = t('keys');
  $('.plist').ariaLabel = t('packetList');
  for (const [cls, key] of [['c-no', 'colNo'], ['c-src', 'colSrc'], ['c-dst', 'colDst'], ['c-proto', 'colProto'], ['c-len', 'colLen'], ['c-info', 'colInfo']] as const) {
    $(`.${cls}`).textContent = t(key);
  }
  applyTheme(document.documentElement.dataset.theme ?? 'dark');

  // Home
  $('.eyebrow').textContent = t('heroEyebrow');
  $('.hero .t1').textContent = t('heroTitle1');
  $('.hero .t2').textContent = t('heroTitle2');
  $('.lede').textContent = t('heroLede');
  const start = $<HTMLAnchorElement>('.go-start');
  start.textContent = `${t('ctaStart')} →`;
  start.href = `#/${LESSONS[0].id}`;
  $('.go-load').textContent = t('ctaPageLoad');
  const packets = LESSONS.reduce((n, l) => n + l.steps.length, 0);
  const bytes = LESSONS.reduce((n, l) => n + l.steps.reduce((m, s) => m + s.packet.bytes.length, 0), 0);
  $('.stats').replaceChildren(
    ...[[LESSONS.length, t('statLessons')], [packets, t('statPackets')], [bytes.toLocaleString('en-US'), t('statBytes')]].map(([n, label]) => {
      const li = h('li');
      li.append(h('b', '', String(n)), h('span', '', String(label)));
      return li;
    }),
  );
  $('.groups').replaceChildren(
    ...GROUPS.map((g) => {
      const sec = h('section', 'group');
      const head = h('div', 'group-head');
      head.append(h('span', 'group-num', g.osi), h('h2', '', g.name), h('p', '', g.blurb));
      const grid = h('div', 'cards');
      for (const id of g.ids) {
        const i = lessonIndex(id);
        const l = LESSONS[i];
        const card = lessonLink(l, 'card');
        const top = h('div', 'card-top');
        top.append(h('span', 'card-num', String(i + 1).padStart(2, '0')), h('span', 'card-steps', t('steps', { n: l.steps.length })));
        const chips = h('div', 'chips');
        for (const p of l.protocols) chips.append(h('span', 'chip', p));
        card.append(top, h('h3', '', tr(l.title)), h('p', '', tr(l.intro)), chips);
        grid.append(card);
      }
      sec.append(head, grid);
      return sec;
    }),
  );

  // Sidebar
  $('.sidebar').replaceChildren(
    ...GROUPS.map((g) => {
      const sec = h('div', 'side-group');
      sec.append(h('h2', '', `${g.osi} · ${g.name}`));
      const ol = h('ol', 'lesson-list');
      for (const id of g.ids) {
        const i = lessonIndex(id);
        const a = lessonLink(LESSONS[i], 'lesson-link');
        a.dataset.i = String(i);
        a.append(h('span', 'num', String(i + 1).padStart(2, '0')), h('span', 'name', tr(LESSONS[i].title)));
        const li = h('li');
        li.append(a);
        ol.append(li);
      }
      sec.append(ol);
      return sec;
    }),
  );
}

// ---------------------------------------------------------------- packet list (Wireshark-style)

function protoLabel(p: Packet): { label: string; kind: LayerKind } {
  const deepest = p.layers.reduce((a, b) => (b.depth > a.depth ? b : a), p.layers[0]);
  const c = chain(p);
  const last = c[c.length - 1];
  const label = deepest.kind === 'tls' ? 'TLSv1.3' : last.label.replace(/ ×\d+$/, '');
  return { label, kind: deepest.kind };
}

function endpoints(p: Packet): [string, string] {
  const ipL = p.layers.findIndex((l) => l.kind === 'ip' && !l.name.startsWith('Quoted'));
  if (ipL >= 0) {
    const f = p.fields.filter((x) => x.layer === ipL);
    return [f.find((x) => x.name === 'Source address')?.value ?? '?', f.find((x) => x.name === 'Destination address')?.value ?? '?'];
  }
  const linkL = Math.max(0, p.layers.findIndex((l) => l.kind === 'eth' || l.kind === 'wifi'));
  const macs = p.fields.filter((x) => x.layer === linkL && x.length === 6).map((x) => x.value.replace(' (broadcast)', ''));
  const bcast = (m: string) => (m === 'ff:ff:ff:ff:ff:ff' ? 'Broadcast' : m);
  return [bcast(macs[1] ?? '?'), bcast(macs[0] ?? '?')];
}

function renderPacketList(lesson: Lesson): void {
  const body = $('.plist tbody');
  body.replaceChildren(
    ...lesson.steps.map((s, i) => {
      const tr_ = h('tr');
      tr_.dataset.i = String(i);
      const { label, kind } = protoLabel(s.packet);
      tr_.style.setProperty('--c', kindColor(kind));
      const [src, dst] = endpoints(s.packet);
      for (const [cls, text] of [['c-no', String(i + 1)], ['c-src', src], ['c-dst', dst], ['c-proto', label], ['c-len', String(s.packet.bytes.length)], ['c-info', tr(s.title)]]) {
        tr_.append(h('td', cls, text));
      }
      tr_.tabIndex = 0;
      return tr_;
    }),
  );
}

$('.plist').addEventListener('click', (e) => {
  const row = (e.target as HTMLElement).closest<HTMLElement>('tr[data-i]');
  if (row) {
    setPlayingQuiet(false);
    go(state.lesson, Number(row.dataset.i));
  }
});
$('.plist').addEventListener('keydown', (e) => {
  const row = (e.target as HTMLElement).closest<HTMLElement>('tr[data-i]');
  if (row && (e.key === 'Enter' || e.key === ' ')) {
    e.preventDefault();
    setPlayingQuiet(false);
    go(state.lesson, Number(row.dataset.i));
  }
});

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

  $('.capture').textContent = `${tr(currentStep().capture)} · ${t('bytesTotal', { n: p.bytes.length })} · ${chain(p).map((c) => c.label).join(' › ')}`;

  $('.tree').replaceChildren(
    ...p.layers.map((l, li) => {
      const d = h('details', 'layer') as HTMLDetailsElement;
      d.open = true;
      d.style.setProperty('--depth', String(l.depth));
      d.style.setProperty('--c', kindColor(l.kind));
      const s = h('summary');
      const osi = h('span', 'osi', `L${osiOf(l)}`);
      osi.title = `OSI layer ${osiOf(l)}`;
      s.append(h('span', 'swatch'), osi, h('span', 'lname', l.name), h('span', 'lsize', t('bytesTotal', { n: l.length })));
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
      hx.append(b);
      const c = p.bytes[i];
      const a = h('span', `b k-${kind}`, c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '·');
      a.dataset.f = String(byteField[i]);
      asc.append(a);
    }
    row.append(hx, asc);
    rows.push(row);
  }
  $('.hex').replaceChildren(...rows);
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
  document.querySelectorAll(`.inspector [data-f="${fi}"]`).forEach((e) => e.classList.add('sel'));
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
    for (const sel of ['.hex', '.tree']) {
      const box = $(sel);
      const el = box.querySelector<HTMLElement>(`[data-f="${fi}"]`);
      if (el && (el.offsetTop < box.scrollTop || el.offsetTop > box.scrollTop + box.clientHeight - 30)) {
        box.scrollTop = el.offsetTop - box.clientHeight / 3;
      }
    }
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
  if (el) document.querySelectorAll(`.inspector [data-f="${el.dataset.f}"]`).forEach((x) => x.classList.add('hover'));
});
inspector.addEventListener('mouseleave', () => document.querySelectorAll('.hover').forEach((x) => x.classList.remove('hover')));

// ---------------------------------------------------------------- lesson view

const currentLesson = () => LESSONS[state.lesson];
const currentStep = () => currentLesson().steps[state.step];
let renderedLesson = -1;

function renderLesson(animate: boolean): void {
  const lesson = currentLesson();
  const step = currentStep();
  document.title = `${tr(lesson.title)} · packet-walk`;

  if (renderedLesson !== state.lesson) {
    renderedLesson = state.lesson;
    document.querySelectorAll<HTMLElement>('.lesson-link').forEach((a) => a.classList.toggle('current', Number(a.dataset.i) === state.lesson));
    diagram.relabel(lesson.labels, lesson.links);
    $('.crumb').textContent = `${groupOf(lesson.id)?.name ?? ''} · ${t('lessonOf', { n: state.lesson + 1, total: LESSONS.length })}`;
    $('.lesson-head h1').textContent = tr(lesson.title);
    $('.intro').textContent = tr(lesson.intro);
    renderPacketList(lesson);
    const pager = $('.pager');
    pager.replaceChildren();
    const prevL = LESSONS[state.lesson - 1];
    const nextL = LESSONS[state.lesson + 1];
    for (const [l, label, cls] of [[prevL, t('prevLesson'), 'pg-prev'], [nextL, t('nextLesson'), 'pg-next']] as const) {
      if (!l) {
        pager.append(h('span'));
        continue;
      }
      const a = lessonLink(l, `pg ${cls}`);
      a.append(h('small', '', label), h('strong', '', tr(l.title)));
      pager.append(a);
    }
    const dots = $('.dots');
    dots.replaceChildren(
      ...lesson.steps.map((s, i) => {
        const li = h('li');
        const a = h('a', 'dot') as HTMLAnchorElement;
        a.href = `#/${lesson.id}/${i + 1}`;
        a.title = tr(s.title);
        a.setAttribute('aria-label', tr(s.title));
        li.append(a);
        return li;
      }),
    );
  }

  $('.step h2').textContent = tr(step.title);
  $('.step p').textContent = tr(step.text);
  $('.counter').textContent = t('step', { n: state.step + 1, total: lesson.steps.length });
  $<HTMLButtonElement>('.prev').disabled = state.step === 0;
  $<HTMLButtonElement>('.next').disabled = state.step === lesson.steps.length - 1 && state.lesson === LESSONS.length - 1;
  $('.play').textContent = state.playing ? `❚❚ ${t('pause')}` : `▶ ${t('play')}`;
  document.querySelectorAll('.dots .dot').forEach((d, i) => d.classList.toggle('current', i === state.step));
  document.querySelectorAll('.plist tr[data-i]').forEach((r, i) => r.classList.toggle('current', i === state.step));
  const box = $('.plist');
  const row = box.querySelector<HTMLElement>(`tr[data-i="${state.step}"]`);
  if (row && (row.offsetTop < box.scrollTop + 28 || row.offsetTop > box.scrollTop + box.clientHeight - row.offsetHeight)) {
    box.scrollTop = row.offsetTop - 60;
  }

  diagram.show(step.from, step.to, step.packet, animate && !reducedMotion.matches, () => {
    if (state.playing) schedulePlay();
  });
  renderPacket(step.packet);
}

function go(lesson: number, step: number, animate = true): void {
  const changed = lesson !== state.lesson || step !== state.step;
  state.lesson = lesson;
  state.step = step;
  if (changed) state.field = -1;
  const target = `#/${LESSONS[lesson].id}/${step + 1}`;
  if (location.hash !== target) history.replaceState(null, '', target);
  showView('lesson');
  renderLesson(animate);
}

function next(): void {
  const l = currentLesson();
  if (state.step < l.steps.length - 1) go(state.lesson, state.step + 1);
  else if (state.lesson < LESSONS.length - 1) {
    go(state.lesson + 1, 0);
    window.scrollTo({ top: 0 });
  }
}

function prev(): void {
  if (state.step > 0) go(state.lesson, state.step - 1);
}

function schedulePlay(): void {
  clearTimeout(playTimer);
  playTimer = window.setTimeout(() => {
    if (!state.playing) return;
    if (state.step < currentLesson().steps.length - 1) go(state.lesson, state.step + 1);
    else setPlaying(false);
  }, 2600);
}

function setPlaying(on: boolean): void {
  state.playing = on;
  clearTimeout(playTimer);
  if (on) go(state.lesson, state.step === currentLesson().steps.length - 1 ? 0 : state.step + 1);
  else renderLesson(false);
}

function setPlayingQuiet(on: boolean): void {
  state.playing = on;
  clearTimeout(playTimer);
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

document.addEventListener('keydown', (e) => {
  if (state.view !== 'lesson') return;
  if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement || e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === 'ArrowRight') {
    setPlayingQuiet(false);
    next();
  } else if (e.key === 'ArrowLeft') {
    setPlayingQuiet(false);
    prev();
  } else if (e.key === ' ' && !(e.target instanceof HTMLButtonElement) && !(e.target instanceof HTMLTableRowElement)) {
    e.preventDefault();
    setPlaying(!state.playing);
  }
});

// ---------------------------------------------------------------- home view & routing

const demo = LESSONS[lessonIndex('page-load')] ?? LESSONS[LESSONS.length - 1];
let heroStep = 0;

function heroLoop(): void {
  clearTimeout(heroTimer);
  if (state.view !== 'home') return;
  const s = demo.steps[heroStep % demo.steps.length];
  heroStep++;
  const animate = !reducedMotion.matches;
  hero.show(s.from, s.to, s.packet, animate, () => {
    heroTimer = window.setTimeout(heroLoop, animate ? 700 : 2500);
  });
}

const VIEW_SEL: Record<View, string> = { home: '.home', lesson: '.lesson-view', models: '.models' };

function showView(view: View): void {
  if (state.view === view && !$(VIEW_SEL[view]).hidden) return;
  state.view = view;
  $('.home').hidden = view !== 'home';
  $('.lesson-view').hidden = view !== 'lesson';
  $('.models').hidden = view !== 'models';
  $('.all').hidden = view === 'home';
  $('.models-link').classList.toggle('current', view === 'models');
  document.body.dataset.view = view;
  if (view === 'home') {
    setPlayingQuiet(false);
    diagram.stop();
    document.title = 'packet-walk · see how the internet works';
    hero.relabel(demo.labels, demo.links);
    heroLoop();
  } else {
    clearTimeout(heroTimer);
    hero.stop();
  }
}

function route(): void {
  const [, id, n] = location.hash.split('/');
  if (id === 'models') {
    renderedLesson = -1;
    showView('models');
    renderModels($('.models'), Math.min(7, Math.max(1, Number(n) || 7)));
    document.title = 'OSI & TCP/IP models · packet-walk';
    window.scrollTo({ top: 0 });
    return;
  }
  const li = id ? lessonIndex(id) : -1;
  if (li < 0) {
    renderedLesson = -1;
    showView('home');
    return;
  }
  const si = Math.min(Math.max(0, (Number(n) || 1) - 1), LESSONS[li].steps.length - 1);
  setPlayingQuiet(false);
  const switching = li !== state.lesson || state.view !== 'lesson';
  if (li !== state.lesson) renderedLesson = -1;
  go(li, si);
  if (switching) window.scrollTo({ top: 0 });
}

window.addEventListener('hashchange', route);

// ---------------------------------------------------------------- boot

const browser = navigator.language.split('-')[0];
setLocale(store.get('locale') ?? (LOCALES[browser] ? browser : 'en'));
langSel.value = getLocale();
applyTheme(store.get('theme') ?? document.documentElement.dataset.theme ?? 'dark');
renderChrome();
state.view = 'lesson'; // force the first showView() to apply
route();
