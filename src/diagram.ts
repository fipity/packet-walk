// The network diagram: five nodes, the links between them, and an animated packet.
import type { NodeId } from './lessons/network';
import { NET } from './lessons/network';
import { t, tr, type Key } from './i18n';
import type { Lesson } from './lessons/network';

const SVG = 'http://www.w3.org/2000/svg';

const POS: Record<NodeId, [number, number]> = {
  laptop: [70, 130],
  router: [250, 130],
  internet: [440, 130],
  dns: [610, 55],
  server: [610, 205],
};

const LINKS: [NodeId, NodeId][] = [
  ['laptop', 'router'],
  ['router', 'internet'],
  ['internet', 'dns'],
  ['internet', 'server'],
];

const LABEL: Record<NodeId, Key> = {
  laptop: 'nodeLaptop',
  router: 'nodeRouter',
  internet: 'nodeInternet',
  dns: 'nodeDns',
  server: 'nodeServer',
};

const ADDR: Record<NodeId, string> = {
  laptop: NET.laptop.ip,
  router: `${NET.router.ip} · ${NET.router.wan}`,
  internet: '',
  dns: NET.dns.ip,
  server: NET.server.ip,
};

const ICON: Record<NodeId, string> = {
  laptop:
    '<rect x="-22" y="-18" width="44" height="28" rx="3" class="ico"/><rect x="-17" y="-13" width="34" height="18" rx="1" class="ico-fill"/><path d="M-28 12 h56 l-4 6 h-48 z" class="ico"/>',
  router:
    '<rect x="-26" y="-6" width="52" height="20" rx="4" class="ico"/><circle cx="-14" cy="4" r="2.5" class="led"/><circle cx="-5" cy="4" r="2.5" class="led"/><path d="M-16 -6 l-6 -16 M16 -6 l6 -16" class="ico-line"/>',
  internet:
    '<path d="M-30 12 a14 14 0 0 1 2 -27 a18 18 0 0 1 32 -6 a14 14 0 0 1 24 10 a12 12 0 0 1 2 23 z" class="ico"/>',
  dns:
    '<rect x="-20" y="-20" width="40" height="40" rx="4" class="ico"/><text x="0" y="5" text-anchor="middle" class="ico-text">DNS</text>',
  server:
    '<rect x="-20" y="-22" width="40" height="13" rx="2" class="ico"/><rect x="-20" y="-6" width="40" height="13" rx="2" class="ico"/><rect x="-20" y="10" width="40" height="13" rx="2" class="ico"/><circle cx="12" cy="-15.5" r="2" class="led"/><circle cx="12" cy="0.5" r="2" class="led"/><circle cx="12" cy="16.5" r="2" class="led"/>',
};

function route(from: NodeId, to: NodeId): NodeId[] {
  const prev = new Map<NodeId, NodeId | null>([[from, null]]);
  const queue: NodeId[] = [from];
  while (queue.length) {
    const n = queue.shift()!;
    if (n === to) break;
    for (const [a, b] of LINKS) {
      const m = a === n ? b : b === n ? a : null;
      if (m && !prev.has(m)) {
        prev.set(m, n);
        queue.push(m);
      }
    }
  }
  const path: NodeId[] = [];
  for (let n: NodeId | null | undefined = to; n; n = prev.get(n)) path.unshift(n);
  return path;
}

export class Diagram {
  readonly el: SVGSVGElement;
  private dot: SVGGElement;
  private nodes = new Map<NodeId, SVGGElement>();
  private links = new Map<string, SVGLineElement>();
  private anim = 0;

  constructor() {
    this.el = document.createElementNS(SVG, 'svg');
    this.el.setAttribute('viewBox', '0 0 720 260');
    this.el.setAttribute('class', 'diagram');
    this.el.setAttribute('role', 'img');

    for (const [a, b] of LINKS) {
      const l = document.createElementNS(SVG, 'line');
      const [x1, y1] = POS[a];
      const [x2, y2] = POS[b];
      l.setAttribute('x1', String(x1));
      l.setAttribute('y1', String(y1));
      l.setAttribute('x2', String(x2));
      l.setAttribute('y2', String(y2));
      l.setAttribute('class', 'link');
      this.el.append(l);
      this.links.set(`${a}-${b}`, l);
    }
    for (const id of Object.keys(POS) as NodeId[]) {
      const g = document.createElementNS(SVG, 'g');
      const [x, y] = POS[id];
      g.setAttribute('transform', `translate(${x} ${y})`);
      g.setAttribute('class', 'node');
      g.innerHTML = `${ICON[id]}<text y="40" text-anchor="middle" class="label"></text><text y="55" text-anchor="middle" class="addr"></text>`;
      this.el.append(g);
      this.nodes.set(id, g);
    }
    this.dot = document.createElementNS(SVG, 'g');
    this.dot.setAttribute('class', 'packet');
    this.dot.innerHTML = '<rect x="-13" y="-9" width="26" height="18" rx="4"/><path d="M-13 -7 l13 9 l13 -9" />';
    this.el.append(this.dot);
    this.relabel();
  }

  private names: Partial<Record<NodeId, string>> = {};

  /** Set node labels, optionally overridden by the current lesson. */
  relabel(overrides: Lesson['labels'] = {}): void {
    for (const [id, g] of this.nodes) {
      const [label, addr] = g.querySelectorAll('text.label, text.addr');
      const o = overrides[id];
      this.names[id] = o ? tr(o.label) : t(LABEL[id]);
      label.textContent = this.names[id]!;
      addr.textContent = o ? o.addr ?? '' : ADDR[id];
    }
  }

  /** Animate a packet from one node to another along the shortest path. */
  show(from: NodeId, to: NodeId, color: string, animate: boolean, onDone?: () => void): void {
    cancelAnimationFrame(this.anim);
    const path = route(from, to);
    this.el.setAttribute('aria-label', `Packet travelling from ${this.names[from]} to ${this.names[to]}`);
    for (const [k, l] of this.links) {
      const [a, b] = k.split('-');
      const active = path.some((n, i) => i > 0 && ((path[i - 1] === a && n === b) || (path[i - 1] === b && n === a)));
      l.classList.toggle('active', active);
    }
    for (const [id, g] of this.nodes) {
      g.classList.toggle('endpoint', id === from || id === to);
    }
    this.dot.style.setProperty('--packet', color);

    const pts = path.map((n) => POS[n]);
    const segs = pts.slice(1).map((p, i) => Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1]));
    const total = segs.reduce((a, b) => a + b, 0) || 1;
    const place = (f: number) => {
      let d = f * total;
      let i = 0;
      while (i < segs.length - 1 && d > segs[i]) d -= segs[i++];
      const [x1, y1] = pts[i];
      const [x2, y2] = pts[Math.min(i + 1, pts.length - 1)];
      const r = segs[i] ? d / segs[i] : 1;
      this.dot.setAttribute('transform', `translate(${x1 + (x2 - x1) * r} ${y1 + (y2 - y1) * r - 26})`);
    };

    place(animate ? 0 : 1);
    if (!animate) {
      onDone?.();
      return;
    }
    const duration = 500 + total * 2.2;
    const start = performance.now();
    const tick = (now: number) => {
      const f = Math.min(1, (now - start) / duration);
      place(f < 0.5 ? 2 * f * f : 1 - Math.pow(-2 * f + 2, 2) / 2);
      if (f < 1) this.anim = requestAnimationFrame(tick);
      else onDone?.();
    };
    this.anim = requestAnimationFrame(tick);
  }
}
