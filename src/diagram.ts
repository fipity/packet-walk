// The network diagram: five nodes, the links between them, and an animated packet that
// shows its layers being wrapped at the sender, re-framed at the router, and unwrapped at the receiver.
import type { NodeId, Lesson } from './lessons/network';
import { NET } from './lessons/network';
import { t, tr, type Key } from './i18n';
import type { Layer, LayerKind, Packet } from './bytes';

const SVG = 'http://www.w3.org/2000/svg';
const W = 880;
const H = 360;

const POS: Record<NodeId, [number, number]> = {
  laptop: [95, 185],
  router: [315, 185],
  internet: [545, 185],
  dns: [785, 80],
  server: [785, 280],
};

const LINKS: [NodeId, NodeId][] = [
  ['laptop', 'router'],
  ['router', 'internet'],
  ['internet', 'dns'],
  ['internet', 'server'],
];

/** Links that only exist in some lessons (e.g. a private network behind a server). */
const OPTIONAL_LINKS: [NodeId, NodeId][] = [['server', 'dns']];

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
    '<rect x="-26" y="-22" width="52" height="33" rx="4" class="ico"/><rect x="-20" y="-16" width="40" height="21" rx="1.5" class="ico-screen"/><path d="M-33 13 h66 l-5 7 h-56 z" class="ico"/>',
  router:
    '<rect x="-30" y="-7" width="60" height="23" rx="5" class="ico"/><circle cx="-17" cy="4.5" r="2.8" class="led"/><circle cx="-7" cy="4.5" r="2.8" class="led"/><circle cx="3" cy="4.5" r="2.8" class="led dim"/><path d="M-19 -7 l-7 -18 M19 -7 l7 -18" class="ico-line"/>',
  internet:
    '<path d="M-36 14 a16 16 0 0 1 2 -31 a21 21 0 0 1 38 -7 a17 17 0 0 1 28 12 a14 14 0 0 1 2 26 z" class="ico"/>',
  dns:
    '<rect x="-23" y="-23" width="46" height="46" rx="6" class="ico"/><text x="0" y="5" text-anchor="middle" class="ico-text">DNS</text>',
  server:
    '<rect x="-23" y="-26" width="46" height="15" rx="3" class="ico"/><rect x="-23" y="-7" width="46" height="15" rx="3" class="ico"/><rect x="-23" y="12" width="46" height="15" rx="3" class="ico"/><circle cx="14" cy="-18.5" r="2.3" class="led"/><circle cx="14" cy="0.5" r="2.3" class="led"/><circle cx="14" cy="19.5" r="2.3" class="led"/>',
};

const ALT_ICON: Record<'database' | 'plc' | 'phone' | 'camera', string> = {
  phone:
    '<rect x="-26" y="-10" width="52" height="30" rx="5" class="ico"/><rect x="-18" y="-4" width="16" height="9" rx="1.5" class="ico-screen"/><path d="M4 -2 h14 M4 4 h14 M4 10 h14" class="ico-line"/><path d="M-28 -12 c0 -14 56 -14 56 0 l-10 4 l-6 -6 h-24 l-6 6 z" class="ico"/>',
  camera:
    '<rect x="-28" y="-14" width="44" height="26" rx="6" class="ico"/><circle cx="-6" cy="-1" r="8" class="ico-screen"/><circle cx="-6" cy="-1" r="3.5" class="led"/><path d="M16 -6 l14 -8 v26 l-14 -8 z" class="ico"/><path d="M-6 12 v12 M-16 24 h20" class="ico-line"/>',
  plc:
    '<rect x="-30" y="-22" width="60" height="40" rx="4" class="ico"/><rect x="-24" y="-16" width="16" height="10" rx="1.5" class="ico-screen"/><circle cx="4" cy="-11" r="2.6" class="led"/><circle cx="12" cy="-11" r="2.6" class="led dim"/><circle cx="20" cy="-11" r="2.6" class="led"/><path d="M-24 4 h48 M-24 10 h48" class="ico-line"/><path d="M-22 18 v6 M-12 18 v6 M-2 18 v6 M8 18 v6 M18 18 v6" class="ico-line"/>',
  database:
    '<ellipse cx="0" cy="-18" rx="22" ry="7" class="ico"/><path d="M-22 -18 v34 a22 7 0 0 0 44 0 v-34" class="ico"/><path d="M-22 -6 a22 7 0 0 0 44 0 M-22 6 a22 7 0 0 0 44 0" class="ico-line" fill="none"/>',
};

// ---------------------------------------------------------------- layer chips

const SHORT: Partial<Record<LayerKind, string>> = {
  eth: 'ETH', wifi: '802.11', arp: 'ARP', dhcp: 'DHCP', udp: 'UDP', tcp: 'TCP', dns: 'DNS', http: 'HTTP',
  ws: 'WS', quic: 'QUIC', ssh: 'SSH', ftp: 'FTP', bgp: 'BGP', ntp: 'NTP', smtp: 'SMTP', imap: 'IMAP',
  pop3: 'POP3', wg: 'WG', eapol: 'EAPOL', phy: 'PHY', radius: 'RADIUS', pg: 'PGSQL',
  pppoe: 'PPPoE', ppp: 'PPP', ike: 'IKEv2', esp: 'ESP', modbus: 'MODBUS',
  sip: 'SIP', sdp: 'SDP', rtsp: 'RTSP',
};

export function shortName(l: Layer): string {
  if (l.kind === 'ip') return l.name.includes('6') ? 'IPv6' : l.name.startsWith('Quoted') ? 'IPv4′' : 'IPv4';
  if (l.kind === 'icmp') return l.name.includes('v6') ? 'ICMPv6' : 'ICMP';
  if (l.kind === 'tls') return l.name.startsWith('TLS record') ? 'TLS' : l.name;
  if (l.kind === 'smb') return l.name.startsWith('NetBIOS') ? 'NBSS' : 'SMB2';
  if (l.kind === 'ppp') return l.name.startsWith('PPP (') ? 'PPP' : l.name.split(' ')[0];
  if (l.kind === 'ike') return 'IKEv2';
  if (l.kind === 'rtp') return l.name === 'RTP' ? 'RTP' : l.name.startsWith('H.264') ? 'H.264' : 'G.711';
  if (l.kind === 'ntp' && l.name.startsWith('NTS')) return 'NTS';
  return SHORT[l.kind] ?? l.name;
}

export interface Chip {
  label: string;
  kind: LayerKind;
}

/** The packet's layers from outermost to innermost, one chip per nesting depth. */
export function chain(p: Packet): Chip[] {
  const byDepth = new Map<number, Layer[]>();
  for (const l of p.layers) byDepth.set(l.depth, [...(byDepth.get(l.depth) ?? []), l]);
  return [...byDepth.keys()].sort((a, b) => a - b).map((d) => {
    const ls = byDepth.get(d)!;
    const names = [...new Set(ls.map(shortName))];
    const label = names.length === 1 ? names[0] + (ls.length > 1 ? ` ×${ls.length}` : '') : names.join('+');
    return { label, kind: ls[0].kind };
  });
}

// ---------------------------------------------------------------- routing

function route(from: NodeId, to: NodeId, links: [NodeId, NodeId][]): NodeId[] {
  const prev = new Map<NodeId, NodeId | null>([[from, null]]);
  const queue: NodeId[] = [from];
  while (queue.length) {
    const n = queue.shift()!;
    if (n === to) break;
    for (const [a, b] of links) {
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

const ease = (f: number) => (f < 0.5 ? 2 * f * f : 1 - Math.pow(-2 * f + 2, 2) / 2);

export class Diagram {
  readonly el: SVGSVGElement;
  readonly caption: HTMLElement;
  private dot: SVGGElement;
  private chipsG: SVGGElement;
  private chips: SVGGElement[] = [];
  private chipW = 0;
  private nodes = new Map<NodeId, SVGGElement>();
  private links = new Map<string, SVGLineElement>();
  private names: Partial<Record<NodeId, string>> = {};
  private enabled: [NodeId, NodeId][] = [...LINKS];
  private anim = 0;

  constructor(className = 'diagram') {
    this.el = document.createElementNS(SVG, 'svg');
    this.el.setAttribute('viewBox', `0 0 ${W} ${H}`);
    this.el.setAttribute('class', className);
    this.el.setAttribute('role', 'img');
    this.caption = document.createElement('div');
    this.caption.className = 'stage-caption';
    this.caption.setAttribute('aria-live', 'polite');

    for (const [a, b] of [...LINKS, ...OPTIONAL_LINKS]) {
      const l = document.createElementNS(SVG, 'line');
      const [x1, y1] = POS[a];
      const [x2, y2] = POS[b];
      for (const [k, v] of Object.entries({ x1, y1, x2, y2 })) l.setAttribute(k, String(v));
      l.setAttribute('class', OPTIONAL_LINKS.some(([x, y]) => x === a && y === b) ? 'link optional' : 'link');
      this.el.append(l);
      this.links.set(`${a}-${b}`, l);
    }
    for (const id of Object.keys(POS) as NodeId[]) {
      const g = document.createElementNS(SVG, 'g');
      const [x, y] = POS[id];
      g.setAttribute('transform', `translate(${x} ${y})`);
      g.setAttribute('class', 'node');
      g.innerHTML = `<circle r="44" class="halo"/><g class="icon">${ICON[id]}</g><text y="50" text-anchor="middle" class="label"></text><text y="67" text-anchor="middle" class="addr"></text>`;
      this.el.append(g);
      this.nodes.set(id, g);
    }
    this.dot = document.createElementNS(SVG, 'g');
    this.dot.setAttribute('class', 'packet');
    this.dot.innerHTML = '<circle r="11" class="pulse"/><circle r="6" class="core"/>';
    this.chipsG = document.createElementNS(SVG, 'g');
    this.chipsG.setAttribute('class', 'chips');
    this.dot.append(this.chipsG);
    this.el.append(this.dot);
    this.relabel();
  }

  /** Set node labels, optionally overridden by the current lesson. */
  relabel(overrides: Lesson['labels'] = {}, links: string[] = []): void {
    this.enabled = [...LINKS, ...OPTIONAL_LINKS.filter(([a, b]) => links.includes(`${a}-${b}`))];
    for (const [k, l] of this.links) l.classList.toggle('shown', links.includes(k));
    for (const [id, g] of this.nodes) {
      const [label, addr] = g.querySelectorAll('text.label, text.addr');
      const o = overrides[id];
      g.querySelector('.icon')!.innerHTML = o?.icon ? ALT_ICON[o.icon] : ICON[id];
      this.names[id] = o ? tr(o.label) : t(LABEL[id]);
      label.textContent = this.names[id]!;
      addr.textContent = o ? o.addr ?? '' : ADDR[id];
    }
  }

  private buildChips(ch: Chip[]): void {
    this.chipsG.replaceChildren();
    this.chips = [];
    let x = 0;
    for (const c of ch) {
      const w = Math.max(36, c.label.length * 7.8 + 16);
      const g = document.createElementNS(SVG, 'g');
      g.setAttribute('class', 'chip');
      g.style.setProperty('--c', `var(--k-${c.kind})`);
      g.setAttribute('transform', `translate(${x} 0)`);
      g.innerHTML = `<rect width="${w - 4}" height="24" rx="6"/><text x="${(w - 4) / 2}" y="16.5" text-anchor="middle"></text>`;
      g.querySelector('text')!.textContent = c.label;
      this.chipsG.append(g);
      this.chips.push(g);
      x += w;
    }
    this.chipW = x - 4;
  }

  /** Show only the innermost `n` chips: encapsulation grows outward. */
  private visible(n: number): void {
    const total = this.chips.length;
    this.chips.forEach((c, i) => c.classList.toggle('off', i < total - n));
  }

  /** Animate a packet from one node to another along the shortest path. */
  show(from: NodeId, to: NodeId, packet: Packet, animate: boolean, onDone?: () => void): void {
    cancelAnimationFrame(this.anim);
    const path = route(from, to, this.enabled);
    const fromName = this.names[from] ?? from;
    const toName = this.names[to] ?? to;
    this.el.setAttribute('aria-label', `Packet travelling from ${fromName} to ${toName}`);

    for (const [k, l] of this.links) {
      const [a, b] = k.split('-');
      let dir = 0;
      path.forEach((n, i) => {
        if (i === 0) return;
        if (path[i - 1] === a && n === b) dir = 1;
        if (path[i - 1] === b && n === a) dir = -1;
      });
      l.classList.toggle('active', dir !== 0);
      l.classList.toggle('rev', dir === -1);
    }
    for (const [id, g] of this.nodes) {
      g.classList.toggle('endpoint', id === from || id === to);
      g.classList.toggle('via', path.includes(id) && id !== from && id !== to);
    }

    const ch = chain(packet);
    this.buildChips(ch);
    const n = ch.length;
    const outer = ch[0];
    const pts = path.map((p) => POS[p]);
    const segs = pts.slice(1).map((p, i) => Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1]));
    const total = segs.reduce((a, b) => a + b, 0) || 1;

    const place = (f: number) => {
      let d = f * total;
      let i = 0;
      while (i < segs.length - 1 && d > segs[i]) d -= segs[i++];
      const [x1, y1] = pts[i];
      const [x2, y2] = pts[Math.min(i + 1, pts.length - 1)];
      const r = segs[i] ? Math.min(1, d / segs[i]) : 1;
      const x = x1 + (x2 - x1) * r;
      const y = y1 + (y2 - y1) * r;
      this.dot.setAttribute('transform', `translate(${x} ${y})`);
      // Keep the chip row inside the drawing, centred over the packet where possible.
      const left = Math.min(Math.max(x - this.chipW / 2, 8), W - 8 - this.chipW);
      this.chipsG.setAttribute('transform', `translate(${left - x} -60)`);
    };

    // Where along the path the packet passes the home router, if its link-layer frame is rebuilt there.
    const ri = path.indexOf('router');
    const reframe = ri > 0 && ri < path.length - 1 && (outer.kind === 'eth' || outer.kind === 'wifi');
    const routerF = reframe ? segs.slice(0, ri).reduce((a, b) => a + b, 0) / total : -1;
    const wrapList = [...ch].reverse().map((c) => c.label).join(' → ');
    const unwrapList = ch.map((c) => c.label).join(' → ');
    const summary = `${fromName} → ${toName} · ${packet.bytes.length} bytes`;

    if (!animate) {
      place(1);
      this.visible(n);
      this.caption.textContent = summary;
      onDone?.();
      return;
    }

    const E = 170 * n + 250;
    const T = 700 + total * 2;
    const D = 150 * n + 250;
    const start = performance.now();
    const tick = (now: number) => {
      const el = now - start;
      if (el < E) {
        place(0);
        this.visible(Math.min(n, Math.ceil((el / E) * n)));
        this.caption.textContent = `${fromName} wraps the data: ${wrapList}`;
      } else if (el < E + T) {
        const f = ease((el - E) / T);
        place(f);
        this.visible(n);
        const atRouter = reframe && Math.abs(f - routerF) < 0.08;
        this.chips[0]?.classList.toggle('swap', atRouter);
        this.caption.textContent = atRouter
          ? `${this.names.router}: strips the ${outer.label} frame and builds a new one for the next link`
          : `In transit · ${packet.bytes.length} bytes`;
      } else if (el < E + T + D) {
        place(1);
        this.chips[0]?.classList.remove('swap');
        this.visible(Math.max(1, n - Math.floor(((el - E - T) / D) * n)));
        this.caption.textContent = `${toName} unwraps it: ${unwrapList}`;
      } else {
        place(1);
        this.visible(n);
        this.caption.textContent = summary;
        onDone?.();
        return;
      }
      this.anim = requestAnimationFrame(tick);
    };
    this.anim = requestAnimationFrame(tick);
  }

  stop(): void {
    cancelAnimationFrame(this.anim);
  }
}
