// The OSI and TCP/IP reference models: layer data, a mapping from protocol layers to OSI
// layers, and the interactive "Models" page.
import type { Layer } from './bytes';
import { LESSONS } from './lessons';
import { chain, shortName } from './diagram';
import { tr } from './i18n';

export interface OsiLayer {
  n: number;
  name: string;
  pdu: string;
  does: string;
  addressing: string;
  devices: string;
  /** Protocols and where to see them in packet-walk. */
  examples: { label: string; lesson: string; note: string }[];
}

export const OSI: OsiLayer[] = [
  {
    n: 7, name: 'Application', pdu: 'Data / message',
    does: 'The protocols programs use to get work done: fetching web pages, resolving names, sending mail, sharing files, logging in.',
    addressing: 'Names and resources: URLs, host names, email addresses, file paths',
    devices: 'Clients and servers, proxies, application firewalls',
    examples: [
      { label: 'HTTP', lesson: 'http', note: 'Requests and responses for web pages' },
      { label: 'DNS', lesson: 'udp-dns', note: 'Names to addresses' },
      { label: 'SMTP / IMAP / POP3', lesson: 'smtp', note: 'Sending and reading email' },
      { label: 'SSH', lesson: 'ssh', note: 'Remote shells' },
      { label: 'FTP / SMB', lesson: 'smb', note: 'File transfer and sharing' },
      { label: 'DHCP / NTP / RADIUS / BGP', lesson: 'radius', note: 'Network services, which are themselves applications' },
    ],
  },
  {
    n: 6, name: 'Presentation', pdu: 'Data',
    does: 'How data is represented: character encodings, serialisation formats, compression and encryption, so both sides understand the bytes the same way. TCP/IP has no separate layer for this, so these jobs live inside application protocols and libraries.',
    addressing: 'None',
    devices: 'Implemented in software libraries (TLS, codecs, parsers)',
    examples: [
      { label: 'TLS encryption', lesson: 'tls', note: 'Records encrypt and authenticate whatever the application sends' },
      { label: 'UTF-16LE text', lesson: 'smb', note: 'SMB encodes file and share names two bytes per character' },
      { label: 'ASN.1 / DER', lesson: 'smb', note: 'The SPNEGO token in the SMB negotiate response' },
      { label: 'Base64 and MIME', lesson: 'websocket', note: 'The Sec-WebSocket-Key/Accept values. Email attachments use the same encoding' },
      { label: 'QPACK header compression', lesson: 'quic', note: 'HTTP/3 compresses headers inside QUIC' },
    ],
  },
  {
    n: 5, name: 'Session', pdu: 'Data',
    does: 'Opening, managing and closing conversations between applications: dialogues, checkpoints, and several logical sessions over one connection. In TCP/IP these functions also live inside applications.',
    addressing: 'Session and channel identifiers',
    devices: 'Implemented in software',
    examples: [
      { label: 'NetBIOS session service', lesson: 'smb', note: 'The 4-byte framing in front of every SMB message' },
      { label: 'SSH channels', lesson: 'ssh-tunnel', note: 'Many channels (shells, tunnels) multiplexed over one SSH connection' },
      { label: 'SMB sessions and trees', lesson: 'smb', note: 'Session IDs and tree IDs in every SMB header' },
      { label: 'TLS sessions', lesson: 'tls', note: 'Handshakes and session tickets establish and resume a secure session' },
      { label: 'RADIUS accounting sessions', lesson: 'radius', note: 'Acct-Session-Id ties together the start and stop records' },
    ],
  },
  {
    n: 4, name: 'Transport', pdu: 'Segment (TCP) / datagram (UDP)',
    does: 'Gets data from a program on one host to a program on another. It adds ports, and TCP or QUIC add reliability, ordering, flow control and congestion control.',
    addressing: 'Port numbers',
    devices: 'Hosts; also stateful firewalls, NAT and load balancers that track connections',
    examples: [
      { label: 'TCP', lesson: 'tcp', note: 'Handshake, sequence numbers, acknowledgements' },
      { label: 'UDP', lesson: 'udp-dns', note: 'Just ports, a length and a checksum' },
      { label: 'QUIC', lesson: 'quic', note: 'Reliable, encrypted streams built on UDP' },
    ],
  },
  {
    n: 3, name: 'Network', pdu: 'Packet',
    does: 'Moves packets between networks, from the source host to the destination host, one router hop at a time.',
    addressing: 'IP addresses (IPv4, IPv6)',
    devices: 'Routers, layer-3 switches',
    examples: [
      { label: 'IPv4', lesson: 'ip-icmp', note: 'TTL, NAT and traceroute' },
      { label: 'IPv6', lesson: 'ipv6', note: '128-bit addresses and neighbor discovery' },
      { label: 'ICMP', lesson: 'ip-icmp', note: 'Ping and error messages' },
      { label: 'WireGuard', lesson: 'wireguard', note: 'A layer-3 tunnel: whole IP packets carried inside UDP' },
      { label: 'BGP routes', lesson: 'bgp', note: 'BGP itself runs over TCP, but it builds the network layer\'s routing tables' },
    ],
  },
  {
    n: 2, name: 'Data link', pdu: 'Frame',
    does: 'Delivers frames between devices on the same local link, detects transmission errors, and decides who may transmit.',
    addressing: 'MAC addresses',
    devices: 'Switches, bridges, Wi-Fi access points, network cards',
    examples: [
      { label: 'Ethernet II', lesson: 'ethernet-arp', note: 'Destination, source and EtherType' },
      { label: '802.11 Wi-Fi', lesson: 'wifi', note: 'Three addresses, acknowledgements and WPA2' },
      { label: 'ARP', lesson: 'ethernet-arp', note: 'Bridges layer 3 and layer 2: it maps IP addresses to MAC addresses' },
      { label: 'EAPOL', lesson: 'wifi', note: 'Port access control before the link carries traffic' },
    ],
  },
  {
    n: 1, name: 'Physical', pdu: 'Bit (symbol)',
    does: 'Turns bits into signals (voltages, light pulses, radio waves) and back again. It covers connectors, cables, frequencies, timing and line coding.',
    addressing: 'None',
    devices: 'Cables, fibre, radios, hubs, repeaters, transceivers',
    examples: [
      { label: 'Preamble, SFD and FCS', lesson: 'physical', note: 'What the network card adds around every Ethernet frame' },
      { label: 'Wi-Fi radio', lesson: 'wifi', note: 'Channels and beacons on 2.4, 5 and 6 GHz' },
    ],
  },
];

export const TCPIP4 = [
  { name: 'Application', span: [5, 7], note: 'Everything above transport: OSI 5–7 combined' },
  { name: 'Transport', span: [4, 4], note: 'TCP, UDP (and QUIC)' },
  { name: 'Internet', span: [3, 3], note: 'IP, ICMP' },
  { name: 'Link', span: [1, 2], note: 'Whatever carries IP on the local network (RFC 1122)' },
];

export const TCPIP5 = [
  { name: 'Application', span: [5, 7] },
  { name: 'Transport', span: [4, 4] },
  { name: 'Network', span: [3, 3] },
  { name: 'Data link', span: [2, 2] },
  { name: 'Physical', span: [1, 1] },
];

/** Which OSI layer a protocol layer in a packet belongs to (by convention). */
export function osiOf(l: Layer): number {
  switch (l.kind) {
    case 'phy':
      return 1;
    case 'eth':
    case 'wifi':
    case 'arp':
    case 'eapol':
      return 2;
    case 'ip':
    case 'icmp':
    case 'wg':
      return 3;
    case 'tcp':
    case 'udp':
    case 'quic':
      return 4;
    case 'tls':
      return 6;
    case 'smb':
      return l.name.startsWith('NetBIOS') ? 5 : 7;
    default:
      return 7;
  }
}

// ---------------------------------------------------------------- page

const h = (tag: string, cls?: string, text?: string) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};

function lessonTitle(id: string): string {
  const l = LESSONS.find((x) => x.id === id);
  return l ? tr(l.title) : id;
}

export function renderModels(root: HTMLElement, selected: number): void {
  const page = h('div', 'models-page');
  const head = h('header', 'models-head');
  head.append(
    h('p', 'crumb', 'Reference'),
    h('h1', '', 'The OSI and TCP/IP models'),
    h('p', 'intro', 'Networking is built in layers, each using the one below and serving the one above. The OSI model names seven layers. The TCP/IP model that the internet actually uses folds them into four (or five, when the physical layer is listed separately). Select a layer to see what it does and where each lesson shows it.'),
  );

  // Comparison grid: 7 rows, three models side by side.
  const grid = h('div', 'models-grid');
  grid.append(h('div', 'mg-h', 'OSI (7 layers)'), h('div', 'mg-h', 'TCP/IP (5 layers)'), h('div', 'mg-h', 'TCP/IP (4 layers, RFC 1122)'), h('div', 'mg-h', 'Unit of data'));
  for (const L of OSI) {
    const row = 8 - L.n + 1;
    const a = h('a', `mg-cell osi l${L.n}${L.n === selected ? ' current' : ''}`) as HTMLAnchorElement;
    a.href = `#/models/${L.n}`;
    a.style.gridRow = String(row);
    a.style.gridColumn = '1';
    a.append(h('b', '', `L${L.n}`), h('span', '', L.name));
    const pdu = h('div', `mg-cell pdu l${L.n}`, L.pdu);
    pdu.style.gridRow = String(row);
    pdu.style.gridColumn = '4';
    grid.append(a, pdu);
  }
  for (const [col, model] of [[2, TCPIP5], [3, TCPIP4]] as const) {
    for (const m of model) {
      const c = h('div', `mg-cell tcpip${selected >= m.span[0] && selected <= m.span[1] ? ' current' : ''}`);
      c.style.gridRow = `${8 - m.span[1] + 1} / ${8 - m.span[0] + 2}`;
      c.style.gridColumn = String(col);
      c.append(h('span', '', m.name));
      if ('note' in m) c.append(h('small', '', m.note));
      grid.append(c);
    }
  }

  // Detail for the selected layer.
  const L = OSI.find((x) => x.n === selected) ?? OSI[0];
  const detail = h('section', 'models-detail');
  detail.style.setProperty('--c', `var(--osi-${L.n})`);
  const dl = h('dl');
  for (const [k, v] of [['Unit of data', L.pdu], ['Addressing', L.addressing], ['Typical devices', L.devices]]) dl.append(h('dt', '', k), h('dd', '', v));
  const ex = h('ul', 'models-ex');
  for (const e of L.examples) {
    const li = h('li');
    const a = h('a', '', e.label) as HTMLAnchorElement;
    a.href = `#/${e.lesson}`;
    li.append(a, h('span', '', ` ${e.note} (${lessonTitle(e.lesson)} lesson)`));
    ex.append(li);
  }
  detail.append(h('p', 'crumb', `Layer ${L.n}`), h('h2', '', L.name), h('p', '', L.does), dl, h('h3', '', 'See it in packet-walk'), ex);

  // Encapsulation of one real packet, by OSI layer.
  const demo = LESSONS.find((l) => l.id === 'tls')!;
  const step = demo.steps[0];
  const p = step.packet;
  const enc = h('section', 'models-enc');
  enc.append(h('h2', '', 'One real packet, layer by layer'), h('p', 'intro', `The TLS ClientHello from the "${tr(demo.title)}" lesson: ${p.bytes.length} bytes on the wire. Each layer adds its header in front of the data from the layer above. The bar shows how much each layer's own fields add. The physical layer would add a further 8-byte preamble and a 4-byte FCS (see the Physical layer lesson).`));
  const bars = h('div', 'enc-bars');
  const total = p.bytes.length;
  for (const [i, l] of p.layers.entries()) {
    const own = p.fields.filter((f) => f.layer === i).reduce((n, f) => n + f.length, 0);
    const row = h('div', 'enc-row');
    row.style.setProperty('--c', `var(--k-${l.kind})`);
    row.style.setProperty('--depth', String(l.depth));
    const bar = h('div', 'enc-bar');
    bar.style.width = `${Math.max(2, (own / total) * 100)}%`;
    bar.style.marginLeft = `${(l.offset / total) * 100}%`;
    row.append(h('span', 'enc-osi', `L${osiOf(l)}`), h('span', 'enc-name', `${shortName(l)}${l.name !== shortName(l) ? ` · ${l.name}` : ''}`), h('span', 'enc-size', `${own} of ${l.length} bytes`), bar);
    bars.append(row);
  }
  enc.append(bars, h('p', 'enc-chain', `On the wire: ${chain(p).map((c) => c.label).join(' › ')}`));

  const back = h('a', 'btn', '← All lessons') as HTMLAnchorElement;
  back.href = '#/';
  page.append(head, grid, detail, enc, back);
  root.replaceChildren(page);
}
