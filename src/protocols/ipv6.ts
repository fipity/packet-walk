// IPv6 (RFC 8200), ICMPv6 (RFC 4443) and Neighbor Discovery (RFC 4861).
import { Header, layer, patch16, checksum, mac, hex16, type Packet } from '../bytes';

/** Parse an IPv6 address (with optional "::") into 16 bytes. */
export function ip6(s: string): number[] {
  const [head, tail] = s.includes('::') ? s.split('::') : [s, undefined];
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = tail === undefined ? h : [...h, ...new Array(8 - h.length - t.length).fill('0'), ...t];
  if (groups.length !== 8) throw new Error(`bad IPv6 address: ${s}`);
  return groups.flatMap((g) => {
    const v = parseInt(g, 16);
    return [v >>> 8, v & 0xff];
  });
}

/** Format 16 bytes as a compressed IPv6 address (RFC 5952). */
export function fmt6(b: ArrayLike<number>): string {
  const g: number[] = [];
  for (let i = 0; i < 16; i += 2) g.push((b[i] << 8) | b[i + 1]);
  let best = -1;
  let bestLen = 1;
  for (let i = 0; i < 8; ) {
    if (g[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) {
      best = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

/** Ethernet multicast MAC for an IPv6 multicast address: 33:33 + last 4 bytes. */
export function multicastMac(addr: string): string {
  const b = ip6(addr).slice(12);
  return ['33', '33', ...b.map((x) => x.toString(16).padStart(2, '0'))].join(':');
}

/** Solicited-node multicast address for a unicast address: ff02::1:ffXX:XXXX. */
export function solicitedNode(addr: string): string {
  const b = ip6(addr);
  return fmt6([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, b[13], b[14], b[15]]);
}

function describe(addr: string): string | undefined {
  if (addr === '::') return 'The unspecified address: "I don\'t have an address yet."';
  if (addr === 'ff02::1') return 'All-nodes multicast: every IPv6 device on this link. IPv6 has no broadcast, only multicast.';
  if (addr === 'ff02::2') return 'All-routers multicast: every router on this link.';
  if (addr.startsWith('ff02::1:ff')) return 'A solicited-node multicast address, built from the last 24 bits of the address being looked up. Only devices whose address ends that way listen to it, so unlike ARP\'s broadcast, everyone else\'s network card filters it out.';
  if (addr.startsWith('fe80:')) return 'A link-local address (fe80::/10). Every IPv6 interface has one automatically. It works only on the local link and is never routed.';
  if (addr.startsWith('2001:db8:')) return 'A global unicast address. (2001:db8::/32 is reserved for documentation.)';
  return undefined;
}

export function ipv6(o: { src: string; dst: string; hopLimit: number }, payload: Packet): Packet {
  const h = new Header();
  h.u32('Version / traffic class / flow label', 0x60000000, '6 / 0 / 0', 'The first 4 bits are the version (6). Then come 8 bits of traffic class (like IPv4\'s DSCP/ECN) and a 20-bit flow label that lets routers keep packets of one flow together.');
  h.u16('Payload length', payload.bytes.length, `${payload.bytes.length} bytes`, 'Unlike IPv4, this does not include the header, which is always exactly 40 bytes.');
  h.u8('Next header', 58, '58 (ICMPv6)', 'Like IPv4\'s Protocol field, but it can also point to optional extension headers chained after this one.');
  h.u8('Hop limit', o.hopLimit, String(o.hopLimit), o.hopLimit === 255 ? 'Neighbor Discovery messages must be sent with 255 and are rejected if they arrive with anything less. That proves they did not come through a router from outside the link.' : 'IPv6\'s name for TTL: every router subtracts 1.');
  h.bytes('Source address', ip6(o.src), o.src, describe(o.src));
  h.bytes('Destination address', ip6(o.dst), o.dst, describe(o.dst));
  // Note: there is no header checksum. IPv6 leaves error detection to the link layer and to TCP/UDP/ICMPv6.
  return layer('IPv6', 'ip', h, payload);
}

const TYPES: Record<number, string> = {
  128: 'echo request',
  129: 'echo reply',
  133: 'router solicitation',
  134: 'router advertisement',
  135: 'neighbor solicitation',
  136: 'neighbor advertisement',
};

/** An ICMPv6 message, with its checksum computed over the IPv6 pseudo-header. */
function icmp6(src: string, dst: string, type: number, body: (h: Header) => void): Packet {
  const h = new Header();
  h.u8('Type', type, `${type} (${TYPES[type]})`);
  h.u8('Code', 0, '0');
  const ck = h.u16('Checksum', 0, '', 'Covers the ICMPv6 message and a pseudo-header with both IPv6 addresses. It is mandatory, because IPv6 itself has no checksum.');
  body(h);
  const pkt = layer('ICMPv6', 'icmp', h);
  const n = pkt.bytes.length;
  const pseudo = new Uint8Array(40 + n);
  pseudo.set(ip6(src), 0);
  pseudo.set(ip6(dst), 16);
  pseudo.set([n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff, 0, 0, 0, 58], 32);
  pseudo.set(pkt.bytes, 40);
  patch16(pkt, ck, checksum(pseudo));
  return pkt;
}

function linkLayerOption(h: Header, type: 1 | 2, addr: string): void {
  const name = type === 1 ? 'Source link-layer address' : 'Target link-layer address';
  h.u8(`Option: ${name}`, type, `${type} (${name.toLowerCase()})`, 'Neighbor Discovery options are type–length–value. The length is counted in units of 8 bytes.');
  h.u8('Option length', 1, '1 (8 bytes)');
  h.bytes(name, mac(addr), addr, 'The MAC address, carried inside the message itself. This is how IPv6 does ARP\'s job.');
}

export function routerSolicitation(src: string, srcMac: string): Packet {
  return icmp6(src, 'ff02::2', 133, (h) => {
    h.u32('Reserved', 0, '0');
    linkLayerOption(h, 1, srcMac);
  });
}

export function routerAdvertisement(o: { src: string; dst: string; mac: string; prefix: string; dns: string }): Packet {
  return icmp6(o.src, o.dst, 134, (h) => {
    h.u8('Current hop limit', 64, '64', 'The hop limit hosts should use for packets they send.');
    h.u8('Flags', 0, 'M=0, O=0 (use SLAAC, no DHCPv6)', 'M=1 would mean "get an address from DHCPv6". O=1 would mean "get other settings from DHCPv6". With both 0, hosts configure themselves.');
    h.u16('Router lifetime', 1800, '1800 seconds', 'How long hosts may use this router as their default gateway.');
    h.u32('Reachable time', 0, '0 (unspecified)');
    h.u32('Retransmit timer', 0, '0 (unspecified)');
    linkLayerOption(h, 1, o.mac);
    h.u8('Option: MTU', 5, '5 (MTU)');
    h.u8('Option length', 1, '1 (8 bytes)');
    h.u16('Reserved', 0, '0');
    h.u32('MTU', 1500, '1500 bytes', 'The largest packet the link carries. IPv6 routers never fragment packets, so senders must get this right.');
    h.u8('Option: Prefix information', 3, '3 (prefix information)', 'The heart of SLAAC: the network prefix that hosts should build their addresses from.');
    h.u8('Option length', 4, '4 (32 bytes)');
    h.u8('Prefix length', 64, '/64', 'The first 64 bits are the network. Hosts choose the other 64 bits themselves.');
    h.u8('Prefix flags', 0xc0, 'L=1 (on-link), A=1 (autonomous)', 'A=1 says hosts may build their own address from this prefix (Stateless Address Autoconfiguration).');
    h.u32('Valid lifetime', 86400, '86400 seconds (1 day)');
    h.u32('Preferred lifetime', 14400, '14400 seconds (4 hours)');
    h.u32('Reserved', 0, '0');
    h.bytes('Prefix', ip6(o.prefix), `${o.prefix}/64`);
    h.u8('Option: Recursive DNS server', 25, '25 (RDNSS)', 'Tells hosts which DNS server to use, so no DHCP is needed at all.');
    h.u8('Option length', 3, '3 (24 bytes)');
    h.u16('Reserved', 0, '0');
    h.u32('DNS lifetime', 1800, '1800 seconds');
    h.bytes('DNS server', ip6(o.dns), o.dns);
  });
}

export function neighborSolicitation(o: { src: string; dst: string; target: string; mac?: string }): Packet {
  return icmp6(o.src, o.dst, 135, (h) => {
    h.u32('Reserved', 0, '0');
    h.bytes('Target address', ip6(o.target), o.target, 'The IPv6 address whose MAC address is wanted, or the address being checked for duplicates.');
    if (o.mac) linkLayerOption(h, 1, o.mac);
  });
}

export function neighborAdvertisement(o: { src: string; dst: string; target: string; mac: string }): Packet {
  return icmp6(o.src, o.dst, 136, (h) => {
    h.u32('Flags', 0x60000000, 'S=1 (solicited), O=1 (override)', 'S=1: this answers a solicitation. O=1: replace any MAC address already cached for this IP. R=0: the sender is not a router.');
    h.bytes('Target address', ip6(o.target), o.target);
    linkLayerOption(h, 2, o.mac);
  });
}

export function echo6(o: { src: string; dst: string; reply: boolean; id: number; seq: number; data: Uint8Array }): Packet {
  return icmp6(o.src, o.dst, o.reply ? 129 : 128, (h) => {
    h.u16('Identifier', o.id, `0x${hex16(o.id)}`);
    h.u16('Sequence number', o.seq, String(o.seq));
    h.bytes('Data', o.data, undefined, 'Echoed back unchanged by the replier.');
  });
}
