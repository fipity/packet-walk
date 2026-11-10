// BGP-4 (RFC 4271, capabilities RFC 5492 / 6793) and NTPv4 (RFC 5905).
import { Header, layer, ip, type Packet } from '../bytes';

// ---------------------------------------------------------------- BGP

const BGP_TYPES: Record<number, string> = { 1: 'OPEN', 2: 'UPDATE', 3: 'NOTIFICATION', 4: 'KEEPALIVE' };

function bgp(type: number, body?: Header): Packet {
  const len = 19 + (body?.length ?? 0);
  const h = new Header();
  h.bytes('Marker', new Array(16).fill(0xff), 'ff × 16', 'Sixteen bytes of all ones. It once carried authentication data. Today it just helps the receiver find message boundaries in the TCP stream.');
  h.u16('Length', len, `${len} bytes`, 'Size of the whole message, including this 19-byte header.');
  h.u8('Type', type, `${type} (${BGP_TYPES[type]})`);
  if (body) {
    const bytes = body.build();
    for (const f of body.fields) h.bytes(f.name, bytes.subarray(f.offset, f.offset + f.length), f.value, f.info);
  }
  return layer(`BGP ${BGP_TYPES[type]}`, 'bgp', h);
}

export function bgpOpen(o: { as: number; holdTime: number; id: string }): Packet {
  const b = new Header();
  b.u8('Version', 4, '4 (BGP-4)');
  b.u16('My AS', o.as, `AS${o.as}`, 'The sender\'s Autonomous System number: the ID of the network it belongs to. (AS64496–64511 are reserved for documentation.)');
  b.u16('Hold time', o.holdTime, `${o.holdTime} seconds`, 'If nothing is heard from the peer for this long, the session is declared dead and all its routes are dropped. Both sides use the smaller of their two values.');
  b.bytes('BGP identifier', ip(o.id), o.id, 'A unique router ID, written like an IPv4 address. It is usually one of the router\'s own addresses.');
  b.u8('Optional parameters length', 20, '20 bytes');
  b.u8('Parameter type', 2, '2 (capabilities)');
  b.u8('Parameter length', 18, '18 bytes');
  b.u8('Capability: multiprotocol', 1, '1 (multiprotocol extensions)', 'Lists which address families this router will exchange.');
  b.u8('Capability length', 4, '4 bytes');
  b.bytes('AFI / SAFI', [0, 1, 0, 1], 'IPv4 unicast', 'Address family 1 (IPv4), sub-family 1 (unicast). An IPv6 session would add AFI 2.');
  b.u8('Capability: route refresh', 2, '2 (route refresh)', 'Lets either side ask the other to resend all its routes, for example after changing a filter.');
  b.u8('Capability length', 0, '0 bytes');
  b.u8('Capability: 4-octet AS', 65, '65 (4-byte AS numbers)', 'The original AS field only holds 16 bits (65,535 networks). That ran out, so routers advertise support for 32-bit AS numbers here.');
  b.u8('Capability length', 4, '4 bytes');
  b.u32('Full AS number', o.as, `AS${o.as}`);
  b.u8('Capability: graceful restart', 64, '64 (graceful restart)', 'If this router restarts its BGP software, the peer keeps forwarding using the old routes for a while instead of dropping them immediately.');
  b.u8('Capability length', 2, '2 bytes');
  b.u16('Restart time', 120, '120 seconds');
  return bgp(1, b);
}

export function bgpKeepalive(): Packet {
  return bgp(4);
}

function prefixBytes(prefix: string, len: number): number[] {
  return ip(prefix).slice(0, Math.ceil(len / 8));
}

export function bgpUpdate(o: { announce?: { prefix: string; len: number; asPath: number[]; nextHop: string }; withdraw?: { prefix: string; len: number } }): Packet {
  const b = new Header();
  if (o.withdraw) {
    const w = prefixBytes(o.withdraw.prefix, o.withdraw.len);
    b.u16('Withdrawn routes length', 1 + w.length, `${1 + w.length} bytes`);
    b.bytes('Withdrawn route', [o.withdraw.len, ...w], `${o.withdraw.prefix}/${o.withdraw.len}`, 'Prefixes are packed: a length in bits, then only as many address bytes as needed.');
  } else {
    b.u16('Withdrawn routes length', 0, '0 (nothing withdrawn)');
  }
  if (!o.announce) {
    b.u16('Total path attribute length', 0, '0');
    return bgp(2, b);
  }
  const a = o.announce;
  const pathLen = 2 + 4 * a.asPath.length;
  b.u16('Total path attribute length', 4 + (3 + pathLen) + 7, `${4 + 3 + pathLen + 7} bytes`);
  b.u8('Attribute flags', 0x40, 'well-known, transitive');
  b.u8('Attribute: ORIGIN', 1, '1 (ORIGIN)');
  b.u8('Attribute length', 1, '1 byte');
  b.u8('Origin', 0, '0 (IGP)', 'Where the route came from originally. IGP means it was configured on purpose, not imported from somewhere else.');
  b.u8('Attribute flags', 0x40, 'well-known, transitive');
  b.u8('Attribute: AS_PATH', 2, '2 (AS_PATH)', 'The list of networks this announcement has passed through. Routers reject any path that already contains their own AS (this prevents loops), and generally prefer shorter paths.');
  b.u8('Attribute length', pathLen, `${pathLen} bytes`);
  b.u8('Segment type', 2, '2 (AS_SEQUENCE)', 'An ordered list. Each network prepends its own number as it passes the route on.');
  b.u8('Segment length', a.asPath.length, `${a.asPath.length} AS`);
  for (const as of a.asPath) b.u32('AS number', as, `AS${as}`);
  b.u8('Attribute flags', 0x40, 'well-known, transitive');
  b.u8('Attribute: NEXT_HOP', 3, '3 (NEXT_HOP)');
  b.u8('Attribute length', 4, '4 bytes');
  b.bytes('Next hop', ip(a.nextHop), a.nextHop, 'Where to send packets for this prefix: here, the announcing router itself.');
  const p = prefixBytes(a.prefix, a.len);
  b.bytes('Announced prefix (NLRI)', [a.len, ...p], `${a.prefix}/${a.len}`, 'Network Layer Reachability Information: the block of addresses being announced, packed as a bit length followed by just enough address bytes.');
  return bgp(2, b);
}

// ---------------------------------------------------------------- NTP

const NTP_EPOCH = 2208988800; // seconds from 1900-01-01 to 1970-01-01

function fmtTime(t: number): string {
  const d = new Date(t * 1000);
  const frac = (t - Math.floor(t)).toFixed(6).slice(1);
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)}${frac} UTC`;
}

function timestamp(h: Header, name: string, t: number, info?: string): void {
  if (t === 0) {
    h.bytes(name, new Array(8).fill(0), '0 (not set)', info);
    return;
  }
  const secs = Math.floor(t);
  const frac = Math.min(0xffffffff, Math.round((t - secs) * 2 ** 32));
  const s = secs + NTP_EPOCH;
  h.bytes(
    name,
    [s >>> 24, (s >>> 16) & 0xff, (s >>> 8) & 0xff, s & 0xff, frac >>> 24, (frac >>> 16) & 0xff, (frac >>> 8) & 0xff, frac & 0xff],
    fmtTime(t),
    (info ? info + ' ' : '') + 'NTP timestamps are 64 bits: 32 bits of seconds since 1 January 1900, and 32 bits of fraction, which gives a resolution of about 0.23 nanoseconds.',
  );
}

export interface NtpOpts {
  mode: 3 | 4;
  stratum: number;
  poll: number;
  precision: number;
  rootDelay: number;
  rootDispersion: number;
  refId: string;
  reference: number;
  origin: number;
  receive: number;
  transmit: number;
}

export function ntp(o: NtpOpts): Packet {
  const h = new Header();
  const b0 = (0 << 6) | (4 << 3) | o.mode;
  h.u8('LI / version / mode', b0, `LI=0, version 4, mode ${o.mode} (${o.mode === 3 ? 'client' : 'server'})`, 'Leap indicator (2 bits: warns of an upcoming leap second), version (3 bits), and mode (3 bits: 3 = client, 4 = server).');
  h.u8('Stratum', o.stratum, o.stratum === 0 ? '0 (unspecified)' : `${o.stratum} (${o.stratum === 1 ? 'primary' : 'secondary'} server)`, 'Distance from a reference clock. Stratum 1 servers are wired to an atomic clock or GPS. Stratum 2 servers sync from stratum 1, and so on.');
  h.u8('Poll interval', o.poll, `2^${o.poll} = ${2 ** o.poll} seconds`, 'How long until the next query. Clients start polling often and back off as their clock settles.');
  h.u8('Precision', o.precision & 0xff, `2^${o.precision} ≈ ${(2 ** o.precision * 1e6).toPrecision(2)} µs`, 'How finely this machine\'s clock can be read, as a signed power of two.');
  const fixed = (name: string, v: number, info: string) => h.u32(name, Math.round(v * 65536), `${(v * 1000).toFixed(3)} ms`, info);
  fixed('Root delay', o.rootDelay, 'Total round-trip delay to the stratum 1 reference clock. Stored as a 16.16 fixed-point number of seconds.');
  fixed('Root dispersion', o.rootDispersion, 'The server\'s estimate of how far its clock could be from true time.');
  h.bytes('Reference ID', o.refId === '' ? [0, 0, 0, 0] : ip(o.refId), o.refId || '0 (none)', 'For stratum 2 and above, the IPv4 address of the upstream server this machine syncs to. Stratum 1 servers put a code here, such as "GPS".');
  timestamp(h, 'Reference timestamp', o.reference, 'When the server last set its clock.');
  timestamp(h, 'Origin timestamp (T1)', o.origin, o.mode === 4 ? 'Copied from the client\'s transmit timestamp. It lets the client match the reply to its request, and makes blind spoofing hard.' : undefined);
  timestamp(h, 'Receive timestamp (T2)', o.receive, o.mode === 4 ? 'Server clock time when the request arrived.' : undefined);
  timestamp(h, 'Transmit timestamp', o.transmit, o.mode === 4 ? 'T3: server clock time when this reply was sent.' : 'T1: client clock time as the request leaves.');
  return layer(o.mode === 3 ? 'NTP request' : 'NTP response', 'ntp', h);
}
