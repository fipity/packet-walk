// IPv4 (RFC 791), ICMP (RFC 792), UDP (RFC 768) and TCP (RFC 9293).
import { Header, layer, patch16, checksum, ip, hex16, truncate, type Packet } from '../bytes';

const PROTO = { ICMP: 1, TCP: 6, UDP: 17 } as const;
export type IpProto = keyof typeof PROTO;

const SERVICES: Record<number, string> = { 53: 'DNS', 80: 'HTTP', 443: 'HTTPS' };
const portName = (p: number) => (SERVICES[p] ? `${p} (${SERVICES[p]})` : `${p}`);
const portInfo = (p: number) =>
  SERVICES[p]
    ? `Port ${p} is the well-known port for ${SERVICES[p]}, so the server knows which program should get the data.`
    : 'A temporary ("ephemeral") port picked by the operating system so replies find their way back to the right program.';

export interface IpOpts {
  src: string;
  dst: string;
  proto: IpProto;
  ttl?: number;
  id?: number;
  df?: boolean;
}

export function ipv4(o: IpOpts, payload: Packet): Packet {
  const ttl = o.ttl ?? 64;
  const id = o.id ?? 0;
  const df = o.df ?? true;
  const total = 20 + payload.bytes.length;
  const h = new Header();
  h.u8('Version / header length', 0x45, '4 / 20 bytes', 'The first 4 bits are the IP version (4). The last 4 bits are the header length in 32-bit words: 5 × 4 = 20 bytes, which means there are no options.');
  h.u8('DSCP / ECN', 0, '0 (best effort)', 'Quality-of-service and congestion-notification bits. Zero means ordinary traffic.');
  h.u16('Total length', total, `${total} bytes`, 'Size of this IP packet, header plus payload.');
  h.u16('Identification', id, `0x${hex16(id)}`, 'If a router has to split the packet into fragments, every fragment carries this same number so the receiver can put them back together.');
  h.u16('Flags / fragment offset', df ? 0x4000 : 0, df ? "Don't fragment, offset 0" : 'offset 0', 'The "don\'t fragment" bit asks routers to drop the packet rather than split it, so that hosts can discover the largest packet size the path allows.');
  h.u8('Time to live', ttl, String(ttl), 'Every router subtracts 1. When it reaches 0 the packet is dropped and the sender is told with an ICMP "time exceeded". This stops packets looping forever.');
  h.u8('Protocol', PROTO[o.proto], `${PROTO[o.proto]} (${o.proto})`, 'Which protocol the payload belongs to.');
  const ck = h.u16('Header checksum', 0, '', 'An Internet checksum over the header only. Routers check it and recompute it after decrementing the TTL.');
  h.bytes('Source address', ip(o.src), o.src);
  h.bytes('Destination address', ip(o.dst), o.dst, 'Unlike MAC addresses, this stays the same from end to end (except when a NAT router rewrites it).');
  const pkt = layer('IPv4', 'ip', h, payload);
  patch16(pkt, ck, checksum(pkt.bytes.subarray(0, 20)));
  return pkt;
}

/** The 12-byte pseudo-header TCP and UDP include in their checksum. */
function pseudoSum(src: string, dst: string, proto: number, segment: Uint8Array): number {
  const buf = new Uint8Array(12 + segment.length);
  buf.set(ip(src), 0);
  buf.set(ip(dst), 4);
  buf[9] = proto;
  buf[10] = segment.length >>> 8;
  buf[11] = segment.length & 0xff;
  buf.set(segment, 12);
  return checksum(buf);
}

export function icmpEcho(o: { reply: boolean; id: number; seq: number; data: Uint8Array }): Packet {
  const h = new Header();
  h.u8('Type', o.reply ? 0 : 8, o.reply ? '0 (echo reply)' : '8 (echo request)', 'What kind of ICMP message this is.');
  h.u8('Code', 0, '0', 'A sub-type. Echo messages only use 0.');
  const ck = h.u16('Checksum', 0, '', 'An Internet checksum over the whole ICMP message.');
  h.u16('Identifier', o.id, String(o.id), 'Picked by the sender (often its process ID) to match replies to the right ping program.');
  h.u16('Sequence number', o.seq, String(o.seq), 'Counts up with every ping, so lost or reordered replies are easy to spot.');
  h.bytes('Data', o.data, undefined, 'Arbitrary bytes. The reply must copy them back exactly. Linux puts a timestamp here to measure the round-trip time.');
  const pkt = layer('ICMP', 'icmp', h);
  patch16(pkt, ck, checksum(pkt.bytes));
  return pkt;
}

export function icmpTimeExceeded(original: Packet): Packet {
  const quoted = truncate(original, 28);
  quoted.layers[0].name = 'Quoted IPv4 header';
  const h = new Header();
  h.u8('Type', 11, '11 (time exceeded)', 'A router dropped the packet because its TTL reached zero.');
  h.u8('Code', 0, '0 (TTL expired in transit)');
  const ck = h.u16('Checksum', 0, '');
  h.u32('Unused', 0, '0');
  const pkt = layer('ICMP', 'icmp', h, quoted);
  patch16(pkt, ck, checksum(pkt.bytes));
  return pkt;
}

export function udp(o: { src: string; dst: string; srcPort: number; dstPort: number }, payload: Packet): Packet {
  const len = 8 + payload.bytes.length;
  const h = new Header();
  h.u16('Source port', o.srcPort, portName(o.srcPort), portInfo(o.srcPort));
  h.u16('Destination port', o.dstPort, portName(o.dstPort), portInfo(o.dstPort));
  h.u16('Length', len, `${len} bytes`, 'Header plus payload. UDP has no other bookkeeping: no connection, no ordering, no retransmission.');
  const ck = h.u16('Checksum', 0, '', 'Covers the UDP header, the payload, and a "pseudo-header" made of the source and destination IP addresses, so a packet delivered to the wrong host is detected.');
  const pkt = layer('UDP', 'udp', h, payload);
  const c = pseudoSum(o.src, o.dst, PROTO.UDP, pkt.bytes);
  patch16(pkt, ck, c === 0 ? 0xffff : c);
  return pkt;
}

const TCP_FLAGS = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'] as const;
export type TcpFlag = (typeof TCP_FLAGS)[number];

export interface TcpOpts {
  src: string;
  dst: string;
  srcPort: number;
  dstPort: number;
  seq: number;
  ack: number;
  flags: TcpFlag[];
  window: number;
  /** Initial sequence numbers, used to show relative numbers like Wireshark does. */
  seqBase?: number;
  ackBase?: number;
}

export function tcp(o: TcpOpts, payload?: Packet): Packet {
  const syn = o.flags.includes('SYN');
  const opts = new Header();
  if (syn) {
    opts.u8('Option: MSS kind', 2, '2 (maximum segment size)');
    opts.u8('Option: MSS length', 4, '4 bytes');
    opts.u16('Option: MSS value', 1460, '1460 bytes', 'The largest chunk of data this side wants to receive in one segment: a 1500-byte Ethernet payload minus 20 bytes of IP and 20 bytes of TCP header.');
    opts.u8('Option: NOP', 1, 'no-operation', 'Padding so the next option starts on a convenient boundary.');
    opts.u8('Option: NOP', 1, 'no-operation');
    opts.u8('Option: SACK permitted kind', 4, '4 (SACK permitted)', 'Says "you may tell me exactly which blocks arrived", so only the missing pieces need to be resent after a loss.');
    opts.u8('Option: SACK permitted length', 2, '2 bytes');
    opts.u8('Option: NOP', 1, 'no-operation');
    opts.u8('Option: window scale kind', 3, '3 (window scale)');
    opts.u8('Option: window scale length', 3, '3 bytes');
    opts.u8('Option: window scale shift', 7, '7 (multiply by 128)', 'The 16-bit window field can only say 65,535 bytes. This shifts it left by 7 bits for the rest of the connection, allowing windows up to 8 MB.');
  }
  const hdrLen = 20 + opts.length;
  const bits = o.flags.reduce((b, f) => b | (1 << TCP_FLAGS.indexOf(f)), 0);
  const rel = (v: number, base?: number) => (base === undefined ? String(v >>> 0) : `${v >>> 0} (relative ${(v - base) >>> 0})`);

  const h = new Header();
  h.u16('Source port', o.srcPort, portName(o.srcPort), portInfo(o.srcPort));
  h.u16('Destination port', o.dstPort, portName(o.dstPort), portInfo(o.dstPort));
  h.u32('Sequence number', o.seq, rel(o.seq, o.seqBase), 'The position of this segment\'s first byte in the sender\'s stream. It starts at a random number (the "initial sequence number") to make spoofing harder. SYN and FIN each count as one byte.');
  h.u32(
    'Acknowledgment number',
    o.ack,
    o.flags.includes('ACK') ? rel(o.ack, o.ackBase) : '0 (not used)',
    'The next byte this side expects from the other side. It confirms that every byte before it arrived.',
  );
  h.u8('Header length', (hdrLen / 4) << 4, `${hdrLen} bytes`, 'The high 4 bits give the header length in 32-bit words, so the receiver knows where options end and data begins.');
  h.u8('Flags', bits, o.flags.join(', '), 'SYN opens a connection, ACK means the acknowledgment number is valid, PSH asks for the data to be delivered right away, FIN closes this side, and RST aborts.');
  const winValue = syn ? `${o.window} bytes` : `${o.window} (× 128 = ${(o.window * 128).toLocaleString('en-US')} bytes)`;
  h.u16('Window', o.window, winValue, 'How many more bytes the sender of this segment is willing to receive right now. This is TCP flow control.');
  const ck = h.u16('Checksum', 0, '', 'Covers the TCP header, the data, and the IP-address pseudo-header.');
  h.u16('Urgent pointer', 0, '0 (not used)');
  for (const f of opts.fields) h.bytes(f.name, opts.build().subarray(f.offset, f.offset + f.length), f.value, f.info);

  const pkt = layer('TCP', 'tcp', h, payload);
  patch16(pkt, ck, pseudoSum(o.src, o.dst, PROTO.TCP, pkt.bytes));
  return pkt;
}
