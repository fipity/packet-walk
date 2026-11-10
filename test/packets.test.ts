// These tests check that every packet in every lesson is self-consistent at the byte level:
// every byte is described exactly once, length fields match, and checksums verify.
import { describe, expect, it } from 'vitest';
import { LESSONS } from '../src/lessons';
import { checksum, type Packet } from '../src/bytes';

const enc = (t: string) => Array.from(new TextEncoder().encode(t));
const u16 = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];

function* allSteps() {
  for (const l of LESSONS) for (const [i, s] of l.steps.entries()) yield [`${l.id} #${i + 1}`, s.packet] as const;
}

/** Walk Ethernet → IPv4 → TCP/UDP/ICMP and verify headers we can check generically. */
function verify(p: Packet) {
  const b = p.bytes;
  let ipStart = -1;
  if (p.layers[0].kind === 'eth') {
    const type = u16(b, 12);
    if (type === 0x0806) {
      expect(b.length).toBe(60); // padded minimum frame
      return;
    }
    expect(type).toBe(0x0800);
    ipStart = 14;
  } else if (p.layers[0].kind === 'ip') {
    ipStart = 0;
  }
  expect(ipStart).toBeGreaterThanOrEqual(0);
  const ipLen = u16(b, ipStart + 2);
  // Anything after the IP packet must be Ethernet padding up to the 60-byte minimum.
  expect(b.length).toBe(Math.max(ipStart + ipLen, ipStart ? 60 : 0));
  const ip = b.subarray(ipStart, ipStart + ipLen);
  expect(ip[0]).toBe(0x45);
  expect(checksum(ip.subarray(0, 20))).toBe(0);

  const proto = ip[9];
  const seg = ip.subarray(20);
  if (proto === 1) {
    expect(checksum(seg)).toBe(0);
  } else {
    const pseudo = new Uint8Array(12 + seg.length);
    pseudo.set(ip.subarray(12, 20), 0);
    pseudo[9] = proto;
    pseudo[10] = seg.length >> 8;
    pseudo[11] = seg.length & 0xff;
    pseudo.set(seg, 12);
    expect(checksum(pseudo)).toBe(0);
    if (proto === 17) expect(u16(seg, 4)).toBe(seg.length);
  }
}

describe('lesson packets', () => {
  for (const [name, p] of allSteps()) {
    it(`${name}: every byte belongs to exactly one field`, () => {
      const owner = new Array(p.bytes.length).fill(0);
      for (const f of p.fields) {
        expect(f.length).toBeGreaterThan(0);
        for (let i = f.offset; i < f.offset + f.length; i++) owner[i]++;
        const l = p.layers[f.layer];
        expect(f.offset).toBeGreaterThanOrEqual(l.offset);
        expect(f.offset + f.length).toBeLessThanOrEqual(l.offset + l.length);
      }
      expect(owner.every((n) => n === 1)).toBe(true);
    });

    it(`${name}: headers, lengths and checksums are valid`, () => verify(p));

    it(`${name}: TLS record lengths match`, () => {
      for (const l of p.layers.filter((x) => x.name.startsWith('TLS record'))) {
        expect(u16(p.bytes, l.offset + 3)).toBe(l.length - 5);
      }
    });
  }
});

describe('specific encodings', () => {
  it('encodes the DNS query name as labels', () => {
    const q = LESSONS.find((l) => l.id === 'udp-dns')!.steps[0].packet;
    const dns = q.layers.find((l) => l.kind === 'dns')!;
    const name = Array.from(q.bytes.subarray(dns.offset + 12, dns.offset + 12 + 17));
    expect(name).toEqual([3, ...enc('www'), 7, ...enc('example'), 3, ...enc('com'), 0]);
  });

  it('acknowledges SYN as one byte in the TCP handshake', () => {
    const [syn, synack] = LESSONS.find((l) => l.id === 'tcp')!.steps.map((s) => s.packet.bytes);
    const seq = (b: Uint8Array) => new DataView(b.buffer).getUint32(34 + 4);
    const ack = (b: Uint8Array) => new DataView(b.buffer).getUint32(34 + 8);
    expect(ack(synack)).toBe((seq(syn) + 1) >>> 0);
  });

  it('carries an HTTP request that parses as text', () => {
    const get = LESSONS.find((l) => l.id === 'http')!.steps[0].packet;
    const http = get.layers.find((l) => l.kind === 'http')!;
    const text = new TextDecoder('latin1').decode(get.bytes.subarray(http.offset));
    expect(text.startsWith('GET / HTTP/1.1\r\nHost: www.example.com\r\n')).toBe(true);
    expect(text.endsWith('\r\n\r\n')).toBe(true);
  });
});

describe('new protocols', () => {
  const lesson = (id: string) => LESSONS.find((l) => l.id === id)!;
  const layerOf = (p: Packet, kind: string) => p.layers.find((l) => l.kind === kind)!;

  it('pads DHCP messages to the 300-byte BOOTP minimum and ends options with 255', () => {
    for (const s of lesson('dhcp').steps) {
      const d = layerOf(s.packet, 'dhcp');
      expect(d.length).toBeGreaterThanOrEqual(300);
      expect(u16(s.packet.bytes, d.offset + 236) << 16 | u16(s.packet.bytes, d.offset + 238)).toBe(0x63825363);
      expect(Array.from(s.packet.bytes.subarray(d.offset, d.offset + d.length))).toContain(255);
    }
  });

  it('pads the QUIC client Initial datagram to 1200 bytes', () => {
    const p = lesson('quic').steps[0].packet;
    const udp = layerOf(p, 'udp');
    expect(udp.length - 8).toBe(1200);
  });

  it('QUIC long-header Length fields cover the rest of each packet', () => {
    for (const s of lesson('quic').steps) {
      for (const f of s.packet.fields.filter((x) => x.name === 'Length' && s.packet.layers[x.layer].kind === 'quic')) {
        const l = s.packet.layers[f.layer];
        const len = ((s.packet.bytes[f.offset] & 0x3f) << 8) | s.packet.bytes[f.offset + 1];
        expect(f.offset + 2 + len).toBe(l.offset + l.length);
      }
    }
  });

  it('masks the WebSocket client frame so it unmasks to the original text', () => {
    const p = lesson('websocket').steps[2].packet;
    const ws = layerOf(p, 'ws');
    const b = p.bytes.subarray(ws.offset, ws.offset + ws.length);
    expect(b[1] & 0x80).toBe(0x80);
    const key = b.subarray(2, 6);
    const text = String.fromCharCode(...Array.from(b.subarray(6), (x, i) => x ^ key[i % 4]));
    expect(text).toBe('Hello, server!');
  });

  it('frames unencrypted SSH binary packets to a multiple of 8 with at least 4 bytes of padding', () => {
    for (const s of lesson('ssh').steps) {
      for (const l of s.packet.layers.filter((x) => x.kind === 'ssh' && /KEX|NEWKEYS/.test(x.name))) {
        const len = new DataView(s.packet.bytes.buffer).getUint32(l.offset);
        expect(len + 4).toBe(l.length);
        expect((len + 4) % 8).toBe(0);
        expect(s.packet.bytes[l.offset + 4]).toBeGreaterThanOrEqual(4);
      }
    }
  });

  it('encodes the FTP passive-mode port correctly', () => {
    const data = lesson('ftp').steps.find((s) => s.packet.layers.some((l) => l.name === 'FTP data'))!.packet;
    const tcp = layerOf(data, 'tcp');
    expect(u16(data.bytes, tcp.offset)).toBe(195 * 256 + 80);
  });
});
