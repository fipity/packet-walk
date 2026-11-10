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
  if (p.layers[0].kind === 'wifi') return; // 802.11 frames are checked separately
  if (p.layers[0].kind === 'eth') {
    const type = u16(b, 12);
    if (type === 0x0806) {
      expect(b.length).toBe(60); // padded minimum frame
      return;
    }
    if (type === 0x86dd) {
      verify6(b.subarray(14));
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

/** IPv6: payload length matches and the ICMPv6 checksum (with the IPv6 pseudo-header) verifies. */
function verify6(ip: Uint8Array) {
  expect(ip[0] >> 4).toBe(6);
  const len = u16(ip, 4);
  expect(ip.length).toBe(40 + len);
  expect(ip[6]).toBe(58);
  const pseudo = new Uint8Array(40 + len);
  pseudo.set(ip.subarray(8, 40), 0);
  pseudo[34] = len >> 8;
  pseudo[35] = len & 0xff;
  pseudo[39] = 58;
  pseudo.set(ip.subarray(40), 40);
  expect(checksum(pseudo)).toBe(0);
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

describe('IPv6, BGP and NTP', () => {
  const lesson = (id: string) => LESSONS.find((l) => l.id === id)!;

  it('formats and parses IPv6 addresses', async () => {
    const { ip6, fmt6, solicitedNode, multicastMac } = await import('../src/protocols/ipv6');
    expect(fmt6(ip6('2001:db8:1:0:1a:2bff:fe3c:4d5e'))).toBe('2001:db8:1:0:1a:2bff:fe3c:4d5e');
    expect(fmt6(ip6('fe80:0:0:0:0:0:0:1'))).toBe('fe80::1');
    expect(fmt6(ip6('::'))).toBe('::');
    expect(solicitedNode('2001:db8:1:0:1a:2bff:fe3c:4d5e')).toBe('ff02::1:ff3c:4d5e');
    expect(multicastMac('ff02::1:ff3c:4d5e')).toBe('33:33:ff:3c:4d:5e');
  });

  it('sends Neighbor Discovery with hop limit 255', () => {
    for (const s of lesson('ipv6').steps) {
      const ip = s.packet.bytes.subarray(14);
      if ([133, 134, 135, 136].includes(ip[40])) expect(ip[7]).toBe(255);
    }
  });

  it('gives every BGP message a valid marker and length, with IP TTL 1', () => {
    for (const s of lesson('bgp').steps) {
      expect(s.packet.bytes[14 + 8]).toBe(1);
      const l = s.packet.layers.find((x) => x.kind === 'bgp')!;
      const b = s.packet.bytes.subarray(l.offset, l.offset + l.length);
      expect(Array.from(b.subarray(0, 16)).every((x) => x === 0xff)).toBe(true);
      expect(u16(b, 16)).toBe(l.length);
    }
  });

  it('builds 48-byte NTP packets whose timestamps give the stated offset', () => {
    const steps = lesson('ntp').steps;
    const ts = (b: Uint8Array, o: number) => new DataView(b.buffer, b.byteOffset).getUint32(o) + new DataView(b.buffer, b.byteOffset).getUint32(o + 4) / 2 ** 32;
    const ntp = (i: number) => {
      const p = steps[i].packet;
      const l = p.layers.find((x) => x.kind === 'ntp')!;
      expect(l.length).toBe(48);
      return p.bytes.subarray(l.offset, l.offset + 48);
    };
    const reply = ntp(1);
    const [T1, T2, T3] = [ts(reply, 24), ts(reply, 32), ts(reply, 40)];
    const T4 = T1 + 0.0241;
    expect(T1).toBeCloseTo(ts(ntp(0), 40), 6);
    expect(((T2 - T1) + (T3 - T4)) / 2).toBeCloseTo(-0.12, 4);
    expect((T4 - T1) - (T3 - T2)).toBeCloseTo(0.024, 4);
  });
});

describe('SMTP, IMAP and WireGuard', () => {
  const lesson = (id: string) => LESSONS.find((l) => l.id === id)!;
  const text = (p: Packet, kind: string) => {
    const l = p.layers.find((x) => x.kind === kind)!;
    return new TextDecoder('latin1').decode(p.bytes.subarray(l.offset, l.offset + l.length));
  };

  it('ends the SMTP message with CRLF.CRLF and every SMTP line with CRLF', () => {
    for (const s of lesson('smtp').steps) expect(text(s.packet, 'smtp').endsWith('\r\n')).toBe(true);
    const msg = lesson('smtp').steps.find((s) => s.packet.layers.some((l) => l.name === 'Email message'))!;
    expect(text(msg.packet, 'smtp')).toMatch(/\r\n\r\n[\s\S]*\r\n\.\r\n$/);
  });

  it('announces the exact IMAP literal length', () => {
    const t = lesson('imap').steps.map((s) => text(s.packet, 'imap')).find((x) => x.includes('FETCH ('))!;
    const m = t.match(/\{(\d+)\}\r\n/)!;
    const start = t.indexOf(m[0]) + m[0].length;
    expect(t.slice(start + Number(m[1]))).toBe(')\r\na3 OK FETCH completed\r\n');
  });

  it('uses the WireGuard message sizes from the protocol', () => {
    const sizes = lesson('wireguard').steps.map((s) => s.packet.layers.find((l) => l.kind === 'wg')!.length);
    expect(sizes[0]).toBe(148);
    expect(sizes[1]).toBe(92);
    expect((sizes[2] - 32) % 16).toBe(0);
    expect(sizes[4]).toBe(32);
  });

  it('writes WireGuard indexes little-endian and echoes the sender index', () => {
    const [init, resp] = lesson('wireguard').steps.map((s) => {
      const l = s.packet.layers.find((x) => x.kind === 'wg')!;
      return new DataView(s.packet.bytes.buffer, s.packet.bytes.byteOffset + l.offset);
    });
    expect(init.getUint32(4, true)).toBe(resp.getUint32(8, true));
    expect(init.getUint32(4, true)).toBe(0x8c1e5a73);
  });
});

describe('POP3, SMB and Wi-Fi', () => {
  const lesson = (id: string) => LESSONS.find((l) => l.id === id)!;
  const text = (p: Packet, kind: string) => {
    const l = p.layers.find((x) => x.kind === kind)!;
    return new TextDecoder('latin1').decode(p.bytes.subarray(l.offset, l.offset + l.length));
  };

  it('makes the POP3 octet count match the message it retrieves', () => {
    const t = lesson('pop3').steps.map((s) => text(s.packet, 'pop3')).find((x) => /^\+OK \d+ octets/.test(x))!;
    const n = Number(t.match(/^\+OK (\d+) octets\r\n/)![1]);
    const body = t.slice(t.indexOf('\r\n') + 2);
    expect(body.length - '.\r\n'.length).toBe(n);
  });

  it('frames SMB with a NetBIOS length and a 64-byte \\xFESMB header', () => {
    for (const s of lesson('smb').steps) {
      const l = s.packet.layers.find((x) => x.name === 'NetBIOS session service')!;
      const b = s.packet.bytes.subarray(l.offset, l.offset + l.length);
      expect((b[1] << 16) | (b[2] << 8) | b[3]).toBe(l.length - 4);
      expect(Array.from(b.subarray(4, 8))).toEqual([0xfe, 0x53, 0x4d, 0x42]);
      expect(b[8] | (b[9] << 8)).toBe(64);
    }
  });

  it('points SMB offsets at the right bytes', () => {
    const steps = lesson('smb').steps;
    const smb = (i: number) => {
      const l = steps[i].packet.layers.find((x) => x.kind === 'smb' && x.name.startsWith('SMB2'))!;
      return steps[i].packet.bytes.subarray(l.offset, l.offset + l.length);
    };
    const tc = smb(2);
    const off = tc[64 + 4] | (tc[64 + 5] << 8);
    const len = tc[64 + 6] | (tc[64 + 7] << 8);
    expect(new TextDecoder('utf-16le').decode(tc.subarray(off, off + len))).toBe('\\\\router\\docs');
    const neg = smb(0);
    expect(neg[64 + 28] | (neg[64 + 29] << 8)).toBe(112);
    expect(neg[112] | (neg[113] << 8)).toBe(1); // first negotiate context: pre-auth integrity
  });

  it('builds EAPOL-Key frames with consistent lengths and key info', () => {
    const frames = lesson('wifi').steps.filter((s) => s.packet.layers.some((l) => l.kind === 'eapol'));
    expect(frames).toHaveLength(4);
    const infos = frames.map((s) => {
      const l = s.packet.layers.find((x) => x.kind === 'eapol')!;
      const b = s.packet.bytes.subarray(l.offset, l.offset + l.length);
      expect(u16(b, 2)).toBe(l.length - 4);
      expect(u16(b, 97)).toBe(l.length - 99);
      return u16(b, 5);
    });
    expect(infos).toEqual([0x008a, 0x010a, 0x13ca, 0x030a]);
  });

  it('sets 802.11 frame control types and protected flag', () => {
    const fc = lesson('wifi').steps.map((s) => [s.packet.bytes[0], s.packet.bytes[1]]);
    expect(fc[0]).toEqual([0x80, 0x00]); // beacon
    expect(fc[1]).toEqual([0xb0, 0x00]); // authentication
    expect(fc[3]).toEqual([0x00, 0x00]); // association request
    expect(fc[9]).toEqual([0x08, 0x41]); // data, To DS + Protected
  });
});

describe('lesson groups', () => {
  it('puts every lesson in exactly one group', async () => {
    const { GROUPS } = await import('../src/groups');
    const ids = GROUPS.flatMap((g) => g.ids);
    expect(new Set(ids).size).toBe(ids.length);
    expect([...ids].sort()).toEqual(LESSONS.map((l) => l.id).sort());
  });
});
