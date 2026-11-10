// Core data model: a packet is a byte array plus a description of every byte in it.
//
// Each protocol builder writes its header with a `Header`, then wraps the payload
// with `layer()`. Offsets of inner fields are shifted automatically, so the final
// packet knows exactly which bytes belong to which field of which layer.

/** Plain English text, or one string per locale code (`{ en: '…', es: '…' }`). */
export type Text = string | Record<string, string>;

export type LayerKind =
  | 'eth' | 'arp' | 'dhcp' | 'ip' | 'icmp' | 'udp' | 'tcp' | 'dns' | 'http' | 'tls' | 'ws' | 'quic' | 'ssh' | 'ftp' | 'bgp' | 'ntp' | 'smtp' | 'imap' | 'wg' | 'pop3' | 'smb' | 'wifi' | 'eapol';

export interface Field {
  /** Index into `Packet.layers`. */
  layer: number;
  name: string;
  offset: number;
  length: number;
  /** Decoded, human-readable value. */
  value: string;
  /** Optional explanation shown when the field is selected. */
  info?: string;
}

export interface Layer {
  name: string;
  kind: LayerKind;
  offset: number;
  length: number;
  /** Nesting depth: 0 for the outermost layer. */
  depth: number;
}

export interface Packet {
  bytes: Uint8Array;
  layers: Layer[];
  fields: Field[];
}

type LocalField = Omit<Field, 'layer'>;

export class Header {
  private buf: number[] = [];
  readonly fields: LocalField[] = [];

  get length(): number {
    return this.buf.length;
  }

  private add(name: string, start: number, value: string, info?: string): number {
    this.fields.push({ name, offset: start, length: this.buf.length - start, value, info });
    return start;
  }

  u8(name: string, v: number, value = String(v), info?: string): number {
    const s = this.buf.length;
    this.buf.push(v & 0xff);
    return this.add(name, s, value, info);
  }

  u16(name: string, v: number, value = String(v), info?: string): number {
    const s = this.buf.length;
    this.buf.push((v >>> 8) & 0xff, v & 0xff);
    return this.add(name, s, value, info);
  }

  u24(name: string, v: number, value = String(v), info?: string): number {
    const s = this.buf.length;
    this.buf.push((v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
    return this.add(name, s, value, info);
  }

  u32(name: string, v: number, value = String(v >>> 0), info?: string): number {
    const s = this.buf.length;
    this.buf.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
    return this.add(name, s, value, info);
  }

  bytes(name: string, data: ArrayLike<number>, value = shortHex(data), info?: string): number {
    const s = this.buf.length;
    for (let i = 0; i < data.length; i++) this.buf.push(data[i] & 0xff);
    return this.add(name, s, value, info);
  }

  ascii(name: string, text: string, value = JSON.stringify(text), info?: string): number {
    return this.bytes(name, asciiBytes(text), value, info);
  }

  build(): Uint8Array {
    return Uint8Array.from(this.buf);
  }
}

/** Wrap `payload` (and an optional trailer) in a new outer layer. */
export function layer(
  name: string,
  kind: LayerKind,
  header: Header,
  payload?: Packet,
  trailer?: Header,
): Packet {
  const h = header.build();
  const p = payload?.bytes ?? new Uint8Array(0);
  const t = trailer?.build() ?? new Uint8Array(0);
  const bytes = new Uint8Array(h.length + p.length + t.length);
  bytes.set(h, 0);
  bytes.set(p, h.length);
  bytes.set(t, h.length + p.length);

  const layers: Layer[] = [{ name, kind, offset: 0, length: bytes.length, depth: 0 }];
  const fields: Field[] = header.fields.map((f) => ({ ...f, layer: 0 }));
  if (payload) {
    for (const l of payload.layers) layers.push({ ...l, offset: l.offset + h.length, depth: l.depth + 1 });
    for (const f of payload.fields) fields.push({ ...f, offset: f.offset + h.length, layer: f.layer + 1 });
  }
  if (trailer) {
    for (const f of trailer.fields) fields.push({ ...f, offset: f.offset + h.length + p.length, layer: 0 });
  }
  return { bytes, layers, fields };
}

/** Place several packets back to back as siblings (e.g. two TLS records in one TCP segment). */
export function concat(...pkts: Packet[]): Packet {
  const total = pkts.reduce((n, p) => n + p.bytes.length, 0);
  const bytes = new Uint8Array(total);
  const layers: Layer[] = [];
  const fields: Field[] = [];
  let off = 0;
  for (const p of pkts) {
    bytes.set(p.bytes, off);
    const base = layers.length;
    for (const l of p.layers) layers.push({ ...l, offset: l.offset + off });
    for (const f of p.fields) fields.push({ ...f, offset: f.offset + off, layer: f.layer + base });
    off += p.bytes.length;
  }
  return { bytes, layers, fields };
}

/** Keep only the first `n` bytes of a packet, clipping layers and fields. */
export function truncate(pkt: Packet, n: number): Packet {
  const keep = pkt.layers.map((l) => l.offset < n);
  const remap: number[] = [];
  const layers: Layer[] = [];
  pkt.layers.forEach((l, i) => {
    if (keep[i]) {
      remap[i] = layers.length;
      layers.push({ ...l, length: Math.min(l.length, n - l.offset) });
    }
  });
  const fields = pkt.fields
    .filter((f) => f.offset < n)
    .map((f) => ({ ...f, layer: remap[f.layer], length: Math.min(f.length, n - f.offset) }));
  return { bytes: pkt.bytes.slice(0, n), layers, fields };
}

/** Overwrite a 16-bit value in a finished packet (used for checksums) and update its field. */
export function patch16(pkt: Packet, offset: number, v: number, value = '0x' + hex16(v)): void {
  pkt.bytes[offset] = (v >>> 8) & 0xff;
  pkt.bytes[offset + 1] = v & 0xff;
  const f = pkt.fields.find((x) => x.offset === offset && x.layer === 0);
  if (f) f.value = value;
}

/** RFC 1071 Internet checksum: ones' complement of the ones' complement sum of 16-bit words. */
export function checksum(data: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i < data.length; i += 2) {
    sum += (data[i] << 8) | (i + 1 < data.length ? data[i + 1] : 0);
  }
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

export function ip(s: string): number[] {
  return s.split('.').map(Number);
}

export function mac(s: string): number[] {
  return s.split(':').map((x) => parseInt(x, 16));
}

export function asciiBytes(s: string): number[] {
  return Array.from(s, (c) => c.charCodeAt(0) & 0xff);
}

export function hex8(v: number): string {
  return v.toString(16).padStart(2, '0');
}

export function hex16(v: number): string {
  return v.toString(16).padStart(4, '0');
}

export function shortHex(data: ArrayLike<number>, max = 8): string {
  const parts: string[] = [];
  for (let i = 0; i < Math.min(data.length, max); i++) parts.push(hex8(data[i]));
  return data.length > max ? `${parts.join(' ')} … (${data.length} bytes)` : parts.join(' ');
}

/** Small deterministic PRNG (mulberry32) so "random" bytes are identical on every load. */
export function randomBytes(seed: number, n: number): Uint8Array {
  let a = seed >>> 0;
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    out[i] = ((t ^ (t >>> 14)) >>> 0) & 0xff;
  }
  return out;
}
