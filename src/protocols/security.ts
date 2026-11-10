// RADIUS (RFC 2865/2866/3579), DNSSEC records (RFC 4034/4035, RFC 6891 EDNS0),
// the Ethernet physical frame (IEEE 802.3 preamble, SFD and FCS), and the PostgreSQL startup message.
import { Header, layer, randomBytes, asciiBytes, ip, hex16, shortHex, type Packet } from '../bytes';
import { md5, hmacMd5, sha256, crc32, concatBytes } from '../crypto';

// ---------------------------------------------------------------- RADIUS

const RADIUS_CODES: Record<number, string> = { 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 4: 'Accounting-Request', 5: 'Accounting-Response' };

export interface RadiusAttr {
  type: number;
  name: string;
  data: number[];
  value: string;
  info?: string;
}

export const rText = (type: number, name: string, s: string, info?: string): RadiusAttr => ({ type, name, data: asciiBytes(s), value: JSON.stringify(s), info });
export const rInt = (type: number, name: string, v: number, value: string, info?: string): RadiusAttr => ({ type, name, data: [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255], value, info });
export const rAddr = (type: number, name: string, a: string, info?: string): RadiusAttr => ({ type, name, data: ip(a), value: a, info });

/** RFC 2865 §5.2: hide a password by XOR-ing 16-byte blocks with MD5(secret + previous block). */
export function hidePassword(password: string, secret: string, requestAuth: ArrayLike<number>): number[] {
  const p = asciiBytes(password);
  const padded = [...p, ...new Array((16 - (p.length % 16)) % 16 || (p.length ? 0 : 16)).fill(0)];
  const out: number[] = [];
  let prev: ArrayLike<number> = requestAuth;
  for (let i = 0; i < padded.length; i += 16) {
    const b = md5(concatBytes(asciiBytes(secret), prev));
    const c = padded.slice(i, i + 16).map((x, j) => x ^ b[j]);
    out.push(...c);
    prev = c;
  }
  return out;
}

export function radius(o: {
  code: 1 | 2 | 3 | 4 | 5;
  id: number;
  attrs: RadiusAttr[];
  secret: string;
  /** Random authenticator for Access-Request; the request's authenticator for replies. */
  requestAuth: Uint8Array;
  messageAuthenticator?: boolean;
}): Packet {
  const attrs = [...o.attrs];
  if (o.messageAuthenticator) attrs.push({ type: 80, name: 'Message-Authenticator', data: new Array(16).fill(0), value: '' });
  const attrBytes = () => attrs.flatMap((a) => [a.type, a.data.length + 2, ...a.data]);
  const len = 20 + attrBytes().length;
  const head = [o.code, o.id, len >>> 8, len & 255];
  const secret = asciiBytes(o.secret);
  const isResponse = o.code === 2 || o.code === 3 || o.code === 5;

  // Message-Authenticator: HMAC-MD5 over the packet with this attribute zeroed and the request authenticator in place.
  if (o.messageAuthenticator) {
    const ma = attrs[attrs.length - 1];
    const mac = hmacMd5(secret, concatBytes(head, o.requestAuth, attrBytes()));
    ma.data = Array.from(mac);
    ma.value = shortHex(mac);
    ma.info = 'HMAC-MD5 of the whole packet, keyed with the shared secret. It proves the packet came from someone who knows the secret and was not modified (RFC 3579). Recent attacks on plain RADIUS (such as Blast-RADIUS in 2024) are why servers now insist on it.';
  }

  let auth: Uint8Array;
  let authInfo: string;
  if (o.code === 1) {
    auth = o.requestAuth;
    authInfo = 'A random 16-byte Request Authenticator. It is the salt for hiding the password, and the server mixes it into its reply so that replies cannot be replayed.';
  } else if (o.code === 4) {
    auth = md5(concatBytes(head, new Array(16).fill(0), attrBytes(), secret));
    authInfo = 'For accounting, the request authenticator is MD5(code + ID + length + 16 zero bytes + attributes + shared secret).';
  } else {
    auth = md5(concatBytes(head, o.requestAuth, attrBytes(), secret));
    authInfo = 'Response Authenticator = MD5(code + ID + length + the request\'s authenticator + attributes + shared secret). The NAS recomputes it to check that the reply really came from its RADIUS server and answers this exact request.';
  }

  const h = new Header();
  h.u8('Code', o.code, `${o.code} (${RADIUS_CODES[o.code]})`, isResponse ? undefined : 'RADIUS has a handful of message types: Access-Request/Accept/Reject/Challenge for logins, Accounting-Request/Response for usage records.');
  h.u8('Identifier', o.id, String(o.id), 'Matches replies to requests. A retry of the same request keeps the same ID; a new request uses a new one.');
  h.u16('Length', len, `${len} bytes`);
  h.bytes('Authenticator', auth, undefined, authInfo);
  for (const a of attrs) {
    h.bytes(`Attribute ${a.type}: ${a.name}`, [a.type, a.data.length + 2, ...a.data], a.value, a.info ?? 'Attributes are type–length–value, with the length covering the 2-byte header.');
  }
  return layer(`RADIUS ${RADIUS_CODES[o.code]}`, 'radius', h);
}

// ---------------------------------------------------------------- DNSSEC

export const ALG_ED25519 = 15;

export function nameWire(name: string): number[] {
  const out: number[] = [];
  for (const label of name.split('.').filter(Boolean)) out.push(label.length, ...asciiBytes(label.toLowerCase()));
  out.push(0);
  return out;
}

export function dnskeyRdata(flags: number, pub: ArrayLike<number>): number[] {
  return [flags >>> 8, flags & 255, 3, ALG_ED25519, ...Array.from(pub)];
}

/** RFC 4034 Appendix B key tag. */
export function keyTag(rdata: number[]): number {
  let ac = 0;
  rdata.forEach((b, i) => (ac += i & 1 ? b : b << 8));
  ac += (ac >>> 16) & 0xffff;
  return ac & 0xffff;
}

/** DS digest (type 2, SHA-256) = SHA-256(owner name in wire form | DNSKEY RDATA). */
export function dsDigest(owner: string, rdata: number[]): Uint8Array {
  return sha256(concatBytes(nameWire(owner), rdata));
}

export interface DnsField {
  name: string;
  bytes: ArrayLike<number>;
  value: string;
  info?: string;
}

export interface RR {
  owner: string;
  type: number;
  ttl: number;
  rdata: DnsField[];
}

const TYPES: Record<number, string> = { 1: 'A', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 48: 'DNSKEY' };
const u16b = (v: number) => [v >>> 8, v & 255];
const u32b = (v: number) => [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];

export const rrA = (owner: string, ttl: number, addr: string): RR => ({
  owner, type: 1, ttl, rdata: [{ name: 'Address', bytes: ip(addr), value: addr }],
});

export function rrDnskey(owner: string, ttl: number, flags: number, pub: ArrayLike<number>): RR {
  const ksk = flags === 257;
  const tag = keyTag(dnskeyRdata(flags, pub));
  return {
    owner, type: 48, ttl,
    rdata: [
      { name: 'Flags', bytes: u16b(flags), value: `${flags} (${ksk ? 'KSK: zone key + secure entry point' : 'ZSK: zone key'})`, info: ksk ? 'The key-signing key. It only signs the DNSKEY set, and its hash is what the parent zone publishes in a DS record. That link ties this zone into the chain of trust.' : 'The zone-signing key, which signs every other record set in the zone. Keeping it separate from the KSK means it can be rotated often without involving the parent zone.' },
      { name: 'Protocol', bytes: [3], value: '3', info: 'Always 3.' },
      { name: 'Algorithm', bytes: [ALG_ED25519], value: '15 (Ed25519)' },
      { name: 'Public key', bytes: pub, value: shortHex(pub), info: `The Ed25519 public key (key tag ${tag}). The bytes here are illustrative.` },
    ],
  };
}

export function rrRrsig(o: { owner: string; ttl: number; covered: number; labels: number; keyTag: number; signer: string; seed: number }): RR {
  const exp = Date.UTC(2026, 11, 1) / 1000;
  const inc = Date.UTC(2026, 10, 1) / 1000;
  return {
    owner: o.owner, type: 46, ttl: o.ttl,
    rdata: [
      { name: 'Type covered', bytes: u16b(o.covered), value: `${o.covered} (${TYPES[o.covered]})`, info: 'Which record set this signature covers. DNSSEC signs whole record sets (all records with the same name and type), not single records.' },
      { name: 'Algorithm', bytes: [ALG_ED25519], value: '15 (Ed25519)' },
      { name: 'Labels', bytes: [o.labels], value: String(o.labels), info: 'How many labels the signed name has. It lets validators handle wildcard answers.' },
      { name: 'Original TTL', bytes: u32b(o.ttl), value: `${o.ttl} seconds`, info: 'The TTL that was signed, since caches count TTLs down.' },
      { name: 'Signature expiration', bytes: u32b(exp), value: '2026-12-01 00:00:00 UTC', info: 'Signatures have a validity window. Old signatures cannot be replayed forever, so zones must be re-signed regularly.' },
      { name: 'Signature inception', bytes: u32b(inc), value: '2026-11-01 00:00:00 UTC' },
      { name: 'Key tag', bytes: u16b(o.keyTag), value: String(o.keyTag), info: 'A 16-bit checksum of the DNSKEY that made this signature, so the validator knows which key to try.' },
      { name: 'Signer\'s name', bytes: nameWire(o.signer), value: o.signer + '.', info: 'The zone that signed it. Never compressed.' },
      { name: 'Signature', bytes: randomBytes(o.seed, 64), value: '64 bytes (Ed25519)', info: 'An Ed25519 signature over the RRSIG fields and the canonical form of the record set. The bytes here are illustrative.' },
    ],
  };
}

export function rrDs(owner: string, ttl: number, tag: number, digest: Uint8Array): RR {
  return {
    owner, type: 43, ttl,
    rdata: [
      { name: 'Key tag', bytes: u16b(tag), value: String(tag), info: 'Points at the child zone\'s KSK.' },
      { name: 'Algorithm', bytes: [ALG_ED25519], value: '15 (Ed25519)' },
      { name: 'Digest type', bytes: [2], value: '2 (SHA-256)' },
      { name: 'Digest', bytes: digest, value: shortHex(digest), info: 'SHA-256 of the child\'s owner name plus its KSK. This one is really computed from the DNSKEY in the previous step: if example.com\'s key were swapped, the hash would not match.' },
    ],
  };
}

export function dnsMessage(o: {
  id: number;
  flags: number;
  flagsText: string;
  flagsInfo: string;
  qname: string;
  qtype: number;
  answers: RR[];
  label: string;
  udpSize?: number;
}): Packet {
  const h = new Header();
  h.u16('Transaction ID', o.id, `0x${hex16(o.id)}`);
  h.u16('Flags', o.flags, `0x${hex16(o.flags)} (${o.flagsText})`, o.flagsInfo);
  h.u16('Questions', 1, '1');
  h.u16('Answer records', o.answers.length, String(o.answers.length));
  h.u16('Authority records', 0, '0');
  h.u16('Additional records', 1, '1 (OPT)');
  h.bytes('Query name', nameWire(o.qname), o.qname);
  h.u16('Query type', o.qtype, `${o.qtype} (${TYPES[o.qtype]})`);
  h.u16('Query class', 1, '1 (IN)');
  for (const rr of o.answers) {
    const tn = TYPES[rr.type];
    if (rr.owner === o.qname) h.u16(`${tn}: name`, 0xc00c, `pointer to ${rr.owner}`);
    else h.bytes(`${tn}: name`, nameWire(rr.owner), rr.owner);
    h.u16(`${tn}: type`, rr.type, `${rr.type} (${tn})`);
    h.u16(`${tn}: class`, 1, '1 (IN)');
    h.u32(`${tn}: TTL`, rr.ttl, `${rr.ttl} seconds`);
    const rlen = rr.rdata.reduce((n, f) => n + f.bytes.length, 0);
    h.u16(`${tn}: data length`, rlen, `${rlen} bytes`);
    for (const f of rr.rdata) h.bytes(`${tn}: ${f.name}`, f.bytes, f.value, f.info);
  }
  const size = o.udpSize ?? 1232;
  h.u8('OPT: name', 0, '<root>', 'EDNS(0) adds a pseudo-record called OPT to extend the old DNS header.');
  h.u16('OPT: type', 41, '41 (OPT)');
  h.u16('OPT: UDP payload size', size, `${size} bytes`, 'The class field is reused to say how big a UDP response this side can accept. DNSSEC answers are large, and 1232 bytes avoids IP fragmentation on almost every path.');
  h.u32('OPT: extended RCODE / version / flags', 0x00008000, 'version 0, DO=1', 'The DO ("DNSSEC OK") bit asks for RRSIG and other DNSSEC records to be included.');
  h.u16('OPT: data length', 0, '0');
  return layer(o.label, 'dns', h);
}

// ---------------------------------------------------------------- Physical layer (Ethernet on the wire)

/** Wrap a complete Ethernet frame with the preamble, SFD and FCS the network card adds on the wire. */
export function onTheWire(sent: Packet, fcsOver: Packet = sent): Packet {
  const pre = new Header();
  pre.bytes('Preamble', new Array(7).fill(0x55), '55 × 7 (alternating 1s and 0s)', 'Seven bytes of 10101010 that let the receiver lock on to the sender\'s clock before any data arrives. Capture tools never show it, because the network card strips it in hardware.');
  pre.u8('Start frame delimiter', 0xd5, '0xd5 (10101011)', 'The pattern breaks with two 1s in a row: "the frame starts right after this". Bytes are sent least-significant bit first, which is why 0x55 reads 1010… on the wire.');
  const fcs = crc32(fcsOver.bytes);
  const t = new Header();
  t.bytes('Frame check sequence', [fcs & 255, (fcs >>> 8) & 255, (fcs >>> 16) & 255, fcs >>> 24], `0x${fcs.toString(16).padStart(8, '0')} (CRC-32)`, sent === fcsOver
    ? 'A CRC-32 of the whole frame, from destination MAC to the end of the padding, computed by the sender. The receiver computes it again, and if the two differ the frame is silently thrown away. This one is the real CRC of this frame.'
    : 'The CRC the sender computed before the bit flipped on the cable. The receiver\'s CRC of the damaged frame no longer matches, so the frame is dropped.');
  return layer('Ethernet physical frame', 'phy', pre, sent, t);
}

// ---------------------------------------------------------------- PostgreSQL (for the SSH tunnel lesson)

export function pgStartup(params: [string, string][]): Packet {
  const body = params.flatMap(([k, v]) => [...asciiBytes(k), 0, ...asciiBytes(v), 0]);
  const len = 4 + 4 + body.length + 1;
  const h = new Header();
  h.u32('Length', len, `${len} bytes`, 'PostgreSQL messages start with their length. The very first message has no type byte.');
  h.u32('Protocol version', 196608, '3.0 (0x00030000)');
  for (const [k, v] of params) h.bytes(`Parameter: ${k}`, [...asciiBytes(k), 0, ...asciiBytes(v), 0], v, k === 'user' ? 'Readable here: inside the private network the database traffic is not protected by the SSH tunnel, only by whatever the database itself uses (here, nothing).' : undefined);
  h.u8('Terminator', 0, '0');
  return layer('PostgreSQL StartupMessage', 'pg', h);
}
