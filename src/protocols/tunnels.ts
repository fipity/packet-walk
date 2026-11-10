// PPPoE (RFC 2516) with PPP LCP (RFC 1661), CHAP (RFC 1994) and IPCP (RFC 1332/1877);
// IKEv2 (RFC 7296) with NAT traversal (RFC 3948) and ESP (RFC 4303); Modbus/TCP.
import { Header, layer, randomBytes, asciiBytes, ip, hex16, hex8, shortHex, type Packet } from '../bytes';
import { md5, sha1, concatBytes } from '../crypto';

const hex32 = (v: number) => `0x${(v >>> 0).toString(16).padStart(8, '0')}`;

// ---------------------------------------------------------------- PPPoE discovery

const PPPOE_CODES: Record<number, string> = { 0x09: 'PADI', 0x07: 'PADO', 0x19: 'PADR', 0x65: 'PADS', 0x00: 'session data' };
const PPPOE_INFO: Record<number, string> = {
  0x09: 'PPPoE Active Discovery Initiation: "Is there an access concentrator out there?"',
  0x07: 'PPPoE Active Discovery Offer: "I can serve you."',
  0x19: 'PPPoE Active Discovery Request: "I choose you."',
  0x65: 'PPPoE Active Discovery Session-confirmation: "Here is your session ID."',
};

export interface PppoeTag {
  type: number;
  name: string;
  value: number[];
  display: string;
  info?: string;
}

function pppoeHeader(h: Header, code: number, session: number, length: number): void {
  h.u8('Version / type', 0x11, '1 / 1', 'Both always 1.');
  h.u8('Code', code, `0x${hex8(code)} (${PPPOE_CODES[code]})`, PPPOE_INFO[code] ?? 'Code 0 means this frame carries PPP session data.');
  h.u16('Session ID', session, session ? `0x${hex16(session)}` : '0 (no session yet)', session ? 'Assigned by the access concentrator in PADS. Together with the two MAC addresses, it identifies this PPP session.' : undefined);
  h.u16('Payload length', length, `${length} bytes`);
}

export function pppoeDiscovery(code: number, session: number, tags: PppoeTag[]): Packet {
  const len = tags.reduce((n, t) => n + 4 + t.value.length, 0);
  const h = new Header();
  pppoeHeader(h, code, session, len);
  for (const t of tags) h.bytes(`Tag: ${t.name}`, [t.type >>> 8, t.type & 255, t.value.length >>> 8, t.value.length & 255, ...t.value], t.display, t.info);
  return layer(`PPPoE discovery (${PPPOE_CODES[code]})`, 'pppoe', h);
}

// ---------------------------------------------------------------- PPP over PPPoE

const PPP_PROTOCOLS: Record<number, string> = { 0xc021: 'LCP', 0xc223: 'CHAP', 0x8021: 'IPCP', 0x0021: 'IPv4' };
const LCP_CODES: Record<number, string> = { 1: 'Configure-Request', 2: 'Configure-Ack', 3: 'Configure-Nak', 4: 'Configure-Reject' };

export interface PppOption {
  name: string;
  bytes: number[];
  value: string;
  info?: string;
}

/** A PPPoE session frame carrying one PPP packet. */
export function pppSession(session: number, protocol: number, inner: Packet): Packet {
  const ppp = new Header();
  ppp.u16('PPP protocol', protocol, `0x${hex16(protocol)} (${PPP_PROTOCOLS[protocol]})`, 'Says what the PPP frame carries: control protocols like LCP, CHAP and IPCP during setup, then 0x0021 for ordinary IPv4 packets.');
  const pppPkt = layer(`PPP (${PPP_PROTOCOLS[protocol]})`, 'ppp', ppp, inner);
  const h = new Header();
  pppoeHeader(h, 0x00, session, pppPkt.bytes.length);
  return layer('PPPoE session', 'pppoe', h, pppPkt);
}

/** LCP or IPCP control packet: code, identifier, length, options. */
export function pppControl(proto: 'LCP' | 'IPCP', code: number, id: number, options: PppOption[]): Packet {
  const len = 4 + options.reduce((n, o) => n + o.bytes.length, 0);
  const h = new Header();
  h.u8('Code', code, `${code} (${LCP_CODES[code]})`, code === 3 ? 'Configure-Nak: "Not those values. Use these instead." The peer tries again with the suggested values.' : code === 2 ? 'Configure-Ack: every option is accepted exactly as sent.' : 'Configure-Request lists the options this side wants for the link.');
  h.u8('Identifier', id, String(id), 'Matches replies to requests.');
  h.u16('Length', len, `${len} bytes`);
  for (const o of options) h.bytes(o.name, o.bytes, o.value, o.info);
  return layer(`${proto} ${LCP_CODES[code]}`, 'ppp', h);
}

export function chapChallenge(id: number, challenge: Uint8Array, name: string): Packet {
  const len = 4 + 1 + challenge.length + name.length;
  const h = new Header();
  h.u8('Code', 1, '1 (Challenge)');
  h.u8('Identifier', id, String(id), 'Mixed into the response hash, so an old response cannot be replayed against a new challenge.');
  h.u16('Length', len, `${len} bytes`);
  h.u8('Value size', challenge.length, `${challenge.length} bytes`);
  h.bytes('Challenge', challenge, undefined, 'Random bytes from the access concentrator. The password never crosses the wire. Instead, the router proves it knows the password by hashing it together with this challenge.');
  h.ascii('Name', name, name);
  return layer('CHAP Challenge', 'ppp', h);
}

/** CHAP-MD5 response: MD5(identifier || secret || challenge). */
export function chapResponse(id: number, secret: string, challenge: Uint8Array, name: string): Packet {
  const value = md5(concatBytes([id], asciiBytes(secret), challenge));
  const len = 4 + 1 + 16 + name.length;
  const h = new Header();
  h.u8('Code', 2, '2 (Response)');
  h.u8('Identifier', id, String(id));
  h.u16('Length', len, `${len} bytes`);
  h.u8('Value size', 16, '16 bytes');
  h.bytes('Response', value, undefined, 'MD5(identifier + password + challenge). This is the real hash for the demo password "dsl-password". The ISP computes the same hash and compares. CHAP-MD5 is weak by modern standards, since a captured exchange can be attacked offline, but it is still common on DSL and fibre lines.');
  h.ascii('Name', name, name, 'The account name the ISP gave you.');
  return layer('CHAP Response', 'ppp', h);
}

export function chapSuccess(id: number, message: string): Packet {
  const h = new Header();
  h.u8('Code', 3, '3 (Success)');
  h.u8('Identifier', id, String(id));
  h.u16('Length', 4 + message.length, `${4 + message.length} bytes`);
  h.ascii('Message', message, JSON.stringify(message));
  return layer('CHAP Success', 'ppp', h);
}

export const lcpMru = (mru: number): PppOption => ({ name: 'Option: Maximum Receive Unit', bytes: [1, 4, mru >>> 8, mru & 255], value: `${mru} bytes`, info: 'PPPoE adds 8 bytes (6 for PPPoE, 2 for PPP) inside the 1500-byte Ethernet payload, so the largest IP packet is 1492 bytes. This is why PPPoE connections are often configured with an MTU of 1492.' });
export const lcpMagic = (seed: number): PppOption => {
  const b = Array.from(randomBytes(seed, 4));
  return { name: 'Option: Magic-Number', bytes: [5, 6, ...b], value: shortHex(b), info: 'A random number. If a side ever receives its own magic number back, the link is looped back on itself.' };
};
export const lcpChap: PppOption = { name: 'Option: Authentication-Protocol', bytes: [3, 5, 0xc2, 0x23, 5], value: 'CHAP with MD5', info: 'The access concentrator insists that the router log in with CHAP (the alternative, PAP, would send the password in clear).' };
export const ipcpAddr = (code: number, name: string, a: string, info?: string): PppOption => ({ name: `Option: ${name}`, bytes: [code, 6, ...ip(a)], value: a, info });

// ---------------------------------------------------------------- IKEv2

export const IKE = { SA: 33, KE: 34, Ni: 40, N: 41, SK: 46 };
const PAYLOAD_NAMES: Record<number, string> = { 0: 'none', 33: 'SA', 34: 'KE', 35: 'IDi', 36: 'IDr', 40: 'Nonce', 41: 'Notify', 46: 'Encrypted (SK)' };

export function natHash(spiI: Uint8Array, spiR: Uint8Array, addr: string, port: number): Uint8Array {
  return sha1(concatBytes(spiI, spiR, ip(addr), [port >>> 8, port & 255]));
}

function ikeHeader(h: Header, o: { spiI: Uint8Array; spiR: Uint8Array; next: number; exchange: 34 | 35; response: boolean; msgId: number; length: number }): void {
  h.bytes('Initiator SPI', o.spiI, undefined, 'An 8-byte value the initiator picked to identify this IKE security association.');
  h.bytes('Responder SPI', o.spiR, o.spiR.every((b) => b === 0) ? '0 (not known yet)' : undefined, 'Picked by the responder in its first reply.');
  h.u8('Next payload', o.next, `${o.next} (${PAYLOAD_NAMES[o.next]})`, 'IKE messages are a chain of payloads. Each one names the type of the next.');
  h.u8('Version', 0x20, '2.0');
  h.u8('Exchange type', o.exchange, o.exchange === 34 ? '34 (IKE_SA_INIT)' : '35 (IKE_AUTH)');
  const flags = o.response ? 0x20 : 0x08;
  h.u8('Flags', flags, o.response ? 'response' : 'initiator', undefined);
  h.u32('Message ID', o.msgId, String(o.msgId), 'Counts exchanges. A request and its response share an ID, which protects against replays.');
  h.u32('Length', o.length, `${o.length} bytes`, 'The whole IKE message, header included.');
}

function genericHeader(h: Header, name: string, next: number, len: number): void {
  h.u8(`${name}: next payload`, next, `${next} (${PAYLOAD_NAMES[next]})`);
  h.u8(`${name}: critical / reserved`, 0, '0');
  h.u16(`${name}: length`, len, `${len} bytes`);
}

export function ikeSaInit(o: { spiI: Uint8Array; spiR: Uint8Array; response: boolean; seed: number; natSrc: Uint8Array; natDst: Uint8Array }): Packet {
  const total = 28 + 40 + 40 + 36 + 28 + 28;
  const h = new Header();
  ikeHeader(h, { spiI: o.spiI, spiR: o.spiR, next: IKE.SA, exchange: 34, response: o.response, msgId: 0, length: total });

  genericHeader(h, 'SA', IKE.KE, 40);
  h.u8('Proposal: last', 0, 'last proposal');
  h.u8('Proposal: reserved', 0, '0');
  h.u16('Proposal: length', 36, '36 bytes');
  h.u8('Proposal number', 1, '1');
  h.u8('Protocol ID', 1, '1 (IKE)');
  h.u8('SPI size', 0, '0');
  h.u8('Number of transforms', 3, '3');
  h.bytes('Transform: encryption', [3, 0, 0, 12, 1, 0, 0, 20, 0x80, 0x0e, 1, 0], 'ENCR_AES_GCM_16, 256-bit key', o.response ? 'The responder echoes back the one choice it accepted from each category.' : 'Each transform is one algorithm choice. AES-GCM is an AEAD cipher, so no separate integrity algorithm is needed.');
  h.bytes('Transform: PRF', [3, 0, 0, 8, 2, 0, 0, 5], 'PRF_HMAC_SHA2_256', 'Used to derive all the keys.');
  h.bytes('Transform: DH group', [0, 0, 0, 8, 4, 0, 0, 31], 'Curve25519 (group 31)');

  genericHeader(h, 'KE', IKE.Ni, 40);
  h.u16('DH group', 31, '31 (Curve25519)');
  h.u16('Reserved', 0, '0');
  h.bytes('Key exchange data', randomBytes(o.seed, 32), undefined, 'This side\'s Diffie–Hellman public key. Like TLS and WireGuard, IKEv2 agrees on keys without ever sending them. The bytes here are illustrative.');

  genericHeader(h, 'Nonce', IKE.N, 36);
  h.bytes('Nonce data', randomBytes(o.seed + 1, 32), undefined, 'Fresh random bytes that make each negotiation unique.');

  genericHeader(h, 'Notify', IKE.N, 28);
  h.u8('Notify: protocol ID', 0, '0');
  h.u8('Notify: SPI size', 0, '0');
  h.u16('Notify type', 16388, '16388 (NAT_DETECTION_SOURCE_IP)');
  h.bytes('NAT detection source hash', o.natSrc, shortHex(o.natSrc), 'SHA-1(SPIs + the sender\'s IP address + port), computed with the address the sender thinks it has. This is the real hash.');
  genericHeader(h, 'Notify', 0, 28);
  h.u8('Notify: protocol ID', 0, '0');
  h.u8('Notify: SPI size', 0, '0');
  h.u16('Notify type', 16389, '16389 (NAT_DETECTION_DESTINATION_IP)');
  h.bytes('NAT detection destination hash', o.natDst, shortHex(o.natDst), o.response
    ? 'SHA-1 of the address and port the responder actually saw the request come from: the router\'s public address after NAT. The laptop computes the same hash with its own private address, and the mismatch tells it there is a NAT in between.'
    : 'SHA-1 of the address the initiator is sending to.');
  return layer(`IKEv2 IKE_SA_INIT ${o.response ? 'response' : 'request'}`, 'ike', h);
}

export function ikeAuth(o: { spiI: Uint8Array; spiR: Uint8Array; response: boolean; plaintext: number; seed: number; hidden: string }): Packet {
  const skLen = 4 + 8 + o.plaintext + 16;
  const total = 28 + skLen;
  const h = new Header();
  h.u32('Non-ESP marker', 0, '0x00000000', 'After the switch to UDP port 4500, IKE messages start with four zero bytes so they can be told apart from ESP packets, which always start with a non-zero SPI.');
  ikeHeader(h, { spiI: o.spiI, spiR: o.spiR, next: IKE.SK, exchange: 35, response: o.response, msgId: 1, length: total });
  genericHeader(h, 'Encrypted', o.response ? 36 : 35, skLen);
  h.bytes('IV', randomBytes(o.seed, 8), undefined, 'The per-message part of the AES-GCM nonce.');
  h.bytes('Encrypted payloads', randomBytes(o.seed + 1, o.plaintext), undefined, `Encrypted with keys from the IKE_SA_INIT exchange. Hidden inside: ${o.hidden}.`);
  h.bytes('Integrity check value', randomBytes(o.seed + 2, 16), undefined, 'The 16-byte AES-GCM tag over the header and ciphertext.');
  return layer(`IKEv2 IKE_AUTH ${o.response ? 'response' : 'request'}`, 'ike', h);
}

export function esp(o: { spi: number; seq: number; inner: number; seed: number; hidden: string }): Packet {
  const pad = (4 - ((o.inner + 2) % 4)) % 4;
  const h = new Header();
  h.u32('SPI', o.spi, hex32(o.spi), 'Security Parameters Index: tells the receiver which IPsec SA (keys, algorithms, allowed traffic) applies. Each direction has its own SA, negotiated in IKE_AUTH.');
  h.u32('Sequence number', o.seq, String(o.seq), 'Increases with every packet, so replayed packets are rejected.');
  h.bytes('IV', randomBytes(o.seed, 8), undefined);
  h.bytes('Encrypted payload', randomBytes(o.seed + 1, o.inner + pad + 2), undefined, `In tunnel mode this is an entire inner IP packet, encrypted. Hidden inside: ${o.hidden}, ${pad} padding bytes, a pad-length byte, and Next Header = 4 (IPv4).`);
  h.bytes('Integrity check value', randomBytes(o.seed + 2, 16), undefined, 'The AES-GCM tag. Tampered packets are dropped.');
  return layer('ESP (UDP-encapsulated)', 'esp', h);
}

// ---------------------------------------------------------------- Modbus/TCP

const MODBUS_FN: Record<number, string> = {
  1: 'Read Coils', 3: 'Read Holding Registers', 5: 'Write Single Coil', 6: 'Write Single Register',
  0x83: 'Read Holding Registers (exception)',
};

export interface ModbusField {
  name: string;
  bytes: number[];
  value: string;
  info?: string;
}

export function modbus(o: { tid: number; unit: number; fn: number; data: ModbusField[]; response: boolean }): Packet {
  const pduLen = 1 + o.data.reduce((n, f) => n + f.bytes.length, 0);
  const h = new Header();
  h.u16('Transaction ID', o.tid, String(o.tid), 'Chosen by the client and echoed by the server, so responses can be matched to requests.');
  h.u16('Protocol ID', 0, '0 (Modbus)');
  h.u16('Length', pduLen + 1, `${pduLen + 1} bytes`, 'Number of bytes that follow: the unit ID plus the PDU.');
  h.u8('Unit ID', o.unit, String(o.unit), 'Which device to talk to. It matters when a gateway bridges Modbus/TCP to devices on an older serial line (RS-485).');
  h.u8('Function code', o.fn, `${o.fn} (${MODBUS_FN[o.fn]})`, o.fn & 0x80 ? 'The top bit is set: this is an exception response. Function 0x83 = 0x03 + 0x80.' : 'What to do. Modbus has a small fixed set of functions for reading and writing bits ("coils") and 16-bit "registers".');
  for (const f of o.data) h.bytes(f.name, f.bytes, f.value, f.info);
  return layer(`Modbus ${MODBUS_FN[o.fn]} ${o.response ? 'response' : 'request'}`, 'modbus', h);
}

export const u16f = (name: string, v: number, value = String(v), info?: string): ModbusField => ({ name, bytes: [v >>> 8, v & 255], value, info });
