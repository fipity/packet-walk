// QUIC version 1 (RFC 9000) with TLS 1.3 (RFC 9001). Payloads are encrypted, so their
// contents are shown as deterministic pseudo-random bytes of the correct length.
import { Header, layer, concat, randomBytes, hex8, type Packet } from '../bytes';

/** QUIC variable-length integer (RFC 9000 §16), using the 2-byte form. */
function varint2(v: number): number[] {
  return [0x40 | (v >>> 8), v & 0xff];
}

const PN_LEN = 1;

function payload(h: Header, ciphertext: number, seed: number, hidden: string): void {
  h.bytes('Encrypted payload', randomBytes(seed, ciphertext - 16), undefined, `QUIC frames, encrypted. Hidden inside: ${hidden}.`);
  h.bytes('Authentication tag', randomBytes(seed + 7, 16), undefined, 'A 16-byte AEAD tag. Any change to the packet, including its header, makes decryption fail.');
}

export interface LongOpts {
  type: 'Initial' | 'Handshake';
  dcid: Uint8Array;
  scid: Uint8Array;
  /** Bytes of ciphertext, including the 16-byte tag. */
  ciphertext: number;
  seed: number;
  hidden: string;
}

export const LONG_HEADER_OVERHEAD = (o: { initial: boolean; cidLen: number }) =>
  1 + 4 + 1 + o.cidLen + 1 + o.cidLen + (o.initial ? 1 : 0) + 2 + PN_LEN;

export function quicLong(o: LongOpts): Packet {
  const typeBits = o.type === 'Initial' ? 0 : 2;
  const mask = randomBytes(o.seed + 3, 2);
  const first = (0xc0 | (typeBits << 4) | (PN_LEN - 1)) ^ (mask[0] & 0x0f);
  const h = new Header();
  h.u8(
    'Header byte',
    first,
    `0x${hex8(first)} (long header, ${o.type})`,
    `The top bit (1) means long header, and the next bit is always 1. The next two bits give the packet type (${typeBits} = ${o.type}). ` +
      'The low 4 bits, which include the packet-number length, are scrambled by header protection, so observers cannot read them.',
  );
  h.u32('Version', 1, '1 (QUIC v1)', 'Lets the protocol evolve: a server that does not speak this version answers with a Version Negotiation packet.');
  h.u8('Destination connection ID length', o.dcid.length, `${o.dcid.length} bytes`);
  h.bytes('Destination connection ID', o.dcid, undefined, 'QUIC connections are identified by these IDs, not by IP address and port. That is why a phone can switch from Wi-Fi to mobile data without dropping the connection.');
  h.u8('Source connection ID length', o.scid.length, `${o.scid.length} bytes`);
  h.bytes('Source connection ID', o.scid, undefined, 'The ID the sender wants the other side to use when replying.');
  if (o.type === 'Initial') h.u8('Token length', 0, '0 (no token)', 'A server can ask the client to retry with a token, which proves the client really owns its IP address.');
  const len = PN_LEN + o.ciphertext;
  h.bytes('Length', varint2(len), `${len} bytes`, 'Length of the rest of this packet, as a variable-length integer: the top two bits (01) mean "2 bytes". It lets several QUIC packets share one UDP datagram.');
  h.u8('Packet number (protected)', mask[1], 'hidden', 'Every packet gets a new number, never reused, even for retransmissions. That makes loss detection unambiguous. It is hidden by header protection.');
  payload(h, o.ciphertext, o.seed, o.hidden);
  return layer(`QUIC ${o.type} packet`, 'quic', h);
}

export function quicShort(o: { dcid: Uint8Array; ciphertext: number; seed: number; hidden: string }): Packet {
  const mask = randomBytes(o.seed + 3, 2);
  const first = (0x40 | (PN_LEN - 1)) ^ (mask[0] & 0x1f);
  const h = new Header();
  h.u8('Header byte', first, `0x${hex8(first)} (short header)`, 'The top bit (0) means short header, which is used for all application data once the handshake is done. The low 5 bits (key phase and packet-number length) are protected.');
  h.bytes('Destination connection ID', o.dcid, undefined, 'Short headers carry no lengths and no source ID. Each side already knows the other\'s connection ID length, so headers stay as small as possible.');
  h.u8('Packet number (protected)', mask[1], 'hidden');
  payload(h, o.ciphertext, o.seed, o.hidden);
  return layer('QUIC 1-RTT packet', 'quic', h);
}

export function datagram(...pkts: Packet[]): Packet {
  return concat(...pkts);
}
