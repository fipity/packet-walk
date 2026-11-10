// Line-based mail protocols, SMTP (RFC 5321) and IMAP (RFC 9051), plus WireGuard (whitepaper / wireguard.com/protocol).
import { Header, layer, randomBytes, type LayerKind, type Packet } from '../bytes';

export interface Line {
  name: string;
  text: string;
  info?: string;
  value?: string;
  /** Don't append CRLF (for IMAP literals, which are counted bytes rather than lines). */
  raw?: boolean;
}

/** A text protocol message made of CRLF-terminated lines, one field per line. */
export function lines(label: string, kind: LayerKind, ls: Line[]): Packet {
  const h = new Header();
  for (const l of ls) {
    const text = l.raw ? l.text : l.text + '\r\n';
    const value = l.value ?? (l.text.length > 70 ? `${text.length} bytes of text` : l.text);
    h.ascii(l.name, text, value, l.info);
  }
  return layer(label, kind, h);
}

// ---------------------------------------------------------------- WireGuard

function le32(v: number): number[] {
  return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, v >>> 24];
}

function le64(v: number): number[] {
  return [...le32(v >>> 0), ...le32(Math.floor(v / 2 ** 32))];
}

const hexIndex = (v: number) => `0x${(v >>> 0).toString(16).padStart(8, '0')}`;

function wgHeader(h: Header, type: number, name: string): void {
  h.u8('Message type', type, `${type} (${name})`, 'WireGuard has just four message types: handshake initiation, handshake response, cookie reply and transport data.');
  h.bytes('Reserved', [0, 0, 0], '0', 'Always zero. Together with the type byte, this makes a 4-byte header that keeps the following fields aligned.');
}

export function wgInitiation(o: { sender: number; seed: number }): Packet {
  const h = new Header();
  wgHeader(h, 1, 'handshake initiation');
  h.bytes('Sender index', le32(o.sender), hexIndex(o.sender), 'A random number that identifies this session on the sender\'s side. The other peer will put it in every packet it sends back. Note that WireGuard integers are little-endian, unlike most network protocols.');
  h.bytes('Unencrypted ephemeral', randomBytes(o.seed, 32), undefined, 'A fresh Curve25519 public key for this handshake only. Throwing it away afterwards gives forward secrecy.');
  h.bytes('Encrypted static', randomBytes(o.seed + 1, 48), undefined, 'The initiator\'s long-term public key (32 bytes + 16-byte tag), encrypted so that observers cannot tell who is connecting. Only the server, using its private key, can decrypt it and look the key up in its list of allowed peers.');
  h.bytes('Encrypted timestamp', randomBytes(o.seed + 2, 28), undefined, 'A 12-byte TAI64N timestamp plus a 16-byte tag. The server rejects any timestamp not newer than the last one it saw from this peer, so a recorded handshake cannot be replayed.');
  h.bytes('MAC1', randomBytes(o.seed + 3, 16), undefined, 'A keyed hash using the server\'s public key. Packets from anyone who does not already know that key are dropped silently, so a WireGuard port looks closed to scanners.');
  h.bytes('MAC2', new Array(16).fill(0), '0 (no cookie)', 'Only used when the server is under load and has sent a cookie. Then the client must prove it can receive packets at its address before the server does any expensive work.');
  return layer('WireGuard handshake initiation', 'wg', h);
}

export function wgResponse(o: { sender: number; receiver: number; seed: number }): Packet {
  const h = new Header();
  wgHeader(h, 2, 'handshake response');
  h.bytes('Sender index', le32(o.sender), hexIndex(o.sender), 'The responder\'s own session ID.');
  h.bytes('Receiver index', le32(o.receiver), hexIndex(o.receiver), 'The initiator\'s sender index, copied back so it can match this response to its request.');
  h.bytes('Unencrypted ephemeral', randomBytes(o.seed, 32), undefined, 'The responder\'s one-time public key. Both sides now mix four Diffie–Hellman results (static and ephemeral keys on each side) into a pair of session keys, one per direction.');
  h.bytes('Encrypted nothing', randomBytes(o.seed + 1, 16), undefined, 'An empty message, so only a 16-byte authentication tag. It proves the responder derived the same keys.');
  h.bytes('MAC1', randomBytes(o.seed + 3, 16), undefined);
  h.bytes('MAC2', new Array(16).fill(0), '0 (no cookie)');
  return layer('WireGuard handshake response', 'wg', h);
}

export function wgData(o: { receiver: number; counter: number; plaintext: number; seed: number; hidden: string }): Packet {
  const h = new Header();
  wgHeader(h, 4, 'transport data');
  h.bytes('Receiver index', le32(o.receiver), hexIndex(o.receiver), 'Tells the receiver which session (and so which keys) to use. There are no IP addresses or ports in the decision, which lets a client roam between networks without reconnecting.');
  h.bytes('Counter', le64(o.counter), String(o.counter), 'A 64-bit nonce that goes up by one with every packet. The receiver keeps a sliding window of recent counters and drops replays.');
  const padded = Math.ceil(o.plaintext / 16) * 16;
  if (padded > 0) {
    h.bytes('Encrypted packet', randomBytes(o.seed, padded), undefined, `ChaCha20 ciphertext. Hidden inside: ${o.hidden}. It is padded to a multiple of 16 bytes (${o.plaintext} → ${padded}) to blur its exact size.`);
  }
  h.bytes('Poly1305 tag', randomBytes(o.seed + 1, 16), undefined, padded === 0 ? 'With nothing to encrypt, a keepalive is just the header and this tag: 32 bytes in total.' : 'Authenticates the ciphertext and header. Forged or corrupted packets are dropped.');
  return layer(padded === 0 ? 'WireGuard keepalive' : 'WireGuard transport data', 'wg', h);
}
