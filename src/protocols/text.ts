// WebSocket framing (RFC 6455), SSH transport (RFC 4253) and FTP (RFC 959).
import { Header, layer, randomBytes, asciiBytes, type Packet } from '../bytes';

// ---------------------------------------------------------------- WebSocket

const WS_OPCODES: Record<number, string> = { 1: 'text', 2: 'binary', 8: 'close', 9: 'ping', 10: 'pong' };

export function wsFrame(o: { opcode: 1 | 8 | 9 | 10; payload: number[]; display: string; mask?: Uint8Array }): Packet {
  const h = new Header();
  const name = WS_OPCODES[o.opcode];
  h.u8('FIN / opcode', 0x80 | o.opcode, `FIN, opcode ${o.opcode} (${name})`, 'FIN=1 means this is the last (here, the only) fragment of the message. The opcode says what kind of frame it is: text, binary, close, ping or pong.');
  const len = o.payload.length;
  if (len > 125) throw new Error('only short frames are supported');
  h.u8('Mask / payload length', (o.mask ? 0x80 : 0) | len, `${o.mask ? 'masked' : 'not masked'}, ${len} bytes`, 'The top bit says whether the payload is masked. The other 7 bits are the length. 126 and 127 would mean "the real length follows in 2 or 8 more bytes".');
  let data = o.payload;
  if (o.mask) {
    const m = o.mask;
    h.bytes('Masking key', m, undefined, 'Browsers must XOR every payload byte with this random key. This is not for secrecy: it stops attackers from making a browser send bytes that a confused proxy might mistake for an HTTP request.');
    data = o.payload.map((b, i) => b ^ m[i % 4]);
  }
  h.bytes(o.mask ? 'Payload (masked)' : 'Payload', data, o.display, o.mask ? 'Un-masked by XOR-ing each byte with the masking key.' : 'Server-to-client frames are never masked.');
  return layer(`WebSocket ${name} frame`, 'ws', h);
}

// ---------------------------------------------------------------- SSH

export function sshVersion(id: string): Packet {
  const h = new Header();
  h.ascii('Identification string', id + '\r\n', id, 'The very first thing each side sends, in plain text: "SSH-2.0-" followed by the software name. It lets both sides check they speak protocol version 2.');
  return layer('SSH version exchange', 'ssh', h);
}

/** Build an unencrypted SSH binary packet around a payload. */
export function sshPacket(name: string, body: Header, seed: number): Packet {
  // packet_length (4) + padding_length (1) + payload + padding must be a multiple of 8, with at least 4 bytes of padding.
  let pad = 8 - ((5 + body.length) % 8);
  if (pad < 4) pad += 8;
  const h = new Header();
  h.u32('Packet length', 1 + body.length + pad, `${1 + body.length + pad} bytes`, 'Length of everything after this field, not counting a MAC.');
  h.u8('Padding length', pad, `${pad} bytes`, 'Random padding makes the total a multiple of the cipher block size and blurs the true length of the message.');
  const bytes = body.build();
  for (const f of body.fields) h.bytes(f.name, bytes.subarray(f.offset, f.offset + f.length), f.value, f.info);
  h.bytes('Random padding', randomBytes(seed, pad), undefined);
  return layer(`SSH ${name}`, 'ssh', h);
}

export function sshString(h: Header, name: string, value: string, info?: string): void {
  if (value === '') {
    h.u32(`${name} length`, 0, '0 bytes (empty list)', info);
    return;
  }
  h.u32(`${name} length`, value.length, `${value.length} bytes`);
  h.ascii(name, value, value, info);
}

export function sshBlob(h: Header, name: string, data: Uint8Array, info?: string): void {
  h.u32(`${name} length`, data.length, `${data.length} bytes`);
  h.bytes(name, data, undefined, info);
}

export function sshEncrypted(o: { plaintext: number; seed: number; hidden: string }): Packet {
  const h = new Header();
  h.bytes('Encrypted packet length', randomBytes(o.seed, 4), 'hidden', 'With chacha20-poly1305, even the length field is encrypted, using its own key. Observers cannot easily tell where one message ends and the next begins.');
  h.bytes('Encrypted packet', randomBytes(o.seed + 1, o.plaintext), undefined, `Ciphertext. Hidden inside: ${o.hidden}, plus random padding.`);
  h.bytes('MAC (Poly1305 tag)', randomBytes(o.seed + 2, 16), undefined, 'Proves the packet was not modified. A single flipped bit makes the receiver close the connection.');
  return layer('SSH encrypted packet', 'ssh', h);
}

// ---------------------------------------------------------------- FTP

export function ftp(line: string, info: string): Packet {
  const h = new Header();
  const reply = /^\d{3}/.test(line);
  h.ascii(reply ? 'Reply' : 'Command', line + '\r\n', line, info);
  return layer(reply ? 'FTP reply' : 'FTP command', 'ftp', h);
}

export function ftpData(content: string): Packet {
  const h = new Header();
  h.bytes('File contents', asciiBytes(content), `${content.length} bytes of text`, 'The raw bytes of the file. The end of the file is marked by the server closing this data connection.');
  return layer('FTP data', 'ftp', h);
}
