// Application protocols: DNS (RFC 1035), HTTP/1.1 (RFC 9112) and TLS 1.3 (RFC 8446).
import { Header, layer, concat, randomBytes, hex16, asciiBytes, type Packet } from '../bytes';

// ---------------------------------------------------------------- DNS

function encodeName(name: string): number[] {
  const out: number[] = [];
  for (const label of name.split('.')) out.push(label.length, ...asciiBytes(label));
  out.push(0);
  return out;
}

function nameInfo(name: string): string {
  const parts = name.split('.').map((l) => `${l.length} "${l}"`);
  return `Names are sent as length-prefixed labels with no dots: ${parts.join(', ')}, then a 0 byte to end the name.`;
}

function dnsHeader(h: Header, id: number, response: boolean, answers: number): void {
  h.u16('Transaction ID', id, `0x${hex16(id)}`, 'A random number chosen by the client. The answer must carry the same ID, which helps reject forged replies.');
  if (response) {
    h.u16('Flags', 0x8180, '0x8180 (response, recursion desired + available, no error)', 'QR=1 marks a response. RD=1 is copied from the query. RA=1 says the server does recursion. RCODE=0 means no error.');
  } else {
    h.u16('Flags', 0x0100, '0x0100 (standard query, recursion desired)', 'QR=0 marks a query. RD=1 asks the resolver to do the whole lookup for us instead of just pointing us to another server.');
  }
  h.u16('Questions', 1, '1');
  h.u16('Answer records', answers, String(answers));
  h.u16('Authority records', 0, '0');
  h.u16('Additional records', 0, '0');
}

function dnsQuestion(h: Header, name: string): void {
  h.bytes('Query name', encodeName(name), name, nameInfo(name));
  h.u16('Query type', 1, '1 (A: IPv4 address)', 'Which kind of record is wanted. A is an IPv4 address; AAAA would be IPv6.');
  h.u16('Query class', 1, '1 (IN: Internet)');
}

export function dnsQuery(o: { id: number; name: string }): Packet {
  const h = new Header();
  dnsHeader(h, o.id, false, 0);
  dnsQuestion(h, o.name);
  return layer('DNS query', 'dns', h);
}

export function dnsResponse(o: { id: number; name: string; addr: string; ttl: number }): Packet {
  const h = new Header();
  dnsHeader(h, o.id, true, 1);
  dnsQuestion(h, o.name);
  h.u16('Answer name', 0xc00c, `pointer to offset 12 (${o.name})`, 'Compression: the top two bits (11) mark a pointer, and the rest is an offset into this message. Offset 12 is where the name already appears in the question, so it is not repeated.');
  h.u16('Answer type', 1, '1 (A)');
  h.u16('Answer class', 1, '1 (IN)');
  h.u32('Time to live', o.ttl, `${o.ttl} seconds`, 'How long the client may cache this answer before asking again.');
  h.u16('Data length', 4, '4 bytes');
  h.bytes('Address', o.addr.split('.').map(Number), o.addr, 'The answer: the IPv4 address of the name we asked about.');
  return layer('DNS response', 'dns', h);
}

// ---------------------------------------------------------------- HTTP

const HEADER_INFO: Record<string, string> = {
  host: 'Required in HTTP/1.1. One IP address can host many sites, so the client says which one it wants.',
  'user-agent': 'Identifies the client software.',
  accept: 'Which media types the client can handle.',
  'accept-encoding': 'Which compression methods the client understands.',
  connection: 'Whether to keep the TCP connection open for more requests.',
  'content-type': 'What kind of data the body is, and its character set.',
  'content-length': 'Exact size of the body in bytes, so the client knows when the response ends.',
  'cache-control': 'How long the response may be cached, and by whom.',
  date: 'When the response was generated.',
  server: 'Identifies the server software.',
};

export function http(startLine: string, headers: [string, string][], body = '', label = 'HTTP/1.1'): Packet {
  const h = new Header();
  const isRequest = !startLine.startsWith('HTTP/');
  h.ascii(
    isRequest ? 'Request line' : 'Status line',
    startLine + '\r\n',
    startLine,
    isRequest
      ? 'Method, path and protocol version, separated by spaces. GET asks for a resource without changing anything.'
      : 'Protocol version, status code and reason phrase. Codes in the 200s mean success.',
  );
  for (const [k, v] of headers) h.ascii(`Header: ${k}`, `${k}: ${v}\r\n`, v, HEADER_INFO[k.toLowerCase()]);
  h.ascii('End of headers', '\r\n', 'CRLF', 'An empty line (carriage return + line feed) marks the end of the headers.');
  if (body) h.ascii('Body', body, `${body.length} bytes of text`, 'The content itself.');
  return layer(label, 'http', h);
}

// ---------------------------------------------------------------- TLS 1.3

const CONTENT_TYPES: Record<number, string> = { 20: 'change_cipher_spec', 22: 'handshake', 23: 'application_data' };

function record(type: 20 | 22 | 23, version: number, inner: Packet | Header, name: string): Packet {
  const len = inner instanceof Header ? inner.length : inner.bytes.length;
  const h = new Header();
  h.u8('Content type', type, `${type} (${CONTENT_TYPES[type]})`, type === 23 ? 'In TLS 1.3 every encrypted record says "application data" on the outside. The real type is hidden inside the encryption.' : undefined);
  h.u16('Legacy version', version, version === 0x0301 ? '0x0301 (TLS 1.0)' : '0x0303 (TLS 1.2)', 'Frozen at an old value because some middleboxes break on unfamiliar numbers. The real version is negotiated in an extension.');
  h.u16('Length', len, `${len} bytes`);
  return inner instanceof Header ? layer(name, 'tls', h, undefined, inner) : layer(name, 'tls', h, inner);
}

function ext(h: Header, type: number, name: string, body: (b: Header) => void, info?: string): void {
  const b = new Header();
  body(b);
  h.u16(`Extension: ${name}`, type, `0x${hex16(type)} (${name})`, info);
  h.u16(`${name} length`, b.length, `${b.length} bytes`);
  const bytes = b.build();
  for (const f of b.fields) h.bytes(f.name, bytes.subarray(f.offset, f.offset + f.length), f.value, f.info);
}

function handshake(type: 1 | 2, name: string, body: Header): Packet {
  const h = new Header();
  h.u8('Handshake type', type, `${type} (${name})`);
  h.u24('Handshake length', body.length, `${body.length} bytes`);
  return layer(name, 'tls', h, undefined, body);
}

export function tlsClientHello(o: { sni: string; seed: number }): Packet {
  const b = new Header();
  b.u16('Legacy version', 0x0303, '0x0303 (TLS 1.2)', 'Kept at 1.2 for compatibility. The supported_versions extension below is what really offers TLS 1.3.');
  b.bytes('Random', randomBytes(o.seed, 32), undefined, '32 fresh random bytes. They are mixed into the keys so that every session is unique.');
  b.u8('Session ID length', 32, '32 bytes');
  b.bytes('Legacy session ID', randomBytes(o.seed + 1, 32), undefined, 'Not used by TLS 1.3, but filled in so the handshake looks like a TLS 1.2 session resumption to old middleboxes.');
  b.u16('Cipher suites length', 6, '6 bytes (3 suites)');
  b.u16('Cipher suite', 0x1301, 'TLS_AES_128_GCM_SHA256', 'The encryption and hash the client can use, in order of preference.');
  b.u16('Cipher suite', 0x1303, 'TLS_CHACHA20_POLY1305_SHA256');
  b.u16('Cipher suite', 0x1302, 'TLS_AES_256_GCM_SHA384');
  b.u8('Compression methods length', 1, '1 byte');
  b.u8('Compression method', 0, '0 (none)', 'TLS compression was removed after the CRIME attack. Only "none" is allowed.');

  const e = new Header();
  ext(e, 0x0000, 'server_name', (x) => {
    x.u16('SNI list length', o.sni.length + 3, `${o.sni.length + 3} bytes`);
    x.u8('SNI type', 0, '0 (host name)');
    x.u16('SNI length', o.sni.length, `${o.sni.length} bytes`);
    x.ascii('SNI host name', o.sni, o.sni, 'The site we want. It is sent in plain text, so anyone watching can see which site you are visiting (Encrypted Client Hello fixes this).');
  }, 'Server Name Indication: lets one IP address serve certificates for many sites.');
  ext(e, 0x000a, 'supported_groups', (x) => {
    x.u16('Groups length', 4, '4 bytes');
    x.u16('Group', 0x001d, 'x25519', 'Elliptic curves the client can use for key exchange.');
    x.u16('Group', 0x0017, 'secp256r1');
  });
  ext(e, 0x000d, 'signature_algorithms', (x) => {
    x.u16('Algorithms length', 6, '6 bytes');
    x.u16('Algorithm', 0x0403, 'ecdsa_secp256r1_sha256', 'Signature types the client accepts on the server\'s certificate and handshake.');
    x.u16('Algorithm', 0x0804, 'rsa_pss_rsae_sha256');
    x.u16('Algorithm', 0x0401, 'rsa_pkcs1_sha256');
  });
  ext(e, 0x0010, 'application_layer_protocol_negotiation', (x) => {
    x.u16('ALPN list length', 9, '9 bytes');
    x.u8('Protocol length', 8, '8 bytes');
    x.ascii('Protocol', 'http/1.1', 'http/1.1', 'The application protocol the client wants to speak inside the encrypted tunnel.');
  });
  ext(e, 0x002b, 'supported_versions', (x) => {
    x.u8('Versions length', 2, '2 bytes');
    x.u16('Version', 0x0304, '0x0304 (TLS 1.3)', 'This is where TLS 1.3 is really requested.');
  });
  ext(e, 0x0033, 'key_share', (x) => {
    x.u16('Client shares length', 36, '36 bytes');
    x.u16('Key share group', 0x001d, 'x25519');
    x.u16('Key exchange length', 32, '32 bytes');
    x.bytes('Public key', randomBytes(o.seed + 2, 32), undefined, 'The client\'s half of an elliptic-curve Diffie–Hellman exchange. The server combines it with its own secret to get a shared key that was never sent over the network.');
  }, 'Sending a key share right away lets TLS 1.3 finish in one round trip instead of two.');

  b.u16('Extensions length', e.length, `${e.length} bytes`);
  const eb = e.build();
  for (const f of e.fields) b.bytes(f.name, eb.subarray(f.offset, f.offset + f.length), f.value, f.info);

  return record(22, 0x0301, handshake(1, 'ClientHello', b), 'TLS record');
}

export function tlsServerHello(o: { seed: number; sessionSeed: number }): Packet {
  const b = new Header();
  b.u16('Legacy version', 0x0303, '0x0303 (TLS 1.2)');
  b.bytes('Random', randomBytes(o.seed, 32), undefined, 'The server\'s 32 random bytes.');
  b.u8('Session ID length', 32, '32 bytes');
  b.bytes('Legacy session ID echo', randomBytes(o.sessionSeed, 32), undefined, 'A copy of the client\'s session ID, for compatibility.');
  b.u16('Cipher suite', 0x1301, 'TLS_AES_128_GCM_SHA256', 'The one cipher suite the server picked from the client\'s list.');
  b.u8('Compression method', 0, '0 (none)');
  const e = new Header();
  ext(e, 0x002b, 'supported_versions', (x) => x.u16('Selected version', 0x0304, '0x0304 (TLS 1.3)'));
  ext(e, 0x0033, 'key_share', (x) => {
    x.u16('Key share group', 0x001d, 'x25519');
    x.u16('Key exchange length', 32, '32 bytes');
    x.bytes('Public key', randomBytes(o.seed + 2, 32), undefined, 'The server\'s half of the key exchange. From this moment both sides can compute the same handshake keys, and everything after this message is encrypted.');
  });
  b.u16('Extensions length', e.length, `${e.length} bytes`);
  const eb = e.build();
  for (const f of e.fields) b.bytes(f.name, eb.subarray(f.offset, f.offset + f.length), f.value, f.info);

  return concat(record(22, 0x0303, handshake(2, 'ServerHello', b), 'TLS record'), tlsChangeCipherSpec());
}

export function tlsChangeCipherSpec(): Packet {
  const b = new Header();
  b.u8('Change cipher spec', 1, '1', 'Meaningless in TLS 1.3 and ignored by the receiver. It is sent only so the handshake looks like TLS 1.2 to old middleboxes.');
  return record(20, 0x0303, b, 'TLS record (compatibility)');
}

/**
 * An encrypted TLS 1.3 record. `plaintextLength` is the size of the hidden content.
 * The ciphertext adds 1 byte for the hidden content type and a 16-byte authentication tag.
 */
export function tlsEncrypted(o: { plaintextLength: number; seed: number; hidden: string }): Packet {
  const b = new Header();
  b.bytes('Encrypted data', randomBytes(o.seed, o.plaintextLength + 1), undefined, `Ciphertext. Without the keys it looks like random noise. Hidden inside: ${o.hidden}, followed by a 1-byte real content type.`);
  b.bytes('Authentication tag', randomBytes(o.seed + 7, 16), undefined, 'A 16-byte AES-GCM tag. If even one bit of the record is changed on the way, the tag will not match and the connection is torn down.');
  return record(23, 0x0303, b, 'TLS record (encrypted)');
}
