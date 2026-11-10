// RTP (RFC 3550) with H.264 FU-A payloads (RFC 6184), SDP bodies (RFC 8866), and
// NTS extension fields for NTPv4 (RFC 8915).
import { Header, layer, randomBytes, concat, type LayerKind, type Packet } from '../bytes';
import { lines, type Line } from './mail';

const hex32 = (v: number) => `0x${(v >>> 0).toString(16).padStart(8, '0')}`;

/** A text message (SIP or RTSP) followed by an SDP body, with Content-Length set correctly. */
export function withSdp(label: string, kind: LayerKind, start: Line[], headers: Line[], sdp: string[] | null): Packet {
  const sdpPkt = sdp ? lines('SDP', 'sdp', sdp.map((t) => ({ name: sdpName(t), text: t, info: SDP_INFO[t[0]] }))) : null;
  const len = sdpPkt?.bytes.length ?? 0;
  const msg = lines(label, kind, [
    ...start,
    ...headers,
    { name: 'Header: Content-Length', text: `Content-Length: ${len}`, info: 'The size of the body in bytes. With SIP over UDP it lets the receiver check that nothing was cut off.' },
    { name: 'End of headers', text: '', value: 'CRLF' },
  ]);
  return sdpPkt ? concat(msg, sdpPkt) : msg;
}

const SDP_NAMES: Record<string, string> = {
  v: 'Version', o: 'Origin', s: 'Session name', c: 'Connection address', t: 'Timing', m: 'Media description', a: 'Attribute',
};
const SDP_INFO: Record<string, string> = {
  v: 'SDP describes a media session in lines of the form "type=value". It does not carry media itself: it is a proposal that SIP or RTSP carries.',
  o: 'Who created the description, plus a session ID and version.',
  c: 'The IP address that media should be sent to.',
  m: 'One media stream: its type, the port to send it to, the transport (RTP/AVP) and the payload type numbers that may be used.',
  a: 'Attributes refine the media line, for example mapping a payload type number to a codec and clock rate.',
  t: '"0 0" means the session is not bounded in time.',
};
const sdpName = (t: string) => `SDP ${SDP_NAMES[t[0]] ?? t[0]}`;

// ---------------------------------------------------------------- RTP

export function rtp(o: { pt: number; ptName: string; seq: number; ts: number; tsInfo: string; ssrc: number; marker?: boolean; payload: Packet }): Packet {
  const h = new Header();
  h.u8('V / P / X / CC', 0x80, 'version 2, no padding, no extension, 0 CSRCs', 'Version 2 is the only one in use. CC would count contributing sources when an audio mixer combines several streams.');
  h.u8('M / payload type', (o.marker ? 0x80 : 0) | o.pt, `${o.marker ? 'marker, ' : ''}PT ${o.pt} (${o.ptName})`, 'The payload type says how to decode the data. Numbers 0–34 are fixed (0 = G.711 µ-law). 96 and up are "dynamic" and are mapped to a codec in the SDP.');
  h.u16('Sequence number', o.seq, String(o.seq), 'Goes up by one per packet, so the receiver can detect loss and put packets back in order. RTP runs over UDP and nothing is retransmitted: a late audio packet is useless anyway.');
  h.u32('Timestamp', o.ts >>> 0, String(o.ts >>> 0), o.tsInfo);
  h.u32('SSRC', o.ssrc, hex32(o.ssrc), 'Synchronisation source: a random ID for this stream, so the receiver can tell streams apart even when they arrive on the same port.');
  return layer('RTP', 'rtp', h, o.payload);
}

export function g711Payload(seed: number): Packet {
  const h = new Header();
  h.bytes('Audio samples', randomBytes(seed, 160), '160 bytes = 20 ms of G.711 µ-law', 'At 8,000 samples per second and one byte per sample, 20 ms of telephone-quality audio is 160 bytes. That is why the RTP timestamp goes up by 160 per packet.');
  return layer('G.711 audio', 'rtp', h);
}

export function h264FuA(seed: number, size: number): Packet {
  const h = new Header();
  h.u8('FU indicator', 0x7c, 'NRI 3, type 28 (FU-A)', 'A video frame is far bigger than one packet, so H.264 frames ("NAL units") are split into fragmentation units. Type 28 means FU-A.');
  h.u8('FU header', 0x85, 'start of fragment, NAL type 5 (IDR slice)', 'S=1 marks the first fragment. Type 5 is an IDR frame: a complete keyframe that decoding can start from.');
  h.bytes('Video slice data', randomBytes(seed, size), `${size} bytes of compressed video`, 'Part of the compressed keyframe. Later fragments carry the rest, and the last one has the RTP marker bit set.');
  return layer('H.264 FU-A', 'rtp', h);
}

// ---------------------------------------------------------------- NTS (NTP extension fields)

function ef(h: Header, type: number, name: string, info: string, body: (b: Header) => void): void {
  const b = new Header();
  body(b);
  const len = 4 + b.length;
  h.u16(`${name}: type`, type, `0x${type.toString(16).padStart(4, '0')} (${name})`, info);
  h.u16(`${name}: length`, len, `${len} bytes`, 'NTP extension fields are type–length–value, padded to a multiple of 4 bytes.');
  const bytes = b.build();
  for (const f of b.fields) h.bytes(f.name, bytes.subarray(f.offset, f.offset + f.length), f.value, f.info);
}

export function ntsRequestFields(o: { uid: Uint8Array; cookie: Uint8Array; seed: number }): Packet {
  const h = new Header();
  ef(h, 0x0104, 'Unique Identifier', 'A random 32-byte value the server must echo, which ties the response to this request and defeats replays.', (b) => b.bytes('Unique ID', o.uid));
  ef(h, 0x0204, 'NTS Cookie', 'One of the cookies from NTS-KE. It holds the session keys, encrypted with a key only the server knows, so the server needs no per-client state.', (b) => b.bytes('Cookie', o.cookie, `${o.cookie.length} bytes (opaque to the client)`));
  ef(h, 0x0404, 'NTS Authenticator', 'Authenticates everything before it in the packet, the 48-byte NTP header included, using AES-SIV with the client-to-server key from NTS-KE.', (b) => {
    b.u16('Nonce length', 16, '16 bytes');
    b.u16('Ciphertext length', 16, '16 bytes');
    b.bytes('Nonce', randomBytes(o.seed, 16));
    b.bytes('Ciphertext', randomBytes(o.seed + 1, 16), '16-byte SIV tag', 'Nothing is encrypted in the request, so the ciphertext is just the 16-byte authentication tag over the packet.');
  });
  return layer('NTS extension fields', 'ntp', h);
}

export function ntsResponseFields(o: { uid: Uint8Array; seed: number; cookieLen: number }): Packet {
  const h = new Header();
  ef(h, 0x0104, 'Unique Identifier', 'Echoed back exactly.', (b) => b.bytes('Unique ID', o.uid));
  const ct = 16 + 4 + o.cookieLen;
  ef(h, 0x0404, 'NTS Authenticator', 'Authenticates the whole response with the server-to-client key. A forged or modified time reply fails this check, which plain NTP cannot detect at all.', (b) => {
    b.u16('Nonce length', 16, '16 bytes');
    b.u16('Ciphertext length', ct, `${ct} bytes`);
    b.bytes('Nonce', randomBytes(o.seed, 16));
    b.bytes('Ciphertext', randomBytes(o.seed + 1, ct), `${ct} bytes`, 'Encrypted inside is a fresh NTS Cookie extension field. Each cookie is used once, so the client always has new ones and observers cannot link its requests together.');
  });
  return layer('NTS extension fields', 'ntp', h);
}
