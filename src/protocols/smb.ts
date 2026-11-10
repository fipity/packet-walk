// SMB 2/3 over TCP port 445 ([MS-SMB2]), with the 4-byte NetBIOS session service (RFC 1002) framing.
// SMB2 integers are little-endian.
import { Header, layer, randomBytes, type Packet } from '../bytes';

const le16 = (v: number) => [v & 0xff, v >>> 8];
const le32 = (v: number) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, v >>> 24];
const le64 = (v: number) => [...le32(v >>> 0), ...le32(Math.floor(v / 2 ** 32))];
const utf16 = (s: string) => Array.from(s).flatMap((c) => le16(c.charCodeAt(0)));
const hex = (v: number, w = 8) => `0x${(v >>> 0).toString(16).padStart(w, '0')}`;

const DIALECTS: Record<number, string> = { 0x0202: 'SMB 2.0.2', 0x0210: 'SMB 2.1', 0x0300: 'SMB 3.0', 0x0302: 'SMB 3.0.2', 0x0311: 'SMB 3.1.1' };

const COMMANDS: Record<number, string> = { 0: 'NEGOTIATE', 1: 'SESSION_SETUP', 3: 'TREE_CONNECT', 5: 'CREATE', 8: 'READ' };

export interface Smb2Hdr {
  command: number;
  response: boolean;
  messageId: number;
  credits: number;
  treeId: number;
  sessionId: number;
  signed: boolean;
  seed: number;
}

function smb2Header(h: Header, o: Smb2Hdr): void {
  h.bytes('Protocol ID', [0xfe, 0x53, 0x4d, 0x42], '\\xFESMB', 'Marks an SMB2/3 message. The original SMB1 used \\xFFSMB.');
  h.bytes('Structure size', le16(64), '64', 'The SMB2 header is always 64 bytes. Note that SMB2 numbers are little-endian, the opposite of most internet protocols.');
  h.bytes('Credit charge', le16(o.command === 0 ? 0 : 1), String(o.command === 0 ? 0 : 1));
  h.bytes(o.response ? 'Status' : 'Channel sequence / reserved', le32(0), o.response ? '0 (STATUS_SUCCESS)' : '0', o.response ? 'An NT status code. 0 means success. Errors like 0xC0000022 (access denied) appear here.' : undefined);
  h.bytes('Command', le16(o.command), `${o.command} (${COMMANDS[o.command]})`);
  h.bytes(o.response ? 'Credits granted' : 'Credits requested', le16(o.credits), String(o.credits),
    'SMB flow control: each request costs credits, and the server hands out more in its responses. That limits how many requests a client can have in flight at once.');
  const flags = (o.response ? 1 : 0) | (o.signed ? 8 : 0);
  h.bytes('Flags', le32(flags), [o.response ? 'response' : 'request', o.signed ? 'signed' : ''].filter(Boolean).join(', '));
  h.bytes('Next command', le32(0), '0 (not compounded)', 'SMB can chain several commands into one message to save round trips. 0 means this is the only one.');
  h.bytes('Message ID', le64(o.messageId), String(o.messageId), 'Increases with each request. The response carries the same ID.');
  h.bytes('Reserved', le32(0), '0');
  h.bytes('Tree ID', le32(o.treeId), o.treeId ? hex(o.treeId) : '0 (none yet)', 'Which connected share this command is for.');
  h.bytes('Session ID', le64(o.sessionId), o.sessionId ? hex(o.sessionId, 16) : '0 (none yet)', 'Which authenticated user session this belongs to.');
  h.bytes('Signature', o.signed ? randomBytes(o.seed, 16) : new Array(16).fill(0), o.signed ? undefined : '0 (unsigned)',
    o.signed ? 'An AES-GMAC signature over the message, keyed from the session\'s authentication. It stops attackers from tampering with or relaying SMB traffic. This value is illustrative.' : 'Negotiation happens before any keys exist, so it cannot be signed. SMB 3.1.1 protects it differently, by hashing all the negotiate messages into the session keys ("pre-authentication integrity").');
}

function smb2(o: Smb2Hdr, body: (h: Header) => void): Packet {
  const h = new Header();
  smb2Header(h, o);
  body(h);
  const smb = layer(`SMB2 ${COMMANDS[o.command]} ${o.response ? 'response' : 'request'}`, 'smb', h);
  const n = new Header();
  n.u8('Message type', 0, '0 (session message)', 'SMB over TCP port 445 keeps the 4-byte NetBIOS session header from the 1980s, purely to mark message lengths in the TCP stream.');
  n.u24('Length', smb.bytes.length, `${smb.bytes.length} bytes`);
  return layer('NetBIOS session service', 'smb', n, smb);
}

export function negotiateRequest(o: Smb2Hdr & { guid: Uint8Array; salt: Uint8Array }): Packet {
  const dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
  return smb2(o, (h) => {
    h.bytes('Structure size', le16(36), '36');
    h.bytes('Dialect count', le16(dialects.length), String(dialects.length));
    h.bytes('Security mode', le16(1), 'signing enabled');
    h.bytes('Reserved', le16(0), '0');
    h.bytes('Capabilities', le32(0x7f), 'DFS, leasing, large MTU, multi-channel, persistent handles, directory leasing, encryption');
    h.bytes('Client GUID', o.guid, undefined, 'A random ID for this client machine.');
    h.bytes('Negotiate context offset', le32(112), '112', 'Where the SMB 3.1.1 negotiate contexts start, counted from the start of the SMB2 header.');
    h.bytes('Negotiate context count', le16(2), '2');
    h.bytes('Reserved', le16(0), '0');
    for (const d of dialects) {
      h.bytes('Dialect', le16(d), DIALECTS[d], 'The client lists every version it speaks. The server picks the highest one it supports.');
    }
    h.bytes('Padding', [0, 0], '2 bytes', 'Negotiate contexts must start on an 8-byte boundary.');
    h.bytes('Context type', le16(1), '1 (pre-authentication integrity)', 'Every negotiate and session-setup message is hashed with SHA-512 into the keys. If an attacker had tampered with the dialect list (say, to force a weaker version), the keys would not match and the connection would fail.');
    h.bytes('Data length', le16(38), '38 bytes');
    h.bytes('Reserved', le32(0), '0');
    h.bytes('Hash algorithm count', le16(1), '1');
    h.bytes('Salt length', le16(32), '32 bytes');
    h.bytes('Hash algorithm', le16(1), '1 (SHA-512)');
    h.bytes('Salt', o.salt, undefined, 'Random bytes mixed into the hash.');
    h.bytes('Padding', [0, 0], '2 bytes');
    h.bytes('Context type', le16(2), '2 (encryption capabilities)', 'The ciphers the client can use if the server requires encryption.');
    h.bytes('Data length', le16(6), '6 bytes');
    h.bytes('Reserved', le32(0), '0');
    h.bytes('Cipher count', le16(2), '2');
    h.bytes('Cipher', le16(4), 'AES-256-GCM');
    h.bytes('Cipher', le16(2), 'AES-128-GCM');
  });
}

function der(tag: number, ...content: number[][]): number[] {
  const body = content.flat();
  if (body.length >= 128) throw new Error('long DER not needed here');
  return [tag, body.length, ...body];
}

export function negotiateResponse(o: Smb2Hdr & { guid: Uint8Array; salt: Uint8Array; time: number }): Packet {
  // SPNEGO negTokenInit (RFC 4178) offering Kerberos and NTLM.
  const kerberos = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
  const ntlm = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
  const spnegoOid = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
  const token = der(0x60, spnegoOid, der(0xa0, der(0x30, der(0xa0, der(0x30, kerberos, ntlm)))));
  const filetime = Math.round((o.time + 11644473600) * 1e7);
  const ft = [...le32(filetime % 2 ** 32), ...le32(Math.floor(filetime / 2 ** 32))];
  const secOffset = 64 + 64;
  const ctxOffset = Math.ceil((secOffset + token.length) / 8) * 8;
  return smb2(o, (h) => {
    h.bytes('Structure size', le16(65), '65');
    h.bytes('Security mode', le16(1), 'signing enabled');
    h.bytes('Dialect revision', le16(0x0311), 'SMB 3.1.1', 'The server chose the newest dialect both sides support.');
    h.bytes('Negotiate context count', le16(2), '2');
    h.bytes('Server GUID', o.guid, undefined);
    h.bytes('Capabilities', le32(0x2f), 'DFS, leasing, large MTU, multi-channel, directory leasing');
    h.bytes('Max transact size', le32(8388608), '8 MiB');
    h.bytes('Max read size', le32(8388608), '8 MiB', 'The largest single READ the server will answer. Big reads are what make SMB fast for large files.');
    h.bytes('Max write size', le32(8388608), '8 MiB');
    h.bytes('System time', ft, new Date(o.time * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC', 'A Windows FILETIME: 100-nanosecond intervals since 1 January 1601.');
    h.bytes('Server start time', new Array(8).fill(0), '0');
    h.bytes('Security buffer offset', le16(secOffset), String(secOffset));
    h.bytes('Security buffer length', le16(token.length), `${token.length} bytes`);
    h.bytes('Negotiate context offset', le32(ctxOffset), String(ctxOffset));
    h.bytes('SPNEGO token', token, 'negTokenInit: Kerberos, NTLMSSP', 'A small ASN.1 (DER) structure listing the authentication methods the server accepts. Kerberos is used on company domains, and NTLM is the fallback for home NAS boxes and local accounts.');
    h.bytes('Padding', new Array(ctxOffset - secOffset - token.length).fill(0), `${ctxOffset - secOffset - token.length} bytes`);
    h.bytes('Context type', le16(1), '1 (pre-authentication integrity)');
    h.bytes('Data length', le16(38), '38 bytes');
    h.bytes('Reserved', le32(0), '0');
    h.bytes('Hash algorithm count', le16(1), '1');
    h.bytes('Salt length', le16(32), '32 bytes');
    h.bytes('Hash algorithm', le16(1), '1 (SHA-512)');
    h.bytes('Salt', o.salt, undefined);
    h.bytes('Padding', [0, 0], '2 bytes');
    h.bytes('Context type', le16(2), '2 (encryption capabilities)');
    h.bytes('Data length', le16(4), '4 bytes');
    h.bytes('Reserved', le32(0), '0');
    h.bytes('Cipher count', le16(1), '1');
    h.bytes('Cipher', le16(4), 'AES-256-GCM', 'Chosen in case the share requires encryption.');
  });
}

export function treeConnectRequest(o: Smb2Hdr & { path: string }): Packet {
  const p = utf16(o.path);
  return smb2(o, (h) => {
    h.bytes('Structure size', le16(9), '9');
    h.bytes('Flags', le16(0), '0');
    h.bytes('Path offset', le16(72), '72');
    h.bytes('Path length', le16(p.length), `${p.length} bytes`);
    h.bytes('Path', p, o.path, 'The share to connect to, as a UNC path. Windows encodes text as UTF-16LE, two bytes per character, which is why you see a 00 after every letter in the hex dump.');
  });
}

export function treeConnectResponse(o: Smb2Hdr): Packet {
  return smb2(o, (h) => {
    h.bytes('Structure size', le16(16), '16');
    h.u8('Share type', 1, '1 (disk)', 'Shares can be disks, printers or named pipes (used for remote procedure calls).');
    h.u8('Reserved', 0, '0');
    h.bytes('Share flags', le32(0), '0 (no caching restrictions)');
    h.bytes('Capabilities', le32(0), '0');
    h.bytes('Maximal access', le32(0x001f01ff), '0x001f01ff (full control)', 'The most this user may do on this share. Individual files can still be more restrictive.');
  });
}

export function createRequest(o: Smb2Hdr & { name: string }): Packet {
  const n = utf16(o.name);
  return smb2(o, (h) => {
    h.bytes('Structure size', le16(57), '57');
    h.u8('Security flags', 0, '0');
    h.u8('Requested oplock level', 0, '0 (none)', 'Oplocks and leases let a client cache a file locally until another client wants it.');
    h.bytes('Impersonation level', le32(2), '2 (impersonation)');
    h.bytes('SMB create flags', le64(0), '0');
    h.bytes('Reserved', le64(0), '0');
    h.bytes('Desired access', le32(0x00120089), '0x00120089 (read data, read attributes, read EA, synchronize)', 'CREATE opens existing files too. This access mask asks only to read.');
    h.bytes('File attributes', le32(0), '0');
    h.bytes('Share access', le32(1), 'read', 'What other clients may do with the file while we have it open.');
    h.bytes('Create disposition', le32(1), '1 (FILE_OPEN: fail if missing)');
    h.bytes('Create options', le32(0x40), '0x40 (non-directory file)');
    h.bytes('Name offset', le16(120), '120');
    h.bytes('Name length', le16(n.length), `${n.length} bytes`);
    h.bytes('Create contexts offset', le32(0), '0');
    h.bytes('Create contexts length', le32(0), '0');
    h.bytes('File name', n, o.name, 'Relative to the share, in UTF-16LE.');
  });
}

export function readResponse(o: Smb2Hdr & { data: string }): Packet {
  const d = Array.from(o.data, (c) => c.charCodeAt(0));
  return smb2(o, (h) => {
    h.bytes('Structure size', le16(17), '17');
    h.u8('Data offset', 80, '80');
    h.u8('Reserved', 0, '0');
    h.bytes('Data length', le32(d.length), `${d.length} bytes`);
    h.bytes('Data remaining', le32(0), '0');
    h.bytes('Flags', le32(0), '0');
    h.bytes('File data', d, `${d.length} bytes of text`, 'The file contents. The share is signed but not encrypted, so the data is readable on the network. Shares can require SMB 3 encryption, in which case every message is wrapped in an AES-GCM "transform header" instead.');
  });
}
