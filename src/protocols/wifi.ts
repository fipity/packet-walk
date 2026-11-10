// IEEE 802.11 management/data frames and the WPA2 4-way handshake (EAPOL-Key, IEEE 802.11i).
// Multi-byte 802.11 fields are little-endian; EAPOL fields are big-endian.
import { Header, layer, mac, randomBytes, hex16, asciiBytes, type Packet } from '../bytes';

const le16 = (v: number) => [v & 0xff, v >>> 8];

function fc(type: number, subtype: number, flags: number): number[] {
  return [(subtype << 4) | (type << 2), flags];
}

const FRAME_NAMES: Record<string, string> = {
  '0/0': 'Association request',
  '0/1': 'Association response',
  '0/8': 'Beacon',
  '0/11': 'Authentication',
  '2/0': 'Data',
};

export interface Hdr80211 {
  type: 0 | 2;
  subtype: number;
  /** Bit 0 To DS, bit 1 From DS, bit 6 Protected. */
  flags?: number;
  addr1: string;
  addr2: string;
  addr3: string;
  seq: number;
  duration?: number;
}

function addrInfo(i: number, h: Hdr80211): [string, string] {
  const toDS = (h.flags ?? 0) & 1;
  const fromDS = (h.flags ?? 0) & 2;
  if (h.type === 0) {
    return [
      ['Receiver / destination', 'Transmitter / source', 'BSSID'][i],
      ['Who should receive this frame.', 'Who sent it.', 'The BSSID: the access point\'s radio MAC address, which identifies the network cell.'][i],
    ];
  }
  if (toDS) {
    return [['Receiver (BSSID)', 'Transmitter / source', 'Final destination'][i], ['The access point that should pick this frame out of the air.', 'The station sending it.', 'Where the frame is ultimately going, after the access point bridges it on. Wi-Fi frames carry three (sometimes four) addresses instead of Ethernet\'s two, because the radio hop and the real destination can differ.'][i]];
  }
  if (fromDS) {
    return [['Receiver / destination', 'Transmitter (BSSID)', 'Original source'][i], ['The station this frame is for.', 'The access point transmitting it.', 'Who originally sent it.'][i]];
  }
  return [`Address ${i + 1}`, ''];
}

function header80211(h: Header, o: Hdr80211): void {
  const name = FRAME_NAMES[`${o.type}/${o.subtype}`];
  const f = o.flags ?? 0;
  const flagNames = [f & 1 && 'To DS', f & 2 && 'From DS', f & 0x40 && 'Protected'].filter(Boolean).join(', ') || 'none';
  h.bytes('Frame control', fc(o.type, o.subtype, f), `${o.type === 0 ? 'management' : 'data'}: ${name}; flags: ${flagNames}`,
    'The first byte holds the protocol version, the frame type (0 = management, 1 = control, 2 = data) and the subtype. The second holds flags: To DS/From DS say whether the frame is heading into or out of the wired side ("distribution system"), and Protected means the body is encrypted.');
  h.bytes('Duration', le16(o.duration ?? 0), `${o.duration ?? 0} µs`, 'How long the sender will keep the channel busy, including the acknowledgment. Other stations hear this and stay quiet that long. This is part of how Wi-Fi shares the air.');
  for (const [i, a] of [o.addr1, o.addr2, o.addr3].entries()) {
    const [n, info] = addrInfo(i, o);
    h.bytes(n, mac(a), a === 'ff:ff:ff:ff:ff:ff' ? `${a} (broadcast)` : a, info || undefined);
  }
  h.bytes('Sequence control', le16(o.seq << 4), `sequence ${o.seq}, fragment 0`, 'Lets the receiver discard duplicates. Unlike Ethernet, every Wi-Fi unicast frame is acknowledged by the receiver and resent if no ACK arrives, so duplicates do happen.');
}

function finish80211(name: string, h: Header, payload?: Packet): Packet {
  return layer(`802.11 ${name}`, 'wifi', h, payload);
}

// ---------------------------------------------------------------- information elements

function ie(h: Header, id: number, name: string, data: number[], value: string, info?: string): void {
  h.u8(`IE: ${name}`, id, `${id} (${name})`, info);
  h.u8('IE length', data.length, `${data.length} bytes`);
  h.bytes(name, data, value);
}

function ssidIe(h: Header, ssid: string): void {
  ie(h, 0, 'SSID', asciiBytes(ssid), JSON.stringify(ssid), 'The network name you see in the Wi-Fi menu. Information elements like this are type–length–value, so new features can be added without breaking old devices.');
}

function ratesIe(h: Header): void {
  ie(h, 1, 'Supported rates', [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24], '1*, 2*, 5.5*, 11*, 6, 9, 12, 18 Mbit/s', 'Legacy data rates in units of 500 kbit/s. A * (top bit set) marks a basic rate every station must support. Modern 802.11ax rates are advertised in separate HT/VHT/HE elements, which are left out here.');
}

const OUI = [0x00, 0x0f, 0xac];

function rsnIe(h: Header): void {
  h.u8('IE: RSN', 48, '48 (RSN: Robust Security Network)', 'Advertises the security the network requires. It is the same element a client copies into its association request and its handshake message 2, which lets the access point detect any downgrade attempt.');
  h.u8('IE length', 20, '20 bytes');
  h.bytes('RSN version', le16(1), '1');
  h.bytes('Group cipher suite', [...OUI, 4], '00-0f-ac:4 (CCMP / AES)', 'Cipher for broadcast and multicast traffic.');
  h.bytes('Pairwise cipher count', le16(1), '1');
  h.bytes('Pairwise cipher suite', [...OUI, 4], '00-0f-ac:4 (CCMP / AES)', 'Cipher for this client\'s own traffic.');
  h.bytes('AKM suite count', le16(1), '1');
  h.bytes('AKM suite', [...OUI, 2], '00-0f-ac:2 (PSK: WPA2-Personal)', 'How keys are authenticated: here a pre-shared key (the Wi-Fi password). WPA3-Personal uses SAE (00-0f-ac:8) instead, which adds a password-authenticated key exchange before the 4-way handshake and resists offline password guessing.');
  h.bytes('RSN capabilities', le16(0x0080), '0x0080 (management frame protection capable)', 'Protected management frames stop attackers from forging "deauthenticate" frames to kick devices off the network.');
}

// ---------------------------------------------------------------- frames

export function beacon(o: { bssid: string; ssid: string; seq: number; channel: number; seed: number }): Packet {
  const h = new Header();
  header80211(h, { type: 0, subtype: 8, addr1: 'ff:ff:ff:ff:ff:ff', addr2: o.bssid, addr3: o.bssid, seq: o.seq });
  h.bytes('Timestamp', [...randomBytes(o.seed, 5), 0, 0, 0], 'access point clock (µs)', 'The access point\'s microsecond clock. Stations copy it to stay in sync, so they can wake from power saving at exactly the right moment.');
  h.bytes('Beacon interval', le16(100), '100 TU (102.4 ms)', 'Beacons go out about ten times a second. A TU (time unit) is 1024 µs.');
  h.bytes('Capability information', le16(0x0411), '0x0411 (ESS, privacy, short slot time)', 'ESS: this is an access point, not an ad-hoc network. Privacy: encryption is required.');
  ssidIe(h, o.ssid);
  ratesIe(h);
  ie(h, 3, 'DS parameter set', [o.channel], `channel ${o.channel}`, 'The radio channel the access point is on.');
  ie(h, 5, 'TIM', [0, 1, 0, 0], 'DTIM count 0, period 1, no buffered frames', 'Traffic Indication Map: tells sleeping devices whether the access point is holding frames for them, so phones can keep their radio off most of the time.');
  rsnIe(h);
  return finish80211('Beacon', h);
}

export function authentication(o: { from: string; to: string; bssid: string; seq: number; step: 1 | 2 }): Packet {
  const h = new Header();
  header80211(h, { type: 0, subtype: 11, addr1: o.to, addr2: o.from, addr3: o.bssid, seq: o.seq, duration: 44 });
  h.bytes('Authentication algorithm', le16(0), '0 (Open System)', 'A leftover from the broken WEP era. With WPA2, this step always succeeds, and the real authentication happens in the 4-way handshake that comes after association. (WPA3 uses algorithm 3, SAE, here instead.)');
  h.bytes('Authentication sequence', le16(o.step), String(o.step));
  h.bytes('Status code', le16(0), '0 (success)');
  return finish80211('Authentication', h);
}

export function associationRequest(o: { from: string; bssid: string; ssid: string; seq: number }): Packet {
  const h = new Header();
  header80211(h, { type: 0, subtype: 0, addr1: o.bssid, addr2: o.from, addr3: o.bssid, seq: o.seq, duration: 44 });
  h.bytes('Capability information', le16(0x0411), '0x0411 (ESS, privacy, short slot time)');
  h.bytes('Listen interval', le16(10), '10 beacon intervals', 'How many beacons the client may sleep through. The access point must buffer frames for at least that long.');
  ssidIe(h, o.ssid);
  ratesIe(h);
  rsnIe(h);
  return finish80211('Association request', h);
}

export function associationResponse(o: { to: string; bssid: string; seq: number; aid: number }): Packet {
  const h = new Header();
  header80211(h, { type: 0, subtype: 1, addr1: o.to, addr2: o.bssid, addr3: o.bssid, seq: o.seq, duration: 44 });
  h.bytes('Capability information', le16(0x0411), '0x0411 (ESS, privacy, short slot time)');
  h.bytes('Status code', le16(0), '0 (success)');
  h.bytes('Association ID', le16(0xc000 | o.aid), `${o.aid}`, 'The client\'s slot number on this access point. Its bit in beacon TIMs says whether frames are waiting for it. The top two bits are always set.');
  ratesIe(h);
  return finish80211('Association response', h);
}

function llcSnap(h: Header, ethertype: number, name: string): void {
  h.bytes('LLC/SNAP header', [0xaa, 0xaa, 0x03, 0, 0, 0, ethertype >>> 8, ethertype & 0xff], `EtherType 0x${hex16(ethertype)} (${name})`,
    '802.11 has no EtherType field, so data frames start with an 8-byte LLC/SNAP header whose last two bytes are the EtherType. That is how the access point can bridge frames to Ethernet unchanged.');
}

export interface EapolKey {
  msg: 1 | 2 | 3 | 4;
  replay: number;
  nonce?: Uint8Array;
  mic: boolean;
  keyData: number[];
  keyDataInfo?: string;
  seed: number;
}

const KEY_INFO: Record<number, [number, string]> = {
  1: [0x008a, 'pairwise, ACK'],
  2: [0x010a, 'pairwise, MIC'],
  3: [0x13ca, 'pairwise, install, ACK, MIC, secure, encrypted key data'],
  4: [0x030a, 'pairwise, MIC, secure'],
};

export function eapolData(o: { toDS: boolean; addr1: string; addr2: string; addr3: string; seq: number; key: EapolKey }): Packet {
  const h = new Header();
  header80211(h, { type: 2, subtype: 0, flags: o.toDS ? 1 : 2, addr1: o.addr1, addr2: o.addr2, addr3: o.addr3, seq: o.seq, duration: 44 });
  llcSnap(h, 0x888e, '802.1X / EAPOL');

  const k = o.key;
  const e = new Header();
  e.u8('EAPOL version', 2, '2 (802.1X-2004)');
  e.u8('EAPOL type', 3, '3 (Key)', 'EAPOL carries authentication messages before the link is allowed to carry normal traffic.');
  e.u16('EAPOL length', 95 + k.keyData.length, `${95 + k.keyData.length} bytes`);
  e.u8('Key descriptor type', 2, '2 (RSN)');
  const [info, infoName] = KEY_INFO[k.msg];
  e.u16('Key information', info, `0x${hex16(info)} (${infoName})`, 'Flags that say which handshake message this is. ACK means "please answer", MIC means it is authenticated, install means "start using the keys", secure means the keys are ready.');
  e.u16('Key length', 16, '16 bytes (CCMP)');
  e.bytes('Replay counter', [0, 0, 0, 0, 0, 0, 0, k.replay], String(k.replay), 'Goes up with each message from the access point. The client echoes it back, so old handshake messages cannot be replayed.');
  e.bytes('Key nonce', k.nonce ?? new Array(32).fill(0), k.nonce ? undefined : '0 (none)', k.msg === 1 || k.msg === 3 ? 'ANonce: the access point\'s random number.' : k.msg === 2 ? 'SNonce: the client\'s random number. The session key (PTK) is derived from the password-based PMK, both nonces and both MAC addresses.' : undefined);
  e.bytes('Key IV', new Array(16).fill(0), '0');
  e.bytes('Key RSC', new Array(8).fill(0), '0', 'Receive sequence counter for the group key.');
  e.bytes('Key ID', new Array(8).fill(0), '0 (reserved)');
  e.bytes('Key MIC', k.mic ? randomBytes(k.seed, 16) : new Array(16).fill(0), k.mic ? undefined : '0 (not yet possible)',
    k.mic ? 'A keyed hash of this EAPOL frame, computed with part of the freshly derived PTK. A correct MIC proves the sender knows the Wi-Fi password, and the password itself is never sent.' : 'Message 1 cannot be authenticated yet: the client has not derived any keys.');
  e.u16('Key data length', k.keyData.length, `${k.keyData.length} bytes`);
  if (k.keyData.length) e.bytes('Key data', k.keyData, undefined, k.keyDataInfo);
  const eapol = layer(`EAPOL-Key (message ${k.msg} of 4)`, 'eapol', e);
  return finish80211('Data', h, eapol);
}

/** Bytes of an RSN IE (for message 2's key data). */
export function rsnIeBytes(): number[] {
  const h = new Header();
  rsnIe(h);
  return Array.from(h.build());
}

export function protectedData(o: { addr1: string; addr2: string; addr3: string; seq: number; pn: number; plaintext: number; seed: number; hidden: string }): Packet {
  const h = new Header();
  header80211(h, { type: 2, subtype: 0, flags: 0x41, addr1: o.addr1, addr2: o.addr2, addr3: o.addr3, seq: o.seq, duration: 44 });
  const pn = o.pn;
  h.bytes('CCMP header', [pn & 0xff, (pn >>> 8) & 0xff, 0, 0x20, (pn >>> 16) & 0xff, (pn >>> 24) & 0xff, 0, 0], `packet number ${pn}, key ID 0`,
    'An 8-byte header holding a 48-bit packet number (split around a key-ID byte). It is the nonce for AES-CCM and must always increase, which blocks replays.');
  h.bytes('Encrypted payload', randomBytes(o.seed, o.plaintext), undefined, `AES-CCMP ciphertext. Hidden inside: ${o.hidden}.`);
  h.bytes('MIC', randomBytes(o.seed + 1, 8), undefined, 'An 8-byte message integrity code over the frame header and payload.');
  return finish80211('Data (protected)', h);
}
