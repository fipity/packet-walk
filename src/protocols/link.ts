// Ethernet II framing and ARP (RFC 826).
import { Header, layer, mac, ip, hex16, type Packet } from '../bytes';

export const BROADCAST = 'ff:ff:ff:ff:ff:ff';

const ETHERTYPES = { IPv4: 0x0800, ARP: 0x0806 } as const;

export function ethernet(o: { dst: string; src: string; type: keyof typeof ETHERTYPES }, payload: Packet): Packet {
  const h = new Header();
  h.bytes(
    'Destination MAC',
    mac(o.dst),
    o.dst === BROADCAST ? `${o.dst} (broadcast)` : o.dst,
    'The hardware address of the next device on this local link. ' +
      'Network cards ignore frames that are not addressed to them, unless the address is the broadcast address ff:ff:ff:ff:ff:ff.',
  );
  h.bytes(
    'Source MAC',
    mac(o.src),
    o.src,
    'The hardware address of the network card that sent this frame. It only has meaning on the local link: ' +
      'every router along the way builds a brand new frame with its own MAC addresses.',
  );
  const t = ETHERTYPES[o.type];
  h.u16('EtherType', t, `0x${hex16(t)} (${o.type})`, 'Tells the receiver which protocol is inside the frame so it can hand the payload to the right code.');

  // Frames shorter than 60 bytes (64 with the 4-byte FCS the card adds) are padded on the wire.
  const len = 14 + payload.bytes.length;
  let trailer: Header | undefined;
  if (len < 60) {
    trailer = new Header();
    trailer.bytes(
      'Padding',
      new Array(60 - len).fill(0),
      `${60 - len} zero bytes`,
      'Ethernet frames must be at least 64 bytes long, including a 4-byte checksum (FCS) that the network card adds and removes in hardware. Short frames are padded with zeros.',
    );
  }
  return layer('Ethernet II', 'eth', h, payload, trailer);
}

export function arp(o: { op: 'request' | 'reply'; senderMac: string; senderIp: string; targetMac: string; targetIp: string }): Packet {
  const h = new Header();
  h.u16('Hardware type', 1, '1 (Ethernet)', 'The kind of link-layer address being resolved.');
  h.u16('Protocol type', 0x0800, '0x0800 (IPv4)', 'The kind of network-layer address being resolved. It reuses the EtherType numbers.');
  h.u8('Hardware size', 6, '6 bytes', 'Length of a MAC address.');
  h.u8('Protocol size', 4, '4 bytes', 'Length of an IPv4 address.');
  h.u16('Opcode', o.op === 'request' ? 1 : 2, o.op === 'request' ? '1 (request)' : '2 (reply)', '1 asks "who has this IP?", 2 answers "I do, and here is my MAC".');
  h.bytes('Sender MAC', mac(o.senderMac), o.senderMac);
  h.bytes('Sender IP', ip(o.senderIp), o.senderIp);
  h.bytes(
    'Target MAC',
    mac(o.targetMac),
    o.targetMac,
    o.op === 'request' ? 'Unknown yet, so it is left as zeros. Finding it is the whole point of the request.' : undefined,
  );
  h.bytes('Target IP', ip(o.targetIp), o.targetIp);
  return layer('ARP', 'arp', h);
}
