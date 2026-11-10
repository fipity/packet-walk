// DHCP (RFC 2131, options from RFC 2132).
import { Header, layer, ip, mac, hex16, type Packet } from '../bytes';

export type DhcpType = 'DISCOVER' | 'OFFER' | 'REQUEST' | 'ACK';
const TYPE_CODE: Record<DhcpType, number> = { DISCOVER: 1, OFFER: 2, REQUEST: 3, ACK: 5 };

export interface DhcpOpts {
  type: DhcpType;
  xid: number;
  clientMac: string;
  /** Address being offered/assigned (OFFER, ACK) or requested (REQUEST). */
  addr: string;
  server: string;
  router: string;
  dns: string;
  hostname: string;
}

const PARAMS: [number, string][] = [
  [1, 'subnet mask'],
  [3, 'router'],
  [6, 'DNS server'],
  [15, 'domain name'],
  [51, 'lease time'],
];

function option(h: Header, code: number, name: string, data: number[], value: string, info?: string): void {
  h.bytes(`Option ${code}: ${name}`, [code, data.length, ...data], value, info ?? `Options are type–length–value: one byte for the code (${code}), one for the length (${data.length}), then the data.`);
}

export function dhcp(o: DhcpOpts): Packet {
  const fromServer = o.type === 'OFFER' || o.type === 'ACK';
  const h = new Header();
  h.u8('Op', fromServer ? 2 : 1, fromServer ? '2 (reply)' : '1 (request)', 'DHCP reuses the older BOOTP format, which only knows "request" (from a client) and "reply" (from a server). The real message type is in option 53.');
  h.u8('Hardware type', 1, '1 (Ethernet)');
  h.u8('Hardware address length', 6, '6 bytes');
  h.u8('Hops', 0, '0', 'Incremented by relay agents that forward DHCP between networks.');
  h.u32('Transaction ID', o.xid, `0x${hex16(o.xid >>> 16)}${hex16(o.xid & 0xffff)}`, 'A random number chosen by the client. Every message in this exchange carries it, so the client can ignore answers meant for someone else.');
  h.u16('Seconds elapsed', 0, '0');
  h.u16('Flags', 0, '0 (unicast replies OK)', 'If the top bit were set, the client would be asking the server to broadcast its replies, because it cannot receive unicast yet.');
  h.bytes('Client IP (ciaddr)', ip('0.0.0.0'), '0.0.0.0', 'Only filled in when the client already has a working address, for example when renewing a lease.');
  h.bytes('Your IP (yiaddr)', ip(fromServer ? o.addr : '0.0.0.0'), fromServer ? o.addr : '0.0.0.0', fromServer ? 'The address the server is giving the client.' : 'Filled in by the server.');
  h.bytes('Server IP (siaddr)', ip('0.0.0.0'), '0.0.0.0', 'Used for network booting. Not needed here.');
  h.bytes('Relay agent IP (giaddr)', ip('0.0.0.0'), '0.0.0.0', 'Set by a relay agent when the DHCP server is on another network.');
  h.bytes('Client hardware address', [...mac(o.clientMac), ...new Array(10).fill(0)], o.clientMac, 'The client\'s MAC address, padded to 16 bytes. The server uses it to recognise the client and send replies to the right network card.');
  h.bytes('Server host name', new Array(64).fill(0), '(empty, 64 bytes)', 'An old BOOTP field. It is still present, but nearly always zero.');
  h.bytes('Boot file name', new Array(128).fill(0), '(empty, 128 bytes)', 'Used by machines that boot over the network. Zero here.');
  h.u32('Magic cookie', 0x63825363, '0x63825363 (DHCP)', 'Marks the start of DHCP options, which is how a DHCP message is told apart from plain BOOTP.');

  const t = TYPE_CODE[o.type];
  option(h, 53, 'Message type', [t], `${t} (${o.type})`, 'The most important option: DISCOVER, OFFER, REQUEST or ACK.');
  if (o.type === 'REQUEST') {
    option(h, 50, 'Requested IP', ip(o.addr), o.addr, 'The address from the offer the client is accepting.');
  }
  if (o.type !== 'DISCOVER') {
    option(h, 54, 'Server identifier', ip(o.server), o.server, o.type === 'REQUEST' ? 'Names the server whose offer was chosen. Any other servers that sent offers see this broadcast and withdraw theirs.' : 'Which DHCP server is talking.');
  }
  if (fromServer) {
    option(h, 51, 'Lease time', [0, 1, 0x51, 0x80], '86400 seconds (1 day)', 'How long the client may use the address. It will try to renew after half the lease.');
    option(h, 1, 'Subnet mask', ip('255.255.255.0'), '255.255.255.0', 'Addresses 192.168.1.0–255 are on the local network. Anything else goes through the router.');
    option(h, 3, 'Router', ip(o.router), o.router, 'The default gateway: where to send packets bound for the rest of the internet.');
    option(h, 6, 'DNS server', ip(o.dns), o.dns, 'Where to send DNS questions.');
  } else {
    option(h, 12, 'Host name', Array.from(o.hostname, (c) => c.charCodeAt(0)), JSON.stringify(o.hostname), 'The client\'s name. Many routers show it in their list of connected devices.');
    option(h, 55, 'Parameter request list', PARAMS.map(([c]) => c), PARAMS.map(([c, n]) => `${c} ${n}`).join(', '), 'The settings the client would like the server to send back.');
  }
  h.u8('Option 255: End', 255, 'end of options');
  if (h.length < 300) {
    h.bytes('Padding', new Array(300 - h.length).fill(0), `${300 - h.length} zero bytes`, 'BOOTP messages are padded to at least 300 bytes, because some old relays and servers reject anything shorter.');
  }
  return layer(`DHCP ${o.type}`, 'dhcp', h);
}
