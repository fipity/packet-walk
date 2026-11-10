// Lessons for IPv6, BGP and NTP.
import { randomBytes, type Packet } from '../bytes';
import { ethernet } from '../protocols/link';
import { ipv4 } from '../protocols/inet';
import {
  ipv6, multicastMac, solicitedNode, routerSolicitation, routerAdvertisement,
  neighborSolicitation, neighborAdvertisement, echo6,
} from '../protocols/ipv6';
import { bgpOpen, bgpKeepalive, bgpUpdate, ntp } from '../protocols/infra';
import { NET, ON_LAPTOP, TcpConn, udpFromLaptop, udpToLaptop, type Lesson } from './network';

// ------------------------------------------------------------ IPv6

// The laptop builds its addresses from its MAC (EUI-64): 02:1a:2b:3c:4d:5e → flip bit 7 → 001a:2bff:fe3c:4d5e.
const V6 = {
  laptopLL: 'fe80::1a:2bff:fe3c:4d5e',
  laptop: '2001:db8:1:0:1a:2bff:fe3c:4d5e',
  prefix: '2001:db8:1::',
  router: 'fe80::1',
  server: '2001:db8:80::80',
  dns: '2001:db8:53::53',
};
const laptopSN = solicitedNode(V6.laptop);

function frame6(srcMac: string, dstMac: string, src: string, dst: string, hopLimit: number, msg: Packet): Packet {
  return ethernet({ dst: dstMac, src: srcMac, type: 'IPv6' }, ipv6({ src, dst, hopLimit }, msg));
}

const ping6Data = () => {
  const d = new Uint8Array(48);
  d.set(randomBytes(6060, 8), 0);
  for (let i = 8; i < 48; i++) d[i] = 0x08 + i;
  return d;
};

const ipv6Lesson: Lesson = {
  id: 'ipv6',
  title: 'IPv6',
  protocols: ['IPv6', 'ICMPv6'],
  labels: {
    laptop: { label: 'Laptop', addr: '…:1a:2bff:fe3c:4d5e' },
    router: { label: 'Home router', addr: 'fe80::1 · 2001:db8:1::/64' },
    dns: { label: 'DNS resolver', addr: V6.dns },
    server: { label: 'www.example.com', addr: V6.server },
  },
  intro:
    'IPv4 has only about 4 billion addresses, which is why home networks hide behind NAT. IPv6 addresses are 128 bits long, so every device can have its own public address. ' +
    'IPv6 also replaces ARP and much of DHCP with ICMPv6 Neighbor Discovery. Here a laptop configures itself and pings a server.',
  steps: [
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'Router Solicitation: "Any routers here?"',
      text:
        'As soon as the laptop joins the network, it gives itself a link-local address (fe80::…) derived from its MAC address. It then multicasts a Router Solicitation to ff02::2, the all-routers group. ' +
        'Notice the IPv6 header: a fixed 40 bytes, no checksum and no fragmentation fields, so routers can process it quickly.',
      packet: frame6(NET.laptop.mac, multicastMac('ff02::2'), V6.laptopLL, 'ff02::2', 255, routerSolicitation(V6.laptopLL, NET.laptop.mac)),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'Router Advertisement: "Here\'s your network."',
      text:
        'The router answers to all nodes (ff02::1) with the network prefix 2001:db8:1::/64, the link MTU, a DNS server and its own MAC address. ' +
        'The "A" flag invites the laptop to build its own global address, which is called SLAAC (stateless address autoconfiguration). It takes the prefix and adds a 64-bit interface ID: ' +
        '2001:db8:1:0:1a:2bff:fe3c:4d5e. (Modern systems use a random interface ID instead of one derived from the MAC address, for privacy.)',
      packet: frame6(NET.router.mac, multicastMac('ff02::1'), V6.router, 'ff02::1', 255,
        routerAdvertisement({ src: V6.router, dst: 'ff02::1', mac: NET.router.mac, prefix: V6.prefix, dns: V6.dns })),
    },
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'Duplicate Address Detection',
      text:
        'Before using its new address, the laptop checks that nobody else has it. It sends a Neighbor Solicitation for its own address, from the unspecified address "::", to that address\'s solicited-node multicast group. ' +
        'If anyone answers, the address is taken. Silence for about a second means it is free.',
      packet: frame6(NET.laptop.mac, multicastMac(laptopSN), '::', laptopSN, 255, neighborSolicitation({ src: '::', dst: laptopSN, target: V6.laptop })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Ping over IPv6',
      text:
        'The laptop pings the server at 2001:db8:80::80. The Ethernet frame goes to the router\'s MAC address, which the laptop learned from the Router Advertisement, so no extra lookup was needed. ' +
        'There is no NAT: the source address is the laptop\'s own public address, all the way to the server.',
      packet: frame6(NET.laptop.mac, NET.router.mac, V6.laptop, V6.server, 64, echo6({ src: V6.laptop, dst: V6.server, reply: false, id: 0x2a17, seq: 1, data: ping6Data() })),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'Neighbor Solicitation: the router looks up the laptop',
      text:
        'The reply has reached the router, but the router does not know which MAC address owns 2001:db8:1:0:1a:2bff:fe3c:4d5e. Where IPv4 would broadcast an ARP request to everyone, IPv6 multicasts to ff02::1:ff3c:4d5e. ' +
        'Only devices whose address ends in 3c:4d5e listen to that group.',
      packet: frame6(NET.router.mac, multicastMac(laptopSN), V6.router, laptopSN, 255, neighborSolicitation({ src: V6.router, dst: laptopSN, target: V6.laptop, mac: NET.router.mac })),
    },
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'Neighbor Advertisement: "That\'s me."',
      text: 'The laptop answers directly to the router with its MAC address. This is the IPv6 equivalent of an ARP reply, but it is an ordinary ICMPv6 message inside an IPv6 packet.',
      packet: frame6(NET.laptop.mac, NET.router.mac, V6.laptop, V6.router, 255, neighborAdvertisement({ src: V6.laptop, dst: V6.router, target: V6.laptop, mac: NET.laptop.mac })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Echo reply delivered',
      text: 'Now the router can forward the echo reply. Its hop limit arrived as 56, eight routers after the server sent it with 64.',
      packet: frame6(NET.router.mac, NET.laptop.mac, V6.server, V6.laptop, 56, echo6({ src: V6.server, dst: V6.laptop, reply: true, id: 0x2a17, seq: 1, data: ping6Data() })),
    },
  ],
};

// ------------------------------------------------------------ BGP

const ISP = { ip: '192.0.2.1', mac: '02:00:00:0a:00:01', as: 64500 };
const HOST = { ip: '192.0.2.2', mac: '02:00:00:0b:00:01', as: 64511 };
const bgpIpId = [0x1100, 0x2200];
const BETWEEN = 'Captured on the link between the two border routers';

const bgpConn = new TcpConn(ISP.ip, 50612, 179, 0x0b6f3e21, 0x5a2c94d0, {
  clientIp: HOST.ip,
  frameClient: (dst, seg) => ethernet({ dst: ISP.mac, src: HOST.mac, type: 'IPv4' }, ipv4({ src: HOST.ip, dst, proto: 'TCP', ttl: 1, id: bgpIpId[0]++ }, seg)),
  frameServer: (src, seg) => ethernet({ dst: HOST.mac, src: ISP.mac, type: 'IPv4' }, ipv4({ src, dst: HOST.ip, proto: 'TCP', ttl: 1, id: bgpIpId[1]++ }, seg)),
});
bgpConn.client(['SYN']);
bgpConn.server(['SYN', 'ACK']);
bgpConn.client(['ACK']);

const bgpLesson: Lesson = {
  id: 'bgp',
  title: 'BGP',
  protocols: ['BGP', 'TCP'],
  labels: {
    internet: { label: 'ISP · AS64500', addr: ISP.ip },
    server: { label: 'Hosting · AS64511', addr: HOST.ip },
  },
  intro:
    'The internet is about 75,000 separate networks, called Autonomous Systems, each run by an ISP, a cloud provider, a university or a company. BGP is how they tell each other which addresses they can reach. ' +
    'Here, the hosting company that runs www.example.com (AS64511) connects to its ISP (AS64500) and announces 203.0.113.0/24.',
  steps: [
    {
      from: 'server', to: 'internet', capture: BETWEEN,
      title: 'OPEN: "I\'m AS64511."',
      text:
        'BGP runs over an ordinary TCP connection to port 179 (its handshake isn\'t shown). The first message is OPEN: the BGP version, the sender\'s AS number, a hold time, a router ID and a list of optional capabilities. ' +
        'Look at the IP TTL: it is 1. External BGP peers are usually directly connected, so a TTL of 1 means the packet cannot have come from further away.',
      packet: bgpConn.client(['PSH', 'ACK'], bgpOpen({ as: HOST.as, holdTime: 90, id: HOST.ip })),
    },
    {
      from: 'internet', to: 'server', capture: BETWEEN,
      title: 'OPEN: "I\'m AS64500."',
      text: 'The ISP sends its own OPEN. Each side checks that the AS number is the one it was configured to expect. A mismatch ends the session with a NOTIFICATION message.',
      packet: bgpConn.server(['PSH', 'ACK'], bgpOpen({ as: ISP.as, holdTime: 90, id: ISP.ip })),
    },
    {
      from: 'server', to: 'internet', capture: BETWEEN,
      title: 'KEEPALIVE: "Accepted."',
      text: 'A KEEPALIVE is just the 19-byte header. Here it confirms the other side\'s OPEN. Later, peers send one every 30 seconds (a third of the hold time) to show they are still alive.',
      packet: bgpConn.client(['PSH', 'ACK'], bgpKeepalive()),
    },
    {
      from: 'internet', to: 'server', capture: BETWEEN,
      title: 'KEEPALIVE: session established',
      text: 'Both sides have accepted, and the session moves to the Established state. Now they can exchange routes.',
      packet: bgpConn.server(['PSH', 'ACK'], bgpKeepalive()),
    },
    {
      from: 'server', to: 'internet', capture: BETWEEN,
      title: 'UPDATE: "203.0.113.0/24 is reachable through me."',
      text:
        'The hosting company announces its block of addresses. The AS_PATH is just [64511], since the route starts here. The ISP will pass it on to its own peers with its own number added in front: [64500, 64511]. ' +
        'Within minutes, routers all over the world know that traffic for www.example.com should head toward AS64500.',
      packet: bgpConn.client(['PSH', 'ACK'], bgpUpdate({ announce: { prefix: '203.0.113.0', len: 24, asPath: [HOST.as], nextHop: HOST.ip } })),
    },
    {
      from: 'internet', to: 'server', capture: BETWEEN,
      title: 'UPDATE: a default route from the ISP',
      text:
        'In the other direction, a small customer does not need all of the roughly one million routes on the internet. The ISP sends just a default route, 0.0.0.0/0, meaning "send me everything you don\'t have a better route for". ' +
        'A zero-length prefix needs no address bytes at all.',
      packet: bgpConn.server(['PSH', 'ACK'], bgpUpdate({ announce: { prefix: '0.0.0.0', len: 0, asPath: [ISP.as], nextHop: ISP.ip } })),
    },
    {
      from: 'server', to: 'internet', capture: BETWEEN,
      title: 'UPDATE: withdrawing the route',
      text:
        'If the hosting company takes the network down for maintenance, it withdraws the prefix, and the withdrawal ripples across the internet. ' +
        'BGP relies largely on trust: if another network wrongly announces someone else\'s prefix, traffic can be hijacked. Systems like RPKI let networks check who is allowed to announce what.',
      packet: bgpConn.client(['PSH', 'ACK'], bgpUpdate({ withdraw: { prefix: '203.0.113.0', len: 24 } })),
    },
  ],
};

// ------------------------------------------------------------ NTP

const NTP_IP = '203.0.113.123';
const NTP_PORT = 41837;
const t0 = Date.UTC(2026, 10, 11, 9, 30, 0) / 1000;
const t1 = t0 + 64;
const SERVER = { stratum: 2, poll: 6, precision: -23, rootDelay: 0.0153, rootDispersion: 0.0211, refId: '192.0.2.123', reference: t0 - 37.25 };
const CLIENT = { stratum: 0, precision: -20, rootDelay: 0, rootDispersion: 0, refId: '', reference: 0, origin: 0, receive: 0 };

const ntpLesson: Lesson = {
  id: 'ntp',
  title: 'NTP',
  protocols: ['NTP', 'UDP'],
  labels: { server: { label: 'NTP server', addr: NTP_IP } },
  intro:
    'Certificates, logs, two-factor codes and databases all depend on clocks agreeing. NTP keeps computers synchronised, often to within a millisecond, with four timestamps and a little arithmetic. ' +
    'Here the laptop\'s clock is running 120 ms fast.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Request: "My clock says 09:30:00.120."',
      text:
        'The client sends a 48-byte UDP packet to port 123. The only field that matters is the transmit timestamp, T1: the time on the client\'s own clock as the packet leaves. ' +
        '(Some clients put a random value there instead, since the server only echoes it back. That avoids revealing the client\'s clock to observers.)',
      packet: udpFromLaptop(NTP_IP, NTP_PORT, 123, ntp({ mode: 3, poll: 6, ...CLIENT, transmit: t0 + 0.12 })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Response: three timestamps',
      text:
        'The server echoes T1 back and adds T2 (when the request arrived) and T3 (when the reply left), both from its own accurate clock. The client notes T4, when the reply arrives by its own clock: 09:30:00.144100. ' +
        'Round-trip delay = (T4 − T1) − (T3 − T2) = 24.1 − 0.1 = 24.0 ms. ' +
        'Clock offset = ((T2 − T1) + (T3 − T4)) / 2 = (−108 + −132) / 2 = −120 ms. The laptop is 120 ms fast. ' +
        'The calculation assumes the trip takes the same time in each direction. Any asymmetry becomes error.',
      packet: udpToLaptop(NTP_IP, 123, NTP_PORT, ntp({ mode: 4, ...SERVER, origin: t0 + 0.12, receive: t0 + 0.012, transmit: t0 + 0.0121 })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'One poll later: checking the correction',
      text:
        'Rather than jumping the clock backwards, which could confuse programs that expect time to only move forward, the client "slews" it: it runs the clock slightly slow until the error is gone. ' +
        '64 seconds later (2^6, the poll interval), it asks again.',
      packet: udpFromLaptop(NTP_IP, NTP_PORT, 123, ntp({ mode: 3, poll: 6, ...CLIENT, transmit: t1 + 0.0004 })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'In sync',
      text:
        'Now T4 is 09:31:04.024500 and the offset works out to ((11.6) + (−12.4)) / 2 = −0.4 ms, so the clock is nearly right. As the measurements stay stable, the client will poll less often, up to every 1,024 seconds. ' +
        'The server reports stratum 2: it gets its time from a stratum 1 server (shown in the Reference ID), which is connected to GPS or an atomic clock.',
      packet: udpToLaptop(NTP_IP, 123, NTP_PORT, ntp({ mode: 4, ...SERVER, origin: t1 + 0.0004, receive: t1 + 0.012, transmit: t1 + 0.0121 })),
    },
  ],
};

export const ROUTING = { ipv6Lesson, bgpLesson, ntpLesson };
