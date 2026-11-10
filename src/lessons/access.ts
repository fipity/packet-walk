// Lessons for PPPoE, IPsec (IKEv2 + ESP) and Modbus/TCP.
import { randomBytes } from '../bytes';
import { ethernet, BROADCAST } from '../protocols/link';
import { ipv4, icmpEcho } from '../protocols/inet';
import {
  pppoeDiscovery, pppSession, pppControl, chapChallenge, chapResponse, chapSuccess,
  lcpMru, lcpMagic, lcpChap, ipcpAddr, ikeSaInit, ikeAuth, esp, natHash, modbus, u16f, type PppoeTag,
} from '../protocols/tunnels';
import { NET, ON_LAPTOP, TcpConn, udpFromLaptop, udpToLaptop, type Lesson } from './network';

// ------------------------------------------------------------ PPPoE

const WAN_MAC = '02:00:5e:10:00:02';
const AC_MAC = '02:00:00:ac:00:01';
const SESSION = 0x1a2b;
const AC_NAME = 'isp-bras-1';
const HOST_UNIQ = Array.from(randomBytes(9601, 4));
const COOKIE = Array.from(randomBytes(9602, 16));
const CHALLENGE = randomBytes(9603, 16);
const WAN = 'Captured on the router\'s WAN link (fibre/DSL modem side)';

const tag = {
  service: { type: 0x0101, name: 'Service-Name', value: [], display: '(any)', info: 'An empty service name means "any service will do". ISPs can offer several services on one line.' } as PppoeTag,
  hostUniq: { type: 0x0103, name: 'Host-Uniq', value: HOST_UNIQ, display: HOST_UNIQ.map((b) => b.toString(16).padStart(2, '0')).join(' '), info: 'A value the router makes up and the access concentrator echoes back, so the router can match replies to its own requests.' } as PppoeTag,
  acName: { type: 0x0102, name: 'AC-Name', value: Array.from(AC_NAME, (c) => c.charCodeAt(0)), display: AC_NAME, info: 'The name of the access concentrator (often called a BRAS or BNG): the ISP box that terminates PPPoE sessions for thousands of customers.' } as PppoeTag,
  cookie: { type: 0x0104, name: 'AC-Cookie', value: COOKIE, display: '16 bytes', info: 'An opaque token the router must send back in PADR. It lets the concentrator ignore floods of fake requests.' } as PppoeTag,
};

const toAc = (pkt: ReturnType<typeof pppoeDiscovery>, discovery: boolean, broadcast = false) =>
  ethernet({ dst: broadcast ? BROADCAST : AC_MAC, src: WAN_MAC, type: discovery ? 'PPPoED' : 'PPPoES' }, pkt);
const fromAc = (pkt: ReturnType<typeof pppoeDiscovery>, discovery: boolean) =>
  ethernet({ dst: WAN_MAC, src: AC_MAC, type: discovery ? 'PPPoED' : 'PPPoES' }, pkt);

const pppoeLesson: Lesson = {
  id: 'pppoe',
  title: 'PPPoE',
  protocols: ['PPPoE', 'PPP', 'CHAP', 'IPCP'],
  labels: {
    router: { label: 'Home router', addr: 'WAN: PPPoE client' },
    internet: { label: 'ISP access concentrator', addr: AC_NAME },
  },
  intro:
    'Many DSL and fibre connections do not just plug the home router into the internet. The router first sets up a PPP session over Ethernet with the ISP, logs in with a username and password, and only then gets its public IP address. ' +
    'This is why routers ask for "PPPoE username and password" during setup.',
  steps: [
    {
      from: 'router', to: 'internet', capture: WAN,
      title: 'PADI: "Any access concentrators?"',
      text:
        'Discovery starts with a broadcast on the ISP-facing Ethernet link, using EtherType 0x8863 (PPPoE discovery). The router does not know the ISP\'s MAC address yet, so it asks whoever can serve it.',
      packet: toAc(pppoeDiscovery(0x09, 0, [tag.service, tag.hostUniq]), true, true),
    },
    {
      from: 'internet', to: 'router', capture: WAN,
      title: 'PADO: an offer',
      text: 'The ISP\'s access concentrator answers with its name and a cookie. If several concentrators answer, the router picks one.',
      packet: fromAc(pppoeDiscovery(0x07, 0, [tag.acName, tag.service, tag.hostUniq, tag.cookie]), true),
    },
    {
      from: 'router', to: 'internet', capture: WAN,
      title: 'PADR: "I\'ll take this one."',
      text: 'The router sends a unicast request to the chosen concentrator, returning the cookie.',
      packet: toAc(pppoeDiscovery(0x19, 0, [tag.service, tag.hostUniq, tag.cookie]), true),
    },
    {
      from: 'internet', to: 'router', capture: WAN,
      title: 'PADS: session 0x1a2b',
      text: 'The concentrator assigns a session ID. From now on, frames use EtherType 0x8864 (PPPoE session) and carry PPP, the same Point-to-Point Protocol that dial-up modems used.',
      packet: fromAc(pppoeDiscovery(0x65, SESSION, [tag.service, tag.hostUniq]), true),
    },
    {
      from: 'router', to: 'internet', capture: WAN,
      title: 'LCP Configure-Request: link options',
      text:
        'PPP starts with the Link Control Protocol, where each side proposes options for the link. The router asks for an MRU of 1492 bytes, since PPPoE adds 8 bytes inside a standard 1500-byte Ethernet frame. ' +
        'Notice the nesting: Ethernet, then PPPoE, then PPP, then LCP.',
      packet: toAc(pppSession(SESSION, 0xc021, pppControl('LCP', 1, 1, [lcpMru(1492), lcpMagic(9610)])), false),
    },
    {
      from: 'internet', to: 'router', capture: WAN,
      title: 'LCP Configure-Request from the ISP: "Use CHAP."',
      text: 'The concentrator sends its own request, which includes the Authentication-Protocol option: the router must log in with CHAP. Each side then acknowledges the other\'s request with a Configure-Ack (not shown).',
      packet: fromAc(pppSession(SESSION, 0xc021, pppControl('LCP', 1, 7, [lcpMru(1492), lcpChap, lcpMagic(9611)])), false),
    },
    {
      from: 'internet', to: 'router', capture: WAN,
      title: 'CHAP Challenge',
      text: 'Authentication starts with a random challenge from the ISP.',
      packet: fromAc(pppSession(SESSION, 0xc223, chapChallenge(1, CHALLENGE, AC_NAME)), false),
    },
    {
      from: 'router', to: 'internet', capture: WAN,
      title: 'CHAP Response: proof of the password',
      text: 'The router answers with MD5(identifier + password + challenge) and its username. The hash in this packet is the real one for the demo password "dsl-password", and the password itself never appears in it.',
      packet: toAc(pppSession(SESSION, 0xc223, chapResponse(1, 'dsl-password', CHALLENGE, 'customer1234@isp.example')), false),
    },
    {
      from: 'internet', to: 'router', capture: WAN,
      title: 'CHAP Success',
      text: 'The ISP checks the hash, usually by asking a RADIUS server behind the scenes (see the RADIUS lesson), and lets the router in.',
      packet: fromAc(pppSession(SESSION, 0xc223, chapSuccess(1, 'Login ok')), false),
    },
    {
      from: 'router', to: 'internet', capture: WAN,
      title: 'IPCP Configure-Request: "What is my address?"',
      text: 'Now the IP Control Protocol configures IPv4 on the link. The router asks for IP address 0.0.0.0 and DNS servers 0.0.0.0, which means "please assign me some".',
      packet: toAc(pppSession(SESSION, 0x8021, pppControl('IPCP', 1, 1, [
        ipcpAddr(3, 'IP-Address', '0.0.0.0'),
        ipcpAddr(129, 'Primary DNS', '0.0.0.0'),
      ])), false),
    },
    {
      from: 'internet', to: 'router', capture: WAN,
      title: 'IPCP Configure-Nak: "Use 198.51.100.7."',
      text: 'The ISP rejects the zeros by suggesting real values: the public address 198.51.100.7 (the WAN address used in the NAT lessons) and a DNS server. The router asks again with these values and gets a Configure-Ack (not shown).',
      packet: fromAc(pppSession(SESSION, 0x8021, pppControl('IPCP', 3, 1, [
        ipcpAddr(3, 'IP-Address', NET.router.wan, 'The router\'s public IPv4 address for this session. It often changes when the session reconnects.'),
        ipcpAddr(129, 'Primary DNS', NET.dns.ip),
      ])), false),
    },
    {
      from: 'router', to: 'server', capture: WAN,
      title: 'IPv4 traffic over PPPoE',
      text:
        'The router is online. Every IP packet leaving it now travels as Ethernet, then PPPoE session, then PPP (protocol 0x0021), then IPv4: here, a ping that started on the laptop and was translated by NAT. ' +
        'The extra 8 bytes are why the largest packet is 1492 bytes instead of 1500.',
      packet: toAc(pppSession(SESSION, 0x0021, ipv4({ src: NET.router.wan, dst: NET.server.ip, proto: 'ICMP', ttl: 63, id: 0x4a10 },
        icmpEcho({ reply: false, id: 0x1f2b, seq: 1, data: randomBytes(9620, 48) }))), false),
    },
  ],
};

// ------------------------------------------------------------ IPsec

const VPN = '203.0.113.60';
const SPI_I = randomBytes(9701, 8);
const SPI_R = randomBytes(9702, 8);
const ZERO8 = new Uint8Array(8);
const ESP_OUT = 0xc5a1f203;
const ESP_IN = 0x7e2d9a14;

const ipsecLesson: Lesson = {
  id: 'ipsec',
  title: 'IPsec (IKEv2 + ESP)',
  protocols: ['IKEv2', 'ESP', 'IPsec', 'UDP'],
  labels: { server: { label: 'IPsec VPN gateway', addr: VPN } },
  intro:
    'IPsec secures traffic at the IP layer itself. It is used for site-to-site links between offices and for many company VPNs. IKEv2 negotiates keys in two exchanges, then ESP carries the encrypted packets. ' +
    'Because the laptop is behind a NAT router, you can also watch IKEv2 detect the NAT and move everything to UDP port 4500.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'IKE_SA_INIT request',
      text:
        'The laptop proposes algorithms (AES-GCM, SHA-256, Curve25519), sends its Diffie–Hellman public key and a nonce, and adds two NAT-detection hashes of the addresses it believes are in use. The whole message travels unencrypted over UDP port 500.',
      packet: udpFromLaptop(VPN, 500, 500, ikeSaInit({ spiI: SPI_I, spiR: ZERO8, response: false, seed: 9710, natSrc: natHash(SPI_I, ZERO8, NET.laptop.ip, 500), natDst: natHash(SPI_I, ZERO8, VPN, 500) })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'IKE_SA_INIT response: NAT detected',
      text:
        'The gateway accepts the proposal and sends its own key share. Its NAT_DETECTION_DESTINATION_IP hash covers the address it actually saw, 198.51.100.7, the router\'s public address. That does not match the laptop\'s own address, so both sides know a NAT is in the path. ' +
        'Both sides can now derive keys, and everything after this is encrypted.',
      packet: udpToLaptop(VPN, 500, 500, ikeSaInit({ spiI: SPI_I, spiR: SPI_R, response: true, seed: 9720, natSrc: natHash(SPI_I, SPI_R, VPN, 500), natDst: natHash(SPI_I, SPI_R, NET.router.wan, 500) })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'IKE_AUTH request on port 4500',
      text:
        'Because of the NAT, the laptop moves to UDP port 4500 ("NAT traversal"). Plain ESP has no ports, which most home routers cannot track through NAT. ' +
        'Encrypted inside: the laptop\'s identity, proof that it holds its certificate or key, the traffic it wants tunnelled, and a request for an internal address.',
      packet: udpFromLaptop(VPN, 4500, 4500, ikeAuth({ spiI: SPI_I, spiR: SPI_R, response: false, plaintext: 412, seed: 9730, hidden: 'IDi, CERT, AUTH, a CHILD_SA proposal for ESP, traffic selectors (all traffic to 10.10.0.0/16) and a CP request for an internal address' })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'IKE_AUTH response: tunnel ready',
      text: 'The gateway proves its own identity, assigns the laptop the internal address 10.10.8.2, and agrees on the first child SA: a pair of ESP security associations, one for each direction, each with its own SPI and keys.',
      packet: udpToLaptop(VPN, 4500, 4500, ikeAuth({ spiI: SPI_I, spiR: SPI_R, response: true, plaintext: 980, seed: 9740, hidden: 'IDr, CERT, AUTH, the accepted CHILD_SA (ESP SPI 0x7e2d9a14 inbound, 0xc5a1f203 outbound), traffic selectors and the assigned address 10.10.8.2' })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'ESP: an encrypted packet',
      text:
        'The laptop pings an internal server at 10.10.0.5. In tunnel mode, the whole inner IP packet (from 10.10.8.2 to 10.10.0.5) is encrypted and placed inside ESP, behind a new outer IP header addressed to the gateway. ' +
        'On the wire there is only a SPI, a sequence number and ciphertext. Without NAT, ESP would be IP protocol 50, sent directly with no UDP header.',
      packet: udpFromLaptop(VPN, 4500, 4500, esp({ spi: ESP_OUT, seq: 1, inner: 84, seed: 9750, hidden: 'an 84-byte IPv4 ICMP echo request from 10.10.8.2 to 10.10.0.5' })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'ESP: the reply',
      text: 'The reply comes back on the other SA, with a different SPI. The gateway decrypted the request, forwarded the inner packet onto the company LAN, and encrypted the answer on its way back.',
      packet: udpToLaptop(VPN, 4500, 4500, esp({ spi: ESP_IN, seq: 1, inner: 84, seed: 9760, hidden: 'an 84-byte IPv4 ICMP echo reply from 10.10.0.5 to 10.10.8.2' })),
    },
  ],
};

// ------------------------------------------------------------ Modbus/TCP

const PLC = { ip: '192.168.1.50', mac: '02:00:00:fa:00:50' };
const plcIds = [0x5000, 0x0100];
const mb = new TcpConn(PLC.ip, 49900, 502, 0x13572468, 0x8899aabb, {
  clientIp: NET.laptop.ip,
  frameClient: (dst, seg) => ethernet({ dst: PLC.mac, src: NET.laptop.mac, type: 'IPv4' }, ipv4({ src: NET.laptop.ip, dst, proto: 'TCP', ttl: 64, id: plcIds[0]++ }, seg)),
  frameServer: (src, seg) => ethernet({ dst: NET.laptop.mac, src: PLC.mac, type: 'IPv4' }, ipv4({ src, dst: NET.laptop.ip, proto: 'TCP', ttl: 64, id: plcIds[1]++ }, seg)),
});
mb.client(['SYN']);
mb.server(['SYN', 'ACK']);
mb.client(['ACK']);

const REG_INFO = 'Holding registers are 16-bit values. Their meaning comes from the device\'s manual, not from the protocol: here, register 0 is temperature in tenths of a degree.';

const modbusLesson: Lesson = {
  id: 'modbus',
  title: 'Modbus/TCP',
  protocols: ['Modbus', 'TCP'],
  labels: { router: { label: 'PLC (Modbus server)', addr: `${PLC.ip} · port 502`, icon: 'plc' } },
  intro:
    'Factories, water plants and building systems are run by PLCs (programmable logic controllers). Modbus, from 1979, is still one of the most common ways to read and control them. Here an engineering laptop on the plant network reads sensors from a PLC and controls a pump. ' +
    'Notice that nothing is authenticated or encrypted.',
  steps: [
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'Read Holding Registers (function 3)',
      text: 'The client asks for 4 registers starting at address 0. A Modbus/TCP message is a 7-byte MBAP header (transaction ID, protocol, length, unit ID) followed by the classic Modbus PDU: a function code and its data.',
      packet: mb.client(['PSH', 'ACK'], modbus({ tid: 1, unit: 1, fn: 3, response: false, data: [u16f('Starting address', 0, '0 (register 40001)', 'Addresses count from 0 on the wire. Manuals often number holding registers from 40001.'), u16f('Quantity', 4, '4 registers')] })),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'The sensor values',
      text: 'The PLC returns 8 bytes: four big-endian 16-bit registers. Decoded with the device\'s register map: 21.5 °C tank temperature, a setpoint of 22.0 °C, a pump speed of 1450 rpm, and status 1 (running).',
      packet: mb.server(['PSH', 'ACK'], modbus({ tid: 1, unit: 1, fn: 3, response: true, data: [
        { name: 'Byte count', bytes: [8], value: '8 bytes' },
        u16f('Register 0: temperature', 215, '215 → 21.5 °C', REG_INFO),
        u16f('Register 1: setpoint', 220, '220 → 22.0 °C'),
        u16f('Register 2: pump speed', 1450, '1450 rpm'),
        u16f('Register 3: status', 1, '1 (running)'),
      ] })),
    },
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'Write Single Register (function 6)',
      text: 'The operator raises the setpoint to 23.0 °C by writing 230 to register 1. The PLC will act on it at once. Modbus has no login, so any device that can reach port 502 could send this.',
      packet: mb.client(['PSH', 'ACK'], modbus({ tid: 2, unit: 1, fn: 6, response: false, data: [u16f('Register address', 1, '1 (setpoint)'), u16f('Value', 230, '230 → 23.0 °C')] })),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'Echo: write confirmed',
      text: 'A successful write is answered by echoing the request back.',
      packet: mb.server(['PSH', 'ACK'], modbus({ tid: 2, unit: 1, fn: 6, response: true, data: [u16f('Register address', 1, '1 (setpoint)'), u16f('Value', 230, '230 → 23.0 °C')] })),
    },
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'Write Single Coil (function 5): stop the pump',
      text: 'Coils are single on/off bits, such as relays and motors. Writing 0x0000 to coil 0 switches the pump off. The value 0xFF00 would switch it on, and any other value is invalid.',
      packet: mb.client(['PSH', 'ACK'], modbus({ tid: 3, unit: 1, fn: 5, response: false, data: [u16f('Coil address', 0, '0 (pump)'), u16f('Value', 0x0000, '0x0000 (OFF)', '0xFF00 = ON, 0x0000 = OFF.')] })),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'Echo: pump off',
      text: 'Confirmed. In a real plant, this is a physical machine stopping.',
      packet: mb.server(['PSH', 'ACK'], modbus({ tid: 3, unit: 1, fn: 5, response: true, data: [u16f('Coil address', 0, '0 (pump)'), u16f('Value', 0x0000, '0x0000 (OFF)')] })),
    },
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'Asking for a register that doesn\'t exist',
      text: 'Read 2 registers at address 100, beyond this PLC\'s register map.',
      packet: mb.client(['PSH', 'ACK'], modbus({ tid: 4, unit: 1, fn: 3, response: false, data: [u16f('Starting address', 100, '100'), u16f('Quantity', 2, '2 registers')] })),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'Exception response',
      text:
        'Errors come back with the function code\'s top bit set (0x83) and a 1-byte exception code: 2 means "illegal data address". ' +
        'Because Modbus trusts anyone who can reach it, plant networks are kept separate from office and internet traffic with firewalls and network segmentation. Newer deployments can use Modbus/TCP Security (Modbus over TLS on port 802).',
      packet: mb.server(['PSH', 'ACK'], modbus({ tid: 4, unit: 1, fn: 0x83, response: true, data: [{ name: 'Exception code', bytes: [2], value: '2 (illegal data address)' }] })),
    },
  ],
};

export const ACCESS = { pppoeLesson, ipsecLesson, modbusLesson };
