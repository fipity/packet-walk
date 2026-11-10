// Lesson content. Each step is a real, fully encoded packet plus a short explanation.
// To translate a string, replace it with an object: { en: '…', es: '…' }.
import { concat, randomBytes } from '../bytes';
import { arp, ethernet, BROADCAST } from '../protocols/link';
import { icmpEcho, icmpTimeExceeded, ipv4 } from '../protocols/inet';
import { dnsQuery, dnsResponse, http, tlsChangeCipherSpec, tlsClientHello, tlsEncrypted, tlsServerHello } from '../protocols/app';
import { GROUPS } from '../groups';
import { MORE } from './more';
import { ROUTING } from './routing';
import { MAIL_LESSONS } from './mail';
import { LOCAL_LESSONS } from './local';
import { ADVANCED } from './advanced';
import { ACCESS } from './access';
import { REALTIME } from './realtime';
import { NET, ON_LAPTOP, TcpConn, fromLaptop, toLaptop, udpFromLaptop, udpToLaptop, type Lesson, type Step } from './network';

// ------------------------------------------------------------ Ethernet & ARP

const arpRequest: Step = {
  from: 'laptop',
  to: 'router',
  capture: ON_LAPTOP,
  title: 'ARP request: "Who has 192.168.1.1?"',
  text:
    'The laptop wants to send something to the internet, so it has to hand the packet to its router at 192.168.1.1. ' +
    'Ethernet and Wi-Fi do not deliver by IP address, though. They deliver by MAC address, and the laptop does not know the router\'s MAC yet. ' +
    'It broadcasts an ARP request to every device on the local network, asking whoever owns 192.168.1.1 to answer.',
  packet: ethernet(
    { dst: BROADCAST, src: NET.laptop.mac, type: 'ARP' },
    arp({ op: 'request', senderMac: NET.laptop.mac, senderIp: NET.laptop.ip, targetMac: '00:00:00:00:00:00', targetIp: NET.router.ip }),
  ),
};

const arpReply: Step = {
  from: 'router',
  to: 'laptop',
  capture: ON_LAPTOP,
  title: 'ARP reply: "192.168.1.1 is at 02:00:5e:10:00:01"',
  text:
    'Only the router recognises its own IP address, so only it replies. The reply goes straight to the laptop (unicast), not to everyone. ' +
    'The laptop stores the answer in its ARP cache for a few minutes. From now on, every packet bound for the internet is put in an Ethernet frame addressed to this MAC.',
  packet: ethernet(
    { dst: NET.laptop.mac, src: NET.router.mac, type: 'ARP' },
    arp({ op: 'reply', senderMac: NET.router.mac, senderIp: NET.router.ip, targetMac: NET.laptop.mac, targetIp: NET.laptop.ip }),
  ),
};

// ------------------------------------------------------------ IP & ICMP

const pingData = (seq: number) => {
  const d = new Uint8Array(48);
  d.set(randomBytes(900 + seq, 8), 0);
  for (let i = 8; i < 48; i++) d[i] = 0x08 + i; // Linux ping's 0x10, 0x11, … pattern
  return d;
};

const echoReq = icmpEcho({ reply: false, id: 0x1f2b, seq: 1, data: pingData(1) });

const pingRequest: Step = {
  from: 'laptop',
  to: 'server',
  capture: ON_LAPTOP,
  title: 'Ping: ICMP echo request',
  text:
    'Running "ping 203.0.113.80" sends an ICMP echo request. You can see the layers nest: the Ethernet frame gets it to the router, and the IPv4 header gets it across the internet. ' +
    'ICMP sits directly on top of IP, with no ports. Notice that the Ethernet destination is the router\'s MAC, while the IP destination is the faraway server.',
  packet: fromLaptop(NET.server.ip, 'ICMP', echoReq),
};

const pingNat: Step = {
  from: 'router',
  to: 'server',
  capture: 'Captured on the router\'s internet side (IP layer only)',
  title: 'The same ping after NAT',
  text:
    'The address 192.168.1.23 is private, so it cannot be used on the public internet. The router does Network Address Translation: it swaps the source for its own public address, 198.51.100.7, and remembers the swap so it can route the reply back. ' +
    'It also lowered the TTL from 64 to 63 and recalculated the IP header checksum. The Ethernet header is gone too, because each link uses its own framing.',
  packet: ipv4({ src: NET.router.wan, dst: NET.server.ip, proto: 'ICMP', ttl: 63, id: 0x4a10 }, echoReq),
};

const pingReply: Step = {
  from: 'server',
  to: 'laptop',
  capture: ON_LAPTOP,
  title: 'ICMP echo reply',
  text:
    'The server swaps the addresses and sends the same data back as an echo reply (type 0). The TTL arrived as 56: the server started at 64, so the reply crossed 8 routers. ' +
    'ping measures the time between the request and this reply. That is the round-trip time.',
  packet: toLaptop(NET.server.ip, 'ICMP', icmpEcho({ reply: true, id: 0x1f2b, seq: 1, data: pingData(1) }), 56, false),
};

const probeIp = ipv4(
  { src: NET.laptop.ip, dst: NET.server.ip, proto: 'ICMP', ttl: 1, id: 0x5b00 },
  icmpEcho({ reply: false, id: 0x1f2c, seq: 1, data: pingData(2) }),
);

const traceProbe: Step = {
  from: 'laptop',
  to: 'router',
  capture: ON_LAPTOP,
  title: 'Traceroute: a probe with TTL 1',
  text:
    'Traceroute exploits the TTL. It sends a probe with TTL set to 1, so the very first router will decrement it to 0 and have to drop it. ' +
    'Then it sends one with TTL 2, then 3, and so on, which makes each router along the path reveal itself in turn.',
  packet: ethernet({ dst: NET.router.mac, src: NET.laptop.mac, type: 'IPv4' }, probeIp),
};

const traceExceeded: Step = {
  from: 'router',
  to: 'laptop',
  capture: ON_LAPTOP,
  title: 'ICMP time exceeded from the first hop',
  text:
    'The router drops the probe and sends back an ICMP "time exceeded" message from its own address. It quotes the first 28 bytes of the dropped packet (the IP header plus 8 bytes), ' +
    'so the laptop can tell which probe this answer belongs to. Now traceroute knows the first hop is 192.168.1.1.',
  packet: toLaptop(NET.router.ip, 'ICMP', icmpTimeExceeded(probeIp), 64, false),
};

// ------------------------------------------------------------ UDP & DNS

const dnsQ: Step = {
  from: 'laptop',
  to: 'dns',
  capture: ON_LAPTOP,
  title: 'DNS query: "What is the address of www.example.com?"',
  text:
    'Before the browser can connect to www.example.com, it needs an IP address. It asks a DNS resolver over UDP port 53. ' +
    'UDP is about as simple as a transport can be: ports, a length, a checksum and nothing else. There is no handshake, so the question goes out in a single packet. ' +
    'If it gets lost, the client simply asks again after a timeout.',
  packet: udpFromLaptop(NET.dns.ip, 51842, 53, dnsQuery({ id: 0x7c3e, name: NET.server.name })),
};

const dnsR: Step = {
  from: 'dns',
  to: 'laptop',
  capture: ON_LAPTOP,
  title: 'DNS response: "203.0.113.80"',
  text:
    'The resolver answers with the same transaction ID, repeats the question, and adds an A record holding the address. ' +
    'To save space, the answer does not spell out the name again. It points back to where the name appears in the question (offset 12). ' +
    'The TTL says the answer can be cached for an hour.',
  packet: udpToLaptop(NET.dns.ip, 53, 51842, dnsResponse({ id: 0x7c3e, name: NET.server.name, addr: NET.server.ip, ttl: 3600 })),
};

// ------------------------------------------------------------ TCP

const tcpDemo = new TcpConn(NET.server.ip, 49812, 80, 0x3b2a1f00, 0x9c41d2a0);

const tcpSteps: Step[] = [
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'SYN: "Let\'s talk. My numbers start here."',
    text:
      'TCP gives applications a reliable, ordered stream of bytes on top of unreliable packets. First, both sides have to agree on where their byte counting starts. ' +
      'The client sends a SYN with a random initial sequence number, along with options like the maximum segment size and window scaling.',
    packet: tcpDemo.client(['SYN']),
  },
  {
    from: 'server', to: 'laptop', capture: ON_LAPTOP,
    title: 'SYN-ACK: "Got it. Here are mine."',
    text:
      'The server acknowledges the client\'s SYN (acknowledgment = client ISN + 1, because a SYN counts as one byte) and sends its own SYN with its own random starting number.',
    packet: tcpDemo.server(['SYN', 'ACK']),
  },
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'ACK: connection established',
    text:
      'The client acknowledges the server\'s SYN. That is the three-way handshake: both sides have proven they can send and receive, and both know the other\'s sequence numbers. ' +
      'Data could start flowing now. The HTTP lesson shows what that looks like.',
    packet: tcpDemo.client(['ACK']),
  },
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'FIN: "I\'m done sending."',
    text:
      'Closing happens one direction at a time. The client sends FIN to say it has nothing more to send. It can still receive.',
    packet: tcpDemo.client(['FIN', 'ACK']),
  },
  {
    from: 'server', to: 'laptop', capture: ON_LAPTOP,
    title: 'FIN-ACK: "Me too."',
    text:
      'The server acknowledges the client\'s FIN and, since it is also finished, sets its own FIN in the same segment. Combining the two saves a packet.',
    packet: tcpDemo.server(['FIN', 'ACK']),
  },
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'Final ACK',
    text:
      'The client acknowledges the server\'s FIN, and the connection is closed. The client keeps a record of it for a short while (the TIME-WAIT state), in case this last ACK got lost and the server resends its FIN.',
    packet: tcpDemo.client(['ACK']),
  },
];

// ------------------------------------------------------------ HTTP

const httpConn = new TcpConn(NET.server.ip, 49814, 80, 0x51e0c7a4, 0x0d93b6e2);
httpConn.client(['SYN']);
httpConn.server(['SYN', 'ACK']);
httpConn.client(['ACK']);

const getRequest = () =>
  http('GET / HTTP/1.1', [
    ['Host', NET.server.name],
    ['User-Agent', 'packet-walk/0.1'],
    ['Accept', 'text/html'],
    ['Accept-Encoding', 'identity'],
    ['Connection', 'keep-alive'],
  ]);

const PAGE = '<!doctype html><title>Hello</title><h1>Hello from packet-walk!</h1>\n';

const okResponse = () =>
  http(
    'HTTP/1.1 200 OK',
    [
      ['Date', 'Wed, 11 Nov 2026 09:30:00 GMT'],
      ['Server', 'demo'],
      ['Content-Type', 'text/html; charset=utf-8'],
      ['Content-Length', String(PAGE.length)],
      ['Cache-Control', 'max-age=600'],
    ],
    PAGE,
  );

const httpSteps: Step[] = [
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'HTTP request: GET /',
    text:
      'The TCP handshake is already done, so the browser writes its request into the connection. HTTP/1.1 is plain text: a request line, some "Name: value" headers, and a blank line. ' +
      'Anyone on the path can read every byte of it, and could even change it. That is why the TLS lesson exists. ' +
      'The TCP PSH flag asks the receiver to pass the data to the application right away.',
    packet: httpConn.client(['PSH', 'ACK'], getRequest()),
  },
  {
    from: 'server', to: 'laptop', capture: ON_LAPTOP,
    title: 'HTTP response: 200 OK',
    text:
      'The server answers with a status line, headers and the page itself. Content-Length tells the browser exactly where the body ends, so the same connection can be reused for the next request. ' +
      'This response also acknowledges the request: look at the TCP acknowledgment number.',
    packet: httpConn.server(['PSH', 'ACK'], okResponse()),
  },
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'TCP ACK: "Got the page."',
    text:
      'The laptop\'s TCP stack confirms that it received every byte of the response. If this ACK had not arrived, the server would have resent the data after a timeout. That is how TCP stays reliable.',
    packet: httpConn.client(['ACK']),
  },
];

// ------------------------------------------------------------ TLS 1.3

const tlsConn = new TcpConn(NET.server.ip, 49816, 443, 0xa7310e5c, 0x2fd8814b);

const tlsTcpSteps: Step[] = [
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'TCP SYN to port 443',
    text: 'HTTPS starts the same way as HTTP: a TCP handshake. The only difference is the port, 443 instead of 80.',
    packet: tlsConn.client(['SYN']),
  },
  {
    from: 'server', to: 'laptop', capture: ON_LAPTOP,
    title: 'TCP SYN-ACK',
    text: 'The server accepts the connection.',
    packet: tlsConn.server(['SYN', 'ACK']),
  },
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'TCP ACK',
    text: 'The connection is open. Before any HTTP is sent, TLS has to build an encrypted tunnel inside it.',
    packet: tlsConn.client(['ACK']),
  },
];

const tlsGet = getRequest();
const tlsOk = okResponse();

const tlsSteps: Step[] = [
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'ClientHello',
    text:
      'The client says hello. It names the site it wants (SNI), lists the cipher suites and signature types it supports, and sends a key share: its half of a Diffie–Hellman key exchange. ' +
      'It is guessing that the server supports x25519, which lets TLS 1.3 finish in one round trip. Everything in this message is still readable by anyone on the path.',
    packet: tlsConn.client(['PSH', 'ACK'], tlsClientHello({ sni: NET.server.name, seed: 1301 })),
  },
  {
    from: 'server', to: 'laptop', capture: ON_LAPTOP,
    title: 'ServerHello',
    text:
      'The server picks a cipher suite and replies with its own key share. Each side combines its secret with the other\'s public key share and arrives at the same shared secret, without that secret ever crossing the network. ' +
      'This is the last unencrypted handshake message. The tiny change_cipher_spec record that follows it is only there to keep old middleboxes happy.',
    packet: tlsConn.server(['PSH', 'ACK'], tlsServerHello({ seed: 2402, sessionSeed: 1302 })),
  },
  {
    from: 'server', to: 'laptop', capture: ON_LAPTOP,
    title: 'Encrypted: certificate and proof',
    text:
      'Everything from here on is encrypted. Hidden in this record are the server\'s certificate (which proves it really is www.example.com), a signature over the handshake made with the certificate\'s private key, and a Finished message. ' +
      'An observer only sees "application data" of some length. Real certificate chains are often several kilobytes and span multiple TCP segments. Here the record is trimmed to fit in one.',
    packet: tlsConn.server(
      ['PSH', 'ACK'],
      tlsEncrypted({ plaintextLength: 1050, seed: 3503, hidden: 'EncryptedExtensions, Certificate, CertificateVerify and Finished' }),
    ),
  },
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'Client Finished',
    text:
      'The browser checks that the certificate is valid for www.example.com and was issued by an authority it trusts, then verifies the server\'s signature. ' +
      'It replies with its own encrypted Finished message: a 32-byte keyed hash of the whole handshake. If an attacker had tampered with any earlier message, the hashes would not match. The handshake is complete.',
    packet: tlsConn.client(['PSH', 'ACK'], concat(tlsChangeCipherSpec(), tlsEncrypted({ plaintextLength: 36, seed: 4604, hidden: 'a Finished message' }))),
  },
  {
    from: 'laptop', to: 'server', capture: ON_LAPTOP,
    title: 'Encrypted HTTP request',
    text:
      `This is the same GET request as in the HTTP lesson, but now it is ciphertext. The record is exactly ${tlsGet.bytes.length} + 1 + 16 bytes: the request, its hidden content type, and the authentication tag. ` +
      'An observer can still see the IP addresses, the ports, the site name from the ClientHello, and the sizes and timing of the records. They cannot see the path, the headers or any cookies.',
    packet: tlsConn.client(['PSH', 'ACK'], tlsEncrypted({ plaintextLength: tlsGet.bytes.length, seed: 5705, hidden: 'GET / HTTP/1.1 and its headers' })),
  },
  {
    from: 'server', to: 'laptop', capture: ON_LAPTOP,
    title: 'Encrypted HTTP response',
    text:
      'The page comes back the same way. Only the browser can decrypt it, and the authentication tag guarantees that no one altered it on the way.',
    packet: tlsConn.server(['PSH', 'ACK'], tlsEncrypted({ plaintextLength: tlsOk.bytes.length, seed: 6806, hidden: 'HTTP/1.1 200 OK, headers and the HTML page' })),
  },
];

// ------------------------------------------------------------ Lessons

const ALL: Lesson[] = [
  {
    id: 'ethernet-arp',
    title: 'Ethernet & ARP',
    protocols: ['Ethernet', 'ARP'],
    intro: 'How does a laptop find the router sitting right next to it? Local networks deliver frames by MAC address, and ARP is how an IP address is turned into a MAC.',
    steps: [arpRequest, arpReply],
  },
  LOCAL_LESSONS.wifiLesson,
  ADVANCED.physicalLesson,
  ACCESS.pppoeLesson,
  REALTIME.sipLesson,
  REALTIME.rtspLesson,
  REALTIME.ntsLesson,
  ACCESS.ipsecLesson,
  ACCESS.modbusLesson,
  ADVANCED.sshTunnelLesson,
  ADVANCED.radiusLesson,
  ADVANCED.dnssecLesson,
  MORE.dhcpLesson,
  {
    id: 'ip-icmp',
    title: 'IP & ICMP',
    protocols: ['IPv4', 'ICMP'],
    intro: 'IP gets packets from one end of the internet to the other, one router at a time. Follow a ping out and back, watch NAT rewrite it, and see how traceroute uses the TTL.',
    steps: [pingRequest, pingNat, pingReply, traceProbe, traceExceeded],
  },
  ROUTING.ipv6Lesson,
  ROUTING.bgpLesson,
  {
    id: 'udp-dns',
    title: 'UDP & DNS',
    protocols: ['UDP', 'DNS'],
    intro: 'People use names and networks use numbers. DNS translates one into the other in a single question and a single answer, carried over UDP.',
    steps: [dnsQ, dnsR],
  },
  ROUTING.ntpLesson,
  {
    id: 'tcp',
    title: 'TCP',
    protocols: ['TCP'],
    intro: 'TCP turns a stream of lossy, unordered packets into a reliable conversation. Watch a connection open with the three-way handshake and close politely.',
    steps: tcpSteps,
  },
  {
    id: 'http',
    title: 'HTTP',
    protocols: ['HTTP/1.1'],
    intro: 'The language of the web, in plain text. A browser asks for a page and the server sends it back, and everyone along the path can read both.',
    steps: httpSteps,
  },
  {
    id: 'tls',
    title: 'HTTPS & TLS 1.3',
    protocols: ['HTTPS', 'TLS 1.3'],
    intro: 'TLS puts the "S" in HTTPS. In one round trip, the client and server agree on keys that nobody else knows, the server proves who it is, and everything after that is encrypted and tamper-proof.',
    steps: tlsSteps,
  },
  MORE.websocketLesson,
  MORE.quicLesson,
  MORE.sshLesson,
  MORE.ftpLesson,
  LOCAL_LESSONS.smbLesson,
  MAIL_LESSONS.smtpLesson,
  MAIL_LESSONS.imapLesson,
  LOCAL_LESSONS.pop3Lesson,
  MAIL_LESSONS.wireguardLesson,
  {
    id: 'page-load',
    title: 'Loading a web page',
    protocols: ['DNS', 'TCP', 'TLS', 'HTTP'],
    intro: 'Everything together: what happens on the wire when you type https://www.example.com and press Enter. The router\'s MAC is already in the ARP cache, so the first packet is a DNS query.',
    steps: [dnsQ, dnsR, ...tlsTcpSteps, ...tlsSteps],
  },
];

/** Lessons in the order of their groups (link → network → transport → application). */
const order = GROUPS.flatMap((g) => g.ids);
export const LESSONS: Lesson[] = [...ALL].sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
