// Lessons for the physical layer, SSH tunneling, RADIUS and DNSSEC.
import { Header, layer, randomBytes, type Packet } from '../bytes';
import { ethernet, arp, BROADCAST } from '../protocols/link';
import { ipv4, tcp, udp } from '../protocols/inet';
import { sshEncrypted } from '../protocols/text';
import {
  radius, rText, rInt, rAddr, hidePassword, onTheWire, pgStartup,
  dnsMessage, rrA, rrDnskey, rrRrsig, rrDs, dnskeyRdata, keyTag, dsDigest,
} from '../protocols/security';
import { NET, ON_LAPTOP, TcpConn, udpFromLaptop, udpToLaptop, type Lesson } from './network';

function unseen(n: number, seed: number): Packet {
  const h = new Header();
  h.bytes('Data', randomBytes(seed, n));
  return layer('Not shown', 'tcp', h);
}

// ------------------------------------------------------------ Physical layer

const arpReq = (senderIp: string) =>
  ethernet(
    { dst: BROADCAST, src: NET.laptop.mac, type: 'ARP' },
    arp({ op: 'request', senderMac: NET.laptop.mac, senderIp, targetMac: '00:00:00:00:00:00', targetIp: NET.router.ip }),
  );
const goodFrame = arpReq(NET.laptop.ip);
// 192.168.1.23 with the top bit of the last byte flipped by noise: 23 ^ 0x80 = 151.
const damagedFrame = arpReq('192.168.1.151');

const physicalLesson: Lesson = {
  id: 'physical',
  title: 'Physical layer',
  protocols: ['Ethernet PHY', 'CRC-32'],
  intro:
    'Everything else in this site rides on this layer: bits turned into voltages on copper, light in fibre, or radio waves. Packet captures start at the destination MAC address, but the network card sends more than that. Here is the ARP request from the first lesson as it actually leaves the network card.',
  steps: [
    {
      from: 'laptop', to: 'router', capture: 'What the network card transmits (normally invisible to capture tools)',
      title: 'A frame on the wire',
      text:
        'Before the frame, the card sends a 7-byte preamble and a start frame delimiter so the receiver can synchronise its clock. After it comes a 4-byte frame check sequence (FCS), a CRC-32 of the whole frame. ' +
        'Then the line must stay quiet for at least 12 byte-times (the inter-frame gap) before the next frame. On gigabit copper (1000BASE-T), these bits travel as five voltage levels on all four wire pairs at once.',
      packet: onTheWire(goodFrame),
    },
    {
      from: 'laptop', to: 'router', capture: 'What arrives after electrical noise flipped one bit',
      title: 'One flipped bit: frame dropped',
      text:
        'Interference flips a single bit in transit, so the sender IP now reads 192.168.1.151 instead of .23. The receiver computes the CRC of what it got, sees that it does not match the FCS, and drops the frame without telling anyone. ' +
        'Ethernet does not retransmit. Recovering is left to higher layers: ARP will simply ask again, and TCP would retransmit its data. The CRC catches every single-bit error and almost all burst errors.',
      packet: onTheWire(damagedFrame, goodFrame),
    },
  ],
};

// ------------------------------------------------------------ SSH tunneling

const BASTION = { ip: '203.0.113.22', inner: '10.0.0.5', mac: '02:00:00:dd:00:05' };
const DB = { ip: '10.0.0.20', mac: '02:00:00:dd:00:20', port: 5432 };

const sshConn = new TcpConn(BASTION.ip, 49880, 22, 0x4c7f1e02, 0xb37a6d50);
sshConn.client(['SYN']);
sshConn.server(['SYN', 'ACK']);
sshConn.client(['ACK']);
// Version exchange, key exchange and user authentication happen first (see the SSH lesson).
sshConn.client(['PSH', 'ACK'], unseen(1580, 9801));
sshConn.server(['PSH', 'ACK'], unseen(1210, 9802));
sshConn.client(['PSH', 'ACK'], unseen(744, 9803));
sshConn.server(['PSH', 'ACK'], unseen(380, 9804));

const startup = pgStartup([['user', 'alice'], ['database', 'inventory'], ['application_name', 'psql']]);
const startupLen = startup.bytes.length;
// SSH_MSG_CHANNEL_DATA = 1 (type) + 4 (recipient channel) + 4 + data, padded so 1 + payload + padding is a multiple of 8 (≥ 4 padding).
const padTo8 = (payload: number) => {
  let pad = 8 - ((1 + payload) % 8);
  if (pad < 4) pad += 8;
  return 1 + payload + pad;
};

let lbPort = 50122;
const loopbackSyn = ipv4({ src: '127.0.0.1', dst: '127.0.0.1', proto: 'TCP', ttl: 64, id: 0x9b21 },
  tcp({ src: '127.0.0.1', dst: '127.0.0.1', srcPort: lbPort, dstPort: 5432, seq: 0x6a0b33f1, ack: 0, flags: ['SYN'], window: 65495 }));

const inner = new TcpConn(DB.ip, 41022, DB.port, 0x22d5ae70, 0x8f1c4b39, {
  clientIp: BASTION.inner,
  frameClient: (dst, seg) => ethernet({ dst: DB.mac, src: BASTION.mac, type: 'IPv4' }, ipv4({ src: BASTION.inner, dst, proto: 'TCP', ttl: 64, id: 0x51a0 + lbPort++ }, seg)),
  frameServer: (src, seg) => ethernet({ dst: BASTION.mac, src: DB.mac, type: 'IPv4' }, ipv4({ src, dst: BASTION.inner, proto: 'TCP', ttl: 64, id: 0x7700 }, seg)),
});
const PRIVATE = 'Captured on the bastion\'s private network (10.0.0.0/24)';

const sshTunnelLesson: Lesson = {
  id: 'ssh-tunnel',
  title: 'SSH tunneling',
  protocols: ['SSH', 'TCP', 'PostgreSQL'],
  labels: {
    server: { label: 'SSH bastion', addr: `${BASTION.ip} · ${BASTION.inner}` },
    dns: { label: 'db.internal', addr: `${DB.ip} (private)`, icon: 'database' },
  },
  links: ['server-dns'],
  intro:
    'A database sits on a private network that the internet cannot reach. Only an SSH "bastion" host can. With ssh -L 5432:db.internal:5432 bastion, the laptop gets a local port that leads, through the encrypted SSH connection, to the database. ' +
    'This follows one connection through the tunnel.',
  steps: [
    {
      from: 'laptop', to: 'laptop', capture: 'Captured on the laptop\'s loopback interface (lo), IP layer',
      title: 'An app connects to localhost:5432',
      text:
        'psql connects to 127.0.0.1:5432, thinking a database is running locally. In fact the ssh client is listening there. This packet never touches a network card: it travels over the loopback interface inside the laptop, so there is no Ethernet header at all.',
      packet: loopbackSyn,
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Encrypted CHANNEL_OPEN "direct-tcpip"',
      text:
        'The ssh client asks the bastion, over the already-open SSH connection, to open a new channel of type "direct-tcpip" to db.internal:5432. SSH multiplexes many channels (shells, file transfers, tunnels) over one TCP connection. ' +
        'All an observer sees is another encrypted SSH packet on port 22.',
      packet: sshConn.client(['PSH', 'ACK'], sshEncrypted({ plaintext: 72, seed: 9810, hidden: 'SSH_MSG_CHANNEL_OPEN "direct-tcpip": sender channel 3, window 2 MiB, max packet 32 KiB, host "db.internal", port 5432, originator 127.0.0.1:50122' })),
    },
    {
      from: 'server', to: 'dns', capture: PRIVATE,
      title: 'The bastion connects to the database',
      text:
        'The bastion makes an ordinary TCP connection from its private address, 10.0.0.5, to 10.0.0.20:5432. To the database, the connection appears to come from the bastion, not from the laptop.',
      packet: inner.client(['SYN']),
    },
    (() => {
      inner.server(['SYN', 'ACK']);
      inner.client(['ACK']);
      return {
        from: 'server' as const, to: 'laptop' as const, capture: ON_LAPTOP,
        title: 'Encrypted CHANNEL_OPEN_CONFIRMATION',
        text: 'Once the database accepts the connection, the bastion confirms that the channel is open. From now on, bytes written to the laptop\'s local socket are relayed, encrypted, to the database.',
        packet: sshConn.server(['PSH', 'ACK'], sshEncrypted({ plaintext: 24, seed: 9820, hidden: 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION: recipient channel 3, sender channel 0, window and packet size' })),
      };
    })(),
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Database traffic inside SSH',
      text:
        `psql sends its ${startupLen}-byte startup message. The ssh client wraps it in an SSH_MSG_CHANNEL_DATA message and encrypts it. Across the internet, the user name and database name cannot be read. ` +
        'Inside, TCP is now carried by SSH, which is itself carried by TCP. That is why heavy tunnels can feel sluggish on lossy links.',
      packet: sshConn.client(['PSH', 'ACK'], sshEncrypted({ plaintext: padTo8(1 + 4 + 4 + startupLen), seed: 9830, hidden: `SSH_MSG_CHANNEL_DATA on channel 0 carrying the ${startupLen}-byte PostgreSQL startup message` })),
    },
    {
      from: 'server', to: 'dns', capture: PRIVATE,
      title: 'Plain text on the private side',
      text:
        'The bastion decrypts the message and writes the bytes into its TCP connection to the database, unchanged. On the private network they are plain text again. The tunnel protects only the hop between the laptop and the bastion. ' +
        'Related forms: ssh -R does the reverse (a port on the server leads back to the client), and ssh -D turns the client into a SOCKS proxy for any destination.',
      packet: inner.client(['PSH', 'ACK'], startup),
    },
  ],
};

// ------------------------------------------------------------ RADIUS

const NAS = { ip: NET.router.wan };
const RADIUS_SERVER = '203.0.113.18';
const SECRET = 's3cr3t-shared';
const NAS_ATTRS = [
  rAddr(4, 'NAS-IP-Address', NAS.ip, 'The address of the device asking. The server looks up the shared secret for this client.'),
  rText(32, 'NAS-Identifier', 'vpn-gw-1'),
  rInt(61, 'NAS-Port-Type', 5, '5 (Virtual)', 'What kind of port the user came in on. Virtual means a VPN.'),
  rText(31, 'Calling-Station-Id', '203.0.113.200', 'Where the user is connecting from.'),
];
const radiusPort = 50318;
let nasIpId = 0x3101;
const AT_NAS = 'Captured on the VPN gateway\'s internet link (IP layer)';

function radiusPacket(fromNas: boolean, acct: boolean, msg: Packet): Packet {
  const port = acct ? 1813 : 1812;
  const [src, dst] = fromNas ? [NAS.ip, RADIUS_SERVER] : [RADIUS_SERVER, NAS.ip];
  const [sp, dp] = fromNas ? [radiusPort, port] : [port, radiusPort];
  return ipv4({ src, dst, proto: 'UDP', ttl: fromNas ? 64 : 55, id: fromNas ? nasIpId++ : 0, df: false }, udp({ src, dst, srcPort: sp, dstPort: dp }, msg));
}

function accessRequest(id: number, password: string, seed: number) {
  const ra = randomBytes(seed, 16);
  const pkt = radius({
    code: 1, id, secret: SECRET, requestAuth: ra, messageAuthenticator: true,
    attrs: [
      rText(1, 'User-Name', 'alice'),
      { type: 2, name: 'User-Password', data: hidePassword(password, SECRET, ra), value: 'hidden (16 bytes)', info: 'The password is padded to 16 bytes and XOR-ed with MD5(shared secret + Request Authenticator). Only someone with the secret can undo it. This is old-fashioned obfuscation rather than modern encryption, so RADIUS should travel over a trusted network or inside TLS (RadSec).' },
      rInt(6, 'Service-Type', 2, '2 (Framed)', 'The user wants a network connection, not a login shell.'),
      ...NAS_ATTRS,
    ],
  });
  return { ra, pkt };
}

const wrong = accessRequest(41, 'hunter2', 9900);
const right = accessRequest(42, 'correct horse', 9901);
const acctAttrs = [
  rInt(40, 'Acct-Status-Type', 1, '1 (Start)', 'Start, Interim-Update or Stop. Together they give a usage record for billing or auditing.'),
  rText(44, 'Acct-Session-Id', '5F1A0003', 'Links all accounting records for this session.'),
  rText(1, 'User-Name', 'alice'),
  rAddr(8, 'Framed-IP-Address', '10.8.0.2'),
  ...NAS_ATTRS.slice(0, 2),
];
const acctReq = radius({ code: 4, id: 7, secret: SECRET, requestAuth: new Uint8Array(16), attrs: acctAttrs });
const acctReqAuth = acctReq.bytes.slice(4, 20);

const radiusLesson: Lesson = {
  id: 'radius',
  title: 'RADIUS',
  protocols: ['RADIUS', 'UDP'],
  labels: {
    router: { label: 'VPN gateway (NAS)', addr: `${NET.router.ip} · ${NAS.ip}` },
    server: { label: 'RADIUS server', addr: RADIUS_SERVER },
  },
  intro:
    'Company VPNs, Wi-Fi (WPA2/WPA3-Enterprise) and network switches rarely check passwords themselves. They ask a central RADIUS server over UDP. The device asking is the NAS (network access server). It shares a secret with the RADIUS server, here "s3cr3t-shared". ' +
    'Every authenticator and hash in these packets is really computed from that secret.',
  steps: [
    {
      from: 'router', to: 'server', capture: AT_NAS,
      title: 'Access-Request (wrong password)',
      text:
        'Alice types her password into the VPN client, and the gateway forwards it to RADIUS port 1812. The attributes carry her user name, her hidden password, and details about the gateway and the connection. ' +
        'Enterprise Wi-Fi works the same way, but carries a whole EAP exchange (often a TLS tunnel) inside EAP-Message attributes instead of a password.',
      packet: radiusPacket(true, false, wrong.pkt),
    },
    {
      from: 'server', to: 'router', capture: AT_NAS,
      title: 'Access-Reject',
      text: 'The server un-hides the password with the shared secret, checks it, and says no. The Response Authenticator proves the reject really came from the server, so a forged "Accept" would not pass.',
      packet: radiusPacket(false, false, radius({ code: 3, id: 41, secret: SECRET, requestAuth: wrong.ra, messageAuthenticator: true, attrs: [rText(18, 'Reply-Message', 'Invalid credentials')] })),
    },
    {
      from: 'router', to: 'server', capture: AT_NAS,
      title: 'Access-Request (correct password)',
      text: 'Alice tries again. This is a new request, so it gets a new Identifier and a fresh random authenticator, and the hidden password bytes come out completely different even for the same secret.',
      packet: radiusPacket(true, false, right.pkt),
    },
    {
      from: 'server', to: 'router', capture: AT_NAS,
      title: 'Access-Accept with authorisation',
      text:
        'Accepted. RADIUS also says what Alice is allowed: here, a VPN address and a maximum session length of 8 hours. Servers can also return a VLAN, bandwidth limits or firewall rules this way. ' +
        'That is the "AA" in AAA: Authentication, Authorisation, and (next) Accounting.',
      packet: radiusPacket(false, false, radius({
        code: 2, id: 42, secret: SECRET, requestAuth: right.ra, messageAuthenticator: true,
        attrs: [rText(18, 'Reply-Message', 'Welcome, alice'), rInt(27, 'Session-Timeout', 28800, '28800 seconds (8 hours)'), rAddr(8, 'Framed-IP-Address', '10.8.0.2', 'The address the VPN should give Alice inside the tunnel.')],
      })),
    },
    {
      from: 'router', to: 'server', capture: AT_NAS,
      title: 'Accounting-Request: session start',
      text: 'The gateway reports that Alice\'s session has started, on port 1813. When she disconnects, a "Stop" record with the duration and byte counts follows. This is the audit trail of who was connected, when, and from where.',
      packet: radiusPacket(true, true, acctReq),
    },
    {
      from: 'server', to: 'router', capture: AT_NAS,
      title: 'Accounting-Response',
      text: 'The server confirms that it stored the record. Without this reply, the gateway would keep retrying, because accounting records matter for billing and security investigations.',
      packet: radiusPacket(false, true, radius({ code: 5, id: 7, secret: SECRET, requestAuth: acctReqAuth, attrs: [] })),
    },
  ],
};

// ------------------------------------------------------------ DNSSEC

const KSK = dnskeyRdata(257, randomBytes(9950, 32));
const ZSK = dnskeyRdata(256, randomBytes(9951, 32));
const COM_ZSK_TAG = keyTag(dnskeyRdata(256, randomBytes(9952, 32)));
const KSK_TAG = keyTag(KSK);
const ZSK_TAG = keyTag(ZSK);
const NS_EX = '203.0.113.10';
const NS_COM = '192.0.2.30';
const R = NET.dns.ip;
const AT_RESOLVER = 'Captured at the resolver (IP layer)';
const WWW = 'www.example.com';

const aSet = [rrA(WWW, 3600, NET.server.ip), rrRrsig({ owner: WWW, ttl: 3600, covered: 1, labels: 3, keyTag: ZSK_TAG, signer: 'example.com', seed: 9960 })];

function resolverQuery(dst: string, id: number, qname: string, qtype: number, label: string, port: number): Packet {
  return ipv4({ src: R, dst, proto: 'UDP', ttl: 64, id: id & 0xffff, df: false }, udp({ src: R, dst, srcPort: port, dstPort: 53 },
    dnsMessage({ id, flags: 0x0010, flagsText: 'query, CD=1', flagsInfo: 'An iterative query from the resolver: no recursion requested. CD ("checking disabled") tells the server that the resolver will do its own validation.', qname, qtype, answers: [], label })));
}

function authAnswer(src: string, id: number, qname: string, qtype: number, answers: ReturnType<typeof rrA>[], label: string, port: number): Packet {
  return ipv4({ src, dst: R, proto: 'UDP', ttl: 57, id: 0, df: false }, udp({ src, dst: R, srcPort: 53, dstPort: port },
    dnsMessage({ id, flags: 0x8400, flagsText: 'response, authoritative', flagsInfo: 'AA=1: this server is authoritative for the zone. It is the source, not a cache.', qname, qtype, answers, label })));
}

const dnssecLesson: Lesson = {
  id: 'dnssec',
  title: 'DNSSEC',
  protocols: ['DNSSEC', 'DNS', 'EDNS0'],
  labels: {
    internet: { label: 'Internet · .com servers', addr: NS_COM },
    server: { label: 'ns1.example.com', addr: NS_EX },
  },
  intro:
    'Plain DNS answers carry no proof, so a forged answer can send you to the wrong server. DNSSEC adds signatures. Each zone signs its records, and each parent vouches for its child\'s key, forming a chain of trust up to the root key that resolvers ship with. ' +
    'Follow a validating resolver checking www.example.com.',
  steps: [
    {
      from: 'laptop', to: 'dns', capture: ON_LAPTOP,
      title: 'Query with the DO bit',
      text:
        'The laptop asks its resolver for www.example.com as usual, but adds an EDNS(0) OPT record with DO=1 ("DNSSEC OK") and sets the AD flag to say it understands validation results.',
      packet: udpFromLaptop(R, 53114, 53, dnsMessage({ id: 0x51c2, flags: 0x0120, flagsText: 'query, RD=1, AD=1', flagsInfo: 'RD asks for recursion. Setting AD in a query asks the resolver to report whether the answer was validated.', qname: WWW, qtype: 1, answers: [], label: 'DNS query (DNSSEC)' })),
    },
    {
      from: 'dns', to: 'server', capture: AT_RESOLVER,
      title: 'Resolver asks the example.com servers',
      text: 'The resolver already knows (from earlier lookups) where example.com\'s nameservers are. It asks for the A record, with DO=1 so that the signatures come back too.',
      packet: resolverQuery(NS_EX, 0x8e01, WWW, 1, 'DNS query (A)', 40211),
    },
    {
      from: 'server', to: 'dns', capture: AT_RESOLVER,
      title: 'A record + RRSIG',
      text:
        `Along with the address, the nameserver returns an RRSIG: a signature over the A record set made with example.com's zone-signing key (key tag ${ZSK_TAG}). To check it, the resolver needs that key.`,
      packet: authAnswer(NS_EX, 0x8e01, WWW, 1, aSet, 'DNS response (A + RRSIG)', 40211),
    },
    {
      from: 'dns', to: 'server', capture: AT_RESOLVER,
      title: 'Fetch the DNSKEY set',
      text: 'The resolver asks example.com for its public keys (type DNSKEY).',
      packet: resolverQuery(NS_EX, 0x8e02, 'example.com', 48, 'DNS query (DNSKEY)', 40212),
    },
    {
      from: 'server', to: 'dns', capture: AT_RESOLVER,
      title: 'Two keys, signed by the KSK',
      text:
        `The zone has two keys: a ZSK (flags 256, tag ${ZSK_TAG}) that signs the zone's data, and a KSK (flags 257, tag ${KSK_TAG}) that signs only this DNSKEY set. With the ZSK, the resolver can now verify the A record's signature. ` +
        'But anyone could publish keys. Why trust this KSK?',
      packet: authAnswer(NS_EX, 0x8e02, 'example.com', 48, [
        rrDnskey('example.com', 3600, 256, ZSK.slice(4)),
        rrDnskey('example.com', 3600, 257, KSK.slice(4)),
        rrRrsig({ owner: 'example.com', ttl: 3600, covered: 48, labels: 2, keyTag: KSK_TAG, signer: 'example.com', seed: 9970 }),
      ], 'DNS response (DNSKEY + RRSIG)', 40212),
    },
    {
      from: 'dns', to: 'internet', capture: AT_RESOLVER,
      title: 'Ask the parent: DS for example.com',
      text: 'Trust comes from the parent zone. The resolver asks the .com servers for example.com\'s DS ("delegation signer") record.',
      packet: resolverQuery(NS_COM, 0x8e03, 'example.com', 43, 'DNS query (DS)', 40213),
    },
    {
      from: 'internet', to: 'dns', capture: AT_RESOLVER,
      title: 'DS: .com vouches for example.com\'s key',
      text:
        `The DS record holds a SHA-256 hash of example.com's KSK, and .com signs it with its own key (tag ${COM_ZSK_TAG}). The resolver hashes the KSK it received and compares. The digest shown is the real SHA-256 of the KSK from step 5. ` +
        'The same check repeats one level up, with .com\'s DS published in the root zone, ending at the root key built into the resolver: the chain of trust.',
      packet: authAnswer(NS_COM, 0x8e03, 'example.com', 43, [
        rrDs('example.com', 86400, KSK_TAG, dsDigest('example.com', KSK)),
        rrRrsig({ owner: 'example.com', ttl: 86400, covered: 43, labels: 2, keyTag: COM_ZSK_TAG, signer: 'com', seed: 9980 }),
      ], 'DNS response (DS + RRSIG)', 40213),
    },
    {
      from: 'dns', to: 'laptop', capture: ON_LAPTOP,
      title: 'Validated answer: AD flag set',
      text:
        'Every link checks out, so the resolver returns the answer with AD=1 ("authenticated data"). If any signature had failed, it would have answered SERVFAIL rather than pass along a possibly forged address. ' +
        'DNSSEC proves the answer is authentic but does not hide it. Encrypting DNS is a separate job, done by DNS over HTTPS or over TLS.',
      packet: udpToLaptop(R, 53, 53114, dnsMessage({ id: 0x51c2, flags: 0x81a0, flagsText: 'response, RD, RA, AD=1', flagsInfo: 'AD=1 means the resolver validated every signature in the chain.', qname: WWW, qtype: 1, answers: aSet, label: 'DNS response (validated)' })),
    },
  ],
};

export const ADVANCED = { physicalLesson, sshTunnelLesson, radiusLesson, dnssecLesson, SECRET };
