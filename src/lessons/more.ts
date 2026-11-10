// Lessons for DHCP, WebSocket, QUIC, SSH and FTP.
import { Header, randomBytes, asciiBytes, concat } from '../bytes';
import { ethernet, BROADCAST } from '../protocols/link';
import { ipv4, udp } from '../protocols/inet';
import { http } from '../protocols/app';
import { dhcp, type DhcpType } from '../protocols/dhcp';
import { quicLong, quicShort, datagram, LONG_HEADER_OVERHEAD } from '../protocols/quic';
import { wsFrame, sshVersion, sshPacket, sshString, sshBlob, sshEncrypted, ftp, ftpData } from '../protocols/text';
import { NET, ON_LAPTOP, TcpConn, udpFromLaptop, udpToLaptop, type Lesson, type Step } from './network';

// ------------------------------------------------------------ DHCP

const XID = 0x3903f326;

function dhcpFrame(type: DhcpType): ReturnType<typeof ethernet> {
  const fromServer = type === 'OFFER' || type === 'ACK';
  const msg = dhcp({
    type, xid: XID, clientMac: NET.laptop.mac, addr: NET.laptop.ip,
    server: NET.router.ip, router: NET.router.ip, dns: NET.dns.ip, hostname: 'laptop',
  });
  const src = fromServer ? NET.router.ip : '0.0.0.0';
  const dst = fromServer ? NET.laptop.ip : '255.255.255.255';
  const [sp, dp] = fromServer ? [67, 68] : [68, 67];
  return ethernet(
    { dst: fromServer ? NET.laptop.mac : BROADCAST, src: fromServer ? NET.router.mac : NET.laptop.mac, type: 'IPv4' },
    ipv4({ src, dst, proto: 'UDP', ttl: fromServer ? 64 : 128, id: 0, df: false }, udp({ src, dst, srcPort: sp, dstPort: dp }, msg)),
  );
}

const dhcpLesson: Lesson = {
  id: 'dhcp',
  title: 'DHCP',
  protocols: ['DHCP', 'UDP'],
  intro:
    'A laptop that has just joined a network has no IP address, no router and no DNS server. DHCP gets all three in four messages: Discover, Offer, Request, Acknowledge ("DORA").',
  steps: [
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'DHCP Discover: "Is there a DHCP server out there?"',
      text:
        'The laptop has no address yet, so it sends from 0.0.0.0 to 255.255.255.255, which means "everyone on this network", wrapped in an Ethernet broadcast. ' +
        'It uses UDP from port 68 to port 67. It includes its MAC address, so a server can answer it, and a list of the settings it wants.',
      packet: dhcpFrame('DISCOVER'),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'DHCP Offer: "You can have 192.168.1.23."',
      text:
        'The home router runs a DHCP server. It picks a free address, sends it in the "your IP" field, and includes the subnet mask, the default gateway (itself), the DNS server and a lease time. ' +
        'It sends the offer directly to the laptop\'s MAC address. The laptop does not own the address yet, though. This is only an offer.',
      packet: dhcpFrame('OFFER'),
    },
    {
      from: 'laptop', to: 'router', capture: ON_LAPTOP,
      title: 'DHCP Request: "I\'ll take it."',
      text:
        'The laptop formally asks for the offered address. It still broadcasts, because a network can have more than one DHCP server. Naming the chosen server (option 54) tells any others that their offers were declined.',
      packet: dhcpFrame('REQUEST'),
    },
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'DHCP Ack: "It\'s yours for a day."',
      text:
        'The server confirms, and the laptop configures 192.168.1.23/24 with 192.168.1.1 as its gateway and 203.0.113.53 for DNS. It is now on the internet. ' +
        'Halfway through the lease it will quietly ask to renew, this time with a unicast REQUEST.',
      packet: dhcpFrame('ACK'),
    },
  ],
};

// ------------------------------------------------------------ WebSocket

const wsConn = new TcpConn(NET.server.ip, 49820, 80, 0x6e1a9b02, 0x13c4f7d9);
wsConn.client(['SYN']);
wsConn.server(['SYN', 'ACK']);
wsConn.client(['ACK']);

const enc = (s: string) => asciiBytes(s);
const close1000 = [0x03, 0xe8, ...enc('bye')];

const websocketLesson: Lesson = {
  id: 'websocket',
  title: 'WebSocket',
  protocols: ['WebSocket', 'HTTP/1.1', 'TCP'],
  intro:
    'HTTP is request and response: the server can only speak when asked. WebSocket starts as an ordinary HTTP request, then turns the TCP connection into a two-way channel where either side can send messages at any time. Chat apps and live dashboards use it.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'HTTP Upgrade request',
      text:
        'The browser sends a normal GET, with "Upgrade: websocket" and a random Sec-WebSocket-Key. The key shown is the sample value from RFC 6455, so you can check the server\'s answer against the specification. ' +
        'Plain ws:// is used here so the bytes are visible. Real sites use wss://, which is the same thing inside TLS.',
      packet: wsConn.client(
        ['PSH', 'ACK'],
        http('GET /chat HTTP/1.1', [
          ['Host', NET.server.name],
          ['Upgrade', 'websocket'],
          ['Connection', 'Upgrade'],
          ['Sec-WebSocket-Key', 'dGhlIHNhbXBsZSBub25jZQ=='],
          ['Sec-WebSocket-Version', '13'],
        ]),
      ),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: '101 Switching Protocols',
      text:
        'The server agrees. Sec-WebSocket-Accept is the base64 of SHA-1(key + a fixed GUID), which proves the server really understood the WebSocket request and is not just an HTTP cache replaying an old response. ' +
        'After the blank line, the connection stops speaking HTTP.',
      packet: wsConn.server(
        ['PSH', 'ACK'],
        http('HTTP/1.1 101 Switching Protocols', [
          ['Upgrade', 'websocket'],
          ['Connection', 'Upgrade'],
          ['Sec-WebSocket-Accept', 's3pPLMBiTxaQ9kYGzzhZRbK+xOo='],
        ]),
      ),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Client text frame (masked)',
      text:
        'Messages travel as small frames. This one has just a 2-byte header, a 4-byte masking key and the text. Frames from a browser are always masked: every byte is XOR-ed with the key, which is why the text is unreadable in the hex view.',
      packet: wsConn.client(['PSH', 'ACK'], wsFrame({ opcode: 1, payload: enc('Hello, server!'), display: '"Hello, server!"', mask: Uint8Array.from([0x37, 0xfa, 0x21, 0x3d]) })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Server pushes a message',
      text:
        'Now the server sends a message without being asked, which plain HTTP cannot do. Server frames are not masked, so the text is readable in the hex dump. Compare its 2-byte header with HTTP\'s hundreds of bytes of headers.',
      packet: wsConn.server(['PSH', 'ACK'], wsFrame({ opcode: 1, payload: enc('Hi! 3 users online'), display: '"Hi! 3 users online"' })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Close frame',
      text:
        'To finish, one side sends a close frame (opcode 8) with a 2-byte status code, here 1000 ("normal closure"), and an optional reason. The other side answers with its own close frame, and then the TCP connection is shut down.',
      packet: wsConn.client(['PSH', 'ACK'], wsFrame({ opcode: 8, payload: close1000, display: '1000 (normal closure), "bye"', mask: Uint8Array.from([0x9c, 0x02, 0x5e, 0xb1]) })),
    },
  ],
};

// ------------------------------------------------------------ QUIC

const clientDcid = randomBytes(8001, 8);
const clientScid = randomBytes(8002, 8);
const serverScid = randomBytes(8003, 8);
const QPORT = 52011;
const initialOverhead = LONG_HEADER_OVERHEAD({ initial: true, cidLen: 8 });

const quicLesson: Lesson = {
  id: 'quic',
  title: 'QUIC & HTTP/3',
  protocols: ['QUIC', 'UDP', 'TLS 1.3'],
  intro:
    'QUIC is a newer transport that runs over UDP and builds in TLS 1.3. It sets up a secure connection in one round trip instead of two, and avoids TCP\'s head-of-line blocking. HTTP/3 runs on top of it. Almost everything, including most of the transport header, is encrypted.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Client Initial: hello and handshake in one',
      text:
        'One UDP datagram to port 443 carries a QUIC Initial packet, which holds the TLS ClientHello in a CRYPTO frame. There is no separate TCP handshake. ' +
        'The datagram is padded to 1200 bytes so the server knows it can safely reply with large packets without being abused to amplify attacks. ' +
        'Initial packets are encrypted, but with keys derived from the destination connection ID, which anyone can compute. This guards against meddling middleboxes, not against eavesdroppers.',
      packet: udpFromLaptop(
        NET.server.ip, QPORT, 443,
        quicLong({ type: 'Initial', dcid: clientDcid, scid: clientScid, ciphertext: 1200 - initialOverhead, seed: 8100, hidden: 'a CRYPTO frame carrying the TLS 1.3 ClientHello, then PADDING frames' }),
      ),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Server Initial + Handshake, coalesced',
      text:
        'The server answers with two QUIC packets packed into one datagram. An Initial packet carries the ServerHello. A Handshake packet, encrypted with real secret keys from the key exchange, carries the certificate, signature and Finished. ' +
        'The server also chooses its own connection ID, which the client will use from now on.',
      packet: udpToLaptop(
        NET.server.ip, 443, QPORT,
        datagram(
          quicLong({ type: 'Initial', dcid: clientScid, scid: serverScid, ciphertext: 140, seed: 8200, hidden: 'an ACK frame and a CRYPTO frame with the ServerHello' }),
          quicLong({ type: 'Handshake', dcid: clientScid, scid: serverScid, ciphertext: 960, seed: 8300, hidden: 'CRYPTO frames with EncryptedExtensions, Certificate, CertificateVerify and Finished' }),
        ),
      ),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Client Finished and the HTTP/3 request, together',
      text:
        'One round trip in, the client finishes the handshake and sends its first request in the same datagram. The Handshake packet holds its Finished message. The short-header 1-RTT packet holds an HTTP/3 request on stream 0. ' +
        'With TCP + TLS, the request would have had to wait for an extra round trip.',
      packet: udpFromLaptop(
        NET.server.ip, QPORT, 443,
        datagram(
          quicLong({ type: 'Handshake', dcid: serverScid, scid: clientScid, ciphertext: 58, seed: 8400, hidden: 'an ACK frame and a CRYPTO frame with the client Finished' }),
          quicShort({ dcid: serverScid, ciphertext: 64, seed: 8500, hidden: 'an HTTP/3 HEADERS frame on stream 0: GET https://www.example.com/ (headers compressed with QPACK)' }),
        ),
      ),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'HTTP/3 response',
      text:
        'The response comes back in short-header packets. Each request gets its own QUIC stream, so if a packet for one stream is lost, the others keep going. With TCP, a single lost segment holds up everything behind it. ' +
        'An observer sees only UDP, a connection ID and ciphertext. Even the packet number is hidden.',
      packet: udpToLaptop(
        NET.server.ip, 443, QPORT,
        quicShort({ dcid: clientScid, ciphertext: 230, seed: 8600, hidden: 'ACK, HANDSHAKE_DONE, and HEADERS (status 200) plus DATA frames carrying the HTML page on stream 0' }),
      ),
    },
  ],
};

// ------------------------------------------------------------ SSH

const sshConn = new TcpConn(NET.server.ip, 49830, 22, 0x2c9d4410, 0xe8a1035b);
sshConn.client(['SYN']);
sshConn.server(['SYN', 'ACK']);
sshConn.client(['ACK']);

const ALGS: [string, string, string?][] = [
  ['kex_algorithms', 'curve25519-sha256,ecdh-sha2-nistp256', 'Key-exchange methods, best first. Both sides pick the first entry in the client\'s list that the server also supports.'],
  ['server_host_key_algorithms', 'ssh-ed25519,rsa-sha2-512', 'Types of host key the server may use to prove its identity.'],
  ['encryption_algorithms_client_to_server', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com', 'Ciphers. Each direction is negotiated separately.'],
  ['encryption_algorithms_server_to_client', 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com'],
  ['mac_algorithms_client_to_server', 'hmac-sha2-256-etm@openssh.com', 'Only used with ciphers that do not authenticate data themselves.'],
  ['mac_algorithms_server_to_client', 'hmac-sha2-256-etm@openssh.com'],
  ['compression_algorithms_client_to_server', 'none'],
  ['compression_algorithms_server_to_client', 'none'],
  ['languages_client_to_server', ''],
  ['languages_server_to_client', ''],
];

function kexinit(seed: number) {
  const b = new Header();
  b.u8('Message code', 20, '20 (SSH_MSG_KEXINIT)', 'Each side lists the algorithms it supports, in order of preference.');
  b.bytes('Cookie', randomBytes(seed, 16), undefined, '16 random bytes. They make every key exchange unique.');
  for (const [name, list, info] of ALGS) sshString(b, name, list, info);
  b.u8('First KEX packet follows', 0, 'false');
  b.u32('Reserved', 0, '0');
  return sshPacket('KEXINIT', b, seed + 1);
}

const ecdhInit = (() => {
  const b = new Header();
  b.u8('Message code', 30, '30 (SSH_MSG_KEX_ECDH_INIT)');
  sshBlob(b, 'Client ephemeral public key', randomBytes(9100, 32), 'A fresh Curve25519 public key, used for this connection only.');
  return sshPacket('KEX_ECDH_INIT', b, 9101);
})();

const ecdhReply = (() => {
  const b = new Header();
  b.u8('Message code', 31, '31 (SSH_MSG_KEX_ECDH_REPLY)');
  b.u32('Host key blob length', 51, '51 bytes');
  sshString(b, 'Host key type', 'ssh-ed25519');
  sshBlob(b, 'Host public key', randomBytes(9200, 32), 'The server\'s long-term identity. The first time you connect, ssh asks "Are you sure you want to continue connecting?" and saves a fingerprint of this key in ~/.ssh/known_hosts. After that, a changed key triggers a loud warning.');
  sshBlob(b, 'Server ephemeral public key', randomBytes(9201, 32), 'The server\'s half of the Curve25519 exchange. Both sides now compute the same shared secret.');
  b.u32('Signature blob length', 83, '83 bytes');
  sshString(b, 'Signature type', 'ssh-ed25519');
  sshBlob(b, 'Signature', randomBytes(9202, 64), 'The server signs a hash of the whole exchange so far with its host key. This proves it holds the private key, and that no one tampered with the negotiation.');
  return sshPacket('KEX_ECDH_REPLY', b, 9203);
})();

const newKeys = (seed: number) => {
  const b = new Header();
  b.u8('Message code', 21, '21 (SSH_MSG_NEWKEYS)', '"Everything I send after this is encrypted with the new keys."');
  return sshPacket('NEWKEYS', b, seed);
};

const sshLesson: Lesson = {
  id: 'ssh',
  title: 'SSH',
  protocols: ['SSH', 'TCP'],
  intro:
    'SSH gives you a secure remote shell. Watch the part you never see when you type "ssh server": the version exchange, algorithm negotiation, key exchange and host-key check that happen before the password prompt.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Client version string',
      text: 'Once the TCP connection to port 22 is open, each side sends one line of plain text saying which protocol version and software it runs.',
      packet: sshConn.client(['PSH', 'ACK'], sshVersion('SSH-2.0-pwclient_1.0')),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Server version string',
      text: 'The server announces itself the same way. Everything after these two lines uses SSH\'s binary packet format.',
      packet: sshConn.server(['PSH', 'ACK'], sshVersion('SSH-2.0-pwserver_1.0')),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Client KEXINIT: "Here\'s what I support."',
      text:
        'The client lists its supported algorithms for key exchange, host keys, encryption, integrity and compression as comma-separated name lists. ' +
        'Notice the binary packet framing: a length, a padding length, the message, and random padding that brings the total to a multiple of 8 bytes.',
      packet: sshConn.client(['PSH', 'ACK'], kexinit(9000)),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Server KEXINIT',
      text: 'The server sends its own lists. For each category, both sides independently pick the first algorithm in the client\'s list that the server also supports, so they always agree without another message.',
      packet: sshConn.server(['PSH', 'ACK'], kexinit(9050)),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Key exchange: client public key',
      text: 'With curve25519-sha256 chosen, the client sends a one-time Curve25519 public key. Its matching private key never leaves the laptop.',
      packet: sshConn.client(['PSH', 'ACK'], ecdhInit),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Key exchange reply and NEWKEYS',
      text:
        'The server sends its host key, its own one-time public key and a signature over the exchange, then NEWKEYS, in the same TCP segment. ' +
        'The client checks the host key against known_hosts and verifies the signature. This is what defeats a man-in-the-middle.',
      packet: sshConn.server(['PSH', 'ACK'], concat(ecdhReply, newKeys(9300))),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Client NEWKEYS',
      text: 'The client switches to the new keys as well. Both directions are now encrypted.',
      packet: sshConn.client(['PSH', 'ACK'], newKeys(9400)),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'First encrypted packet',
      text:
        'From here on, everything is ciphertext: the request to start user authentication, your password or key, and every keystroke of your session. ' +
        'Interactive sessions send small packets as you type, and their timing can still leak a little information. Modern OpenSSH adds fake keystroke packets to blur it.',
      packet: sshConn.client(['PSH', 'ACK'], sshEncrypted({ plaintext: 24, seed: 9500, hidden: 'SSH_MSG_SERVICE_REQUEST "ssh-userauth"' })),
    },
  ],
};

// ------------------------------------------------------------ FTP

const ftpCtl = new TcpConn(NET.server.ip, 49840, 21, 0x7d0e2c31, 0x44b8a90f);
ftpCtl.client(['SYN']);
ftpCtl.server(['SYN', 'ACK']);
ftpCtl.client(['ACK']);

const FILE = 'Welcome to the packet-walk FTP demo.\nEverything on this connection, including passwords, is plain text.\n';
const ftpData1 = new TcpConn(NET.server.ip, 49842, 50000, 0x1a77f0c2, 0x9203bd4e);
ftpData1.client(['SYN']);
ftpData1.server(['SYN', 'ACK']);
ftpData1.client(['ACK']);

const s = (line: string, title: string, text: string, info = text): Step => ({
  from: 'server', to: 'laptop', capture: ON_LAPTOP, title, text, packet: ftpCtl.server(['PSH', 'ACK'], ftp(line, info)),
});
const c = (line: string, title: string, text: string, info = text): Step => ({
  from: 'laptop', to: 'server', capture: ON_LAPTOP, title, text, packet: ftpCtl.client(['PSH', 'ACK'], ftp(line, info)),
});

const ftpLesson: Lesson = {
  id: 'ftp',
  title: 'FTP',
  protocols: ['FTP', 'TCP'],
  intro:
    'FTP is one of the oldest internet protocols (1971). It uses two TCP connections: a control connection for text commands, and a separate data connection for each file. It also sends everything, password included, in plain text, which makes it a good example of why encryption matters.',
  steps: [
    s('220 packet-walk FTP server ready', 'Server greeting', 'After the TCP handshake to port 21, the server speaks first. Every reply starts with a 3-digit code: 2xx means success, 3xx means "go on", and 4xx/5xx are errors.', 'A 220 reply means the service is ready.'),
    c('USER demo', 'USER', 'The client sends its username as a plain-text command, ending with CRLF, like every FTP line.'),
    s('331 Password required for demo', '331: need a password', 'A 3xx code means "fine so far, now send the next part".'),
    c('PASS hunter2', 'PASS: the password, in plain text', 'Look at the hex dump: the password is right there, readable by anyone who can see this traffic, such as other people on public Wi-Fi. This is why FTP has been replaced by SFTP (which runs over SSH) and FTPS (which runs over TLS).'),
    s('230 User demo logged in', '230: logged in', 'Authentication succeeded.'),
    c('PASV', 'PASV: "Where should I connect for data?"', 'Files do not travel over the control connection. In passive mode, the client asks the server to open a port and say which one, so the client can connect out to it. This works through NAT and firewalls.'),
    s('227 Entering Passive Mode (203,0,113,80,195,80)', '227: "Connect to port 50000"', 'The address and port are written as six numbers: four for the IP, then the port as two bytes. 195 × 256 + 80 = 50000. Embedding addresses inside the protocol is one reason FTP and NAT have never got along.', '203.0.113.80, port 195 × 256 + 80 = 50000.'),
    c('RETR welcome.txt', 'RETR: download a file', 'The client opens a second TCP connection to port 50000 (that handshake isn\'t shown) and asks for the file on the control connection.'),
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'The file, on the data connection',
      text:
        'The file arrives on the separate data connection. Look at the TCP ports: 50000 → 49842, not 21. Once the file is sent, the server closes this connection to mark the end of the file. ' +
        '(The "150 Opening data connection" reply sent on the control connection isn\'t shown.)',
      // The 150 reply is sent on the control connection first; it is not shown, but it advances the sequence numbers.
      packet: (ftpCtl.server(['PSH', 'ACK'], ftp('150 Opening data connection for welcome.txt', '')), ftpData1.server(['PSH', 'ACK'], ftpData(FILE))),
    },
    s('226 Transfer complete', '226: transfer complete', 'Back on the control connection, the server confirms that the whole file was sent. The client could now ask for another file, which would need another data connection, or send QUIT.'),
  ],
};

export const MORE = { dhcpLesson, websocketLesson, quicLesson, sshLesson, ftpLesson };
