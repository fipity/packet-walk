// Lessons for POP3, SMB and Wi-Fi.
import { Header, layer, randomBytes, type Packet } from '../bytes';
import { lines, type Line } from '../protocols/mail';
import { negotiateRequest, negotiateResponse, treeConnectRequest, treeConnectResponse, createRequest, readResponse, type Smb2Hdr } from '../protocols/smb';
import { beacon, authentication, associationRequest, associationResponse, eapolData, rsnIeBytes, protectedData } from '../protocols/wifi';
import { NET, ON_LAPTOP, TcpConn, fromLaptop, toLaptop, type Lesson, type Step } from './network';
import { MAIL, SENDER, MESSAGE_HEADERS, BODY } from './mail';

/** Stand-in payload for messages that are sent but not shown (keeps TCP sequence numbers honest). */
function unseen(n: number, seed: number): Packet {
  const h = new Header();
  h.bytes('Data', randomBytes(seed, n));
  return layer('Not shown', 'tcp', h);
}

// ------------------------------------------------------------ POP3

const pop = new TcpConn(MAIL.ip, 49860, 110, 0x2e6f71c0, 0x8d0a3b15);
pop.client(['SYN']);
pop.server(['SYN', 'ACK']);
pop.client(['ACK']);

const stored: Line[] = [
  { name: 'Header: Return-Path', text: `Return-Path: <alice@example.org>`, info: 'Added by the receiving server: the envelope sender from SMTP\'s MAIL FROM.' },
  { name: 'Header: Received', text: `Received: from ${SENDER.name} (${SENDER.name} [${SENDER.ip}])`, info: 'Each server that handles a message adds a Received header on top, so you can trace its route (reading from the bottom up).' },
  { name: 'Header: Received (folded)', text: '        by mail.example.com with ESMTP id 4Xb7Qk2mZ1z', info: 'A line that starts with whitespace continues the previous header ("folding").' },
  { name: 'Header: Received (folded)', text: '        for <bob@example.com>; Wed, 11 Nov 2026 09:41:01 +0000' },
  ...MESSAGE_HEADERS.map(([k, v]) => ({ name: `Header: ${k}`, text: `${k}: ${v}` })),
  { name: 'End of headers', text: '', value: 'CRLF' },
  ...BODY.map((t) => ({ name: 'Body line', text: t, value: t === '' ? '(blank line)' : t })),
];
const octets = stored.reduce((n, l) => n + l.text.length + 2, 0);

const popS = (title: string, text: string, ls: Line[], label = 'POP3 response'): Step => ({
  from: 'server', to: 'laptop', capture: ON_LAPTOP, title, text, packet: pop.server(['PSH', 'ACK'], lines(label, 'pop3', ls)),
});
const popC = (title: string, text: string, ls: Line[]): Step => ({
  from: 'laptop', to: 'server', capture: ON_LAPTOP, title, text, packet: pop.client(['PSH', 'ACK'], lines('POP3 command', 'pop3', ls)),
});

const pop3Lesson: Lesson = {
  id: 'pop3',
  title: 'POP3',
  protocols: ['POP3', 'TCP'],
  labels: { server: { label: MAIL.name, addr: MAIL.ip } },
  intro:
    'POP3 is the simpler, older way to collect email: connect, download everything, usually delete it from the server, and disconnect. Unlike IMAP there are no folders and no shared read/unread state, because the mailbox lives on your computer. ' +
    'Port 110 is shown here so you can read it. Real clients use 995 (POP3 inside TLS).',
  steps: [
    popS('Greeting: +OK', 'POP3 replies are as simple as it gets: "+OK" or "-ERR", followed by some text for humans.', [
      { name: 'Reply', text: '+OK POP3 server ready' },
    ]),
    popC('USER', 'Log in with a username.', [{ name: 'Command', text: 'USER bob' }]),
    popS('+OK', 'The server asks for the password.', [{ name: 'Reply', text: '+OK send your password' }]),
    popC('PASS', 'The password, in plain text. Inside TLS on port 995, nobody on the path could read it.', [
      { name: 'Command', text: 'PASS s3cret', info: 'Readable in the hex dump: never use POP3 without TLS.' },
    ]),
    popS('Mailbox locked and ready', 'The server locks the mailbox so that no other session can change it while this one is downloading.', [
      { name: 'Reply', text: `+OK maildrop has 2 messages (${octets + 2310} octets)` },
    ]),
    popC('LIST', 'Ask for the size of each message.', [{ name: 'Command', text: 'LIST' }]),
    popS('Scan listing', 'A multi-line response: one line per message (number and size in bytes), ending with a line containing only ".". Message 1 is Alice\'s email from the SMTP lesson.', [
      { name: 'Reply', text: '+OK 2 messages' },
      { name: 'Listing', text: `1 ${octets}`, info: 'Message 1 and its exact size in bytes as stored, including the headers the server added.' },
      { name: 'Listing', text: '2 2310' },
      { name: 'End of list', text: '.' },
    ]),
    popC('RETR 1', 'Download message 1, complete with headers.', [{ name: 'Command', text: 'RETR 1' }]),
    popS('The whole message', `Exactly ${octets} bytes of message, then the "." terminator, the same rule SMTP uses. Notice the Return-Path and Received headers that mail.example.com added when the message arrived.`, [
      { name: 'Reply', text: `+OK ${octets} octets` },
      ...stored,
      { name: 'End of message', text: '.' },
    ], 'POP3 response + message'),
    (() => {
      const step = popC('DELE 1', 'Mark message 1 for deletion. The server answers "+OK message 1 deleted" (not shown), but nothing is actually removed until the session ends cleanly. If the connection drops now, the message survives.', [
        { name: 'Command', text: 'DELE 1' },
      ]);
      pop.server(['PSH', 'ACK'], lines('POP3 response', 'pop3', [{ name: 'Reply', text: '+OK message 1 deleted' }]));
      return step;
    })(),
    popC('QUIT', 'QUIT moves the session to the UPDATE state, where deletions are carried out.', [{ name: 'Command', text: 'QUIT' }]),
    popS('Deleted and done', 'The message now exists only on Bob\'s laptop. This download-and-delete model is why POP3 fell out of favour once people started reading mail on several devices.', [
      { name: 'Reply', text: '+OK bye, 1 message deleted' },
    ]),
  ],
};

// ------------------------------------------------------------ SMB

const NAS = NET.router.ip;
const smbConn = new TcpConn(NAS, 49870, 445, 0x61b0d7e3, 0x0c55a2f8, {
  clientIp: NET.laptop.ip,
  frameClient: (dst, seg) => fromLaptop(dst, 'TCP', seg),
  frameServer: (src, seg) => toLaptop(src, 'TCP', seg, 64),
});
smbConn.client(['SYN']);
smbConn.server(['SYN', 'ACK']);
smbConn.client(['ACK']);

const SESSION = 0x0000_1c00_0000_0045;
const TREE = 5;
const base = (o: Partial<Smb2Hdr> & { command: number; response: boolean; messageId: number }): Smb2Hdr => ({
  credits: o.response ? 32 : 1, treeId: 0, sessionId: 0, signed: false, seed: 9600 + o.messageId * 2 + (o.response ? 1 : 0), ...o,
});
const FILE = 'Shopping list\r\n- coffee\r\n- bread\r\n- printer paper\r\n';
const CAPTURE = ON_LAPTOP;

const smbLesson: Lesson = {
  id: 'smb',
  title: 'SMB',
  protocols: ['SMB 3.1.1', 'TCP'],
  labels: { router: { label: 'Router + NAS', addr: `${NAS} · \\\\router\\docs` } },
  intro:
    'SMB is how Windows (and macOS, Linux and most NAS boxes) share files over a network. When you open \\\\server\\share in Explorer, this is the protocol underneath. Here the laptop reads a file from a USB drive shared by the home router.',
  steps: [
    {
      from: 'laptop', to: 'router', capture: CAPTURE,
      title: 'NEGOTIATE request',
      text:
        'Over TCP port 445, the client lists the SMB dialects it speaks, from 2.0.2 up to 3.1.1, plus its capabilities. Every message has a 64-byte SMB2 header with a command, message ID, credits, tree ID and session ID. ' +
        'SMB 3.1.1 adds "negotiate contexts" for downgrade protection and encryption.',
      packet: smbConn.client(['PSH', 'ACK'], negotiateRequest({ ...base({ command: 0, response: false, messageId: 0 }), guid: randomBytes(9501, 16), salt: randomBytes(9502, 32) })),
    },
    {
      from: 'router', to: 'laptop', capture: CAPTURE,
      title: 'NEGOTIATE response: SMB 3.1.1',
      text:
        'The server picks 3.1.1 and offers a small SPNEGO token listing the login methods it accepts. ' +
        'Next come two SESSION_SETUP round trips (not shown), where the laptop proves the user\'s identity with NTLM or Kerberos without sending the password. Those exchanges produce the keys used for signing.',
      packet: smbConn.server(['PSH', 'ACK'], negotiateResponse({ ...base({ command: 0, response: true, messageId: 0, credits: 1 }), guid: randomBytes(9503, 16), salt: randomBytes(9504, 32), time: Date.UTC(2026, 10, 11, 10, 2, 0) / 1000 })),
    },
    (() => {
      // Two SESSION_SETUP round trips happen here; they advance the TCP stream but aren't shown.
      smbConn.client(['PSH', 'ACK'], unseen(166, 9510));
      smbConn.server(['PSH', 'ACK'], unseen(305, 9511));
      smbConn.client(['PSH', 'ACK'], unseen(534, 9512));
      smbConn.server(['PSH', 'ACK'], unseen(81, 9513));
      return {
        from: 'laptop', to: 'router', capture: CAPTURE,
        title: 'TREE_CONNECT \\\\router\\docs',
        text:
          'Now signed in, with a session ID, the client connects to a share. The UNC path is in UTF-16LE, so every ASCII letter is followed by a 00 byte. ' +
          'From here on every message is signed: the Signature field proves it came from someone holding the session key.',
        packet: smbConn.client(['PSH', 'ACK'], treeConnectRequest({ ...base({ command: 3, response: false, messageId: 3, sessionId: SESSION, signed: true }), path: '\\\\router\\docs' })),
      } satisfies Step;
    })(),
    {
      from: 'router', to: 'laptop', capture: CAPTURE,
      title: 'TREE_CONNECT response',
      text: 'The server confirms that this is a disk share, says what this user may do there, and assigns a Tree ID that later commands use to refer to it.',
      packet: smbConn.server(['PSH', 'ACK'], treeConnectResponse(base({ command: 3, response: true, messageId: 3, sessionId: SESSION, treeId: TREE, signed: true }))),
    },
    {
      from: 'laptop', to: 'router', capture: CAPTURE,
      title: 'CREATE: open shopping.txt for reading',
      text:
        'Despite its name, CREATE is how SMB opens any file. The disposition FILE_OPEN means "only if it already exists". The server will reply with a 16-byte file ID (not shown), and the client then sends a READ for up to 8 MiB at that ID.',
      packet: smbConn.client(['PSH', 'ACK'], createRequest({ ...base({ command: 5, response: false, messageId: 4, sessionId: SESSION, treeId: TREE, signed: true }), name: 'shopping.txt' })),
    },
    (() => {
      smbConn.server(['PSH', 'ACK'], unseen(160, 9520)); // CREATE response
      smbConn.client(['PSH', 'ACK'], unseen(117, 9521)); // READ request
      return {
        from: 'router', to: 'laptop', capture: CAPTURE,
        title: 'READ response: the file',
        text:
          'The contents arrive in a READ response. They are signed, but readable on the wire. ' +
          'SMB 3 can encrypt per share or per server, and Windows Server and many NAS boxes can be set to require it. That matters most when SMB crosses networks you do not trust. Port 445 should never be open to the internet.',
        packet: smbConn.server(['PSH', 'ACK'], readResponse({ ...base({ command: 8, response: true, messageId: 5, sessionId: SESSION, treeId: TREE, signed: true }), data: FILE })),
      } satisfies Step;
    })(),
  ],
};

// ------------------------------------------------------------ Wi-Fi

const AP = NET.router.mac;
const STA = NET.laptop.mac;
const SSID = 'HomeNet';
const AIR = 'Captured over the air (Wi-Fi monitor mode)';
let apSeq = 1830;
let staSeq = 112;

const wifiLesson: Lesson = {
  id: 'wifi',
  title: 'Wi-Fi & WPA2',
  protocols: ['802.11', 'WPA2', 'EAPOL'],
  labels: { router: { label: 'Wi-Fi access point', addr: `"${SSID}" · channel 6` } },
  intro:
    'Before any IP packet moves, the laptop has to join the wireless network: find it, associate with it, and prove it knows the password, all without ever sending the password itself. ' +
    'These are raw 802.11 frames as a monitor-mode capture sees them. They have three addresses instead of two, little-endian fields, and the WPA2 4-way handshake.',
  steps: [
    {
      from: 'router', to: 'laptop', capture: AIR,
      title: 'Beacon: "HomeNet is here."',
      text:
        'About ten times a second, the access point broadcasts a beacon with its network name, supported rates, channel and security requirements (the RSN element: WPA2, AES-CCMP). This is what fills your list of nearby networks.',
      packet: beacon({ bssid: AP, ssid: SSID, seq: apSeq++, channel: 6, seed: 9700 }),
    },
    {
      from: 'laptop', to: 'router', capture: AIR,
      title: 'Authentication (Open System)',
      text: 'The laptop starts joining. Despite the name, this "authentication" is a formality left over from WEP and always succeeds. The real check comes later, in the 4-way handshake.',
      packet: authentication({ from: STA, to: AP, bssid: AP, seq: staSeq++, step: 1 }),
    },
    {
      from: 'router', to: 'laptop', capture: AIR,
      title: 'Authentication: success',
      text: 'The access point accepts. Every unicast frame like this one is also acknowledged with a tiny ACK control frame (not shown). Radio is lossy, so Wi-Fi retries at the link layer.',
      packet: authentication({ from: AP, to: STA, bssid: AP, seq: apSeq++, step: 2 }),
    },
    {
      from: 'laptop', to: 'router', capture: AIR,
      title: 'Association request',
      text: 'The laptop asks to join HomeNet and repeats the security settings it will use (its own RSN element), which must match what the access point offered.',
      packet: associationRequest({ from: STA, bssid: AP, ssid: SSID, seq: staSeq++ }),
    },
    {
      from: 'router', to: 'laptop', capture: AIR,
      title: 'Association response',
      text: 'Accepted, with association ID 1. The laptop is connected to the radio network, but the access point still blocks all its traffic except handshake (EAPOL) frames until it proves it knows the password.',
      packet: associationResponse({ to: STA, bssid: AP, seq: apSeq++, aid: 1 }),
    },
    {
      from: 'router', to: 'laptop', capture: AIR,
      title: '4-way handshake 1/4: ANonce',
      text:
        'Both sides already share the PMK, a 256-bit key derived from the Wi-Fi password and the network name. The access point sends a random number (ANonce). ' +
        'Note the data-frame format: From DS is set, and an LLC/SNAP header carries EtherType 0x888e (EAPOL).',
      packet: eapolData({ toDS: false, addr1: STA, addr2: AP, addr3: AP, seq: apSeq++, key: { msg: 1, replay: 1, nonce: randomBytes(9710, 32), mic: false, keyData: [], seed: 9711 } }),
    },
    {
      from: 'laptop', to: 'router', capture: AIR,
      title: '4-way handshake 2/4: SNonce + MIC',
      text:
        'The laptop picks its own random SNonce and computes the session key (PTK) from the PMK, both nonces and both MAC addresses. It sends the SNonce with a MIC computed from the new key. ' +
        'When the access point verifies that MIC, it knows the laptop has the right password. Anyone who captures these two messages can try guessing passwords offline, which is why WPA3 replaces this with SAE.',
      packet: eapolData({ toDS: true, addr1: AP, addr2: STA, addr3: AP, seq: staSeq++, key: { msg: 2, replay: 1, nonce: randomBytes(9720, 32), mic: true, keyData: rsnIeBytes(), keyDataInfo: 'A copy of the laptop\'s RSN element, so the access point can check that no attacker tampered with the security settings in the association.', seed: 9721 } }),
    },
    {
      from: 'router', to: 'laptop', capture: AIR,
      title: '4-way handshake 3/4: install keys + group key',
      text:
        'The access point proves that it knows the password too (with its own MIC) and tells the laptop to install the keys. It also sends the group key (GTK), encrypted with AES key wrap, which is used for broadcast and multicast traffic shared by everyone on the network.',
      packet: eapolData({ toDS: false, addr1: STA, addr2: AP, addr3: AP, seq: apSeq++, key: { msg: 3, replay: 2, nonce: randomBytes(9710, 32), mic: true, keyData: Array.from(randomBytes(9730, 56)), keyDataInfo: 'Encrypted (AES key wrap): the access point\'s RSN element and the group temporal key (GTK). Its length is a multiple of 8, as key wrap requires.', seed: 9731 } }),
    },
    {
      from: 'laptop', to: 'router', capture: AIR,
      title: '4-way handshake 4/4: done',
      text: 'The laptop confirms. Both sides switch on encryption, and the access point unblocks the laptop\'s traffic.',
      packet: eapolData({ toDS: true, addr1: AP, addr2: STA, addr3: AP, seq: staSeq++, key: { msg: 4, replay: 2, mic: true, keyData: [], seed: 9741 } }),
    },
    {
      from: 'laptop', to: 'router', capture: AIR,
      title: 'Encrypted data frame',
      text:
        'The first real packet, the DNS query from the "UDP & DNS" lesson, now travels encrypted with AES-CCMP. The Protected flag is set, an 8-byte CCMP header carries the packet number, and an 8-byte MIC ends the frame. ' +
        'The MAC addresses are still visible, but the IP addresses, ports and DNS question are not. The access point decrypts the frame and forwards it on as ordinary Ethernet.',
      packet: protectedData({ addr1: AP, addr2: STA, addr3: AP, seq: staSeq++, pn: 1, plaintext: 8 + 61, seed: 9750, hidden: 'an LLC/SNAP header and the 61-byte IPv4/UDP DNS query for www.example.com' }),
    },
  ],
};

export const LOCAL_LESSONS = { pop3Lesson, smbLesson, wifiLesson };
