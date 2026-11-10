// Lessons for SMTP, IMAP and WireGuard.
import { ethernet } from '../protocols/link';
import { ipv4 } from '../protocols/inet';
import { lines, wgInitiation, wgResponse, wgData } from '../protocols/mail';
import { TcpConn, udpFromLaptop, udpToLaptop, ON_LAPTOP, type Lesson, type Step } from './network';

const MAIL = { ip: '203.0.113.25', mac: '02:00:00:cc:00:25', gw: '02:00:00:cc:00:01', name: 'mail.example.com' };
const SENDER = { ip: '198.51.100.25', name: 'mail.example.org' };

const MESSAGE_HEADERS: [string, string][] = [
  ['From', 'Alice <alice@example.org>'],
  ['To', 'Bob <bob@example.com>'],
  ['Subject', 'Lunch on Friday?'],
  ['Date', 'Wed, 11 Nov 2026 09:41:00 +0000'],
  ['Message-ID', '<20261111094100.4f2a@example.org>'],
];
const BODY = ['Hi Bob,', '', 'Are you free for lunch on Friday?', '', '-- Alice'];

// ------------------------------------------------------------ SMTP

const ids = [0x3a00, 0x7c00];
const AT_SERVER = 'Captured on mail.example.com\'s network link';

const smtpConn = new TcpConn(MAIL.ip, 51544, 25, 0x4d1c2e07, 0xa03b6611, {
  clientIp: SENDER.ip,
  frameClient: (dst, seg) => ethernet({ dst: MAIL.mac, src: MAIL.gw, type: 'IPv4' }, ipv4({ src: SENDER.ip, dst, proto: 'TCP', ttl: 52, id: ids[0]++ }, seg)),
  frameServer: (src, seg) => ethernet({ dst: MAIL.gw, src: MAIL.mac, type: 'IPv4' }, ipv4({ src, dst: SENDER.ip, proto: 'TCP', ttl: 64, id: ids[1]++ }, seg)),
});
smtpConn.client(['SYN']);
smtpConn.server(['SYN', 'ACK']);
smtpConn.client(['ACK']);

const smtpS = (title: string, text: string, ls: Parameters<typeof lines>[2]): Step => ({
  from: 'server', to: 'laptop', capture: AT_SERVER, title, text, packet: smtpConn.server(['PSH', 'ACK'], lines('SMTP reply', 'smtp', ls)),
});
const smtpC = (title: string, text: string, ls: Parameters<typeof lines>[2], label = 'SMTP command'): Step => ({
  from: 'laptop', to: 'server', capture: AT_SERVER, title, text, packet: smtpConn.client(['PSH', 'ACK'], lines(label, 'smtp', ls)),
});

const smtpLesson: Lesson = {
  id: 'smtp',
  title: 'SMTP',
  protocols: ['SMTP', 'TCP'],
  labels: {
    laptop: { label: SENDER.name, addr: SENDER.ip },
    router: { label: 'Router', addr: '' },
    server: { label: MAIL.name, addr: MAIL.ip },
  },
  intro:
    'Email travels between servers using SMTP, a text protocol from 1982 that still carries billions of messages a day. Alice\'s mail server (mail.example.org) delivers her message to Bob\'s (mail.example.com) on TCP port 25. ' +
    'Real servers almost always switch to encryption with STARTTLS right after EHLO. This lesson skips that step so you can read the conversation.',
  steps: [
    smtpS('Greeting: 220', 'The receiving server speaks first. Like FTP, every SMTP reply starts with a 3-digit code: 2xx success, 3xx "continue", 4xx "try again later", 5xx "permanent failure".', [
      { name: 'Reply', text: '220 mail.example.com ESMTP ready', info: '220 means the service is ready.' },
    ]),
    smtpC('EHLO: "Hello, I\'m mail.example.org."', 'The sending server introduces itself. EHLO (extended hello) rather than the original HELO asks the server to list its extensions.', [
      { name: 'Command', text: 'EHLO mail.example.org', info: 'The argument is the client\'s own host name. Receivers often check that it matches the connecting IP address.' },
    ]),
    smtpS('Extensions list', 'A multi-line reply: every line except the last has a hyphen after the code. Each line advertises an extension.', [
      { name: 'Reply line', text: '250-mail.example.com' },
      { name: 'Extension', text: '250-PIPELINING', info: 'The client may send several commands without waiting for each reply, which saves round trips.' },
      { name: 'Extension', text: '250-SIZE 52428800', info: 'The largest message accepted: 50 MB.' },
      { name: 'Extension', text: '250-STARTTLS', info: 'The server can switch this connection to TLS. A real sender would use it here.' },
      { name: 'Extension', text: '250-8BITMIME', info: 'Message bodies may contain 8-bit bytes, not just 7-bit ASCII.' },
      { name: 'Extension', text: '250-ENHANCEDSTATUSCODES', info: 'Replies add a more detailed x.y.z code, such as 2.1.0.' },
      { name: 'Last line', text: '250 SMTPUTF8', info: 'No hyphen after the code: this is the last line. SMTPUTF8 allows non-ASCII email addresses.' },
    ]),
    smtpC('Envelope: MAIL FROM, RCPT TO, DATA (pipelined)', 'Thanks to PIPELINING, three commands go in one segment. MAIL FROM and RCPT TO form the envelope: the addresses SMTP actually delivers by. They can differ from the From: and To: headers inside the message. Bcc works this way, and so does spoofing.', [
      { name: 'Command', text: 'MAIL FROM:<alice@example.org>', info: 'The envelope sender, where bounces go. Receivers check it against SPF records in DNS.' },
      { name: 'Command', text: 'RCPT TO:<bob@example.com>', info: 'One RCPT per recipient.' },
      { name: 'Command', text: 'DATA', info: '"The message itself comes next."' },
    ]),
    smtpS('Three replies in one', 'The server answers all three in order. 354 means "go ahead, send the message, and end it with a line containing only a dot".', [
      { name: 'Reply', text: '250 2.1.0 Ok' },
      { name: 'Reply', text: '250 2.1.5 Ok' },
      { name: 'Reply', text: '354 End data with <CR><LF>.<CR><LF>' },
    ]),
    smtpC('The message', 'Headers, a blank line, then the body, ending with "." on a line of its own. Any line in the body that starts with a dot gets a second dot added ("dot-stuffing"), so it cannot end the message early. ' +
      'Real senders also add a DKIM-Signature header: a signature that lets the receiver check the message really came from example.org.', [
      ...MESSAGE_HEADERS.map(([k, v]) => ({ name: `Header: ${k}`, text: `${k}: ${v}` })),
      { name: 'End of headers', text: '', value: 'CRLF', info: 'A blank line separates the headers from the body.' },
      ...BODY.map((t) => ({ name: 'Body line', text: t, value: t === '' ? '(blank line)' : t })),
      { name: 'End of data', text: '.', info: 'A lone dot ends the message.' },
    ], 'Email message'),
    smtpS('Queued: 250', 'The server has taken responsibility for the message. It adds a "Received:" header and files the message in Bob\'s mailbox. If it could not deliver it, it would now have to send a bounce to the envelope sender.', [
      { name: 'Reply', text: '250 2.0.0 Ok: queued as 4Xb7Qk2mZ1z', info: 'The queue ID is useful for tracing the message in the server logs.' },
    ]),
    smtpC('QUIT', 'The sender ends the session. It could also have sent more messages over the same connection first.', [{ name: 'Command', text: 'QUIT' }]),
    smtpS('221: goodbye', 'The server confirms and both sides close the TCP connection. The next lesson picks up from here: Bob reads the message using IMAP.', [{ name: 'Reply', text: '221 2.0.0 Bye' }]),
  ],
};

// ------------------------------------------------------------ IMAP

const imapConn = new TcpConn(MAIL.ip, 49850, 143, 0x15f0c3a2, 0x6b2d9e44);
imapConn.client(['SYN']);
imapConn.server(['SYN', 'ACK']);
imapConn.client(['ACK']);

const imapS = (title: string, text: string, ls: Parameters<typeof lines>[2]): Step => ({
  from: 'server', to: 'laptop', capture: ON_LAPTOP, title, text, packet: imapConn.server(['PSH', 'ACK'], lines('IMAP response', 'imap', ls)),
});
const imapC = (title: string, text: string, ls: Parameters<typeof lines>[2]): Step => ({
  from: 'laptop', to: 'server', capture: ON_LAPTOP, title, text, packet: imapConn.client(['PSH', 'ACK'], lines('IMAP command', 'imap', ls)),
});

const literal = `From: ${MESSAGE_HEADERS[0][1]}\r\nSubject: ${MESSAGE_HEADERS[2][1]}\r\n\r\n`;

const imapLesson: Lesson = {
  id: 'imap',
  title: 'IMAP',
  protocols: ['IMAP', 'TCP'],
  labels: { server: { label: MAIL.name, addr: MAIL.ip } },
  intro:
    'IMAP lets a mail app work with a mailbox that lives on the server, so your phone and laptop see the same folders and read/unread state. Bob\'s laptop picks up Alice\'s message from the SMTP lesson. ' +
    'This uses plain port 143 so you can read it. Real mail apps use port 993, which is IMAP inside TLS, and servers normally refuse plain-text logins.',
  steps: [
    imapS('Server greeting', 'Lines that start with "*" are untagged: information the server sends without being asked for it specifically. The greeting includes the server\'s capabilities.', [
      { name: 'Untagged OK', text: '* OK [CAPABILITY IMAP4rev2 AUTH=PLAIN IDLE] mail.example.com ready', info: 'IMAP4rev2 is the current version (RFC 9051). IDLE lets the server push new-mail notifications.' },
    ]),
    imapC('LOGIN', 'Every client command starts with a tag the client makes up, here "a1". The server uses the same tag to say which command a reply answers, so several commands can be in progress at once.', [
      { name: 'Tagged command', text: 'a1 LOGIN bob s3cret', info: 'Username and password in plain text, readable in the hex dump. This is exactly why IMAP should run inside TLS.' },
    ]),
    imapS('Logged in', 'The tagged OK completes command a1.', [
      { name: 'Tagged OK', text: 'a1 OK Logged in', info: 'Tagged replies end a command: OK, NO (failed) or BAD (protocol error).' },
    ]),
    imapC('SELECT INBOX', 'Open a mailbox. IMAP supports many folders, and the client chooses which one to work in.', [{ name: 'Tagged command', text: 'a2 SELECT INBOX' }]),
    imapS('Mailbox status', 'Several untagged lines describe the mailbox, then the tagged OK closes the command. Bob has 3 messages.', [
      { name: 'Untagged EXISTS', text: '* 3 EXISTS', info: 'Number of messages in the mailbox. They are numbered 1 to 3.' },
      { name: 'Untagged FLAGS', text: '* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)', info: 'The system flags. \\Seen is what makes a message "read". Because it is stored on the server, every device agrees.' },
      { name: 'Untagged OK', text: '* OK [UIDVALIDITY 1762850000] UIDs valid', info: 'Messages also have permanent unique IDs (UIDs), which let clients cache safely. If this number ever changes, the client must throw away its cache.' },
      { name: 'Untagged OK', text: '* OK [UIDNEXT 4] Predicted next UID' },
      { name: 'Tagged OK', text: 'a2 OK [READ-WRITE] SELECT completed' },
    ]),
    imapC('FETCH just the headers', 'Fetch the sender and subject of message 3, the new one. BODY.PEEK reads it without marking it \\Seen, which is how mail apps show an inbox list without "reading" everything.', [
      { name: 'Tagged command', text: 'a3 FETCH 3 (FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])' },
    ]),
    imapS('FETCH response with a literal', `Data that may contain anything, even line breaks, is sent as a literal: {${literal.length}} announces exactly ${literal.length} bytes, which follow after a line break. The receiver counts bytes instead of looking for an ending. ` +
      'The FLAGS list is empty, so the message is unread.', [
      { name: 'Untagged FETCH', text: `* 3 FETCH (FLAGS () BODY[HEADER.FIELDS (FROM SUBJECT)] {${literal.length}}`, info: `The {${literal.length}} at the end says a ${literal.length}-byte literal follows.` },
      { name: 'Literal', text: literal, raw: true, value: `${literal.length} bytes: From + Subject headers`, info: 'Exactly the announced number of bytes, including its own CRLFs.' },
      { name: 'End of FETCH', text: ')' },
      { name: 'Tagged OK', text: 'a3 OK FETCH completed' },
    ]),
    imapC('IDLE: "Tell me when something arrives."', 'Instead of checking every few minutes, the client says IDLE and waits. The server replies "+ idling" (not shown), and the connection stays open.', [
      { name: 'Tagged command', text: 'a4 IDLE' },
    ]),
    imapS('Push: new mail', 'Some time later another message arrives, and the server immediately pushes an untagged EXISTS. That is why new mail shows up instantly. The client will send DONE to end IDLE and then FETCH message 4.', [
      { name: 'Untagged EXISTS', text: '* 4 EXISTS', info: 'The mailbox now has 4 messages.' },
    ]),
  ],
};

// ------------------------------------------------------------ WireGuard

const VPN = { ip: '203.0.113.51', port: 51820 };
const WG_PORT = 43512;
const I_IDX = 0x8c1e5a73;
const R_IDX = 0x2f90d41b;

const wireguardLesson: Lesson = {
  id: 'wireguard',
  title: 'WireGuard',
  protocols: ['WireGuard', 'UDP'],
  labels: { server: { label: 'VPN server', addr: VPN.ip } },
  intro:
    'WireGuard is a modern VPN. It builds an encrypted tunnel over UDP using just four message types, one fixed set of cryptography (Curve25519, ChaCha20-Poly1305 and BLAKE2s), and keys configured in advance like SSH keys. ' +
    'Here the laptop (tunnel address 10.8.0.2) connects to a VPN server (tunnel address 10.8.0.1) on UDP port 51820.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Handshake initiation',
      text:
        'Before the first packet goes through the tunnel, the laptop sends a 148-byte handshake initiation. It carries a one-time public key, the laptop\'s identity (encrypted), a timestamp against replays, and MAC1, which proves the sender knows the server\'s public key. ' +
        'There is no version number and no algorithm negotiation. If the cryptography ever needs to change, the protocol version changes with it.',
      packet: udpFromLaptop(VPN.ip, WG_PORT, VPN.port, wgInitiation({ sender: I_IDX, seed: 7100 })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Handshake response',
      text:
        'The server recognises the laptop\'s key in its configuration and answers with 92 bytes. That completes the handshake in a single round trip, and both sides now hold fresh session keys. ' +
        'They are replaced every two minutes, and the old ones are erased.',
      packet: udpToLaptop(VPN.ip, VPN.port, WG_PORT, wgResponse({ sender: R_IDX, receiver: I_IDX, seed: 7200 })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Tunnelled packet',
      text:
        'Now the laptop pings 10.8.0.1 through the tunnel. The whole inner IPv4 packet (84 bytes) is encrypted and padded to 96 bytes. An observer sees only UDP to 203.0.113.51:51820, a session index, a counter and ciphertext. ' +
        'The 32-byte overhead (16-byte header and 16-byte tag) is part of why WireGuard is fast.',
      packet: udpFromLaptop(VPN.ip, WG_PORT, VPN.port, wgData({ receiver: R_IDX, counter: 0, plaintext: 84, seed: 7300, hidden: 'an IPv4 ICMP echo request from 10.8.0.2 to 10.8.0.1' })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Tunnelled reply',
      text:
        'The server decrypts the packet and checks that its inner source address, 10.8.0.2, is in this peer\'s AllowedIPs. That check ties each tunnel address to a key, which WireGuard calls cryptokey routing. The reply comes back the same way.',
      packet: udpToLaptop(VPN.ip, VPN.port, WG_PORT, wgData({ receiver: I_IDX, counter: 0, plaintext: 84, seed: 7400, hidden: 'an IPv4 ICMP echo reply from 10.8.0.1 to 10.8.0.2' })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Keepalive',
      text:
        'WireGuard stays silent when there is nothing to send, which is good for phone batteries and makes it hard to detect. But a home router\'s NAT forgets idle UDP mappings, so with PersistentKeepalive = 25 the laptop sends an empty 32-byte packet every 25 seconds to keep the mapping open. ' +
        'Notice the counter has moved on to 1.',
      packet: udpFromLaptop(VPN.ip, WG_PORT, VPN.port, wgData({ receiver: R_IDX, counter: 1, plaintext: 0, seed: 7500, hidden: '' })),
    },
  ],
};

export const MAIL_LESSONS = { smtpLesson, imapLesson, wireguardLesson };
