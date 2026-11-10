// Lessons for SIP (VoIP calls with SDP and RTP), RTSP (IP camera streaming) and NTS (NTP secured with TLS).
import { concat, randomBytes } from '../bytes';
import { ethernet } from '../protocols/link';
import { ipv4, udp } from '../protocols/inet';
import { tlsClientHello, tlsServerHello, tlsEncrypted, tlsChangeCipherSpec } from '../protocols/app';
import { ntp } from '../protocols/infra';
import { withSdp, rtp, g711Payload, h264FuA, ntsRequestFields, ntsResponseFields } from '../protocols/media';
import type { Line } from '../protocols/mail';
import { NET, ON_LAPTOP, TcpConn, udpFromLaptop, udpToLaptop, type Lesson } from './network';

const hdr = (name: string, text: string, info?: string): Line => ({ name: `Header: ${name}`, text: `${name}: ${text}`, info });

// ------------------------------------------------------------ SIP

const PROXY = '203.0.113.70';
const BOB = '203.0.113.99';
const PUBLIC = NET.router.wan;
const CALL_ID = 'a84b4c76e66710@192.168.1.23';
const FROM = '"Alice" <sip:alice@example.com>;tag=1928301774';
const TO = '<sip:bob@example.com>';
const TO_TAGGED = '<sip:bob@example.com>;tag=a6c85cf';
const VIA_INFO = 'Records the path the request took, so responses can retrace it. The branch parameter identifies this transaction. "rport" asks the proxy to note the public port it saw, which helps with NAT.';

const via = (branch: string, response: boolean) =>
  hdr('Via', `SIP/2.0/UDP 192.168.1.23:5060;branch=${branch}${response ? `;received=${PUBLIC};rport=5060` : ';rport'}`,
    response ? 'Copied from the request, with "received" and "rport" added by the proxy: the address and port it actually saw. That is how the response gets back through the home router\'s NAT.' : VIA_INFO);

const OFFER = [
  'v=0',
  `o=alice 2890844526 2890844526 IN IP4 ${PUBLIC}`,
  's=-',
  `c=IN IP4 ${PUBLIC}`,
  't=0 0',
  'm=audio 49170 RTP/AVP 0 101',
  'a=rtpmap:0 PCMU/8000',
  'a=rtpmap:101 telephone-event/8000',
  'a=sendrecv',
];
const ANSWER = [
  'v=0',
  `o=bob 2808844564 2808844564 IN IP4 ${BOB}`,
  's=-',
  `c=IN IP4 ${BOB}`,
  't=0 0',
  'm=audio 30000 RTP/AVP 0 101',
  'a=rtpmap:0 PCMU/8000',
  'a=rtpmap:101 telephone-event/8000',
  'a=sendrecv',
];

const sipOut = (text: string, start: string, headers: Line[], sdp: string[] | null = null, label = 'SIP request') =>
  udpFromLaptop(PROXY, 5060, 5060, withSdp(label, 'sip', [{ name: 'Request line', text: start, info: text }], headers, sdp));
const sipIn = (text: string, start: string, headers: Line[], sdp: string[] | null = null) =>
  udpToLaptop(PROXY, 5060, 5060, withSdp('SIP response', 'sip', [{ name: 'Status line', text: start, info: text }], headers, sdp));

const ALICE_SSRC = 0x3a1f09c4;
const BOB_SSRC = 0x9b7e2d51;

const sipLesson: Lesson = {
  id: 'sip',
  title: 'SIP & RTP (VoIP)',
  protocols: ['SIP', 'SDP', 'RTP'],
  labels: {
    server: { label: 'sip.example.com', addr: `SIP proxy · ${PROXY}` },
    dns: { label: 'Bob\'s phone', addr: BOB, icon: 'phone' },
  },
  intro:
    'Internet phone calls, office desk phones and most mobile VoLTE calls use SIP to set up a call and RTP to carry the voice. SIP is a text protocol modelled on HTTP. It carries SDP, a description of which codecs and ports to use. ' +
    'Alice calls Bob through their provider\'s SIP proxy. Once the call is up, the audio flows directly between the two phones.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'INVITE with an SDP offer',
      text:
        'Alice\'s softphone sends INVITE to the proxy over UDP port 5060. The headers identify the call (Call-ID, From, To, CSeq), and the SDP body offers audio: send it to 198.51.100.7 port 49170 using G.711 µ-law (payload type 0) or telephone-event for keypad tones. ' +
        'The phone used STUN beforehand to learn its public address, since its private 192.168.1.23 would be useless to Bob.',
      packet: sipOut('INVITE asks to start a session. The Request-URI is who we want to reach.', 'INVITE sip:bob@example.com SIP/2.0', [
        via('z9hG4bK776asdhds', false),
        hdr('Max-Forwards', '70', 'Decremented by every proxy, like an IP TTL, to stop loops.'),
        hdr('From', FROM, 'The caller. The tag is a random value that, with the To tag and Call-ID, identifies the dialog (the call).'),
        hdr('To', TO, 'The person being called. Bob\'s phone will add its own tag.'),
        hdr('Call-ID', CALL_ID, 'A globally unique ID for this call.'),
        hdr('CSeq', '314159 INVITE', 'A sequence number plus the method, for matching responses and ordering requests in the dialog.'),
        hdr('Contact', `<sip:alice@${PUBLIC}:5060>`, 'Where Bob\'s phone should send requests later in the call, such as BYE.'),
        hdr('Content-Type', 'application/sdp'),
      ], OFFER, 'SIP INVITE'),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: '100 Trying',
      text: 'The proxy answers at once so that Alice\'s phone stops retransmitting (SIP over UDP retransmits on its own timers). Meanwhile, the proxy looks up where Bob is registered and forwards the INVITE to his phone. In practice the proxy usually first challenges Alice with "407 Proxy Authentication Required".',
      packet: sipIn('1xx responses are provisional: "working on it".', 'SIP/2.0 100 Trying', [via('z9hG4bK776asdhds', true), hdr('From', FROM), hdr('To', TO), hdr('Call-ID', CALL_ID), hdr('CSeq', '314159 INVITE')]),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: '180 Ringing',
      text: 'Bob\'s phone is ringing, and Alice hears a ringback tone. The To header now carries Bob\'s tag: an early dialog exists.',
      packet: sipIn('180 means the callee is being alerted.', 'SIP/2.0 180 Ringing', [via('z9hG4bK776asdhds', true), hdr('From', FROM), hdr('To', TO_TAGGED), hdr('Call-ID', CALL_ID), hdr('CSeq', '314159 INVITE'), hdr('Contact', `<sip:bob@${BOB}>`)]),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: '200 OK with the SDP answer',
      text:
        'Bob picks up. His phone answers the offer: send audio to 203.0.113.99 port 30000, G.711 µ-law. This offer/answer exchange is the whole negotiation, and both sides now know where to send media and how to encode it.',
      packet: sipIn('200 OK: the call is accepted.', 'SIP/2.0 200 OK', [via('z9hG4bK776asdhds', true), hdr('From', FROM), hdr('To', TO_TAGGED), hdr('Call-ID', CALL_ID), hdr('CSeq', '314159 INVITE'), hdr('Contact', `<sip:bob@${BOB}>`), hdr('Content-Type', 'application/sdp')], ANSWER),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'ACK: the three-way handshake completes',
      text: 'Alice confirms that she received the 200 OK. INVITE, 200 and ACK form SIP\'s own three-way handshake, needed because UDP gives no delivery guarantees.',
      packet: sipOut('ACK confirms the final response to an INVITE.', 'ACK sip:bob@203.0.113.99 SIP/2.0', [via('z9hG4bK74b43', false), hdr('Max-Forwards', '70'), hdr('From', FROM), hdr('To', TO_TAGGED), hdr('Call-ID', CALL_ID), hdr('CSeq', '314159 ACK')]),
    },
    {
      from: 'laptop', to: 'dns', capture: ON_LAPTOP,
      title: 'RTP: Alice\'s voice',
      text:
        'Audio now goes straight to Bob\'s phone, not through the proxy: one small UDP packet every 20 ms (50 a second) in each direction. Each holds 160 bytes of G.711 audio behind a 12-byte RTP header. ' +
        'This audio is not encrypted. Modern phones use SRTP, and get its keys through SIP over TLS (port 5061) or DTLS.',
      packet: udpFromLaptop(BOB, 49170, 30000, rtp({ pt: 0, ptName: 'PCMU / G.711 µ-law', seq: 18203, ts: 1611520, tsInfo: 'Counts audio samples (8,000 per second here), not wall-clock time. It goes up by 160 per 20 ms packet, so the receiver can play audio back smoothly despite network jitter.', ssrc: ALICE_SSRC, marker: true, payload: g711Payload(9850) })),
    },
    {
      from: 'dns', to: 'laptop', capture: ON_LAPTOP,
      title: 'RTP: Bob\'s voice',
      text: 'Bob\'s stream has its own SSRC, sequence numbers and timestamps. The two directions are independent. Separate RTCP packets (not shown) report loss and jitter so the phones can adapt.',
      packet: udpToLaptop(BOB, 30000, 49170, rtp({ pt: 0, ptName: 'PCMU / G.711 µ-law', seq: 5402, ts: 744320, tsInfo: 'Bob\'s own timestamp sequence, which starts at a random value.', ssrc: BOB_SSRC, payload: g711Payload(9851) })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'BYE: hanging up',
      text: 'Alice hangs up. BYE ends the dialog, and both phones stop sending RTP. The CSeq number goes up, since this is a new request in the same dialog.',
      packet: sipOut('BYE terminates the call.', 'BYE sip:bob@203.0.113.99 SIP/2.0', [via('z9hG4bKnashds10', false), hdr('Max-Forwards', '70'), hdr('From', FROM), hdr('To', TO_TAGGED), hdr('Call-ID', CALL_ID), hdr('CSeq', '314160 BYE')]),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: '200 OK: call ended',
      text: 'Bob\'s phone confirms the BYE. The call is over.',
      packet: sipIn('200 OK to the BYE.', 'SIP/2.0 200 OK', [via('z9hG4bKnashds10', true), hdr('From', FROM), hdr('To', TO_TAGGED), hdr('Call-ID', CALL_ID), hdr('CSeq', '314160 BYE')]),
    },
  ],
};

// ------------------------------------------------------------ RTSP

const CAM = { ip: '192.168.1.64', mac: '02:00:00:ca:00:64' };
const URL = `rtsp://${CAM.ip}/stream1`;
const SESSION = '7F3A2C91';
const camIds = [0x6100, 0x1200];
const rtsp = new TcpConn(CAM.ip, 49910, 554, 0x0f1e2d3c, 0x4b5a6978, {
  clientIp: NET.laptop.ip,
  frameClient: (dst, seg) => ethernet({ dst: CAM.mac, src: NET.laptop.mac, type: 'IPv4' }, ipv4({ src: NET.laptop.ip, dst, proto: 'TCP', ttl: 64, id: camIds[0]++ }, seg)),
  frameServer: (src, seg) => ethernet({ dst: NET.laptop.mac, src: CAM.mac, type: 'IPv4' }, ipv4({ src, dst: NET.laptop.ip, proto: 'TCP', ttl: 64, id: camIds[1]++ }, seg)),
});
rtsp.client(['SYN']);
rtsp.server(['SYN', 'ACK']);
rtsp.client(['ACK']);

const CAM_SDP = [
  'v=0',
  `o=- 1762851600 1 IN IP4 ${CAM.ip}`,
  's=Front door',
  'c=IN IP4 0.0.0.0',
  't=0 0',
  'a=control:*',
  'm=video 0 RTP/AVP 96',
  'a=rtpmap:96 H264/90000',
  'a=fmtp:96 packetization-mode=1;profile-level-id=640028',
  'a=control:trackID=1',
];

const rtspReq = (title: string, text: string, start: string, info: string, headers: Line[]) => ({
  from: 'laptop' as const, to: 'router' as const, capture: ON_LAPTOP, title, text,
  packet: rtsp.client(['PSH', 'ACK'], withSdp('RTSP request', 'rtsp', [{ name: 'Request line', text: start, info }], [...headers, hdr('User-Agent', 'packet-walk/0.1')], null)),
});
const rtspResp = (title: string, text: string, headers: Line[], sdp: string[] | null = null) => ({
  from: 'router' as const, to: 'laptop' as const, capture: ON_LAPTOP, title, text,
  packet: rtsp.server(['PSH', 'ACK'], withSdp('RTSP response', 'rtsp', [{ name: 'Status line', text: 'RTSP/1.0 200 OK' }], headers, sdp)),
});

const rtspLesson: Lesson = {
  id: 'rtsp',
  title: 'RTSP (IP camera)',
  protocols: ['RTSP', 'SDP', 'RTP', 'H.264'],
  labels: { router: { label: 'IP camera', addr: `${CAM.ip} · RTSP 554`, icon: 'camera' } },
  intro:
    'Security cameras and many video tools (VLC, NVRs, ffmpeg) use RTSP, a "remote control" for media streams with commands like SETUP, PLAY and TEARDOWN. As with SIP, the media itself travels separately over RTP. ' +
    'Here a laptop opens rtsp://192.168.1.64/stream1 on the home network.',
  steps: [
    rtspReq('DESCRIBE: "What does this stream contain?"', 'RTSP looks like HTTP: a request line, headers and a CSeq number that every response echoes. Real cameras usually answer with "401 Unauthorized" first and require a Digest login (not shown).',
      `DESCRIBE ${URL} RTSP/1.0`, 'DESCRIBE asks for a description of the media.', [hdr('CSeq', '2', 'Sequence number, echoed in the response.'), hdr('Accept', 'application/sdp')]),
    rtspResp('200 OK with SDP', 'The camera describes its stream in SDP: one video track, H.264 at a 90 kHz RTP clock, with a control URL for the track.',
      [hdr('CSeq', '2'), hdr('Content-Base', `${URL}/`, 'Relative control URLs in the SDP are resolved against this one.'), hdr('Content-Type', 'application/sdp')], CAM_SDP),
    rtspReq('SETUP: "Send the video to these ports."', 'The client chooses how to receive the track: unicast RTP over UDP to ports 50000 (RTP) and 50001 (RTCP). Over unreliable networks, clients often ask for RTP interleaved in the RTSP TCP connection instead.',
      `SETUP ${URL}/trackID=1 RTSP/1.0`, 'SETUP prepares one media track.', [hdr('CSeq', '3'), hdr('Transport', 'RTP/AVP;unicast;client_port=50000-50001', 'The transport parameters the client wants.')]),
    rtspResp('200 OK: session created', 'The camera agrees, says which ports it will send from, and creates a session. Every later request must carry this Session ID.',
      [hdr('CSeq', '3'), hdr('Session', `${SESSION};timeout=60`, 'RTSP is stateful: this session ID names the stream setup on the server. If the client is silent for 60 seconds, the session is dropped.'), hdr('Transport', 'RTP/AVP;unicast;client_port=50000-50001;server_port=6970-6971;ssrc=1B2C3D4E')]),
    rtspReq('PLAY', 'Start streaming from the beginning (npt = normal play time). For a live camera, "the beginning" simply means now.',
      `PLAY ${URL}/ RTSP/1.0`, 'PLAY starts the media flowing.', [hdr('CSeq', '4'), hdr('Session', SESSION), hdr('Range', 'npt=0.000-')]),
    rtspResp('200 OK with RTP-Info', 'RTP-Info gives the first RTP sequence number and timestamp, so the client can line the RTP stream up with the play position.',
      [hdr('CSeq', '4'), hdr('Session', SESSION), hdr('RTP-Info', `url=${URL}/trackID=1;seq=21000;rtptime=3600000`)]),
    {
      from: 'router', to: 'laptop', capture: ON_LAPTOP,
      title: 'RTP: a slice of video',
      text:
        'The video arrives over UDP, separate from the RTSP connection. A single H.264 keyframe can be 50–200 KB, so it is split across many RTP packets. This is the first fragment (FU-A, start bit set). ' +
        'The timestamp uses a 90,000 Hz clock: at 25 frames a second, it goes up by 3,600 per frame.',
      packet: ethernet({ dst: NET.laptop.mac, src: CAM.mac, type: 'IPv4' }, ipv4({ src: CAM.ip, dst: NET.laptop.ip, proto: 'UDP', ttl: 64, id: 0x2300, df: false },
        udp({ src: CAM.ip, dst: NET.laptop.ip, srcPort: 6970, dstPort: 50000 },
          rtp({ pt: 96, ptName: 'dynamic: H264/90000', seq: 21000, ts: 3600000, tsInfo: 'A 90 kHz clock, as declared in the SDP rtpmap. All fragments of one frame share the same timestamp.', ssrc: 0x1b2c3d4e, payload: h264FuA(9860, 1000) })))),
    },
    rtspReq('TEARDOWN', 'Stop the stream and release the session.', `TEARDOWN ${URL}/ RTSP/1.0`, 'TEARDOWN ends the session.', [hdr('CSeq', '5'), hdr('Session', SESSION)]),
    rtspResp('200 OK: stream stopped', 'The camera stops sending RTP. Note that the RTSP traffic here, including any login, was unencrypted. Cameras that support RTSPS (RTSP over TLS, port 322) or SRTP should use them, and cameras should never be exposed directly to the internet.',
      [hdr('CSeq', '5'), hdr('Session', SESSION)]),
  ],
};

// ------------------------------------------------------------ NTS (NTP over TLS)

const NTS = { ip: '203.0.113.123', name: 'time.example.com' };
const nts = new TcpConn(NTS.ip, 49920, 4460, 0x5e6f7081, 0x92a3b4c5);
nts.client(['SYN']);
nts.server(['SYN', 'ACK']);
nts.client(['ACK']);

const UID = randomBytes(9870, 32);
const COOKIE = randomBytes(9871, 104);
const t0 = Date.UTC(2026, 10, 11, 10, 15, 0) / 1000;
const ntsUdp = (out: boolean, payload: ReturnType<typeof concat>) =>
  out ? udpFromLaptop(NTS.ip, 41838, 123, payload) : udpToLaptop(NTS.ip, 123, 41838, payload);

const ntsLesson: Lesson = {
  id: 'nts',
  title: 'NTS (NTP over TLS)',
  protocols: ['NTS', 'NTP', 'TLS 1.3'],
  labels: { server: { label: `${NTS.name} (NTS)`, addr: NTS.ip } },
  intro:
    'Plain NTP (see the NTP lesson) has no authentication. Anyone on the path can forge a reply and shift your clock, which can break certificate checks and replay protection. Network Time Security fixes this in two phases. ' +
    'First, a short TLS 1.3 session ("NTS Key Establishment") agrees on keys and hands out cookies. Then ordinary NTP over UDP carries extra fields that authenticate every packet.',
  steps: [
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'NTS-KE: TLS ClientHello on port 4460',
      text: 'The client opens a TCP connection to port 4460 and starts TLS 1.3, asking via ALPN for the protocol "ntske/1". The server\'s certificate is what proves this is really time.example.com, the trust that plain NTP lacks.',
      packet: nts.client(['PSH', 'ACK'], tlsClientHello({ sni: NTS.name, seed: 9880, alpn: 'ntske/1' })),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'ServerHello + encrypted handshake',
      text: 'A normal TLS 1.3 handshake, as in the HTTPS lesson: key share, then the encrypted certificate, signature and Finished. The client checks the certificate the same way a browser would.',
      packet: nts.server(['PSH', 'ACK'], concat(tlsServerHello({ seed: 9881, sessionSeed: 9882 }), tlsEncrypted({ plaintextLength: 980, seed: 9883, hidden: 'EncryptedExtensions (ALPN "ntske/1"), Certificate, CertificateVerify and Finished' }))),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'NTS-KE request (encrypted)',
      text:
        'After its Finished message, the client sends a tiny NTS-KE request of three records: "next protocol: NTPv4", "AEAD algorithm: AES-SIV-CMAC-256", and "end of message". ' +
        'Both sides then use the TLS exporter to derive two keys for NTP, one for each direction, without sending them.',
      packet: nts.client(['PSH', 'ACK'], concat(tlsChangeCipherSpec(), tlsEncrypted({ plaintextLength: 36, seed: 9884, hidden: 'the client Finished message' }), tlsEncrypted({ plaintextLength: 16, seed: 9885, hidden: 'NTS-KE records: Next Protocol = NTPv4, AEAD = AES-SIV-CMAC-256 (15), End of Message' }))),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'NTS-KE response: eight cookies',
      text:
        'The server confirms the choices and hands over eight cookies. Each cookie is the session keys, encrypted under a secret only the server holds. The server can therefore throw away all per-client state and still verify later NTP packets. ' +
        'The TLS connection then closes. It is only needed again when the cookies run out.',
      packet: nts.server(['PSH', 'ACK'], tlsEncrypted({ plaintextLength: 880, seed: 9886, hidden: 'NTS-KE records: Next Protocol, AEAD algorithm, 8 × NTS New Cookie (104 bytes each), End of Message' })),
    },
    {
      from: 'laptop', to: 'server', capture: ON_LAPTOP,
      title: 'Authenticated NTP request',
      text:
        'Now an ordinary 48-byte NTP request goes to UDP port 123, followed by three extension fields: a unique ID, one cookie, and an authenticator that covers the whole packet. ' +
        'The time stamps themselves are not encrypted. NTS is about authenticity, not secrecy.',
      packet: ntsUdp(true, concat(
        ntp({ mode: 3, stratum: 0, poll: 6, precision: -20, rootDelay: 0, rootDispersion: 0, refId: '', reference: 0, origin: 0, receive: 0, transmit: t0 + 0.0031 }),
        ntsRequestFields({ uid: UID, cookie: COOKIE, seed: 9887 }),
      )),
    },
    {
      from: 'server', to: 'laptop', capture: ON_LAPTOP,
      title: 'Authenticated NTP response',
      text:
        'The server decrypts the cookie to recover the keys, checks the request, and replies with the timestamps, the echoed unique ID, and an authenticator. It also sends a fresh cookie, encrypted inside, to replace the one just used. ' +
        'If an attacker changed even one timestamp bit, the client would reject the reply. The offset and delay arithmetic is then exactly as in the NTP lesson.',
      packet: ntsUdp(false, concat(
        ntp({ mode: 4, stratum: 2, poll: 6, precision: -23, rootDelay: 0.0153, rootDispersion: 0.0211, refId: '192.0.2.123', reference: t0 - 40.5, origin: t0 + 0.0031, receive: t0 + 0.0152, transmit: t0 + 0.0153 }),
        ntsResponseFields({ uid: UID, seed: 9888, cookieLen: 104 }),
      )),
    },
  ],
};

export const REALTIME = { sipLesson, rtspLesson, ntsLesson };
