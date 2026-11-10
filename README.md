# packet-walk

**See how the internet works, one packet at a time.**

packet-walk is a free, open-source, interactive explainer for the protocols that move
data across the internet. Each lesson steps through a real exchange on a small
imaginary network (laptop → home router → internet → server), and every packet is
encoded for real and decoded byte by byte: click any field to see its bytes, or click any byte
to see which field it belongs to and what it means.

**Live site:** https://fipity.github.io/packet-walk/

## Lessons

| # | Layer | Lesson | Protocols |
|---|-------|--------|-----------|
| 1 | L1 Physical | Physical layer: preamble, SFD and a real CRC-32 FCS; a flipped bit | Ethernet PHY |
| 2 | L2 Link | Ethernet & ARP: finding the router | Ethernet II, ARP |
| 3 | L2 Link | Wi-Fi & WPA2: beacon, association, 4-way handshake, CCMP | 802.11, EAPOL |
| 4 | L2 Link | PPPoE: discovery, LCP, CHAP login, IPCP, IP over PPP | PPPoE, PPP |
| 5 | L3 Network | DHCP: getting an address (Discover, Offer, Request, Ack) | DHCP, UDP |
| 6 | L3 Network | IP & ICMP: ping, NAT and traceroute | IPv4, ICMP |
| 7 | L3 Network | IPv6: SLAAC, neighbor discovery, ping without NAT | IPv6, ICMPv6 |
| 8 | L3 Network | BGP: two networks peer and exchange routes | BGP, TCP |
| 9 | L3 Network | WireGuard: 1-RTT handshake, encrypted tunnel, keepalive | WireGuard, UDP |
| 10 | L3 Network | IPsec: IKEv2 with NAT detection, ESP over UDP 4500 | IKEv2, ESP |
| 11 | L4 Transport | TCP: handshake and teardown | TCP |
| 12 | L4 Transport | UDP & DNS: turning a name into an address | UDP, DNS |
| 13 | L4 Transport | QUIC & HTTP/3: a 1-RTT handshake over UDP | QUIC, TLS 1.3 |
| 14 | L5–7 Application | NTP: four timestamps, one clock offset | NTP, UDP |
| 15 | L5–7 Application | NTS (NTP over TLS): TLS 1.3 key establishment, cookies, authenticated NTP | NTS, NTP, TLS 1.3 |
| 16 | L5–7 Application | DNSSEC: RRSIG, DNSKEY, DS and the chain of trust | DNSSEC, EDNS0 |
| 17 | L5–7 Application | HTTP: asking for a page | HTTP/1.1 |
| 18 | L5–7 Application | HTTPS & TLS 1.3: making it private | TLS 1.3 |
| 19 | L5–7 Application | WebSocket: upgrade, masked frames, close | WebSocket |
| 20 | L5–7 Application | SIP & RTP: a VoIP call with SDP offer/answer, voice packets, hang-up | SIP, SDP, RTP |
| 21 | L5–7 Application | RTSP: DESCRIBE, SETUP, PLAY an IP camera; H.264 over RTP | RTSP, RTP |
| 22 | L5–7 Application | SSH: version exchange, KEXINIT, Curve25519 key exchange | SSH |
| 23 | L5–7 Application | SSH tunneling: local port forwarding to a private database | SSH, PostgreSQL |
| 24 | L5–7 Application | FTP: control and data connections, plain-text passwords | FTP |
| 25 | L5–7 Application | SMB: negotiate, tree connect, open and read a file | SMB 3.1.1 |
| 26 | L5–7 Application | RADIUS: Access-Request/Reject/Accept and accounting (AAA) | RADIUS |
| 27 | L5–7 Application | SMTP: one server delivers mail to another, pipelined | SMTP |
| 28 | L5–7 Application | IMAP: tags, literals, IDLE push | IMAP |
| 29 | L5–7 Application | POP3: download and delete | POP3 |
| 30 | L5–7 Application | Modbus/TCP: read registers, write a setpoint, switch a pump, exceptions | Modbus |
| 31 | L5–7 Application | Loading a web page: everything together | DNS, TCP, TLS, HTTP |

There is also an **OSI & TCP/IP models** page (`#/models`). It compares the 7-layer OSI
model with the 5- and 4-layer TCP/IP models, and explains every layer, including Session
and Presentation, with links to the lessons where you can see it. It ends with one real
packet broken down by layer. In the packet inspector, every protocol layer is tagged with
its OSI layer number.

## What you see

- **An animated stage.** The packet is drawn as a row of layer chips (for example
  `ETH | IPv4 | TCP | TLS`). The sender wraps the data layer by layer, the router
  rebuilds the link-layer frame, and the receiver unwraps it.
- **A Wireshark-style inspector.** A packet list shows every step of the lesson
  (source, destination, protocol, length, info). Below it are a decoded layer tree and a
  hex dump that highlight each other as you click.
- **A dark theme by default**, with a light theme one click away.

## The packets are real

The packets aren't hand-drawn mock-ups. They're built by small encoders in
[`src/protocols`](src/protocols), with correct lengths, Internet checksums (including
the TCP/UDP pseudo-header), TCP sequence/acknowledgment numbers, DNS name compression
and TLS record framing. The test suite checks that every byte of every packet is
described exactly once and that every checksum verifies. Exported to a pcap file, they
decode cleanly in `tcpdump` and Wireshark.

Several values are really computed rather than made up: RADIUS authenticators, hidden
passwords and Message-Authenticators (MD5 and HMAC-MD5 with the shared secret), the PPP
CHAP response (MD5), IKEv2 NAT-detection hashes (SHA-1), DNSSEC
key tags and DS digests (SHA-256), and the Ethernet FCS (CRC-32). `src/crypto.ts` is
tested against the published test vectors.

Some simplifications are deliberate:

- Encrypted TLS records, QUIC payloads and SSH packets contain deterministic
  pseudo-random bytes of the correct length. They are not real ciphertext, and
  QUIC header-protection bits are randomised the same way.
- SMTP, IMAP and POP3 are shown without STARTTLS/TLS so they can be read; real
  deployments encrypt them (the lessons say so).
- Some messages are sent but not shown (e.g. SMB session setup, FTP's 150 reply);
  they still advance TCP sequence numbers so the shown packets stay consistent.
- DNSSEC public keys and signatures are illustrative bytes. The DS digest and key tags
  computed from them are real.
- Wi-Fi frames are shown without radiotap headers or FCS; encrypted handshake
  key data and SMB signatures are illustrative bytes.
- The WebSocket handshake uses the sample key and accept values from RFC 6455.
- The server's certificate flight is trimmed to fit in one TCP segment.
- The Ethernet frame check sequence (FCS) isn't shown, because network cards add and
  strip it in hardware and packet captures don't include it either.
- All addresses come from documentation ranges (RFC 5737, and 2001:db8::/32 for IPv6),
  private ranges (RFC 1918) and documentation AS numbers (RFC 5398).

## Running locally

```sh
npm install
npm run dev     # start a dev server
npm test        # check every packet byte by byte
npm run build   # build a static site into dist/
```

There are no runtime dependencies. It's plain TypeScript and SVG, built with Vite. Fonts
(Inter, Space Grotesk, JetBrains Mono) load from Google Fonts. If they're blocked, system
fonts are used instead.

## Project layout

```
src/
  bytes.ts          packet model: Header builder, layering, checksums
  protocols/        encoders: link.ts (Ethernet, ARP), inet.ts (IPv4, ICMP, UDP, TCP),
                    app.ts (DNS, HTTP, TLS 1.3), dhcp.ts, quic.ts,
                    text.ts (WebSocket, SSH, FTP), ipv6.ts
                    (IPv6, ICMPv6, Neighbor Discovery), infra.ts (BGP, NTP),
                    mail.ts (SMTP, IMAP, POP3, WireGuard),
                    smb.ts, wifi.ts (802.11, EAPOL)
  lessons/          the imaginary network and the lesson scripts
  diagram.ts        animated network diagram and layer chips
  groups.ts         lesson grouping and order (by layer)
  models.ts         OSI / TCP/IP reference data and the models page
  crypto.ts         MD5, HMAC-MD5, SHA-1, SHA-256, CRC-32
  i18n.ts           UI strings and locale handling
  main.ts           the app: home page, lesson view, packet list and inspector
test/               byte-level consistency tests
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a
protocol, a lesson or a translation.

## License

[MIT](LICENSE)
