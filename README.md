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
| 1 | Link | Ethernet & ARP: finding the router | Ethernet II, ARP |
| 2 | Link | Wi-Fi & WPA2: beacon, association, 4-way handshake, CCMP | 802.11, EAPOL |
| 3 | Network | DHCP: getting an address (Discover, Offer, Request, Ack) | DHCP, UDP |
| 4 | Network | IP & ICMP: ping, NAT and traceroute | IPv4, ICMP |
| 5 | Network | IPv6: SLAAC, neighbor discovery, ping without NAT | IPv6, ICMPv6 |
| 6 | Network | BGP: two networks peer and exchange routes | BGP, TCP |
| 7 | Network | WireGuard: 1-RTT handshake, encrypted tunnel, keepalive | WireGuard, UDP |
| 8 | Transport | TCP: handshake and teardown | TCP |
| 9 | Transport | UDP & DNS: turning a name into an address | UDP, DNS |
| 10 | Transport | QUIC & HTTP/3: a 1-RTT handshake over UDP | QUIC, TLS 1.3 |
| 11 | Application | NTP: four timestamps, one clock offset | NTP, UDP |
| 12 | Application | HTTP: asking for a page | HTTP/1.1 |
| 13 | Application | HTTPS & TLS 1.3: making it private | TLS 1.3 |
| 14 | Application | WebSocket: upgrade, masked frames, close | WebSocket |
| 15 | Application | SSH: version exchange, KEXINIT, Curve25519 key exchange | SSH |
| 16 | Application | FTP: control and data connections, plain-text passwords | FTP |
| 17 | Application | SMB: negotiate, tree connect, open and read a file | SMB 3.1.1 |
| 18 | Application | SMTP: one server delivers mail to another, pipelined | SMTP |
| 19 | Application | IMAP: tags, literals, IDLE push | IMAP |
| 20 | Application | POP3: download and delete | POP3 |
| 21 | Application | Loading a web page: everything together | DNS, TCP, TLS, HTTP |

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

Some simplifications are deliberate:

- Encrypted TLS records, QUIC payloads and SSH packets contain deterministic
  pseudo-random bytes of the correct length. They are not real ciphertext, and
  QUIC header-protection bits are randomised the same way.
- SMTP, IMAP and POP3 are shown without STARTTLS/TLS so they can be read; real
  deployments encrypt them (the lessons say so).
- Some messages are sent but not shown (e.g. SMB session setup, FTP's 150 reply);
  they still advance TCP sequence numbers so the shown packets stay consistent.
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
  i18n.ts           UI strings and locale handling
  main.ts           the app: home page, lesson view, packet list and inspector
test/               byte-level consistency tests
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a
protocol, a lesson or a translation.

## License

[MIT](LICENSE)
