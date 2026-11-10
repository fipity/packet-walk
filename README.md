# packet-walk

**See how the internet works, one packet at a time.**

packet-walk is a free, open-source, interactive explainer for the protocols that move
data across the internet. Each lesson steps through a real exchange on a small
imaginary network (laptop → home router → internet → server), and every packet is
encoded for real and decoded byte by byte: click any field to see its bytes, or click any byte
to see which field it belongs to and what it means.

**Live site:** https://fipity.github.io/packet-walk/

## Lessons

| # | Lesson | Protocols |
|---|--------|-----------|
| 1 | Ethernet & ARP: finding the router | Ethernet II, ARP |
| 2 | DHCP: getting an address (Discover, Offer, Request, Ack) | DHCP, UDP |
| 3 | IP & ICMP: ping, NAT and traceroute | IPv4, ICMP |
| 4 | IPv6: SLAAC, neighbor discovery, ping without NAT | IPv6, ICMPv6 |
| 5 | BGP: two networks peer and exchange routes | BGP, TCP |
| 6 | UDP & DNS: turning a name into an address | UDP, DNS |
| 7 | NTP: four timestamps, one clock offset | NTP, UDP |
| 8 | TCP: handshake and teardown | TCP |
| 9 | HTTP: asking for a page | HTTP/1.1 |
| 10 | HTTPS & TLS 1.3: making it private | TLS 1.3 |
| 11 | WebSocket: upgrade, masked frames, close | WebSocket |
| 12 | QUIC & HTTP/3: a 1-RTT handshake over UDP | QUIC, TLS 1.3 |
| 13 | SSH: version exchange, KEXINIT, Curve25519 key exchange | SSH |
| 14 | FTP: control and data connections, plain-text passwords | FTP |
| 15 | Loading a web page: everything together | DNS, TCP, TLS, HTTP |

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

There are no runtime dependencies. It's plain TypeScript and SVG, built with Vite.

## Project layout

```
src/
  bytes.ts          packet model: Header builder, layering, checksums
  protocols/        encoders: link.ts (Ethernet, ARP), inet.ts (IPv4, ICMP, UDP, TCP),
                    app.ts (DNS, HTTP, TLS 1.3), dhcp.ts, quic.ts,
                    text.ts (WebSocket, SSH, FTP), ipv6.ts
                    (IPv6, ICMPv6, Neighbor Discovery), infra.ts (BGP, NTP)
  lessons/          the imaginary network and the lesson scripts
  diagram.ts        animated network diagram
  i18n.ts           UI strings and locale handling
  main.ts           the app: lesson navigation and packet inspector
test/               byte-level consistency tests
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a
protocol, a lesson or a translation.

## License

[MIT](LICENSE)
