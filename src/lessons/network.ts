// The imaginary network every lesson uses. All addresses come from ranges reserved
// for documentation (RFC 5737) or private use (RFC 1918), so nothing points at a real host.
import type { Packet, Text } from '../bytes';
import { ethernet } from '../protocols/link';
import { ipv4, tcp, udp, type IpProto, type TcpFlag } from '../protocols/inet';

export type NodeId = 'laptop' | 'router' | 'internet' | 'dns' | 'server';

export const NET = {
  laptop: { mac: '02:1a:2b:3c:4d:5e', ip: '192.168.1.23' },
  router: { mac: '02:00:5e:10:00:01', ip: '192.168.1.1', wan: '198.51.100.7' },
  dns: { ip: '203.0.113.53' },
  server: { ip: '203.0.113.80', name: 'www.example.com' },
} as const;

export interface Step {
  from: NodeId;
  to: NodeId;
  title: Text;
  text: Text;
  /** Where the packet was "captured", shown above the decoder. */
  capture: Text;
  packet: Packet;
}

export interface Lesson {
  id: string;
  title: Text;
  protocols: string[];
  intro: Text;
  steps: Step[];
}

export const ON_LAPTOP = 'Captured on the laptop\'s network link';

let ipId = 0x4a10;
let serverIpId = 0x6c02;

/** A packet leaving the laptop, as seen on the laptop's link: Ethernet to the router, IP to the far end. */
export function fromLaptop(dst: string, proto: IpProto, payload: Packet, ttl = 64): Packet {
  return ethernet(
    { dst: NET.router.mac, src: NET.laptop.mac, type: 'IPv4' },
    ipv4({ src: NET.laptop.ip, dst, proto, ttl, id: ipId++ }, payload),
  );
}

/** A packet arriving at the laptop. `ttl` is what's left after crossing the internet. */
export function toLaptop(src: string, proto: IpProto, payload: Packet, ttl = 56, df = true): Packet {
  return ethernet(
    { dst: NET.laptop.mac, src: NET.router.mac, type: 'IPv4' },
    ipv4({ src, dst: NET.laptop.ip, proto, ttl, id: serverIpId++, df }, payload),
  );
}

export function udpFromLaptop(dst: string, srcPort: number, dstPort: number, payload: Packet): Packet {
  return fromLaptop(dst, 'UDP', udp({ src: NET.laptop.ip, dst, srcPort, dstPort }, payload));
}

export function udpToLaptop(src: string, srcPort: number, dstPort: number, payload: Packet): Packet {
  return toLaptop(src, 'UDP', udp({ src, dst: NET.laptop.ip, srcPort, dstPort }, payload), 56, false);
}

/** Tracks sequence numbers for one TCP connection between the laptop and a server. */
export class TcpConn {
  private cNext: number;
  private sNext: number;

  constructor(
    readonly serverIp: string,
    readonly clientPort: number,
    readonly serverPort: number,
    readonly clientIsn: number,
    readonly serverIsn: number,
  ) {
    this.cNext = clientIsn;
    this.sNext = serverIsn;
  }

  private advance(flags: TcpFlag[], payload?: Packet): number {
    return (payload?.bytes.length ?? 0) + (flags.includes('SYN') ? 1 : 0) + (flags.includes('FIN') ? 1 : 0);
  }

  /** Segment from laptop to server. */
  client(flags: TcpFlag[], payload?: Packet): Packet {
    const seg = tcp(
      {
        src: NET.laptop.ip, dst: this.serverIp, srcPort: this.clientPort, dstPort: this.serverPort,
        seq: this.cNext, ack: flags.includes('ACK') ? this.sNext : 0, flags,
        window: flags.includes('SYN') ? 64240 : 502, seqBase: this.clientIsn, ackBase: this.serverIsn,
      },
      payload,
    );
    this.cNext = (this.cNext + this.advance(flags, payload)) >>> 0;
    return fromLaptop(this.serverIp, 'TCP', seg);
  }

  /** Segment from server to laptop. */
  server(flags: TcpFlag[], payload?: Packet): Packet {
    const seg = tcp(
      {
        src: this.serverIp, dst: NET.laptop.ip, srcPort: this.serverPort, dstPort: this.clientPort,
        seq: this.sNext, ack: flags.includes('ACK') ? this.cNext : 0, flags,
        window: flags.includes('SYN') ? 65160 : 509, seqBase: this.serverIsn, ackBase: this.clientIsn,
      },
      payload,
    );
    this.sNext = (this.sNext + this.advance(flags, payload)) >>> 0;
    return toLaptop(this.serverIp, 'TCP', seg);
  }
}
