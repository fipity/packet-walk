// How lessons are grouped on the home page and in the sidebar, roughly by network layer.
export interface Group {
  id: string;
  name: string;
  /** The OSI layer(s) this group corresponds to. */
  osi: string;
  blurb: string;
  ids: string[];
}

export const GROUPS: Group[] = [
  {
    id: 'physical',
    name: 'Physical layer',
    osi: 'L1',
    blurb: 'Bits as voltages, light or radio: preambles, line codes and error-detecting checksums.',
    ids: ['physical'],
  },
  {
    id: 'link',
    name: 'Link layer',
    osi: 'L2',
    blurb: 'Getting frames to the next device over a cable or radio, using MAC addresses.',
    ids: ['ethernet-arp', 'wifi', 'pppoe'],
  },
  {
    id: 'network',
    name: 'Network layer',
    osi: 'L3',
    blurb: 'Addresses, routes and tunnels that carry packets across the internet.',
    ids: ['dhcp', 'ip-icmp', 'ipv6', 'bgp', 'wireguard', 'ipsec'],
  },
  {
    id: 'transport',
    name: 'Transport layer',
    osi: 'L4',
    blurb: 'Connections between programs, made reliable, ordered and fast.',
    ids: ['tcp', 'udp-dns', 'quic'],
  },
  {
    id: 'app',
    name: 'Application layer',
    osi: 'L5–7',
    blurb: 'The protocols you actually use: names, time, the web, remote access, files and mail.',
    ids: ['ntp', 'nts', 'dnssec', 'http', 'tls', 'websocket', 'sip', 'rtsp', 'ssh', 'ssh-tunnel', 'ftp', 'smb', 'radius', 'smtp', 'imap', 'pop3', 'modbus', 'page-load'],
  },
];
