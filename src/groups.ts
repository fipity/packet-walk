// How lessons are grouped on the home page and in the sidebar, roughly by network layer.
export interface Group {
  id: string;
  name: string;
  blurb: string;
  ids: string[];
}

export const GROUPS: Group[] = [
  {
    id: 'link',
    name: 'Link layer',
    blurb: 'Getting frames to the next device over a cable or radio, using MAC addresses.',
    ids: ['ethernet-arp', 'wifi'],
  },
  {
    id: 'network',
    name: 'Network layer',
    blurb: 'Addresses, routes and tunnels that carry packets across the internet.',
    ids: ['dhcp', 'ip-icmp', 'ipv6', 'bgp', 'wireguard'],
  },
  {
    id: 'transport',
    name: 'Transport layer',
    blurb: 'Connections between programs, made reliable, ordered and fast.',
    ids: ['tcp', 'udp-dns', 'quic'],
  },
  {
    id: 'app',
    name: 'Application layer',
    blurb: 'The protocols you actually use: names, time, the web, remote access, files and mail.',
    ids: ['ntp', 'http', 'tls', 'websocket', 'ssh', 'ftp', 'smb', 'smtp', 'imap', 'pop3', 'page-load'],
  },
];
