// Spot packets that show something going wrong, so the stage can sound a distinct tone when
// they arrive. Everything is read from the packet itself, not from lesson text.
import type { Packet } from './bytes';
import { crc32 } from './crypto';

/** True if the packet carries a detectable error: a bad Ethernet FCS, a RADIUS Access-Reject or a Modbus exception. */
export function isFailure(p: Packet): boolean {
  return p.layers.some((l, li) => {
    const fields = p.fields.filter((f) => f.layer === li);
    switch (l.kind) {
      case 'phy': {
        // The FCS is the CRC-32 of the frame (the next layer down), sent least-significant byte first.
        const fcs = fields.find((f) => f.name === 'Frame check sequence');
        const frame = p.layers.find((x) => x.depth === l.depth + 1 && x.offset >= l.offset);
        if (!fcs || !frame || fcs.length !== 4) return false;
        const b = p.bytes;
        const sent = (b[fcs.offset] | (b[fcs.offset + 1] << 8) | (b[fcs.offset + 2] << 16) | (b[fcs.offset + 3] << 24)) >>> 0;
        return crc32(b.subarray(frame.offset, fcs.offset)) !== sent;
      }
      case 'radius':
        return p.bytes[l.offset] === 3; // Code 3: Access-Reject
      case 'modbus': {
        const fn = fields.find((f) => f.name === 'Function code');
        return !!fn && (p.bytes[fn.offset] & 0x80) !== 0; // top bit set: exception response
      }
      default:
        return false;
    }
  });
}
