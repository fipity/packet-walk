import { describe, expect, it } from 'vitest';
import { md5, hmacMd5, sha256, crc32 } from '../src/crypto';

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

describe('hash functions (known test vectors)', () => {
  it('MD5 (RFC 1321)', () => {
    expect(hex(md5(enc('')))).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(hex(md5(enc('abc')))).toBe('900150983cd24fb0d6963f7d28e17f72');
    expect(hex(md5(enc('12345678901234567890123456789012345678901234567890123456789012345678901234567890')))).toBe('57edf4a22be3c955ac49da2e2107b67a');
  });
  it('HMAC-MD5 (RFC 2104)', () => {
    expect(hex(hmacMd5(enc('Jefe'), enc('what do ya want for nothing?')))).toBe('750c783e6ab0b503eaa86e310a5db738');
  });
  it('SHA-256 (FIPS 180-4)', () => {
    expect(hex(sha256(enc('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(hex(sha256(enc('')))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    expect(hex(sha256(enc('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')))).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });
  it('CRC-32 (IEEE 802.3)', () => {
    expect(crc32(enc('123456789'))).toBe(0xcbf43926);
  });
});
