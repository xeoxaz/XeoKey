import * as crypto from 'crypto';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

function getHmacAlgo(algo: TotpAlgorithm): string {
  switch (algo) {
    case 'SHA256':
      return 'sha256';
    case 'SHA512':
      return 'sha512';
    case 'SHA1':
    default:
      return 'sha1';
  }
}

// Minimal Base32 decoder (RFC 4648, no padding or with '=' padding)
export function base32ToBuffer(base32: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = base32.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  let bits = '';
  for (let i = 0; i < cleaned.length; i++) {
    const val = alphabet.indexOf(cleaned[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

export function generateTotpCode(
  secretBase32: string,
  timestampMs: number = Date.now(),
  period: number = 30,
  digits: number = 6,
  algorithm: TotpAlgorithm = 'SHA1'
): string {
  const key = base32ToBuffer(secretBase32);
  const counter = Math.floor(timestampMs / 1000 / period);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter % 0x100000000, 4);

  const hmac = crypto.createHmac(getHmacAlgo(algorithm), key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const str = (code % 10 ** digits).toString().padStart(digits, '0');
  return str;
}

export function verifyTotpCode(
  secretBase32: string,
  code: string,
  window: number = 1,
  period: number = 30,
  digits: number = 6,
  algorithm: TotpAlgorithm = 'SHA1'
): boolean {
  const now = Date.now();
  for (let w = -window; w <= window; w++) {
    const ts = now + w * period * 1000;
    const expected = generateTotpCode(secretBase32, ts, period, digits, algorithm);
    if (expected === code) {
      return true;
    }
  }
  return false;
}


