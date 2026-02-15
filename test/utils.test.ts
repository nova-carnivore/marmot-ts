import { describe, it, expect } from 'vitest';
import {
  bytesToBase64,
  base64ToBytes,
  bytesToHex,
  hexToBytes,
  encodeContent,
  decodeContent,
  detectEncoding,
  isValidPubkey,
  isValidRelayUrl,
  isValidHex,
  isNonDefaultExtension,
  formatExtensionId,
  parseExtensionId,
  getTagValue,
  getTagValues,
  bytesEqual,
  concatBytes,
  randomBytes,
  canonicalizeMimeType,
} from '../src/utils.js';

describe('utils', () => {
  describe('bytesToBase64 / base64ToBytes', () => {
    it('should roundtrip bytes through base64', () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
      const b64 = bytesToBase64(original);
      const decoded = base64ToBytes(b64);
      expect(decoded).toEqual(original);
    });

    it('should encode empty bytes', () => {
      const b64 = bytesToBase64(new Uint8Array(0));
      expect(b64).toBe('');
      const decoded = base64ToBytes(b64);
      expect(decoded.length).toBe(0);
    });

    it('should encode known value', () => {
      const hello = new TextEncoder().encode('Hello');
      const b64 = bytesToBase64(hello);
      expect(b64).toBe('SGVsbG8=');
    });
  });

  describe('bytesToHex / hexToBytes', () => {
    it('should roundtrip bytes through hex', () => {
      const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const hex = bytesToHex(original);
      expect(hex).toBe('deadbeef');
      const decoded = hexToBytes(hex);
      expect(decoded).toEqual(original);
    });
  });

  describe('encodeContent / decodeContent', () => {
    it('should encode/decode as base64', () => {
      const data = new Uint8Array([10, 20, 30]);
      const encoded = encodeContent(data, 'base64');
      const decoded = decodeContent(encoded, 'base64');
      expect(decoded).toEqual(data);
    });

    it('should encode/decode as hex', () => {
      const data = new Uint8Array([0xff, 0x00, 0xab]);
      const encoded = encodeContent(data, 'hex');
      expect(encoded).toBe('ff00ab');
      const decoded = decodeContent(encoded, 'hex');
      expect(decoded).toEqual(data);
    });
  });

  describe('detectEncoding', () => {
    it('should detect base64 encoding', () => {
      expect(detectEncoding([['encoding', 'base64']])).toBe('base64');
    });

    it('should detect hex encoding', () => {
      expect(detectEncoding([['encoding', 'hex']])).toBe('hex');
    });

    it('should default to hex when no tag', () => {
      expect(detectEncoding([])).toBe('hex');
    });
  });

  describe('isValidPubkey', () => {
    it('should accept valid 64-char hex pubkey', () => {
      const pk = 'a'.repeat(64);
      expect(isValidPubkey(pk)).toBe(true);
    });

    it('should reject short pubkey', () => {
      expect(isValidPubkey('abcd')).toBe(false);
    });

    it('should reject uppercase', () => {
      expect(isValidPubkey('A'.repeat(64))).toBe(false);
    });

    it('should reject non-hex chars', () => {
      expect(isValidPubkey('g'.repeat(64))).toBe(false);
    });
  });

  describe('isValidRelayUrl', () => {
    it('should accept wss:// URLs', () => {
      expect(isValidRelayUrl('wss://relay.example.com')).toBe(true);
    });

    it('should accept ws:// URLs', () => {
      expect(isValidRelayUrl('ws://localhost:8080')).toBe(true);
    });

    it('should reject https:// URLs', () => {
      expect(isValidRelayUrl('https://example.com')).toBe(false);
    });

    it('should reject invalid URLs', () => {
      expect(isValidRelayUrl('not-a-url')).toBe(false);
    });
  });

  describe('isValidHex', () => {
    it('should validate hex strings', () => {
      expect(isValidHex('abcdef0123456789')).toBe(true);
    });

    it('should validate with byte length', () => {
      expect(isValidHex('aabb', 2)).toBe(true);
      expect(isValidHex('aabb', 3)).toBe(false);
    });

    it('should reject non-hex', () => {
      expect(isValidHex('xyz')).toBe(false);
    });
  });

  describe('isNonDefaultExtension', () => {
    it('should reject default extensions', () => {
      expect(isNonDefaultExtension(0x0001)).toBe(false);
      expect(isNonDefaultExtension(0x0002)).toBe(false);
      expect(isNonDefaultExtension(0x0003)).toBe(false);
      expect(isNonDefaultExtension(0x0004)).toBe(false);
      expect(isNonDefaultExtension(0x0005)).toBe(false);
    });

    it('should accept marmot_group_data extension', () => {
      expect(isNonDefaultExtension(0xf2ee)).toBe(true);
    });

    it('should accept last_resort extension', () => {
      expect(isNonDefaultExtension(0x000a)).toBe(true);
    });
  });

  describe('formatExtensionId / parseExtensionId', () => {
    it('should format extension IDs', () => {
      expect(formatExtensionId(0xf2ee)).toBe('0xf2ee');
      expect(formatExtensionId(0x000a)).toBe('0x000a');
    });

    it('should parse extension IDs', () => {
      expect(parseExtensionId('0xf2ee')).toBe(0xf2ee);
      expect(parseExtensionId('0xF2EE')).toBe(0xf2ee);
      expect(parseExtensionId('0x000a')).toBe(0x000a);
    });

    it('should roundtrip', () => {
      expect(parseExtensionId(formatExtensionId(0xf2ee))).toBe(0xf2ee);
    });
  });

  describe('getTagValue / getTagValues', () => {
    const tags = [
      ['e', 'event123'],
      ['relays', 'wss://r1.com', 'wss://r2.com'],
      ['encoding', 'base64'],
    ];

    it('should get single tag value', () => {
      expect(getTagValue(tags, 'e')).toBe('event123');
      expect(getTagValue(tags, 'encoding')).toBe('base64');
      expect(getTagValue(tags, 'missing')).toBeUndefined();
    });

    it('should get all tag values', () => {
      expect(getTagValues(tags, 'relays')).toEqual(['wss://r1.com', 'wss://r2.com']);
      expect(getTagValues(tags, 'missing')).toEqual([]);
    });
  });

  describe('bytesEqual', () => {
    it('should detect equal arrays', () => {
      expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    });

    it('should detect unequal arrays', () => {
      expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(
        false
      );
    });

    it('should detect different lengths', () => {
      expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    });
  });

  describe('concatBytes', () => {
    it('should concatenate arrays', () => {
      const result = concatBytes(
        new Uint8Array([1, 2]),
        new Uint8Array([3, 4]),
        new Uint8Array([5])
      );
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    });

    it('should handle empty arrays', () => {
      const result = concatBytes(new Uint8Array(0), new Uint8Array([1]));
      expect(result).toEqual(new Uint8Array([1]));
    });
  });

  describe('randomBytes', () => {
    it('should generate bytes of correct length', () => {
      const bytes = randomBytes(32);
      expect(bytes.length).toBe(32);
    });

    it('should generate different values', () => {
      const a = randomBytes(32);
      const b = randomBytes(32);
      expect(bytesEqual(a, b)).toBe(false);
    });
  });

  describe('canonicalizeMimeType', () => {
    it('should lowercase', () => {
      expect(canonicalizeMimeType('IMAGE/JPEG')).toBe('image/jpeg');
    });

    it('should strip parameters', () => {
      expect(canonicalizeMimeType('image/jpeg; charset=utf-8')).toBe('image/jpeg');
    });

    it('should trim whitespace', () => {
      expect(canonicalizeMimeType('  image/png  ')).toBe('image/png');
    });
  });
});
