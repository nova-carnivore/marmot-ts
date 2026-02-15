import { describe, it, expect } from 'vitest';
import {
  deriveFileKey,
  encryptMedia,
  decryptMedia,
  buildImetaTag,
  parseImetaTag,
  isCanonicalMimeType,
  COMMON_MIME_TYPES,
  isSupportedVersion,
  isDeprecatedVersion,
} from '../src/mip04.js';
import { MEDIA_VERSION, MEDIA_VERSION_DEPRECATED } from '../src/types.js';
import { bytesToHex } from '../src/utils.js';

describe('MIP-04: Encrypted Media', () => {
  const testExporterSecret = new Uint8Array(32).fill(0x42);

  describe('deriveFileKey', () => {
    it('should derive 32-byte key', () => {
      const fileHash = new Uint8Array(32).fill(0xaa);
      const key = deriveFileKey(testExporterSecret, fileHash, 'image/jpeg', 'test.jpg');
      expect(key.length).toBe(32);
    });

    it('should be deterministic', () => {
      const fileHash = new Uint8Array(32).fill(0xaa);
      const a = deriveFileKey(testExporterSecret, fileHash, 'image/jpeg', 'test.jpg');
      const b = deriveFileKey(testExporterSecret, fileHash, 'image/jpeg', 'test.jpg');
      expect(bytesToHex(a)).toBe(bytesToHex(b));
    });

    it('should differ for different filenames', () => {
      const fileHash = new Uint8Array(32).fill(0xaa);
      const a = deriveFileKey(testExporterSecret, fileHash, 'image/jpeg', 'a.jpg');
      const b = deriveFileKey(testExporterSecret, fileHash, 'image/jpeg', 'b.jpg');
      expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });

    it('should differ for different MIME types', () => {
      const fileHash = new Uint8Array(32).fill(0xaa);
      const a = deriveFileKey(testExporterSecret, fileHash, 'image/jpeg', 'test.img');
      const b = deriveFileKey(testExporterSecret, fileHash, 'image/png', 'test.img');
      expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });

    it('should canonicalize MIME types', () => {
      const fileHash = new Uint8Array(32).fill(0xaa);
      const a = deriveFileKey(testExporterSecret, fileHash, 'IMAGE/JPEG', 'test.jpg');
      const b = deriveFileKey(testExporterSecret, fileHash, 'image/jpeg', 'test.jpg');
      expect(bytesToHex(a)).toBe(bytesToHex(b));
    });
  });

  describe('encryptMedia / decryptMedia', () => {
    it('should encrypt and decrypt media', () => {
      const data = new TextEncoder().encode('This is a test image file content');

      const result = encryptMedia({
        data,
        mimeType: 'image/jpeg',
        filename: 'photo.jpg',
        exporterSecret: testExporterSecret,
      });

      expect(result.encryptedData.length).toBeGreaterThan(data.length);
      expect(result.meta.mimeType).toBe('image/jpeg');
      expect(result.meta.filename).toBe('photo.jpg');
      expect(result.meta.version).toBe(MEDIA_VERSION);
      expect(result.meta.nonce.length).toBe(24); // 12 bytes hex
      expect(result.meta.fileHash.length).toBe(64); // 32 bytes hex
      expect(result.encryptedHash.length).toBe(64);

      const decrypted = decryptMedia({
        encryptedData: result.encryptedData,
        meta: result.meta,
        exporterSecret: testExporterSecret,
      });

      expect(new TextDecoder().decode(decrypted)).toBe(
        'This is a test image file content'
      );
    });

    it('should fail with wrong exporter secret', () => {
      const data = new TextEncoder().encode('secret data');
      const result = encryptMedia({
        data,
        mimeType: 'text/plain',
        filename: 'test.txt',
        exporterSecret: testExporterSecret,
      });

      const wrongSecret = new Uint8Array(32).fill(0xff);
      expect(() =>
        decryptMedia({
          encryptedData: result.encryptedData,
          meta: result.meta,
          exporterSecret: wrongSecret,
        })
      ).toThrow();
    });

    it('should fail with tampered data', () => {
      const data = new TextEncoder().encode('original content');
      const result = encryptMedia({
        data,
        mimeType: 'text/plain',
        filename: 'test.txt',
        exporterSecret: testExporterSecret,
      });

      result.encryptedData[0] ^= 0xff;
      expect(() =>
        decryptMedia({
          encryptedData: result.encryptedData,
          meta: result.meta,
          exporterSecret: testExporterSecret,
        })
      ).toThrow();
    });

    it('should reject deprecated version', () => {
      const data = new TextEncoder().encode('test');
      const result = encryptMedia({
        data,
        mimeType: 'text/plain',
        filename: 'test.txt',
        exporterSecret: testExporterSecret,
      });

      result.meta.version = MEDIA_VERSION_DEPRECATED;
      expect(() =>
        decryptMedia({
          encryptedData: result.encryptedData,
          meta: result.meta,
          exporterSecret: testExporterSecret,
        })
      ).toThrow('Deprecated version');
    });

    it('should reject wrong-length exporter secret', () => {
      expect(() =>
        encryptMedia({
          data: new Uint8Array(10),
          mimeType: 'text/plain',
          filename: 'test.txt',
          exporterSecret: new Uint8Array(16),
        })
      ).toThrow('exporter_secret must be 32 bytes');
    });

    it('should handle empty file', () => {
      const result = encryptMedia({
        data: new Uint8Array(0),
        mimeType: 'text/plain',
        filename: 'empty.txt',
        exporterSecret: testExporterSecret,
      });

      const decrypted = decryptMedia({
        encryptedData: result.encryptedData,
        meta: result.meta,
        exporterSecret: testExporterSecret,
      });

      expect(decrypted.length).toBe(0);
    });

    it('should canonicalize MIME types during encryption', () => {
      const data = new TextEncoder().encode('test');
      const result = encryptMedia({
        data,
        mimeType: 'IMAGE/JPEG; charset=utf-8',
        filename: 'test.jpg',
        exporterSecret: testExporterSecret,
      });

      expect(result.meta.mimeType).toBe('image/jpeg');
    });

    it('should use random nonces (different each time)', () => {
      const data = new TextEncoder().encode('same content');
      const a = encryptMedia({
        data,
        mimeType: 'text/plain',
        filename: 'test.txt',
        exporterSecret: testExporterSecret,
      });
      const b = encryptMedia({
        data,
        mimeType: 'text/plain',
        filename: 'test.txt',
        exporterSecret: testExporterSecret,
      });

      // Nonces should be different (random)
      expect(a.meta.nonce).not.toBe(b.meta.nonce);
    });
  });

  describe('buildImetaTag', () => {
    it('should build correct imeta tag', () => {
      const tag = buildImetaTag({
        url: 'https://blossom.example.com/abc123',
        mimeType: 'image/jpeg',
        filename: 'photo.jpg',
        fileHash: 'a'.repeat(64),
        nonce: 'b'.repeat(24),
        version: MEDIA_VERSION,
      });

      expect(tag[0]).toBe('imeta');
      expect(tag).toContain('url https://blossom.example.com/abc123');
      expect(tag).toContain('m image/jpeg');
      expect(tag).toContain('filename photo.jpg');
      expect(tag).toContain(`x ${'a'.repeat(64)}`);
      expect(tag).toContain(`n ${'b'.repeat(24)}`);
      expect(tag).toContain(`v ${MEDIA_VERSION}`);
    });

    it('should include optional dimensions', () => {
      const tag = buildImetaTag({
        url: 'https://blossom.example.com/abc',
        mimeType: 'image/png',
        filename: 'img.png',
        fileHash: 'a'.repeat(64),
        nonce: 'b'.repeat(24),
        version: MEDIA_VERSION,
        dimensions: '1920x1080',
      });

      expect(tag).toContain('dim 1920x1080');
    });

    it('should include optional blurhash', () => {
      const tag = buildImetaTag({
        url: 'https://blossom.example.com/abc',
        mimeType: 'image/png',
        filename: 'img.png',
        fileHash: 'a'.repeat(64),
        nonce: 'b'.repeat(24),
        version: MEDIA_VERSION,
        blurhash: 'L6PZfSi_.AyE_3t7t7R**0o#DgR4',
      });

      expect(tag).toContain('blurhash L6PZfSi_.AyE_3t7t7R**0o#DgR4');
    });
  });

  describe('parseImetaTag', () => {
    it('should parse valid imeta tag', () => {
      const tag = [
        'imeta',
        'url https://blossom.example.com/abc123',
        'm image/jpeg',
        'filename photo.jpg',
        `x ${'a'.repeat(64)}`,
        `n ${'b'.repeat(24)}`,
        `v ${MEDIA_VERSION}`,
        'dim 1920x1080',
      ];

      const meta = parseImetaTag(tag);
      expect(meta.url).toBe('https://blossom.example.com/abc123');
      expect(meta.mimeType).toBe('image/jpeg');
      expect(meta.filename).toBe('photo.jpg');
      expect(meta.fileHash).toBe('a'.repeat(64));
      expect(meta.nonce).toBe('b'.repeat(24));
      expect(meta.version).toBe(MEDIA_VERSION);
      expect(meta.dimensions).toBe('1920x1080');
    });

    it('should reject non-imeta tag', () => {
      expect(() => parseImetaTag(['e', 'some-event'])).toThrow('Not an imeta tag');
    });

    it('should reject missing required fields', () => {
      expect(() => parseImetaTag(['imeta', 'url https://example.com'])).toThrow(
        'Missing'
      );
    });

    it('should reject deprecated version', () => {
      const tag = [
        'imeta',
        'url https://example.com/abc',
        'm image/jpeg',
        'filename test.jpg',
        `x ${'a'.repeat(64)}`,
        `v ${MEDIA_VERSION_DEPRECATED}`,
      ];

      expect(() => parseImetaTag(tag)).toThrow('Deprecated version');
    });

    it('should reject v2 without nonce', () => {
      const tag = [
        'imeta',
        'url https://example.com/abc',
        'm image/jpeg',
        'filename test.jpg',
        `x ${'a'.repeat(64)}`,
        `v ${MEDIA_VERSION}`,
      ];

      expect(() => parseImetaTag(tag)).toThrow('requires n (nonce)');
    });
  });

  describe('isCanonicalMimeType', () => {
    it('should accept canonical types', () => {
      expect(isCanonicalMimeType('image/jpeg')).toBe(true);
      expect(isCanonicalMimeType('text/plain')).toBe(true);
    });

    it('should reject non-canonical types', () => {
      expect(isCanonicalMimeType('IMAGE/JPEG')).toBe(false);
      expect(isCanonicalMimeType(' image/jpeg')).toBe(false);
    });
  });

  describe('COMMON_MIME_TYPES', () => {
    it('should have standard types', () => {
      expect(COMMON_MIME_TYPES.JPEG).toBe('image/jpeg');
      expect(COMMON_MIME_TYPES.PNG).toBe('image/png');
      expect(COMMON_MIME_TYPES.MP4).toBe('video/mp4');
      expect(COMMON_MIME_TYPES.PDF).toBe('application/pdf');
    });
  });

  describe('version utilities', () => {
    it('should identify supported version', () => {
      expect(isSupportedVersion(MEDIA_VERSION)).toBe(true);
      expect(isSupportedVersion('mip04-v99')).toBe(false);
    });

    it('should identify deprecated version', () => {
      expect(isDeprecatedVersion(MEDIA_VERSION_DEPRECATED)).toBe(true);
      expect(isDeprecatedVersion(MEDIA_VERSION)).toBe(false);
    });
  });
});
