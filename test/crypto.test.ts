import { describe, it, expect } from 'vitest';
import {
  sha256Hash,
  sha256Hex,
  hkdfExpand,
  generateKeypair,
  generateEphemeralKeypair,
  keypairFromSecret,
  keypairFromSecretHex,
  getPublicKey,
  getPublicKeyHex,
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
  deriveUploadKeypair,
  computeConversationKey,
  deriveGroupConversationKey,
} from '../src/crypto.js';
import { bytesToHex } from '../src/utils.js';

describe('crypto', () => {
  describe('sha256', () => {
    it('should hash empty bytes', () => {
      const hash = sha256Hex(new Uint8Array(0));
      expect(hash).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
      );
    });

    it('should hash known value', () => {
      const data = new TextEncoder().encode('hello');
      const hash = sha256Hex(data);
      expect(hash).toBe(
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
      );
    });

    it('should return 32-byte Uint8Array', () => {
      const hash = sha256Hash(new Uint8Array([1, 2, 3]));
      expect(hash.length).toBe(32);
      expect(hash).toBeInstanceOf(Uint8Array);
    });
  });

  describe('hkdfExpand', () => {
    it('should produce 32 bytes by default', () => {
      const prk = new Uint8Array(32).fill(42);
      const result = hkdfExpand(prk, 'test-info', 32);
      expect(result.length).toBe(32);
    });

    it('should produce different output for different info', () => {
      const prk = new Uint8Array(32).fill(42);
      const a = hkdfExpand(prk, 'info-a', 32);
      const b = hkdfExpand(prk, 'info-b', 32);
      expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });

    it('should produce consistent output', () => {
      const prk = new Uint8Array(32).fill(1);
      const a = hkdfExpand(prk, 'same', 32);
      const b = hkdfExpand(prk, 'same', 32);
      expect(bytesToHex(a)).toBe(bytesToHex(b));
    });

    it('should support custom lengths', () => {
      const prk = new Uint8Array(32).fill(42);
      const result = hkdfExpand(prk, 'test', 16);
      expect(result.length).toBe(16);
    });
  });

  describe('generateKeypair', () => {
    it('should generate valid keypair', () => {
      const kp = generateKeypair();
      expect(kp.privateKey.length).toBe(32);
      expect(kp.publicKey.length).toBe(32);
      expect(kp.publicKeyHex.length).toBe(64);
      expect(kp.privateKeyHex.length).toBe(64);
    });

    it('should generate unique keypairs', () => {
      const a = generateKeypair();
      const b = generateKeypair();
      expect(a.publicKeyHex).not.toBe(b.publicKeyHex);
    });
  });

  describe('generateEphemeralKeypair', () => {
    it('should generate a valid keypair', () => {
      const kp = generateEphemeralKeypair();
      expect(kp.privateKey.length).toBe(32);
      expect(kp.publicKey.length).toBe(32);
    });

    it('should generate unique keypairs every call', () => {
      const keypairs = Array.from({ length: 5 }, () => generateEphemeralKeypair());
      const hexes = keypairs.map((kp) => kp.publicKeyHex);
      const unique = new Set(hexes);
      expect(unique.size).toBe(5);
    });
  });

  describe('keypairFromSecret', () => {
    it('should derive consistent keypair from secret', () => {
      const secret = new Uint8Array(32).fill(0x42);
      const a = keypairFromSecret(secret);
      const b = keypairFromSecret(secret);
      expect(a.publicKeyHex).toBe(b.publicKeyHex);
    });

    it('should work with hex input', () => {
      const hex = '42'.repeat(32);
      const kp = keypairFromSecretHex(hex);
      expect(kp.publicKeyHex.length).toBe(64);
    });
  });

  describe('getPublicKey', () => {
    it('should derive x-only pubkey', () => {
      const kp = generateKeypair();
      const pubkey = getPublicKey(kp.privateKey);
      expect(pubkey.length).toBe(32);
      expect(bytesToHex(pubkey)).toBe(kp.publicKeyHex);
    });

    it('should work with hex', () => {
      const kp = generateKeypair();
      const pubkeyHex = getPublicKeyHex(kp.privateKeyHex);
      expect(pubkeyHex).toBe(kp.publicKeyHex);
    });
  });

  describe('ChaCha20-Poly1305', () => {
    it('should encrypt and decrypt', () => {
      const key = new Uint8Array(32).fill(1);
      const nonce = new Uint8Array(12).fill(2);
      const plaintext = new TextEncoder().encode('Hello, Marmot!');

      const encrypted = chacha20Poly1305Encrypt(key, nonce, plaintext);
      expect(encrypted.length).toBe(plaintext.length + 16); // +16 for tag

      const decrypted = chacha20Poly1305Decrypt(key, nonce, encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, Marmot!');
    });

    it('should encrypt and decrypt with AAD', () => {
      const key = new Uint8Array(32).fill(3);
      const nonce = new Uint8Array(12).fill(4);
      const plaintext = new TextEncoder().encode('Secret data');
      const aad = new TextEncoder().encode('authenticated metadata');

      const encrypted = chacha20Poly1305Encrypt(key, nonce, plaintext, aad);
      const decrypted = chacha20Poly1305Decrypt(key, nonce, encrypted, aad);
      expect(new TextDecoder().decode(decrypted)).toBe('Secret data');
    });

    it('should fail with wrong key', () => {
      const key1 = new Uint8Array(32).fill(1);
      const key2 = new Uint8Array(32).fill(2);
      const nonce = new Uint8Array(12).fill(3);
      const plaintext = new TextEncoder().encode('test');

      const encrypted = chacha20Poly1305Encrypt(key1, nonce, plaintext);
      expect(() => chacha20Poly1305Decrypt(key2, nonce, encrypted)).toThrow(
        'Authentication failed'
      );
    });

    it('should fail with wrong AAD', () => {
      const key = new Uint8Array(32).fill(1);
      const nonce = new Uint8Array(12).fill(2);
      const plaintext = new TextEncoder().encode('test');
      const aad1 = new TextEncoder().encode('correct aad');
      const aad2 = new TextEncoder().encode('wrong aad');

      const encrypted = chacha20Poly1305Encrypt(key, nonce, plaintext, aad1);
      expect(() => chacha20Poly1305Decrypt(key, nonce, encrypted, aad2)).toThrow(
        'Authentication failed'
      );
    });

    it('should fail with tampered ciphertext', () => {
      const key = new Uint8Array(32).fill(1);
      const nonce = new Uint8Array(12).fill(2);
      const plaintext = new TextEncoder().encode('test');

      const encrypted = chacha20Poly1305Encrypt(key, nonce, plaintext);
      encrypted[0] ^= 0xff; // Tamper
      expect(() => chacha20Poly1305Decrypt(key, nonce, encrypted)).toThrow(
        'Authentication failed'
      );
    });

    it('should reject too-short ciphertext', () => {
      const key = new Uint8Array(32).fill(1);
      const nonce = new Uint8Array(12).fill(2);

      expect(() => chacha20Poly1305Decrypt(key, nonce, new Uint8Array(10))).toThrow(
        'Ciphertext too short'
      );
    });

    it('should handle empty plaintext', () => {
      const key = new Uint8Array(32).fill(1);
      const nonce = new Uint8Array(12).fill(2);
      const plaintext = new Uint8Array(0);

      const encrypted = chacha20Poly1305Encrypt(key, nonce, plaintext);
      expect(encrypted.length).toBe(16); // Just the tag

      const decrypted = chacha20Poly1305Decrypt(key, nonce, encrypted);
      expect(decrypted.length).toBe(0);
    });
  });

  describe('deriveUploadKeypair', () => {
    it('should derive consistent keypair from image key', () => {
      const imageKey = new Uint8Array(32).fill(0xaa);
      const a = deriveUploadKeypair(imageKey);
      const b = deriveUploadKeypair(imageKey);
      expect(a.publicKeyHex).toBe(b.publicKeyHex);
    });

    it('should derive different keypair for different image key', () => {
      const key1 = new Uint8Array(32).fill(0xaa);
      const key2 = new Uint8Array(32).fill(0xbb);
      const a = deriveUploadKeypair(key1);
      const b = deriveUploadKeypair(key2);
      expect(a.publicKeyHex).not.toBe(b.publicKeyHex);
    });
  });

  describe('computeConversationKey', () => {
    it('should produce 32-byte key', () => {
      const kp = generateKeypair();
      const key = computeConversationKey(kp.privateKey, kp.publicKeyHex);
      expect(key.length).toBe(32);
    });
  });

  describe('deriveGroupConversationKey', () => {
    it('should produce consistent key', () => {
      const secret = new Uint8Array(32).fill(0x42);
      const a = deriveGroupConversationKey(secret);
      const b = deriveGroupConversationKey(secret);
      expect(bytesToHex(a)).toBe(bytesToHex(b));
    });
  });
});
