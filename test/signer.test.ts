import { describe, it, expect } from 'vitest';
import {
  PrivateKeySigner,
  Nip07Signer,
  Nip46Signer,
  computeEventId,
} from '../src/signer.js';
import { generateKeypair } from '../src/crypto.js';
import type { UnsignedEvent } from '../src/types.js';

describe('signer', () => {
  describe('PrivateKeySigner', () => {
    const testKeypair = generateKeypair();
    const signer = new PrivateKeySigner(testKeypair.privateKeyHex);

    it('should return correct public key', async () => {
      const pubkey = await signer.getPublicKey();
      expect(pubkey).toBe(testKeypair.publicKeyHex);
    });

    it('should sign events', async () => {
      const event: UnsignedEvent = {
        kind: 1,
        created_at: 1000000,
        pubkey: testKeypair.publicKeyHex,
        content: 'test content',
        tags: [],
      };

      const signed = await signer.signEvent(event);
      expect(signed.id).toBeDefined();
      expect(signed.sig).toBeDefined();
      expect(signed.id.length).toBe(64);
      expect(signed.sig.length).toBe(128);
      expect(signed.pubkey).toBe(testKeypair.publicKeyHex);
    });

    it('should produce deterministic event IDs', async () => {
      const event: UnsignedEvent = {
        kind: 1,
        created_at: 1000000,
        pubkey: testKeypair.publicKeyHex,
        content: 'deterministic',
        tags: [],
      };

      const signed1 = await signer.signEvent(event);
      const signed2 = await signer.signEvent(event);
      expect(signed1.id).toBe(signed2.id);
    });

    it('should encrypt and decrypt with NIP-44', async () => {
      // Use the signer's own pubkey as the recipient (self-encryption)
      const pubkey = await signer.getPublicKey();
      const plaintext = 'Hello, NIP-44 encryption!';

      const encrypted = await signer.nip44Encrypt(pubkey, plaintext);
      expect(encrypted).toBeDefined();
      expect(encrypted).not.toBe(plaintext);

      const decrypted = await signer.nip44Decrypt(pubkey, encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertexts for same plaintext (random nonce)', async () => {
      const pubkey = await signer.getPublicKey();
      const plaintext = 'test message';

      const encrypted1 = await signer.nip44Encrypt(pubkey, plaintext);
      const encrypted2 = await signer.nip44Encrypt(pubkey, plaintext);
      expect(encrypted1).not.toBe(encrypted2); // Different nonces
    });

    it('should expose private key hex', () => {
      expect(signer.getPrivateKeyHex()).toBe(testKeypair.privateKeyHex);
    });
  });

  describe('computeEventId', () => {
    it('should compute event ID', () => {
      const event: UnsignedEvent = {
        kind: 1,
        created_at: 1000000,
        pubkey: 'a'.repeat(64),
        content: 'hello',
        tags: [],
      };

      const id = computeEventId(event);
      expect(id.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(id)).toBe(true);
    });

    it('should be deterministic', () => {
      const event: UnsignedEvent = {
        kind: 1,
        created_at: 1000000,
        pubkey: 'b'.repeat(64),
        content: 'test',
        tags: [['t', 'test']],
      };

      expect(computeEventId(event)).toBe(computeEventId(event));
    });

    it('should change with different content', () => {
      const base: UnsignedEvent = {
        kind: 1,
        created_at: 1000000,
        pubkey: 'a'.repeat(64),
        content: 'hello',
        tags: [],
      };

      const modified = { ...base, content: 'world' };
      expect(computeEventId(base)).not.toBe(computeEventId(modified));
    });
  });

  describe('Nip07Signer', () => {
    it('should throw when window.nostr is not available', async () => {
      const signer = new Nip07Signer();
      await expect(signer.getPublicKey()).rejects.toThrow('NIP-07 signer not available');
    });
  });

  describe('Nip46Signer', () => {
    it('should return remote pubkey', async () => {
      const signer = new Nip46Signer({
        remotePubkey: 'a'.repeat(64),
        relayUrl: 'wss://relay.example.com',
      });

      const pubkey = await signer.getPublicKey();
      expect(pubkey).toBe('a'.repeat(64));
    });

    it('should expose config', () => {
      const config = {
        remotePubkey: 'b'.repeat(64),
        relayUrl: 'wss://relay.test.com',
        secret: 'test-secret',
      };
      const signer = new Nip46Signer(config);
      expect(signer.getConfig()).toEqual(config);
    });

    it('should throw on signEvent (not yet implemented)', async () => {
      const signer = new Nip46Signer({
        remotePubkey: 'a'.repeat(64),
        relayUrl: 'wss://relay.example.com',
      });

      await expect(
        signer.signEvent({
          kind: 1,
          created_at: 1000,
          pubkey: 'a'.repeat(64),
          content: '',
          tags: [],
        })
      ).rejects.toThrow('NIP-46 signEvent not yet implemented');
    });
  });
});
