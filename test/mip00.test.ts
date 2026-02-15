import { describe, it, expect } from 'vitest';
import {
  createKeyPackageEvent,
  createSignedKeyPackageEvent,
  parseKeyPackageEvent,
  validateCredentialIdentity,
  pubkeyToCredentialIdentity,
  isKeyPackageCompatible,
  hasRequiredMarmotExtensions,
  createKeyPackageRelayListEvent,
  parseKeyPackageRelayList,
  createKeyPackageDeletionEvent,
} from '../src/mip00.js';
import {
  MARMOT_EVENT_KINDS,
  MLS_CIPHERSUITES,
  MLS_EXTENSION_TYPES,
} from '../src/types.js';
import { PrivateKeySigner } from '../src/signer.js';
import { generateKeypair } from '../src/crypto.js';
import { bytesToHex } from '../src/utils.js';

describe('MIP-00: Credentials & Key Packages', () => {
  const testKeypair = generateKeypair();
  const testPubkey = testKeypair.publicKeyHex;
  const testKeyPackageData = new Uint8Array(128).fill(0xab);

  describe('createKeyPackageEvent', () => {
    it('should create valid event with base64 encoding', () => {
      const event = createKeyPackageEvent(testPubkey, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com', 'wss://relay2.com'],
      });

      expect(event.kind).toBe(MARMOT_EVENT_KINDS.KEY_PACKAGE);
      expect(event.pubkey).toBe(testPubkey);
      expect(event.content.length).toBeGreaterThan(0);

      // Check tags
      const tags = event.tags;
      const versionTag = tags.find((t) => t[0] === 'mls_protocol_version');
      expect(versionTag?.[1]).toBe('1.0');

      const csTag = tags.find((t) => t[0] === 'mls_ciphersuite');
      expect(csTag?.[1]).toBe('0x0001');

      const encodingTag = tags.find((t) => t[0] === 'encoding');
      expect(encodingTag?.[1]).toBe('base64');

      // Must include marmot_group_data and last_resort
      const extTag = tags.find((t) => t[0] === 'mls_extensions');
      expect(extTag).toBeDefined();
      expect(extTag!.includes('0xf2ee')).toBe(true);
      expect(extTag!.includes('0x000a')).toBe(true);
    });

    it('should include NIP-70 protected tag by default', () => {
      const event = createKeyPackageEvent(testPubkey, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com'],
      });

      expect(event.tags.some((t) => t[0] === '-')).toBe(true);
    });

    it('should allow disabling protected tag', () => {
      const event = createKeyPackageEvent(testPubkey, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com'],
        protected: false,
      });

      expect(event.tags.some((t) => t[0] === '-')).toBe(false);
    });

    it('should include client name when specified', () => {
      const event = createKeyPackageEvent(testPubkey, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com'],
        clientName: 'marmot-ts-test',
      });

      const clientTag = event.tags.find((t) => t[0] === 'client');
      expect(clientTag?.[1]).toBe('marmot-ts-test');
    });

    it('should reject invalid pubkey', () => {
      expect(() =>
        createKeyPackageEvent('invalid', {
          keyPackageData: testKeyPackageData,
          ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
          relays: ['wss://relay1.com'],
        })
      ).toThrow('Invalid Nostr pubkey');
    });

    it('should reject invalid relay URL', () => {
      expect(() =>
        createKeyPackageEvent(testPubkey, {
          keyPackageData: testKeyPackageData,
          ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
          relays: ['https://not-a-relay.com'],
        })
      ).toThrow('Invalid relay URL');
    });

    it('should filter out default extensions', () => {
      const event = createKeyPackageEvent(testPubkey, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com'],
        extensions: [0x0001, 0x0002, 0xf2ee, 0x000a], // Includes default extensions
      });

      const extTag = event.tags.find((t) => t[0] === 'mls_extensions');
      expect(extTag).toBeDefined();
      // Should NOT include default extensions 0x0001, 0x0002
      expect(extTag!.includes('0x0001')).toBe(false);
      expect(extTag!.includes('0x0002')).toBe(false);
      // Should include non-default extensions
      expect(extTag!.includes('0xf2ee')).toBe(true);
      expect(extTag!.includes('0x000a')).toBe(true);
    });
  });

  describe('createSignedKeyPackageEvent', () => {
    it('should create and sign a KeyPackage event', async () => {
      const signer = new PrivateKeySigner(testKeypair.privateKeyHex);
      const signed = await createSignedKeyPackageEvent(signer, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com'],
      });

      expect(signed.id).toBeDefined();
      expect(signed.sig).toBeDefined();
      expect(signed.kind).toBe(MARMOT_EVENT_KINDS.KEY_PACKAGE);
    });
  });

  describe('parseKeyPackageEvent', () => {
    it('should parse a created event', () => {
      const event = createKeyPackageEvent(testPubkey, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com'],
        clientName: 'test-client',
      });
      event.id = 'test-event-id';

      const parsed = parseKeyPackageEvent(event);
      expect(parsed.pubkey).toBe(testPubkey);
      expect(parsed.protocolVersion).toBe('1.0');
      expect(parsed.ciphersuite).toBe('0x0001');
      expect(parsed.encoding).toBe('base64');
      expect(parsed.clientName).toBe('test-client');
      expect(parsed.relays).toEqual(['wss://relay1.com']);
      expect(parsed.extensions).toContain(MLS_EXTENSION_TYPES.MARMOT_GROUP_DATA);
      expect(parsed.extensions).toContain(MLS_EXTENSION_TYPES.LAST_RESORT);
    });

    it('should parse hex-encoded events', () => {
      const event = createKeyPackageEvent(testPubkey, {
        keyPackageData: testKeyPackageData,
        ciphersuite: MLS_CIPHERSUITES.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        relays: ['wss://relay1.com'],
        encoding: 'hex',
      });

      const parsed = parseKeyPackageEvent(event);
      expect(parsed.encoding).toBe('hex');
      expect(bytesToHex(parsed.keyPackageData)).toBe(bytesToHex(testKeyPackageData));
    });

    it('should reject wrong event kind', () => {
      expect(() =>
        parseKeyPackageEvent({
          id: 'test',
          kind: 1,
          created_at: 1000,
          pubkey: testPubkey,
          content: '',
          tags: [],
          sig: 'test',
        })
      ).toThrow('Expected kind 443');
    });
  });

  describe('validateCredentialIdentity', () => {
    it('should validate matching identity', () => {
      const pubkey = testPubkey;
      const identity = pubkeyToCredentialIdentity(pubkey);
      expect(validateCredentialIdentity(identity, pubkey)).toBe(true);
    });

    it('should reject wrong length', () => {
      expect(validateCredentialIdentity(new Uint8Array(16), testPubkey)).toBe(false);
    });

    it('should reject mismatched identity', () => {
      const identity = new Uint8Array(32).fill(0xff);
      expect(validateCredentialIdentity(identity, testPubkey)).toBe(false);
    });
  });

  describe('pubkeyToCredentialIdentity', () => {
    it('should convert pubkey to 32-byte identity', () => {
      const identity = pubkeyToCredentialIdentity(testPubkey);
      expect(identity.length).toBe(32);
    });

    it('should reject invalid pubkey', () => {
      expect(() => pubkeyToCredentialIdentity('invalid')).toThrow('Invalid Nostr pubkey');
    });
  });

  describe('isKeyPackageCompatible', () => {
    const parsed = {
      eventId: 'test',
      pubkey: testPubkey,
      keyPackageData: testKeyPackageData,
      protocolVersion: '1.0',
      ciphersuite: '0x0001',
      extensions: [0xf2ee, 0x000a],
      encoding: 'base64' as const,
      relays: ['wss://relay1.com'],
      createdAt: 1000,
    };

    it('should be compatible with matching ciphersuite', () => {
      expect(isKeyPackageCompatible(parsed, '0x0001')).toBe(true);
    });

    it('should be incompatible with different ciphersuite', () => {
      expect(isKeyPackageCompatible(parsed, '0x0002')).toBe(false);
    });

    it('should check required extensions', () => {
      expect(isKeyPackageCompatible(parsed, '0x0001', [0xf2ee])).toBe(true);
      expect(isKeyPackageCompatible(parsed, '0x0001', [0xffff])).toBe(false);
    });
  });

  describe('hasRequiredMarmotExtensions', () => {
    it('should detect when both required extensions present', () => {
      expect(
        hasRequiredMarmotExtensions({
          extensions: [0xf2ee, 0x000a],
        } as unknown as import('../src/types.js').ParsedKeyPackage)
      ).toBe(true);
    });

    it('should detect when marmot_group_data missing', () => {
      expect(
        hasRequiredMarmotExtensions({
          extensions: [0x000a],
        } as unknown as import('../src/types.js').ParsedKeyPackage)
      ).toBe(false);
    });
  });

  describe('KeyPackage Relay List', () => {
    it('should create relay list event', () => {
      const event = createKeyPackageRelayListEvent(testPubkey, [
        'wss://relay1.com',
        'wss://relay2.com',
      ]);

      expect(event.kind).toBe(MARMOT_EVENT_KINDS.KEY_PACKAGE_RELAY_LIST);
      expect(event.tags).toEqual([
        ['relay', 'wss://relay1.com'],
        ['relay', 'wss://relay2.com'],
      ]);
    });

    it('should parse relay list event', () => {
      const event = createKeyPackageRelayListEvent(testPubkey, ['wss://relay1.com']);
      const parsed = parseKeyPackageRelayList(event);
      expect(parsed.relays).toEqual(['wss://relay1.com']);
    });
  });

  describe('KeyPackage Deletion', () => {
    it('should create deletion event', () => {
      const event = createKeyPackageDeletionEvent(testPubkey, ['event1', 'event2']);

      expect(event.kind).toBe(5);
      expect(event.tags).toContainEqual(['e', 'event1']);
      expect(event.tags).toContainEqual(['e', 'event2']);
      expect(event.tags).toContainEqual(['k', '443']);
    });

    it('should reject empty event IDs', () => {
      expect(() => createKeyPackageDeletionEvent(testPubkey, [])).toThrow(
        'Must specify at least one event ID'
      );
    });
  });
});
