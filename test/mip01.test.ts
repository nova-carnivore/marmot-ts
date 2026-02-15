import { describe, it, expect } from 'vitest';
import {
  MARMOT_GROUP_DATA_EXTENSION_ID,
  MARMOT_GROUP_DATA_VERSION,
  MARMOT_GROUP_DATA_MIN_SIZE,
  serializeMarmotGroupData,
  deserializeMarmotGroupData,
  validateMarmotGroupData,
  detectAndValidateVersion,
  validateStructure,
  createGroupData,
  generateMlsGroupId,
  isAdmin,
  verifyAdminAuthorization,
  encryptGroupImage,
  decryptGroupImage,
  deriveImageUploadKeypair,
  updateGroupData,
  getNostrGroupIdHex,
} from '../src/mip01.js';
import type { MarmotGroupData } from '../src/types.js';
import { bytesToHex } from '../src/utils.js';

describe('MIP-01: Group Construction', () => {
  const testPubkey1 = 'a'.repeat(64);
  const testPubkey2 = 'b'.repeat(64);

  function makeTestGroupData(): MarmotGroupData {
    return createGroupData({
      name: 'Test Group',
      description: 'A test group',
      adminPubkeys: [testPubkey1],
      relays: ['wss://relay1.com', 'wss://relay2.com'],
    });
  }

  describe('Extension Constants', () => {
    it('should have correct extension ID', () => {
      expect(MARMOT_GROUP_DATA_EXTENSION_ID).toBe(0xf2ee);
    });

    it('should have version 1', () => {
      expect(MARMOT_GROUP_DATA_VERSION).toBe(1);
    });

    it('should have correct minimum size', () => {
      expect(MARMOT_GROUP_DATA_MIN_SIZE).toBe(118);
    });
  });

  describe('serializeMarmotGroupData / deserializeMarmotGroupData', () => {
    it('should roundtrip basic group data', () => {
      const original = makeTestGroupData();
      const serialized = serializeMarmotGroupData(original);
      const deserialized = deserializeMarmotGroupData(serialized);

      expect(deserialized.version).toBe(original.version);
      expect(bytesToHex(deserialized.nostrGroupId)).toBe(
        bytesToHex(original.nostrGroupId)
      );
      expect(deserialized.name).toBe(original.name);
      expect(deserialized.description).toBe(original.description);
      expect(deserialized.adminPubkeys).toEqual(original.adminPubkeys);
      expect(deserialized.relays).toEqual(original.relays);
      expect(bytesToHex(deserialized.imageHash)).toBe(bytesToHex(original.imageHash));
      expect(bytesToHex(deserialized.imageKey)).toBe(bytesToHex(original.imageKey));
      expect(bytesToHex(deserialized.imageNonce)).toBe(bytesToHex(original.imageNonce));
    });

    it('should handle empty strings', () => {
      const data = makeTestGroupData();
      data.name = '';
      data.description = '';

      const serialized = serializeMarmotGroupData(data);
      const deserialized = deserializeMarmotGroupData(serialized);

      expect(deserialized.name).toBe('');
      expect(deserialized.description).toBe('');
    });

    it('should handle multiple admin pubkeys', () => {
      const data = makeTestGroupData();
      data.adminPubkeys = [testPubkey1, testPubkey2];

      const serialized = serializeMarmotGroupData(data);
      const deserialized = deserializeMarmotGroupData(serialized);

      expect(deserialized.adminPubkeys).toEqual([testPubkey1, testPubkey2]);
    });

    it('should handle multiple relays', () => {
      const data = makeTestGroupData();
      data.relays = ['wss://r1.com', 'wss://r2.com', 'wss://r3.com'];

      const serialized = serializeMarmotGroupData(data);
      const deserialized = deserializeMarmotGroupData(serialized);

      expect(deserialized.relays).toEqual([
        'wss://r1.com',
        'wss://r2.com',
        'wss://r3.com',
      ]);
    });

    it('should handle UTF-8 names', () => {
      const data = makeTestGroupData();
      data.name = 'Test 🦫 Group';
      data.description = 'Marmot 🏔️ Chat';

      const serialized = serializeMarmotGroupData(data);
      const deserialized = deserializeMarmotGroupData(serialized);

      expect(deserialized.name).toBe('Test 🦫 Group');
      expect(deserialized.description).toBe('Marmot 🏔️ Chat');
    });

    it('should use big-endian uint16 for version', () => {
      const data = makeTestGroupData();
      const serialized = serializeMarmotGroupData(data);

      // Version 1 in big-endian: 0x00 0x01
      expect(serialized[0]).toBe(0);
      expect(serialized[1]).toBe(1);
    });

    it('should reject buffer too small', () => {
      expect(() => deserializeMarmotGroupData(new Uint8Array(10))).toThrow(
        'Buffer too small'
      );
    });
  });

  describe('validateMarmotGroupData', () => {
    it('should accept valid data', () => {
      const data = makeTestGroupData();
      expect(() => validateMarmotGroupData(data)).not.toThrow();
    });

    it('should reject invalid version', () => {
      const data = makeTestGroupData();
      data.version = 0;
      expect(() => validateMarmotGroupData(data)).toThrow('Invalid version');
    });

    it('should reject wrong nostrGroupId length', () => {
      const data = makeTestGroupData();
      data.nostrGroupId = new Uint8Array(16);
      expect(() => validateMarmotGroupData(data)).toThrow(
        'nostr_group_id must be 32 bytes'
      );
    });

    it('should reject invalid admin pubkey', () => {
      const data = makeTestGroupData();
      data.adminPubkeys = ['invalid-pubkey'];
      expect(() => validateMarmotGroupData(data)).toThrow('Invalid admin pubkey');
    });

    it('should reject duplicate admin pubkeys', () => {
      const data = makeTestGroupData();
      data.adminPubkeys = [testPubkey1, testPubkey1];
      expect(() => validateMarmotGroupData(data)).toThrow('Duplicate admin pubkeys');
    });

    it('should reject invalid relay URL', () => {
      const data = makeTestGroupData();
      data.relays = ['https://not-a-relay.com'];
      expect(() => validateMarmotGroupData(data)).toThrow('Invalid relay URL');
    });

    it('should reject wrong image_hash length', () => {
      const data = makeTestGroupData();
      data.imageHash = new Uint8Array(16);
      expect(() => validateMarmotGroupData(data)).toThrow('image_hash must be 32 bytes');
    });

    it('should reject wrong image_key length', () => {
      const data = makeTestGroupData();
      data.imageKey = new Uint8Array(16);
      expect(() => validateMarmotGroupData(data)).toThrow('image_key must be 32 bytes');
    });

    it('should reject wrong image_nonce length', () => {
      const data = makeTestGroupData();
      data.imageNonce = new Uint8Array(16);
      expect(() => validateMarmotGroupData(data)).toThrow('image_nonce must be 12 bytes');
    });
  });

  describe('detectAndValidateVersion', () => {
    it('should detect version 1', () => {
      const data = makeTestGroupData();
      const serialized = serializeMarmotGroupData(data);
      expect(detectAndValidateVersion(serialized)).toBe(1);
    });

    it('should reject version 0', () => {
      const buffer = new Uint8Array(MARMOT_GROUP_DATA_MIN_SIZE);
      // version = 0
      buffer[0] = 0;
      buffer[1] = 0;
      expect(() => detectAndValidateVersion(buffer)).toThrow('Invalid version: 0');
    });

    it('should reject too-short data', () => {
      expect(() => detectAndValidateVersion(new Uint8Array(1))).toThrow(
        'Extension data too short'
      );
    });
  });

  describe('validateStructure', () => {
    it('should validate correct structure', () => {
      const data = makeTestGroupData();
      const serialized = serializeMarmotGroupData(data);
      expect(validateStructure(serialized)).toBe(true);
    });

    it('should reject too-short data', () => {
      expect(validateStructure(new Uint8Array(50))).toBe(false);
    });
  });

  describe('createGroupData', () => {
    it('should create group data with defaults', () => {
      const data = createGroupData({
        name: 'My Group',
        adminPubkeys: [testPubkey1],
        relays: ['wss://relay1.com'],
      });

      expect(data.version).toBe(1);
      expect(data.nostrGroupId.length).toBe(32);
      expect(data.name).toBe('My Group');
      expect(data.description).toBe('');
      expect(data.adminPubkeys).toEqual([testPubkey1]);
      expect(data.relays).toEqual(['wss://relay1.com']);
      expect(data.imageHash).toEqual(new Uint8Array(32));
      expect(data.imageKey).toEqual(new Uint8Array(32));
      expect(data.imageNonce).toEqual(new Uint8Array(12));
    });

    it('should require at least one admin', () => {
      expect(() =>
        createGroupData({
          name: 'Test',
          adminPubkeys: [],
          relays: ['wss://relay1.com'],
        })
      ).toThrow('At least one admin pubkey is required');
    });
  });

  describe('generateMlsGroupId', () => {
    it('should generate 32-byte random ID', () => {
      const id = generateMlsGroupId();
      expect(id.length).toBe(32);
    });

    it('should generate unique IDs', () => {
      const a = generateMlsGroupId();
      const b = generateMlsGroupId();
      expect(bytesToHex(a)).not.toBe(bytesToHex(b));
    });
  });

  describe('Admin Authorization', () => {
    const data = makeTestGroupData();

    it('should identify admin', () => {
      expect(isAdmin(data, testPubkey1)).toBe(true);
    });

    it('should identify non-admin', () => {
      expect(isAdmin(data, testPubkey2)).toBe(false);
    });

    it('should allow admin commits', () => {
      expect(verifyAdminAuthorization(data, testPubkey1, false)).toBe(true);
    });

    it('should reject non-admin commits', () => {
      expect(verifyAdminAuthorization(data, testPubkey2, false)).toBe(false);
    });

    it('should allow self-update from any member', () => {
      expect(verifyAdminAuthorization(data, testPubkey2, true)).toBe(true);
    });
  });

  describe('Group Image Encryption', () => {
    it('should encrypt and decrypt group image', () => {
      const imageData = new TextEncoder().encode('fake image data for testing');
      const { encryptedImage, imageHash, imageKey, imageNonce } =
        encryptGroupImage(imageData);

      expect(encryptedImage.length).toBeGreaterThan(imageData.length);
      expect(imageHash.length).toBe(32);
      expect(imageKey.length).toBe(32);
      expect(imageNonce.length).toBe(12);

      const decrypted = decryptGroupImage(encryptedImage, imageKey, imageNonce);
      expect(new TextDecoder().decode(decrypted)).toBe('fake image data for testing');
    });
  });

  describe('deriveImageUploadKeypair', () => {
    it('should derive consistent keypair', () => {
      const imageKey = new Uint8Array(32).fill(0xcc);
      const a = deriveImageUploadKeypair(imageKey);
      const b = deriveImageUploadKeypair(imageKey);
      expect(a.publicKeyHex).toBe(b.publicKeyHex);
    });
  });

  describe('updateGroupData', () => {
    it('should allow admin to update', () => {
      const data = makeTestGroupData();
      const updated = updateGroupData(data, { name: 'New Name' }, testPubkey1);
      expect(updated.name).toBe('New Name');
      expect(updated.version).toBe(data.version);
    });

    it('should reject non-admin update', () => {
      const data = makeTestGroupData();
      expect(() => updateGroupData(data, { name: 'New Name' }, testPubkey2)).toThrow(
        'not an admin'
      );
    });
  });

  describe('getNostrGroupIdHex', () => {
    it('should return hex string', () => {
      const data = makeTestGroupData();
      const hex = getNostrGroupIdHex(data);
      expect(hex.length).toBe(64);
      expect(/^[0-9a-f]{64}$/.test(hex)).toBe(true);
    });
  });
});
