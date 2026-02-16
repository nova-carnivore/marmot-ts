import { describe, it, expect } from 'vitest';
import {
  MARMOT_GROUP_DATA_EXTENSION_ID,
  MARMOT_GROUP_DATA_VERSION,
  MARMOT_GROUP_DATA_MIN_SIZE,
  serializeMarmotGroupData,
  serializeMarmotGroupDataV2,
  deserializeMarmotGroupData,
  deserializeMarmotGroupDataV2,
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
  readVLI,
  writeVLI,
  vliSize,
} from '../src/mip01.js';
import type { MarmotGroupData } from '../src/types.js';
import { bytesToHex, hexToBytes } from '../src/utils.js';

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
      // After v2 support, version detection happens first
      // A small all-zeros buffer will be detected as version 0 (unsupported)
      expect(() => deserializeMarmotGroupData(new Uint8Array(10))).toThrow();
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

  describe('VLI Encoding (RFC 9000 §16)', () => {
    it('should encode/decode 1-byte values (0-63)', () => {
      const buffer = new Uint8Array(10);

      // Test boundary values
      expect(writeVLI(buffer, 0, 0)).toBe(1);
      expect(buffer[0]).toBe(0x00);
      expect(readVLI(buffer, 0)).toEqual({ value: 0, bytesRead: 1 });

      expect(writeVLI(buffer, 0, 63)).toBe(1);
      expect(buffer[0]).toBe(0x3f);
      expect(readVLI(buffer, 0)).toEqual({ value: 63, bytesRead: 1 });

      expect(writeVLI(buffer, 0, 42)).toBe(1);
      expect(buffer[0]).toBe(42);
      expect(readVLI(buffer, 0)).toEqual({ value: 42, bytesRead: 1 });
    });

    it('should encode/decode 2-byte values (64-16383)', () => {
      const buffer = new Uint8Array(10);

      // Test boundary values
      expect(writeVLI(buffer, 0, 64)).toBe(2);
      expect(buffer[0]).toBe(0x40);
      expect(buffer[1]).toBe(0x40);
      expect(readVLI(buffer, 0)).toEqual({ value: 64, bytesRead: 2 });

      expect(writeVLI(buffer, 0, 16383)).toBe(2);
      expect(buffer[0]).toBe(0x7f);
      expect(buffer[1]).toBe(0xff);
      expect(readVLI(buffer, 0)).toEqual({ value: 16383, bytesRead: 2 });

      expect(writeVLI(buffer, 0, 1234)).toBe(2);
      expect(readVLI(buffer, 0)).toEqual({ value: 1234, bytesRead: 2 });
    });

    it('should encode/decode 4-byte values', () => {
      const buffer = new Uint8Array(10);

      expect(writeVLI(buffer, 0, 16384)).toBe(4);
      expect(buffer[0]).toBe(0x80);
      expect(readVLI(buffer, 0)).toEqual({ value: 16384, bytesRead: 4 });

      expect(writeVLI(buffer, 0, 1073741823)).toBe(4);
      expect(readVLI(buffer, 0)).toEqual({ value: 1073741823, bytesRead: 4 });

      expect(writeVLI(buffer, 0, 100000)).toBe(4);
      expect(readVLI(buffer, 0)).toEqual({ value: 100000, bytesRead: 4 });
    });

    it('should calculate correct VLI sizes', () => {
      expect(vliSize(0)).toBe(1);
      expect(vliSize(63)).toBe(1);
      expect(vliSize(64)).toBe(2);
      expect(vliSize(16383)).toBe(2);
      expect(vliSize(16384)).toBe(4);
      expect(vliSize(1073741823)).toBe(4);
      expect(vliSize(1073741824)).toBe(8);
    });

    it('should reject negative values', () => {
      const buffer = new Uint8Array(10);
      expect(() => writeVLI(buffer, 0, -1)).toThrow('negative values');
    });

    it('should reject non-integer values', () => {
      const buffer = new Uint8Array(10);
      expect(() => writeVLI(buffer, 0, 3.14)).toThrow('must be an integer');
    });
  });

  describe('MIP-01 v2: VLI-encoded Group Data', () => {
    function makeTestGroupDataV2(): MarmotGroupData {
      return {
        version: 2,
        nostrGroupId: new Uint8Array(32).fill(0xaa),
        name: 'Test Group v2',
        description: 'VLI-encoded group',
        adminPubkeys: [testPubkey1],
        relays: ['wss://relay1.com', 'wss://relay2.com'],
        imageHash: new Uint8Array(0), // Empty in v2
        imageKey: new Uint8Array(0),
        imageNonce: new Uint8Array(0),
        imageUploadKey: new Uint8Array(0),
      };
    }

    it('should serialize and deserialize v2 with empty image fields', () => {
      const original = makeTestGroupDataV2();
      const serialized = serializeMarmotGroupDataV2(original);
      const deserialized = deserializeMarmotGroupDataV2(serialized);

      expect(deserialized.version).toBe(2);
      expect(bytesToHex(deserialized.nostrGroupId)).toBe(
        bytesToHex(original.nostrGroupId)
      );
      expect(deserialized.name).toBe(original.name);
      expect(deserialized.description).toBe(original.description);
      expect(deserialized.adminPubkeys).toEqual(original.adminPubkeys);
      expect(deserialized.relays).toEqual(original.relays);
      expect(deserialized.imageHash.length).toBe(0);
      expect(deserialized.imageKey.length).toBe(0);
      expect(deserialized.imageNonce.length).toBe(0);
      expect(deserialized.imageUploadKey).toBe(undefined);
    });

    it('should serialize and deserialize v2 with populated image fields', () => {
      const data = makeTestGroupDataV2();
      data.imageHash = new Uint8Array(32).fill(0xbb);
      data.imageKey = new Uint8Array(32).fill(0xcc);
      data.imageNonce = new Uint8Array(12).fill(0xdd);
      data.imageUploadKey = new Uint8Array(32).fill(0xee);

      const serialized = serializeMarmotGroupDataV2(data);
      const deserialized = deserializeMarmotGroupDataV2(serialized);

      expect(bytesToHex(deserialized.imageHash)).toBe(bytesToHex(data.imageHash));
      expect(bytesToHex(deserialized.imageKey)).toBe(bytesToHex(data.imageKey));
      expect(bytesToHex(deserialized.imageNonce)).toBe(bytesToHex(data.imageNonce));
      expect(bytesToHex(deserialized.imageUploadKey!)).toBe(
        bytesToHex(data.imageUploadKey)
      );
    });

    it('should handle multiple admin pubkeys in v2 (individually VLI-prefixed)', () => {
      const data = makeTestGroupDataV2();
      data.adminPubkeys = [testPubkey1, testPubkey2, 'c'.repeat(64)];

      const serialized = serializeMarmotGroupDataV2(data);
      const deserialized = deserializeMarmotGroupDataV2(serialized);

      expect(deserialized.adminPubkeys).toEqual([
        testPubkey1,
        testPubkey2,
        'c'.repeat(64),
      ]);
    });

    it('should handle multiple relays in v2 (individually VLI-prefixed)', () => {
      const data = makeTestGroupDataV2();
      data.relays = ['wss://r1.com', 'wss://r2.com', 'wss://r3.com', 'wss://r4.com'];

      const serialized = serializeMarmotGroupDataV2(data);
      const deserialized = deserializeMarmotGroupDataV2(serialized);

      expect(deserialized.relays).toEqual([
        'wss://r1.com',
        'wss://r2.com',
        'wss://r3.com',
        'wss://r4.com',
      ]);
    });

    it('should auto-detect v2 and deserialize correctly', () => {
      const data = makeTestGroupDataV2();
      const serialized = serializeMarmotGroupDataV2(data);
      const deserialized = deserializeMarmotGroupData(serialized); // Auto-detect

      expect(deserialized.version).toBe(2);
      expect(deserialized.name).toBe(data.name);
    });

    it('should validate v2 structure correctly', () => {
      const data = makeTestGroupDataV2();
      const serialized = serializeMarmotGroupDataV2(data);
      expect(validateStructure(serialized)).toBe(true);
    });

    it('should deserialize real MDK v2 data (212 bytes)', () => {
      // Real test data from MDK/0.5.3
      const hexData =
        '0002468bf188103161e4510e7c5686cfb868cb50e3fd5c132f040f0534f1833e439b1e436861742077697468206e707562313373687035376839387367753478770f4d61726d6f7420434c49206368617440424040323965373166386562383961353731343834643762353938373466323234613565326165383761663535616365616633336364376435343433653230303636363a0d7773733a2f2f6e6f732e6c6f6c147773733a2f2f72656c61792e64616d75732e696f167773733a2f2f72656c61792e7072696d616c2e6e657400000000';
      const buffer = hexToBytes(hexData);

      expect(buffer.length).toBe(212);

      const data = deserializeMarmotGroupData(buffer);

      expect(data.version).toBe(2);
      expect(data.name).toBe('Chat with npub13shp57h98sgu4xw');
      expect(data.description).toBe('Marmot CLI chat');
      expect(data.adminPubkeys).toEqual([
        '29e71f8eb89a571484d7b59874f224a5e2ae87af55aceaf33cd7d5443e200666',
      ]);
      expect(data.relays).toEqual([
        'wss://nos.lol',
        'wss://relay.damus.io',
        'wss://relay.primal.net',
      ]);
      expect(data.imageHash.length).toBe(0);
      expect(data.imageKey.length).toBe(0);
      expect(data.imageNonce.length).toBe(0);
      expect(data.imageUploadKey).toBe(undefined);
    });

    it('should roundtrip v2 serialization', () => {
      const original = makeTestGroupDataV2();
      original.adminPubkeys = [testPubkey1, testPubkey2];
      original.relays = ['wss://r1.com', 'wss://r2.com', 'wss://r3.com'];

      const serialized = serializeMarmotGroupDataV2(original);
      const deserialized = deserializeMarmotGroupDataV2(serialized);
      const reSerialized = serializeMarmotGroupDataV2(deserialized);

      expect(bytesToHex(serialized)).toBe(bytesToHex(reSerialized));
    });

    it('should validate v2 data with optional imageUploadKey', () => {
      const data = makeTestGroupDataV2();
      data.imageUploadKey = new Uint8Array(32).fill(0xff);

      expect(() => validateMarmotGroupData(data)).not.toThrow();
    });

    it('should reject imageUploadKey in v1', () => {
      const data = makeTestGroupData();
      (data as any).imageUploadKey = new Uint8Array(32);

      expect(() => validateMarmotGroupData(data)).toThrow('only supported in version 2');
    });

    it('should allow empty image fields in v2', () => {
      const data = makeTestGroupDataV2();
      data.imageHash = new Uint8Array(0);
      data.imageKey = new Uint8Array(0);
      data.imageNonce = new Uint8Array(0);

      expect(() => validateMarmotGroupData(data)).not.toThrow();
    });

    it('should reject wrong-sized image fields in v2', () => {
      const data = makeTestGroupDataV2();
      data.imageHash = new Uint8Array(16); // Wrong size

      expect(() => validateMarmotGroupData(data)).toThrow(
        'image_hash must be 0 or 32 bytes'
      );
    });
  });

  describe('v1/v2 compatibility', () => {
    it('should maintain v1 compatibility', () => {
      const v1Data = makeTestGroupData();
      const serialized = serializeMarmotGroupData(v1Data);
      const deserialized = deserializeMarmotGroupData(serialized);

      expect(deserialized.version).toBe(1);
      expect(deserialized.name).toBe(v1Data.name);
      expect(deserialized.adminPubkeys).toEqual(v1Data.adminPubkeys);
    });

    it('should detect and route v1 correctly', () => {
      const v1Data = makeTestGroupData();
      const serialized = serializeMarmotGroupData(v1Data);

      expect(detectAndValidateVersion(serialized)).toBe(1);
      expect(validateStructure(serialized)).toBe(true);
    });

    it('should detect and route v2 correctly', () => {
      const v2Data: MarmotGroupData = {
        version: 2,
        nostrGroupId: new Uint8Array(32),
        name: 'v2 test',
        description: 'test',
        adminPubkeys: [testPubkey1],
        relays: ['wss://relay.com'],
        imageHash: new Uint8Array(0),
        imageKey: new Uint8Array(0),
        imageNonce: new Uint8Array(0),
      };
      const serialized = serializeMarmotGroupDataV2(v2Data);

      expect(detectAndValidateVersion(serialized)).toBe(2);
      expect(validateStructure(serialized)).toBe(true);
    });

    it('should reject unsupported version', () => {
      const buffer = new Uint8Array(100);
      const view = new DataView(buffer.buffer);
      view.setUint16(0, 99, false); // Version 99

      expect(() => deserializeMarmotGroupData(buffer)).toThrow('Unsupported version: 99');
    });
  });
});
