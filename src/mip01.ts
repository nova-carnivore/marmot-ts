/**
 * MIP-01: Group Construction & Marmot Group Data Extension
 *
 * Group creation, Marmot Group Data Extension (0xF2EE) serialization/deserialization,
 * member management, and admin authorization.
 */

import type { MarmotGroupData, CreateGroupOptions } from './types.js';
import { MLS_EXTENSION_TYPES } from './types.js';
import { isValidPubkey, isValidRelayUrl, randomBytes, bytesToHex } from './utils.js';
import {
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
  sha256Hash,
  hkdfExpand,
  keypairFromSecret,
} from './crypto.js';

// ─── Extension Constants ────────────────────────────────────────────────────

/** Extension ID for Marmot Group Data */
export const MARMOT_GROUP_DATA_EXTENSION_ID = MLS_EXTENSION_TYPES.MARMOT_GROUP_DATA; // 0xF2EE

/** Current extension format version */
export const MARMOT_GROUP_DATA_VERSION = 1;

/** Minimum serialized size of the extension (in bytes) */
export const MARMOT_GROUP_DATA_MIN_SIZE = 2 + 32 + 2 + 2 + 2 + 2 + 32 + 32 + 12; // = 118 bytes

// ─── TLS Serialization ─────────────────────────────────────────────────────

/**
 * Serialize Marmot Group Data to TLS presentation language format.
 *
 * CRITICAL: Must use exact TLS serialization with proper length prefixes.
 */
export function serializeMarmotGroupData(data: MarmotGroupData): Uint8Array {
  validateMarmotGroupData(data);

  const encoder = new TextEncoder();

  // Encode variable-length fields
  const nameBytes = encoder.encode(data.name);
  const descBytes = encoder.encode(data.description);
  const adminStr = data.adminPubkeys.join(',');
  const adminBytes = encoder.encode(adminStr);
  const relayStr = data.relays.join(',');
  const relayBytes = encoder.encode(relayStr);

  // Calculate total size
  const totalSize =
    2 + // version (uint16)
    32 + // nostr_group_id
    2 +
    nameBytes.length + // name (length-prefixed)
    2 +
    descBytes.length + // description (length-prefixed)
    2 +
    adminBytes.length + // admin_pubkeys (length-prefixed)
    2 +
    relayBytes.length + // relays (length-prefixed)
    32 + // image_hash
    32 + // image_key
    12; // image_nonce

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // version (uint16, big-endian)
  view.setUint16(offset, data.version, false);
  offset += 2;

  // nostr_group_id (32 bytes)
  buffer.set(data.nostrGroupId, offset);
  offset += 32;

  // name (length-prefixed, uint16 + bytes)
  view.setUint16(offset, nameBytes.length, false);
  offset += 2;
  buffer.set(nameBytes, offset);
  offset += nameBytes.length;

  // description (length-prefixed)
  view.setUint16(offset, descBytes.length, false);
  offset += 2;
  buffer.set(descBytes, offset);
  offset += descBytes.length;

  // admin_pubkeys (length-prefixed)
  view.setUint16(offset, adminBytes.length, false);
  offset += 2;
  buffer.set(adminBytes, offset);
  offset += adminBytes.length;

  // relays (length-prefixed)
  view.setUint16(offset, relayBytes.length, false);
  offset += 2;
  buffer.set(relayBytes, offset);
  offset += relayBytes.length;

  // image_hash (32 bytes)
  buffer.set(data.imageHash, offset);
  offset += 32;

  // image_key (32 bytes)
  buffer.set(data.imageKey, offset);
  offset += 32;

  // image_nonce (12 bytes)
  buffer.set(data.imageNonce, offset);

  return buffer;
}

/**
 * Deserialize Marmot Group Data from TLS presentation language format.
 */
export function deserializeMarmotGroupData(buffer: Uint8Array): MarmotGroupData {
  if (buffer.length < MARMOT_GROUP_DATA_MIN_SIZE) {
    throw new Error(
      `Buffer too small: ${buffer.length} bytes (minimum ${MARMOT_GROUP_DATA_MIN_SIZE})`
    );
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const decoder = new TextDecoder();
  let offset = 0;

  // version
  const version = view.getUint16(offset, false);
  offset += 2;

  // nostr_group_id
  const nostrGroupId = buffer.slice(offset, offset + 32);
  offset += 32;

  // name
  const nameLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + nameLen > buffer.length) {
    throw new Error('Invalid name length');
  }
  const name = decoder.decode(buffer.slice(offset, offset + nameLen));
  offset += nameLen;

  // description
  const descLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + descLen > buffer.length) {
    throw new Error('Invalid description length');
  }
  const description = decoder.decode(buffer.slice(offset, offset + descLen));
  offset += descLen;

  // admin_pubkeys
  const adminLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + adminLen > buffer.length) {
    throw new Error('Invalid admin_pubkeys length');
  }
  const adminStr = decoder.decode(buffer.slice(offset, offset + adminLen));
  offset += adminLen;
  const adminPubkeys = adminStr.length > 0 ? adminStr.split(',') : [];

  // relays
  const relayLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + relayLen > buffer.length) {
    throw new Error('Invalid relays length');
  }
  const relayStr = decoder.decode(buffer.slice(offset, offset + relayLen));
  offset += relayLen;
  const relays = relayStr.length > 0 ? relayStr.split(',') : [];

  // Fixed-size trailing fields
  const remaining = buffer.length - offset;
  const expectedRemaining = 32 + 32 + 12;
  if (remaining < expectedRemaining) {
    throw new Error(
      `Insufficient data for fixed fields: ${remaining} bytes remaining (need ${expectedRemaining})`
    );
  }

  const imageHash = buffer.slice(offset, offset + 32);
  offset += 32;

  const imageKey = buffer.slice(offset, offset + 32);
  offset += 32;

  const imageNonce = buffer.slice(offset, offset + 12);

  return {
    version,
    nostrGroupId,
    name,
    description,
    adminPubkeys,
    relays,
    imageHash,
    imageKey,
    imageNonce,
  };
}

// ─── Validation ─────────────────────────────────────────────────────────────

/**
 * Validate Marmot Group Data fields.
 */
export function validateMarmotGroupData(data: MarmotGroupData): void {
  if (data.version < 1) {
    throw new Error(`Invalid version: ${data.version}`);
  }

  if (data.nostrGroupId.length !== 32) {
    throw new Error(`nostr_group_id must be 32 bytes, got ${data.nostrGroupId.length}`);
  }

  for (const pubkey of data.adminPubkeys) {
    if (!isValidPubkey(pubkey)) {
      throw new Error(`Invalid admin pubkey: ${pubkey}`);
    }
  }

  // Check for duplicate admin keys
  const uniqueAdmins = new Set(data.adminPubkeys);
  if (uniqueAdmins.size !== data.adminPubkeys.length) {
    throw new Error('Duplicate admin pubkeys detected');
  }

  for (const relay of data.relays) {
    if (!isValidRelayUrl(relay)) {
      throw new Error(`Invalid relay URL: ${relay}`);
    }
  }

  if (data.imageHash.length !== 32) {
    throw new Error(`image_hash must be 32 bytes, got ${data.imageHash.length}`);
  }

  if (data.imageKey.length !== 32) {
    throw new Error(`image_key must be 32 bytes, got ${data.imageKey.length}`);
  }

  if (data.imageNonce.length !== 12) {
    throw new Error(`image_nonce must be 12 bytes, got ${data.imageNonce.length}`);
  }
}

/**
 * Validate extension structure and version compatibility.
 * Returns the version if valid, throws on error.
 */
export function detectAndValidateVersion(buffer: Uint8Array): number {
  if (buffer.length < 2) {
    throw new Error('Extension data too short for version field');
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const version = view.getUint16(0, false);

  if (version === 0) {
    throw new Error('Invalid version: 0');
  }

  // Validate structure
  if (!validateStructure(buffer)) {
    throw new Error('Invalid extension structure');
  }

  return version;
}

/**
 * Validate the TLS structure of extension data.
 */
export function validateStructure(data: Uint8Array): boolean {
  if (data.length < MARMOT_GROUP_DATA_MIN_SIZE) return false;

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 2 + 32; // Skip version and nostr_group_id

  // Validate name length
  if (offset + 2 > data.length) return false;
  const nameLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + nameLen > data.length) return false;
  offset += nameLen;

  // Validate description length
  if (offset + 2 > data.length) return false;
  const descLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + descLen > data.length) return false;
  offset += descLen;

  // Validate admin_pubkeys length
  if (offset + 2 > data.length) return false;
  const adminLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + adminLen > data.length) return false;
  offset += adminLen;

  // Validate relays length
  if (offset + 2 > data.length) return false;
  const relayLen = view.getUint16(offset, false);
  offset += 2;
  if (offset + relayLen > data.length) return false;
  offset += relayLen;

  // Check remaining fixed fields
  const remainingFixed = 32 + 32 + 12; // image_hash + image_key + image_nonce
  return offset + remainingFixed === data.length;
}

// ─── Group Creation ─────────────────────────────────────────────────────────

/**
 * Create initial Marmot Group Data for a new group.
 */
export function createGroupData(options: CreateGroupOptions): MarmotGroupData {
  if (options.adminPubkeys.length === 0) {
    throw new Error('At least one admin pubkey is required');
  }

  for (const pubkey of options.adminPubkeys) {
    if (!isValidPubkey(pubkey)) {
      throw new Error(`Invalid admin pubkey: ${pubkey}`);
    }
  }

  for (const relay of options.relays) {
    if (!isValidRelayUrl(relay)) {
      throw new Error(`Invalid relay URL: ${relay}`);
    }
  }

  return {
    version: MARMOT_GROUP_DATA_VERSION,
    nostrGroupId: randomBytes(32),
    name: options.name,
    description: options.description ?? '',
    adminPubkeys: options.adminPubkeys,
    relays: options.relays,
    imageHash: new Uint8Array(32), // zeros = no image
    imageKey: new Uint8Array(32),
    imageNonce: new Uint8Array(12),
  };
}

/**
 * Generate a random MLS group ID (32 bytes).
 * This is distinct from nostr_group_id and MUST be kept private.
 */
export function generateMlsGroupId(): Uint8Array {
  return randomBytes(32);
}

// ─── Admin Authorization ────────────────────────────────────────────────────

/**
 * Check if a pubkey is an admin of the group.
 */
export function isAdmin(groupData: MarmotGroupData, pubkey: string): boolean {
  return groupData.adminPubkeys.includes(pubkey);
}

/**
 * Verify admin authorization for a commit.
 *
 * @param groupData - Current group data
 * @param committerPubkey - Pubkey of the commit sender
 * @param isSelfUpdate - Whether this is a self-update commit
 * @returns true if authorized
 */
export function verifyAdminAuthorization(
  groupData: MarmotGroupData,
  committerPubkey: string,
  isSelfUpdate: boolean
): boolean {
  // Self-update commits are allowed from any member
  if (isSelfUpdate) return true;
  // All other commits require admin status
  return isAdmin(groupData, committerPubkey);
}

// ─── Group Image Encryption ─────────────────────────────────────────────────

/**
 * Encrypt a group image using ChaCha20-Poly1305.
 *
 * @returns Updated image fields for Marmot Group Data
 */
export function encryptGroupImage(imageData: Uint8Array): {
  encryptedImage: Uint8Array;
  imageHash: Uint8Array;
  imageKey: Uint8Array;
  imageNonce: Uint8Array;
} {
  const imageKey = randomBytes(32);
  const imageNonce = randomBytes(12);
  const encryptedImage = chacha20Poly1305Encrypt(imageKey, imageNonce, imageData);
  const imageHash = sha256Hash(encryptedImage);

  return { encryptedImage, imageHash, imageKey, imageNonce };
}

/**
 * Decrypt a group image using ChaCha20-Poly1305.
 */
export function decryptGroupImage(
  encryptedImage: Uint8Array,
  imageKey: Uint8Array,
  imageNonce: Uint8Array
): Uint8Array {
  return chacha20Poly1305Decrypt(imageKey, imageNonce, encryptedImage);
}

/**
 * Derive the Blossom upload keypair from the image key.
 * Uses HKDF-Expand with domain separation.
 */
export function deriveImageUploadKeypair(imageKey: Uint8Array): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
} {
  const uploadSecret = hkdfExpand(imageKey, 'mip01-blossom-upload-v1', 32);
  return keypairFromSecret(uploadSecret);
}

// ─── Group Data Update ──────────────────────────────────────────────────────

/**
 * Create an updated copy of group data with new fields.
 * Validates admin authorization.
 */
export function updateGroupData(
  currentData: MarmotGroupData,
  updates: Partial<
    Pick<
      MarmotGroupData,
      | 'name'
      | 'description'
      | 'adminPubkeys'
      | 'relays'
      | 'imageHash'
      | 'imageKey'
      | 'imageNonce'
      | 'nostrGroupId'
    >
  >,
  committerPubkey: string
): MarmotGroupData {
  if (!isAdmin(currentData, committerPubkey)) {
    throw new Error(
      `Pubkey ${committerPubkey} is not an admin and cannot update group data`
    );
  }

  const updated: MarmotGroupData = {
    ...currentData,
    ...updates,
    // Ensure version is preserved
    version: currentData.version,
  };

  validateMarmotGroupData(updated);
  return updated;
}

/**
 * Get the hex-encoded nostr_group_id for use in event tags.
 */
export function getNostrGroupIdHex(groupData: MarmotGroupData): string {
  return bytesToHex(groupData.nostrGroupId);
}
