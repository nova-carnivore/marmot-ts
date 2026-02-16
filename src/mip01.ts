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

// ─── VLI Encoding (RFC 9000 §16) ────────────────────────────────────────────

/**
 * Read a QUIC-style Variable-Length Integer from a buffer.
 * Returns { value, bytesRead }.
 *
 * Format (RFC 9000 §16):
 * - 0b00xxxxxx                       → 1 byte,  value = byte & 0x3f (0-63)
 * - 0b01xxxxxx xxxxxxxx              → 2 bytes, value = (byte[0] & 0x3f) << 8 | byte[1] (64-16383)
 * - 0b10xxxxxx ... (4 bytes total)   → 4 bytes
 * - 0b11xxxxxx ... (8 bytes total)   → 8 bytes
 */
export function readVLI(buffer: Uint8Array, offset: number): { value: number; bytesRead: number } {
  if (offset >= buffer.length) {
    throw new Error('VLI: offset out of bounds');
  }

  const firstByte = buffer[offset]!;
  const prefix = (firstByte & 0xc0) >> 6; // Top 2 bits

  switch (prefix) {
    case 0: // 1-byte
      return { value: firstByte & 0x3f, bytesRead: 1 };

    case 1: { // 2-byte
      if (offset + 2 > buffer.length) throw new Error('VLI: truncated 2-byte integer');
      const value = ((firstByte & 0x3f) << 8) | buffer[offset + 1]!;
      return { value, bytesRead: 2 };
    }

    case 2: { // 4-byte
      if (offset + 4 > buffer.length) throw new Error('VLI: truncated 4-byte integer');
      const value =
        ((firstByte & 0x3f) << 24) |
        (buffer[offset + 1]! << 16) |
        (buffer[offset + 2]! << 8) |
        buffer[offset + 3]!;
      return { value, bytesRead: 4 };
    }

    case 3: { // 8-byte (we only support up to 53-bit precision safely in JS)
      if (offset + 8 > buffer.length) throw new Error('VLI: truncated 8-byte integer');
      // JS can safely handle integers up to 2^53 - 1
      // Read as BigInt and convert
      const high =
        ((firstByte & 0x3f) << 24) |
        (buffer[offset + 1]! << 16) |
        (buffer[offset + 2]! << 8) |
        buffer[offset + 3]!;
      const low =
        (buffer[offset + 4]! << 24) |
        (buffer[offset + 5]! << 16) |
        (buffer[offset + 6]! << 8) |
        buffer[offset + 7]!;
      const value = high * 0x100000000 + low;
      if (value > Number.MAX_SAFE_INTEGER) {
        throw new Error('VLI: 8-byte integer exceeds safe JS number range');
      }
      return { value, bytesRead: 8 };
    }
  }

  throw new Error('VLI: invalid prefix');
}

/**
 * Write a QUIC-style Variable-Length Integer to a buffer.
 * Returns the number of bytes written.
 */
export function writeVLI(buffer: Uint8Array, offset: number, value: number): number {
  if (value < 0) throw new Error('VLI: negative values not supported');
  if (!Number.isInteger(value)) throw new Error('VLI: value must be an integer');

  if (value < 64) {
    // 1-byte: 0b00xxxxxx
    buffer[offset] = value;
    return 1;
  } else if (value < 16384) {
    // 2-byte: 0b01xxxxxx xxxxxxxx
    if (offset + 2 > buffer.length) throw new Error('VLI: buffer overflow');
    buffer[offset] = 0x40 | (value >> 8);
    buffer[offset + 1] = value & 0xff;
    return 2;
  } else if (value < 1073741824) {
    // 4-byte: 0b10xxxxxx ...
    if (offset + 4 > buffer.length) throw new Error('VLI: buffer overflow');
    buffer[offset] = 0x80 | (value >> 24);
    buffer[offset + 1] = (value >> 16) & 0xff;
    buffer[offset + 2] = (value >> 8) & 0xff;
    buffer[offset + 3] = value & 0xff;
    return 4;
  } else {
    // 8-byte: 0b11xxxxxx ...
    if (offset + 8 > buffer.length) throw new Error('VLI: buffer overflow');
    if (value > Number.MAX_SAFE_INTEGER) {
      throw new Error('VLI: value exceeds safe JS number range');
    }
    const high = Math.floor(value / 0x100000000);
    const low = value >>> 0;
    buffer[offset] = 0xc0 | (high >> 24);
    buffer[offset + 1] = (high >> 16) & 0xff;
    buffer[offset + 2] = (high >> 8) & 0xff;
    buffer[offset + 3] = high & 0xff;
    buffer[offset + 4] = (low >> 24) & 0xff;
    buffer[offset + 5] = (low >> 16) & 0xff;
    buffer[offset + 6] = (low >> 8) & 0xff;
    buffer[offset + 7] = low & 0xff;
    return 8;
  }
}

/**
 * Calculate the size in bytes needed to encode a value as VLI.
 */
export function vliSize(value: number): number {
  if (value < 64) return 1;
  if (value < 16384) return 2;
  if (value < 1073741824) return 4;
  return 8;
}

// ─── TLS Serialization ─────────────────────────────────────────────────────

/**
 * Serialize Marmot Group Data to TLS presentation language format (v1).
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
 * Serialize Marmot Group Data to TLS presentation language format (v2).
 * Uses QUIC-style Variable-Length Integer encoding for all length prefixes.
 */
export function serializeMarmotGroupDataV2(data: MarmotGroupData): Uint8Array {
  validateMarmotGroupData(data);

  const encoder = new TextEncoder();

  // Encode variable-length fields
  const nameBytes = encoder.encode(data.name);
  const descBytes = encoder.encode(data.description);

  // v2: admin_pubkeys are individually VLI-prefixed
  const adminPubkeyBuffers = data.adminPubkeys.map((pk) => encoder.encode(pk));
  const relayBuffers = data.relays.map((r) => encoder.encode(r));

  // Calculate size for outer VLI containers
  let adminBytesSize = 0;
  for (const buf of adminPubkeyBuffers) {
    adminBytesSize += vliSize(buf.length) + buf.length;
  }

  let relayBytesSize = 0;
  for (const buf of relayBuffers) {
    relayBytesSize += vliSize(buf.length) + buf.length;
  }

  // Image fields: always present in v2, but may be empty (VLI length = 0)
  const imageHashBytes = data.imageHash;
  const imageKeyBytes = data.imageKey;
  const imageNonceBytes = data.imageNonce;
  const imageUploadKeyBytes = data.imageUploadKey || new Uint8Array(0);

  // Calculate total size
  const totalSize =
    2 + // version (uint16 BE)
    32 + // nostr_group_id
    vliSize(nameBytes.length) +
    nameBytes.length +
    vliSize(descBytes.length) +
    descBytes.length +
    vliSize(adminBytesSize) +
    adminBytesSize +
    vliSize(relayBytesSize) +
    relayBytesSize +
    vliSize(imageHashBytes.length) +
    imageHashBytes.length +
    vliSize(imageKeyBytes.length) +
    imageKeyBytes.length +
    vliSize(imageNonceBytes.length) +
    imageNonceBytes.length +
    vliSize(imageUploadKeyBytes.length) +
    imageUploadKeyBytes.length;

  const buffer = new Uint8Array(totalSize);
  const view = new DataView(buffer.buffer);
  let offset = 0;

  // version (uint16, big-endian)
  view.setUint16(offset, data.version, false);
  offset += 2;

  // nostr_group_id (32 bytes)
  buffer.set(data.nostrGroupId, offset);
  offset += 32;

  // name (VLI-prefixed)
  offset += writeVLI(buffer, offset, nameBytes.length);
  buffer.set(nameBytes, offset);
  offset += nameBytes.length;

  // description (VLI-prefixed)
  offset += writeVLI(buffer, offset, descBytes.length);
  buffer.set(descBytes, offset);
  offset += descBytes.length;

  // admin_pubkeys (VLI outer container + VLI-prefixed items)
  offset += writeVLI(buffer, offset, adminBytesSize);
  for (const buf of adminPubkeyBuffers) {
    offset += writeVLI(buffer, offset, buf.length);
    buffer.set(buf, offset);
    offset += buf.length;
  }

  // relays (VLI outer container + VLI-prefixed items)
  offset += writeVLI(buffer, offset, relayBytesSize);
  for (const buf of relayBuffers) {
    offset += writeVLI(buffer, offset, buf.length);
    buffer.set(buf, offset);
    offset += buf.length;
  }

  // image_hash (VLI-prefixed, may be empty)
  offset += writeVLI(buffer, offset, imageHashBytes.length);
  buffer.set(imageHashBytes, offset);
  offset += imageHashBytes.length;

  // image_key (VLI-prefixed, may be empty)
  offset += writeVLI(buffer, offset, imageKeyBytes.length);
  buffer.set(imageKeyBytes, offset);
  offset += imageKeyBytes.length;

  // image_nonce (VLI-prefixed, may be empty)
  offset += writeVLI(buffer, offset, imageNonceBytes.length);
  buffer.set(imageNonceBytes, offset);
  offset += imageNonceBytes.length;

  // image_upload_key (VLI-prefixed, may be empty, v2 only)
  offset += writeVLI(buffer, offset, imageUploadKeyBytes.length);
  buffer.set(imageUploadKeyBytes, offset);

  return buffer;
}

/**
 * Deserialize Marmot Group Data from TLS presentation language format (v2).
 * Uses QUIC-style Variable-Length Integer encoding.
 */
export function deserializeMarmotGroupDataV2(buffer: Uint8Array): MarmotGroupData {
  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const decoder = new TextDecoder();
  let offset = 0;

  // version (uint16 BE)
  if (offset + 2 > buffer.length) throw new Error('v2: buffer too short for version');
  const version = view.getUint16(offset, false);
  offset += 2;

  // nostr_group_id (32 bytes)
  if (offset + 32 > buffer.length) throw new Error('v2: buffer too short for nostr_group_id');
  const nostrGroupId = buffer.slice(offset, offset + 32);
  offset += 32;

  // name (VLI-prefixed)
  let vli = readVLI(buffer, offset);
  offset += vli.bytesRead;
  if (offset + vli.value > buffer.length) throw new Error('v2: invalid name length');
  const name = decoder.decode(buffer.slice(offset, offset + vli.value));
  offset += vli.value;

  // description (VLI-prefixed)
  vli = readVLI(buffer, offset);
  offset += vli.bytesRead;
  if (offset + vli.value > buffer.length) throw new Error('v2: invalid description length');
  const description = decoder.decode(buffer.slice(offset, offset + vli.value));
  offset += vli.value;

  // admin_pubkeys (VLI outer container + VLI-prefixed items)
  vli = readVLI(buffer, offset);
  offset += vli.bytesRead;
  const adminEndOffset = offset + vli.value;
  if (adminEndOffset > buffer.length) throw new Error('v2: invalid admin_pubkeys container length');
  const adminPubkeys: string[] = [];
  while (offset < adminEndOffset) {
    const itemVli = readVLI(buffer, offset);
    offset += itemVli.bytesRead;
    if (offset + itemVli.value > buffer.length) throw new Error('v2: invalid admin pubkey item length');
    const pubkey = decoder.decode(buffer.slice(offset, offset + itemVli.value));
    adminPubkeys.push(pubkey);
    offset += itemVli.value;
  }

  // relays (VLI outer container + VLI-prefixed items)
  vli = readVLI(buffer, offset);
  offset += vli.bytesRead;
  const relayEndOffset = offset + vli.value;
  if (relayEndOffset > buffer.length) throw new Error('v2: invalid relays container length');
  const relays: string[] = [];
  while (offset < relayEndOffset) {
    const itemVli = readVLI(buffer, offset);
    offset += itemVli.bytesRead;
    if (offset + itemVli.value > buffer.length) throw new Error('v2: invalid relay item length');
    const relay = decoder.decode(buffer.slice(offset, offset + itemVli.value));
    relays.push(relay);
    offset += itemVli.value;
  }

  // image_hash (VLI-prefixed, may be empty)
  vli = readVLI(buffer, offset);
  offset += vli.bytesRead;
  if (offset + vli.value > buffer.length) throw new Error('v2: invalid image_hash length');
  const imageHash = vli.value === 0 ? new Uint8Array(0) : buffer.slice(offset, offset + vli.value);
  offset += vli.value;

  // image_key (VLI-prefixed, may be empty)
  vli = readVLI(buffer, offset);
  offset += vli.bytesRead;
  if (offset + vli.value > buffer.length) throw new Error('v2: invalid image_key length');
  const imageKey = vli.value === 0 ? new Uint8Array(0) : buffer.slice(offset, offset + vli.value);
  offset += vli.value;

  // image_nonce (VLI-prefixed, may be empty)
  vli = readVLI(buffer, offset);
  offset += vli.bytesRead;
  if (offset + vli.value > buffer.length) throw new Error('v2: invalid image_nonce length');
  const imageNonce = vli.value === 0 ? new Uint8Array(0) : buffer.slice(offset, offset + vli.value);
  offset += vli.value;

  // image_upload_key (VLI-prefixed, may be empty, v2 only)
  let imageUploadKey: Uint8Array | undefined;
  if (offset < buffer.length) {
    vli = readVLI(buffer, offset);
    offset += vli.bytesRead;
    if (offset + vli.value > buffer.length) throw new Error('v2: invalid image_upload_key length');
    imageUploadKey = vli.value === 0 ? undefined : buffer.slice(offset, offset + vli.value);
  }

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
    imageUploadKey,
  };
}

/**
 * Deserialize Marmot Group Data from TLS presentation language format.
 * Auto-detects version and routes to appropriate deserializer.
 */
export function deserializeMarmotGroupData(buffer: Uint8Array): MarmotGroupData {
  // Read version to determine format
  if (buffer.length < 2) {
    throw new Error('Buffer too short to read version');
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const version = view.getUint16(0, false);

  if (version === 1) {
    // v1: use uint16 BE length prefixes, minimum size check applies
    if (buffer.length < MARMOT_GROUP_DATA_MIN_SIZE) {
      throw new Error(
        `Buffer too small for v1: ${buffer.length} bytes (minimum ${MARMOT_GROUP_DATA_MIN_SIZE})`
      );
    }
    return deserializeMarmotGroupDataV1(buffer);
  } else if (version === 2) {
    // v2: use VLI encoding, no minimum size requirement (image fields can be empty)
    return deserializeMarmotGroupDataV2(buffer);
  } else {
    throw new Error(`Unsupported version: ${version}`);
  }
}

/**
 * Deserialize Marmot Group Data from TLS presentation language format (v1).
 * Uses uint16 BE length prefixes.
 */
function deserializeMarmotGroupDataV1(buffer: Uint8Array): MarmotGroupData {
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

  // v1: image fields must be exactly the specified size
  // v2: image fields can be empty (0 bytes) or the specified size
  if (data.version === 1) {
    if (data.imageHash.length !== 32) {
      throw new Error(`image_hash must be 32 bytes, got ${data.imageHash.length}`);
    }
    if (data.imageKey.length !== 32) {
      throw new Error(`image_key must be 32 bytes, got ${data.imageKey.length}`);
    }
    if (data.imageNonce.length !== 12) {
      throw new Error(`image_nonce must be 12 bytes, got ${data.imageNonce.length}`);
    }
  } else {
    // v2+: allow empty or correct size
    if (data.imageHash.length !== 0 && data.imageHash.length !== 32) {
      throw new Error(`image_hash must be 0 or 32 bytes, got ${data.imageHash.length}`);
    }
    if (data.imageKey.length !== 0 && data.imageKey.length !== 32) {
      throw new Error(`image_key must be 0 or 32 bytes, got ${data.imageKey.length}`);
    }
    if (data.imageNonce.length !== 0 && data.imageNonce.length !== 12) {
      throw new Error(`image_nonce must be 0 or 12 bytes, got ${data.imageNonce.length}`);
    }
  }

  // imageUploadKey is optional (v2 only)
  if (data.imageUploadKey !== undefined) {
    if (data.version < 2) {
      throw new Error('imageUploadKey is only supported in version 2+');
    }
    if (data.imageUploadKey.length !== 0 && data.imageUploadKey.length !== 32) {
      throw new Error(`imageUploadKey must be 0 or 32 bytes, got ${data.imageUploadKey.length}`);
    }
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
 * Handles both v1 (uint16 BE) and v2 (VLI) encoding.
 */
export function validateStructure(data: Uint8Array): boolean {
  if (data.length < 2) return false;

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const version = view.getUint16(0, false);

  if (version === 1) {
    return validateStructureV1(data);
  } else if (version === 2) {
    return validateStructureV2(data);
  } else {
    return false; // Unknown version
  }
}

/**
 * Validate v1 structure (uint16 BE length prefixes).
 */
function validateStructureV1(data: Uint8Array): boolean {
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

/**
 * Validate v2 structure (VLI length prefixes).
 */
function validateStructureV2(data: Uint8Array): boolean {
  try {
    let offset = 2 + 32; // Skip version and nostr_group_id

    // name (VLI-prefixed)
    let vli = readVLI(data, offset);
    offset += vli.bytesRead + vli.value;
    if (offset > data.length) return false;

    // description (VLI-prefixed)
    vli = readVLI(data, offset);
    offset += vli.bytesRead + vli.value;
    if (offset > data.length) return false;

    // admin_pubkeys (VLI outer container)
    vli = readVLI(data, offset);
    offset += vli.bytesRead + vli.value;
    if (offset > data.length) return false;

    // relays (VLI outer container)
    vli = readVLI(data, offset);
    offset += vli.bytesRead + vli.value;
    if (offset > data.length) return false;

    // image_hash (VLI-prefixed)
    vli = readVLI(data, offset);
    offset += vli.bytesRead + vli.value;
    if (offset > data.length) return false;

    // image_key (VLI-prefixed)
    vli = readVLI(data, offset);
    offset += vli.bytesRead + vli.value;
    if (offset > data.length) return false;

    // image_nonce (VLI-prefixed)
    vli = readVLI(data, offset);
    offset += vli.bytesRead + vli.value;
    if (offset > data.length) return false;

    // image_upload_key (VLI-prefixed, optional)
    if (offset < data.length) {
      vli = readVLI(data, offset);
      offset += vli.bytesRead + vli.value;
    }

    // Should consume entire buffer
    return offset === data.length;
  } catch {
    return false;
  }
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
