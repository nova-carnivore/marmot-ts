/**
 * MIP-04: Encrypted Media
 *
 * Media encryption using ChaCha20-Poly1305 with keys derived from
 * MLS exporter secrets. Content-addressed storage via Blossom.
 */

import type {
  EncryptedMediaMeta,
  EncryptMediaOptions,
  EncryptedMediaResult,
  DecryptMediaOptions,
} from './types.js';
import { MEDIA_VERSION, MEDIA_VERSION_DEPRECATED } from './types.js';
import { randomBytes, concatBytes, canonicalizeMimeType, bytesToHex } from './utils.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import {
  sha256Hash,
  sha256Hex,
  hkdfExpand,
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
} from './crypto.js';

// ─── Key Derivation ─────────────────────────────────────────────────────────

/**
 * Build the HKDF info/context bytes for MIP-04 key derivation.
 *
 * Format: scheme_label || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes || 0x00 || purpose
 */
function buildContext(
  schemeLabel: string,
  fileHash: Uint8Array,
  mimeType: string,
  filename: string,
  purpose: string
): Uint8Array {
  const encoder = new TextEncoder();
  const NULL = new Uint8Array([0]);

  return concatBytes(
    encoder.encode(schemeLabel),
    NULL,
    fileHash,
    NULL,
    encoder.encode(mimeType),
    NULL,
    encoder.encode(filename),
    NULL,
    encoder.encode(purpose)
  );
}

/**
 * Derive the file encryption key from MLS exporter secret (Version 2).
 *
 * file_key = HKDF-Expand(exporter_secret, context || "key", 32)
 */
export function deriveFileKey(
  exporterSecret: Uint8Array,
  fileHash: Uint8Array,
  mimeType: string,
  filename: string
): Uint8Array {
  const canonicalMime = canonicalizeMimeType(mimeType);
  const context = buildContext(MEDIA_VERSION, fileHash, canonicalMime, filename, 'key');
  return hkdfExpand(exporterSecret, context, 32);
}

/**
 * Build AAD (Associated Authenticated Data) for encryption.
 *
 * Format: scheme_label || 0x00 || file_hash_bytes || 0x00 || mime_type_bytes || 0x00 || filename_bytes
 */
function buildAAD(
  schemeLabel: string,
  fileHash: Uint8Array,
  mimeType: string,
  filename: string
): Uint8Array {
  const encoder = new TextEncoder();
  const NULL = new Uint8Array([0]);

  return concatBytes(
    encoder.encode(schemeLabel),
    NULL,
    fileHash,
    NULL,
    encoder.encode(mimeType),
    NULL,
    encoder.encode(filename)
  );
}

// ─── Media Encryption ───────────────────────────────────────────────────────

/**
 * Encrypt media for sharing in a Marmot group (Version 2).
 *
 * Process:
 * 1. Hash the original file for integrity
 * 2. Derive encryption key from exporter secret
 * 3. Generate random nonce (12 bytes)
 * 4. Encrypt with ChaCha20-Poly1305 AEAD
 *
 * @param options - Encryption parameters
 * @returns Encrypted data, metadata, and storage hash
 */
export function encryptMedia(options: EncryptMediaOptions): EncryptedMediaResult {
  const { data, mimeType, filename, exporterSecret } = options;

  if (exporterSecret.length !== 32) {
    throw new Error(`exporter_secret must be 32 bytes, got ${exporterSecret.length}`);
  }

  // Canonicalize MIME type
  const canonicalMime = canonicalizeMimeType(mimeType);

  // Hash original content for integrity
  const fileHashBytes = sha256Hash(data);
  const fileHashHex = bytesToHex(fileHashBytes);

  // Derive encryption key
  const fileKey = deriveFileKey(exporterSecret, fileHashBytes, canonicalMime, filename);

  // Generate random nonce (CRITICAL: must be random for v2)
  const nonce = randomBytes(12);
  const nonceHex = bytesToHex(nonce);

  // Build AAD
  const aad = buildAAD(MEDIA_VERSION, fileHashBytes, canonicalMime, filename);

  // Encrypt with ChaCha20-Poly1305
  const encryptedData = chacha20Poly1305Encrypt(fileKey, nonce, data, aad);

  // Hash encrypted content for storage addressing
  const encryptedHash = sha256Hex(encryptedData);

  const meta: EncryptedMediaMeta = {
    url: '', // To be set after upload
    mimeType: canonicalMime,
    filename,
    fileHash: fileHashHex,
    nonce: nonceHex,
    version: MEDIA_VERSION,
  };

  return { encryptedData, meta, encryptedHash };
}

/**
 * Decrypt media from a Marmot group (Version 2).
 *
 * Process:
 * 1. Verify version is mip04-v2
 * 2. Derive encryption key from exporter secret
 * 3. Extract nonce from metadata
 * 4. Decrypt with ChaCha20-Poly1305 AEAD
 * 5. Verify integrity (SHA-256 of decrypted data matches)
 */
export function decryptMedia(options: DecryptMediaOptions): Uint8Array {
  const { encryptedData, meta, exporterSecret } = options;

  // Version check
  if (meta.version === MEDIA_VERSION_DEPRECATED) {
    throw new Error(
      `Deprecated version ${MEDIA_VERSION_DEPRECATED} MUST NOT be used. ` +
        'This version has known security vulnerabilities (nonce reuse).'
    );
  }

  if (meta.version !== MEDIA_VERSION) {
    throw new Error(
      `Unsupported media version: ${meta.version}. Expected ${MEDIA_VERSION}.`
    );
  }

  if (exporterSecret.length !== 32) {
    throw new Error(`exporter_secret must be 32 bytes, got ${exporterSecret.length}`);
  }

  // Validate nonce
  if (!meta.nonce || meta.nonce.length !== 24) {
    throw new Error('Version 2 requires a nonce field (24 hex characters for 12 bytes)');
  }

  const canonicalMime = canonicalizeMimeType(meta.mimeType);

  // Derive encryption key
  const fileHashBytes = hexToBytes(meta.fileHash);
  const fileKey = deriveFileKey(
    exporterSecret,
    fileHashBytes,
    canonicalMime,
    meta.filename
  );

  // Extract nonce
  const nonce = hexToBytes(meta.nonce);
  if (nonce.length !== 12) {
    throw new Error(`Nonce must be 12 bytes, got ${nonce.length}`);
  }

  // Build AAD
  const aad = buildAAD(MEDIA_VERSION, fileHashBytes, canonicalMime, meta.filename);

  // Decrypt
  const decryptedData = chacha20Poly1305Decrypt(fileKey, nonce, encryptedData, aad);

  // Verify integrity
  const actualHash = sha256Hex(decryptedData);
  if (actualHash !== meta.fileHash) {
    throw new Error(
      `Integrity check failed: expected hash ${meta.fileHash}, got ${actualHash}`
    );
  }

  return decryptedData;
}

// ─── imeta Tag Handling ─────────────────────────────────────────────────────

/**
 * Build an imeta tag array from encrypted media metadata.
 * NIP-92 compliant format.
 */
export function buildImetaTag(meta: EncryptedMediaMeta): string[] {
  const tag = [
    'imeta',
    `url ${meta.url}`,
    `m ${meta.mimeType}`,
    `filename ${meta.filename}`,
    `x ${meta.fileHash}`,
    `n ${meta.nonce}`,
    `v ${meta.version}`,
  ];

  if (meta.dimensions) {
    tag.push(`dim ${meta.dimensions}`);
  }

  if (meta.blurhash) {
    tag.push(`blurhash ${meta.blurhash}`);
  }

  return tag;
}

/**
 * Parse an imeta tag into EncryptedMediaMeta.
 */
export function parseImetaTag(tag: string[]): EncryptedMediaMeta {
  if (tag[0] !== 'imeta') {
    throw new Error('Not an imeta tag');
  }

  const fields: Record<string, string> = {};
  for (let i = 1; i < tag.length; i++) {
    const field = tag[i]!;
    const spaceIndex = field.indexOf(' ');
    if (spaceIndex === -1) continue;
    const key = field.substring(0, spaceIndex);
    const value = field.substring(spaceIndex + 1);
    fields[key] = value;
  }

  const url = fields['url'];
  const mimeType = fields['m'];
  const filename = fields['filename'];
  const fileHash = fields['x'];
  const version = fields['v'];

  if (!url) throw new Error('Missing url in imeta tag');
  if (!mimeType) throw new Error('Missing m (mime type) in imeta tag');
  if (!filename) throw new Error('Missing filename in imeta tag');
  if (!fileHash) throw new Error('Missing x (file hash) in imeta tag');
  if (!version) throw new Error('Missing v (version) in imeta tag');

  // Version 2 requires nonce
  if (version === MEDIA_VERSION) {
    const nonce = fields['n'];
    if (!nonce) {
      throw new Error('Version 2 requires n (nonce) field in imeta tag');
    }
    if (nonce.length !== 24) {
      throw new Error(`Nonce must be 24 hex characters, got ${nonce.length}`);
    }
  }

  // Reject deprecated version
  if (version === MEDIA_VERSION_DEPRECATED) {
    throw new Error(
      `Deprecated version ${MEDIA_VERSION_DEPRECATED} MUST NOT be used. ` +
        'This version has known security vulnerabilities.'
    );
  }

  return {
    url,
    mimeType,
    filename,
    fileHash,
    nonce: fields['n'] ?? '',
    version,
    dimensions: fields['dim'],
    blurhash: fields['blurhash'],
  };
}

// ─── MIME Type Utilities ────────────────────────────────────────────────────

/**
 * Validate that a MIME type is in canonical form.
 */
export function isCanonicalMimeType(mimeType: string): boolean {
  const canonical = canonicalizeMimeType(mimeType);
  return canonical === mimeType;
}

/**
 * Common MIME types for media sharing.
 */
export const COMMON_MIME_TYPES = {
  JPEG: 'image/jpeg',
  PNG: 'image/png',
  GIF: 'image/gif',
  WEBP: 'image/webp',
  MP4: 'video/mp4',
  WEBM: 'video/webm',
  MP3: 'audio/mpeg',
  OGG: 'audio/ogg',
  PDF: 'application/pdf',
} as const;

// ─── Version Utilities ──────────────────────────────────────────────────────

/**
 * Check if a media version is supported.
 */
export function isSupportedVersion(version: string): boolean {
  return version === MEDIA_VERSION;
}

/**
 * Check if a media version is deprecated.
 */
export function isDeprecatedVersion(version: string): boolean {
  return version === MEDIA_VERSION_DEPRECATED;
}
