/**
 * Marmot Protocol Utilities
 *
 * Encoding, validation, and helper functions.
 */

import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import type { ContentEncoding, NostrTag } from './types.js';

// ─── Encoding ───────────────────────────────────────────────────────────────

/**
 * Convert bytes to hex string.
 */
export { bytesToHex, hexToBytes };

/**
 * Encode bytes to base64.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  // Works in both Node.js and browsers
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  // Browser fallback
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/**
 * Decode base64 to bytes.
 */
export function base64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  // Browser fallback
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode bytes using the specified encoding.
 */
export function encodeContent(
  data: Uint8Array,
  encoding: ContentEncoding = 'base64'
): string {
  switch (encoding) {
    case 'base64':
      return bytesToBase64(data);
    case 'hex':
      return bytesToHex(data);
    default:
      throw new Error(`Unsupported encoding: ${encoding as string}`);
  }
}

/**
 * Decode content using the specified encoding.
 */
export function decodeContent(
  content: string,
  encoding: ContentEncoding = 'base64'
): Uint8Array {
  switch (encoding) {
    case 'base64':
      return base64ToBytes(content);
    case 'hex':
      return hexToBytes(content);
    default:
      throw new Error(`Unsupported encoding: ${encoding as string}`);
  }
}

/**
 * Detect encoding from event tags.
 * If "encoding" tag is "base64", returns "base64".
 * If "encoding" tag is "hex" or absent, returns "hex".
 */
export function detectEncoding(tags: NostrTag[]): ContentEncoding {
  const encodingTag = tags.find((t) => t[0] === 'encoding');
  if (encodingTag?.[1] === 'base64') return 'base64';
  return 'hex';
}

// ─── Validation ─────────────────────────────────────────────────────────────

/**
 * Validate a hex-encoded public key (64 hex chars = 32 bytes).
 */
export function isValidPubkey(pubkey: string): boolean {
  return /^[0-9a-f]{64}$/.test(pubkey);
}

/**
 * Validate a WebSocket URL.
 */
export function isValidRelayUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'ws:' || parsed.protocol === 'wss:';
  } catch {
    return false;
  }
}

/**
 * Validate a hex string of specified byte length.
 */
export function isValidHex(hex: string, byteLength?: number): boolean {
  if (!/^[0-9a-f]+$/.test(hex)) return false;
  if (byteLength !== undefined && hex.length !== byteLength * 2) return false;
  return true;
}

/**
 * Validate an MLS extension type ID (not a default extension).
 */
export function isNonDefaultExtension(extensionId: number): boolean {
  const defaultExtensions = [0x0001, 0x0002, 0x0003, 0x0004, 0x0005];
  return !defaultExtensions.includes(extensionId);
}

/**
 * Format an extension ID as hex string (e.g., 0xf2ee).
 */
export function formatExtensionId(id: number): string {
  return '0x' + id.toString(16).padStart(4, '0');
}

/**
 * Parse an extension ID from hex string (e.g., "0xf2ee" or "0xF2EE").
 */
export function parseExtensionId(hex: string): number {
  const normalized = hex.toLowerCase().replace(/^0x/, '');
  const parsed = parseInt(normalized, 16);
  if (isNaN(parsed)) {
    throw new Error(`Invalid extension ID: ${hex}`);
  }
  return parsed;
}

// ─── Tag Helpers ────────────────────────────────────────────────────────────

/**
 * Get the first tag value by tag name.
 */
export function getTagValue(tags: NostrTag[], name: string): string | undefined {
  return tags.find((t) => t[0] === name)?.[1];
}

/**
 * Get all values for a tag (e.g., relays tag has multiple values).
 */
export function getTagValues(tags: NostrTag[], name: string): string[] {
  const tag = tags.find((t) => t[0] === name);
  if (!tag) return [];
  return tag.slice(1);
}

/**
 * Get the current Unix timestamp in seconds.
 */
export function unixTimestamp(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * Compare two Uint8Arrays for equality.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Concatenate multiple Uint8Arrays.
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(length: number): Uint8Array {
  if (typeof globalThis.crypto !== 'undefined') {
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
  }
  // Node.js fallback (should not normally be needed with modern Node)
  throw new Error(
    'No crypto.getRandomValues available. Use Node.js >= 20 or a modern browser.'
  );
}

/**
 * Canonicalize a MIME type for consistent key derivation.
 * Lowercases, trims whitespace, strips parameters.
 */
export function canonicalizeMimeType(mimeType: string): string {
  return mimeType.trim().toLowerCase().split(';')[0]!.trim();
}
