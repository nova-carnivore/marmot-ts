/**
 * MIP-00: Credentials & Key Packages
 *
 * KeyPackage event creation (kind: 443), credential validation,
 * encoding support, and KeyPackage lifecycle management.
 */

import type {
  KeyPackageOptions,
  ParsedKeyPackage,
  KeyPackageRelayList,
  SignedEvent,
  UnsignedEvent,
  ContentEncoding,
} from './types.js';
import { MARMOT_EVENT_KINDS, MLS_EXTENSION_TYPES } from './types.js';
import {
  encodeContent,
  decodeContent,
  detectEncoding,
  isValidPubkey,
  isValidRelayUrl,
  formatExtensionId,
  parseExtensionId,
  isNonDefaultExtension,
  getTagValue,
  getTagValues,
  unixTimestamp,
} from './utils.js';
import type { MarmotSigner } from './signer.js';

// ─── KeyPackage Event Creation ──────────────────────────────────────────────

/**
 * Create an unsigned KeyPackage event (kind: 443).
 *
 * @param pubkey - Nostr public key (hex-encoded)
 * @param options - KeyPackage configuration
 * @returns Unsigned Nostr event ready for signing
 */
export function createKeyPackageEvent(
  pubkey: string,
  options: KeyPackageOptions
): UnsignedEvent {
  if (!isValidPubkey(pubkey)) {
    throw new Error(`Invalid Nostr pubkey: ${pubkey}`);
  }

  const encoding: ContentEncoding = options.encoding ?? 'base64';
  const content = encodeContent(options.keyPackageData, encoding);

  // Build extension list - MUST include marmot_group_data and last_resort
  const extensions = new Set(options.extensions ?? []);
  extensions.add(MLS_EXTENSION_TYPES.MARMOT_GROUP_DATA); // 0xf2ee
  extensions.add(MLS_EXTENSION_TYPES.LAST_RESORT); // 0x000a

  // Filter out default extensions (MUST NOT be listed)
  const nonDefaultExtensions = [...extensions].filter(isNonDefaultExtension);

  // Validate relay URLs
  for (const relay of options.relays) {
    if (!isValidRelayUrl(relay)) {
      throw new Error(`Invalid relay URL: ${relay}`);
    }
  }

  const tags: string[][] = [
    ['mls_protocol_version', options.protocolVersion ?? '1.0'],
    ['mls_ciphersuite', options.ciphersuite],
    ['mls_extensions', ...nonDefaultExtensions.map(formatExtensionId)],
    ['encoding', encoding],
    ['relays', ...options.relays],
  ];

  if (options.clientName) {
    tags.push(['client', options.clientName]);
  }

  // NIP-70 protected tag (default: true)
  if (options.protected !== false) {
    tags.push(['-']);
  }

  return {
    kind: MARMOT_EVENT_KINDS.KEY_PACKAGE,
    created_at: unixTimestamp(),
    pubkey,
    content,
    tags,
  };
}

/**
 * Create and sign a KeyPackage event.
 */
export async function createSignedKeyPackageEvent(
  signer: MarmotSigner,
  options: KeyPackageOptions
): Promise<SignedEvent> {
  const pubkey = await signer.getPublicKey();
  const event = createKeyPackageEvent(pubkey, options);
  return signer.signEvent(event);
}

// ─── KeyPackage Event Parsing ───────────────────────────────────────────────

/**
 * Parse a KeyPackage event (kind: 443).
 *
 * @param event - Signed Nostr event
 * @returns Parsed KeyPackage data
 * @throws If the event is invalid or missing required fields
 */
export function parseKeyPackageEvent(
  event: SignedEvent | UnsignedEvent
): ParsedKeyPackage {
  if (event.kind !== MARMOT_EVENT_KINDS.KEY_PACKAGE) {
    throw new Error(`Expected kind ${MARMOT_EVENT_KINDS.KEY_PACKAGE}, got ${event.kind}`);
  }

  if (!isValidPubkey(event.pubkey)) {
    throw new Error(`Invalid pubkey in KeyPackage event: ${event.pubkey}`);
  }

  const encoding = detectEncoding(event.tags);
  const keyPackageData = decodeContent(event.content, encoding);

  const protocolVersion = getTagValue(event.tags, 'mls_protocol_version');
  if (!protocolVersion) {
    throw new Error('Missing mls_protocol_version tag');
  }

  const ciphersuite = getTagValue(event.tags, 'mls_ciphersuite');
  if (!ciphersuite) {
    throw new Error('Missing mls_ciphersuite tag');
  }

  const extensionStrings = getTagValues(event.tags, 'mls_extensions');
  const extensions = extensionStrings.map(parseExtensionId);

  const relays = getTagValues(event.tags, 'relays');
  const clientName = getTagValue(event.tags, 'client');

  return {
    eventId: event.id ?? '',
    pubkey: event.pubkey,
    keyPackageData,
    protocolVersion,
    ciphersuite,
    extensions,
    encoding,
    clientName,
    relays,
    createdAt: event.created_at,
  };
}

// ─── Credential Validation ──────────────────────────────────────────────────

/**
 * Validate that an MLS credential identity matches the Nostr pubkey.
 *
 * CRITICAL: The MLS identity field MUST contain the raw 32-byte public key,
 * NOT the hex-encoded string.
 *
 * @param credentialIdentity - Raw bytes from MLS credential identity field
 * @param nostrPubkey - Hex-encoded Nostr public key
 * @returns true if valid
 */
export function validateCredentialIdentity(
  credentialIdentity: Uint8Array,
  nostrPubkey: string
): boolean {
  if (credentialIdentity.length !== 32) {
    return false;
  }
  if (!isValidPubkey(nostrPubkey)) {
    return false;
  }
  // Compare raw bytes to hex-decoded pubkey
  const pubkeyBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    pubkeyBytes[i] = parseInt(nostrPubkey.substring(i * 2, i * 2 + 2), 16);
  }
  for (let i = 0; i < 32; i++) {
    if (credentialIdentity[i] !== pubkeyBytes[i]) return false;
  }
  return true;
}

/**
 * Convert a hex-encoded Nostr pubkey to raw 32-byte identity for MLS credentials.
 */
export function pubkeyToCredentialIdentity(nostrPubkey: string): Uint8Array {
  if (!isValidPubkey(nostrPubkey)) {
    throw new Error(`Invalid Nostr pubkey: ${nostrPubkey}`);
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(nostrPubkey.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ─── KeyPackage Compatibility ───────────────────────────────────────────────

/**
 * Check if a KeyPackage is compatible with a target ciphersuite and extensions.
 */
export function isKeyPackageCompatible(
  keyPackage: ParsedKeyPackage,
  targetCiphersuite: string,
  requiredExtensions: number[] = []
): boolean {
  if (keyPackage.ciphersuite !== targetCiphersuite) {
    return false;
  }
  for (const ext of requiredExtensions) {
    if (!keyPackage.extensions.includes(ext)) {
      return false;
    }
  }
  return true;
}

/**
 * Check if a KeyPackage has the required Marmot extensions.
 * MUST include marmot_group_data (0xf2ee) and last_resort (0x000a).
 */
export function hasRequiredMarmotExtensions(keyPackage: ParsedKeyPackage): boolean {
  return (
    keyPackage.extensions.includes(MLS_EXTENSION_TYPES.MARMOT_GROUP_DATA) &&
    keyPackage.extensions.includes(MLS_EXTENSION_TYPES.LAST_RESORT)
  );
}

// ─── KeyPackage Relay List ──────────────────────────────────────────────────

/**
 * Create a KeyPackage relay list event (kind: 10051).
 */
export function createKeyPackageRelayListEvent(
  pubkey: string,
  relays: string[]
): UnsignedEvent {
  if (!isValidPubkey(pubkey)) {
    throw new Error(`Invalid Nostr pubkey: ${pubkey}`);
  }
  for (const relay of relays) {
    if (!isValidRelayUrl(relay)) {
      throw new Error(`Invalid relay URL: ${relay}`);
    }
  }

  return {
    kind: MARMOT_EVENT_KINDS.KEY_PACKAGE_RELAY_LIST,
    created_at: unixTimestamp(),
    pubkey,
    content: '',
    tags: relays.map((r) => ['relay', r]),
  };
}

/**
 * Parse a KeyPackage relay list event (kind: 10051).
 */
export function parseKeyPackageRelayList(
  event: SignedEvent | UnsignedEvent
): KeyPackageRelayList {
  if (event.kind !== MARMOT_EVENT_KINDS.KEY_PACKAGE_RELAY_LIST) {
    throw new Error(
      `Expected kind ${MARMOT_EVENT_KINDS.KEY_PACKAGE_RELAY_LIST}, got ${event.kind}`
    );
  }
  const relays = event.tags.filter((t) => t[0] === 'relay' && t[1]).map((t) => t[1]!);
  return { relays };
}

// ─── KeyPackage Deletion ────────────────────────────────────────────────────

/**
 * Create a deletion event for a KeyPackage (NIP-09).
 *
 * @param pubkey - Nostr public key
 * @param eventIds - IDs of KeyPackage events to delete
 * @returns Unsigned deletion event
 */
export function createKeyPackageDeletionEvent(
  pubkey: string,
  eventIds: string[]
): UnsignedEvent {
  if (!isValidPubkey(pubkey)) {
    throw new Error(`Invalid Nostr pubkey: ${pubkey}`);
  }
  if (eventIds.length === 0) {
    throw new Error('Must specify at least one event ID to delete');
  }

  return {
    kind: 5, // NIP-09 deletion
    created_at: unixTimestamp(),
    pubkey,
    content: 'KeyPackage consumed',
    tags: [
      ...eventIds.map((id) => ['e', id]),
      ['k', String(MARMOT_EVENT_KINDS.KEY_PACKAGE)],
    ],
  };
}
