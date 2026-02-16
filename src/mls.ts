/**
 * MLS Runtime Operations
 *
 * Wraps ts-mls to provide protocol-level MLS operations for the Marmot Protocol.
 * Handles ciphersuite management, KeyPackage generation/parsing, group creation,
 * member management, and state serialization.
 *
 * @packageDocumentation
 */

import {
  generateKeyPackage as tsGenerateKeyPackage,
  createGroup as tsCreateGroup,
  joinGroup as tsJoinGroup,
  createCommit as tsCreateCommit,
  mlsExporter,
  encodeGroupState as tsEncodeGroupState,
  decodeGroupState as tsDecodeGroupState,
  encodeMlsMessage,
  decodeMlsMessage,
  getCiphersuiteImpl as tsGetCiphersuiteImpl,
  getCiphersuiteFromName,
  ciphersuites as tsCiphersuites,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
} from 'ts-mls';

import { defaultClientConfig } from 'ts-mls/clientConfig.js';

// Import encode/decode for KeyPackage and Welcome from subpaths
import {
  encodeKeyPackage as tsEncodeKeyPackage,
  decodeKeyPackage as tsDecodeKeyPackage,
} from 'ts-mls/keyPackage.js';

import {
  encodeWelcome as tsEncodeWelcome,
  decodeWelcome as tsDecodeWelcome,
} from 'ts-mls/welcome.js';

import type {
  CiphersuiteName,
  CiphersuiteImpl,
  KeyPackage as TsKeyPackage,
  PrivateKeyPackage as TsPrivateKeyPackage,
  ClientState,
  GroupState,
  Welcome as TsWelcome,
  MLSMessage,
  Credential,
  ProposalAdd,
} from 'ts-mls';

import type { ParsedKeyPackage, SignedEvent, UnsignedEvent } from './types.js';
import { parseKeyPackageEvent } from './mip00.js';

// ─── Constants ──────────────────────────────────────────────────────────────

/**
 * Default MLS ciphersuite used by all known Marmot clients.
 * 0x0001 — AES-128-GCM + Ed25519
 */
export const DEFAULT_CIPHERSUITE: CiphersuiteName =
  'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';

/**
 * Marmot exporter secret label.
 */
const EXPORTER_LABEL = 'marmot-exporter-secret';

/**
 * Exporter secret length in bytes.
 */
const EXPORTER_LENGTH = 32;

// ─── Ciphersuite Management ────────────────────────────────────────────────

/** Cache for CiphersuiteImpl instances */
const ciphersuiteCache = new Map<CiphersuiteName, CiphersuiteImpl>();

/**
 * Get a CiphersuiteImpl, lazily initializing and caching.
 *
 * @param name - Ciphersuite name
 * @returns The CiphersuiteImpl
 */
export async function getCiphersuiteImpl(
  name: CiphersuiteName = DEFAULT_CIPHERSUITE
): Promise<CiphersuiteImpl> {
  const cached = ciphersuiteCache.get(name);
  if (cached) return cached;

  const cs = getCiphersuiteFromName(name);
  const impl = await tsGetCiphersuiteImpl(cs);
  ciphersuiteCache.set(name, impl);
  return impl;
}

/**
 * Get all supported ciphersuite names.
 */
export function getSupportedCiphersuites(): CiphersuiteName[] {
  return Object.keys(tsCiphersuites) as CiphersuiteName[];
}

/**
 * Convert a ciphersuite name to its numeric ID.
 *
 * @param name - Ciphersuite name
 * @returns Numeric ID (e.g. 1 for MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
 */
export function ciphersuiteNameToId(name: CiphersuiteName): number {
  const id = tsCiphersuites[name];
  if (id === undefined) {
    throw new Error(`Unknown ciphersuite: ${name}`);
  }
  return id;
}

/**
 * Convert a numeric ciphersuite ID to its name.
 *
 * @param id - Numeric ciphersuite ID
 * @returns Ciphersuite name
 */
export function ciphersuiteIdToName(id: number): CiphersuiteName {
  for (const [name, value] of Object.entries(tsCiphersuites)) {
    if (value === id) return name as CiphersuiteName;
  }
  throw new Error(`Unknown ciphersuite ID: ${id}`);
}

// ─── KeyPackage Generation ──────────────────────────────────────────────────

/**
 * Result of generating an MLS KeyPackage.
 */
export interface GeneratedKeyPackage {
  /** Raw TLS-encoded KeyPackage bytes (NOT MLSMessage-wrapped) */
  keyPackageBytes: Uint8Array;
  /** The ts-mls KeyPackage object */
  keyPackage: TsKeyPackage;
  /** Private keys associated with this KeyPackage */
  privateKeyPackage: TsPrivateKeyPackage;
}

/**
 * Generate a real MLS KeyPackage via ts-mls.
 *
 * The identity is the raw 32-byte Nostr public key.
 * The output keyPackageBytes are in RAW KeyPackage format (NOT MLSMessage-wrapped),
 * matching what marmot-cli, MDK, and marmot-chat all use.
 *
 * @param identity - Nostr pubkey hex (64 chars)
 * @param ciphersuite - Ciphersuite name (default: DEFAULT_CIPHERSUITE)
 * @returns Generated KeyPackage with raw bytes and private keys
 */
export async function generateMlsKeyPackage(
  identity: string,
  ciphersuite: CiphersuiteName = DEFAULT_CIPHERSUITE
): Promise<GeneratedKeyPackage> {
  if (identity.length !== 64 || !/^[0-9a-f]+$/i.test(identity)) {
    throw new Error(`Invalid Nostr pubkey hex: ${identity}`);
  }

  const cs = await getCiphersuiteImpl(ciphersuite);

  // Convert hex pubkey to raw 32-byte identity
  const identityBytes = hexToBytes(identity);

  const credential: Credential = {
    credentialType: 'basic',
    identity: identityBytes,
  };

  const { publicPackage, privatePackage } = await tsGenerateKeyPackage(
    credential,
    defaultCapabilities(),
    defaultLifetime,
    [], // extensions
    cs,
  );

  // Encode as raw KeyPackage (NOT MLSMessage-wrapped)
  const keyPackageBytes = tsEncodeKeyPackage(publicPackage);

  return {
    keyPackageBytes,
    keyPackage: publicPackage,
    privateKeyPackage: privatePackage,
  };
}

// ─── KeyPackage Parsing ─────────────────────────────────────────────────────

/**
 * Parse raw TLS-encoded KeyPackage bytes.
 *
 * Detects and handles both formats:
 * - Raw KeyPackage: starts with version (0x0001) + ciphersuite
 * - MLSMessage-wrapped: starts with 0x0001 0x0005 (version + wireformat=mls_key_package)
 *
 * @param bytes - Raw or MLSMessage-wrapped KeyPackage bytes
 * @returns The ts-mls KeyPackage object
 */
export function parseKeyPackageBytes(bytes: Uint8Array): TsKeyPackage {
  if (bytes.length < 4) {
    throw new Error('KeyPackage data too short');
  }

  // Check for OpenMLS format (starts with 0xd34d) - not supported
  if (bytes[0] === 0xd3 && bytes[1] === 0x4d) {
    throw new Error('OpenMLS format (0xd34d) is not supported; use standard TLS encoding');
  }

  // Check version: must be 0x0001 (mls10)
  if (bytes[0] !== 0x00 || bytes[1] !== 0x01) {
    throw new Error(
      `Unknown KeyPackage format: expected version 0x0001, got 0x${bytes[0]!.toString(16).padStart(2, '0')}${bytes[1]!.toString(16).padStart(2, '0')}`
    );
  }

  // Check if MLSMessage-wrapped (wireformat 0x0005 = mls_key_package)
  if (bytes[2] === 0x00 && bytes[3] === 0x05) {
    // MLSMessage-wrapped: strip the 4-byte header (version + wireformat) and parse body
    const innerBytes = bytes.slice(4);
    const result = tsDecodeKeyPackage(innerBytes, 0);
    if (!result) {
      throw new Error('Failed to decode MLSMessage-wrapped KeyPackage');
    }
    return result[0];
  }

  // Raw KeyPackage: parse directly
  const result = tsDecodeKeyPackage(bytes, 0);
  if (!result) {
    throw new Error('Failed to decode raw KeyPackage');
  }
  return result[0];
}

// ─── KeyPackage from Nostr Event ────────────────────────────────────────────

/**
 * Result of parsing a KeyPackage from a Nostr event.
 */
export interface ParsedKeyPackageFromEvent {
  /** Parsed Nostr event data (encoding, tags, etc.) */
  parsed: ParsedKeyPackage;
  /** Parsed ts-mls KeyPackage object */
  mlsKeyPackage: TsKeyPackage;
}

/**
 * Parse a KeyPackage from a kind:443 Nostr event.
 *
 * Combines mip00.ts parseKeyPackageEvent() with MLS wire format parsing.
 * Handles both base64 and hex encoded content, and both raw and
 * MLSMessage-wrapped KeyPackage formats.
 *
 * @param event - A signed or unsigned kind:443 Nostr event
 * @returns Parsed Nostr event data + ts-mls KeyPackage
 */
export function parseKeyPackageFromEvent(
  event: SignedEvent | UnsignedEvent
): ParsedKeyPackageFromEvent {
  const parsed = parseKeyPackageEvent(event);
  const mlsKeyPackage = parseKeyPackageBytes(parsed.keyPackageData);
  return { parsed, mlsKeyPackage };
}

// ─── Group Creation ─────────────────────────────────────────────────────────

/**
 * Result of creating an MLS group.
 */
export interface MlsGroupResult {
  /** The MLS group state */
  state: ClientState;
  /** Encoded state for persistence */
  encodedState: Uint8Array;
  /** Group ID */
  groupId: Uint8Array;
  /** Marmot exporter secret (32 bytes) */
  exporterSecret: Uint8Array;
}

/**
 * Create a new MLS group.
 *
 * @param groupId - Group identifier bytes
 * @param identity - Nostr pubkey hex (64 chars)
 * @param ciphersuite - Ciphersuite name (default: DEFAULT_CIPHERSUITE)
 * @returns Group state, encoded state, group ID, and exporter secret
 */
export async function createMlsGroup(
  groupId: Uint8Array,
  identity: string,
  ciphersuite: CiphersuiteName = DEFAULT_CIPHERSUITE
): Promise<MlsGroupResult> {
  const cs = await getCiphersuiteImpl(ciphersuite);

  // Generate a KeyPackage for the group creator
  const { keyPackage, privateKeyPackage } = await generateMlsKeyPackage(
    identity,
    ciphersuite
  );

  const state = await tsCreateGroup(
    groupId,
    keyPackage,
    privateKeyPackage,
    [], // extensions
    cs,
  );

  const encodedState = tsEncodeGroupState(state);
  const exporterSecret = await deriveExporterSecret(state, ciphersuite);

  return {
    state,
    encodedState,
    groupId,
    exporterSecret,
  };
}

// ─── Adding Members ─────────────────────────────────────────────────────────

/**
 * Result of adding members to an MLS group.
 */
export interface AddMembersResult {
  /** Updated group state */
  newState: ClientState;
  /** Welcome message for new members */
  welcome: TsWelcome;
  /** Commit message */
  commit: MLSMessage;
  /** Encoded new state for persistence */
  encodedState: Uint8Array;
  /** New exporter secret after state change */
  exporterSecret: Uint8Array;
}

/**
 * Add members to an MLS group via Add proposals + Commit.
 *
 * @param state - Current group state
 * @param memberKeyPackages - KeyPackages of members to add
 * @param ciphersuite - Ciphersuite name (default: DEFAULT_CIPHERSUITE)
 * @returns New state, Welcome, Commit, and exporter secret
 */
export async function addMlsGroupMembers(
  state: ClientState,
  memberKeyPackages: TsKeyPackage[],
  ciphersuite: CiphersuiteName = DEFAULT_CIPHERSUITE
): Promise<AddMembersResult> {
  const cs = await getCiphersuiteImpl(ciphersuite);

  // Build Add proposals
  const extraProposals: ProposalAdd[] = memberKeyPackages.map((kp) => ({
    proposalType: 'add' as const,
    add: { keyPackage: kp },
  }));

  const result = await tsCreateCommit(
    { state, cipherSuite: cs },
    {
      extraProposals,
      ratchetTreeExtension: true,
    },
  );

  if (!result.welcome) {
    throw new Error('Expected Welcome message when adding members');
  }

  const encodedState = tsEncodeGroupState(result.newState);
  const exporterSecret = await deriveExporterSecret(result.newState, ciphersuite);

  return {
    newState: result.newState,
    welcome: result.welcome,
    commit: result.commit,
    encodedState,
    exporterSecret,
  };
}

// ─── Joining from Welcome ───────────────────────────────────────────────────

/**
 * Result of joining a group from a Welcome message.
 */
export interface JoinGroupResult {
  /** The MLS group state */
  state: ClientState;
  /** Encoded state for persistence */
  encodedState: Uint8Array;
  /** Marmot exporter secret (32 bytes) */
  exporterSecret: Uint8Array;
  /** Group ID from the joined group */
  groupId: Uint8Array;
}

/**
 * Join an MLS group from a Welcome message.
 *
 * @param welcome - The Welcome message
 * @param keyPackage - The KeyPackage that was used in the invitation
 * @param privateKeyPackage - Private keys for the KeyPackage
 * @param ciphersuite - Ciphersuite name (default: DEFAULT_CIPHERSUITE)
 * @returns Group state, encoded state, exporter secret, and group ID
 */
export async function joinMlsGroupFromWelcome(
  welcome: TsWelcome,
  keyPackage: TsKeyPackage,
  privateKeyPackage: TsPrivateKeyPackage,
  ciphersuite: CiphersuiteName = DEFAULT_CIPHERSUITE
): Promise<JoinGroupResult> {
  const cs = await getCiphersuiteImpl(ciphersuite);

  const state = await tsJoinGroup(
    welcome,
    keyPackage,
    privateKeyPackage,
    emptyPskIndex,
    cs,
  );

  const encodedState = tsEncodeGroupState(state);
  const exporterSecret = await deriveExporterSecret(state, ciphersuite);
  const groupId = state.groupContext.groupId;

  return {
    state,
    encodedState,
    exporterSecret,
    groupId,
  };
}

// ─── Exporter Secret ────────────────────────────────────────────────────────

/**
 * Derive the Marmot exporter secret from MLS state.
 *
 * Uses label 'marmot-exporter-secret', empty context, length 32.
 *
 * @param state - MLS group state
 * @param ciphersuite - Ciphersuite name (default: DEFAULT_CIPHERSUITE)
 * @returns 32-byte exporter secret
 */
export async function deriveExporterSecret(
  state: ClientState,
  ciphersuite: CiphersuiteName = DEFAULT_CIPHERSUITE
): Promise<Uint8Array> {
  const cs = await getCiphersuiteImpl(ciphersuite);
  return mlsExporter(
    state.keySchedule.exporterSecret,
    EXPORTER_LABEL,
    new Uint8Array(0),
    EXPORTER_LENGTH,
    cs,
  );
}

// ─── State Serialization ────────────────────────────────────────────────────

/**
 * Encode MLS group state for persistence.
 */
export function encodeMlsState(state: GroupState): Uint8Array {
  return tsEncodeGroupState(state);
}

/**
 * Decode MLS group state from persisted bytes.
 */
export function decodeMlsState(bytes: Uint8Array): GroupState {
  const result = tsDecodeGroupState(bytes, 0);
  if (!result) {
    throw new Error('Failed to decode MLS group state');
  }
  return result[0];
}

/**
 * Encode a Welcome message to MLSMessage-wrapped wire format.
 *
 * Per MIP-02, Welcome content in kind:444 events is a serialized MLSMessage
 * containing the Welcome object (NOT raw Welcome bytes).
 *
 * Wire format: version (0x0001) + wireformat (0x0003 = mls_welcome) + welcome body
 */
export function encodeWelcome(welcome: TsWelcome): Uint8Array {
  return encodeMlsMessage({
    version: 'mls10',
    wireformat: 'mls_welcome',
    welcome,
  });
}

/**
 * Decode a Welcome message from wire format.
 *
 * Per MIP-02, expects MLSMessage-wrapped Welcome (starts with 0x0001 0x0003).
 * Falls back to raw Welcome decoding for compatibility.
 */
export function decodeWelcome(bytes: Uint8Array): TsWelcome {
  if (bytes.length < 4) {
    throw new Error('Welcome data too short');
  }

  // Try MLSMessage-wrapped first (expected per MIP-02)
  // MLSMessage starts with version 0x0001, then wireformat
  if (bytes[0] === 0x00 && bytes[1] === 0x01) {
    const mlsResult = decodeMlsMessage(bytes, 0);
    if (mlsResult) {
      const [msg] = mlsResult;
      if (msg.wireformat === 'mls_welcome') {
        return msg.welcome;
      }
      throw new Error(
        `Expected MLSMessage with wireformat mls_welcome, got ${msg.wireformat}`
      );
    }
  }

  // Fallback: try raw Welcome decoding for compatibility
  const rawResult = tsDecodeWelcome(bytes, 0);
  if (!rawResult) {
    throw new Error('Failed to decode Welcome message');
  }
  return rawResult[0];
}

/**
 * Encode a Welcome message to raw TLS wire format (NOT MLSMessage-wrapped).
 *
 * Most callers should use `encodeWelcome()` which produces the MLSMessage-wrapped
 * format required by MIP-02. This raw variant is for advanced/internal use only.
 */
export function encodeWelcomeRaw(welcome: TsWelcome): Uint8Array {
  return tsEncodeWelcome(welcome);
}

/**
 * Decode a Welcome message from raw TLS wire format (NOT MLSMessage-wrapped).
 *
 * Most callers should use `decodeWelcome()` which handles the MLSMessage-wrapped
 * format used by MIP-02. This raw variant is for advanced/internal use only.
 */
export function decodeWelcomeRaw(bytes: Uint8Array): TsWelcome {
  const result = tsDecodeWelcome(bytes, 0);
  if (!result) {
    throw new Error('Failed to decode raw Welcome message');
  }
  return result[0];
}

/**
 * Encode a KeyPackage to raw TLS wire format (NOT MLSMessage-wrapped).
 *
 * Per MIP-00, KeyPackage content in kind:443 events uses raw TLS-serialized
 * KeyPackage bytes (NOT MLSMessage-wrapped).
 */
export function encodeKeyPackage(keyPackage: TsKeyPackage): Uint8Array {
  return tsEncodeKeyPackage(keyPackage);
}

/**
 * Decode a KeyPackage from raw TLS wire format.
 * For MLSMessage-wrapped or auto-detection, use parseKeyPackageBytes().
 */
export function decodeKeyPackage(bytes: Uint8Array): TsKeyPackage {
  const result = tsDecodeKeyPackage(bytes, 0);
  if (!result) {
    throw new Error('Failed to decode KeyPackage');
  }
  return result[0];
}

// ─── GroupState → ClientState conversion ────────────────────────────────────

/**
 * Convert a GroupState (from deserialization) to a ClientState
 * by adding the default client configuration.
 *
 * This is needed when loading persisted MLS state, since only GroupState
 * is serializable — ClientState includes non-serializable runtime config.
 *
 * @param groupState - The deserialized GroupState
 * @returns A ClientState with default client configuration
 */
export function groupStateToClientState(groupState: GroupState): ClientState {
  return {
    ...groupState,
    clientConfig: defaultClientConfig,
  };
}

// ─── Helper: Hex to Bytes ───────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ─── Re-exported Types ──────────────────────────────────────────────────────
// Re-export ts-mls types so consumers don't need a direct ts-mls dependency.

export type {
  CiphersuiteName,
  ClientState,
  GroupState,
  MLSMessage,
};

export type { TsKeyPackage as KeyPackage };
export type { TsPrivateKeyPackage as PrivateKeyPackage };
export type { TsWelcome as Welcome };
