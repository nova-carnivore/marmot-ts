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
  encode,
  decode,
  clientStateEncoder,
  clientStateDecoder,
  mlsMessageEncoder,
  mlsMessageDecoder,
  getCiphersuiteImpl as tsGetCiphersuiteImpl,
  ciphersuites as tsCiphersuites,
  defaultLifetime,
  defaultCapabilities as tsDefaultCapabilities,
  defaultCredentialTypes,
  defaultProposalTypes,
  unsafeTestingAuthenticationService,
  protocolVersions,
  wireformats,
  keyPackageEncoder as tsKeyPackageEncoder,
  keyPackageDecoder as tsKeyPackageDecoder,
} from 'ts-mls';

import {
  welcomeEncoder as tsWelcomeEncoder,
  welcomeDecoder as tsWelcomeDecoder,
} from 'ts-mls/welcome.js';

import type {
  Capabilities,
  CiphersuiteName,
  CiphersuiteId,
  CiphersuiteImpl,
  KeyPackage as TsKeyPackage,
  PrivateKeyPackage as TsPrivateKeyPackage,
  ClientState,
  GroupState,
  Welcome as TsWelcome,
  MlsMessage,
  MlsFramedMessage,
  MlsWelcomeMessage,
  Credential,
  Proposal,
  MlsContext,
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
 * Default ciphersuite numeric ID.
 */
export const DEFAULT_CIPHERSUITE_ID: CiphersuiteId = tsCiphersuites[DEFAULT_CIPHERSUITE];

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

  const impl = await tsGetCiphersuiteImpl(name);
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

// ─── Marmot Capabilities ────────────────────────────────────────────────────

/**
 * Marmot-specific MLS capabilities.
 *
 * Builds on ts-mls v2's defaultCapabilities() (which includes GREASE values),
 * then ensures Marmot-required extensions are present and filters ciphersuites
 * to the ones we actually support.
 *
 * This function returns interop-tested capabilities:
 * - versions: [1] (mls10) + GREASE
 * - ciphersuites: [1, 3] (AES-128-GCM + ChaCha20) + GREASE, filtered from default
 * - extensions: includes [0x000a, 0xf2ee] (ratchet_tree + marmot_group_data) + GREASE
 * - proposals: [] + GREASE
 * - credentials: [1] (basic) + GREASE
 *
 * Per MIP-00: "Marmot implementations MUST include the 0xf2ee extension for
 * marmot_group_data and the 0x000a extension for last_resort."
 */
export function marmotCapabilities(): Capabilities {
  // Start with ts-mls v2 defaults (includes GREASE)
  const caps = tsDefaultCapabilities();

  // Ensure marmot extensions are present
  const extensions = Array.from(caps.extensions);
  if (!extensions.includes(0xf2ee)) extensions.push(0xf2ee);
  if (!extensions.includes(0x000a)) extensions.push(0x000a);

  // Filter ciphersuites: keep 0x0001, 0x0003, and GREASE values
  const allowedCiphersuites = new Set<number>([
    tsCiphersuites.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, // 1
    tsCiphersuites.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, // 3
  ]);
  const filteredCiphersuites = caps.ciphersuites.filter(
    (id) => allowedCiphersuites.has(id) || isGreaseValue(id)
  );

  // Only include basic credential type (filter out x509), keep GREASE
  const filteredCredentials = caps.credentials.filter(
    (c) => c === defaultCredentialTypes.basic || isGreaseValue(c)
  );

  return {
    ...caps,
    extensions,
    ciphersuites: filteredCiphersuites as Capabilities['ciphersuites'],
    credentials: filteredCredentials,
  };
}

/**
 * MLS GREASE values (RFC 8701 / RFC 9420).
 * Pattern: 0x?A?A where the two nibbles are the same.
 * e.g. 0x0A0A, 0x1A1A, ..., 0xEAEA
 */
const GREASE_VALUES = new Set([
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
  0xbaba, 0xcaca, 0xdada, 0xeaea,
]);

function isGreaseValue(v: number): boolean {
  return GREASE_VALUES.has(v);
}

// ─── MLS Context ────────────────────────────────────────────────────────────

/**
 * Create an MlsContext for ts-mls v2 operations.
 *
 * @param ciphersuite - Ciphersuite name (default: DEFAULT_CIPHERSUITE)
 * @returns MlsContext with ciphersuite and auth service
 */
async function createMlsContext(
  ciphersuite: CiphersuiteName = DEFAULT_CIPHERSUITE
): Promise<MlsContext> {
  const cs = await getCiphersuiteImpl(ciphersuite);
  return {
    cipherSuite: cs,
    authService: unsafeTestingAuthenticationService,
  };
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
 * Uses marmotCapabilities() instead of ts-mls's defaultCapabilities() for
 * interoperability with OpenMLS-based clients.
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
    credentialType: defaultCredentialTypes.basic,
    identity: identityBytes,
  };

  const { publicPackage, privatePackage } = await tsGenerateKeyPackage({
    credential,
    capabilities: marmotCapabilities(),
    lifetime: defaultLifetime(),
    extensions: [],
    cipherSuite: cs,
  });

  // Encode as raw KeyPackage (NOT MLSMessage-wrapped)
  const keyPackageBytes = encode(tsKeyPackageEncoder, publicPackage);

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
    throw new Error(
      'OpenMLS format (0xd34d) is not supported; use standard TLS encoding'
    );
  }

  // Check version: must be 0x0001 (mls10)
  if (bytes[0] !== 0x00 || bytes[1] !== 0x01) {
    throw new Error(
      `Unknown KeyPackage format: expected version 0x0001, got 0x${bytes[0]!.toString(16).padStart(2, '0')}${bytes[1]!.toString(16).padStart(2, '0')}`
    );
  }

  // Check if MLSMessage-wrapped (wireformat 0x0005 = mls_key_package)
  if (bytes[2] === 0x00 && bytes[3] === 0x05) {
    // MLSMessage-wrapped: decode via mlsMessageDecoder
    const result = decode(mlsMessageDecoder, bytes);
    if (!result) {
      throw new Error('Failed to decode MLSMessage-wrapped KeyPackage');
    }
    if (result.wireformat !== wireformats.mls_key_package) {
      throw new Error(`Expected mls_key_package wireformat, got ${result.wireformat}`);
    }
    return (
      result as {
        wireformat: typeof wireformats.mls_key_package;
        keyPackage: TsKeyPackage;
      }
    ).keyPackage;
  }

  // Raw KeyPackage: parse directly
  const result = decode(tsKeyPackageDecoder, bytes);
  if (!result) {
    throw new Error('Failed to decode raw KeyPackage');
  }
  return result;
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
  const context = await createMlsContext(ciphersuite);

  // Generate a KeyPackage for the group creator
  const { keyPackage, privateKeyPackage } = await generateMlsKeyPackage(
    identity,
    ciphersuite
  );

  const state = await tsCreateGroup({
    context,
    groupId,
    keyPackage,
    privateKeyPackage,
    extensions: [],
  });

  const encodedState = encode(clientStateEncoder, state);
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
  commit: MlsFramedMessage;
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
  const context = await createMlsContext(ciphersuite);

  // Build Add proposals (proposalType is numeric in ts-mls v2)
  const extraProposals: Proposal[] = memberKeyPackages.map((kp) => ({
    proposalType: defaultProposalTypes.add,
    add: { keyPackage: kp },
  }));

  const result = await tsCreateCommit({
    context,
    state,
    extraProposals,
    ratchetTreeExtension: true,
  });

  if (!result.welcome) {
    throw new Error('Expected Welcome message when adding members');
  }

  const encodedState = encode(clientStateEncoder, result.newState);
  const exporterSecret = await deriveExporterSecret(result.newState, ciphersuite);

  return {
    newState: result.newState,
    welcome: result.welcome.welcome,
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
  const context = await createMlsContext(ciphersuite);

  const state = await tsJoinGroup({
    context,
    welcome,
    keyPackage,
    privateKeys: privateKeyPackage,
  });

  const encodedState = encode(clientStateEncoder, state);
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
    cs
  );
}

// ─── State Serialization ────────────────────────────────────────────────────

/**
 * Encode MLS group state for persistence.
 */
export function encodeMlsState(state: ClientState): Uint8Array {
  return encode(clientStateEncoder, state);
}

/**
 * Decode MLS group state from persisted bytes.
 */
export function decodeMlsState(bytes: Uint8Array): ClientState {
  const result = decode(clientStateDecoder, bytes);
  if (!result) {
    throw new Error('Failed to decode MLS group state');
  }
  return result;
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
  return encode(mlsMessageEncoder, {
    version: protocolVersions.mls10,
    wireformat: wireformats.mls_welcome,
    welcome,
  } as MlsMessage);
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
    const msg = decode(mlsMessageDecoder, bytes);
    if (msg) {
      if (msg.wireformat === wireformats.mls_welcome) {
        return (msg as { wireformat: typeof wireformats.mls_welcome; welcome: TsWelcome })
          .welcome;
      }
      throw new Error(
        `Expected MLSMessage with wireformat mls_welcome, got ${msg.wireformat}`
      );
    }
  }

  // Fallback: try raw Welcome decoding for compatibility
  const rawResult = decode(tsWelcomeDecoder, bytes);
  if (!rawResult) {
    throw new Error('Failed to decode Welcome message');
  }
  return rawResult;
}

/**
 * Encode a Welcome message to raw TLS wire format (NOT MLSMessage-wrapped).
 *
 * Most callers should use `encodeWelcome()` which produces the MLSMessage-wrapped
 * format required by MIP-02. This raw variant is for advanced/internal use only.
 */
export function encodeWelcomeRaw(welcome: TsWelcome): Uint8Array {
  return encode(tsWelcomeEncoder, welcome);
}

/**
 * Decode a Welcome message from raw TLS wire format (NOT MLSMessage-wrapped).
 *
 * Most callers should use `decodeWelcome()` which handles the MLSMessage-wrapped
 * format used by MIP-02. This raw variant is for advanced/internal use only.
 */
export function decodeWelcomeRaw(bytes: Uint8Array): TsWelcome {
  const result = decode(tsWelcomeDecoder, bytes);
  if (!result) {
    throw new Error('Failed to decode raw Welcome message');
  }
  return result;
}

/**
 * Encode a KeyPackage to raw TLS wire format (NOT MLSMessage-wrapped).
 *
 * Per MIP-00, KeyPackage content in kind:443 events uses raw TLS-serialized
 * KeyPackage bytes (NOT MLSMessage-wrapped).
 */
export function encodeKeyPackage(keyPackage: TsKeyPackage): Uint8Array {
  return encode(tsKeyPackageEncoder, keyPackage);
}

/**
 * Decode a KeyPackage from raw TLS wire format.
 * For MLSMessage-wrapped or auto-detection, use parseKeyPackageBytes().
 */
export function decodeKeyPackage(bytes: Uint8Array): TsKeyPackage {
  const result = decode(tsKeyPackageDecoder, bytes);
  if (!result) {
    throw new Error('Failed to decode KeyPackage');
  }
  return result;
}

// ─── GroupState → ClientState conversion ────────────────────────────────────

/**
 * Convert a GroupState (from deserialization) to a ClientState.
 *
 * In ts-mls v2, ClientState = GroupState & PublicGroupState, and
 * serialization includes both parts. This function is provided for
 * backward compatibility but typically you should use decodeMlsState()
 * which returns a full ClientState directly.
 *
 * @param groupState - The deserialized GroupState
 * @returns The same state (in v2, decode gives full ClientState)
 */
export function groupStateToClientState(groupState: GroupState): ClientState {
  // In v2, GroupState doesn't include ratchetTree and groupContext.
  // If this is actually a ClientState (which it should be from decodeMlsState),
  // just return it as-is.
  return groupState as unknown as ClientState;
}

// ─── Helper: Hex to Bytes ───────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHexInternal(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─── MLS Varint + Standalone KeyPackage Parser ──────────────────────────────

/**
 * Read an MLS variable-length integer (QUIC-style, RFC 9420 Section 2.1.2).
 *
 * Top 2 bits of the first byte determine the prefix size:
 * - `00xxxxxx` = 1 byte, value = byte & 0x3F (max 63)
 * - `01xxxxxx xxxxxxxx` = 2 bytes, value = (first & 0x3F)<<8 | second (max 16383)
 * - `10xxxxxx ...` = 4 bytes, value = (first & 0x3F)<<24 | ... (max 1073741823)
 * - `11xxxxxx` = invalid
 *
 * @param data - The byte array to read from
 * @param offset - Starting offset in the byte array
 * @returns Tuple of [value, newOffset]
 */
export function readMlsVarint(
  data: Uint8Array,
  offset: number
): [value: number, newOffset: number] {
  if (offset >= data.length) {
    throw new Error(
      `readMlsVarint: offset ${offset} out of bounds (length ${data.length})`
    );
  }

  const first = data[offset]!;
  const prefix = first >> 6;

  if (prefix === 0) {
    // 1-byte: 00xxxxxx
    return [first & 0x3f, offset + 1];
  }

  if (prefix === 1) {
    // 2-byte: 01xxxxxx xxxxxxxx
    if (offset + 1 >= data.length) {
      throw new Error('readMlsVarint: insufficient data for 2-byte varint');
    }
    const value = ((first & 0x3f) << 8) | data[offset + 1]!;
    return [value, offset + 2];
  }

  if (prefix === 2) {
    // 4-byte: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    if (offset + 3 >= data.length) {
      throw new Error('readMlsVarint: insufficient data for 4-byte varint');
    }
    const value =
      ((first & 0x3f) << 24) |
      (data[offset + 1]! << 16) |
      (data[offset + 2]! << 8) |
      data[offset + 3]!;
    return [value, offset + 4];
  }

  // prefix === 3 (0b11) — invalid
  throw new Error(
    `readMlsVarint: invalid prefix 0b11 at offset ${offset} (byte 0x${first.toString(16).padStart(2, '0')})`
  );
}

/**
 * Parsed MLS capabilities from a KeyPackage.
 */
export interface ParsedCapabilities {
  /** MLS version IDs (e.g. [1] for mls10) */
  versions: number[];
  /** Ciphersuite IDs (e.g. [1, 0x7a7a]) — includes GREASE values */
  ciphersuites: number[];
  /** Extension type IDs (e.g. [0x000a, 0xf2ee]) — includes GREASE values */
  extensions: number[];
  /** Proposal type IDs — includes GREASE values */
  proposals: number[];
  /** Credential type IDs (e.g. [1]) — includes GREASE values */
  credentials: number[];
}

/**
 * Parsed KeyPackage extension.
 */
export interface ParsedExtension {
  /** Extension type ID */
  type: number;
  /** Raw extension data */
  data: Uint8Array;
}

/**
 * Result of standalone KeyPackage parsing with all raw fields.
 *
 * Unlike `parseKeyPackageBytes()` which delegates to ts-mls, this parser
 * reads the wire format directly using MLS varint decoding. Useful for
 * debugging interop issues and analyzing KeyPackages from any MLS implementation.
 */
export interface ParsedKeyPackageRaw {
  /** MLS protocol version (uint16, 1 = mls10) */
  version: number;
  /** Ciphersuite ID (uint16, e.g. 1 = AES-128-GCM + Ed25519) */
  cipherSuite: number;
  /** HPKE init key (raw bytes) */
  initKey: Uint8Array;
  /** HPKE encryption key (raw bytes) */
  encryptionKey: Uint8Array;
  /** Signature key (raw bytes, typically 32 bytes for Ed25519) */
  signatureKey: Uint8Array;
  /** Credential type (uint16, 1 = basic) */
  credentialType: number;
  /** Identity bytes (raw — may be 32 bytes binary or 64 bytes hex string depending on client) */
  identity: Uint8Array;
  /** Identity as hex string (normalized: if identity is a hex-encoded ASCII string, it's decoded; otherwise hex-encoded) */
  identityHex: string;
  /** Parsed capabilities */
  capabilities: ParsedCapabilities;
  /** Leaf node source (uint8, 1 = key_package, 2 = update, 3 = commit) */
  leafNodeSource: number;
  /** Lifetime: not_before (uint64 as bigint) — only present when leafNodeSource === 1 */
  notBefore?: bigint;
  /** Lifetime: not_after (uint64 as bigint) — only present when leafNodeSource === 1 */
  notAfter?: bigint;
  /** Leaf node extensions (parsed) */
  leafExtensions: ParsedExtension[];
  /** Leaf node signature (raw bytes, typically 64 bytes for Ed25519) */
  leafSignature: Uint8Array;
  /** KeyPackage extensions (parsed) */
  kpExtensions: ParsedExtension[];
  /** KeyPackage signature (raw bytes, typically 64 bytes for Ed25519) */
  kpSignature: Uint8Array;
  /** Total bytes consumed */
  totalBytes: number;
}

/**
 * Read a uint16 (big-endian) from a byte array.
 */
function readUint16BE(data: Uint8Array, offset: number): number {
  if (offset + 1 >= data.length) {
    throw new Error(
      `readUint16BE: offset ${offset} out of bounds (length ${data.length})`
    );
  }
  return (data[offset]! << 8) | data[offset + 1]!;
}

/**
 * Read a uint64 (big-endian) as bigint from a byte array.
 */
function readUint64BE(data: Uint8Array, offset: number): bigint {
  if (offset + 7 >= data.length) {
    throw new Error(
      `readUint64BE: offset ${offset} out of bounds (length ${data.length})`
    );
  }
  let value = 0n;
  for (let i = 0; i < 8; i++) {
    value = (value << 8n) | BigInt(data[offset + i]!);
  }
  return value;
}

/**
 * Read a varint-prefixed byte vector.
 */
function readVarintBytes(
  data: Uint8Array,
  offset: number
): [bytes: Uint8Array, newOffset: number] {
  const [len, off] = readMlsVarint(data, offset);
  if (off + len > data.length) {
    throw new Error(
      `readVarintBytes: vector length ${len} exceeds data (offset ${off}, length ${data.length})`
    );
  }
  return [data.slice(off, off + len), off + len];
}

/**
 * Parse a varint-prefixed list of uint16 values.
 */
function readUint16List(
  data: Uint8Array,
  offset: number
): [values: number[], newOffset: number] {
  const [vecBytes, newOff] = readVarintBytes(data, offset);
  const values: number[] = [];
  for (let i = 0; i + 1 < vecBytes.length; i += 2) {
    values.push((vecBytes[i]! << 8) | vecBytes[i + 1]!);
  }
  return [values, newOff];
}

/**
 * Parse a varint-prefixed extensions list.
 * Each extension is: type(uint16) + data(varint-prefixed bytes).
 */
function readExtensionsList(
  data: Uint8Array,
  offset: number
): [extensions: ParsedExtension[], newOffset: number] {
  const [vecBytes, newOff] = readVarintBytes(data, offset);
  const extensions: ParsedExtension[] = [];
  let i = 0;
  while (i + 1 < vecBytes.length) {
    const type = (vecBytes[i]! << 8) | vecBytes[i + 1]!;
    i += 2;
    const [extData, nextI] = readVarintBytes(vecBytes, i);
    extensions.push({ type, data: extData });
    i = nextI;
  }
  return [extensions, newOff];
}

/**
 * Check if a byte array looks like a hex-encoded ASCII string.
 * Returns true if all bytes are valid hex ASCII characters (0-9, a-f, A-F)
 * and the length is even.
 */
function isHexAscii(bytes: Uint8Array): boolean {
  if (bytes.length === 0 || bytes.length % 2 !== 0) return false;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (
      !(b >= 0x30 && b <= 0x39) && // 0-9
      !(b >= 0x61 && b <= 0x66) && // a-f
      !(b >= 0x41 && b <= 0x46) // A-F
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Parse raw TLS-encoded KeyPackage bytes using standalone varint-aware parsing.
 *
 * Unlike `parseKeyPackageBytes()` which delegates to ts-mls's decoder,
 * this parser reads the wire format directly. This is useful for:
 * - Debugging interop issues between different MLS implementations
 * - Analyzing KeyPackages from OpenMLS, marmot-chat (XChat), MDK, etc.
 * - Extracting fields without requiring ts-mls to successfully parse the package
 *
 * Handles both raw KeyPackage format and MLSMessage-wrapped format
 * (strips the 4-byte header if wireformat is 0x0005).
 *
 * @param bytes - Raw or MLSMessage-wrapped KeyPackage bytes
 * @returns Parsed KeyPackage with all raw fields
 */
export function parseKeyPackageRaw(bytes: Uint8Array): ParsedKeyPackageRaw {
  if (bytes.length < 4) {
    throw new Error('parseKeyPackageRaw: data too short');
  }

  let data = bytes;
  let offset = 0;

  // Check for MLSMessage-wrapped format: version(0x0001) + wireformat(0x0005)
  if (data[0] === 0x00 && data[1] === 0x01 && data[2] === 0x00 && data[3] === 0x05) {
    data = data.slice(4);
  }

  // version: uint16
  const version = readUint16BE(data, offset);
  offset += 2;

  // cipher_suite: uint16
  const cipherSuite = readUint16BE(data, offset);
  offset += 2;

  // init_key: varint(len) + bytes
  const [initKey, offsetAfterInit] = readVarintBytes(data, offset);
  offset = offsetAfterInit;

  // LeafNode starts here
  // encryption_key: varint(len) + bytes
  const [encryptionKey, offsetAfterEnc] = readVarintBytes(data, offset);
  offset = offsetAfterEnc;

  // signature_key: varint(len) + bytes
  const [signatureKey, offsetAfterSig] = readVarintBytes(data, offset);
  offset = offsetAfterSig;

  // credential_type: uint16
  const credentialType = readUint16BE(data, offset);
  offset += 2;

  // identity: varint(len) + bytes
  const [identity, offsetAfterIdent] = readVarintBytes(data, offset);
  offset = offsetAfterIdent;

  // Normalize identity to hex string
  let identityHex: string;
  if (isHexAscii(identity)) {
    // XChat/marmot-chat style: identity is hex-encoded ASCII string
    identityHex = new TextDecoder().decode(identity);
  } else {
    // MDK style: identity is raw 32-byte pubkey
    identityHex = bytesToHexInternal(identity);
  }

  // capabilities
  const [versions, offsetAfterVer] = readUint16List(data, offset);
  offset = offsetAfterVer;

  const [ciphersuites, offsetAfterCs] = readUint16List(data, offset);
  offset = offsetAfterCs;

  const [extensions, offsetAfterExt] = readUint16List(data, offset);
  offset = offsetAfterExt;

  const [proposals, offsetAfterProp] = readUint16List(data, offset);
  offset = offsetAfterProp;

  const [credentials, offsetAfterCred] = readUint16List(data, offset);
  offset = offsetAfterCred;

  const capabilities: ParsedCapabilities = {
    versions,
    ciphersuites,
    extensions,
    proposals,
    credentials,
  };

  // leaf_node_source: uint8
  const leafNodeSource = data[offset]!;
  offset += 1;

  // Lifetime (only for key_package source, type 1)
  let notBefore: bigint | undefined;
  let notAfter: bigint | undefined;
  if (leafNodeSource === 1) {
    notBefore = readUint64BE(data, offset);
    offset += 8;
    notAfter = readUint64BE(data, offset);
    offset += 8;
  }

  // leaf_extensions: varint(len) + extensions list
  const [leafExtensions, offsetAfterLeafExt] = readExtensionsList(data, offset);
  offset = offsetAfterLeafExt;

  // leaf_signature: varint(len) + bytes
  const [leafSignature, offsetAfterLeafSig] = readVarintBytes(data, offset);
  offset = offsetAfterLeafSig;

  // kp_extensions: varint(len) + extensions list
  const [kpExtensions, offsetAfterKpExt] = readExtensionsList(data, offset);
  offset = offsetAfterKpExt;

  // kp_signature: varint(len) + bytes
  const [kpSignature, offsetAfterKpSig] = readVarintBytes(data, offset);
  offset = offsetAfterKpSig;

  return {
    version,
    cipherSuite,
    initKey,
    encryptionKey,
    signatureKey,
    credentialType,
    identity,
    identityHex,
    capabilities,
    leafNodeSource,
    notBefore,
    notAfter,
    leafExtensions,
    leafSignature,
    kpExtensions,
    kpSignature,
    totalBytes: offset,
  };
}

// ─── Re-exported Types ──────────────────────────────────────────────────────
// Re-export ts-mls types so consumers don't need a direct ts-mls dependency.

export type { CiphersuiteName, ClientState, GroupState };

export type { MlsMessage, MlsFramedMessage, MlsWelcomeMessage };

export type { TsKeyPackage as KeyPackage };
export type { TsPrivateKeyPackage as PrivateKeyPackage };
export type { TsWelcome as Welcome };
