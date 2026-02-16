/**
 * Marmot Protocol Types
 *
 * Core type definitions for the Marmot Protocol (MLS + Nostr).
 * Covers all MIPs (MIP-00 through MIP-04).
 */

// ─── Nostr Event Types ──────────────────────────────────────────────────────

/**
 * Marmot-specific Nostr event kinds.
 */
export const MARMOT_EVENT_KINDS = {
  /** MIP-00: KeyPackage events */
  KEY_PACKAGE: 443,
  /** MIP-02: Welcome events (gift-wrapped) */
  WELCOME: 444,
  /** MIP-03: Group events (messages, proposals, commits) */
  GROUP_EVENT: 445,
  /** MIP-00: KeyPackage relay list */
  KEY_PACKAGE_RELAY_LIST: 10051,
} as const;

export type MarmotEventKind =
  (typeof MARMOT_EVENT_KINDS)[keyof typeof MARMOT_EVENT_KINDS];

/**
 * Encoding format for MLS content in events.
 */
export type ContentEncoding = 'base64' | 'hex';

/**
 * A Nostr event tag (array of strings).
 */
export type NostrTag = string[];

/**
 * Unsigned Nostr event (rumor) — inner events MUST NOT be signed.
 */
export interface UnsignedEvent {
  kind: number;
  created_at: number;
  pubkey: string;
  content: string;
  tags: NostrTag[];
  id?: string;
}

/**
 * Signed Nostr event.
 */
export interface SignedEvent extends UnsignedEvent {
  id: string;
  sig: string;
}

// ─── MIP-00: Credentials & Key Packages ─────────────────────────────────────

/**
 * MLS ciphersuite identifiers.
 * See RFC 9420 Section 17.1.
 */
export const MLS_CIPHERSUITES = {
  // Classical (RFC 9420)
  MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519: '0x0001',
  MLS_128_DHKEMP256_AES128GCM_SHA256_P256: '0x0002',
  MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519: '0x0003',
  MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448: '0x0004',
  MLS_256_DHKEMP521_AES256GCM_SHA512_P521: '0x0005',
  MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448: '0x0006',
  MLS_256_DHKEMP384_AES256GCM_SHA384_P384: '0x0007',
  // Post-quantum (ML-KEM)
  MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519: '0x004d',
  MLS_128_MLKEM512_CHACHA20POLY1305_SHA256_Ed25519: '0x004e',
  MLS_256_MLKEM768_AES256GCM_SHA384_Ed25519: '0x004f',
  MLS_256_MLKEM768_CHACHA20POLY1305_SHA384_Ed25519: '0x0050',
  MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519: '0x0051',
  MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_Ed25519: '0x0052',
  // Post-quantum (X-Wing)
  MLS_256_XWING_AES256GCM_SHA512_Ed25519: '0x0053',
  MLS_256_XWING_CHACHA20POLY1305_SHA512_Ed25519: '0x0054',
  // Post-quantum (ML-KEM + ML-DSA)
  MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87: '0x0055',
  MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87: '0x0056',
  MLS_256_XWING_AES256GCM_SHA512_MLDSA87: '0x0057',
  MLS_256_XWING_CHACHA20POLY1305_SHA512_MLDSA87: '0x0058',
} as const;

export type MLSCiphersuite = (typeof MLS_CIPHERSUITES)[keyof typeof MLS_CIPHERSUITES];

/**
 * MLS extension type IDs used by Marmot.
 */
export const MLS_EXTENSION_TYPES = {
  /** Marmot Group Data Extension */
  MARMOT_GROUP_DATA: 0xf2ee,
  /** Last Resort KeyPackage */
  LAST_RESORT: 0x000a,
  /** Default extensions that MUST NOT be listed in capabilities */
  APPLICATION_ID: 0x0001,
  RATCHET_TREE: 0x0002,
  REQUIRED_CAPABILITIES: 0x0003,
  EXTERNAL_PUB: 0x0004,
  EXTERNAL_SENDERS: 0x0005,
} as const;

/**
 * Options for creating a KeyPackage event (kind: 443).
 */
export interface KeyPackageOptions {
  /** TLS-serialized KeyPackageBundle (raw bytes) */
  keyPackageData: Uint8Array;
  /** MLS protocol version (default: "1.0") */
  protocolVersion?: string;
  /** MLS ciphersuite */
  ciphersuite: MLSCiphersuite;
  /** Supported MLS extension type IDs (non-default) */
  extensions?: number[];
  /** Content encoding (default: "base64") */
  encoding?: ContentEncoding;
  /** Client name (optional, for UX) */
  clientName?: string;
  /** Relay URLs where this KeyPackage is published */
  relays: string[];
  /** Whether to include NIP-70 protected tag (default: true) */
  protected?: boolean;
}

/**
 * Parsed KeyPackage event data.
 */
export interface ParsedKeyPackage {
  /** Event ID */
  eventId: string;
  /** Nostr pubkey of the KeyPackage owner */
  pubkey: string;
  /** Raw KeyPackage data */
  keyPackageData: Uint8Array;
  /** MLS protocol version */
  protocolVersion: string;
  /** MLS ciphersuite */
  ciphersuite: string;
  /** Supported extensions */
  extensions: number[];
  /** Content encoding used */
  encoding: ContentEncoding;
  /** Client name */
  clientName?: string;
  /** Relays */
  relays: string[];
  /** Created at timestamp */
  createdAt: number;
}

/**
 * KeyPackage relay list (kind: 10051).
 */
export interface KeyPackageRelayList {
  relays: string[];
}

// ─── MIP-01: Group Construction ─────────────────────────────────────────────

/**
 * Marmot Group Data Extension fields.
 * TLS-serialized with extension ID 0xF2EE.
 */
export interface MarmotGroupData {
  /** Extension format version (currently 1) */
  version: number;
  /** 32-byte Nostr group identifier (distinct from MLS group ID) */
  nostrGroupId: Uint8Array;
  /** UTF-8 group name */
  name: string;
  /** UTF-8 group description */
  description: string;
  /** Array of 32-byte admin Nostr public keys (hex-encoded strings) */
  adminPubkeys: string[];
  /** Array of WebSocket relay URLs */
  relays: string[];
  /** SHA-256 hash of encrypted group image (32 bytes, zeros if none) */
  imageHash: Uint8Array;
  /** ChaCha20-Poly1305 encryption key for group image (32 bytes, zeros if none) */
  imageKey: Uint8Array;
  /** ChaCha20-Poly1305 nonce for group image encryption (12 bytes, zeros if none) */
  imageNonce: Uint8Array;
}

/**
 * Options for creating a new Marmot group.
 */
export interface CreateGroupOptions {
  /** Group name */
  name: string;
  /** Group description */
  description?: string;
  /** Admin Nostr pubkeys (hex-encoded) */
  adminPubkeys: string[];
  /** Relay URLs for the group */
  relays: string[];
  /** MLS ciphersuite to use */
  ciphersuite?: MLSCiphersuite;
}

// ─── MIP-02: Welcome Events ─────────────────────────────────────────────────

/**
 * Options for creating a Welcome event (kind: 444).
 */
export interface WelcomeEventOptions {
  /** Serialized MLS Welcome message */
  welcomeData: Uint8Array;
  /** KeyPackage event ID that was consumed */
  keyPackageEventId: string;
  /** Relay URLs where the new member should look for Group Events */
  relays: string[];
  /** Content encoding (default: "base64") */
  encoding?: ContentEncoding;
}

/**
 * Parsed Welcome event data.
 */
export interface ParsedWelcomeEvent {
  /** Serialized MLS Welcome message */
  welcomeData: Uint8Array;
  /** Referenced KeyPackage event ID */
  keyPackageEventId: string;
  /** Relay URLs */
  relays: string[];
  /** Content encoding */
  encoding: ContentEncoding;
}

/**
 * NIP-59 gift wrap event structure.
 */
export interface GiftWrapEvent {
  /** The outer (sealed) event */
  outer: SignedEvent;
  /** The inner rumor (unsigned) */
  rumor: UnsignedEvent;
}

// ─── MIP-03: Group Messages ─────────────────────────────────────────────────

/**
 * MLS message types in group events.
 */
export type MLSMessageType = 'proposal' | 'commit' | 'application';

/**
 * Options for creating a group event (kind: 445).
 */
export interface GroupEventOptions {
  /** NIP-44 encrypted MLS message content */
  encryptedContent: string;
  /** Nostr group ID from Marmot Group Data Extension (hex) */
  nostrGroupId: string;
}

/**
 * Parsed group event data.
 */
export interface ParsedGroupEvent {
  /** Event ID */
  eventId: string;
  /** Ephemeral pubkey used for this event */
  ephemeralPubkey: string;
  /** Encrypted content (NIP-44) */
  encryptedContent: string;
  /** Nostr group ID from h tag */
  nostrGroupId: string;
  /** Created at timestamp */
  createdAt: number;
}

/**
 * Application message (inner Nostr event within MLS envelope).
 */
export interface ApplicationMessage {
  /** The inner unsigned Nostr event */
  event: UnsignedEvent;
  /** MLS sender identity (Nostr pubkey) */
  senderPubkey: string;
}

/**
 * Commit resolution priority for race conditions.
 */
export interface CommitPriority {
  /** Timestamp of the commit */
  createdAt: number;
  /** Event ID for tiebreaking */
  eventId: string;
}

// ─── MIP-04: Encrypted Media ────────────────────────────────────────────────

/**
 * Current encrypted media version.
 */
export const MEDIA_VERSION = 'mip04-v2' as const;

/**
 * Deprecated media version.
 */
export const MEDIA_VERSION_DEPRECATED = 'mip04-v1' as const;

/**
 * Encrypted media metadata (imeta tag fields).
 */
export interface EncryptedMediaMeta {
  /** Storage URL for the encrypted blob */
  url: string;
  /** MIME type in canonical form */
  mimeType: string;
  /** Original filename */
  filename: string;
  /** Image/video dimensions "widthxheight" */
  dimensions?: string;
  /** BlurHash for progressive loading */
  blurhash?: string;
  /** SHA-256 hash of original file content (hex-encoded) */
  fileHash: string;
  /** Encryption nonce (hex-encoded, 24 chars) */
  nonce: string;
  /** Encryption version */
  version: string;
}

/**
 * Options for encrypting media.
 */
export interface EncryptMediaOptions {
  /** Original file content */
  data: Uint8Array;
  /** MIME type */
  mimeType: string;
  /** Original filename */
  filename: string;
  /** MLS exporter secret (32 bytes) */
  exporterSecret: Uint8Array;
}

/**
 * Result of media encryption.
 */
export interface EncryptedMediaResult {
  /** Encrypted blob data */
  encryptedData: Uint8Array;
  /** Metadata for imeta tag */
  meta: EncryptedMediaMeta;
  /** SHA-256 hash of encrypted data (for storage addressing) */
  encryptedHash: string;
}

/**
 * Options for decrypting media.
 */
export interface DecryptMediaOptions {
  /** Encrypted blob data */
  encryptedData: Uint8Array;
  /** Metadata from imeta tag */
  meta: EncryptedMediaMeta;
  /** MLS exporter secret (32 bytes) */
  exporterSecret: Uint8Array;
}
