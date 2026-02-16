/**
 * marmot-ts — TypeScript library for the Marmot Protocol
 *
 * Secure, decentralized group messaging combining MLS + Nostr.
 *
 * @packageDocumentation
 */

// ─── Types ──────────────────────────────────────────────────────────────────
export type {
  MarmotEventKind,
  ContentEncoding,
  NostrTag,
  UnsignedEvent,
  SignedEvent,
  MLSCiphersuite,
  KeyPackageOptions,
  ParsedKeyPackage,
  KeyPackageRelayList,
  MarmotGroupData,
  CreateGroupOptions,
  WelcomeEventOptions,
  ParsedWelcomeEvent,
  GiftWrapEvent,
  MLSMessageType,
  GroupEventOptions,
  ParsedGroupEvent,
  ApplicationMessage,
  CommitPriority,
  EncryptedMediaMeta,
  EncryptMediaOptions,
  EncryptedMediaResult,
  DecryptMediaOptions,
} from './types.js';

export {
  MARMOT_EVENT_KINDS,
  MLS_CIPHERSUITES,
  MLS_EXTENSION_TYPES,
  MEDIA_VERSION,
  MEDIA_VERSION_DEPRECATED,
} from './types.js';

// ─── Signer ─────────────────────────────────────────────────────────────────
export type { MarmotSigner, Nip46Config } from './signer.js';
export { PrivateKeySigner, Nip07Signer, Nip46Signer, computeEventId } from './signer.js';

// ─── Crypto ─────────────────────────────────────────────────────────────────
export {
  sha256Hash,
  sha256Hex,
  hkdfExpand,
  generateKeypair,
  generateEphemeralKeypair,
  keypairFromSecret,
  keypairFromSecretHex,
  getPublicKey,
  getPublicKeyHex,
  computeConversationKey,
  deriveGroupConversationKey,
  chacha20Poly1305Encrypt,
  chacha20Poly1305Decrypt,
  deriveUploadKeypair,
} from './crypto.js';

// ─── Utils ──────────────────────────────────────────────────────────────────
export {
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  encodeContent,
  decodeContent,
  detectEncoding,
  isValidPubkey,
  isValidRelayUrl,
  isValidHex,
  isNonDefaultExtension,
  formatExtensionId,
  parseExtensionId,
  getTagValue,
  getTagValues,
  unixTimestamp,
  bytesEqual,
  concatBytes,
  randomBytes,
  canonicalizeMimeType,
} from './utils.js';

// ─── MIP-00: Credentials & Key Packages ─────────────────────────────────────
export {
  createKeyPackageEvent,
  createSignedKeyPackageEvent,
  parseKeyPackageEvent,
  validateCredentialIdentity,
  pubkeyToCredentialIdentity,
  isKeyPackageCompatible,
  hasRequiredMarmotExtensions,
  createKeyPackageRelayListEvent,
  parseKeyPackageRelayList,
  createKeyPackageDeletionEvent,
} from './mip00.js';

// ─── MIP-01: Group Construction ─────────────────────────────────────────────
export {
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
} from './mip01.js';

// ─── MIP-02: Welcome Events ────────────────────────────────────────────────
export {
  createWelcomeRumor,
  parseWelcomeEvent,
  giftWrapWelcome,
  unwrapWelcome,
  CommitWelcomeOrderTracker,
  validateWelcomeEvent,
  isInitialGroupCreation,
} from './mip02.js';

// ─── MIP-03: Group Messages ────────────────────────────────────────────────
export {
  createGroupEvent,
  parseGroupEvent,
  deriveEncryptionKeypair,
  encryptGroupContent,
  decryptGroupContent,
  createApplicationMessage,
  createReactionMessage,
  validateApplicationMessage,
  verifyApplicationMessageSender,
  serializeApplicationMessage,
  deserializeApplicationMessage,
  compareCommitPriority,
  selectWinningCommit,
  CommitOrderTracker,
  isValidSelfUpdate,
} from './mip03.js';

// ─── MIP-04: Encrypted Media ───────────────────────────────────────────────
export {
  deriveFileKey,
  encryptMedia,
  decryptMedia,
  buildImetaTag,
  parseImetaTag,
  isCanonicalMimeType,
  COMMON_MIME_TYPES,
  isSupportedVersion,
  isDeprecatedVersion,
} from './mip04.js';

// ─── MLS Runtime Operations ────────────────────────────────────────────────
export {
  DEFAULT_CIPHERSUITE,
  marmotCapabilities,
  getCiphersuiteImpl,
  getSupportedCiphersuites,
  ciphersuiteNameToId,
  ciphersuiteIdToName,
  generateMlsKeyPackage,
  parseKeyPackageBytes,
  parseKeyPackageFromEvent,
  parseKeyPackageRaw,
  readMlsVarint,
  createMlsGroup,
  addMlsGroupMembers,
  joinMlsGroupFromWelcome,
  deriveExporterSecret,
  encodeMlsState,
  decodeMlsState,
  encodeWelcome,
  decodeWelcome,
  encodeWelcomeRaw,
  decodeWelcomeRaw,
  encodeKeyPackage,
  decodeKeyPackage,
  groupStateToClientState,
} from './mls.js';

export type {
  GeneratedKeyPackage,
  ParsedKeyPackageFromEvent,
  ParsedKeyPackageRaw,
  ParsedCapabilities,
  ParsedExtension,
  MlsGroupResult,
  AddMembersResult,
  JoinGroupResult,
  CiphersuiteName,
  ClientState,
  GroupState,
  KeyPackage,
  PrivateKeyPackage,
  Welcome,
  MLSMessage,
} from './mls.js';
