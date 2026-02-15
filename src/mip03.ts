/**
 * MIP-03: Group Messages
 *
 * Group event creation (kind: 445), ephemeral keypair generation,
 * double encryption (MLS + NIP-44), unsigned inner events,
 * and commit race condition handling.
 */

import type {
  GroupEventOptions,
  ParsedGroupEvent,
  UnsignedEvent,
  SignedEvent,
  CommitPriority,
} from './types.js';
import { MARMOT_EVENT_KINDS } from './types.js';
import { getTagValue, unixTimestamp, isValidPubkey, bytesToHex } from './utils.js';
import { generateEphemeralKeypair, getPublicKeyHex } from './crypto.js';
import type { MarmotSigner } from './signer.js';
import { PrivateKeySigner, computeEventId } from './signer.js';

// ─── Group Event Creation ───────────────────────────────────────────────────

/**
 * Create a Group Event (kind: 445) with an ephemeral keypair.
 *
 * CRITICAL: A fresh ephemeral keypair MUST be generated for EVERY group event.
 *
 * @param options - Group event configuration
 * @returns Object containing the signed event and the ephemeral private key
 */
export async function createGroupEvent(
  options: GroupEventOptions
): Promise<{ event: SignedEvent; ephemeralPrivateKey: string }> {
  // Generate fresh ephemeral keypair for this event
  const ephemeral = generateEphemeralKeypair();

  const event: UnsignedEvent = {
    kind: MARMOT_EVENT_KINDS.GROUP_EVENT,
    created_at: unixTimestamp(),
    pubkey: ephemeral.publicKeyHex,
    content: options.encryptedContent,
    tags: [['h', options.nostrGroupId]],
  };

  // Sign with ephemeral key
  const ephemeralSigner = new PrivateKeySigner(ephemeral.privateKeyHex);
  const signedEvent = await ephemeralSigner.signEvent(event);

  return {
    event: signedEvent,
    ephemeralPrivateKey: ephemeral.privateKeyHex,
  };
}

/**
 * Parse a Group Event (kind: 445).
 */
export function parseGroupEvent(event: SignedEvent | UnsignedEvent): ParsedGroupEvent {
  if (event.kind !== MARMOT_EVENT_KINDS.GROUP_EVENT) {
    throw new Error(`Expected kind ${MARMOT_EVENT_KINDS.GROUP_EVENT}, got ${event.kind}`);
  }

  const nostrGroupId = getTagValue(event.tags, 'h');
  if (!nostrGroupId) {
    throw new Error('Missing h tag (Nostr group ID)');
  }

  return {
    eventId: event.id ?? '',
    ephemeralPubkey: event.pubkey,
    encryptedContent: event.content,
    nostrGroupId,
    createdAt: event.created_at,
  };
}

// ─── NIP-44 Encryption with Exporter Secret ─────────────────────────────────

/**
 * Derive the NIP-44 encryption keypair from the MLS exporter secret.
 *
 * The exporter_secret is used as a private key to derive a public key.
 * Both are used for NIP-44 conversation key derivation.
 *
 * @param exporterSecret - MLS exporter_secret (32 bytes)
 * @returns Keypair for NIP-44 encryption
 */
export function deriveEncryptionKeypair(exporterSecret: Uint8Array): {
  privateKeyHex: string;
  publicKeyHex: string;
} {
  if (exporterSecret.length !== 32) {
    throw new Error(`exporter_secret must be 32 bytes, got ${exporterSecret.length}`);
  }

  const privateKeyHex = bytesToHex(exporterSecret);
  const publicKeyHex = getPublicKeyHex(privateKeyHex);

  return { privateKeyHex, publicKeyHex };
}

/**
 * Encrypt MLS message content for a group event using NIP-44.
 *
 * Process:
 * 1. Use exporter_secret as private key
 * 2. Derive public key from exporter_secret
 * 3. Use NIP-44 with conversation_key derived from (secret → pubkey(secret))
 *
 * @param signer - Signer that supports NIP-44 (or custom implementation)
 * @param mlsMessage - Serialized MLS message (encoded as string)
 * @param exporterSecret - MLS exporter_secret (32 bytes)
 * @returns NIP-44 encrypted content string
 */
export async function encryptGroupContent(
  signer: MarmotSigner,
  mlsMessage: string,
  exporterSecret: Uint8Array
): Promise<string> {
  const { publicKeyHex } = deriveEncryptionKeypair(exporterSecret);
  // NIP-44 encrypt using the exporter_secret-derived conversation
  return signer.nip44Encrypt(publicKeyHex, mlsMessage);
}

/**
 * Decrypt group event content using NIP-44.
 *
 * @param signer - Signer that supports NIP-44
 * @param encryptedContent - NIP-44 encrypted content
 * @param exporterSecret - MLS exporter_secret (32 bytes)
 * @returns Decrypted MLS message string
 */
export async function decryptGroupContent(
  signer: MarmotSigner,
  encryptedContent: string,
  exporterSecret: Uint8Array
): Promise<string> {
  const { publicKeyHex } = deriveEncryptionKeypair(exporterSecret);
  return signer.nip44Decrypt(publicKeyHex, encryptedContent);
}

// ─── Application Messages ───────────────────────────────────────────────────

/**
 * Create an unsigned application message (inner Nostr event).
 *
 * CRITICAL SECURITY:
 * - Inner events MUST remain unsigned (no sig field)
 * - MUST NOT include h tags or other group identifiers
 * - This prevents leaked events from being published to public relays
 *
 * @param senderPubkey - Sender's Nostr pubkey (for identity verification)
 * @param content - Message content
 * @param kind - Event kind (default: 9 for chat messages)
 * @param additionalTags - Additional tags (must NOT include h or group IDs)
 * @returns Unsigned inner event
 */
export function createApplicationMessage(
  senderPubkey: string,
  content: string,
  kind: number = 9,
  additionalTags: string[][] = []
): UnsignedEvent {
  if (!isValidPubkey(senderPubkey)) {
    throw new Error(`Invalid sender pubkey: ${senderPubkey}`);
  }

  // Security: reject any h tags or group identifiers
  for (const tag of additionalTags) {
    if (tag[0] === 'h') {
      throw new Error(
        'Application messages MUST NOT include h tags (group identifiers). ' +
          'This would leak group metadata if the inner event is published.'
      );
    }
  }

  const event: UnsignedEvent = {
    kind,
    created_at: unixTimestamp(),
    pubkey: senderPubkey,
    content,
    tags: additionalTags,
  };

  // Compute the event ID but do NOT sign
  event.id = computeEventId(event);

  return event;
}

/**
 * Create a reaction application message (kind: 7).
 */
export function createReactionMessage(
  senderPubkey: string,
  targetEventId: string,
  targetPubkey: string,
  reaction: string = '+'
): UnsignedEvent {
  return createApplicationMessage(senderPubkey, reaction, 7, [
    ['e', targetEventId],
    ['p', targetPubkey],
  ]);
}

/**
 * Validate an application message (inner event).
 *
 * Checks:
 * - Must be unsigned (no sig field)
 * - Must NOT contain h tags
 * - Must have valid pubkey
 */
export function validateApplicationMessage(event: UnsignedEvent): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Must not be signed
  if ('sig' in event && (event as Record<string, unknown>).sig) {
    errors.push('Application message MUST NOT be signed (prevents leak publication)');
  }

  // Must not contain h tags
  const hTag = event.tags.find((t) => t[0] === 'h');
  if (hTag) {
    errors.push('Application message MUST NOT contain h tags (leaks group identity)');
  }

  // Validate pubkey
  if (!isValidPubkey(event.pubkey)) {
    errors.push(`Invalid pubkey: ${event.pubkey}`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Verify that the MLS sender identity matches the inner event's pubkey.
 *
 * CRITICAL: Clients MUST verify this to prevent impersonation.
 *
 * @param innerEventPubkey - Pubkey from the inner Nostr event
 * @param mlsSenderIdentity - MLS credential identity (Nostr pubkey)
 * @returns true if they match
 */
export function verifyApplicationMessageSender(
  innerEventPubkey: string,
  mlsSenderIdentity: string
): boolean {
  return (
    isValidPubkey(innerEventPubkey) &&
    isValidPubkey(mlsSenderIdentity) &&
    innerEventPubkey === mlsSenderIdentity
  );
}

/**
 * Serialize an application message to JSON for MLS encryption.
 */
export function serializeApplicationMessage(event: UnsignedEvent): string {
  return JSON.stringify(event);
}

/**
 * Deserialize an application message from JSON.
 */
export function deserializeApplicationMessage(json: string): UnsignedEvent {
  const event = JSON.parse(json) as UnsignedEvent;

  // Verify it's not signed
  if ('sig' in event && (event as Record<string, unknown>).sig) {
    throw new Error(
      'Deserialized application message has a signature. ' +
        'Inner events MUST NOT be signed.'
    );
  }

  return event;
}

// ─── Commit Race Condition Handling ─────────────────────────────────────────

/**
 * Compare two commits for race condition resolution.
 *
 * Priority rules:
 * 1. Earlier timestamp wins
 * 2. Lexicographically smaller ID breaks ties
 *
 * @returns negative if a wins, positive if b wins, 0 if equal
 */
export function compareCommitPriority(a: CommitPriority, b: CommitPriority): number {
  // Timestamp priority (earlier wins)
  if (a.createdAt !== b.createdAt) {
    return a.createdAt - b.createdAt;
  }
  // ID tiebreaker (lexicographically smaller wins)
  return a.eventId.localeCompare(b.eventId);
}

/**
 * Select the winning commit from competing commits for the same epoch.
 *
 * @param commits - Array of competing commit events
 * @returns The winning commit (or null if array is empty)
 */
export function selectWinningCommit(commits: CommitPriority[]): CommitPriority | null {
  if (commits.length === 0) return null;

  return commits.reduce((winner, current) =>
    compareCommitPriority(current, winner) < 0 ? current : winner
  );
}

/**
 * Commit ordering state tracker.
 *
 * Tracks commit confirmation and handles race conditions.
 */
export class CommitOrderTracker {
  /** Commits awaiting relay confirmation */
  private _pendingCommits: Map<string, { event: SignedEvent; appliedLocally: boolean }> =
    new Map();

  /** Confirmed commit IDs */
  private _confirmedCommits: Set<string> = new Set();

  /**
   * Record a sent commit that's awaiting confirmation.
   * The commit should NOT be applied locally until confirmed.
   */
  addPendingCommit(event: SignedEvent): void {
    this._pendingCommits.set(event.id, {
      event,
      appliedLocally: false,
    });
  }

  /**
   * Mark a commit as confirmed by relay.
   * Returns true if this commit can be applied locally.
   */
  confirmCommit(eventId: string): boolean {
    this._confirmedCommits.add(eventId);
    const pending = this._pendingCommits.get(eventId);
    if (pending) {
      pending.appliedLocally = true;
      return true;
    }
    return false;
  }

  /**
   * Check if a commit has been confirmed.
   */
  isConfirmed(eventId: string): boolean {
    return this._confirmedCommits.has(eventId);
  }

  /**
   * Check if the initial group creation commit (epoch 0) should be applied locally.
   * The initial commit MUST NOT be sent to relays.
   */
  isInitialCommit(epoch: number): boolean {
    return epoch === 0;
  }
}

// ─── Self-Update Commits ────────────────────────────────────────────────────

/**
 * Validate that a commit is a valid self-update.
 *
 * A self-update commit:
 * - Contains ONLY an Update proposal for the sender's own LeafNode
 * - Does NOT modify group data or membership
 * - Can be created by ANY member (not just admins)
 *
 * @param committerPubkey - Pubkey of the commit sender
 * @param updatedLeafPubkey - Pubkey from the LeafNode being updated
 * @param proposalCount - Total number of proposals in the commit
 * @returns true if this is a valid self-update
 */
export function isValidSelfUpdate(
  committerPubkey: string,
  updatedLeafPubkey: string,
  proposalCount: number
): boolean {
  // Must be a single proposal
  if (proposalCount !== 1) return false;
  // Must be updating own leaf
  return committerPubkey === updatedLeafPubkey;
}
