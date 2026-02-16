/**
 * MIP-02: Welcome Events
 *
 * Welcome event creation (kind: 444), NIP-59 gift wrapping,
 * and commit/welcome ordering validation.
 */

import type {
  WelcomeEventOptions,
  ParsedWelcomeEvent,
  UnsignedEvent,
  SignedEvent,
  ContentEncoding,
} from './types.js';
import { MARMOT_EVENT_KINDS } from './types.js';
import {
  encodeContent,
  decodeContent,
  detectEncoding,
  getTagValue,
  getTagValues,
  unixTimestamp,
} from './utils.js';
import { generateEphemeralKeypair } from './crypto.js';
import type { MarmotSigner } from './signer.js';
import { PrivateKeySigner } from './signer.js';

// ─── Welcome Event Creation ─────────────────────────────────────────────────

/**
 * Create an unsigned Welcome rumor event (kind: 444).
 *
 * IMPORTANT: This event MUST remain unsigned to prevent accidental publication.
 * It is designed to be wrapped in a NIP-59 gift wrap.
 *
 * @param senderPubkey - Ephemeral or sender pubkey
 * @param options - Welcome event configuration
 * @returns Unsigned Welcome event (rumor)
 */
export function createWelcomeRumor(
  senderPubkey: string,
  options: WelcomeEventOptions
): UnsignedEvent {
  const encoding: ContentEncoding = options.encoding ?? 'base64';
  const content = encodeContent(options.welcomeData, encoding);

  const tags: string[][] = [
    ['e', options.keyPackageEventId],
    ['relays', ...options.relays],
    ['encoding', encoding],
  ];

  return {
    kind: MARMOT_EVENT_KINDS.WELCOME,
    created_at: unixTimestamp(),
    pubkey: senderPubkey,
    content,
    tags,
  };
}

// ─── Welcome Event Parsing ──────────────────────────────────────────────────

/**
 * Parse a Welcome event (kind: 444) rumor.
 *
 * @param event - The unsigned Welcome rumor
 * @returns Parsed Welcome event data
 */
export function parseWelcomeEvent(event: UnsignedEvent): ParsedWelcomeEvent {
  if (event.kind !== MARMOT_EVENT_KINDS.WELCOME) {
    throw new Error(`Expected kind ${MARMOT_EVENT_KINDS.WELCOME}, got ${event.kind}`);
  }

  const encoding = detectEncoding(event.tags);
  const welcomeData = decodeContent(event.content, encoding);

  const keyPackageEventId = getTagValue(event.tags, 'e');
  if (!keyPackageEventId) {
    throw new Error('Missing e tag (KeyPackage event ID)');
  }

  const relays = getTagValues(event.tags, 'relays');

  return {
    welcomeData,
    keyPackageEventId,
    relays,
    encoding,
  };
}

// ─── NIP-59 Gift Wrapping ───────────────────────────────────────────────────

/**
 * Create a NIP-59 gift-wrapped Welcome event.
 *
 * The Welcome rumor is encrypted with NIP-44 and wrapped in a seal,
 * then wrapped again in an outer gift wrap event.
 *
 * @param signer - Signer for the admin sending the Welcome
 * @param recipientPubkey - Hex pubkey of the new member
 * @param welcomeRumor - The unsigned Welcome event
 * @returns Signed gift wrap event
 */
export async function giftWrapWelcome(
  signer: MarmotSigner,
  recipientPubkey: string,
  welcomeRumor: UnsignedEvent
): Promise<SignedEvent> {
  const senderPubkey = await signer.getPublicKey();

  // Step 1: Create the rumor (already unsigned, no sig)
  const rumorJson = JSON.stringify(welcomeRumor);

  // Step 2: Create the seal (encrypt rumor with sender's key to recipient)
  const encryptedRumor = await signer.nip44Encrypt(recipientPubkey, rumorJson);

  const sealEvent: UnsignedEvent = {
    kind: 13, // NIP-59 seal
    created_at: randomizeTimestamp(unixTimestamp()),
    pubkey: senderPubkey,
    content: encryptedRumor,
    tags: [],
  };

  // Sign seal with sender's key
  const signedSeal = await signer.signEvent(sealEvent);
  const sealJson = JSON.stringify(signedSeal);

  // Step 3: Create the gift wrap (encrypt seal with EPHEMERAL keypair per NIP-59)
  // The gift wrap MUST use a fresh ephemeral key for unlinkability.
  // This is the core privacy mechanism of NIP-59.
  const ephemeral = generateEphemeralKeypair();
  const ephemeralSigner = new PrivateKeySigner(ephemeral.privateKeyHex);

  // Encrypt seal to recipient using ephemeral key (NIP-44)
  const wrappedContent = await ephemeralSigner.nip44Encrypt(recipientPubkey, sealJson);

  const giftWrapEvent: UnsignedEvent = {
    kind: 1059, // NIP-59 gift wrap
    created_at: randomizeTimestamp(unixTimestamp()),
    pubkey: ephemeral.publicKeyHex,
    content: wrappedContent,
    tags: [['p', recipientPubkey]],
  };

  // Sign gift wrap with ephemeral key (NOT sender's key — privacy!)
  return ephemeralSigner.signEvent(giftWrapEvent);
}

/**
 * Unwrap a NIP-59 gift-wrapped Welcome event.
 *
 * @param signer - Signer for the recipient
 * @param giftWrap - The gift wrap event
 * @returns The inner Welcome rumor
 */
export async function unwrapWelcome(
  signer: MarmotSigner,
  giftWrap: SignedEvent
): Promise<UnsignedEvent> {
  if (giftWrap.kind !== 1059) {
    throw new Error(`Expected kind 1059 gift wrap, got ${giftWrap.kind}`);
  }

  // Step 1: Decrypt the seal from the gift wrap
  const sealJson = await signer.nip44Decrypt(giftWrap.pubkey, giftWrap.content);
  const seal = JSON.parse(sealJson) as SignedEvent;

  if (seal.kind !== 13) {
    throw new Error(`Expected kind 13 seal, got ${seal.kind}`);
  }

  // Step 2: Decrypt the rumor from the seal
  const rumorJson = await signer.nip44Decrypt(seal.pubkey, seal.content);
  const rumor = JSON.parse(rumorJson) as UnsignedEvent;

  if (rumor.kind !== MARMOT_EVENT_KINDS.WELCOME) {
    throw new Error(
      `Expected Welcome rumor (kind ${MARMOT_EVENT_KINDS.WELCOME}), got ${rumor.kind}`
    );
  }

  // Verify the rumor is unsigned (security requirement)
  if ('sig' in rumor && (rumor as Record<string, unknown>).sig) {
    throw new Error(
      'Welcome rumor MUST be unsigned (security requirement). ' +
        'Signed inner events can be leaked to public relays.'
    );
  }

  return rumor;
}

// ─── Commit/Welcome Ordering ────────────────────────────────────────────────

/**
 * Commit/Welcome ordering state tracker.
 *
 * Ensures Welcome events are only sent after Commit confirmation.
 *
 * CRITICAL: Sending Welcome before Commit confirmation causes state forks.
 */
export class CommitWelcomeOrderTracker {
  /** Map of commit event IDs to their confirmation status */
  private _confirmedCommits: Set<string> = new Set();
  /** Map of pending welcome sends (commit ID → recipient info) */
  private _pendingWelcomes: Map<
    string,
    { recipientPubkey: string; welcomeRumor: UnsignedEvent }[]
  > = new Map();

  /**
   * Record that a Commit has been confirmed by relays.
   *
   * @param commitEventId - The event ID of the confirmed Commit
   * @returns Any pending Welcome events that can now be sent
   */
  confirmCommit(
    commitEventId: string
  ): { recipientPubkey: string; welcomeRumor: UnsignedEvent }[] {
    this._confirmedCommits.add(commitEventId);
    const pending = this._pendingWelcomes.get(commitEventId) ?? [];
    this._pendingWelcomes.delete(commitEventId);
    return pending;
  }

  /**
   * Queue a Welcome to be sent after its Commit is confirmed.
   *
   * @param commitEventId - The Commit event ID this Welcome depends on
   * @param recipientPubkey - The recipient's pubkey
   * @param welcomeRumor - The Welcome rumor to send
   * @returns true if the Commit is already confirmed (send immediately)
   */
  queueWelcome(
    commitEventId: string,
    recipientPubkey: string,
    welcomeRumor: UnsignedEvent
  ): boolean {
    if (this._confirmedCommits.has(commitEventId)) {
      return true; // Already confirmed, safe to send
    }

    const existing = this._pendingWelcomes.get(commitEventId) ?? [];
    existing.push({ recipientPubkey, welcomeRumor });
    this._pendingWelcomes.set(commitEventId, existing);
    return false;
  }

  /**
   * Check if a Commit has been confirmed.
   */
  isCommitConfirmed(commitEventId: string): boolean {
    return this._confirmedCommits.has(commitEventId);
  }

  /**
   * Get the number of pending Welcomes.
   */
  get pendingCount(): number {
    let count = 0;
    for (const entries of this._pendingWelcomes.values()) {
      count += entries.length;
    }
    return count;
  }
}

// ─── Welcome Processing ─────────────────────────────────────────────────────

/**
 * Validate Welcome event before processing.
 *
 * @param welcomeEvent - The Welcome rumor
 * @param expectedKeyPackageId - Expected KeyPackage event ID
 * @returns Validation result with any errors
 */
export function validateWelcomeEvent(
  welcomeEvent: UnsignedEvent,
  expectedKeyPackageId?: string
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (welcomeEvent.kind !== MARMOT_EVENT_KINDS.WELCOME) {
    errors.push(
      `Invalid kind: expected ${MARMOT_EVENT_KINDS.WELCOME}, got ${welcomeEvent.kind}`
    );
  }

  // Must be unsigned
  if ('sig' in welcomeEvent && (welcomeEvent as Record<string, unknown>).sig) {
    errors.push('Welcome event MUST NOT be signed (security requirement)');
  }

  const keyPackageId = getTagValue(welcomeEvent.tags, 'e');
  if (!keyPackageId) {
    errors.push('Missing e tag (KeyPackage event ID)');
  } else if (expectedKeyPackageId && keyPackageId !== expectedKeyPackageId) {
    errors.push(
      `KeyPackage mismatch: expected ${expectedKeyPackageId}, got ${keyPackageId}`
    );
  }

  const relays = getTagValues(welcomeEvent.tags, 'relays');
  if (relays.length === 0) {
    errors.push('Missing or empty relays tag');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Check if a Welcome event is for initial group creation
 * (single-member group, no prior epochs).
 * Initial creation does NOT require commit confirmation wait.
 */
export function isInitialGroupCreation(commitEpoch: number): boolean {
  return commitEpoch === 0;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Randomize a timestamp for privacy (NIP-59).
 *
 * IMPORTANT: Most relays reject events with timestamps in the future (typically
 * allowing only 10-15 minutes of clock skew). To prevent rejection while still
 * providing privacy, we randomize ONLY into the past.
 *
 * WORKAROUND: Reduced range to 2-120 minutes (was 0-48 hours) to work around
 * marmot-cli event fetching issue with old timestamps. See:
 * https://github.com/kai-familiar/marmot-cli/issues/8
 */
function randomizeTimestamp(timestamp: number): number {
  const minOffset = 2 * 60;      // 2 minutes in seconds
  const maxOffset = 120 * 60;    // 120 minutes in seconds
  const randomOffset = minOffset + Math.floor(Math.random() * (maxOffset - minOffset));
  return timestamp - randomOffset; // Subtract 2-120 minutes
}
