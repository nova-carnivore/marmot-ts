/**
 * Social — Follow list management
 *
 * Generic Nostr social graph helpers for the Marmot Protocol.
 * Provides kind:3 follow list event creation and parsing.
 *
 * @packageDocumentation
 */

import type { UnsignedEvent, SignedEvent } from './types.js';
import type { MarmotSigner } from './signer.js';
import { unixTimestamp, isValidPubkey } from './utils.js';

// ─── Constants ──────────────────────────────────────────────────────────────

/**
 * Nostr event kind for contact/follow lists.
 */
export const FOLLOW_LIST_KIND = 3;

// ─── Follow List Management ─────────────────────────────────────────────────

/**
 * Create an unsigned follow list event (kind:3).
 *
 * This creates a replacement event containing all pubkeys the user follows.
 * Per NIP-02, this is a full replacement — not a diff.
 *
 * @param pubkey - The user's own pubkey (hex)
 * @param followPubkeys - Array of pubkeys to follow (hex)
 * @returns Unsigned kind:3 event
 */
export function createFollowListEvent(
  pubkey: string,
  followPubkeys: string[]
): UnsignedEvent {
  // Validate all pubkeys
  if (!isValidPubkey(pubkey)) {
    throw new Error(`Invalid pubkey: ${pubkey}`);
  }
  for (const p of followPubkeys) {
    if (!isValidPubkey(p)) {
      throw new Error(`Invalid follow pubkey: ${p}`);
    }
  }

  // Deduplicate
  const uniquePubkeys = [...new Set(followPubkeys)];

  return {
    kind: FOLLOW_LIST_KIND,
    created_at: unixTimestamp(),
    pubkey,
    tags: uniquePubkeys.map((p) => ['p', p]),
    content: '',
  };
}

/**
 * Create a signed follow list event (kind:3) and return the signed event.
 *
 * @param signer - Signer for the user
 * @param followPubkeys - Array of pubkeys to follow (hex)
 * @returns Signed kind:3 event
 */
export async function publishFollowList(
  signer: MarmotSigner,
  followPubkeys: string[]
): Promise<SignedEvent> {
  const pubkey = await signer.getPublicKey();
  const event = createFollowListEvent(pubkey, followPubkeys);
  return signer.signEvent(event);
}

/**
 * Parse a follow list event (kind:3) and extract followed pubkeys.
 *
 * @param event - A kind:3 Nostr event (signed or unsigned)
 * @returns Array of followed pubkeys (hex)
 */
export function parseFollowList(event: UnsignedEvent): string[] {
  if (event.kind !== FOLLOW_LIST_KIND) {
    throw new Error(`Expected kind ${FOLLOW_LIST_KIND}, got ${event.kind}`);
  }

  return event.tags
    .filter((t) => t[0] === 'p' && t[1] && isValidPubkey(t[1]))
    .map((t) => t[1]!);
}

/**
 * Add a pubkey to an existing follow list.
 *
 * @param currentFollows - Current list of followed pubkeys
 * @param newPubkey - Pubkey to add
 * @returns Updated follow list (deduplicated)
 */
export function addToFollowList(
  currentFollows: string[],
  newPubkey: string
): string[] {
  if (!isValidPubkey(newPubkey)) {
    throw new Error(`Invalid pubkey: ${newPubkey}`);
  }
  const set = new Set(currentFollows);
  set.add(newPubkey);
  return [...set];
}

/**
 * Remove a pubkey from an existing follow list.
 *
 * @param currentFollows - Current list of followed pubkeys
 * @param removePubkey - Pubkey to remove
 * @returns Updated follow list
 */
export function removeFromFollowList(
  currentFollows: string[],
  removePubkey: string
): string[] {
  return currentFollows.filter((p) => p !== removePubkey);
}
